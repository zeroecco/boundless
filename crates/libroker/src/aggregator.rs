use crate::{now_timestamp_secs, Order, State};
use alloy::{
    primitives::{utils, U256},
    providers::{Provider, WalletProvider},
};
use anyhow::{Context, Result};
use boundless_assessor::{AssessorInput, Fulfillment};
use boundless_market::contracts::eip712_domain;
use broker::provers;
use risc0_aggregation::GuestState;
use risc0_zkvm::{
    sha::{Digest, Digestible},
    ReceiptClaim,
};

#[derive(Default)]
pub struct Batch {
    /// Orders from the market that are included in this batch.
    pub orders: Vec<Order>,
    pub assessor_claim_digest: Option<Digest>,
    /// Tuple of the current aggregation state, as committed by the set builder guest, and the
    /// proof ID for the receipt that attests to the correctness of this state.
    pub aggregation_state: Option<AggregationState>,
    // /// When the batch was initially created.
    // pub start_time: DateTime<Utc>,
    /// The deadline for the batch, which is the earliest deadline for any order in the batch.
    pub deadline: Option<u64>,
    /// The total fees for the batch, which is the sum of fees from all orders.
    pub fees: U256,
    pub error_msg: Option<String>,
}

/// Struct containing the information about an order used by the aggregation worker.
#[derive(Debug)]
pub struct AggregationOrder {
    pub order: Order,
    pub proof_id: String,
    pub expiration: u64,
    pub fee: U256,
}

#[derive(Clone)]
pub struct AggregationState {
    pub guest_state: risc0_aggregation::GuestState,
    /// All claim digests in this aggregation.
    /// This collection can be used to construct the aggregation Merkle tree and Merkle paths.
    pub claim_digests: Vec<Digest>,
    /// Proof ID for the STARK proof that compresses the root of the aggregation tree.
    pub proof_id: String,
    /// Proof ID for the Groth16 proof that compresses the root of the aggregation tree.
    pub groth16_proof_id: Option<String>,
}

impl<P> State<P>
where
    P: Provider + 'static + Clone + WalletProvider,
{
    async fn prove_set_builder(
        &self,
        aggregation_state: Option<&AggregationState>,
        proofs: &[String],
        finalize: bool,
    ) -> Result<AggregationState> {
        // TODO(#268): Handle failure to get an individual order.
        let mut claims = Vec::<ReceiptClaim>::with_capacity(proofs.len());
        for proof_id in proofs {
            let receipt = self
                .prover
                .get_receipt(proof_id)
                .await
                .with_context(|| format!("Failed to get proof receipt for {proof_id}"))?
                .with_context(|| format!("Proof receipt not found for {proof_id}"))?;
            let claim = receipt
                .claim()
                .with_context(|| format!("Receipt for {proof_id} missing claim"))?
                .value()
                .with_context(|| format!("Receipt for {proof_id} claims pruned"))?;
            claims.push(claim);
        }

        let input = aggregation_state
            .map_or(GuestState::initial(self.set_builder_guest_id), |s| s.guest_state.clone())
            .into_input(claims.clone(), finalize)
            .context("Failed to build set builder input")?;

        // Gather the proof IDs for the assumptions we will need: any pending proofs, and the proof
        // for the current aggregation state.
        let assumption_ids: Vec<String> = aggregation_state
            .map(|s| s.proof_id.clone())
            .into_iter()
            .chain(proofs.iter().cloned())
            .collect();

        let input_data =
            provers::encode_input(&input).context("Failed to encode set-builder proof input")?;
        let input_id = self
            .prover
            .upload_input(input_data)
            .await
            .context("Failed to upload set-builder input")?;

        // TODO: we should run this on a different stream in the prover
        // aka make a few different priority streams for each level of the proving

        // TODO: Need to set a timeout here to handle stuck or even just alert on delayed proving if
        // the proving cluster is overloaded

        tracing::info!("Starting proving of set-builder");
        let proof_res = self
            .prover
            .prove_and_monitor_stark(
                &self.set_builder_guest_id.to_string(),
                &input_id,
                assumption_ids,
            )
            .await
            .context("Failed to prove set-builder")?;
        tracing::info!(
            "completed proving of set-builder cycles: {} time: {}",
            proof_res.stats.total_cycles,
            proof_res.elapsed_time
        );

        let journal = self
            .prover
            .get_journal(&proof_res.id)
            .await
            .with_context(|| format!("Failed to get set-builder journal from {}", proof_res.id))?
            .with_context(|| format!("set-builder journal missing from {}", proof_res.id))?;

        let guest_state = GuestState::decode(&journal).context("Failed to decode guest output")?;
        let claim_digests = aggregation_state
            .map(|s| s.claim_digests.clone())
            .unwrap_or_default()
            .into_iter()
            .chain(claims.into_iter().map(|claim| claim.digest()))
            .collect();

        Ok(AggregationState {
            guest_state,
            proof_id: proof_res.id,
            claim_digests,
            groth16_proof_id: None,
        })
    }

    async fn prove_assessor(&self, orders: &[Order]) -> Result<String> {
        let mut fills = vec![];
        let mut assumptions = vec![];

        for order in orders {
            let proof_id: String = order
                .proof_id
                .as_ref()
                .cloned()
                .with_context(|| format!("Missing proof_id for order: {:x}", order.id()))?;

            assumptions.push(proof_id.clone());

            let journal = self
                .prover
                .get_journal(&proof_id)
                .await
                .with_context(|| format!("Failed to get {proof_id} journal"))?
                .with_context(|| format!("{proof_id} journal missing"))?;

            fills.push(Fulfillment {
                request: order.request.clone(),
                signature: order.client_sig.clone().to_vec(),
                journal,
                require_payment: true,
            })
        }

        let order_count = fills.len();
        let domain = self.market.eip712_domain().await?;
        let input = AssessorInput { fills, domain, prover_address: self.prover_address };
        let input_data = input.to_vec();

        let input_id = self
            .prover
            .upload_input(input_data)
            .await
            .context("Failed to upload assessor input")?;

        let proof_res = self
            .prover
            .prove_and_monitor_stark(&self.assessor_guest_id.to_string(), &input_id, assumptions)
            .await
            .context("Failed to prove assesor stark")?;

        tracing::info!(
            "Assessor proof completed, count: {} cycles: {} time: {}",
            order_count,
            proof_res.stats.total_cycles,
            proof_res.elapsed_time
        );

        Ok(proof_res.id)
    }

    /// Get the sum of the size of the journals for proofs in a batch
    async fn get_combined_journal_size(&self, orders: &[Order]) -> Result<usize> {
        let mut journal_size = 0;
        for order in orders {
            let proof_id: String = order
                .proof_id
                .as_ref()
                .cloned()
                .with_context(|| format!("Missing proof_id for order: {:x}", order.id()))?;

            let journal = self
                .prover
                .get_journal(&proof_id)
                .await
                .with_context(|| format!("Failed to get journal for {proof_id}"))?
                .with_context(|| format!("Journal for {proof_id} missing"))?;

            journal_size += journal.len();
        }

        Ok(journal_size)
    }

    /// Check if we should finalize the batch
    ///
    /// Checks current min-deadline, batch timer, and current block.
    async fn check_finalize(
        &self,
        batch_id: usize,
        batch: &Batch,
        pending_orders: &[Order],
    ) -> Result<bool> {
        // TODO(libroker): always immediately finalizing for now
        Ok(true)
        // let (conf_batch_size, conf_batch_time, conf_batch_fees, conf_max_journal_bytes) = {
        //     let config = self.config.lock_all().context("Failed to lock config")?;

        //     // TODO: Move this parse into config
        //     let batch_max_fees = match config.batcher.batch_max_fees.as_ref() {
        //         Some(elm) => {
        //             Some(utils::parse_ether(elm).context("Failed to parse batch max fees")?)
        //         }
        //         None => None,
        //     };
        //     (
        //         config.batcher.batch_size,
        //         config.batcher.batch_max_time,
        //         batch_max_fees,
        //         config.batcher.batch_max_journal_bytes,
        //     )
        // };

        // // Skip finalization checks if we have nothing in this batch
        // let is_initial_state =
        //     batch.aggregation_state.as_ref().map(|s| s.guest_state.is_initial()).unwrap_or(true);
        // if is_initial_state && pending_orders.is_empty() {
        //     return Ok(false);
        // }

        // // Finalize the batch whenever it exceeds a target size.
        // // Add any pending jobs into the batch along with the finalization run.
        // let batch_size = batch.orders.len() + pending_orders.len();
        // if let Some(batch_target_size) = conf_batch_size {
        //     if batch_size >= batch_target_size as usize {
        //         tracing::info!(
        //             "Finalizing batch {batch_id}: size target hit {} - {}",
        //             batch_size,
        //             batch_target_size
        //         );
        //         return Ok(true);
        //     } else {
        //         tracing::debug!(
        //             "Batch {batch_id} below size target hit {} - {}",
        //             batch_size,
        //             batch_target_size
        //         );
        //     }
        // }

        // // Finalize the batch if the journal size is already above the max
        // let batch_journal_size = self.get_combined_journal_size(&batch.orders).await?;
        // // let pending_order_ids: Vec<_> = pending_orders.iter().map(|o| o.order_id).collect();
        // let pending_journal_size = self.get_combined_journal_size(pending_orders).await?;
        // let journal_size = batch_journal_size + pending_journal_size;
        // if journal_size >= conf_max_journal_bytes {
        //     tracing::info!(
        //         "Finalizing batch {batch_id}: journal size target hit {} >= {}",
        //         journal_size,
        //         conf_max_journal_bytes
        //     );
        //     return Ok(true);
        // } else {
        //     tracing::debug!(
        //         "Batch {batch_id} journal size below limit {} < {}",
        //         journal_size,
        //         conf_max_journal_bytes
        //     );
        // }

        // // // Finalize the batch whenever the current batch exceeds a certain age (e.g. one hour).
        // // if let Some(batch_time) = conf_batch_time {
        // //     let time_delta = Utc::now() - batch.start_time;
        // //     if time_delta.num_seconds() as u64 >= batch_time {
        // //         tracing::info!(
        // //             "Finalizing batch {batch_id}: time limit hit {} - {}",
        // //             time_delta.num_seconds(),
        // //             batch.start_time
        // //         );
        // //         return Ok(true);
        // //     } else {
        // //         tracing::debug!("Batch {batch_id} below time limit");
        // //     }
        // // }

        // // // Finalize whenever a batch hits the target fee total.
        // // if let Some(batch_target_fees) = conf_batch_fees {
        // //     let fees =
        // //         pending_orders.iter().map(|order| order.fee).fold(batch.fees, |sum, fee| sum + fee);

        // //     if fees >= batch_target_fees {
        // //         tracing::info!("Finalizing batch {batch_id}: fee target hit");
        // //         return Ok(true);
        // //     } else {
        // //         tracing::debug!("Batch {batch_id} below fee target");
        // //     }
        // // }

        // // Finalize whenever a deadline is approaching.
        // let conf_deadline_buf_secs = {
        //     let config = self.config.lock_all().context("Failed to lock config")?;
        //     config.batcher.block_deadline_buffer_secs
        // };
        // let now = now_timestamp_secs();

        // let deadline = pending_orders
        //     .iter()
        //     .map(|order| order.expiration)
        //     // .chain(batch.deadline)
        //     .reduce(u64::min);

        // if let Some(deadline) = deadline {
        //     let remaining_secs = deadline.saturating_sub(now);
        //     if remaining_secs <= conf_deadline_buf_secs {
        //         tracing::info!(
        //             "Finalizing batch {batch_id}: getting close to deadline {remaining_secs}"
        //         );
        //         return Ok(true);
        //     } else {
        //         tracing::debug!("Batch {batch_id} not too close to deadline {remaining_secs}");
        //     }
        // } else {
        //     tracing::warn!("Batch {batch_id} does not yet have a block_deadline");
        // };

        // Ok(false)
    }

    async fn aggregate_proofs(
        &self,
        batch_id: usize,
        batch: &Batch,
        new_proofs: &[Order],
        finalize: bool,
    ) -> Result<AggregationState> {
        let assessor_proof_id = if finalize {
            // let assessor_order_ids: Vec<U256> =
            //     batch.orders.iter().copied().chain(new_proofs.iter().map(|p| p.order_id)).collect();

            tracing::debug!(
                "Running assessor for batch {batch_id} with orders {:x?}",
                batch.orders
            );

            let assessor_proof_id =
                self.prove_assessor(&batch.orders).await.with_context(|| {
                    format!("Failed to prove assessor with orders {:x?}", batch.orders)
                })?;

            Some(assessor_proof_id)
        } else {
            None
        };

        let proof_ids: Vec<String> = new_proofs
            .iter()
            // TODO(libroker) an unwrap here, but should be guaranteed.
            .map(|proof| proof.proof_id.as_ref().unwrap().clone())
            .chain(assessor_proof_id.iter().cloned())
            .collect();

        tracing::debug!("Running set builder for {batch_id} with proofs {:x?}", proof_ids);
        let aggregation_state = self
            .prove_set_builder(batch.aggregation_state.as_ref(), &proof_ids, finalize)
            .await
            .context("Failed to prove set builder for batch {batch_id}")?;

        tracing::info!("Completed aggregation into batch {batch_id} of proofs {:x?}", proof_ids);

        let assessor_claim_digest = if let Some(proof_id) = assessor_proof_id {
            let receipt = self
                .prover
                .get_receipt(&proof_id)
                .await
                .with_context(|| format!("Failed to get proof receipt for proof {proof_id}"))?
                .with_context(|| format!("Proof receipt not found for proof {proof_id}"))?;
            let claim = receipt
                .claim()
                .with_context(|| format!("Receipt for proof {proof_id} missing claim"))?
                .value()
                .with_context(|| format!("Receipt for proof {proof_id} claims pruned"))?;
            Some(claim.digest())
        } else {
            None
        };

        // self.db
        //     .update_batch(batch_id, &aggregation_state, new_proofs, assessor_claim_digest)
        //     .await
        //     .with_context(|| format!("Failed to update batch {batch_id} in the DB"))?;

        Ok(aggregation_state)
    }

    pub async fn aggregate(&self, new_proofs: &[Order]) -> Result<Option<Batch>> {
        // Get the current batch. This aggregator service works on one batch at a time, including
        // any proofs ready for aggregation into the current batch.
        // let batch_id =
        //     self.db.get_current_batch().await.context("Failed to get current batch ID")?;
        // let batch = self.db.get_batch(batch_id).await.context("Failed to get batch")?;

        // let (aggregation_proof_id, compress) = match batch.status {
        //     BatchStatus::Aggregating => {
        // // Fetch all proofs that are pending aggregation from the DB.
        // let new_proofs = self
        //     .db
        //     .get_aggregation_proofs()
        //     .await
        //     .context("Failed to get pending agg proofs from DB")?;

        let mut batch = Batch::default();
        // TODO(libroker): this is statically 0, doesn't handle creating batch over time.
        let batch_id = 0;

        // Finalize the current batch before adding any new orders if the finalization conditions
        // are already met.
        let finalize = self.check_finalize(batch_id, &batch, new_proofs).await?;

        // If we don't need to finalize, and there are no new proofs, there is no work to do.
        if !finalize && new_proofs.is_empty() {
            tracing::trace!("No aggregation work to do for batch {batch_id}");
            return Ok(None);
        }

        let mut aggregation_state =
            self.aggregate_proofs(batch_id, &batch, new_proofs, finalize).await?;
        // }
        // BatchStatus::PendingCompression => {
        //     let Some(aggregation_state) = batch.aggregation_state else {
        //         bail!("Batch {batch_id} in inconsistent state: status is PendingCompression but aggregation_state is None");
        //     };
        //     (aggregation_state.proof_id, true)
        // }
        // status => bail!("Unexpected batch status {status:?}"),
        // };

        if finalize {
            tracing::info!("Starting groth16 compression proof for batch {batch_id}");
            let compress_proof_id = self
                .prover
                .compress(&aggregation_state.proof_id)
                .await
                .context("Failed to complete compression")?;
            tracing::info!("Completed groth16 compression for batch {batch_id}");

            aggregation_state.groth16_proof_id = Some(compress_proof_id);
            batch.aggregation_state = Some(aggregation_state);

            // self.db
            //     .complete_batch(batch_id, compress_proof_id)
            //     .await
            //     .context("Failed to set batch as complete")?;
            return Ok(Some(batch));
        }

        Ok(None)
    }
}
