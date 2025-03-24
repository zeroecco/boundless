use std::collections::HashMap;

use crate::{aggregator::Batch, State};
use alloy::{
    network::Ethereum,
    primitives::B256,
    providers::{Provider, WalletProvider},
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use boundless_market::contracts::{AssessorReceipt, Fulfillment};
use guest_assessor::ASSESSOR_GUEST_ID;
use risc0_aggregation::{SetInclusionReceipt, SetInclusionReceiptVerifierParameters};
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::{
    sha::{Digest, Digestible},
    MaybePruned, Receipt, ReceiptClaim,
};

impl<P> State<P>
where
    P: Provider<Ethereum> + WalletProvider + 'static + Clone,
{
    async fn fetch_encode_g16(&self, g16_proof_id: &str) -> Result<Vec<u8>> {
        let groth16_receipt = self
            .prover
            .get_compressed_receipt(g16_proof_id)
            .await
            .context("Failed to fetch g16 receipt")?
            .context("Groth16 receipt missing")?;

        let groth16_receipt: Receipt =
            bincode::deserialize(&groth16_receipt).context("Failed to deserialize g16 receipt")?;

        let encoded_seal =
            encode_seal(&groth16_receipt).context("Failed to encode g16 receipt seal")?;

        Ok(encoded_seal)
    }

    pub async fn submit_batch(&self, batch_id: usize, batch: &Batch) -> Result<()> {
        tracing::info!("Submitting batch {batch_id}");

        let Some(ref aggregation_state) = batch.aggregation_state else {
            bail!("Cannot submit batch with no recorded aggregation state");
        };
        let Some(ref groth16_proof_id) = aggregation_state.groth16_proof_id else {
            bail!("Cannot submit batch with no recorded Groth16 proof ID");
        };
        ensure!(
            !aggregation_state.claim_digests.is_empty(),
            "Cannot submit batch with no claim digests"
        );
        ensure!(
            batch.assessor_claim_digest.is_some(),
            "Cannot submit batch with no assessor claim digest"
        );
        ensure!(
            aggregation_state.guest_state.mmr.is_finalized(),
            "Cannot submit guest state that is not finalized"
        );

        // Collect the needed parts for the new merkle root:
        let batch_seal = self.fetch_encode_g16(groth16_proof_id).await?;
        let batch_root = risc0_aggregation::merkle_root(&aggregation_state.claim_digests);
        let root = B256::from_slice(batch_root.as_bytes());

        ensure!(
            aggregation_state.guest_state.mmr.clone().finalized_root().unwrap() == batch_root,
            "Guest state finalized root is inconsistent with claim digests"
        );

        // Collect the needed parts for the fulfillBatch:
        let inclusion_params =
            SetInclusionReceiptVerifierParameters { image_id: self.set_builder_img_id };

        let mut fulfillments = vec![];
        let mut order_prices = HashMap::new();

        for order in batch.orders.iter() {
            let order_id = *order.id();
            tracing::info!("Submitting order {order_id:x}");

            let res = async {
                // let (order_request, order_proof_id, order_img_id, lock_price) =
                //     self.db.get_submission_order(*order_id).await.context(
                //         "Failed to get order from DB for submission, order NOT finalized",
                //     )?;

                order_prices.insert(order_id, lock_price);

                let order_journal = self
                    .prover
                    .get_journal(&order_proof_id)
                    .await
                    .context("Failed to get order journal from prover")?
                    .context("Order proof Journal missing")?;

                // NOTE: We assume here that the order execution ended with exit code 0.
                let order_claim =
                    ReceiptClaim::ok(order_img_id.0, MaybePruned::Pruned(order_journal.digest()));
                let order_claim_index = aggregation_state
                    .claim_digests
                    .iter()
                    .position(|claim| *claim == order_claim.digest())
                    .ok_or(anyhow!(
                        "Failed to find order claim {order_claim:x?} in aggregated claims"
                    ))?;
                let order_path = risc0_aggregation::merkle_path(
                    &aggregation_state.claim_digests,
                    order_claim_index,
                );
                tracing::debug!(
                    "Merkle path for order {order_id:x} : {:x?} : {order_path:x?}",
                    order_claim.digest()
                );
                let set_inclusion_receipt = SetInclusionReceipt::from_path_with_verifier_params(
                    order_claim,
                    order_path,
                    inclusion_params.digest(),
                );
                let seal =
                    set_inclusion_receipt.abi_encode_seal().context("Failed to encode seal")?;

                let request_digest = order_request
                    .eip712_signing_hash(&self.market.eip712_domain().await?.alloy_struct());
                fulfillments.push(Fulfillment {
                    id: order_id,
                    requestDigest: request_digest,
                    imageId: order_img_id,
                    journal: order_journal.into(),
                    seal: seal.into(),
                });
                anyhow::Ok(())
            };

            if let Err(err) = res.await {
                panic!("failed to submit {order_id:x}: {err}");
                // tracing::error!("Failed to submit {order_id:x}: {err}");
                // if let Err(db_err) = self.db.set_order_failure(order_id, err.to_string()).await {
                //     tracing::error!("Failed to set order failure during proof submission: {order_id:x} {db_err:?}");
                // }
            }
        }

        let assessor_claim_index = aggregation_state
            .claim_digests
            .iter()
            .position(|claim| *claim == batch.assessor_claim_digest.unwrap())
            .ok_or(anyhow!("Failed to find order claim assessor claim in aggregated claims"))?;
        let assessor_path =
            risc0_aggregation::merkle_path(&aggregation_state.claim_digests, assessor_claim_index);
        tracing::debug!(
            "Merkle path for assessor : {:x?} : {assessor_path:x?}",
            batch.assessor_claim_digest
        );

        let assessor_seal = SetInclusionReceipt::from_path_with_verifier_params(
            // TODO: Set inclusion proofs, when ABI encoded, currently don't contain anything
            // derived from the claim. So instead of constructing the journal, we simply use the
            // zero digest. We should either plumb through the data for the assessor journal, or we
            // should make an explicit way to encode an inclusion proof without the claim.
            ReceiptClaim::ok(ASSESSOR_GUEST_ID, MaybePruned::Pruned(Digest::ZERO)),
            assessor_path,
            inclusion_params.digest(),
        );
        let assessor_seal =
            assessor_seal.abi_encode_seal().context("ABI encode assessor set inclusion receipt")?;

        let single_txn_fulfill = {
            let config = self.config.lock_all().context("Failed to read config")?;
            config.batcher.single_txn_fulfill
        };
        let assessor_fill = AssessorReceipt {
            seal: assessor_seal.into(),
            selectors: vec![],
            prover: self.prover_address,
            callbacks: vec![],
        };
        if single_txn_fulfill {
            if let Err(err) = self
                .market
                .submit_merkle_and_fulfill(
                    self.set_verifier_addr,
                    root,
                    batch_seal.into(),
                    fulfillments.clone(),
                    assessor_fill,
                )
                .await
            {
                tracing::error!("Failed to submit proofs for batch {batch_id}: {err:?}");

                for fulfillment in fulfillments.iter() {
                    if let Err(db_err) = self
                        .db
                        .set_order_failure(U256::from(fulfillment.id), format!("{err:?}"))
                        .await
                    {
                        tracing::error!(
                            "Failed to set order failure during proof submission: {:x} {db_err:?}",
                            fulfillment.id
                        );
                    }
                }
                bail!("transaction to fulfill batch failed");
            }
        } else {
            let contains_root = match self.set_verifier.contains_root(root).await {
                Ok(res) => res,
                Err(err) => {
                    tracing::error!("Failed to query if set-verifier contains the new root, trying to submit anyway {err:?}");
                    false
                }
            };
            if !contains_root {
                tracing::info!("Submitting app merkle root: {root}");
                self.set_verifier
                    .submit_merkle_root(root, batch_seal.into())
                    .await
                    .context("Failed to submit app merkle_root")?;
            } else {
                tracing::info!("Contract already contains root, skipping to fulfillment");
            }

            if let Err(err) = self.market.fulfill_batch(fulfillments.clone(), assessor_fill).await {
                tracing::error!("Failed to submit proofs: {err:?} for batch {batch_id}");
                for fulfillment in fulfillments.iter() {
                    if let Err(db_err) = self
                        .db
                        .set_order_failure(U256::from(fulfillment.id), format!("{err:?}"))
                        .await
                    {
                        tracing::error!(
                            "Failed to set order failure during proof submission: {:x} {db_err:?}",
                            fulfillment.id
                        );
                    }
                }
                bail!("transaction to fulfill batch failed");
            }
        }

        for fulfillment in fulfillments.iter() {
            if let Err(db_err) = self.db.set_order_complete(U256::from(fulfillment.id)).await {
                tracing::error!(
                    "Failed to set order complete during proof submission: {:x} {db_err:?}",
                    fulfillment.id
                );
                continue;
            }
            let lock_price = order_prices.get(&fulfillment.id).unwrap_or(&U256::ZERO);
            tracing::info!(
                "✨ Completed order: {:x} fee: {} ✨",
                fulfillment.id,
                format_ether(*lock_price)
            );
        }

        Ok(())
    }

    pub async fn process_next_batch(&self) -> Result<bool, SupervisorErr> {
        let batch_res = self
            .db
            .get_complete_batch()
            .await
            .context("Failed to check db for complete batch")
            .map_err(SupervisorErr::Recover)?;

        let Some((batch_id, batch)) = batch_res else {
            return Ok(false);
        };

        let max_batch_submission_attempts = self
            .config
            .lock_all()
            .map_err(|e| SupervisorErr::Recover(e.into()))?
            .batcher
            .max_submission_attempts;

        let mut errors = Vec::new();
        for attempt in 0..max_batch_submission_attempts {
            match self.submit_batch(batch_id, &batch).await {
                Ok(_) => {
                    if let Err(db_err) = self.db.set_batch_submitted(batch_id).await {
                        tracing::error!("Failed to set batch submitted status: {db_err:?}");
                        return Err(SupervisorErr::Fault(db_err.into()));
                    }
                    tracing::info!(
                        "Completed batch: {batch_id} total_fees: {}",
                        format_ether(batch.fees)
                    );
                    return Ok(true);
                }
                Err(err) => {
                    tracing::warn!(
                        "Batch submission attempt {}/{} failed",
                        attempt + 1,
                        max_batch_submission_attempts,
                    );
                    errors.push(err);
                }
            }
        }
        tracing::error!("Batch {batch_id} has reached max submission attempts");
        if let Err(err) = self.db.set_batch_failure(batch_id, format!("{errors:?}")).await {
            tracing::error!("Failed to set batch failure in db: {batch_id} - {err:?}");
            return Err(SupervisorErr::Recover(err.into()));
        }
        Ok(false)
    }
}
