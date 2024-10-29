use std::time::Duration;

use super::LIGHT_CLIENT_GUEST_ELF;
use crate::prover::ProofOutput;
use alloy::{
    network::Ethereum,
    primitives::{aliases::U96, utils::parse_ether},
    providers::Provider,
    transports::Transport,
};
use async_trait::async_trait;
use boundless_market::{
    contracts::{Input, Offer, Predicate, ProvingRequest, Requirements},
    sdk::client::Client,
    storage::StorageProvider,
};
use risc0_zkvm::{compute_image_id, default_executor, sha::Digestible, ExecutorEnv};

use super::Blobstream0Prover;

pub struct BoundlessProver<T, P, S> {
    pub image_url: String,
    pub client: Client<T, P, S>,
}

#[async_trait]
impl<T, P, S> Blobstream0Prover for BoundlessProver<T, P, S>
where
    T: Transport + Clone + Send + Sync,
    P: Provider<T, Ethereum> + 'static + Clone + Send + Sync,
    S: StorageProvider + Clone + Send + Sync,
    <S as StorageProvider>::Error: std::fmt::Debug,
{
    async fn prove(&self, input: Vec<u8>) -> anyhow::Result<ProofOutput> {
        let input_url = self.client.upload_input(&input).await?;

        // Dry run the ELF with the input to get the journal and cycle count.
        // This can be useful to estimate the cost of the proving request.
        // It can also be useful to ensure the guest can be executed correctly and we do not send into
        // the market unprovable proving requests. If you have a different mechanism to get the expected
        // journal and set a price, you can skip this step.
        let env = ExecutorEnv::builder().write_slice(&input).build()?;
        let session_info = default_executor().execute(env, LIGHT_CLIENT_GUEST_ELF)?;
        let mcycles_count = session_info
            .segments
            .iter()
            .map(|segment| 1 << segment.po2)
            .sum::<u64>()
            .div_ceil(1_000_000);
        let journal = session_info.journal;

        // Recompute the image ID. Do not use the methods codegen, as it will be incorrect for
        // prebuit docker builds.
        // TODO avoid recomputing this, can be added to prover
        let image_id = compute_image_id(LIGHT_CLIENT_GUEST_ELF)?;

        // Create a proving request with the image, input, requirements and offer.
        // The ELF (i.e. image) is specified by the image URL.
        // The input can be specified by an URL, as in this example, or can be posted on chain by using
        // the `with_inline` method with the input bytes.
        // The requirements are the image ID and the digest of the journal. In this way, the market can
        // verify that the proof is correct by checking both the committed image id and digest of the
        // journal. The offer specifies the price range and the timeout for the request.
        // Additionally, the offer can also specify:
        // - the bidding start time: the block number when the bidding starts;
        // - the ramp up period: the number of blocks before the price start increasing until reaches
        //   the maxPrice, starting from the the bidding start;
        // - the lockin price: the price at which the request can be locked in by a prover, if the
        //   request is not fulfilled before the timeout, the prover can be slashed.
        let request = ProvingRequest::default()
            .with_image_url(&self.image_url)
            .with_input(Input::url(&input_url))
            .with_requirements(Requirements::new(
                image_id,
                Predicate::digest_match(journal.digest()),
            ))
            .with_offer(
                Offer::default()
                    // The market uses a reverse Dutch auction mechanism to match requests with provers.
                    // Each request has a price range that a prover can bid on. One way to set the price
                    // is to choose a desired (min and max) price per million cycles and multiply it
                    // by the number of cycles. Alternatively, you can use the `with_min_price` and
                    // `with_max_price` methods to set the price directly.
                    .with_min_price_per_mcycle(
                        U96::from::<u128>(parse_ether("0.0001")?.try_into()?),
                        mcycles_count,
                    )
                    // NOTE: If your offer is not being accepted, try increasing the max price.
                    .with_max_price_per_mcycle(
                        U96::from::<u128>(parse_ether("0.001")?.try_into()?),
                        mcycles_count,
                    )
                    .with_lockin_stake(500000000000000000u128.try_into()?)
                    // The timeout is the maximum number of blocks the request can stay
                    // unfulfilled in the market before it expires. If a prover locks in
                    // the request and does not fulfill it before the timeout, the prover can be
                    // slashed.
                    .with_timeout(150),
            );

        // Send the request and wait for it to be completed.
        let request_id = self.client.submit_request(&request).await.unwrap();
        tracing::info!(target: "blobstream0::core", "Request {} submitted", request_id);

        // Wait for the request to be fulfilled by the market, returning the journal and seal.
        tracing::info!(target: "blobstream0::core", "Waiting for request {} to be fulfilled", request_id);
        let (journal, seal) = tokio::time::timeout(
            Duration::from_secs(12 * 150),
            self.client
                .wait_for_request_fulfillment(request_id, Duration::from_secs(8), None),
        )
        .await??;

        Ok(ProofOutput {
            journal: journal.into(),
            seal: seal.into(),
        })
    }
}
