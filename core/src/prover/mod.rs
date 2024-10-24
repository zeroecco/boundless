use crate::LIGHT_CLIENT_GUEST_ELF;
use alloy_sol_types::SolValue;
use anyhow::Context;
use async_trait::async_trait;
use blobstream0_primitives::{
    proto::{TrustedLightBlock, UntrustedLightBlock},
    LightBlockProveData, RangeCommitment,
};
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_prover, is_dev_mode, sha::Digestible, ExecutorEnv, ProverOpts};
use serde::{Deserialize, Serialize};
use std::{ops::Range, sync::Arc};
use tendermint::block::Height;
use tendermint_proto::{types::Header as ProtoHeader, Protobuf};
use tendermint_rpc::HttpClient;
use tracing::{instrument, Level};

use crate::range_iterator::LightBlockRangeIterator;

// #[cfg(feature = "boundless")]
mod boundless;
// #[cfg(feature = "boundless")]
pub use boundless::BoundlessProver;

/// Output from generating a proof. This represents the data that will be posted to the contract on
/// chain.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofOutput {
    pub journal: Vec<u8>,
    pub seal: Vec<u8>,
}

#[async_trait]
pub trait Blobstream0Prover {
    /// Prove a range of serialized light client blocks as input.
    ///
    /// This is the only method needed to be implemented for each prover.
    async fn prove(&self, input: Vec<u8>) -> anyhow::Result<ProofOutput>;

    /// Prove a single block with the trusted light client block and the height to fetch and prove.
    #[instrument(
    target = "blobstream0::core",
    skip(self, input),
    fields(light_range = ?input.untrusted_height()..input.trusted_height()),
    err, level = Level::DEBUG)]
    async fn prove_block(&self, input: LightBlockProveData) -> anyhow::Result<ProofOutput> {
        let mut buffer = Vec::<u8>::new();
        assert_eq!(
            input.untrusted_height() - input.trusted_height() - 1,
            input.interval_headers.len() as u64
        );
        let expected_next_hash = input.untrusted_block.signed_header.header().hash();
        let expected_next_height = input.untrusted_height();
        let expected_trusted_hash = input.trusted_block.signed_header.header().hash();

        TrustedLightBlock {
            signed_header: input.trusted_block.signed_header,
            next_validators: input.trusted_block.next_validators,
        }
        .encode_length_delimited(&mut buffer)?;

        UntrustedLightBlock {
            signed_header: input.untrusted_block.signed_header,
            validators: input.untrusted_block.validators,
        }
        .encode_length_delimited(&mut buffer)?;

        for header in input.interval_headers {
            Protobuf::<ProtoHeader>::encode_length_delimited(header, &mut buffer)?;
        }

        let buffer_len: u32 = buffer
            .len()
            .try_into()
            .expect("buffer cannot exceed 32 bit range");

        tracing::debug!(target: "blobstream0::core", "Proving light client");

        let mut serialized_input = Vec::with_capacity(buffer_len as usize + 4);
        serialized_input.extend_from_slice(&buffer_len.to_le_bytes());
        serialized_input.extend_from_slice(&buffer);
        let proof = self.prove(serialized_input).await?;

        let commitment = RangeCommitment::abi_decode(&proof.journal, true)?;
        // Assert that what is proven is expected based on the inputs.
        assert_eq!(expected_next_hash.as_bytes(), commitment.newHeaderHash);
        assert_eq!(expected_next_height, commitment.newHeight);
        assert_eq!(
            expected_trusted_hash.as_bytes(),
            commitment.trustedHeaderHash.as_slice()
        );

        Ok(proof)
    }

    /// Fetches and proves a range of light client blocks.
    #[instrument(target = "blobstream0::core", skip(self, client), err, level = Level::INFO)]
    async fn prove_block_range(
        &self,
        client: Arc<HttpClient>,
        range: Range<u64>,
    ) -> anyhow::Result<ProofOutput> {
        // Include fetching the trusted light client block from before the range.
        let (trusted_block, blocks) = tokio::try_join!(
            super::fetch_trusted_light_block(&client, Height::try_from(range.start - 1)?),
            super::fetch_headers(client.clone(), range.start..range.end)
        )?;

        let mut range_iterator = LightBlockRangeIterator {
            client: &client,
            trusted_block,
            blocks: &blocks,
        };

        let inputs = range_iterator
            .next_range()
            .await?
            .context("unable to prove any blocks in the range")?;
        let receipt = self.prove_block(inputs).await?;

        Ok(receipt)
    }
}

// TODO move out Bonsai impl to optimize avoiding uploading ELF for each proof.
#[derive(Debug)]
pub struct Risc0Prover;

#[async_trait]
impl Blobstream0Prover for Risc0Prover {
    async fn prove(&self, input: Vec<u8>) -> anyhow::Result<ProofOutput> {
        let receipt = tokio::task::spawn_blocking(move || {
            let env = ExecutorEnv::builder().write_slice(&input).build()?;

            let prover = default_prover();
            prover.prove_with_opts(env, LIGHT_CLIENT_GUEST_ELF, &ProverOpts::groth16())
        })
        .await??
        .receipt;

        let seal = match is_dev_mode() {
            true => [&[0u8; 4], receipt.claim()?.digest().as_bytes()].concat(),
            false => groth16::encode(receipt.inner.groth16()?.seal.clone())?,
        };

        Ok(ProofOutput {
            journal: receipt.journal.bytes,
            seal,
        })
    }
}
