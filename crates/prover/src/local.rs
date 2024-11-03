use crate::{AsyncProve, ProofOutput};
use async_trait::async_trait;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_prover, is_dev_mode, sha::Digestible, ExecutorEnv, ProverOpts};

// TODO move out Bonsai impl to optimize avoiding uploading ELF for each proof.
#[derive(Debug)]
pub struct LocalProver {
    elf: &'static [u8],
}

#[async_trait]
impl AsyncProve for LocalProver {
    async fn prove(&self, input: Vec<u8>) -> anyhow::Result<ProofOutput> {
        let elf = self.elf;
        let receipt = tokio::task::spawn_blocking(move || {
            let env = ExecutorEnv::builder().write_slice(&input).build()?;

            let prover = default_prover();
            prover.prove_with_opts(env, elf, &ProverOpts::groth16())
        })
        .await??
        .receipt;

        let seal = match is_dev_mode() {
            true => [&[0u8; 4], receipt.claim()?.digest().as_bytes()].concat(),
            false => groth16::encode(receipt.inner.groth16()?.seal.clone())?,
        };

        Ok(ProofOutput { journal: receipt.journal.bytes, seal })
    }
}
