use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// TODO resolve public inputs
mod boundless;
mod local;
pub use boundless::BoundlessProver;

/// Output from generating a proof. This represents the data that will be posted to the contract on
/// chain.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofOutput {
    pub journal: Vec<u8>,
    pub seal: Vec<u8>,
}

#[async_trait]
pub trait AsyncProve {
    /// TODO docs
    async fn prove(&self, input: Vec<u8>) -> anyhow::Result<ProofOutput>;
}

