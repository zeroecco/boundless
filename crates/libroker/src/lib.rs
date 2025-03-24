use std::{sync::Arc, time::SystemTime};

use alloy::{primitives::{Address, Bytes, U256}, providers::Provider};
use boundless_market::contracts::{boundless_market::BoundlessMarketService, ProofRequest};
use broker::{config::ConfigLock, provers::ProverObj};
use risc0_ethereum_contracts::set_verifier::SetVerifierService;
use risc0_zkvm::sha::Digest;
use tokio::sync::{watch, OnceCell, OwnedSemaphorePermit, Semaphore};

mod pricing;
mod lock;
mod prove;
mod aggregator;
mod submitter;

pub use pricing::{OrderLockTiming, PriceOrderErr};

pub struct State<P> {
    pub block_number_receiver: watch::Receiver<u64>,
    pub prover: ProverObj,
    pub config: ConfigLock,
    pub market: BoundlessMarketService<P>,
    pub concurrent_locks: Arc<Semaphore>,

    // TODO split into separate state for aggregator.
    pub set_builder_guest_id: Digest,
    pub assessor_guest_id: Digest,
    pub set_verifier: SetVerifierService<P>,
    pub prover_address: Address,
}

#[derive(Debug)]
pub struct Order {
    /// Proof request object
    pub request: ProofRequest,
    // /// status of the order
    // status: OrderStatus,
    /// Client Signature
    pub client_sig: Bytes,
    // /// Last update time
    // #[serde(with = "ts_seconds")]
    // updated_at: DateTime<Utc>,
    /// Locking status target UNIX timestamp
    pub target_timestamp: Option<u64>,
    // TODO perhaps these should be persisted to avoid duplicate logic and re-uploads
    pub image_url: OnceCell<String>,
    pub input_url: OnceCell<String>,
    pub semaphore_permit: Option<OwnedSemaphorePermit>,
    /// Proof Id
    ///
    /// Populated after proof completion
    pub proof_id: Option<String>,
    // /// UNIX timestamp the order expires at
    // ///
    // /// Populated during order picking
    // expire_timestamp: Option<u64>,
    // /// Price the lockin was set at
    // lock_price: Option<U256>,
    // /// Failure message
    // error_msg: Option<String>,
}

impl Order {
    pub fn new(request: ProofRequest, client_sig: Bytes) -> Self {
        Self {
            request,
            client_sig,
            target_timestamp: None,
            image_url: OnceCell::new(),
            input_url: OnceCell::new(),
            semaphore_permit: None,
            proof_id: None,
        }
    }

    pub fn id(&self) -> &U256 {
        &self.request.id
    }
}

impl<P> State<P> {
    pub fn provider(&self) -> &P
    where
        P: Provider,
    {
        self.market.instance().provider()
    }
}

// TODO remove duplicate function declaration
pub fn now_timestamp_secs() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

