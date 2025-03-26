// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::{
    network::{Ethereum},
    primitives::{Address, U256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
        },
        Identity, Provider, ProviderBuilder, RootProvider,
    },
    rpc::types::BlockTransactionsKind,
    transports::{RpcError, TransportErrorKind},
};
use boundless_market::contracts::boundless_market::{BoundlessMarketService, MarketError};
use clap::Parser;
use thiserror::Error;
use tokio::time;
use url::Url;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum PulseError {
    #[error("Boundless market error: {0}")]
    BoundlessMarketError(#[from] MarketError),

    #[error("RPC error: {0}")]
    RpcError(#[from] RpcError<TransportErrorKind>),

    #[error("Event query error: {0}")]
    EventQueryError(#[from] alloy::contract::Error),

    #[error("Maximum retries reached")]
    MaxRetries,
}

type ProviderWallet = FillProvider<
    JoinFill<Identity, JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>
    >,
    RootProvider,
>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// RPC URL for the Ethereum node
    #[arg(long, env)]
    rpc_url: Url,

    /// Address of the BoundlessMarket contract
    #[arg(long, env)]
    boundless_market_address: Address,

    /// Starting block number (optional)
    #[arg(long, env)]
    starting_block: Option<u64>,

    /// Interval in seconds between pulse updates
    #[arg(long, default_value = "10")]
    interval: u64,

    /// Number of retries before giving up
    #[arg(long, default_value = "3")]
    retries: u32,
}

struct MarketStats {
    // Atomic counters for simple stats
    total_requests: AtomicU64,
    total_delivered: AtomicU64,
    total_expired: AtomicU64,
    
    period_requests: AtomicU64,
    period_delivered: AtomicU64,
    period_expired: AtomicU64,
    
    // Concurrent hashmap for active requests
    active_requests: RwLock<HashMap<U256, u64>>,
}

impl MarketStats {
    fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            total_delivered: AtomicU64::new(0),
            total_expired: AtomicU64::new(0),
            period_requests: AtomicU64::new(0),
            period_delivered: AtomicU64::new(0),
            period_expired: AtomicU64::new(0),
            active_requests: Default::default(),
        }
    }
    
    fn increment_total_requests(&self, count: u64) {
        self.total_requests.fetch_add(count, Ordering::SeqCst);
        self.period_requests.fetch_add(count, Ordering::SeqCst);
    }
    
    fn increment_total_delivered(&self, count: u64) {
        self.total_delivered.fetch_add(count, Ordering::SeqCst);
        self.period_delivered.fetch_add(count, Ordering::SeqCst);
    }
    
    fn increment_total_expired(&self, count: u64) {
        self.total_expired.fetch_add(count, Ordering::SeqCst);
        self.period_expired.fetch_add(count, Ordering::SeqCst);
    }
    
    fn reset_period_stats(&self) {
        self.period_requests.store(0, Ordering::SeqCst);
        self.period_delivered.store(0, Ordering::SeqCst);
        self.period_expired.store(0, Ordering::SeqCst);
    }
}

struct MarketPulseMonitor<P> {
    boundless_market: BoundlessMarketService<P>,
    stats: Arc<MarketStats>,
    interval: Duration,
    retries: u32,
    last_processed_block: u64,
}

impl MarketPulseMonitor<ProviderWallet> {
    fn new(
        rpc_url: Url,
        market_address: Address,
        interval: Duration,
        retries: u32,
    ) -> Result<Self, PulseError> {
        // Set up the provider
        let provider = ProviderBuilder::new().on_http(rpc_url);

        // Create the BoundlessMarket service
        let boundless_market = BoundlessMarketService::new(
            market_address,
            provider,
            Address::ZERO, // Caller address not important for read-only operations
        );

        Ok(Self {
            boundless_market,
            stats: Arc::new(MarketStats::new()),
            interval,
            retries,
            last_processed_block: 0,
        })
    }
}

impl<P> MarketPulseMonitor<P>
where
    P: Provider<Ethereum> + 'static + Clone,
{
    async fn run(mut self, starting_block: Option<u64>) -> Result<(), PulseError> {
        let mut interval = time::interval(self.interval);
        let current_block = self.current_block().await?;
        self.last_processed_block = starting_block.unwrap_or(current_block);
        let mut from_block = self.last_processed_block;

        let mut attempt = 0;

        loop {
            interval.tick().await;
            
            match self.current_block().await {
                Ok(to_block) => {
                    if to_block <= from_block {
                        continue;
                    }

                    tracing::info!("Processing blocks from {} to {}", from_block, to_block);

                    match self.process_blocks(from_block, to_block).await {
                        Ok(_) => {
                            attempt = 0;
                            from_block = to_block + 1;
                            self.last_processed_block = to_block;
                            
                            // Print the pulse
                            self.print_pulse().await;
                            
                            // Reset period stats
                            self.stats.reset_period_stats();
                        }
                        Err(e) => {
                            attempt += 1;
                            tracing::warn!(
                                "Failed to process blocks from {} to {}: {:?}, attempt number {}",
                                from_block,
                                to_block,
                                e,
                                attempt
                            );

                            if attempt > self.retries {
                                return Err(PulseError::MaxRetries);
                            }
                        }
                    }
                }
                Err(e) => {
                    attempt += 1;
                    tracing::warn!("Failed to get current block: {:?}, attempt number {}", e, attempt);

                    if attempt > self.retries {
                        return Err(PulseError::MaxRetries);
                    }
                }
            }
        }
    }

    async fn process_blocks(&self, from: u64, to: u64) -> Result<(), PulseError> {
        // Process locked events
        self.process_locked_events(from, to).await?;

        // Process delivered proofs
        self.process_proof_delivered_events(from, to).await?;

        // Process fulfilled events
        self.process_fulfilled_events(from, to).await?;

        // Process expired requests
        self.process_expired_requests(to).await?;

        Ok(())
    }

    async fn process_locked_events(&self, from_block: u64, to_block: u64) -> Result<(), PulseError> {
        let event_filter = self
            .boundless_market
            .instance()
            .RequestLocked_filter()
            .from_block(from_block)
            .to_block(to_block);

        // Query the logs for the event
        let logs = event_filter.query().await?;
        tracing::info!(
            "Found {} locked events from block {} to block {}",
            logs.len(),
            from_block,
            to_block
        );

        if !logs.is_empty() {
            self.stats.increment_total_requests(logs.len() as u64);

            for (log, _) in logs {
                // Get the deadline for this request
                match self.boundless_market.instance().requestDeadline(log.requestId).call().await {
                    Ok(deadline) => {
                        let mut active_requests = self.stats.active_requests.write().await;
                        active_requests.insert(log.requestId, deadline._0);
                        tracing::debug!(
                            "Added request 0x{:x} with deadline {}",
                            log.requestId,
                            deadline._0
                        );
                    },
                    Err(e) => {
                        tracing::warn!("Failed to get deadline for request 0x{:x}: {:?}", log.requestId, e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn process_proof_delivered_events(&self, from_block: u64, to_block: u64) -> Result<(), PulseError> {
        let event_filter = self
            .boundless_market
            .instance()
            .ProofDelivered_filter()
            .from_block(from_block)
            .to_block(to_block);

        // Query the logs for the event
        let logs = event_filter.query().await?;
        tracing::info!(
            "Found {} proof delivered events from block {} to block {}",
            logs.len(),
            from_block,
            to_block
        );

        if !logs.is_empty() {
            self.stats.increment_total_delivered(logs.len() as u64);

            for (log, _) in logs {
                let mut active_requests = self.stats.active_requests.write().await;
                active_requests.remove(&log.requestId);
                tracing::debug!("Removed delivered request 0x{:x}", log.requestId);
            }
        }

        Ok(())
    }

    async fn process_fulfilled_events(&self, from_block: u64, to_block: u64) -> Result<(), PulseError> {
        let event_filter = self
            .boundless_market
            .instance()
            .RequestFulfilled_filter()
            .from_block(from_block)
            .to_block(to_block);

        // Query the logs for the event
        let logs = event_filter.query().await?;
        tracing::info!(
            "Found {} fulfilled events from block {} to block {}",
            logs.len(),
            from_block,
            to_block
        );

            for (log, _) in logs {
                let mut active_requests = self.stats.active_requests.write().await;
                active_requests.remove(&log.requestId);
                tracing::debug!("Removed fulfilled request 0x{:x}", log.requestId);
            }

        Ok(())
    }

    async fn process_expired_requests(&self, current_block: u64) -> Result<(), PulseError> {
        let current_timestamp = self.block_timestamp(current_block).await?;
        let mut expired_requests = Vec::new();
        
        {
            let active_requests = self.stats.active_requests.read().await;
            for (request_id, deadline) in active_requests.iter() {
                if current_timestamp > *deadline {
                    expired_requests.push(*request_id);
                }
            }
        }
        
        if !expired_requests.is_empty() {
            self.stats.increment_total_expired(expired_requests.len() as u64);
            
            let mut active_requests = self.stats.active_requests.write().await;
            for request_id in expired_requests {
                active_requests.remove(&request_id);
                tracing::debug!("Marked request 0x{:x} as expired", request_id);
            }
        }

        Ok(())
    }

    async fn current_block(&self) -> Result<u64, PulseError> {
        Ok(self.boundless_market.instance().provider().get_block_number().await?)
    }

    async fn block_timestamp(&self, block_number: u64) -> Result<u64, PulseError> {
        Ok(self
            .boundless_market
            .instance()
            .provider()
            .get_block_by_number(block_number.into(), BlockTransactionsKind::Hashes)
            .await?
            .unwrap()
            .header
            .timestamp)
    }

    async fn print_pulse(&self) {
        let active_count = self.stats.active_requests.read().await.len();
        
        println!("=== BOUNDLESS MARKET PULSE ===");
        println!("Time: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
        println!("Last processed block: {}", self.last_processed_block);
        println!("Active Requests: {}", active_count);
        println!("Period Stats (last {} seconds):", self.interval.as_secs());
        println!("  New Requests: {}", self.stats.period_requests.load(Ordering::SeqCst));
        println!("  Delivered Proofs: {}", self.stats.period_delivered.load(Ordering::SeqCst));
        println!("  Expired Requests: {}", self.stats.period_expired.load(Ordering::SeqCst));
        println!("Cumulative Stats:");
        println!("  Total Requests: {}", self.stats.total_requests.load(Ordering::SeqCst));
        println!("  Total Delivered: {}", self.stats.total_delivered.load(Ordering::SeqCst));
        println!("  Total Expired: {}", self.stats.total_expired.load(Ordering::SeqCst));
        println!("===============================");
    }
}

#[tokio::main]
async fn main() -> Result<(), PulseError> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args = Args::parse();

    // Create the market pulse monitor
    let monitor = MarketPulseMonitor::new(
        args.rpc_url,
        args.boundless_market_address,
        Duration::from_secs(args.interval),
        args.retries,
    )?;

    // Run the monitor
    println!("Starting Market Pulse Monitor...");
    println!("Monitoring BoundlessMarket at: {}", args.boundless_market_address);
    println!("Pulse interval: {} seconds", args.interval);
    
    monitor.run(args.starting_block).await
}
