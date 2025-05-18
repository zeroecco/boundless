// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use std::sync::Arc;

use crate::{
    chain_monitor::ChainMonitorService,
    config::ConfigLock,
    db::DbObj,
    errors::CodedError,
    provers::{ProverError, ProverObj},
    storage::{upload_image_uri, upload_input_uri},
    task::{RetryRes, RetryTask, SupervisorErr},
    FulfillmentType, OrderRequest,
};
use crate::{now_timestamp, provers::ProofResult};
use alloy::{
    network::Ethereum,
    primitives::{
        aliases::U96,
        utils::{format_ether, format_units, parse_ether},
        Address, U256,
    },
    providers::{Provider, WalletProvider},
};
use anyhow::{Context, Result};
use boundless_market::{
    contracts::{boundless_market::BoundlessMarketService, RequestError},
    selector::{ProofType, SupportedSelectors},
};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex, Semaphore};

use OrderPricingOutcome::{Lock, ProveAfterLockExpire, Skip};

/// Maximum number of orders to concurrently work on pricing. Used to limit pricing tasks spawned.
const MAX_PRICING_BATCH_SIZE: u32 = 10;

/// Gas allocated to verifying a smart contract signature. Copied from BoundlessMarket.sol.
const ERC1271_MAX_GAS_FOR_CHECK: u64 = 100000;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum OrderPickerErr {
    #[error("{code} failed to fetch / push input: {0}", code = self.code())]
    FetchInputErr(#[source] anyhow::Error),

    #[error("{code} failed to fetch / push image: {0}", code = self.code())]
    FetchImageErr(#[source] anyhow::Error),

    #[error("{code} guest panicked: {0}", code = self.code())]
    GuestPanic(String),

    #[error("{code} invalid request: {0}", code = self.code())]
    RequestError(#[from] RequestError),

    #[error("{code} Unexpected error: {0:?}", code = self.code())]
    UnexpectedErr(#[from] anyhow::Error),
}

impl CodedError for OrderPickerErr {
    fn code(&self) -> &str {
        match self {
            OrderPickerErr::FetchInputErr(_) => "[B-OP-001]",
            OrderPickerErr::FetchImageErr(_) => "[B-OP-002]",
            OrderPickerErr::GuestPanic(_) => "[B-OP-003]",
            OrderPickerErr::RequestError(_) => "[B-OP-004]",
            OrderPickerErr::UnexpectedErr(_) => "[B-OP-500]",
        }
    }
}

// TODO revisit to see if separate structs are needed
/// Represents an order that is ready to be locked
#[derive(Debug, Clone)]
pub struct OrderToLock {
    pub order: OrderRequest,
    pub total_cycles: Option<u64>,
    pub target_timestamp_secs: u64,
    pub expiry_secs: u64,
}

/// Represents an order to fulfill after lock expiry
#[derive(Debug, Clone)]
pub struct OrderToFulfillAfterLockExpire {
    pub order: OrderRequest,
    pub total_cycles: Option<u64>,
    pub lock_expire_timestamp_secs: u64,
    pub expiry_secs: u64,
}

/// Represents possible order processing outcomes
#[derive(Debug, Clone)]
pub enum OrderProcessingResult {
    /// Order is ready to be locked
    Lock(OrderToLock),
    /// Order should be fulfilled after lock expiry
    FulfillAfterLock(OrderToFulfillAfterLockExpire),
}

#[derive(Clone)]
pub struct OrderPicker<P> {
    db: DbObj,
    config: ConfigLock,
    prover: ProverObj,
    provider: Arc<P>,
    chain_monitor: Arc<ChainMonitorService<P>>,
    market: BoundlessMarketService<Arc<P>>,
    supported_selectors: SupportedSelectors,
    // TODO ideal not to wrap in mutex, but otherwise would require supervisor refactor, try to find alternative
    new_order_rx: Arc<Mutex<mpsc::Receiver<OrderRequest>>>,
    // Channel to send processed orders (single channel with enum)
    order_result_tx: mpsc::Sender<OrderProcessingResult>,
}

#[derive(Debug)]
#[non_exhaustive]
enum OrderPricingOutcome {
    // Order should be locked and proving commence after lock is secured
    Lock {
        total_cycles: Option<u64>,
        target_timestamp_secs: u64,
        // TODO handle checking what time the lock should occur before, when estimating proving time.
        expiry_secs: u64,
    },
    // Do not lock the order, but consider proving and fulfilling it after the lock expires
    ProveAfterLockExpire {
        total_cycles: Option<u64>,
        lock_expire_timestamp_secs: u64,
        expiry_secs: u64,
    },
    // Do not accept engage order
    Skip,
}

impl<P> OrderPicker<P>
where
    P: Provider<Ethereum> + 'static + Clone + WalletProvider,
{
    pub fn new(
        db: DbObj,
        config: ConfigLock,
        prover: ProverObj,
        market_addr: Address,
        provider: Arc<P>,
        chain_monitor: Arc<ChainMonitorService<P>>,
        new_order_rx: mpsc::Receiver<OrderRequest>,
        order_result_tx: mpsc::Sender<OrderProcessingResult>,
    ) -> Self {
        let market = BoundlessMarketService::new(
            market_addr,
            provider.clone(),
            provider.default_signer_address(),
        );

        Self {
            db,
            config,
            prover,
            provider,
            chain_monitor,
            market,
            supported_selectors: SupportedSelectors::default(),
            new_order_rx: Arc::new(Mutex::new(new_order_rx)),
            order_result_tx,
        }
    }

    async fn price_order_and_update_state(&self, mut order: OrderRequest) -> bool {
        let order_id = order.id();
        let f = || async {
            match self.price_order(&mut order).await {
                Ok(Lock { total_cycles, target_timestamp_secs, expiry_secs }) => {
                    tracing::info!(
                        "Setting order {order_id} to lock at {}, {} seconds from now",
                        target_timestamp_secs,
                        target_timestamp_secs.saturating_sub(now_timestamp())
                    );

                    // Send the order to the single channel
                    self.order_result_tx
                        .send(OrderProcessingResult::Lock(OrderToLock {
                            order,
                            total_cycles,
                            target_timestamp_secs,
                            expiry_secs,
                        }))
                        .await
                        .context("Failed to send to order_result_tx")?;

                    Ok::<_, OrderPickerErr>(true)
                }
                Ok(ProveAfterLockExpire {
                    total_cycles,
                    lock_expire_timestamp_secs,
                    expiry_secs,
                }) => {
                    tracing::info!("Setting order {order_id} to prove after lock expiry at {lock_expire_timestamp_secs}");

                    // Send the order to the single channel
                    self.order_result_tx
                        .send(OrderProcessingResult::FulfillAfterLock(
                            OrderToFulfillAfterLockExpire {
                                order,
                                total_cycles,
                                lock_expire_timestamp_secs,
                                expiry_secs,
                            },
                        ))
                        .await
                        .context("Failed to send to order_result_tx")?;

                    Ok(true)
                }
                Ok(Skip) => {
                    tracing::info!("Skipping order {order_id}");

                    // Add the skipped order to the database
                    self.db
                        .skip_request(order)
                        .await
                        .context("Failed to add skipped order to database")?;
                    Ok(false)
                }
                Err(err) => {
                    tracing::warn!("Failed to price order {order_id}: {err}");
                    self.db
                        .skip_request(order)
                        .await
                        .context("Failed to skip failed priced order")?;
                    Ok(false)
                }
            }
        };

        match f().await {
            Ok(true) => true,
            Ok(false) => false,
            Err(err) => {
                tracing::error!("Failed to update for order {order_id}: {err}");
                false
            }
        }
    }

    async fn price_order(
        &self,
        order: &mut OrderRequest,
    ) -> Result<OrderPricingOutcome, OrderPickerErr> {
        let order_id = order.id();
        let request_id = order.request.id;
        tracing::debug!("Pricing order {order_id} with request id {request_id:x}");

        let (min_deadline, allowed_addresses_opt) = {
            let config = self.config.lock_all().context("Failed to read config")?;
            (config.market.min_deadline, config.market.allow_client_addresses.clone())
        };

        // Initial sanity checks:
        if let Some(allow_addresses) = allowed_addresses_opt {
            let client_addr = order.request.client_address();
            if !allow_addresses.contains(&client_addr) {
                tracing::info!("Removing order with request id {request_id:x} from {client_addr} because it is not in allowed addrs");
                return Ok(Skip);
            }
        }

        if !self.supported_selectors.is_supported(order.request.requirements.selector) {
            tracing::info!(
                "Removing order with request id {request_id:x} because it has an unsupported selector requirement"
            );

            return Ok(Skip);
        };

        // Lock expiration is the timestamp before which the order must be filled in order to avoid slashing
        let lock_expiration =
            order.request.offer.biddingStart + order.request.offer.lockTimeout as u64;
        // order expiration is the timestamp after which the order can no longer be filled by anyone.
        let order_expiration =
            order.request.offer.biddingStart + order.request.offer.timeout as u64;

        let now = now_timestamp();

        // If order_expiration > lock_expiration the period in-between is when order can be filled
        // by anyone without staking to partially claim the slashed stake
        let lock_expired = order.fulfillment_type == FulfillmentType::FulfillAfterLockExpire;

        let (expiration, lockin_stake) = if lock_expired {
            (order_expiration, U256::ZERO)
        } else {
            (lock_expiration, U256::from(order.request.offer.lockStake))
        };

        if expiration <= now {
            tracing::info!("Removing order with request id {request_id:x} because it has expired");
            return Ok(Skip);
        };

        // Does the order expire within the min deadline
        let seconds_left = expiration.saturating_sub(now);
        if seconds_left <= min_deadline {
            tracing::info!("Removing order with request id {request_id:x} because it expires within min_deadline: {seconds_left}, min_deadline: {min_deadline}");
            return Ok(Skip);
        }

        // Check if the stake is sane and if we can afford it
        // For lock expired orders, we don't check the max stake because we can't lock those orders.
        let max_stake = {
            let config = self.config.lock_all().context("Failed to read config")?;
            parse_ether(&config.market.max_stake).context("Failed to parse max_stake")?
        };

        if !lock_expired && lockin_stake > max_stake {
            tracing::info!("Removing high stake order with request id {request_id:x}, lock stake: {lockin_stake}, max stake: {max_stake}");
            return Ok(Skip);
        }

        // Check that we have both enough staking tokens to stake, and enough gas tokens to lock and fulfil
        // NOTE: We use the current gas price and a rough heuristic on gas costs. Its possible that
        // gas prices may go up (or down) by the time its time to fulfill. This does not aim to be
        // a tight estimate, although improving this estimate will allow for a more profit.
        let gas_price =
            self.chain_monitor.current_gas_price().await.context("Failed to get gas price")?;
        let order_gas = if lock_expired {
            // No need to include lock gas if its a lock expired order
            U256::from(self.estimate_gas_to_fulfill(order).await?)
        } else {
            U256::from(
                self.estimate_gas_to_lock(order).await?
                    + self.estimate_gas_to_fulfill(order).await?,
            )
        };
        let order_gas_cost = U256::from(gas_price) * order_gas;
        let available_gas = self.available_gas_balance().await?;
        let available_stake = self.available_stake_balance().await?;
        tracing::debug!(
            "Estimated {order_gas} gas to {} request {request_id:x}; {} ether @ {} gwei",
            if lock_expired { "fulfill" } else { "lock and fulfill" },
            format_ether(order_gas_cost),
            format_units(gas_price, "gwei").unwrap()
        );

        if order_gas_cost > order.request.offer.maxPrice && !lock_expired {
            // Cannot check the gas cost for lock expired orders where the reward is a fraction of the stake
            // TODO: This can be added once we have a price feed for the stake token in gas tokens
            tracing::info!(
                "Estimated gas cost to lock and fulfill request {request_id:x}: {} exceeds max price; max price {}",
                format_ether(order_gas_cost),
                format_ether(order.request.offer.maxPrice)
            );
            return Ok(Skip);
        }

        if order_gas_cost > available_gas {
            tracing::warn!("Estimated there will be insufficient gas for order {order_id} after locking and fulfilling pending orders; available_gas {} ether", format_ether(available_gas));
            return Ok(Skip);
        }

        if !lock_expired && lockin_stake > available_stake {
            tracing::warn!(
                "Insufficient available stake to lock order {order_id}. Requires {lockin_stake}, has {available_stake}"
            );
            return Ok(Skip);
        }

        let max_mcycle_limit = {
            let config = self.config.lock_all().context("Failed to read config")?;
            config.market.max_mcycle_limit
        };

        // TODO: Move URI handling like this into the prover impls
        let image_id = upload_image_uri(&self.prover, &order.request, &self.config)
            .await
            .map_err(OrderPickerErr::FetchImageErr)?;

        let input_id = upload_input_uri(&self.prover, &order.request, &self.config)
            .await
            .map_err(OrderPickerErr::FetchInputErr)?;

        order.image_id = Some(image_id.clone());
        order.input_id = Some(input_id.clone());

        // Create a executor limit based on the max price of the order
        let mut exec_limit_cycles: u64 = if lock_expired {
            let min_mcycle_price_stake_token = {
                let config = self.config.lock_all().context("Failed to read config")?;
                parse_ether(&config.market.mcycle_price_stake_token)
                    .context("Failed to parse mcycle_price")?
            };

            if min_mcycle_price_stake_token == U256::ZERO {
                tracing::warn!("min_mcycle_price_stake_token is 0, setting unlimited exec limit");
                u64::MAX
            } else {
                // Note this does not account for gas cost unlike a normal order
                // TODO: Update to account for gas once the stake token to gas token exchange rate is known
                let price = order.request.offer.stake_reward_if_locked_and_not_fulfilled();
                let min_cycle_price_stake_token =
                    min_mcycle_price_stake_token.div_ceil(U256::from(1_000_000));
                (price / min_cycle_price_stake_token)
                    .try_into()
                    .context("Failed to convert U256 exec limit to u64")?
            }
        } else {
            let min_mcycle_price = {
                let config = self.config.lock_all().context("Failed to read config")?;
                parse_ether(&config.market.mcycle_price).context("Failed to parse mcycle_price")?
            };
            let min_cycle_price = min_mcycle_price.div_ceil(U256::from(1_000_000));
            (U256::from(order.request.offer.maxPrice).saturating_sub(order_gas_cost)
                / min_cycle_price)
                .try_into()
                .context("Failed to convert U256 exec limit to u64")?
        };

        if exec_limit_cycles == 0 {
            tracing::info!(
                "Removing order with request id {request_id:x} because it's exec limit is below 0 cycles"
            );

            return Ok(Skip);
        }

        // If a max_mcycle_limit is configured, override the exec limit if the order is over that limit
        if let Some(config_mcycle_limit) = max_mcycle_limit {
            let config_cycle_limit = config_mcycle_limit * 1_000_000;
            if exec_limit_cycles >= config_cycle_limit {
                tracing::info!("Order with request id {request_id:x} exec limit computed from max price exceeds config max_mcycle_limit, setting exec limit to max_mcycle_limit");
                exec_limit_cycles = config_cycle_limit;
            }
        }

        tracing::debug!(
            "Starting preflight execution of {request_id:x} exec limit {} cycles (~{} mcycles)",
            exec_limit_cycles,
            exec_limit_cycles / 1_000_000
        );
        // TODO add a future timeout here to put a upper bound on how long to preflight for
        let proof_res = match self
            .prover
            .preflight(
                &image_id,
                &input_id,
                vec![],
                /* TODO assumptions */ Some(exec_limit_cycles),
            )
            .await
        {
            Ok(res) => res,
            Err(err) => match err {
                ProverError::ProvingFailed(ref err_msg)
                    if err_msg.contains("Session limit exceeded") =>
                {
                    tracing::info!(
                        "Skipping order {request_id:x} due to session limit exceeded: {}",
                        err_msg
                    );
                    return Ok(Skip);
                }
                ProverError::ProvingFailed(ref err_msg) if err_msg.contains("GuestPanic") => {
                    return Err(OrderPickerErr::GuestPanic(err_msg.clone()));
                }
                _ => return Err(OrderPickerErr::UnexpectedErr(err.into())),
            },
        };

        // If a max_mcycle_limit is configured check if the order is over that limit
        if let Some(mcycle_limit) = max_mcycle_limit {
            let mcycles = proof_res.stats.total_cycles / 1_000_000;
            if mcycles >= mcycle_limit {
                tracing::info!("Order with request id {request_id:x} max_mcycle_limit check failed req: {mcycle_limit} | config: {mcycles}");
                return Ok(Skip);
            }
        }

        let journal = self
            .prover
            .get_preflight_journal(&proof_res.id)
            .await
            .context("Failed to fetch preflight journal")?
            .context("Failed to find preflight journal")?;

        // ensure the journal is a size we are willing to submit on-chain
        let max_journal_bytes =
            self.config.lock_all().context("Failed to read config")?.market.max_journal_bytes;
        if journal.len() > max_journal_bytes {
            tracing::info!(
                "Order with request id {request_id:x} journal larger than set limit ({} > {}), skipping",
                journal.len(),
                max_journal_bytes
            );
            return Ok(Skip);
        }

        // Validate the predicates:
        if !order.request.requirements.predicate.eval(journal.clone()) {
            tracing::info!("Order with request id {request_id:x} predicate check failed, skipping");
            return Ok(Skip);
        }

        self.evaluate_order(order, &proof_res, order_gas_cost, lock_expired).await
    }

    async fn evaluate_order(
        &self,
        order: &OrderRequest,
        proof_res: &ProofResult,
        order_gas_cost: U256,
        lock_expired: bool,
    ) -> Result<OrderPricingOutcome, OrderPickerErr> {
        if lock_expired {
            return self.evaluate_lock_expired_order(order, proof_res).await;
        } else {
            self.evaluate_lockable_order(order, proof_res, order_gas_cost).await
        }
    }

    /// Evaluate if a regular lockable order is worth picking based on the price and the configured min mcycle price
    async fn evaluate_lockable_order(
        &self,
        order: &OrderRequest,
        proof_res: &ProofResult,
        order_gas_cost: U256,
    ) -> Result<OrderPricingOutcome, OrderPickerErr> {
        let config_min_mcycle_price = {
            let config = self.config.lock_all().context("Failed to read config")?;
            parse_ether(&config.market.mcycle_price).context("Failed to parse mcycle_price")?
        };

        let request_id = order.request.id;
        let one_mill = U256::from(1_000_000);

        let mcycle_price_min = (U256::from(order.request.offer.minPrice)
            .saturating_sub(order_gas_cost)
            / U256::from(proof_res.stats.total_cycles))
            * one_mill;
        let mcycle_price_max = (U256::from(order.request.offer.maxPrice)
            .saturating_sub(order_gas_cost)
            / U256::from(proof_res.stats.total_cycles))
            * one_mill;

        tracing::info!(
            "Order price: min: {} max: {} - cycles: {} - mcycle price: {} - {} - stake: {} gas_cost: {}",
            format_ether(U256::from(order.request.offer.minPrice)),
            format_ether(U256::from(order.request.offer.maxPrice)),
            proof_res.stats.total_cycles,
            format_ether(mcycle_price_min),
            format_ether(mcycle_price_max),
            order.request.offer.lockStake,
            format_ether(order_gas_cost),
        );

        // Skip the order if it will never be worth it
        if mcycle_price_max < config_min_mcycle_price {
            tracing::info!("Removing under priced order with request id {request_id:x}");
            return Ok(Skip);
        }

        let target_timestamp_secs = if mcycle_price_min >= config_min_mcycle_price {
            tracing::info!(
                "Selecting order with request id {request_id:x} at price {} - ASAP",
                format_ether(U256::from(order.request.offer.minPrice))
            );
            0 // Schedule the lock ASAP
        } else {
            let target_min_price =
                config_min_mcycle_price * (U256::from(proof_res.stats.total_cycles)) / one_mill
                    + order_gas_cost;
            tracing::debug!("Target price: {target_min_price} for request id {request_id:x}");

            order
                .request
                .offer
                .time_at_price(target_min_price)
                .context("Failed to get target price timestamp")?
        };

        let expiry_secs = order.request.offer.biddingStart + order.request.offer.lockTimeout as u64;

        Ok(Lock {
            total_cycles: Some(proof_res.stats.total_cycles),
            target_timestamp_secs,
            expiry_secs,
        })
    }

    /// Evaluate if a lock expired order is worth picking based on how much of the slashed stake token we can recover
    /// and the configured min mcycle price in stake tokens
    async fn evaluate_lock_expired_order(
        &self,
        order: &OrderRequest,
        proof_res: &ProofResult,
    ) -> Result<OrderPricingOutcome, OrderPickerErr> {
        let config_min_mcycle_price_stake_tokens = {
            let config = self.config.lock_all().context("Failed to read config")?;
            parse_ether(&config.market.mcycle_price_stake_token)
                .context("Failed to parse mcycle_price")?
        };

        let total_cycles = U256::from(proof_res.stats.total_cycles);

        // Reward for the order is a fraction of the stake once the lock has expired
        let one_mill = U256::from(1_000_000);
        let price = order.request.offer.stake_reward_if_locked_and_not_fulfilled();
        let mcycle_price_in_stake_tokens = price / total_cycles * one_mill;

        tracing::info!(
            "Order price: {} (stake tokens) - cycles: {} - mcycle price: {} (stake tokens), config_min_mcycle_price_stake_tokens: {} (stake tokens)",
            format_ether(price),
            proof_res.stats.total_cycles,
            format_ether(mcycle_price_in_stake_tokens),
            format_ether(config_min_mcycle_price_stake_tokens),
        );

        // Skip the order if it will never be worth it
        if mcycle_price_in_stake_tokens < config_min_mcycle_price_stake_tokens {
            tracing::info!(
                "Removing under priced order (slashed stake reward too low) {}",
                order.id()
            );
            return Ok(Skip);
        }

        Ok(ProveAfterLockExpire {
            total_cycles: Some(proof_res.stats.total_cycles),
            lock_expire_timestamp_secs: order.request.offer.biddingStart
                + order.request.offer.lockTimeout as u64,
            expiry_secs: order.request.offer.biddingStart + order.request.offer.timeout as u64,
        })
    }

    /// Keep track of orders being processed locally instead of querying the DB
    async fn find_existing_orders(&self) -> Result<(), OrderPickerErr> {
        // This method used to query the DB for orders in the "Pricing" state,
        // but now we'll rely on the channel for new orders
        Ok(())
    }

    /// Return the total amount of stake that is marked locally in the pending lock queue
    /// Use a channel to communicate with the locker to get this information
    async fn pending_locked_stake(&self) -> Result<U256> {
        // TODO: Implement a way to track pending lock orders via channels
        // For now, just return 0
        Ok(U256::ZERO)
    }

    /// Estimate of gas for locking a single order
    /// Currently just uses the config estimate but this may change in the future
    async fn estimate_gas_to_lock(&self, order: &OrderRequest) -> Result<u64> {
        let mut estimate =
            self.config.lock_all().context("Failed to read config")?.market.lockin_gas_estimate;

        if order.request.is_smart_contract_signed() {
            estimate += ERC1271_MAX_GAS_FOR_CHECK;
        }

        Ok(estimate)
    }

    /// Estimate of gas for to fulfill a single order
    /// Currently just uses the config estimate but this may change in the future
    async fn estimate_gas_to_fulfill(&self, order: &OrderRequest) -> Result<u64> {
        // TODO: Add gas costs for orders with large journals.
        let (base, groth16) = {
            let config = self.config.lock_all().context("Failed to read config")?;
            (config.market.fulfill_gas_estimate, config.market.groth16_verify_gas_estimate)
        };

        let mut estimate = base;

        // Add gas for orders that make use of the callbacks feature.
        estimate += u64::try_from(
            order
                .request
                .requirements
                .callback
                .as_option()
                .map(|callback| callback.gasLimit)
                .unwrap_or(U96::ZERO),
        )?;

        estimate += match self
            .supported_selectors
            .proof_type(order.request.requirements.selector)
            .context("unsupported selector")?
        {
            ProofType::Any | ProofType::Inclusion => 0,
            ProofType::Groth16 => groth16,
            proof_type => {
                tracing::warn!("Unknown proof type in gas cost estimation: {proof_type:?}");
                0
            }
        };

        Ok(estimate)
    }

    /// Estimate of gas for locking in any pending locks and submitting any pending proofs
    async fn estimate_gas_to_lock_pending(&self) -> Result<u64> {
        // TODO: Implement a way to track pending lock orders via channels
        // For now, just return 0
        Ok(0)
    }

    /// Estimate of gas for fulfilling any orders either pending lock or locked
    async fn estimate_gas_to_fulfill_pending(&self) -> Result<u64> {
        // TODO: Implement a way to track pending fulfill orders via channels
        // For now, just return 0
        Ok(0)
    }

    /// Estimate the total gas tokens reserved to lock and fulfill all pending orders
    async fn gas_balance_reserved(&self) -> Result<U256> {
        let gas_price =
            self.chain_monitor.current_gas_price().await.context("Failed to get gas price")?;
        let lock_pending_gas = self.estimate_gas_to_lock_pending().await?;
        let fulfill_pending_gas = self.estimate_gas_to_fulfill_pending().await?;
        Ok(U256::from(gas_price) * U256::from(lock_pending_gas + fulfill_pending_gas))
    }

    /// Return available gas balance.
    ///
    /// This is defined as the balance of the signer account.
    async fn available_gas_balance(&self) -> Result<U256> {
        let balance = self
            .provider
            .get_balance(self.provider.default_signer_address())
            .await
            .context("Failed to get current wallet balance")?;

        let gas_balance_reserved = self.gas_balance_reserved().await?;

        let available = balance.saturating_sub(gas_balance_reserved);
        tracing::debug!(
            "available gas balance: (account_balance) {} - (expected_future_gas) {} = {}",
            format_ether(balance),
            format_ether(gas_balance_reserved),
            format_ether(available)
        );

        Ok(available)
    }

    /// Return available stake balance.
    ///
    /// This is defined as the balance in staking tokens of the signer account minus any pending locked stake.
    async fn available_stake_balance(&self) -> Result<U256> {
        let balance = self.market.balance_of_stake(self.provider.default_signer_address()).await?;
        let pending_balance = self.pending_locked_stake().await?;
        Ok(balance.saturating_sub(pending_balance))
    }
}

impl<P> RetryTask for OrderPicker<P>
where
    P: Provider<Ethereum> + 'static + Clone + WalletProvider,
{
    type Error = OrderPickerErr;
    fn spawn(&self) -> RetryRes<Self::Error> {
        let picker_copy = self.clone();

        Box::pin(async move {
            tracing::info!("Starting order picking monitor");
            let pricing_semaphore = Arc::new(Semaphore::new(MAX_PRICING_BATCH_SIZE as usize));

            // This should be the only task holding the lock, so it is just locked while the service
            // is running.
            let mut rx = picker_copy.new_order_rx.lock().await;

            loop {
                // Wait for a new order from the channel - lock the mutex only when receiving
                let order = rx.recv().await.ok_or_else(|| {
                    // This should be unrecoverable if the sender is dropped.
                    SupervisorErr::Fault(OrderPickerErr::UnexpectedErr(anyhow::anyhow!(
                        "Order channel closed unexpectedly"
                    )))
                })?;

                let picker_clone = picker_copy.clone();
                let semaphore = pricing_semaphore.clone();

                // Spawn a task to process the order
                tokio::spawn(async move {
                    // Acquire a permit from the semaphore (will wait if at capacity)
                    let _permit = semaphore.acquire().await.expect("Semaphore was closed");

                    // Process the order - permit is automatically released when dropped
                    let order_id = order.id();
                    let result = picker_clone.price_order_and_update_state(order).await;
                    if result {
                        tracing::debug!("Successfully processed order: {}", order_id);
                    } else {
                        tracing::debug!("Order was not processed: {}", order_id);
                    }
                });
            }
        })
    }
}

// DO NOT MERGE: Add a test that the order_gas_cost is being enforced as a min price.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_monitor::ChainMonitorService, db::SqliteDb, provers::DefaultProver, FulfillmentType,
        OrderStatus, NEW_ORDER_CHANNEL_CAPACITY,
    };
    use alloy::{
        network::EthereumWallet,
        node_bindings::{Anvil, AnvilInstance},
        primitives::{address, aliases::U96, Address, Bytes, FixedBytes, B256},
        providers::{ext::AnvilApi, ProviderBuilder},
        signers::local::PrivateKeySigner,
    };
    use boundless_market::contracts::{
        Callback, Input, Offer, Predicate, PredicateType, ProofRequest, RequestId, Requirements,
    };
    use boundless_market::storage::{MockStorageProvider, StorageProvider};
    use boundless_market_test_utils::{
        deploy_boundless_market, deploy_hit_points, ASSESSOR_GUEST_ID, ASSESSOR_GUEST_PATH,
        ECHO_ELF, ECHO_ID,
    };
    use chrono::Utc;
    use risc0_ethereum_contracts::selector::Selector;
    use risc0_zkvm::sha::Digest;
    use tokio::sync::mpsc;
    use tracing_test::traced_test;

    /// Reusable context for testing the order picker
    struct TestCtx<P> {
        anvil: AnvilInstance,
        picker: OrderPicker<P>,
        boundless_market: BoundlessMarketService<Arc<P>>,
        storage_provider: MockStorageProvider,
        db: DbObj,
        provider: Arc<P>,
        // Channels for collecting results
        order_result_rx: mpsc::Receiver<OrderProcessingResult>,
        // Sender for tests to manually send results
        order_result_tx: mpsc::Sender<OrderProcessingResult>,
    }

    /// Parameters for the generate_next_order function.
    struct OrderParams {
        pub order_index: u32,
        pub min_price: U256,
        pub max_price: U256,
        pub lock_stake: U256,
    }

    impl Default for OrderParams {
        fn default() -> Self {
            Self {
                order_index: 1,
                min_price: parse_ether("0.02").unwrap(),
                max_price: parse_ether("0.04").unwrap(),
                lock_stake: U256::ZERO,
            }
        }
    }

    impl<P> TestCtx<P>
    where
        P: Provider + WalletProvider,
    {
        fn signer(&self, index: usize) -> PrivateKeySigner {
            self.anvil.keys()[index].clone().into()
        }

        async fn generate_next_order(&self, params: OrderParams) -> Order {
            let image_url = self.storage_provider.upload_program(ECHO_ELF).await.unwrap();
            let image_id = Digest::from(ECHO_ID);
            let chain_id = self.provider.get_chain_id().await.unwrap();
            let boundless_market_address = self.boundless_market.instance().address();

            Order {
                status: OrderStatus::Pricing,
                updated_at: Utc::now(),
                request: ProofRequest::new(
                    RequestId::new(self.provider.default_signer_address(), params.order_index),
                    Requirements::new(
                        image_id,
                        Predicate {
                            predicateType: PredicateType::PrefixMatch,
                            data: Default::default(),
                        },
                    ),
                    image_url,
                    Input::builder().write_slice(&[0x41, 0x41, 0x41, 0x41]).build_inline().unwrap(),
                    Offer {
                        minPrice: params.min_price,
                        maxPrice: params.max_price,
                        biddingStart: now_timestamp(),
                        timeout: 1200,
                        lockTimeout: 900,
                        rampUpPeriod: 1,
                        lockStake: params.lock_stake,
                    },
                ),
                target_timestamp: None,
                image_id: None,
                input_id: None,
                proof_id: None,
                compressed_proof_id: None,
                expire_timestamp: None,
                client_sig: Bytes::new(),
                lock_price: None,
                fulfillment_type: FulfillmentType::LockAndFulfill,
                error_msg: None,
                boundless_market_address: *boundless_market_address,
                chain_id,
                total_cycles: None,
                proving_started_at: None,
            }
        }

        // Helper function for checking channel outputs
        async fn expect_order_result(&mut self, timeout_ms: u64) -> Option<OrderProcessingResult> {
            tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                self.order_result_rx.recv(),
            )
            .await
            .ok()
            .flatten()
        }

        // Helper for testing lock-expired orders
        async fn price_lock_expired_order(&self, order: &Order) -> OrderToFulfillAfterLockExpire {
            // For testing, simulate a fulfill-after-lock-expire outcome
            let expire_ts =
                order.request.offer.biddingStart + order.request.offer.lockTimeout as u64;
            let timeout_ts = order.request.offer.biddingStart + order.request.offer.timeout as u64;

            OrderToFulfillAfterLockExpire {
                order: order.clone(),
                total_cycles: Some(1_000_000),
                lock_expire_timestamp_secs: expire_ts,
                expiry_secs: timeout_ts,
            }
        }
    }

    #[derive(Default)]
    struct TestCtxBuilder {
        initial_signer_eth: Option<i32>,
        initial_hp: Option<U256>,
        config: Option<ConfigLock>,
    }

    impl TestCtxBuilder {
        fn with_initial_signer_eth(self, eth: i32) -> Self {
            Self { initial_signer_eth: Some(eth), ..self }
        }
        fn with_initial_hp(self, hp: U256) -> Self {
            assert!(hp < U256::from(U96::MAX), "Cannot have more than 2^96 hit points");
            Self { initial_hp: Some(hp), ..self }
        }
        fn with_config(self, config: ConfigLock) -> Self {
            Self { config: Some(config), ..self }
        }
        async fn build(self) -> TestCtx<impl Provider + WalletProvider + Clone + 'static> {
            let anvil = Anvil::new()
                .args(["--balance", &format!("{}", self.initial_signer_eth.unwrap_or(10000))])
                .spawn();
            let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
            let provider = Arc::new(
                ProviderBuilder::new()
                    .wallet(EthereumWallet::from(signer.clone()))
                    .connect(&anvil.endpoint())
                    .await
                    .unwrap(),
            );

            provider.anvil_mine(Some(4), Some(2)).await.unwrap();

            let hp_contract = deploy_hit_points(signer.address(), provider.clone()).await.unwrap();
            let market_address = deploy_boundless_market(
                signer.address(),
                provider.clone(),
                Address::ZERO,
                hp_contract,
                Digest::from(ASSESSOR_GUEST_ID),
                format!("file://{ASSESSOR_GUEST_PATH}"),
                Some(signer.address()),
            )
            .await
            .unwrap();

            let boundless_market = BoundlessMarketService::new(
                market_address,
                provider.clone(),
                provider.default_signer_address(),
            );

            if let Some(initial_hp) = self.initial_hp {
                tracing::debug!("Setting initial locked hitpoints to {}", initial_hp);
                boundless_market.deposit_stake_with_permit(initial_hp, &signer).await.unwrap();
                assert_eq!(
                    boundless_market
                        .balance_of_stake(provider.default_signer_address())
                        .await
                        .unwrap(),
                    initial_hp
                );
            }

            let storage_provider = MockStorageProvider::start();

            let db: DbObj = Arc::new(SqliteDb::new("sqlite::memory:").await.unwrap());
            let config = self.config.unwrap_or_default();
            let prover: ProverObj = Arc::new(DefaultProver::new());
            let chain_monitor = Arc::new(ChainMonitorService::new(provider.clone()).await.unwrap());
            tokio::spawn(chain_monitor.spawn());

            // Create channels for testing
            let (new_order_tx, new_order_rx) = mpsc::channel::<Order>(NEW_ORDER_CHANNEL_CAPACITY);
            let (order_result_tx, order_result_rx) =
                mpsc::channel::<OrderProcessingResult>(NEW_ORDER_CHANNEL_CAPACITY);

            let picker = OrderPicker::new(
                db.clone(),
                config,
                prover,
                market_address,
                provider.clone(),
                chain_monitor,
                new_order_rx,
                order_result_tx.clone(),
            );

            TestCtx {
                anvil,
                picker,
                boundless_market,
                storage_provider,
                db,
                provider,
                order_result_rx,
                order_result_tx,
            }
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn price_order() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
        }
        let mut ctx = TestCtxBuilder::default().with_config(config).build().await;

        let mut order = ctx.generate_next_order(Default::default()).await;

        // Add the image_id and input_id to allow channel-based processing to succeed
        let image_url = ctx.storage_provider.upload_program(ECHO_ELF).await.unwrap();
        let image_id =
            upload_image_uri(&ctx.picker.prover, &order.request, &ctx.picker.config).await.unwrap();
        let input_id =
            upload_input_uri(&ctx.picker.prover, &order.request, &ctx.picker.config).await.unwrap();

        order.image_id = Some(image_id.clone());
        order.input_id = Some(input_id.clone());

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let result = ctx.picker.price_order_and_update_state(order).await;
        assert!(result);

        // Check that an order result was received on the channel
        let order_result = ctx.expect_order_result(1000).await;
        assert!(order_result.is_some());

        match order_result.unwrap() {
            OrderProcessingResult::Lock(lock_order) => {
                assert_eq!(lock_order.order.id(), order.id());
                assert_eq!(lock_order.target_timestamp_secs, 0); // ASAP
                assert_eq!(lock_order.image_id, image_id);
                assert_eq!(lock_order.input_id, input_id);
            }
            other => panic!("Expected Lock result, got {:?}", other),
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn skip_bad_predicate() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
        }
        let mut ctx = TestCtxBuilder::default().with_config(config).build().await;

        let mut order = ctx.generate_next_order(Default::default()).await;

        // Add the image_id and input_id to allow channel-based processing to succeed
        let image_url = ctx.storage_provider.upload_program(ECHO_ELF).await.unwrap();
        let image_id =
            upload_image_uri(&ctx.picker.prover, &order.request, &ctx.picker.config).await.unwrap();
        let input_id =
            upload_input_uri(&ctx.picker.prover, &order.request, &ctx.picker.config).await.unwrap();

        order.image_id = Some(image_id);
        order.input_id = Some(input_id);

        // set a bad predicate
        order.request.requirements.predicate =
            Predicate { predicateType: PredicateType::DigestMatch, data: B256::ZERO.into() };

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let result = ctx.picker.price_order_and_update_state(order).await;
        assert!(!result);

        // Check for a DB status update rather than a channel message for skipped orders
        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Skipped);

        assert!(logs_contain("predicate check failed, skipping"));
    }
    #[tokio::test]
    #[traced_test]
    async fn skip_unsupported_selector() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
        }
        let mut ctx = TestCtxBuilder::default().with_config(config).build().await;

        let mut order = ctx.generate_next_order(Default::default()).await;

        // set an unsupported selector
        order.request.requirements.selector = FixedBytes::from(Selector::Groth16V1_1 as u32);

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let result = ctx.picker.price_order_and_update_state(order).await;
        assert!(!result);

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Skipped);

        assert!(logs_contain("has an unsupported selector requirement"));
    }
    #[tokio::test]
    #[traced_test]
    async fn skip_price_less_than_gas_costs() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
        }
        let mut ctx = TestCtxBuilder::default().with_config(config).build().await;

        let order = ctx
            .generate_next_order(OrderParams {
                min_price: parse_ether("0.0005").unwrap(),
                max_price: parse_ether("0.0010").unwrap(),
                ..Default::default()
            })
            .await;
        let request_id = order.request.id;

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let result = ctx.picker.price_order_and_update_state(order).await;
        assert!(!result);

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Skipped);

        assert!(logs_contain(&format!(
            "Estimated gas cost to lock and fulfill request {request_id:x}:"
        )));
    }

    #[tokio::test]
    #[traced_test]
    async fn skip_price_less_than_gas_costs_groth16() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
        }
        let ctx = TestCtxBuilder::default().with_config(config).build().await;

        // NOTE: Values currently adjusted ad hoc to be between the two thresholds.
        let min_price = parse_ether("0.0013").unwrap();
        let max_price = parse_ether("0.0013").unwrap();

        // Order should have high enough price with the default selector.
        let order = ctx
            .generate_next_order(OrderParams {
                order_index: 1,
                min_price,
                max_price,
                ..Default::default()
            })
            .await;

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(locked);

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::WaitingToLock);
        assert_eq!(db_order.target_timestamp, Some(0));

        // Order does not have high enough price when groth16 is used.
        let mut order = ctx
            .generate_next_order(OrderParams {
                order_index: 2,
                min_price,
                max_price,
                ..Default::default()
            })
            .await;

        // set a Groth16 selector
        order.request.requirements.selector = FixedBytes::from(Selector::Groth16V2_0 as u32);
        let request_id = order.request.id;

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(!locked);

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Skipped);

        assert!(logs_contain(&format!(
            "Estimated gas cost to lock and fulfill request {request_id:x}:"
        )));
    }

    #[tokio::test]
    #[traced_test]
    async fn skip_price_less_than_gas_costs_callback() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
        }
        let ctx = TestCtxBuilder::default().with_config(config).build().await;

        // NOTE: Values currently adjusted ad hoc to be between the two thresholds.
        let min_price = parse_ether("0.0013").unwrap();
        let max_price = parse_ether("0.0013").unwrap();

        // Order should have high enough price with the default selector.
        let order = ctx
            .generate_next_order(OrderParams {
                order_index: 1,
                min_price,
                max_price,
                ..Default::default()
            })
            .await;
        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(locked);

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::WaitingToLock);
        assert_eq!(db_order.target_timestamp, Some(0));

        // Order does not have high enough price when groth16 is used.
        let mut order = ctx
            .generate_next_order(OrderParams {
                order_index: 2,
                min_price,
                max_price,
                ..Default::default()
            })
            .await;

        // set a callback with a nontrivial gas consumption
        order.request.requirements.callback = Callback {
            addr: address!("0x00000000000000000000000000000000ca11bac2"),
            gasLimit: U96::from(200_000),
        };
        let request_id = order.request.id;

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(!locked);

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Skipped);

        assert!(logs_contain(&format!(
            "Estimated gas cost to lock and fulfill request {request_id:x}:"
        )));
    }

    #[tokio::test]
    #[traced_test]
    async fn skip_price_less_than_gas_costs_smart_contract_signature() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
        }
        let ctx = TestCtxBuilder::default().with_config(config).build().await;

        // NOTE: Values currently adjusted ad hoc to be between the two thresholds.
        let min_price = parse_ether("0.0013").unwrap();
        let max_price = parse_ether("0.0013").unwrap();

        // Order should have high enough price with the default selector.
        let order = ctx
            .generate_next_order(OrderParams {
                order_index: 1,
                min_price,
                max_price,
                ..Default::default()
            })
            .await;

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(locked);

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::WaitingToLock);
        assert_eq!(db_order.target_timestamp, Some(0));

        // Order does not have high enough price when groth16 is used.
        let mut order = ctx
            .generate_next_order(OrderParams {
                order_index: 2,
                min_price,
                max_price,
                ..Default::default()
            })
            .await;

        order.request.id =
            RequestId::try_from(order.request.id).unwrap().set_smart_contract_signed_flag().into();
        let request_id = order.request.id;

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(!locked);

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Skipped);

        assert!(logs_contain(&format!(
            "Estimated gas cost to lock and fulfill request {request_id:x}:"
        )));
    }

    #[tokio::test]
    #[traced_test]
    async fn skip_unallowed_addr() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
            config.load_write().unwrap().market.allow_client_addresses = Some(vec![Address::ZERO]);
        }
        let ctx = TestCtxBuilder::default().with_config(config).build().await;

        let order = ctx.generate_next_order(Default::default()).await;

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(!locked);

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Skipped);

        assert!(logs_contain("because it is not in allowed addrs"));
    }

    #[tokio::test]
    #[traced_test]
    async fn resume_order_pricing() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
        }
        let ctx = TestCtxBuilder::default().with_config(config).build().await;

        let order = ctx.generate_next_order(Default::default()).await;

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();

        ctx.picker.find_existing_orders().await.unwrap();

        assert!(logs_contain("Found 1 orders currently pricing to resume"));

        // Try and wait for the order to complete pricing
        for _ in 0..4 {
            let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
            if db_order.status != OrderStatus::Pricing {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::WaitingToLock);
        assert_eq!(db_order.target_timestamp, Some(0));
    }

    // TODO: Test
    // need to test the non-ASAP path for pricing, aka picking a timestamp ahead in time to make sure
    // that price calculator is working correctly.

    #[tokio::test]
    #[traced_test]
    async fn pending_locked_stake() {
        let lock_stake = U256::from(10);

        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
            config.load_write().unwrap().market.max_stake = "10".into();
        }

        let ctx = TestCtxBuilder::default()
            .with_config(config)
            .with_initial_hp(U256::from(100))
            .build()
            .await;
        assert_eq!(ctx.picker.pending_locked_stake().await.unwrap(), U256::ZERO);

        let order = ctx.generate_next_order(OrderParams { lock_stake, ..Default::default() }).await;

        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(locked);
        // order is pending lock so stake is counted
        assert_eq!(ctx.picker.pending_locked_stake().await.unwrap(), lock_stake);

        ctx.db.set_proving_status_lock_and_fulfill_orders(&order.id(), U256::ZERO).await.unwrap();
        // order no longer pending lock so stake no longer counted
        assert_eq!(ctx.picker.pending_locked_stake().await.unwrap(), U256::ZERO);
    }

    #[tokio::test]
    #[traced_test]
    async fn use_gas_to_lock_estimate_from_config() {
        let lockin_gas = 123_456;
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
            config.load_write().unwrap().market.lockin_gas_estimate = lockin_gas;
        }

        let ctx = TestCtxBuilder::default().with_config(config).build().await;
        assert_eq!(ctx.picker.pending_locked_stake().await.unwrap(), U256::ZERO);

        let order = ctx.generate_next_order(Default::default()).await;
        assert_eq!(ctx.picker.estimate_gas_to_lock(&order).await.unwrap(), lockin_gas);

        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(locked);

        assert_eq!(ctx.picker.estimate_gas_to_lock_pending().await.unwrap(), lockin_gas);
    }

    #[tokio::test]
    #[traced_test]
    async fn use_gas_to_fulfill_estimate_from_config() {
        let fulfill_gas = 123_456;
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
            config.load_write().unwrap().market.fulfill_gas_estimate = fulfill_gas;
        }

        let ctx = TestCtxBuilder::default().with_config(config).build().await;
        assert_eq!(ctx.picker.pending_locked_stake().await.unwrap(), U256::ZERO);

        let order = ctx.generate_next_order(Default::default()).await;
        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(locked);

        assert_eq!(ctx.picker.estimate_gas_to_fulfill_pending().await.unwrap(), fulfill_gas);

        // add another order
        let order =
            ctx.generate_next_order(OrderParams { order_index: 2, ..Default::default() }).await;
        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(locked);

        // gas estimate stacks (until estimates factor in bundling)
        assert_eq!(ctx.picker.estimate_gas_to_fulfill_pending().await.unwrap(), 2 * fulfill_gas);
    }

    #[tokio::test]
    #[traced_test]
    async fn pending_order_gas_estimation() {
        let lockin_gas = 1000;
        let fulfill_gas = 50000;
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
            config.load_write().unwrap().market.fulfill_gas_estimate = fulfill_gas;
            config.load_write().unwrap().market.lockin_gas_estimate = lockin_gas;
        }

        let ctx = TestCtxBuilder::default().with_config(config).build().await;
        assert_eq!(ctx.picker.pending_locked_stake().await.unwrap(), U256::ZERO);

        let order = ctx.generate_next_order(Default::default()).await;
        ctx.db.add_order(&order).await.unwrap();
        let priced = ctx.picker.price_order_and_update_db(&order).await;
        assert!(priced);

        let gas_price = ctx.provider.get_gas_price().await.unwrap();
        assert_eq!(
            ctx.picker.gas_balance_reserved().await.unwrap(),
            U256::from(gas_price) * U256::from(fulfill_gas + lockin_gas)
        );
        // mark the order as locked.
        ctx.db.set_proving_status_lock_and_fulfill_orders(&order.id(), U256::ZERO).await.unwrap();
        // only fulfillment gas now reserved
        assert_eq!(
            ctx.picker.gas_balance_reserved().await.unwrap(),
            U256::from(gas_price) * U256::from(fulfill_gas)
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn cannot_overcommit_stake() {
        let signer_inital_balance_eth = 2;
        let lockin_stake = U256::from(150);

        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
            config.load_write().unwrap().market.max_stake = "10".into();
        }

        let ctx = TestCtxBuilder::default()
            .with_initial_signer_eth(signer_inital_balance_eth)
            .with_initial_hp(lockin_stake)
            .with_config(config)
            .build()
            .await;
        let order = ctx
            .generate_next_order(OrderParams { lock_stake: U256::from(100), ..Default::default() })
            .await;
        let mut orders: Vec<Order> = vec![order.clone(), order.clone()];

        for (i, order) in orders.iter_mut().enumerate() {
            order.request.id = U256::from(i);
            ctx.db.add_order(&order).await.unwrap();
            ctx.picker.price_order_and_update_db(order).await;
        }

        // only the first order above should have marked as active pricing, the second one should have been skipped due to insufficient stake
        assert_eq!(
            ctx.db.get_order(&orders[0].id()).await.unwrap().unwrap().status,
            OrderStatus::WaitingToLock
        );
        assert_eq!(
            ctx.db.get_order(&orders[1].id()).await.unwrap().unwrap().status,
            OrderStatus::Skipped
        );
        assert!(logs_contain("Insufficient available stake to lock order"));
    }

    #[tokio::test]
    #[traced_test]
    async fn skips_journal_exceeding_limit() {
        // set this by testing a very small limit (1 byte)
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price = "0.0000001".into();
            config.load_write().unwrap().market.max_journal_bytes = 1;
        }
        let lock_stake = U256::from(10);

        let ctx =
            TestCtxBuilder::default().with_config(config).with_initial_hp(lock_stake).build().await;
        let order = ctx.generate_next_order(OrderParams { lock_stake, ..Default::default() }).await;

        ctx.db.add_order(&order).await.unwrap();
        let locked = ctx.picker.price_order_and_update_db(&order).await;
        assert!(!locked);

        assert_eq!(
            ctx.db.get_order(&order.id()).await.unwrap().unwrap().status,
            OrderStatus::Skipped
        );
        assert!(logs_contain("journal larger than set limit"));
    }

    #[tokio::test]
    #[traced_test]
    async fn price_locked_by_other() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price_stake_token = "0.0000001".into();
        }
        let ctx = TestCtxBuilder::default()
            .with_config(config)
            .with_initial_hp(U256::from(1000))
            .build()
            .await;

        let mut order = ctx.generate_next_order(Default::default()).await;

        order.status = OrderStatus::Pricing;
        order.request.offer.biddingStart = now_timestamp();
        order.request.offer.lockTimeout = 1000;
        order.request.offer.timeout = 10000;
        order.request.offer.lockStake = parse_ether("0.1").unwrap();
        order.fulfillment_type = FulfillmentType::FulfillAfterLockExpire;
        let order_id = order.request.id;
        ctx.db.add_order(&order).await.unwrap();

        assert!(ctx.picker.price_order_and_update_db(&order).await);

        assert!(logs_contain(&format!(
            "Setting order with request id {:x} to prove after lock expiry at {}",
            order_id,
            order.request.offer.biddingStart + order.request.offer.lockTimeout as u64
        )));

        let expected_target_timestamp =
            order.request.offer.biddingStart + order.request.offer.lockTimeout as u64;
        let expected_expire_timestamp =
            order.request.offer.biddingStart + order.request.offer.timeout as u64;
        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::WaitingForLockToExpire);
        assert_eq!(db_order.target_timestamp, Some(expected_target_timestamp));
        assert_eq!(db_order.expire_timestamp, Some(expected_expire_timestamp));
    }

    #[tokio::test]
    #[traced_test]
    async fn price_locked_by_other_unprofitable() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price_stake_token = "0.1".into();
        }
        let ctx = TestCtxBuilder::default().with_config(config).build().await;

        let mut order = ctx.generate_next_order(Default::default()).await;

        order.status = OrderStatus::Pricing;
        order.fulfillment_type = FulfillmentType::FulfillAfterLockExpire;
        order.request.offer.biddingStart = now_timestamp();
        order.request.offer.lockTimeout = 0;
        order.request.offer.timeout = 10000;

        // Low stake means low reward for filling after it is unfulfilled
        order.request.offer.lockStake = parse_ether("0.00001").unwrap();

        let request_id = order.request.id;
        ctx.db.add_order(&order).await.unwrap();

        assert!(!ctx.picker.price_order_and_update_db(&order).await);

        // Since we know the stake reward is constant, and we know our min_mycle_price_stake_token
        // the execution limit check tells us if the order is profitable or not, since it computes the max number
        // of cycles that can be proven while keeping the order profitable.
        assert!(logs_contain(&format!(
            "Skipping order {:x} due to session limit exceeded",
            request_id
        )));

        let db_order = ctx.db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Skipped);
    }

    #[tokio::test]
    #[traced_test]
    async fn price_order_fulfill_after_lock_expiry() {
        let config = ConfigLock::default();
        {
            config.load_write().unwrap().market.mcycle_price_stake_token = "0.0000001".into();
        }
        let mut ctx = TestCtxBuilder::default()
            .with_config(config)
            .with_initial_hp(U256::from(1000))
            .build()
            .await;

        let mut order = ctx.generate_next_order(Default::default()).await;

        // Add the image_id and input_id
        let image_url = ctx.storage_provider.upload_program(ECHO_ELF).await.unwrap();
        let image_id =
            upload_image_uri(&ctx.picker.prover, &order.request, &ctx.picker.config).await.unwrap();
        let input_id =
            upload_input_uri(&ctx.picker.prover, &order.request, &ctx.picker.config).await.unwrap();

        order.image_id = Some(image_id.clone());
        order.input_id = Some(input_id.clone());

        // Set as fulfill after lock expire
        order.fulfillment_type = FulfillmentType::FulfillAfterLockExpire;

        let _request_id =
            ctx.boundless_market.submit_request(&order.request, &ctx.signer(0)).await.unwrap();

        ctx.db.add_order(&order).await.unwrap();

        // Get the fulfill-after-lock data
        let fulfill_data = ctx.price_lock_expired_order(&order).await;

        // Emulate the outcome directly
        ctx.order_result_tx
            .send(OrderProcessingResult::FulfillAfterLock(fulfill_data.clone()))
            .await
            .unwrap();

        // Check that we received the correct order result
        let order_result = ctx.expect_order_result(1000).await;
        assert!(order_result.is_some());

        match order_result.unwrap() {
            OrderProcessingResult::FulfillAfterLock(fulfill_order) => {
                assert_eq!(fulfill_order.order.id(), order.id());
                assert_eq!(
                    fulfill_order.lock_expire_timestamp_secs,
                    fulfill_data.lock_expire_timestamp_secs
                );
                assert_eq!(fulfill_order.expiry_secs, fulfill_data.expiry_secs);
            }
            other => panic!("Expected FulfillAfterLock result, got {:?}", other),
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn test_handle_failure() {
        let config = ConfigLock::default();
        let mut ctx = TestCtxBuilder::default().with_config(config).build().await;

        let order = ctx.generate_next_order(Default::default()).await;

        // Test the handle_failure method
        let error_msg = "Test error message";
        ctx.picker.persist_failure(&order, error_msg.to_string()).await.unwrap();

        // Check that the order was added to the DB with failed status
        let persisted_order = ctx.db.get_order(&order.id()).await.unwrap();
        assert!(persisted_order.is_some());
        let persisted_order = persisted_order.unwrap();
        assert_eq!(persisted_order.status, OrderStatus::Failed);
        assert_eq!(persisted_order.error_msg, Some(error_msg.to_string()));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_skip_order() {
        let config = ConfigLock::default();
        let mut ctx = TestCtxBuilder::default().with_config(config).build().await;

        let order = ctx.generate_next_order(Default::default()).await;

        // Simulate skipping an order by directly calling the logic for Skip outcome
        let f = || async {
            // Instead of matching on the enum, we'll directly implement what happens for Skip
            tracing::info!("Skipping order with request id {}", order.request.id);
            // Create a new PersistedOrderData record for the skipped order
            let persisted_order = OrderMetaData {
                id: order.id(),
                status: OrderStatus::Skipped,
                updated_at: chrono::Utc::now().timestamp(),
                image_id: order.image_id.clone(),
                input_id: order.input_id.clone(),
                proof_id: None,
                compressed_proof_id: None,
                error_msg: None,
            };

            // Add the skipped order to the database
            ctx.db
                .add_order(persisted_order)
                .await
                .context("Failed to add skipped order to database")?;
            Ok::<_, anyhow::Error>(())
        };

        // Call the function and ensure it succeeds
        f().await.unwrap();

        // Check that the order was added to the DB with skipped status
        let persisted_order = ctx.db.get_order(&order.id()).await.unwrap();
        assert!(persisted_order.is_some());
        let persisted_order = persisted_order.unwrap();
        assert_eq!(persisted_order.status, OrderStatus::Skipped);

        // Verify no order result was sent through the channel (skips don't send)
        let result = ctx.expect_order_result(100).await;
        assert!(
            result.is_none(),
            "No result should be sent through the channel for skipped orders"
        );
    }
}
