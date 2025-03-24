use alloy::{
    network::Ethereum,
    primitives::{
        utils::{format_ether, parse_ether},
        FixedBytes, U256,
    },
    providers::{Provider, WalletProvider},
};
use anyhow::Context;
use boundless_market::contracts::RequestError;
use broker::{provers::ProverError, upload_image_uri, upload_input_uri};

use crate::{now_timestamp_secs, Order, State};

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum PriceOrderErr {
    #[error("Failed to fetch / push input: {0}")]
    FetchInputErr(anyhow::Error),

    #[error("Failed to fetch / push image: {0}")]
    FetchImageErr(anyhow::Error),

    #[error("Guest execution faulted: {0}")]
    GuestPanic(String),

    #[error("Request: {0}")]
    RequestError(#[from] RequestError),

    #[error("Other: {0}")]
    OtherErr(#[from] anyhow::Error),
}

#[derive(Debug)]
pub struct OrderLockTiming {
    pub target_timestamp_secs: u64,
    // TODO handle checking what time the lock should occur before, when estimating proving time.
    pub expiry_secs: u64,
}

impl<P> State<P>
where
    P: Provider<Ethereum> + 'static + Clone + WalletProvider,
{
    pub async fn price_order(
        &self,
        order_id: U256,
        order: &Order,
    ) -> Result<Option<OrderLockTiming>, PriceOrderErr> {
        tracing::debug!("Processing order {order_id:x}: {order:?}");

        let (min_deadline, allowed_addresses_opt) = {
            let config = self.config.lock_all().context("Failed to read config")?;
            (config.market.min_deadline, config.market.allow_client_addresses.clone())
        };

        // Initial sanity checks:
        if let Some(allow_addresses) = allowed_addresses_opt {
            let client_addr = order.request.client_address()?;
            if !allow_addresses.contains(&client_addr) {
                tracing::warn!("Removing order {order_id:x} from {client_addr} because it is not in allowed addrs");
                return Ok(None);
            }
        }

        // TODO(#BM-536): Filter based on supported selectors
        // Drop orders that specify a selector
        if order.request.requirements.selector != FixedBytes::<4>([0; 4]) {
            tracing::warn!("Removing order {order_id:x} because it has a selector requirement");
            return Ok(None);
        }

        // is the order expired already?
        // TODO: Handle lockTimeout separately from timeout.

        let expiration = order.request.offer.biddingStart + order.request.offer.lockTimeout as u64;

        let now = now_timestamp_secs();
        if expiration <= now {
            tracing::warn!("Removing order {order_id:x} because it has expired");
            return Ok(None);
        };

        // Does the order expire within the min deadline
        let seconds_left = expiration - now;
        if seconds_left <= min_deadline {
            tracing::warn!("Removing order {order_id:x} because it expires within the deadline left: {seconds_left} deadline: {min_deadline}");
            return Ok(None);
        }

        // Check if the stake is sane and if we can afford it
        let max_stake = {
            let config = self.config.lock_all().context("Failed to read config")?;
            parse_ether(&config.market.max_stake).context("Failed to parse max_stake")?
        };

        let lockin_stake = U256::from(order.request.offer.lockStake);
        if lockin_stake > max_stake {
            tracing::warn!("Removing high stake order {order_id:x}");
            return Ok(None);
        }

        // Check that we have both enough staking tokens to stake, and enough gas tokens to lock and fulfil
        let gas_price = self.provider().get_gas_price().await.context("Failed to get gas price")?;
        let gas_to_lock_order =
            U256::from(gas_price) * U256::from(self.estimate_gas_to_lock(order).await?);
        let available_gas = self.available_gas_balance().await?;
        let available_stake = self.available_stake_balance().await?;

        if gas_to_lock_order > available_gas {
            tracing::warn!("Estimated there will be insufficient gas to lock this order after locking and fulfilling pending orders");
            return Ok(None);
        }
        if lockin_stake > available_stake {
            tracing::warn!(
			"Insufficient available stake to lock order {order_id:x}. Requires {lockin_stake}, has {available_stake}"
		);
            return Ok(None);
        }

        let (skip_preflight, max_size, peak_prove_khz, fetch_retries, max_mcycle_limit) = {
            let config = self.config.lock_all().context("Failed to read config")?;
            let skip_preflight =
                if let Some(skip_preflights) = config.market.skip_preflight_ids.as_ref() {
                    skip_preflights.contains(&order.request.requirements.imageId)
                } else {
                    false
                };

            (
                skip_preflight,
                config.market.max_file_size,
                config.market.peak_prove_khz,
                config.market.max_fetch_retries,
                config.market.max_mcycle_limit,
            )
        };

        if skip_preflight {
            return Ok(Some(OrderLockTiming { target_timestamp_secs: 0, expiry_secs: expiration }));
        }

        // Initialize image and input uploads
        let image_id = order
            .image_url
            .get_or_try_init(|| async {
                upload_image_uri(&self.prover, &order.request, max_size, fetch_retries).await
            })
            .await
            .map_err(PriceOrderErr::FetchImageErr)?;

        let input_id = order
            .input_url
            .get_or_try_init(|| async {
                upload_input_uri(&self.prover, &order.request, max_size, fetch_retries).await
            })
            .await
            .map_err(PriceOrderErr::FetchInputErr)?;

        // Create a executor limit based on the max price of the order
        let config_min_mcycle_price = {
            let config = self.config.lock_all().context("Failed to read config")?;
            parse_ether(&config.market.mcycle_price).context("Failed to parse mcycle_price")?
        };

        let exec_limit: u64 = (U256::from(order.request.offer.maxPrice) / config_min_mcycle_price)
            .try_into()
            .context("Failed to convert U256 exec limit to u64")?;

        if exec_limit == 0 {
            tracing::warn!(
                "Removing order {order_id:x} because it's mcycle price limit is below 0 mcycles"
            );
            return Ok(None);
        }

        tracing::debug!(
            "Starting preflight execution of {order_id:x} exec limit {exec_limit} mcycles"
        );
        // TODO add a future timeout here to put a upper bound on how long to preflight for
        let proof_res = self
            .prover
            .preflight(
                image_id,
                input_id,
                vec![],
                /* TODO assumptions */ Some(exec_limit * 1024 * 1024),
            )
            .await
            .map_err(|err| match err {
                ProverError::ProvingFailed(ref err_msg) => {
                    // TODO: Get enum'd errors from the SDK to prevent str
                    // checks
                    if err_msg.contains("GuestPanic") {
                        PriceOrderErr::GuestPanic(err_msg.clone())
                    } else {
                        PriceOrderErr::OtherErr(err.into())
                    }
                }
                _ => PriceOrderErr::OtherErr(err.into()),
            })?;

        // If a max_mcycle_limit is configured check if the order is over that limit
        if let Some(mcycle_limit) = max_mcycle_limit {
            let mcycles = proof_res.stats.total_cycles / 1_000_000;
            if mcycles >= mcycle_limit {
                tracing::warn!("Order {order_id:x} max_mcycle_limit check failed req: {mcycle_limit} | config: {mcycles}");
                return Ok(None);
            }
        }

        // TODO: this only checks that we could prove this at peak_khz, not if the cluster currently
        // can absorb that proving load, we need to cordinate this check with parallel
        // proofs and the current state of Bento
        if let Some(prove_khz) = peak_prove_khz {
            let required_khz = (proof_res.stats.total_cycles / 1_000) / seconds_left;
            tracing::debug!("peak_prove_khz checking: {prove_khz} required: {required_khz}");
            if required_khz >= prove_khz {
                tracing::warn!("Order {order_id:x} peak_prove_khz check failed req: {required_khz} | config: {prove_khz}");
                return Ok(None);
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
            tracing::warn!(
                "Order {order_id:x} journal larger than set limit ({} > {}), skipping",
                journal.len(),
                max_journal_bytes
            );
            return Ok(None);
        }

        // Validate the predicates:
        if !order.request.requirements.predicate.eval(journal.clone()) {
            tracing::warn!("Order {order_id:x} predicate check failed, skipping");
            return Ok(None);
        }

        let one_mill = U256::from(1_000_000);

        let mcycle_price_min = (U256::from(order.request.offer.minPrice)
            / U256::from(proof_res.stats.total_cycles))
            * one_mill;
        let mcycle_price_max = (U256::from(order.request.offer.maxPrice)
            / U256::from(proof_res.stats.total_cycles))
            * one_mill;

        tracing::info!(
            "Order price: min: {} max: {} - cycles: {} - mcycle price: {} - {} - stake: {}",
            format_ether(U256::from(order.request.offer.minPrice)),
            format_ether(U256::from(order.request.offer.maxPrice)),
            proof_res.stats.total_cycles,
            format_ether(mcycle_price_min),
            format_ether(mcycle_price_max),
            order.request.offer.lockStake,
        );

        // Skip the order if it will never be worth it
        if mcycle_price_max < config_min_mcycle_price {
            tracing::warn!("Removing under priced order {order_id:x}");
            return Ok(None);
        }

        let target_timestamp_secs = if mcycle_price_min >= config_min_mcycle_price {
            tracing::info!(
                "Selecting order {order_id:x} at price {} - ASAP",
                format_ether(U256::from(order.request.offer.minPrice))
            );
            0
        }
        // Here we have to pick a target timestamp that the price would be at our target price
        // TODO: Clean up and do more testing on this since its just a rough shot first draft
        else {
            let target_min_price =
                config_min_mcycle_price * (U256::from(proof_res.stats.total_cycles)) / one_mill;
            tracing::debug!("Target price: {target_min_price}");

            let target_timestamp: u64 = order
                .request
                .offer
                .time_at_price(target_min_price)
                .context("Failed to get target price timestamp")?;
            tracing::info!(
                "Selecting order {order_id:x} at price {} - at time {}",
                format_ether(target_min_price),
                target_timestamp,
            );
            target_timestamp
        };

        Ok(Some(OrderLockTiming { target_timestamp_secs, expiry_secs: expiration }))
    }

    /// Estimate of gas for locking a single order
    /// Currently just uses the config estimate but this may change in the future
    async fn estimate_gas_to_lock(&self, _order: &Order) -> anyhow::Result<u64> {
        Ok(self.config.lock_all().context("Failed to read config")?.market.lockin_gas_estimate)
    }

    /// Return available gas balance.
    ///
    /// This is defined as the balance of the signer account.
    async fn available_gas_balance(&self) -> anyhow::Result<U256> {
        let balance = self
            .provider()
            .get_balance(self.provider().default_signer_address())
            .await
            .context("Failed to get current wallet balance")?;

        let gas_reserved = self.gas_reserved().await?;

        tracing::debug!(
            "Available Balance = account_balance({}) - expected_future_gas({})",
            format_ether(balance),
            format_ether(gas_reserved)
        );

        Ok(balance - gas_reserved)
    }

    /// Return available stake balance.
    ///
    /// This is defined as the balance in staking tokens of the signer account minus any pending locked stake.
    async fn available_stake_balance(&self) -> anyhow::Result<U256> {
        let balance =
            self.market.balance_of_stake(self.provider().default_signer_address()).await?;
        let pending_balance = self.pending_locked_stake().await?;
        Ok(balance - pending_balance)
    }

    /// Estimate the total gas tokens reserved to lock and fulfill all pending orders
    async fn gas_reserved(&self) -> anyhow::Result<U256> {
        let gas_price = self.provider().get_gas_price().await.context("Failed to get gas price")?;
        let lock_pending_gas = self.estimate_gas_to_lock_pending().await?;
        let fulfill_pending_gas = self.estimate_gas_to_fulfill_pending().await?;
        Ok(U256::from(gas_price) * U256::from(lock_pending_gas + fulfill_pending_gas))
    }

    /// Estimate of gas for locking in any pending locks and submitting any pending proofs
    async fn estimate_gas_to_lock_pending(&self) -> anyhow::Result<u64> {
        let gas = 0;
        // TODO handle gas estimation for locking orders
        // // NOTE: i64::max is the largest timestamp value possible in the DB.
        // for (_, order) in self.db.get_pending_lock_orders(i64::MAX as u64).await?.iter() {
        //     gas += self.estimate_gas_to_lock(order).await?;
        // }
        Ok(gas)
    }

    /// Estimate of gas for fulfilling any orders either pending lock or locked
    async fn estimate_gas_to_fulfill_pending(&self) -> anyhow::Result<u64> {
        // TODO handle gas for fulfilling existing orders
        // let pending_fulfill_orders = self.db.get_orders_committed_to_fulfill_count().await?;
        // Ok((pending_fulfill_orders as u64)
        //     * self.config.lock_all().context("Failed to read config")?.market.fulfill_gas_estimate)
        Ok(0)
    }

    /// Return the total amount of stake that is marked locally in the DB to be locked
    /// but has not yet been locked in the market contract thus has not been deducted from the account balance
    async fn pending_locked_stake(&self) -> anyhow::Result<U256> {
        // // NOTE: i64::max is the largest timestamp value possible in the DB.
        // let pending_locks = self.db.get_pending_lock_orders(i64::MAX as u64).await?;
        // let stake = pending_locks
        //     .iter()
        //     .map(|(_, order)| order.request.offer.lockStake)
        //     .fold(U256::ZERO, |acc, x| acc + x);
        // Ok(stake)
        // TODO handle
        Ok(U256::ZERO)
    }
}
