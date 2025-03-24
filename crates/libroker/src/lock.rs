use alloy::{primitives::U256, providers::{Provider, WalletProvider}, rpc::types::BlockTransactionsKind};
use anyhow::Context;
use boundless_market::contracts::{boundless_market::MarketError, ProofStatus};

use crate::{Order, State};

#[derive(thiserror::Error, Debug)]
pub enum LockOrderErr {
    #[error("Failed to fetch / push image: {0}")]
    OrderLockedInBlock(MarketError),

    // #[error("Invalid order status for locking: {0:?}")]
    // InvalidStatus(OrderStatus),

    #[error("Order already locked")]
    AlreadyLocked,

    #[error("Other: {0}")]
    OtherErr(#[from] anyhow::Error),
}

impl<P> State<P>
where
    P: Provider + 'static + Clone + WalletProvider,
{
    pub async fn lock_order(&self, order: &Order) -> Result<U256, LockOrderErr> {
		let order_id = order.request.id;
        let order_status = self
            .market
            .get_status(order_id, Some(order.request.expires_at()))
            .await
            .context("Failed to get order status")?;
        if order_status != ProofStatus::Unknown {
            tracing::warn!("Order {order_id:x} not open: {order_status:?}, skipping");
            // TODO: fetch some chain data to find out who / and for how much the order
            // was locked in at
            return Err(LockOrderErr::AlreadyLocked);
        }

        let conf_priority_gas = {
            let conf = self.config.lock_all().context("Failed to lock config")?;
            conf.market.lockin_priority_gas
        };

        tracing::info!("Locking order: {order_id:x} for stake: {}", order.request.offer.lockStake);
        let lock_block = self
            .market
            .lock_request(&order.request, &order.client_sig, conf_priority_gas)
            .await
            .map_err(LockOrderErr::OrderLockedInBlock)?;

        let lock_timestamp = self
            .provider()
            .get_block_by_number(lock_block.into(), BlockTransactionsKind::Hashes)
            .await
            .with_context(|| format!("failed to get block {lock_block}"))?
            .with_context(|| format!("failed to get block {lock_block}: block not found"))?
            .header
            .timestamp;

        let lock_price = order
            .request
            .offer
            .price_at(lock_timestamp)
            .context("Failed to calculate lock price")?;

        Ok(lock_price)
    }
}
