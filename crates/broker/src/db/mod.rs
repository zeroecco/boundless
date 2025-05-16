// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use std::{default::Default, str::FromStr, sync::Arc};

use alloy::primitives::{ruint::ParseError as RuintParseErr, Bytes, B256, U256};
use async_trait::async_trait;
use boundless_market::order_stream_client::OrderData;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
    Row,
};
use thiserror::Error;

use crate::{
    errors::{impl_coded_debug, CodedError},
    AggregationState, Batch, BatchStatus, FulfillmentType, Order, OrderStatus, ProofRequest,
};
use tracing::instrument;

#[cfg(test)]
mod fuzz_db;

#[derive(Error)]
pub enum DbError {
    #[error("{code} Order key {0} not found in DB", code = self.code())]
    OrderNotFound(String),

    #[error("{code} Batch key {0} not found in DB", code = self.code())]
    BatchNotFound(usize),

    #[error("{code} Batch key {0} has no aggreagtion state", code = self.code())]
    BatchAggregationStateIsNone(usize),

    #[cfg(test)]
    #[error("{code} Batch insert failed {0}", code = self.code())]
    BatchInsertFailure(usize),

    #[error("{code} DB Missing column value: {0}", code = self.code())]
    MissingElm(&'static str),

    #[error("{code} SQL error {0}", code = self.code())]
    SqlErr(sqlx::Error),

    #[error("{code} SQL Pool timed out {0}", code = self.code())]
    SqlPoolTimedOut(sqlx::Error),

    #[error("{code} SQL Database locked {0}", code = self.code())]
    SqlDatabaseLocked(anyhow::Error),

    #[error("{code} SQL Unique violation {0}", code = self.code())]
    SqlUniqueViolation(sqlx::Error),

    #[error("{code} SQL Migration error", code = self.code())]
    MigrateErr(#[from] sqlx::migrate::MigrateError),

    #[error("{code} JSON serialization error", code = self.code())]
    JsonErr(#[from] serde_json::Error),

    #[error("{code} Invalid order id", code = self.code())]
    InvalidOrderId(#[from] RuintParseErr),

    #[error("{code} Invalid block number: {0}", code = self.code())]
    BadBlockNumb(String),

    #[error("{code} Failed to set last block", code = self.code())]
    SetBlockFail,

    #[error("{code} Invalid order id: {0} missing field: {1}", code = self.code())]
    InvalidOrder(String, &'static str),

    #[error("{code} Invalid max connection env var value", code = self.code())]
    MaxConnEnvVar(#[from] std::num::ParseIntError),
}

impl_coded_debug!(DbError);

impl CodedError for DbError {
    fn code(&self) -> &str {
        match self {
            DbError::SqlDatabaseLocked(_) => "[B-DB-001]",
            DbError::SqlPoolTimedOut(_) => "[B-DB-002]",
            DbError::SqlUniqueViolation(_) => "[B-DB-003]",
            _ => "[B-DB-500]",
        }
    }
}

impl From<sqlx::Error> for DbError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(ref db_err) = e {
            let msg = db_err.message().to_string();
            if msg.contains("database is locked") {
                return DbError::SqlDatabaseLocked(anyhow::anyhow!(msg));
            }
            if db_err.is_unique_violation() {
                return DbError::SqlUniqueViolation(e);
            }
        }
        match e {
            sqlx::Error::PoolTimedOut => DbError::SqlPoolTimedOut(e),
            _ => DbError::SqlErr(e),
        }
    }
}

/// Struct containing the information about an order used by the aggregation worker.
#[derive(Clone, Debug)]
pub struct AggregationOrder {
    pub order_id: String,
    pub proof_id: String,
    pub expiration: u64,
    pub fee: U256,
}

#[async_trait]
pub trait BrokerDb {
    async fn add_order(&self, order: OrderMetaData) -> Result<(), DbError>;
    async fn get_order(&self, id: &str) -> Result<Option<OrderMetaData>, DbError>;
}

pub type DbObj = Arc<dyn BrokerDb + Send + Sync>;

const SQL_BLOCK_KEY: i64 = 0;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, sqlx::FromRow)]
pub struct OrderMetaData {
    pub id: String,
    pub status: OrderStatus,
    pub updated_at: i64,
    pub image_id: Option<String>,
    pub input_id: Option<String>,
    pub proof_id: Option<String>,
    pub compressed_proof_id: Option<String>,
    pub error_msg: Option<String>,
}

pub struct SqliteDb {
    pool: SqlitePool,
}

impl SqliteDb {
    pub async fn new(conn_str: &str) -> Result<Self, DbError> {
        let opts = SqliteConnectOptions::from_str(conn_str)?
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .create_if_missing(true)
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            // set timeouts to None for sqlite in-memory:
            // https://github.com/launchbadge/sqlx/issues/1647
            .max_lifetime(None)
            .idle_timeout(None)
            .min_connections(1)
            // Limit the DB to a single connection to prevent database-locked
            // this does effectively make the DB single threaded but it should be
            // a non-issue with the low DB contention
            .max_connections(1);

        let pool = pool.connect_with(opts).await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self { pool })
    }

    #[cfg(test)]
    pub async fn from(pool: SqlitePool) -> Result<Self, DbError> {
        Ok(Self { pool })
    }

    async fn new_batch(&self) -> Result<usize, DbError> {
        let batch = Batch { start_time: Utc::now(), ..Default::default() };

        let res: i64 = sqlx::query_scalar("INSERT INTO batches (data) VALUES ($1) RETURNING id")
            .bind(sqlx::types::Json(&batch))
            .fetch_one(&self.pool)
            .await?;

        Ok(res as usize)
    }

    pub async fn update_order_status(&self, id: &str, status: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE orders SET status = ?, updated_at = ? WHERE id = ?")
            .bind(status)
            .bind(Utc::now().to_rfc3339())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct DbOrder {
    id: String,
    #[sqlx(json)]
    data: Order,
}

#[derive(sqlx::FromRow)]
struct DbBatch {
    id: i64,
    #[sqlx(json)]
    data: Batch,
}

#[derive(sqlx::FromRow)]
struct DbLockedRequest {
    #[allow(dead_code)]
    id: String,
    locker: String,
    block_number: u64,
}

#[async_trait]
impl BrokerDb for SqliteDb {
    #[instrument(level = "trace", skip_all, fields(id = %order.id))]
    async fn add_order(&self, order: OrderMetaData) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO orders (id, status, updated_at, image_id, input_id, proof_id, compressed_proof_id, error_msg) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&order.id)
        .bind(&order.status)
        .bind(&order.updated_at)
        .bind(&order.image_id)
        .bind(&order.input_id)
        .bind(&order.proof_id)
        .bind(&order.compressed_proof_id)
        .bind(&order.error_msg)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(id = %format!("{id}")))]
    async fn get_order(&self, id: &str) -> Result<Option<OrderMetaData>, DbError> {
        let order = sqlx::query_as::<_, OrderMetaData>("SELECT * FROM orders WHERE id = ? LIMIT 1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(order)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProofRequest;
    use alloy::primitives::{Address, Bytes, U256};
    use boundless_market::contracts::{
        Input, InputType, Offer, Predicate, PredicateType, RequestId, Requirements,
    };
    use risc0_aggregation::GuestState;
    use risc0_zkvm::sha::Digest;

    fn create_order() -> Order {
        Order {
            status: OrderStatus::New,
            updated_at: Utc::now(),
            target_timestamp: None,
            request: ProofRequest::new(
                RequestId::new(Address::ZERO, 1),
                Requirements::new(
                    Digest::ZERO,
                    Predicate {
                        predicateType: PredicateType::PrefixMatch,
                        data: Default::default(),
                    },
                ),
                "http://risczero.com",
                Input { inputType: InputType::Inline, data: "".into() },
                Offer {
                    minPrice: U256::from(1),
                    maxPrice: U256::from(2),
                    biddingStart: 0,
                    timeout: 100,
                    lockTimeout: 100,
                    rampUpPeriod: 1,
                    lockStake: U256::from(0),
                },
            ),
            image_id: None,
            input_id: None,
            proof_id: None,
            compressed_proof_id: None,
            expire_timestamp: None,
            client_sig: Bytes::new(),
            lock_price: None,
            fulfillment_type: FulfillmentType::LockAndFulfill,
            error_msg: None,
            boundless_market_address: Address::ZERO,
            chain_id: 1,
            total_cycles: None,
            proving_started_at: None,
        }
    }

    #[sqlx::test]
    async fn add_order(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let order = create_order();
        db.add_order(order).await.unwrap();
    }

    #[sqlx::test]
    async fn order_not_exists(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        assert!(!db.order_exists_with_request_id(U256::ZERO).await.unwrap());
    }

    #[sqlx::test]
    async fn order_exists(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let order = create_order();
        db.add_order(order.clone()).await.unwrap();

        assert!(db.order_exists_with_request_id(order.request.id).await.unwrap());
    }

    #[sqlx::test]
    async fn get_order(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let order = create_order();
        db.add_order(order.clone()).await.unwrap();

        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();

        assert_eq!(order.request, db_order.request);
    }

    #[sqlx::test]
    async fn get_submission_order(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let mut order = create_order();
        order.proof_id = Some("test".to_string());
        order.lock_price = Some(U256::from(10));
        db.add_order(order.clone()).await.unwrap();

        let submit_order: (ProofRequest, Bytes, String, B256, U256, FulfillmentType) =
            db.get_submission_order(&order.id()).await.unwrap();
        assert_eq!(submit_order.0, order.request);
        assert_eq!(submit_order.1, order.client_sig);
        assert_eq!(submit_order.2, order.proof_id.unwrap());
        assert_eq!(submit_order.3, order.request.requirements.imageId);
        assert_eq!(submit_order.4, order.lock_price.unwrap());
        assert_eq!(submit_order.5, order.fulfillment_type);
    }

    #[sqlx::test]
    async fn update_orders_for_pricing(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let id = U256::ZERO;
        let mut order = create_order();
        db.add_order(order.clone()).await.unwrap();
        order.request.id = id + U256::from(2);
        db.add_order(order.clone()).await.unwrap();
        order.request.id = id + U256::from(3);
        db.add_order(order.clone()).await.unwrap();

        let price_order = db.update_orders_for_pricing(1).await.unwrap();
        assert_eq!(price_order.len(), 1);
        assert_eq!(price_order[0].status, OrderStatus::Pricing);
        assert_ne!(price_order[0].updated_at, order.updated_at);

        // Request the next two orders, which should skip the first
        let price_order = db.update_orders_for_pricing(2).await.unwrap();
        assert_eq!(price_order.len(), 2);
        assert_eq!(price_order[0].status, OrderStatus::Pricing);
        assert_eq!(price_order[1].status, OrderStatus::Pricing);
    }

    /// Create a db with two orders that were locked by others
    async fn init_db_locked_by_others(pool: SqlitePool) -> (DbObj, Order, Order) {
        let db = Arc::new(SqliteDb::from(pool).await.unwrap());
        let mut order1 = create_order();
        order1.status = OrderStatus::New;
        order1.request.offer.lockTimeout = 100;
        order1.request.offer.timeout = 200;
        order1.request.id = U256::from(1);
        db.add_order(order1.clone()).await.unwrap();

        let mut order2 = create_order();
        order2.status = OrderStatus::New;
        order2.request.offer.lockTimeout = 150;
        order2.request.offer.timeout = 250;
        order2.request.id = U256::from(2);
        db.add_order(order2.clone()).await.unwrap();
        (db, order1, order2)
    }

    #[sqlx::test]
    async fn update_orders_for_pricing_updates(pool: SqlitePool) {
        // // both still locked
        let (db, order1, order2) = init_db_locked_by_others(pool).await;
        let result = db.update_orders_for_pricing(2).await.unwrap();

        // Check order status is updated
        assert_eq!(result.len(), 2);
        assert_eq!(db.get_order(&order1.id()).await.unwrap().unwrap().status, OrderStatus::Pricing);
        assert_eq!(db.get_order(&order2.id()).await.unwrap().unwrap().status, OrderStatus::Pricing);
    }

    #[sqlx::test]
    async fn get_active_pricing_orders(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let mut order = create_order();
        order.request.id = U256::from(1);
        order.status = OrderStatus::Pricing;
        db.add_order(order.clone()).await.unwrap();

        let mut order2 = create_order();
        order2.status = OrderStatus::Pricing;
        order2.request.id = U256::from(2);
        db.add_order(order2.clone()).await.unwrap();

        let orders = db.get_active_pricing_orders().await.unwrap();
        assert_eq!(orders.len(), 2);
        assert_eq!(orders[0].id(), order.id());
        assert_eq!(orders[0].status, OrderStatus::Pricing);
        assert_eq!(orders[1].id(), order2.id());
        assert_eq!(orders[1].status, OrderStatus::Pricing);
    }

    #[sqlx::test]
    async fn set_order_lock(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let mut order = create_order();
        order.request.id = U256::ZERO;
        db.add_order(order.clone()).await.unwrap();

        let lock_timestamp = 10;
        let expire_timestamp = 20;
        db.set_order_lock(&order.id(), lock_timestamp, expire_timestamp, None).await.unwrap();

        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::WaitingToLock);
        assert_eq!(db_order.target_timestamp, Some(lock_timestamp));
        assert_eq!(db_order.expire_timestamp, Some(expire_timestamp));
    }

    #[sqlx::test]
    #[should_panic(expected = "Order key 10 not found")]
    async fn set_order_lock_fail(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let order = create_order();
        db.add_order(order.clone()).await.unwrap();
        let bad_id = U256::from(10);
        db.set_order_lock(&bad_id.to_string(), 1, 1, None).await.unwrap();
    }

    #[sqlx::test]
    async fn set_order_fulfill_after_lock_expire(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let order = create_order();
        db.add_order(order.clone()).await.unwrap();
        let lock_timestamp = 10;
        let expire_timestamp = 20;
        db.set_order_fulfill_after_lock_expire(&order.id(), lock_timestamp, expire_timestamp, None)
            .await
            .unwrap();
        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::WaitingForLockToExpire);
        assert_eq!(db_order.target_timestamp, Some(lock_timestamp));
        assert_eq!(db_order.expire_timestamp, Some(expire_timestamp));
    }

    #[sqlx::test]
    #[should_panic(expected = "Order key 10 not found")]
    async fn set_order_fulfill_after_lock_expire_fail(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let order = create_order();
        db.add_order(order.clone()).await.unwrap();
        let bad_id = U256::from(10);
        db.set_order_fulfill_after_lock_expire(&bad_id.to_string(), 1, 1, None).await.unwrap();
    }

    #[sqlx::test]
    async fn set_proving_status(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let order = create_order();
        db.add_order(order.clone()).await.unwrap();

        let lock_price = U256::from(20);

        db.set_proving_status_lock_and_fulfill_orders(&order.id(), lock_price).await.unwrap();

        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::PendingProving);
        assert_eq!(db_order.lock_price, Some(lock_price));
    }

    #[sqlx::test]
    async fn get_fulfill_after_lock_expire_orders(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        // Create orders with different target timestamps
        let mut order1 = create_order();
        order1.status = OrderStatus::WaitingForLockToExpire;
        order1.request.id = U256::from(1);
        order1.target_timestamp = Some(10);
        db.add_order(order1.clone()).await.unwrap();

        let mut order2 = create_order();
        order2.request.id = U256::from(2);
        order2.status = OrderStatus::WaitingForLockToExpire;
        order2.target_timestamp = Some(20);
        db.add_order(order2.clone()).await.unwrap();

        // Test with timestamp before both orders
        let orders = db.get_fulfill_after_lock_expire_orders(5).await.unwrap();
        assert_eq!(orders.len(), 0);

        // Test with timestamp between orders
        let orders = db.get_fulfill_after_lock_expire_orders(15).await.unwrap();
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0].id(), order1.id());

        // Test with timestamp after both orders
        let orders = db.get_fulfill_after_lock_expire_orders(25).await.unwrap();
        assert_eq!(orders.len(), 2);
        assert_eq!(orders[0].id(), order1.id());
        assert_eq!(orders[1].id(), order2.id());
    }

    #[sqlx::test]
    async fn set_proving_status_fulfill_after_lock_expire_orders(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let mut order = create_order();
        order.status = OrderStatus::Pricing;
        db.add_order(order.clone()).await.unwrap();

        // Order should not be updated if we query before the target timestamp.
        db.set_proving_status_fulfill_after_lock_expire_orders(&order.id()).await.unwrap();

        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::PendingProving);
        assert_eq!(db_order.lock_price, Some(U256::ZERO));
    }

    #[sqlx::test]
    async fn set_order_failure(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let order = create_order();
        db.add_order(order.clone()).await.unwrap();

        let failure_str = "TEST_FAIL";
        db.set_order_failure(&order.id(), failure_str.into()).await.unwrap();

        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Failed);
        assert_eq!(db_order.error_msg, Some(failure_str.into()));
    }

    #[sqlx::test]
    async fn set_order_complete(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let order = create_order();
        db.add_order(order.clone()).await.unwrap();

        db.set_order_complete(&order.id()).await.unwrap();

        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Done);
    }

    #[sqlx::test]
    async fn skip_order(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let order = create_order();
        db.add_order(order.clone()).await.unwrap();

        db.skip_order(&order.id()).await.unwrap();
        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Skipped);
    }

    #[sqlx::test]
    async fn set_get_block(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let mut block_numb = 20;
        db.set_last_block(block_numb).await.unwrap();

        let db_block = db.get_last_block().await.unwrap().unwrap();
        assert_eq!(block_numb, db_block);

        block_numb = 21;
        db.set_last_block(block_numb).await.unwrap();

        let db_block = db.get_last_block().await.unwrap().unwrap();
        assert_eq!(block_numb, db_block);
    }

    #[sqlx::test]
    async fn get_pending_lock_orders(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let id = U256::ZERO;
        let target_timestamp = 20;
        let good_end = 25;
        let bad_end = 15;
        let mut order1 = create_order();
        order1.status = OrderStatus::WaitingToLock;
        order1.target_timestamp = Some(target_timestamp);
        order1.request.id = id;
        db.add_order(order1.clone()).await.unwrap();
        let mut order2 = create_order();
        order2.request.id = id + U256::from(1);
        order2.target_timestamp = Some(good_end + 1);
        db.add_order(order2.clone()).await.unwrap();

        let res = db.get_pending_lock_orders(good_end).await.unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id(), order1.id());
        assert_eq!(res[0].target_timestamp, Some(target_timestamp));

        let res = db.get_pending_lock_orders(bad_end).await.unwrap();
        assert_eq!(res.len(), 0);
    }

    #[sqlx::test]
    async fn get_proving_order(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let id = U256::ZERO;
        let mut order = create_order();
        order.status = OrderStatus::PendingProving;
        order.request.id = id;
        db.add_order(order.clone()).await.unwrap();

        let db_order = db.get_proving_order().await.unwrap();
        let db_order = db_order.unwrap();
        assert_eq!(db_order.id(), order.id());
        assert_eq!(db_order.status, OrderStatus::Proving);
    }

    #[sqlx::test]
    async fn set_order_proof_id(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let id = U256::ZERO;
        let mut order = create_order();
        order.request.id = id;
        db.add_order(order.clone()).await.unwrap();

        let proof_id = "test";
        db.set_order_proof_id(&order.id(), proof_id).await.unwrap();

        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();
        assert_eq!(db_order.proof_id, Some(proof_id.into()));
    }

    #[sqlx::test]
    async fn get_active_proofs(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let id = U256::ZERO;
        let mut order = create_order();
        order.status = OrderStatus::Done;
        order.request.id = id;
        db.add_order(order.clone()).await.unwrap();

        let id_2 = U256::from(1);
        let mut order = create_order();
        order.status = OrderStatus::Proving;
        order.request.id = id_2;
        db.add_order(order.clone()).await.unwrap();

        let proving_orders = db.get_active_proofs().await.unwrap();
        assert_eq!(proving_orders.len(), 1);
        assert_eq!(proving_orders[0].id(), order.id());
    }

    #[sqlx::test]
    async fn set_image_input_ids(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let id = U256::ZERO;
        let mut order = create_order();
        order.status = OrderStatus::PendingProving;
        order.request.id = id;
        db.add_order(order.clone()).await.unwrap();

        let image_id = "test_img";
        let input_id = "test_input";
        db.set_image_input_ids(&order.id(), image_id, input_id).await.unwrap();

        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();

        assert_eq!(db_order.image_id, Some(image_id.into()));
        assert_eq!(db_order.input_id, Some(input_id.into()));
    }

    #[sqlx::test]
    async fn set_aggregation_status(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let id = U256::ZERO;
        let mut order = create_order();
        order.request.id = id;
        db.add_order(order.clone()).await.unwrap();

        db.set_aggregation_status(&order.id(), OrderStatus::PendingAgg).await.unwrap();

        let db_order = db.get_order(&order.id()).await.unwrap().unwrap();

        assert_eq!(db_order.status, OrderStatus::PendingAgg);
    }

    #[sqlx::test]
    async fn get_aggregation_proofs(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let mut orders = [
            Order {
                status: OrderStatus::New,
                proof_id: Some("test_id3".to_string()),
                expire_timestamp: Some(10),
                lock_price: Some(U256::from(10u64)),
                ..create_order()
            },
            Order {
                status: OrderStatus::PendingAgg,
                proof_id: Some("test_id1".to_string()),
                expire_timestamp: Some(10),
                lock_price: Some(U256::from(10u64)),
                ..create_order()
            },
            Order {
                status: OrderStatus::Aggregating,
                proof_id: Some("test_id2".to_string()),
                expire_timestamp: Some(10),
                lock_price: Some(U256::from(10u64)),
                ..create_order()
            },
            Order {
                status: OrderStatus::PendingSubmission,
                proof_id: Some("test_id4".to_string()),
                expire_timestamp: Some(10),
                lock_price: Some(U256::from(10u64)),
                ..create_order()
            },
        ];
        for (i, order) in orders.iter_mut().enumerate() {
            order.request.id = U256::from(i);
            db.add_order(order.clone()).await.unwrap();
        }

        let agg_proofs = db.get_aggregation_proofs().await.unwrap();

        assert_eq!(agg_proofs.len(), 2);

        let agg_proof = &agg_proofs[0];
        assert_eq!(agg_proof.order_id, orders[1].id());
        assert_eq!(agg_proof.proof_id, "test_id1");
        assert_eq!(agg_proof.expiration, 10);
        assert_eq!(agg_proof.fee, U256::from(10u64));

        let agg_proof = &agg_proofs[1];
        assert_eq!(agg_proof.order_id, orders[2].id());
        assert_eq!(agg_proof.proof_id, "test_id2");
        assert_eq!(agg_proof.expiration, 10);
        assert_eq!(agg_proof.fee, U256::from(10u64));

        let db_order = db.get_order(&agg_proofs[0].order_id).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Aggregating);
        let db_order = db.get_order(&agg_proofs[1].order_id).await.unwrap().unwrap();
        assert_eq!(db_order.status, OrderStatus::Aggregating);
    }

    #[sqlx::test]
    async fn get_current_batch(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let batch_id = db.get_current_batch().await.unwrap();
        assert_eq!(batch_id, 1);

        let batch = db.get_batch(batch_id).await.unwrap();
        assert_eq!(batch.status, BatchStatus::Aggregating);

        let batch_id = db.get_current_batch().await.unwrap();
        assert_eq!(batch_id, 1);

        db.set_batch_status(1, BatchStatus::PendingCompression).await.unwrap();

        let batch = db.get_batch(batch_id).await.unwrap();
        assert_eq!(batch.status, BatchStatus::PendingCompression);

        let batch_id = db.get_current_batch().await.unwrap();
        assert_eq!(batch_id, 1);
    }

    #[sqlx::test]
    async fn add_batch(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let batch_id = 1;
        let batch = Batch { start_time: Utc::now(), ..Default::default() };
        db.add_batch(batch_id, batch.clone()).await.unwrap();

        let batch = db.get_batch(batch_id).await.unwrap();
        assert_eq!(batch.status, BatchStatus::Aggregating);
    }

    #[sqlx::test]
    async fn complete_batch(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let batch_id = 1;
        let batch = Batch {
            aggregation_state: Some(AggregationState {
                guest_state: GuestState::initial([1u32; 8]),
                claim_digests: vec![],
                groth16_proof_id: None,
                proof_id: "a".to_string(),
            }),
            ..Default::default()
        };
        db.add_batch(batch_id, batch).await.unwrap();

        let g16_proof_id = "Testg16";
        db.complete_batch(batch_id, g16_proof_id).await.unwrap();

        let db_batch = db.get_batch(batch_id).await.unwrap();
        assert_eq!(db_batch.status, BatchStatus::Complete);
        assert_eq!(db_batch.aggregation_state.unwrap().groth16_proof_id.unwrap(), g16_proof_id);
    }

    #[sqlx::test]
    async fn get_complete_batch(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let batch_id = 1;
        let batch =
            Batch { start_time: Utc::now(), status: BatchStatus::Complete, ..Default::default() };

        db.add_batch(batch_id, batch.clone()).await.unwrap();

        let (db_batch_id, db_batch) = db.get_complete_batch().await.unwrap().unwrap();
        assert_eq!(db_batch_id, batch_id);
        assert_eq!(db_batch.status, BatchStatus::PendingSubmission);
    }

    #[sqlx::test]
    async fn set_batch_submitted(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let batch_id = db.get_current_batch().await.unwrap();
        db.set_batch_submitted(batch_id).await.unwrap();

        let db_batch = db.get_batch(batch_id).await.unwrap();
        assert_eq!(db_batch.status, BatchStatus::Submitted);
    }

    #[sqlx::test]
    async fn set_batch_failure(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let batch_id = db.get_current_batch().await.unwrap();
        let err_msg = "test_err";
        db.set_batch_failure(batch_id, err_msg.into()).await.unwrap();

        let db_batch = db.get_batch(batch_id).await.unwrap();
        assert_eq!(db_batch.status, BatchStatus::Failed);
        assert_eq!(db_batch.error_msg, Some(err_msg.into()));
    }

    #[sqlx::test]
    async fn update_batch(pool: SqlitePool) {
        // Create a persistent DB for manual testing:
        //
        // let db_url = "sqlite:///tmp/test.db";
        // if !Sqlite::database_exists(db_url).await.unwrap() {
        //     Sqlite::create_database(db_url).await.unwrap()
        // }
        // let tmp_pool = SqlitePool::connect("sqlite:///tmp/test.db").await.unwrap();
        // sqlx::migrate!("./migrations").run(&tmp_pool).await.unwrap();

        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());
        let mut order1 = create_order();
        order1.request.id = U256::from(11);
        db.add_order(order1.clone()).await.unwrap();
        let mut order2 = create_order();
        order2.request.id = U256::from(12);
        db.add_order(order2.clone()).await.unwrap();

        let batch_id = 1;
        let agg_proofs = [
            AggregationOrder {
                proof_id: "a".to_string(),
                order_id: order1.id(),
                expiration: 20,
                fee: U256::from(5),
            },
            AggregationOrder {
                proof_id: "b".to_string(),
                order_id: order2.id(),
                expiration: 25,
                fee: U256::from(10),
            },
        ];
        let claim_digests = vec![[1u32; 8].into(), [2u32; 8].into()];
        let mut guest_state = GuestState::initial([3u32; 8]);
        guest_state.mmr.extend(&claim_digests);
        let agg_state = AggregationState {
            guest_state,
            proof_id: "c".to_string(),
            claim_digests: claim_digests.clone(),
            groth16_proof_id: None,
        };

        let base_fees = U256::from(10);
        let batch = Batch {
            start_time: Utc::now(),
            deadline: Some(100),
            fees: base_fees,
            ..Default::default()
        };

        db.add_batch(batch_id, batch.clone()).await.unwrap();
        db.update_batch(batch_id, &agg_state, &agg_proofs, Some("proof_id".to_string()))
            .await
            .unwrap();

        let db_batch = db.get_batch(batch_id).await.unwrap();
        assert_eq!(db_batch.status, BatchStatus::PendingCompression);
        assert_eq!(db_batch.orders, vec![order1.id(), order2.id()]);
        assert_eq!(db_batch.deadline, Some(20));
        assert_eq!(db_batch.fees, U256::from(25));
        assert!(db_batch.aggregation_state.is_some());
        let agg_state = db_batch.aggregation_state.unwrap();
        assert_eq!(agg_state.groth16_proof_id.as_ref(), None);
        assert!(!agg_state.guest_state.is_initial());
        assert_eq!(&agg_state.proof_id, "c");
        assert_eq!(&agg_state.claim_digests, &claim_digests);
    }

    #[sqlx::test]
    async fn set_and_check_request_fulfilled(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let request_id = U256::from(123);
        let block_number = 42;

        // Initially should not be fulfilled
        assert!(!db.is_request_fulfilled(request_id).await.unwrap());

        // Set as fulfilled
        db.set_request_fulfilled(request_id, block_number).await.unwrap();

        // Should now be fulfilled
        assert!(db.is_request_fulfilled(request_id).await.unwrap());

        // Different request should still not be fulfilled
        assert!(!db.is_request_fulfilled(U256::from(413)).await.unwrap());
    }

    #[sqlx::test]
    async fn set_and_check_request_locked(pool: SqlitePool) {
        let db: DbObj = Arc::new(SqliteDb::from(pool).await.unwrap());

        let request_id = U256::from(123);
        let locker = "test_locker";
        let block_number = 42;
        // Initially should not be locked
        assert!(!db.is_request_locked(request_id).await.unwrap());

        // Set as locked
        db.set_request_locked(request_id, locker, block_number).await.unwrap();

        // Should now be locked
        assert!(db.is_request_locked(request_id).await.unwrap());

        // Different request should still not be locked
        assert!(!db.is_request_locked(U256::from(413)).await.unwrap());
    }
}
