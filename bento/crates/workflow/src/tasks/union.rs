// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj},
    Agent,
};
use anyhow::{Context, Result};
use uuid::Uuid;
use workflow_common::{UnionReq, KECCAK_RECEIPT_PATH};

/// Run the union operation
pub async fn union(agent: &Agent, job_id: &Uuid, request: &UnionReq) -> Result<()> {
    tracing::info!("Starting union for job_id: {job_id}");

    // Setup redis keys - read from the RECEIPT_PATH where keccak stores its output
    let job_prefix = format!("job:{job_id}");
    let receipts_prefix = format!("{job_prefix}:{KECCAK_RECEIPT_PATH}");
    let left_receipt_key = format!("{receipts_prefix}:{}", request.left);
    let right_receipt_key = format!("{receipts_prefix}:{}", request.right);
    let output_key = format!("{receipts_prefix}:{}", request.idx);

    // Get a single Redis connection for reuse
    let mut conn = agent.get_redis_connection().await?;

    // Fetch both receipts in a single batch operation
    tracing::info!("Batch fetching receipts");
    let receipts: Vec<Vec<u8>> = conn.mget(&[&left_receipt_key, &right_receipt_key]).await
        .with_context(|| "Failed to fetch receipts")?;

    let left_bytes = &receipts[0];
    let right_bytes = &receipts[1];

    // Deserialize both receipts
    tracing::info!("Deserializing receipts");
    let left_receipt = deserialize_obj(left_bytes)
        .context("Failed to deserialize left receipt")?;

    let right_receipt = deserialize_obj(right_bytes)
        .context("Failed to deserialize right receipt")?;

    // Run union
    tracing::info!("Union {job_id} - {} + {} -> {}", request.left, request.right, request.idx);
    let unioned = agent
        .prover
        .as_ref()
        .context("Missing prover from union prove task")?
        .union(&left_receipt, &right_receipt)
        .context("Failed to union on left/right receipt")?
        .into_unknown();

    // Serialize the result and store in Redis in a background task
    let pool_storage = agent.redis_pool.clone();
    let ttl = agent.args.redis_ttl;
    let job_id_clone = *job_id;
    let left_idx = request.left;
    let output_key_clone = output_key.clone();

    tokio::task::spawn(async move {
        // Serialize in a blocking task
        let union_result = match tokio::task::spawn_blocking(move || serialize_obj(&unioned)).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                tracing::error!("Failed to serialize union receipt: {}", e);
                return;
            }
            Err(e) => {
                tracing::error!("Failed to join serialization task: {}", e);
                return;
            }
        };

        // Store in Redis
        match redis::get_connection(&pool_storage).await {
            Ok(mut conn) => {
                if let Err(e) =
                    redis::set_key_with_expiry(&mut conn, &output_key_clone, union_result, Some(ttl))
                        .await
                {
                    tracing::error!("Failed to store union receipt: {}", e);
                    return;
                }
                tracing::info!("Union result stored for {job_id_clone} - {left_idx}");
            }
            Err(e) => {
                tracing::error!("Failed to get Redis connection for storage: {}", e);
            }
        }
    });

    tracing::info!("Union computation complete {job_id} - {} -> {}", request.left, request.idx);
    Ok(())
}
