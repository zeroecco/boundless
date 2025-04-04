// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj, RECEIPT_PATH},
    Agent,
};
use anyhow::{Context, Result};
use uuid::Uuid;
use workflow_common::UnionReq;

/// Run the union operation
pub async fn union(agent: &Agent, job_id: &Uuid, request: &UnionReq) -> Result<()> {
    tracing::info!("Starting union for job_id: {job_id}");
    let mut conn = redis::get_connection(&agent.redis_pool).await?;

    // setup redis keys - read from the RECEIPT_PATH where keccak stores its output
    let job_prefix = format!("job:{job_id}");
    let receipts_prefix = format!("{job_prefix}:{RECEIPT_PATH}");
    let left_receipt_key = format!("{receipts_prefix}:{}", request.left);
    let right_receipt_key = format!("{receipts_prefix}:{}", request.right);

    // Fetch left receipt first
    let left_receipt_bytes: Vec<u8> = conn
        .get(&left_receipt_key)
        .await
        .with_context(|| format!("Left receipt not found for key: {left_receipt_key}"))?;

    // Start deserializing left receipt
    let left_receipt_future = tokio::task::spawn_blocking(move || -> Result<_> {
        deserialize_obj(&left_receipt_bytes).context("Failed to deserialize left receipt")
    });

    // While left receipt is deserializing, fetch right receipt
    let right_receipt_bytes: Vec<u8> = conn
        .get(&right_receipt_key)
        .await
        .with_context(|| format!("Right receipt not found for key: {right_receipt_key}"))?;

    // Wait for left receipt deserialization to complete
    let left_receipt = left_receipt_future
        .await
        .context("Failed to join left receipt deserialization task")?
        .context("Failed to deserialize left receipt")?;

    // Deserialize right receipt
    let right_receipt =
        deserialize_obj(&right_receipt_bytes).context("Failed to deserialize right receipt")?;

    // run union
    tracing::info!("Union {job_id} - {} + {} -> {}", request.left, request.right, request.idx);

    let unioned = agent
        .prover
        .as_ref()
        .context("Missing prover from union prove task")?
        .union(&left_receipt, &right_receipt)
        .context("Failed to union on left/right receipt")?
        .into_unknown();

    // send result to redis - store output in the same RECEIPT_PATH
    let union_result = serialize_obj(&unioned).context("Failed to serialize union receipt")?;
    let output_key = format!("{receipts_prefix}:{}", request.idx);
    redis::set_key_with_expiry(&mut conn, &output_key, union_result, Some(agent.args.redis_ttl))
        .await
        .context("Failed to set redis key for union receipt")?;

    tracing::info!("Union complete {job_id} - {} -> {}", request.left, request.idx);

    Ok(())
}
