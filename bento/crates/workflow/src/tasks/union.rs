// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj, COPROC_CB_PATH, RECEIPT_PATH},
    Agent,
};
use anyhow::{Context, Result};
use uuid::Uuid;
use workflow_common::UnionReq;

/// Run the union operation
pub async fn union(agent: &Agent, job_id: &Uuid, request: &UnionReq) -> Result<()> {
    tracing::info!("Starting union for job_id: {job_id}");
    let mut conn = redis::get_connection(&agent.redis_pool).await?;

    // Get the claim digests for the task IDs from Redis
    // First, try to get the task ID to digest mapping
    let job_prefix = format!("job:{job_id}");
    let left_task_key = format!("{job_prefix}:task:{}", request.left);
    let right_task_key = format!("{job_prefix}:task:{}", request.right);

    // Try to get the claim digests for the task IDs
    let left_digest: Option<String> = conn.get(&left_task_key).await.ok();
    let right_digest: Option<String> = conn.get(&right_task_key).await.ok();

    // Set up redis keys for receipts
    let receipts_prefix = format!("{job_prefix}:{RECEIPT_PATH}");

    // If we have the digests, use them, otherwise try the task IDs directly
    let left_receipt_key = if let Some(digest) = left_digest {
        format!("{receipts_prefix}:{}", digest)
    } else {
        // If we can't find the mapping, try fallback to old format with task ID
        // Try to read from COPROC_CB_PATH first to get the claim digest
        let coproc_key = format!("{job_prefix}:{COPROC_CB_PATH}:{}", request.left);
        if let Ok(coproc_data) = conn.get::<_, Vec<u8>>(&coproc_key).await {
            if let Ok(digest_str) = String::from_utf8(coproc_data.clone()) {
                // Try to parse it as a hexadecimal string
                if digest_str.len() == 64 && digest_str.chars().all(|c| c.is_ascii_hexdigit()) {
                    format!("{receipts_prefix}:{}", digest_str)
                } else {
                    // If the data isn't a valid digest string, just use the task ID
                    format!("{receipts_prefix}:{}", request.left)
                }
            } else {
                format!("{receipts_prefix}:{}", request.left)
            }
        } else {
            format!("{receipts_prefix}:{}", request.left)
        }
    };

    let right_receipt_key = if let Some(digest) = right_digest {
        format!("{receipts_prefix}:{}", digest)
    } else {
        // If we can't find the mapping, try fallback to old format with task ID
        // Try to read from COPROC_CB_PATH first to get the claim digest
        let coproc_key = format!("{job_prefix}:{COPROC_CB_PATH}:{}", request.right);
        if let Ok(coproc_data) = conn.get::<_, Vec<u8>>(&coproc_key).await {
            if let Ok(digest_str) = String::from_utf8(coproc_data.clone()) {
                // Try to parse it as a hexadecimal string
                if digest_str.len() == 64 && digest_str.chars().all(|c| c.is_ascii_hexdigit()) {
                    format!("{receipts_prefix}:{}", digest_str)
                } else {
                    // If the data isn't a valid digest string, just use the task ID
                    format!("{receipts_prefix}:{}", request.right)
                }
            } else {
                format!("{receipts_prefix}:{}", request.right)
            }
        } else {
            format!("{receipts_prefix}:{}", request.right)
        }
    };

    tracing::info!("Fetching left receipt from: {left_receipt_key}");
    // get assets from redis
    let left_receipt_bytes: Vec<u8> = conn.get(&left_receipt_key).await.with_context(|| {
        format!("segment data not found for root receipt key: {left_receipt_key}")
    })?;
    let left_receipt =
        deserialize_obj(&left_receipt_bytes).context("Failed to deserialize left receipt")?;

    tracing::info!("Fetching right receipt from: {right_receipt_key}");
    let right_receipt_bytes: Vec<u8> = conn.get(&right_receipt_key).await.with_context(|| {
        format!("segment data not found for root receipt key: {right_receipt_key}")
    })?;
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

    // send result to redis
    let union_result = serialize_obj(&unioned).context("Failed to serialize union receipt")?;
    let output_key = format!("{receipts_prefix}:{}", request.idx);
    redis::set_key_with_expiry(&mut conn, &output_key, union_result, Some(agent.args.redis_ttl))
        .await
        .context("Failed to set redis key for union receipt")?;

    tracing::info!("Union complete {job_id} - {}", request.left);

    Ok(())
}
