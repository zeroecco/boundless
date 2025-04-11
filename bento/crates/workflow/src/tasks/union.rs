// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj},
    Agent,
};
use anyhow::{bail, Context, Result};
use std::time::Instant;
use uuid::Uuid;
use workflow_common::{UnionReq, KECCAK_RECEIPT_PATH};

/// Maximum number of union attempts before giving up
const MAX_UNION_ATTEMPTS: usize = 3;

/// Run the union operation
pub async fn union(agent: &Agent, job_id: &Uuid, request: &UnionReq) -> Result<()> {
    tracing::info!("Starting union for job_id: {job_id}");
    let mut conn = redis::get_connection(&agent.redis_pool).await?;

    // setup redis keys
    let keccak_receipts_prefix = format!("job:{job_id}:{KECCAK_RECEIPT_PATH}");
    let left_receipt_key = format!("{keccak_receipts_prefix}:{}", request.left);
    let right_receipt_key = format!("{keccak_receipts_prefix}:{}", request.right);

    // Check if both receipts exist before attempting to union
    let keys_exist: Vec<bool> = conn
        .exists(vec![&left_receipt_key, &right_receipt_key])
        .await
        .context("Failed to check if receipt keys exist in Redis")?;

    if keys_exist.iter().any(|&exists| !exists) {
        bail!("One or more receipts do not exist: {left_receipt_key}, {right_receipt_key}");
    }

    // get assets from redis
    let (left_receipt_bytes, right_receipt_bytes): (Vec<u8>, Vec<u8>) = conn
        .mget(vec![&left_receipt_key, &right_receipt_key])
        .await
        .context("Failed to get redis keys for left and right receipts")?;

    if left_receipt_bytes.is_empty() || right_receipt_bytes.is_empty() {
        bail!("One or more receipts are empty");
    }

    let left_receipt =
        deserialize_obj(&left_receipt_bytes).context("Failed to deserialize left receipt")?;

    let right_receipt =
        deserialize_obj(&right_receipt_bytes).context("Failed to deserialize right receipt")?;

    // run union
    tracing::info!("Union {job_id} - {} + {} -> {}", request.left, request.right, request.idx);

    // Start timer for performance tracking
    let start_time = Instant::now();

    // Try a few times to union - sometimes there are transient issues
    let mut union_result = None;
    let mut last_error = None;

    for attempt in 0..MAX_UNION_ATTEMPTS {
        match attempt {
            0 => tracing::info!("Attempting union (first try)"),
            _ => tracing::info!("Retrying union (attempt {})", attempt + 1),
        }

        match agent
            .prover
            .as_ref()
            .context("Missing prover from union prove task")?
            .union(&left_receipt, &right_receipt)
        {
            Ok(result) => {
                tracing::info!(
                    "Union succeeded after {} attempt(s) in {:?}",
                    attempt + 1,
                    start_time.elapsed()
                );
                union_result = Some(result.into_unknown());
                break;
            }
            Err(err) => {
                tracing::warn!("Union attempt {} failed: {}", attempt + 1, err);
                last_error = Some(err);

                // Short delay before retry
                if attempt < MAX_UNION_ATTEMPTS - 1 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    let unioned = match union_result {
        Some(result) => result,
        None => {
            bail!(
                "Union failed after {} attempts: {}",
                MAX_UNION_ATTEMPTS,
                last_error.unwrap_or_else(|| anyhow::anyhow!("Unknown error"))
            )
        }
    };

    // send result to redis
    let union_result = serialize_obj(&unioned).context("Failed to serialize union receipt")?;
    let output_key = format!("{keccak_receipts_prefix}:{}", request.idx);
    redis::set_key_with_expiry(&mut conn, &output_key, union_result, Some(agent.args.redis_ttl))
        .await
        .context("Failed to set redis key for union receipt")?;

    tracing::info!(
        "Union complete {job_id} - {} + {} -> {}",
        request.left,
        request.right,
        request.idx
    );

    Ok(())
}
