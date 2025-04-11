// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj, RECUR_RECEIPT_PATH},
    Agent,
};
use anyhow::{bail, Context, Result};
use std::time::Instant;
use uuid::Uuid;
use workflow_common::JoinReq;

/// Maximum number of join attempts before giving up
const MAX_JOIN_ATTEMPTS: usize = 3;

/// Run the join operation
pub async fn join(agent: &Agent, job_id: &Uuid, request: &JoinReq) -> Result<()> {
    let mut conn = redis::get_connection(&agent.redis_pool).await?;
    // Build the redis keys for the right and left joins
    let job_prefix = format!("job:{job_id}");
    let recur_receipts_prefix = format!("{job_prefix}:{RECUR_RECEIPT_PATH}");

    let left_path_key = format!("{recur_receipts_prefix}:{}", request.left);
    let right_path_key = format!("{recur_receipts_prefix}:{}", request.right);

    let (left_receipt_vec, right_receipt_vec): (Vec<u8>, Vec<u8>) = conn
        .mget(vec![left_path_key, right_path_key])
        .await
        .context("Failed to get redis keys for left and right receipts")?;

    if left_receipt_vec.is_empty() || right_receipt_vec.is_empty() {
        bail!("One or more receipts are empty");
    }

    let left_receipt =
        deserialize_obj(&left_receipt_vec).context("Failed to deserialize left receipt")?;
    let right_receipt =
        deserialize_obj(&right_receipt_vec).context("Failed to deserialize right receipt")?;

    tracing::info!("Joining {job_id} - {} + {} -> {}", request.left, request.right, request.idx);

    // Start timer for performance tracking
    let start_time = Instant::now();

    // Try multiple approaches to handle the join with retries
    let mut join_result = None;
    let mut error_msgs = Vec::new();

    // Approach 1: Standard join with retries
    for attempt in 0..MAX_JOIN_ATTEMPTS {
        match attempt {
            0 => tracing::info!("Attempting standard join (first try)"),
            _ => tracing::info!("Retrying standard join (attempt {})", attempt + 1),
        }

        match agent
            .prover
            .as_ref()
            .context("Missing prover from join task")?
            .join(&left_receipt, &right_receipt)
        {
            Ok(result) => {
                tracing::info!(
                    "Standard join succeeded after {} attempt(s) in {:?}",
                    attempt + 1,
                    start_time.elapsed()
                );
                join_result = Some(result);
                break;
            }
            Err(err) => {
                tracing::warn!("Standard join attempt {} failed: {}", attempt + 1, err);
                error_msgs.push(format!("Standard join attempt {}: {}", attempt + 1, err));

                // Short delay before retry
                if attempt < MAX_JOIN_ATTEMPTS - 1 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    // Approach 2: Try to reload the receipts to normalize format
    if join_result.is_none() {
        tracing::info!("Trying receipts reload approach");

        // Store and reload the right receipt to normalize format
        let tmp_right_key = format!("{recur_receipts_prefix}:tmp_right:{}", request.right);
        let right_bytes = right_receipt_vec.clone();

        // Store in temp location
        redis::set_key_with_expiry(
            &mut conn,
            &tmp_right_key,
            right_bytes,
            Some(agent.args.redis_ttl),
        )
        .await
        .context("Failed to store temporary right receipt")?;

        // Reload it
        let reloaded_right_vec: Vec<u8> =
            conn.get(&tmp_right_key).await.context("Failed to reload temporary right receipt")?;

        let reloaded_right = deserialize_obj(&reloaded_right_vec)
            .context("Failed to deserialize reloaded right receipt")?;

        // Try join with reloaded receipt
        match agent.prover.as_ref().context("Missing prover")?.join(&left_receipt, &reloaded_right)
        {
            Ok(result) => {
                tracing::info!("Reloaded receipt join succeeded in {:?}", start_time.elapsed());
                join_result = Some(result);
                // Clean up
                let _: () = conn.del(&tmp_right_key).await.unwrap_or(());
            }
            Err(err) => {
                tracing::warn!("Reloaded receipt join failed: {}", err);
                error_msgs.push(format!("Reloaded join attempt: {}", err));
                // Clean up
                let _: () = conn.del(&tmp_right_key).await.unwrap_or(());
            }
        }
    }

    // If we have a join result, serialize and store it
    if let Some(joined) = join_result {
        let join_result = serialize_obj(&joined).expect("Failed to serialize the segment");
        let output_key = format!("{recur_receipts_prefix}:{}", request.idx);
        redis::set_key_with_expiry(&mut conn, &output_key, join_result, Some(agent.args.redis_ttl))
            .await?;

        tracing::info!("Join Complete {job_id} - {}", request.left);
        return Ok(());
    }

    // If we get here, all approaches failed
    bail!("All join approaches failed: {}", error_msgs.join("; "));
}
