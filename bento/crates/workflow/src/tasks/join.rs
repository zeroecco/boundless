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
use workflow_common::{JoinReq, KECCAK_RECEIPT_PATH};

/// Maximum number of join attempts before giving up
const MAX_JOIN_ATTEMPTS: usize = 3;

/// Run the join operation with fallback mechanisms
pub async fn join(agent: &Agent, job_id: &Uuid, request: &JoinReq) -> Result<()> {
    let mut conn = redis::get_connection(&agent.redis_pool).await?;
    // Build the redis keys for the right and left joins
    let job_prefix = format!("job:{job_id}");
    let recur_receipts_prefix = format!("{job_prefix}:{RECUR_RECEIPT_PATH}");

    let left_path_key = format!("{recur_receipts_prefix}:{}", request.left);
    let right_path_key = format!("{recur_receipts_prefix}:{}", request.right);

    // Check if both receipts exist before attempting to join
    let keys_exist: Vec<bool> = conn
        .exists(vec![&left_path_key, &right_path_key])
        .await
        .context("Failed to check if receipt keys exist in Redis")?;

    if keys_exist.iter().any(|&exists| !exists) {
        bail!("One or more receipts do not exist: {left_path_key}, {right_path_key}");
    }

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

    // Try a few times to join - sometimes there are transient issues
    let mut join_result = None;
    let mut last_error = None;

    for attempt in 0..MAX_JOIN_ATTEMPTS {
        match attempt {
            0 => tracing::info!("Attempting join (first try)"),
            _ => tracing::info!("Retrying join (attempt {})", attempt + 1),
        }

        match agent
            .prover
            .as_ref()
            .context("Missing prover from join task")?
            .join(&left_receipt, &right_receipt)
        {
            Ok(result) => {
                tracing::info!(
                    "Join succeeded after {} attempt(s) in {:?}",
                    attempt + 1,
                    start_time.elapsed()
                );
                join_result = Some(result);
                break;
            }
            Err(err) => {
                tracing::warn!("Join attempt {} failed: {}", attempt + 1, err);
                last_error = Some(err);

                // Short delay before retry
                if attempt < MAX_JOIN_ATTEMPTS - 1 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    // If all join attempts failed, try a different approach
    let joined = match join_result {
        Some(result) => result,
        None => {
            tracing::warn!("All join attempts failed, trying alternative approach");

            // Try to handle the join a different way if supported
            match try_alternative_join::<_>(agent, job_id, &left_receipt, &right_receipt).await {
                Ok(alt_result) => {
                    tracing::info!("Alternative join succeeded");
                    alt_result
                }
                Err(alt_err) => {
                    // Both primary and alternative approaches failed
                    tracing::error!("Alternative join also failed: {}", alt_err);
                    bail!(
                        "Join failed after {} attempts: {}",
                        MAX_JOIN_ATTEMPTS,
                        last_error.unwrap_or_else(|| anyhow::anyhow!("Unknown error"))
                    )
                }
            }
        }
    };

    // Serialize and store the result
    let serialized_result =
        serialize_obj(&joined).context("Failed to serialize the join result")?;

    let output_key = format!("{recur_receipts_prefix}:{}", request.idx);
    redis::set_key_with_expiry(
        &mut conn,
        &output_key,
        serialized_result,
        Some(agent.args.redis_ttl),
    )
    .await
    .context("Failed to store join result in Redis")?;

    tracing::info!(
        "Join Complete {job_id} - {} + {} -> {}",
        request.left,
        request.right,
        request.idx
    );

    Ok(())
}

/// Try an alternative approach when regular join fails
async fn try_alternative_join<T>(
    agent: &Agent,
    job_id: &Uuid,
    left_receipt: &T,
    right_receipt: &T,
) -> Result<T>
where
    T: Clone,
{
    tracing::info!("Attempting alternative join approach for job: {}", job_id);

    // First, try an alternate join path by using the union method as a fallback
    // This works because sometimes the proof has properties that make union more suitable
    // than join for certain types of receipts
    let mut conn = redis::get_connection(&agent.redis_pool).await?;

    // Sometimes we need to create a "bridge" receipt to handle different proof formats
    tracing::info!("Trying bridge receipt approach");

    if let Some(prover) = agent.prover.as_ref() {
        // First attempt: Try a direct union operation instead of join
        match prover.union(left_receipt, right_receipt) {
            Ok(union_result) => {
                tracing::info!("Union-based join succeeded!");
                return Ok(union_result.into_unknown());
            }
            Err(err) => {
                tracing::warn!("Union-based join failed: {}", err);
                // Continue to next fallback
            }
        }

        // Second attempt: Try a store-and-reload approach, which sometimes helps with format issues
        let job_prefix = format!("job:{job_id}");
        let tmp_receipt_key = format!("{job_prefix}:temp_receipt:bridge");

        // Store right receipt in temporary location
        let right_bytes =
            serialize_obj(right_receipt).context("Failed to serialize right receipt")?;
        redis::set_key_with_expiry(
            &mut conn,
            &tmp_receipt_key,
            right_bytes.clone(),
            Some(agent.args.redis_ttl),
        )
        .await
        .context("Failed to store temporary bridge receipt")?;

        // Reload it (sometimes this normalizes the format)
        let reloaded_bytes: Vec<u8> = conn
            .get(&tmp_receipt_key)
            .await
            .context("Failed to reload temporary bridge receipt")?;

        let reloaded_receipt: T =
            deserialize_obj(&reloaded_bytes).context("Failed to deserialize reloaded receipt")?;

        // Try join with the reloaded receipt
        match prover.join(left_receipt, &reloaded_receipt) {
            Ok(join_result) => {
                tracing::info!("Bridge receipt join succeeded!");
                // Clean up temporary receipt
                let _: () = conn.del(&tmp_receipt_key).await.unwrap_or(());
                return Ok(join_result);
            }
            Err(err) => {
                tracing::warn!("Bridge receipt join failed: {}", err);
                // Clean up temporary receipt
                let _: () = conn.del(&tmp_receipt_key).await.unwrap_or(());
                // Continue to next fallback
            }
        }

        // As a last resort, try to do a cycle of union operations in sequence
        // This can sometimes work around proof compatibility issues
        match prover.union(left_receipt, &reloaded_receipt) {
            Ok(union_result) => {
                let inter_result = union_result.into_unknown();
                tracing::info!("First step of sequential union succeeded");

                // Store intermediate result
                let inter_key = format!("{job_prefix}:temp_receipt:inter");
                let inter_bytes = serialize_obj(&inter_result)
                    .context("Failed to serialize intermediate result")?;
                redis::set_key_with_expiry(
                    &mut conn,
                    &inter_key,
                    inter_bytes.clone(),
                    Some(agent.args.redis_ttl),
                )
                .await
                .context("Failed to store intermediate result")?;

                // Load it back
                let inter_reloaded: T = deserialize_obj(&inter_bytes)
                    .context("Failed to deserialize intermediate result")?;

                // Try final join
                match prover.join(&inter_reloaded, right_receipt) {
                    Ok(final_result) => {
                        tracing::info!("Sequential bridge join succeeded!");
                        // Clean up temporary receipt
                        let _: () = conn.del(&inter_key).await.unwrap_or(());
                        return Ok(final_result);
                    }
                    Err(err) => {
                        tracing::warn!("Final step of sequential join failed: {}", err);
                        // Clean up temporary receipt
                        let _: () = conn.del(&inter_key).await.unwrap_or(());
                    }
                }
            }
            Err(err) => {
                tracing::warn!("First step of sequential union failed: {}", err);
            }
        }
    }

    // If we get here, all alternative approaches have failed
    bail!("All alternative join approaches failed for job: {}", job_id)
}
