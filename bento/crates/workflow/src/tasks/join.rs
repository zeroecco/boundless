// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj, KECCAK_RECEIPT_PATH, RECUR_RECEIPT_PATH},
    Agent,
};
use anyhow::{bail, Context, Result};
use std::time::Instant;
use uuid::Uuid;
use workflow_common::JoinReq;

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
            match try_alternative_join(agent, job_id, &left_receipt, &right_receipt).await {
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
async fn try_alternative_join(
    agent: &Agent,
    job_id: &Uuid,
    left_receipt: &impl risc0_zkvm::ProofType,
    right_receipt: &impl risc0_zkvm::ProofType,
) -> Result<impl risc0_zkvm::ProofType> {
    tracing::info!("Attempting alternative join approach");

    // Try a different join algorithm that might work better for certain cases
    // First, let's try with different parameters
    match agent.prover.as_ref().context("Missing prover from alternative join task")? {
        prover => {
            // For now, we'll simply try a more intensive join attempt with longer timeout
            // This is a placeholder for a more sophisticated alternative approach

            // In a real implementation, we might:
            // 1. Try a different algorithm
            // 2. Use a special case handler for known edge cases
            // 3. Try to repair/normalize the proofs before joining
            // 4. Use a completely different join strategy

            // For demonstration, we'll just log that we're trying a more intensive approach
            tracing::info!("Trying intensive join approach");

            // This is just a placeholder - we'd normally have a dedicated implementation here
            // that would handle cases the regular join can't handle
            bail!("Alternative join not yet fully implemented");

            // When implemented, it would return something like:
            // Ok(prover.alternative_join(left_receipt, right_receipt)?)
        }
    }
}
