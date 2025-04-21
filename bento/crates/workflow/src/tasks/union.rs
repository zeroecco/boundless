// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::Agent;
use anyhow::{Context, Result};
use redis::AsyncCommands;
use task_queue::Task;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

/// Run the union operation
pub async fn union(agent: &Agent, task: &Task) -> Result<()> {
    let job_id = task.job_id;
    tracing::info!("Starting union for job_id: {job_id}");
    let mut conn = agent.redis_conn.clone();

    // First receipt is passed directly via task.data
    let mut left_receipt = bincode::deserialize(&task.data)
        .context("Failed to deserialize receipt from task.data")?;

    // Setup Redis prefix
    let keccak_receipts_prefix = format!("job:{job_id}:keccak");

    // Start with the next receipt (index 2)
    let mut counter = 1;

    // Continuous union loop
    loop {
        counter += 1;
        tracing::info!("Attempting to union with keccak receipt {}", counter);

        // Try to get the next receipt with polling
        let right_receipt_bytes = match poll_for_receipt(counter, &job_id, &mut conn, 5, Duration::from_secs(5)).await {
            Ok(receipt) => receipt,
            Err(_) => {
                // If we've tried enough times and the receipt isn't available,
                // store our current progress and exit
                let receipt_key = format!("{keccak_receipts_prefix}:partial_{}", counter-1);
                let bytes = bincode::serialize(&left_receipt)
                    .context("Failed to serialize partial union result")?;
                agent
                    .set_in_redis(&receipt_key, &bytes, Some(agent.args.redis_ttl))
                    .await
                    .context("Failed to store partial union result")?;

                tracing::info!("Keccak receipt {} not available after polling, stored partial result and exiting", counter);
                return Ok(());
            }
        };
        let right_receipt = bincode::deserialize(&right_receipt_bytes)
            .context("Failed to deserialize keccak receipt from Redis")?;

        // Perform the union
        tracing::info!("Unioning with keccak receipt {}", counter);
        let unioned = agent
            .prover
            .as_ref()
            .context("Missing prover from union task")?
            .union(&left_receipt, &right_receipt)
            .context("Failed to union receipts")?
            .into_unknown();

        // Store the intermediate union result
        let receipt_key = format!("{keccak_receipts_prefix}:joined_{}", counter);
        let bytes = bincode::serialize(&unioned)
            .context("Failed to serialize unioned result")?;
        agent
            .set_in_redis(&receipt_key, &bytes, Some(agent.args.redis_ttl))
            .await
            .context("Failed to store unioned result")?;

        tracing::info!("Successfully unioned with keccak receipt {}", counter);

        // Continue with the next receipt
        left_receipt = unioned;
    }
}

/// Poll for a keccak receipt until it's available or max attempts reached
async fn poll_for_receipt(
    id: usize,
    job_id: &Uuid,
    conn: &mut redis::aio::ConnectionManager,
    max_attempts: usize,
    delay: Duration,
) -> Result<Vec<u8>> {
    // Use consistent key format with job prefix
    let keccak_receipts_prefix = format!("job:{job_id}:keccak");
    let store_key = format!("{keccak_receipts_prefix}:{}", id);

    for attempt in 1..=max_attempts {
        tracing::info!("Polling for keccak receipt {} (attempt {}/{})", id, attempt, max_attempts);

        // Check if the key exists
        let exists: bool = conn.exists(&store_key).await.unwrap_or(false);

        if exists {
            let receipt_bytes: Vec<u8> = conn.get(&store_key)
                .await
                .context("Failed to fetch keccak receipt from Redis")?;

            return Ok(receipt_bytes);
        }

        // Wait before trying again
        if attempt < max_attempts {
            tracing::info!("Keccak receipt {} not found, waiting for {:?} before retry", id, delay);
            sleep(delay).await;
        }
    }

    Err(anyhow::anyhow!("Keccak receipt {} not available after {} polling attempts", id, max_attempts))
}
