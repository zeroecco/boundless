// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{tasks::RECUR_RECEIPT_PATH, Agent};
use anyhow::{Context, Result};
use redis::AsyncCommands;
use risc0_zkvm::{ReceiptClaim, SuccinctReceipt};
use task_queue::Task;
use tokio::time::{sleep, Duration};

/// Run the join operation
pub async fn join(agent: &Agent, task: &Task) -> Result<()> {
    let mut conn = agent.redis_conn.clone();

    let mut left_receipt: SuccinctReceipt<ReceiptClaim> = bincode::deserialize(&task.data)
        .context("Failed to deserialize receipt from task.data")?;

    let mut counter = 1;

    // Store the final result in Redis
    let job_prefix = format!("job:{}", task.job_id);

    // Continuous join loop
    loop {
        counter += 1;
        tracing::debug!("Attempting to join with receipt {}", counter);

        // Try to get the next receipt with polling
        let right_receipt = match poll_for_receipt(counter, &task.job_id, &mut conn, 5, Duration::from_secs(5)).await {
            Ok(receipt) => receipt,
            Err(_e) => {
                // If we've tried enough times and the receipt isn't available,
                // store our current progress and exit
                let receipt_key = format!("{}:{}:partial_{}", job_prefix, RECUR_RECEIPT_PATH, counter-1);
                let bytes = bincode::serialize(&left_receipt).context("Failed to serialize partial join result")?;
                conn.set_ex::<_, _, ()>(&receipt_key, &bytes, 3600).await
                    .context("Failed to store partial join result")?;

                // Enqueue a Resolve task, followed by a Finalize task
                if counter > 2 { // Only proceed if we've processed at least one receipt
                    let max_idx = counter-1;

                    // Collect all prerequisites for the resolve task
                    // We need all prove task completions (which create segment outputs)
                    let mut prereqs = Vec::new();

                    // Find all segment receipts by scanning Redis
                    for i in 1..=max_idx {
                        prereqs.push(format!("prove:{}:{}", task.job_id, i));
                    }

                    tracing::info!("Collected {} prerequisites for resolve task", prereqs.len());

                    // First, create and enqueue the Resolve task
                    let resolve_task = Task {
                        job_id: task.job_id,
                        task_id: format!("resolve:{}", task.job_id),
                        task_def: serde_json::to_value(workflow_common::TaskType::Resolve(workflow_common::ResolveReq {
                            max_idx,
                            union_max_idx: None, // No union dependency for standard join
                        })).unwrap(),
                        data: bytes.clone(),
                        prereqs, // All prove tasks must complete first
                        max_retries: 3,
                    };

                    tracing::info!("Enqueuing resolve task with max_idx={}", max_idx);
                    task_queue::enqueue_task(&mut conn, workflow_common::JOIN_WORK_TYPE, resolve_task)
                        .await
                        .context("Failed to enqueue resolve task")?;

                    // Now create and enqueue the Finalize task which depends on Resolve
                    let finalize_task = Task {
                        job_id: task.job_id,
                        task_id: format!("finalize:{}", task.job_id),
                        task_def: serde_json::to_value(workflow_common::TaskType::Finalize(workflow_common::FinalizeReq {
                            max_idx,
                        })).unwrap(),
                        data: vec![],
                        prereqs: vec![format!("resolve:{}", task.job_id)], // Depends on the resolve task
                        max_retries: 3,
                    };

                    tracing::info!("Enqueuing finalize task with max_idx={}", max_idx);
                    task_queue::enqueue_task(&mut conn, workflow_common::PROVE_WORK_TYPE, finalize_task)
                        .await
                        .context("Failed to enqueue finalize task")?;
                }

                tracing::info!("Receipt {} not available after polling, stored partial result and exiting", counter);
                return Ok(());
            }
        };

        // Join the receipts
        tracing::info!("Joining with receipt {}", counter);
        let joined = agent
            .prover
            .as_ref()
            .context("Missing prover from join task")?
            .join(&left_receipt, &right_receipt)
            .context("Failed to join receipts")?;

        // Store the intermediate join result
        let receipt_key = format!("{}:{}:joined_{}", job_prefix, RECUR_RECEIPT_PATH, counter);
        let bytes = bincode::serialize(&joined).context("Failed to serialize joined result")?;
        conn.set_ex::<_, _, ()>(&receipt_key, &bytes, 3600).await
            .context("Failed to store joined result")?;

        tracing::info!("Successfully joined with receipt {}", counter);

        // Continue with the next receipt
        left_receipt = joined;
    }
}

/// Poll for a receipt until it's available or max attempts reached
async fn poll_for_receipt(
    id: usize,
    job_id: &uuid::Uuid,
    conn: &mut redis::aio::ConnectionManager,
    max_attempts: usize,
    delay: Duration,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
    // Use consistent key format with job prefix
    let job_prefix = format!("job:{}", job_id);
    let store_key = format!("{}:{}:{}", job_prefix, RECUR_RECEIPT_PATH, id);

    for attempt in 1..=max_attempts {
        tracing::info!("Polling for receipt {} (attempt {}/{})", id, attempt, max_attempts);

        // Check if the key exists
        let exists: bool = conn.exists(&store_key).await.unwrap_or(false);

        if exists {
            // Get the receipt
            let receipt_bytes = conn.get::<_, Vec<u8>>(&store_key)
                .await
                .context("Failed to fetch receipt from Redis")?;

            return bincode::deserialize(&receipt_bytes)
                .context("Failed to deserialize receipt from Redis");
        }

        // Wait before trying again
        if attempt < max_attempts {
            tracing::info!("Receipt {} not found, waiting for {:?} before retry", id, delay);
            sleep(delay).await;
        }
    }

    Err(anyhow::anyhow!("Receipt {} not available after {} polling attempts", id, max_attempts))
}



