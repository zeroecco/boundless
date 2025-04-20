// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    tasks::{deserialize_obj, serialize_obj},
    Agent,
};
use anyhow::{Context, Result};
use redis::AsyncCommands;
use task_queue::Task;
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use workflow_common::UnionReq;

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
                let bytes = serialize_obj(&left_receipt).context("Failed to serialize partial union result")?;
                agent
                    .set_in_redis(&receipt_key, &bytes, Some(agent.args.redis_ttl))
                    .await
                    .context("Failed to store partial union result")?;

                // Enqueue a Resolve task followed by a Finalize task
                if counter > 2 { // Only proceed if we've processed at least one receipt
                    let max_idx = counter-1;

                    // First, create and enqueue the Resolve task with union dependency
                    let resolve_task = Task {
                        job_id,
                        task_id: format!("resolve:{}", job_id),
                        task_def: serde_json::to_value(workflow_common::TaskType::Resolve(workflow_common::ResolveReq {
                            max_idx: 1, // For the standard join path
                            union_max_idx: Some(max_idx), // Union dependency
                        })).unwrap(),
                        data: bytes.clone(),
                        prereqs: vec![],
                        max_retries: 3,
                    };

                    tracing::info!("Enqueuing resolve task with union_max_idx={}", max_idx);
                    task_queue::enqueue_task(&mut conn, workflow_common::JOIN_WORK_TYPE, resolve_task)
                        .await
                        .context("Failed to enqueue resolve task")?;

                    // Then, create and enqueue a Finalize task that depends on the Resolve task
                    let finalize_task = Task {
                        job_id,
                        task_id: format!("finalize:{}", job_id),
                        task_def: serde_json::to_value(workflow_common::TaskType::Finalize(workflow_common::FinalizeReq {
                            max_idx: 1, // Use the same max_idx as in the resolve task
                        })).unwrap(),
                        data: vec![],
                        prereqs: vec![format!("resolve:{}", job_id)], // Depends on the resolve task
                        max_retries: 3,
                    };

                    tracing::info!("Enqueuing finalize task with max_idx=1");
                    task_queue::enqueue_task(&mut conn, workflow_common::KECCAK_WORK_TYPE, finalize_task)
                        .await
                        .context("Failed to enqueue finalize task")?;
                }

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
        let bytes = serialize_obj(&unioned).context("Failed to serialize unioned result")?;
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
            // Get the receipt
            let receipt_bytes: Vec<u8> = conn.get(&store_key)
                .await
                .context("Failed to fetch keccak receipt from Redis")?;

            return deserialize_obj(&receipt_bytes)
                .context("Failed to deserialize keccak receipt from Redis");
        }

        // Wait before trying again
        if attempt < max_attempts {
            tracing::info!("Keccak receipt {} not found, waiting for {:?} before retry", id, delay);
            sleep(delay).await;
        }
    }

    Err(anyhow::anyhow!("Keccak receipt {} not available after {} polling attempts", id, max_attempts))
}
