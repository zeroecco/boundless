// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{tasks::RECUR_RECEIPT_PATH, Agent};
use anyhow::{Context, Result};
use redis::AsyncCommands;
use risc0_zkvm::{ReceiptClaim, SuccinctReceipt};
use task_queue::Task;

/// Run the join operation
pub async fn join(agent: &Agent, task: &Task) -> Result<()> {
    let mut conn = agent.redis_conn.clone();

    let task_type: workflow_common::TaskType = serde_json::from_value(task.task_def.clone())
        .context("Failed to deserialize TaskType from task_def")?;

    let req = match task_type {
        workflow_common::TaskType::Join(req) => req,
        _ => return Err(anyhow::anyhow!("Expected Join task type, got {:?}", task_type)),
    };


    // Get left receipt
    let left_leaf = req.idx - 1;
    let right_leaf = req.idx;
    let join_idx = req.idx + 1;
    tracing::info!("Fetching left receipt for index {} from job {}", left_leaf, task.job_id);

    let left_receipt = get_receipt(left_leaf, &task.job_id, &mut conn).await.context("Failed to fetch left receipt")?;
    let right_receipt = bincode::deserialize(&task.data).context("Failed to deserialize right receipt")?;
    tracing::info!("Joining {} - {} + {} -> {}", task.job_id, left_leaf, right_leaf, join_idx);

    // Perform the join
    let receipt_claim = agent.prover
                .as_ref()
                .context("Missing prover from join task")?
                .join(&left_receipt, &right_receipt)
                .context("Failed to join receipts")?;

    // Serialize the result
    let receipt_bytes = bincode::serialize(&receipt_claim).context("Failed to serialize receipt")?;

    // setup the next join task
    let mut conn = agent.redis_conn.clone();
        let join_task = Task {
            job_id: task.job_id,
            task_id: format!("join:{}", task.job_id),
            task_def: serde_json::to_value(workflow_common::TaskType::Join(workflow_common::JoinReq {
                idx: join_idx,
            })).unwrap(),
            data: receipt_bytes,
            prereqs: vec![],
            max_retries: 3,
        };
        tracing::info!("Enqueuing join task: {}", join_idx);

        task_queue::enqueue_task(&mut conn, workflow_common::JOIN_WORK_TYPE, join_task)
            .await
            .context("Failed to enqueue join task")?;
    Ok(())
}

/// Get a receipt from Redis with retries
async fn get_receipt(
    id: usize,
    job_id: &uuid::Uuid,
    conn: &mut redis::aio::ConnectionManager,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
    // Validate receipt index - segments should start at index 1, not 0
    if id == 0 {
        return Err(anyhow::anyhow!("Invalid receipt id: 0. Receipt indices should start at 1"));
    }

    // Use consistent key format with job prefix
    let job_prefix = format!("job:{}", job_id);
    let store_key = format!("{}:{}:{}", job_prefix, RECUR_RECEIPT_PATH, id);

    let max_retries = 30; // Maximum 30 retries (30 seconds)
    let mut retry_count = 0;

    loop {
        // Try to get the receipt directly with the known key
        let result: Option<Vec<u8>> = conn.get(&store_key).await.context("Redis get error")?;

        if let Some(data) = result {
            if !data.is_empty() {
                // Found valid data
                tracing::info!("Successfully retrieved data for key: {}", store_key);
                return bincode::deserialize(&data).context("Failed to deserialize receipt");
            }
        }

        // Extra check: Verify if there are any keys that match the pattern for this specific id
        // but potentially different job
        let pattern = format!("job:*:{}:{}", RECUR_RECEIPT_PATH, id);
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(conn)
            .await
            .context("Redis KEYS error")?;

        if !keys.is_empty() {
            tracing::info!("Found {} potential keys for receipt id {}", keys.len(), id);
            for key in &keys {
                // Extract job_id from the key for logging
                if let Some(job_part) = key.split(':').nth(1) {
                    tracing::info!("Found receipt for job {} with id {}", job_part, id);
                }

                // Only proceed if this key belongs to our job
                if key == &store_key {
                    let data: Option<Vec<u8>> = conn.get(key).await.context("Redis get error")?;
                    if let Some(bytes) = data {
                        if !bytes.is_empty() {
                            tracing::info!("Found valid data for key: {}", key);
                            return bincode::deserialize(&bytes).context("Failed to deserialize receipt");
                        }
                    }
                }
            }

            if keys.len() > 1 {
                tracing::warn!("Multiple keys found for receipt id {}. Using only key for job {}", id, job_id);
            }
        }

        // Key not found or empty data, retry
        retry_count += 1;
        if retry_count >= max_retries {
            return Err(anyhow::anyhow!("Maximum retries reached waiting for receipt with id: {}", id));
        }

        tracing::info!("Receipt for id {} not yet available, retrying ({}/{})", id, retry_count, max_retries);
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}



