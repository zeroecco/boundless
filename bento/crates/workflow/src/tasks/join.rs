// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{tasks::RECUR_RECEIPT_PATH, Agent};
use anyhow::{Context, Result};
use redis::AsyncCommands;
use risc0_zkvm::{ReceiptClaim, SuccinctReceipt};
use task_queue::Task;
use uuid;

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
    tracing::info!("Fetching left receipt for index {} from job {}", req.left, task.job_id);
    let left_receipt = get_receipt(req.left, &task.job_id, &mut conn).await?;
    // Log info about left receipt
    tracing::info!("Left receipt obtained for index {}", req.left);

    let perform_join = |left_receipt: &SuccinctReceipt<ReceiptClaim>, right_receipt: &SuccinctReceipt<ReceiptClaim>| -> Result<SuccinctReceipt<ReceiptClaim>> {
        // Additional validation before join
        tracing::info!("Validating receipts before join operation");

        // Perform the join
        let result = agent
            .prover
            .as_ref()
            .context("Missing prover from join task")?
            .join(left_receipt, right_receipt);

        if let Err(ref e) = result {
            tracing::error!("Join operation failed: {}", e);
            tracing::error!("This often indicates the receipts are from different computations or jobs");
        }

        result
    };

    // Check if we have data for the right receipt
    if task.data.is_empty() {
        tracing::info!("Task data is empty, retrieving right receipt from Redis");
        // If data is empty, get the right receipt from Redis instead
        tracing::info!("Fetching right receipt for index {} from job {}", req.right, task.job_id);
        let right_receipt = get_receipt(req.right, &task.job_id, &mut conn).await?;
        // Log info about right receipt
        tracing::info!("Right receipt obtained for index {}", req.right);

        tracing::info!("Joining {} - {} + {} -> {}", task.job_id, req.left, req.right, req.idx);

        // Perform the join
        let receipt_claim = perform_join(&left_receipt, &right_receipt)?;

        // Store the result with consistent key format
        let receipt_bytes = bincode::serialize(&receipt_claim)?;
        let job_prefix = format!("job:{}", task.job_id);
        let store_key = format!("{}:{}:{}", job_prefix, RECUR_RECEIPT_PATH, req.idx);
        conn.set_ex::<_, _, ()>(store_key, &receipt_bytes, 3600).await?;
        tracing::info!("Stored joined receipt for idx {}", req.idx);

        // Continue with parent task creation...
        create_parent_task(agent, task, req, receipt_bytes, &mut conn).await?;
    } else {
        // Get right receipt from task data
        tracing::info!("Deserializing right receipt from task data (size: {} bytes)", task.data.len());
        let right_receipt: SuccinctReceipt<ReceiptClaim> = bincode::deserialize(&task.data)
            .context("Failed to deserialize right receipt from task data")?;
        // Log info about right receipt from task data
        tracing::info!("Right receipt deserialized from task data for index {}", req.right);

        tracing::info!("Joining {} - {} + {} -> {}", task.job_id, req.left, req.right, req.idx);

        // Perform the join
        let receipt_claim = perform_join(&left_receipt, &right_receipt)?;

        // Store the result with consistent key format
        let receipt_bytes = bincode::serialize(&receipt_claim)?;
        let job_prefix = format!("job:{}", task.job_id);
        let store_key = format!("{}:{}:{}", job_prefix, RECUR_RECEIPT_PATH, req.idx);
        conn.set_ex::<_, _, ()>(store_key, &receipt_bytes, 3600).await?;
        tracing::info!("Stored joined receipt for idx {}", req.idx);

        // Continue with parent task creation...
        create_parent_task(agent, task, req, receipt_bytes, &mut conn).await?;
    }

    Ok(())
}

/// Create a parent task if necessary
async fn create_parent_task(
    agent: &Agent,
    task: &Task,
    req: workflow_common::JoinReq,
    receipt_bytes: Vec<u8>,
    conn: &mut redis::aio::ConnectionManager,
) -> Result<()> {
    // Check if we need to create a parent task
    match req.idx {
        idx if idx > 1 => {
            let sibling_idx = if req.idx % 2 == 0 { req.idx + 1 } else { req.idx - 1 };
            let parent_idx = req.idx / 2;

            tracing::info!("Creating parent join task: {} for parent {}", req.idx, parent_idx);

            // Create the join request for the parent
            let join_req = workflow_common::JoinReq {
                idx: parent_idx,
                left: sibling_idx.min(req.idx),  // Left is the smaller index
                right: sibling_idx.max(req.idx), // Right is the larger index
            };

            // Create task definition for the parent
            let task_def = serde_json::to_value(workflow_common::TaskType::Join(join_req))
                .context("Failed to serialize parent join task definition")?;

            // For odd indices, we're the right child, for even indices, we're the left child
            let is_right_child = req.idx % 2 == 1;

            // Create the parent join task
            let parent_task = Task {
                job_id: task.job_id,
                task_id: format!("join:{}:{}", task.job_id, parent_idx),
                task_def,
                prereqs: vec![],
                max_retries: 3,
                // If we're the right child, include our receipt as data
                // If we're the left child, set empty data (right child will provide it)
                data: if is_right_child { receipt_bytes } else { Vec::new() },
            };

            // Enqueue the parent join task
            task_queue::enqueue_task(conn, workflow_common::JOIN_WORK_TYPE, parent_task)
                .await
                .context("Failed to enqueue parent join task")?;

            tracing::info!("Enqueued parent join task for node {}", parent_idx);
        },
        1 => {
            // This is the root node, we are done with the binary tree
            tracing::info!("Completed final join at root node 1");

            // Store the final result in a special key
            let final_key = format!("job:{}:final_receipt", task.job_id);
            conn.set_ex::<_, _, ()>(final_key, &receipt_bytes, 7200).await?;
            tracing::info!("Stored final receipt for job {}", task.job_id);
        },
        _ => {
            // Should never happen with our indexing strategy
            tracing::warn!("Unexpected join index: {}", req.idx);
        }
    }

    Ok(())
}

/// Get a receipt from Redis with retries
async fn get_receipt(
    id: usize,
    job_id: &uuid::Uuid,
    conn: &mut redis::aio::ConnectionManager,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
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



