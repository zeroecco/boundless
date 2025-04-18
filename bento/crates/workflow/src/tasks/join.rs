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
    let left_receipt = get_receipt(req.left, &mut conn).await?;

    // Get right receipt (from task data)
    let right_receipt: SuccinctReceipt<ReceiptClaim> = bincode::deserialize(&task.data)?;

    tracing::info!("Joining {} - {} + {} -> {}", task.job_id, req.left, req.right, req.idx);

    // Perform the join
    let receipt_claim = agent
        .prover
        .as_ref()
        .context("Missing prover from join task")?
        .join(&left_receipt, &right_receipt)?;

    // Store the result with consistent key format
    let receipt_bytes = bincode::serialize(&receipt_claim)?;
    let job_prefix = format!("job:{}", task.job_id);
    let store_key = format!("{}:{}:{}", job_prefix, RECUR_RECEIPT_PATH, req.idx);
    conn.set_ex::<_, _, ()>(store_key, &receipt_bytes, 3600).await?;
    tracing::info!("Stored joined receipt for idx {}", req.idx);

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
            task_queue::enqueue_task(&mut conn, workflow_common::JOIN_WORK_TYPE, parent_task)
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
async fn get_receipt(id: usize, conn: &mut redis::aio::ConnectionManager) -> Result<SuccinctReceipt<ReceiptClaim>> {
    // Use consistent key format with job prefix
    let prefix = format!("job:");  // We don't know job_id here, so we'll check all matching keys
    let suffix = format!("{}:{}", RECUR_RECEIPT_PATH, id);
    let pattern = format!("{}*:{}", prefix, suffix);

    let max_retries = 30; // Maximum 30 retries (30 seconds)
    let mut retry_count = 0;

    loop {
        // First, try to find all keys matching our pattern
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(conn)
            .await
            .context("Redis KEYS error")?;

        if !keys.is_empty() {
            // Use the first matching key
            let key = &keys[0];
            let result: Option<Vec<u8>> = conn.get(key).await.context("Redis get error")?;

            if let Some(data) = result {
                if !data.is_empty() {
                    // Found valid data
                    tracing::info!("Successfully retrieved data for key: {}", key);
                    return bincode::deserialize(&data).context("Failed to deserialize receipt");
                }
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



