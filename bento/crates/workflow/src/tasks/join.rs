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

    // Extract index from request
    let current_idx = req.idx;

    // Calculate indices for left and right children in binary tree
    let left_leaf = current_idx * 2;
    let right_leaf = left_leaf + 1;
    let join_idx = current_idx / 2;

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

    // Store the joined receipt
    let job_prefix = format!("job:{}", task.job_id);
    let store_key = format!("{}:{}:{}", job_prefix, RECUR_RECEIPT_PATH, join_idx);
    conn.set(&store_key, receipt_bytes.clone())
        .await
        .context("Failed to store joined receipt in Redis")?;

    // If we're at the root (idx = 1), we're done
    if join_idx == 1 {
        tracing::info!("Reached root receipt (idx=1) for job {}", task.job_id);
        return Ok(());
    }

    // Calculate parent and sibling indices
    let parent_idx = join_idx / 2;
    let sibling_idx = if join_idx % 2 == 0 { join_idx + 1 } else { join_idx - 1 };

    // Check if sibling receipt is already available
    let sibling_receipt = match get_receipt(sibling_idx, &task.job_id, &mut conn).await {
        Ok(receipt) => {
            // Sibling is ready, proceed with join
            tracing::info!("Sibling receipt {} already available, creating join task for parent {}", sibling_idx, parent_idx);
            receipt
        },
        Err(_) => {
            // Sibling not ready, re-enqueue the same task with backoff
            tracing::info!("Sibling receipt {} not yet available, re-enqueueing current task", sibling_idx);

            // Re-enqueue the same join task to check again later
            let retry_task = Task {
                job_id: task.job_id,
                task_id: format!("join:{}", task.job_id),
                task_def: serde_json::to_value(workflow_common::TaskType::Join(workflow_common::JoinReq {
                    idx: join_idx,
                })).unwrap(),
                data: receipt_bytes,
                prereqs: vec![],
                max_retries: task.max_retries - 1,
            };

            task_queue::enqueue_task(&mut conn, workflow_common::JOIN_WORK_TYPE, retry_task)
                .await
                .context("Failed to re-enqueue join task")?;

            return Ok(());
        }
    };

    // Create a task for joining with the sibling
    let join_task = Task {
        job_id: task.job_id,
        task_id: format!("join:{}", task.job_id),
        task_def: serde_json::to_value(workflow_common::TaskType::Join(workflow_common::JoinReq {
            idx: parent_idx,
        })).unwrap(),
        data: bincode::serialize(&sibling_receipt).context("Failed to serialize sibling receipt")?,
        prereqs: vec![],
        max_retries: 3,
    };

    // Enqueue the task
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
    let receipt = conn.get::<_, Vec<u8>>(&store_key)
        .await
        .context("Failed to fetch receipt from Redis")?;

    let receipt = bincode::deserialize(&receipt)
        .context("Failed to deserialize receipt from Redis")?;

    Ok(receipt)
}



