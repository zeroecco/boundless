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

    let left_receipt = get_left_leaf(req.left, &mut conn).await?;

    let right_receipt: SuccinctReceipt<ReceiptClaim> = bincode::deserialize(&task.data)?;
    tracing::info!("Joining {} - {} + {} -> {}", task.job_id, req.left, req.right, req.idx);
    let receipt_claim = agent
        .prover
        .as_ref()
        .context("Missing prover from join task")?
        .join(&left_receipt, &right_receipt)?;

    // Store the result
    let receipt_bytes = bincode::serialize(&receipt_claim)?;
    let store_key = format!("join:{}:{}", RECUR_RECEIPT_PATH, req.idx);
    conn.set_ex::<_, _, ()>(store_key, &receipt_bytes, 3600).await?;
    tracing::info!("Stored joined receipt for idx {}", req.idx);

    // If this is an odd-indexed node, create a parent join task
    if req.idx % 2 == 1 {
        let left_idx = req.idx - 1;
        let parent_idx = req.idx / 2;

        tracing::info!("Creating parent join task: {} + {} -> {}", left_idx, req.idx, parent_idx);

        // Create the join request for the parent
        let join_req = workflow_common::JoinReq {
            idx: parent_idx,
            left: left_idx,
            right: req.idx,
        };

        // Create task definition for the parent
        let task_def = serde_json::to_value(workflow_common::TaskType::Join(join_req))
            .context("Failed to serialize parent join task definition")?;

        // Create the parent join task
        let parent_task = Task {
            job_id: task.job_id,
            task_id: format!("join:{}:{}", task.job_id, parent_idx),
            task_def,
            prereqs: vec![],
            max_retries: 3,
            data: receipt_bytes,  // Include this node's result as the right receipt
        };

        // Enqueue the parent join task
        task_queue::enqueue_task(&mut conn, workflow_common::JOIN_WORK_TYPE, parent_task)
            .await
            .context("Failed to enqueue parent join task")?;

        tracing::info!("Enqueued parent join task for node {}", parent_idx);
    } else if req.idx == 0 {
        // This is the root node, we are done with the binary tree
        tracing::info!("Completed final join at root node 0");

        // Here you could trigger the next stage of your pipeline
        // For example, store the final result in a special key
        let final_key = format!("job:{}:final_receipt", task.job_id);
        conn.set_ex::<_, _, ()>(final_key, &receipt_bytes, 7200).await?;
        tracing::info!("Stored final receipt for job {}", task.job_id);
    } else {
        // This is an even-indexed node, waiting for sibling
        tracing::info!("Node {} is even-indexed, waiting for sibling node {}", req.idx, req.idx + 1);
    }

    Ok(())
}

async fn get_left_leaf(id: usize, conn: &mut redis::aio::ConnectionManager) -> Result<SuccinctReceipt<ReceiptClaim>> {
    let key = format!("join:{}:{}", RECUR_RECEIPT_PATH, id);
    let max_retries = 30; // Maximum 30 retries (30 seconds)
    let mut retry_count = 0;

    loop {
        let result: Result<Option<Vec<u8>>> = conn.get(&key).await.context("Redis get error");

        match result {
            Ok(Some(data)) if !data.is_empty() => {
                // Found valid data
                tracing::info!("Successfully retrieved data for key: {}", key);
                return bincode::deserialize(&data).context("Failed to deserialize receipt");
            },
            _ => {
                retry_count += 1;
                if retry_count >= max_retries {
                    return Err(anyhow::anyhow!("Maximum retries reached waiting for key: {}", key));
                }

                tracing::info!("Key {} not yet available, retrying ({}/{})", key, retry_count, max_retries);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                // Continue loop to retry
            }
        }
    }
}



