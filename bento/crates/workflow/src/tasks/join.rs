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

    enqueue_left_leaf(&mut conn, req.idx, receipt_claim).await?;

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

/// Enqueue a left leaf for the join operation
async fn enqueue_left_leaf(conn: &mut redis::aio::ConnectionManager, right: usize, data: SuccinctReceipt<ReceiptClaim>) -> Result<()> {
    let key = format!("join:{}:{}", RECUR_RECEIPT_PATH, right + 1);
    conn.set_ex::<_, _, ()>(key, bincode::serialize(&data)?, 300).await?;
    Ok(())
}



