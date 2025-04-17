// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{tasks::{deserialize_obj, serialize_obj, RECUR_RECEIPT_PATH}, Agent, TaskType};
use anyhow::{Context, Result};
use redis::AsyncCommands;
use std::time::Instant;
use task_queue::Task;
use uuid::Uuid;
use workflow_common::JoinReq;

/// Run the join operation
pub async fn join(agent: &Agent, job_id: &Uuid, request: &JoinReq) -> Result<()> {
    let start_time = Instant::now();
    let mut conn = agent.redis_conn.clone();

    // Build the redis keys for the right and left joins
    let job_prefix = format!("job:{}", job_id);
    let recur_receipts_prefix = format!("{}:{}", job_prefix, RECUR_RECEIPT_PATH);

    let left_path_key = format!("{}:{}", recur_receipts_prefix, request.left);
    let right_path_key = format!("{}:{}", recur_receipts_prefix, request.right);

    tracing::info!("Joining {} - {} + {} -> {}", job_id, request.left, request.right, request.idx);

    // Get left receipt - use brpop with timeout
    let left_receipt_data: Vec<u8>;
    let left_receipt_result: Option<(String, Vec<u8>)> = conn
        .brpop(&left_path_key, 1.0)
        .await
        .with_context(|| format!("Failed to access queue: {}", left_path_key))?;

    if let Some((_, data)) = left_receipt_result {
        if data.is_empty() {
            return Err(anyhow::anyhow!("Received empty data from queue: {}", left_path_key));
        }
        left_receipt_data = data;
    } else {
        tracing::info!("Queue empty for {}, trying GET instead", left_path_key);
        left_receipt_data = conn
            .get::<_, Vec<u8>>(&left_path_key)
            .await
            .with_context(|| format!("Failed to get data with GET: {}", left_path_key))?;
        if left_receipt_data.is_empty() {
            return Err(anyhow::anyhow!("Received empty data from GET: {}", left_path_key));
        }
    }

    // Deserialize left receipt
    let left_receipt = deserialize_obj(&left_receipt_data)
        .with_context(|| "Failed to deserialize left receipt".to_string())?;

    // Get right receipt - use brpop with timeout
    let right_receipt_data: Vec<u8>;
    let right_receipt_result: Option<(String, Vec<u8>)> = conn
        .brpop(&right_path_key, 1.0)
        .await
        .with_context(|| format!("Failed to access queue: {}", right_path_key))?;

    if let Some((_, data)) = right_receipt_result {
        if data.is_empty() {
            return Err(anyhow::anyhow!("Received empty data from queue: {}", right_path_key));
        }
        right_receipt_data = data;
    } else {
        tracing::info!("Queue empty for {}, trying GET instead", right_path_key);
        right_receipt_data = conn
            .get::<_, Vec<u8>>(&right_path_key)
            .await
            .with_context(|| format!("Failed to get data with GET: {}", right_path_key))?;
        if right_receipt_data.is_empty() {
            return Err(anyhow::anyhow!("Received empty data from GET: {}", right_path_key));
        }
    }

    // Deserialize right receipt
    let right_receipt = deserialize_obj(&right_receipt_data)
        .with_context(|| "Failed to deserialize right receipt".to_string())?;

    // Perform the join
    let join_start = Instant::now();
    let joined = agent
        .prover
        .as_ref()
        .context("Missing prover from join task")?
        .join(&left_receipt, &right_receipt)?;
    let join_duration = join_start.elapsed();

    // Serialize joined receipt
    let serialize_start = Instant::now();
    let join_result = serialize_obj(&joined).expect("Failed to serialize the joined receipt");
    let serialize_duration = serialize_start.elapsed();

    // Store joined result under the new index key
    let output_key = format!("{}:{}", recur_receipts_prefix, request.idx);
    let store_start = Instant::now();
    conn.lpush::<_, _, ()>(&output_key, &join_result)
        .await
        .context("Failed to push joined receipt to Redis queue")?;
    let store_duration = store_start.elapsed();

    let total_duration = start_time.elapsed();
    tracing::info!(
        "Join {} + {} -> {} completed in {:?} (join: {:?}, serialize: {:?}, store: {:?})",
        request.left,
        request.right,
        request.idx,
        total_duration,
        join_duration,
        serialize_duration,
        store_duration
    );

    // Schedule parent join if this is an odd-indexed node
    if request.idx % 2 == 0 {
        tracing::info!("Node {} is even-indexed, waiting for sibling", request.idx);
    } else {
        let left_idx = request.idx - 1;
        let parent_idx = request.idx / 2;

        tracing::info!(
            "Creating parent join task: {} + {} -> {}",
            left_idx,
            request.idx,
            parent_idx
        );

        let join_req = JoinReq { idx: parent_idx, left: left_idx, right: request.idx };
        let serialized_task_def = serde_json::to_value(TaskType::Join(join_req.clone()))
            .context("Failed to serialize parent join task definition")?;

        let left_task_id = format!("join:{}:{}", job_id, left_idx);
        let right_task_id = format!("join:{}:{}", job_id, request.idx);
        let prereqs = vec![left_task_id, right_task_id];

        let parent_join_task = Task {
            job_id: *job_id,
            task_id: format!("join:{}:{}", job_id, parent_idx),
            task_def: serialized_task_def,
            prereqs,
            max_retries: 3,
            data: Vec::new(),
        };

        task_queue::enqueue_task(&mut agent.redis_conn.clone(), "join", parent_join_task)
            .await
            .context("Failed to enqueue parent join task")?;

        tracing::info!("Enqueued parent join task for node {}", parent_idx);
    }

    Ok(())
}
