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
            tracing::info!("Received empty data from queue: {}, will requeue task", left_path_key);
            // Requeue the task to try again later
            return requeue_join_task(agent, job_id, request).await;
        }
        left_receipt_data = data;
    } else {
        tracing::info!("Queue empty for {}, trying GET instead", left_path_key);
        let get_result = conn
            .get::<_, Option<Vec<u8>>>(&left_path_key)
            .await
            .with_context(|| format!("Failed to get data with GET: {}", left_path_key))?;

        if let Some(data) = get_result {
            if data.is_empty() {
                tracing::info!("Received empty data from GET: {}, will requeue task", left_path_key);
                // Requeue the task to try again later
                return requeue_join_task(agent, job_id, request).await;
            }
            left_receipt_data = data;
        } else {
            tracing::info!("No data found for {}, will requeue task", left_path_key);
            // Requeue the task to try again later
            return requeue_join_task(agent, job_id, request).await;
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
            tracing::info!("Received empty data from queue: {}, will requeue task", right_path_key);
            // Requeue the task to try again later
            return requeue_join_task(agent, job_id, request).await;
        }
        right_receipt_data = data;
    } else {
        tracing::info!("Queue empty for {}, trying GET instead", right_path_key);
        let get_result = conn
            .get::<_, Option<Vec<u8>>>(&right_path_key)
            .await
            .with_context(|| format!("Failed to get data with GET: {}", right_path_key))?;

        if let Some(data) = get_result {
            if data.is_empty() {
                tracing::info!("Received empty data from GET: {}, will requeue task", right_path_key);
                // Requeue the task to try again later
                return requeue_join_task(agent, job_id, request).await;
            }
            right_receipt_data = data;
        } else {
            tracing::info!("No data found for {}, will requeue task", right_path_key);
            // Requeue the task to try again later
            return requeue_join_task(agent, job_id, request).await;
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

        task_queue::enqueue_task(&mut agent.redis_conn.clone(), workflow_common::JOIN_WORK_TYPE, parent_join_task)
            .await
            .context("Failed to enqueue parent join task")?;

        tracing::info!("Enqueued parent join task for node {}", parent_idx);
    }

    Ok(())
}

/// Helper function to requeue a join task with a delay
async fn requeue_join_task(agent: &Agent, job_id: &Uuid, request: &JoinReq) -> Result<()> {
    tracing::info!("Requeuing join task for job {} segments {} + {} -> {} to retry later",
                  job_id, request.left, request.right, request.idx);

    let join_req = request.clone();
    let serialized_task_def = serde_json::to_value(TaskType::Join(join_req))
        .context("Failed to serialize requeued join task definition")?;

    let task = Task {
        job_id: *job_id,
        task_id: format!("join:{}:{}", job_id, request.idx),
        task_def: serialized_task_def,
        prereqs: vec![],
        max_retries: 3,  // Reset retry count for requeued tasks
        data: Vec::new(),
    };

    // Spawn a task to enqueue after a delay
    let clone_task = task.clone();
    let conn_clone = agent.redis_conn.clone();
    tokio::spawn(async move {
        // Wait for the delay
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Then enqueue to the main queue
        let mut delayed_conn = conn_clone;
        let _ = task_queue::enqueue_task(
            &mut delayed_conn,
            workflow_common::JOIN_WORK_TYPE,
            clone_task
        ).await;
    });

    // Return Ok to prevent the task from being marked as failed
    Ok(())
}
