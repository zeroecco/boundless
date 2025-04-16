// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    tasks::{serialize_obj, RECUR_RECEIPT_PATH},
    TaskType,
    Agent,
};
use anyhow::{Context, Result};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::time::Instant;
use task_queue::Task;
use uuid::Uuid;
use workflow_common::JoinReq;

/// Run a prove request
pub async fn prove(agent: &Agent, task: &Task) -> Result<()> {
    let start_time = Instant::now();
    let job_id = task.job_id;
    let task_id = &task.task_id;

    let deserialize_start = Instant::now();
    let segment = bincode::deserialize(&task.data)?;
    let deserialize_duration = deserialize_start.elapsed();
    tracing::debug!("Deserialized segment in {:?}", deserialize_duration);

    let job_prefix = format!("job:{job_id}");

    tracing::info!("Starting proof of idx: {job_id} - {task_id}");

    let prove_start = Instant::now();
    let segment_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from prove task")?
        .prove_segment(&agent.verifier_ctx, &segment)
        .context("Failed to prove segment")?;
    let prove_duration = prove_start.elapsed();

    tracing::info!("Completed proof: {job_id} - {task_id} in {:?}", prove_duration);

    tracing::info!("lifting {job_id} - {task_id}");
    let lift_start = Instant::now();
    let lift_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from resolve task")?
        .lift(&segment_receipt)
        .with_context(|| format!("Failed to lift segment {task_id}"))?;
    let lift_duration = lift_start.elapsed();

    tracing::info!("lifting complete {job_id} - {task_id} in {:?}", lift_duration);

    let output_key = format!("{job_prefix}:{RECUR_RECEIPT_PATH}:{task_id}");

    let serialize_start = Instant::now();
    // Write out lifted receipt
    let lift_asset = serialize_obj(&lift_receipt).expect("Failed to serialize the segment");
    let serialize_duration = serialize_start.elapsed();
    tracing::debug!("Serialized lift receipt in {:?}", serialize_duration);

    let store_start = Instant::now();
    // Use Redis queue instead of setex
    let mut conn = agent.redis_conn.clone();
    conn.lpush::<_, _, ()>(&output_key, &lift_asset).await
        .context("Failed to push receipt to Redis queue")?;
    let store_duration = store_start.elapsed();
    tracing::info!("Pushed lift receipt to Redis queue in {:?}", store_duration);

    let total_duration = start_time.elapsed();
    tracing::info!("Total prove+lift task completed in {:?}", total_duration);
    tracing::info!("Performance breakdown: Deserialize: {:?}, Prove: {:?}, Lift: {:?}, Serialize: {:?}, Store: {:?}",
                 deserialize_duration, prove_duration, lift_duration, serialize_duration, store_duration);

    // Extract the segment index from the task_id
    if let Some(segment_idx_str) = task_id.split(':').last() {
        if let Ok(segment_idx) = segment_idx_str.parse::<usize>() {
            // Enqueue a join task for this segment
            match enqueue_join_leaf(&mut agent.redis_conn.clone(), &job_id, task_id, segment_idx).await {
                Ok(_) => tracing::info!("Successfully enqueued join task for segment {}", segment_idx),
                Err(e) => tracing::error!("Failed to enqueue join task for segment {}: {}", segment_idx, e),
            }
        }
    }

    Ok(())
}

/// Run a prove request for a pair of segments
pub async fn prove_pair(
    agent: &Agent,
    task: &Task,
    req1: workflow_common::ProveReq,
    req2: workflow_common::ProveReq
) -> Result<()> {
    let start_time = Instant::now();
    let job_id = task.job_id;
    let task_id = &task.task_id;

    let deserialize_start = Instant::now();
    let (segment1, segment2): (risc0_zkvm::Segment, risc0_zkvm::Segment) = bincode::deserialize(&task.data)?;
    let deserialize_duration = deserialize_start.elapsed();
    tracing::debug!("Deserialized segment pair in {:?}", deserialize_duration);

    let job_prefix = format!("job:{job_id}");

    tracing::info!("Starting proof of segment pair: {job_id} - {task_id} (indices: {} and {})",
                  req1.index, req2.index);

    // Prove the first segment
    let prove1_start = Instant::now();
    let segment1_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from prove task")?
        .prove_segment(&agent.verifier_ctx, &segment1)
        .context("Failed to prove first segment")?;
    let prove1_duration = prove1_start.elapsed();

    tracing::info!("Completed proof for first segment ({}): {job_id} in {:?}", req1.index, prove1_duration);

    // Prove the second segment
    let prove2_start = Instant::now();
    let segment2_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from prove task")?
        .prove_segment(&agent.verifier_ctx, &segment2)
        .context("Failed to prove second segment")?;
    let prove2_duration = prove2_start.elapsed();

    tracing::info!("Completed proof for second segment ({}): {job_id} in {:?}", req2.index, prove2_duration);

    // Lift both segments
    tracing::info!("Lifting segment pair {job_id} - {task_id}");

    let lift1_start = Instant::now();
    let lift1_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from resolve task")?
        .lift(&segment1_receipt)
        .with_context(|| format!("Failed to lift segment {}", req1.index))?;
    let lift1_duration = lift1_start.elapsed();

    let lift2_start = Instant::now();
    let lift2_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from resolve task")?
        .lift(&segment2_receipt)
        .with_context(|| format!("Failed to lift segment {}", req2.index))?;
    let lift2_duration = lift2_start.elapsed();

    tracing::info!("Lifting complete for segment pair in {:?} and {:?}", lift1_duration, lift2_duration);
    let joined = agent
        .prover
        .as_ref()
        .context("Missing prover from join task")?
        .join(&lift1_receipt, &lift2_receipt)?;
    let serialize_start = Instant::now();
    let join_result = serialize_obj(&joined).expect("Failed to serialize the joined receipt");
    let serialize_duration = serialize_start.elapsed();

    Ok(())
}

// Helper function to enqueue join task as part of binary tree
async fn enqueue_join_leaf(
    conn: &mut ConnectionManager,
    job_id: &Uuid,
    task_id: &str,
    segment_idx: usize
) -> Result<()> {
    // Calculate node's position in binary tree
    let is_even = segment_idx % 2 == 0;

    // For odd-indexed segments, we're the right child of a join
    // For even-indexed segments, we'll be the left child and need to wait for the right
    if !is_even {
        // We're the right child (odd index)
        let left_idx = segment_idx - 1;
        let parent_idx = segment_idx / 2;

        // Create the join request with proper fields
        let join_req = JoinReq {
            idx: parent_idx,      // Parent node index in the binary tree
            left: left_idx,       // Left is previous even segment
            right: segment_idx,   // Right is current odd segment
        };

        // Create the task definition
        let join_task_def = TaskType::Join(join_req);
        let serialized_task_def = serde_json::to_value(join_task_def)
            .context("Failed to serialize join task definition")?;

        // Define prerequisites - join task depends on both segments being proven
        let left_task_id = format!("prove:{}:{}", job_id, left_idx);
        let prereqs = vec![left_task_id, task_id.to_string()];

        // Create a deterministic join task ID based on the parent index
        let join_task_id = format!("join:{}:{}", job_id, parent_idx);

        // Create the join task
        let join_task = task_queue::Task {
            job_id: *job_id,
            task_id: join_task_id,
            task_def: serialized_task_def,
            prereqs,
            max_retries: 3,
            data: Vec::new(), // Empty data as we don't need to store any binary data
        };

        // Enqueue the join task
        task_queue::enqueue_task(conn, "join", join_task)
            .await
            .context("Failed to enqueue join task")?;

        tracing::info!("Enqueued join task for parent {} with children {} and {}",
                       parent_idx, left_idx, segment_idx);
    } else {
        // We're the left child (even index)
        // No action needed yet - the right child will create the join task when it completes
        tracing::info!("Segment {} is left child, waiting for right child to complete", segment_idx);
    }

    Ok(())
}

