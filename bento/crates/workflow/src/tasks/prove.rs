// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{tasks::{serialize_obj, RECUR_RECEIPT_PATH}, Agent};
use anyhow::{Context, Result};
use redis::AsyncCommands;
use std::time::Instant;
use task_queue::Task;

/// Run a prove request
pub async fn prove(agent: &Agent, task: &Task) -> Result<()> {
    let start_time = Instant::now();
    let job_id = task.job_id;

    // Debug log the raw task_def to see what we're trying to deserialize
    tracing::debug!("Raw task_def to deserialize: {:?}", task.task_def);

    // First, deserialize the task_def as a TaskType
    let task_type: workflow_common::TaskType = serde_json::from_value(task.task_def.clone())
        .context("Failed to deserialize TaskType from task_def")?;

    // Then, extract the ProveReq from the TaskType
    let req = match task_type {
        workflow_common::TaskType::Prove(req) => req,
        _ => return Err(anyhow::anyhow!("Expected Prove task type, got {:?}", task_type)),
    };

    let index = req.index;

    let deserialize_start = Instant::now();
    let segment = bincode::deserialize(&task.data)?;
    let deserialize_duration = deserialize_start.elapsed();
    tracing::debug!("Deserialized segment in {:?}", deserialize_duration);

    tracing::info!("Starting proof of job {} segment {}", job_id, index);

    let prove_start = Instant::now();
    let segment_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from prove task")?
        .prove_segment(&agent.verifier_ctx, &segment)
        .context("Failed to prove segment")?;
    let prove_duration = prove_start.elapsed();

    tracing::info!("Completed proof: job {} segment {} in {:?}", job_id, index, prove_duration);

    tracing::info!("lifting job {} segment {}", job_id, index);
    let lift_start = Instant::now();
    let lift_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from resolve task")?
        .lift(&segment_receipt)
        .with_context(|| format!("Failed to lift segment {}", index))?;
    let lift_duration = lift_start.elapsed();

    tracing::info!("lifting complete job {} segment {} in {:?}", job_id, index, lift_duration);

    let serialize_start = Instant::now();
    let lift_asset = serialize_obj(&lift_receipt).expect("Failed to serialize the segment");
    let serialize_duration = serialize_start.elapsed();
    tracing::debug!("Serialized lift receipt in {:?}", serialize_duration);

    // Store receipt in Redis with consistent key format
    let job_prefix = format!("job:{}", job_id);
    let receipt_key = format!("{}:{}:{}", job_prefix, RECUR_RECEIPT_PATH, index);

    // emit lift receipt as a key-value pair
    let mut conn = agent.redis_conn.clone();
    conn.set_ex::<_, _, ()>(receipt_key, &lift_asset, 3600).await
        .context("Failed to store receipt in Redis")?;
    tracing::info!("Stored receipt for segment {} in Redis", index);

    // Create join tasks for this segment
    // Each segment participates in exactly one join
    let is_right_child = index % 2 == 1;

    if is_right_child {
        // This is a right child, create a join task with its left sibling
        let left_idx = index - 1;
        let parent_idx = index / 2;

        tracing::info!("Creating join task {} + {} -> {}", left_idx, index, parent_idx);

        // Create the join request
        let join_req = workflow_common::JoinReq {
            idx: parent_idx,
            left: left_idx,
            right: index,
        };

        // Create task definition
        let task_def = serde_json::to_value(workflow_common::TaskType::Join(join_req))
            .context("Failed to serialize join task definition")?;

        // Create the join task with this receipt as data
        let join_task = Task {
            job_id,
            task_id: format!("join:{}:{}", job_id, parent_idx),
            task_def,
            prereqs: vec![],
            max_retries: 3,
            data: lift_asset,  // Right child provides its receipt data
        };

        // Enqueue the join task
        task_queue::enqueue_task(&mut conn, workflow_common::JOIN_WORK_TYPE, join_task)
            .await
            .context("Failed to enqueue join task")?;

        tracing::info!("Enqueued join task for segments {} + {}", left_idx, index);
    } else {
        // This is a left child, just wait for the right sibling
        tracing::info!("Segment {} is left child, waiting for right sibling {}", index, index + 1);
    }

    let total_duration = start_time.elapsed();
    tracing::info!("Total prove+lift task completed in {:?}", total_duration);
    tracing::info!(
        "Performance breakdown: Deserialize: {:?}, Prove: {:?}, Lift: {:?}, Serialize: {:?}",
        deserialize_duration, prove_duration, lift_duration, serialize_duration
    );

    Ok(())
}
