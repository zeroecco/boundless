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

    // Calculate the leaf position in the binary tree
    // Segment indices should start at 1, so we need to compute appropriate leaf positions
    // For a binary tree, leaves start at positions 2^h where h is the height
    let leaf_position = index;

    let receipt_key = format!("{}:{}:{}", job_prefix, RECUR_RECEIPT_PATH, leaf_position);

    // Store the receipt in Redis
    let mut conn = agent.redis_conn.clone();
    conn.set_ex::<_, _, ()>(&receipt_key, &lift_asset, 3600).await
        .context("Failed to store receipt in Redis")?;
    tracing::info!("Stored receipt for segment {} at position {} in Redis", index, leaf_position);

    // If this is the first segment, we need to create a join task that will start the join process
    if index == 1 {
        tracing::info!("First segment completed, starting the join process");

        // Create a join task that will poll for additional receipts as they become available
        let join_task = Task {
            job_id,
            task_id: format!("join:{}", job_id),
            task_def: serde_json::to_value(workflow_common::TaskType::Join(workflow_common::JoinReq {
                idx: 1,  // Starting index doesn't matter for our polling approach
            })).unwrap(),
            data: lift_asset,  // Pass our receipt as the starting point
            prereqs: vec![],
            max_retries: 3,
        };

        tracing::info!("Enqueuing join task to begin incremental joining");
        task_queue::enqueue_task(&mut conn, workflow_common::JOIN_WORK_TYPE, join_task)
            .await
            .context("Failed to enqueue join task")?;
    }

    let total_duration = start_time.elapsed();
    tracing::info!("Total prove+lift task completed in {:?}", total_duration);
    tracing::info!(
        "Performance breakdown: Deserialize: {:?}, Prove: {:?}, Lift: {:?}, Serialize: {:?}",
        deserialize_duration, prove_duration, lift_duration, serialize_duration
    );

    Ok(())
}
