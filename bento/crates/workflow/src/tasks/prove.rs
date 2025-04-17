// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{tasks::{serialize_obj, RECUR_RECEIPT_PATH}, Agent};
use anyhow::{Context, Result};
use redis::AsyncCommands;
use std::time::Instant;
use task_queue::Task;
use workflow_common::ProveReq; // import request type

/// Run a prove request
pub async fn prove(agent: &Agent, task: &Task) -> Result<()> {
    let start_time = Instant::now();
    let job_id = task.job_id;

    // Parse the ProveReq to get the segment index
    let req: ProveReq = serde_json::from_value(task.task_def.clone())
        .context("Failed to parse ProveReq from task_def")?;
    let index = req.index;

    let deserialize_start = Instant::now();
    let segment = bincode::deserialize(&task.data)?;
    let deserialize_duration = deserialize_start.elapsed();
    tracing::debug!("Deserialized segment in {:?}", deserialize_duration);

    let job_prefix = format!("job:{}", job_id);

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

    // Store receipt in a list keyed by segment index
    let output_key = format!("{}:{}:{}", job_prefix, RECUR_RECEIPT_PATH, index);

    let serialize_start = Instant::now();
    let lift_asset = serialize_obj(&lift_receipt).expect("Failed to serialize the segment");
    let serialize_duration = serialize_start.elapsed();
    tracing::debug!("Serialized lift receipt in {:?}", serialize_duration);

    let store_start = Instant::now();
    let mut conn = agent.redis_conn.clone();
    conn.lpush::<_, _, ()>(&output_key, &lift_asset)
        .await
        .context("Failed to push receipt to Redis queue")?;
    let store_duration = store_start.elapsed();
    tracing::info!("Pushed lift receipt to Redis queue in {:?}", store_duration);

    let total_duration = start_time.elapsed();
    tracing::info!("Total prove+lift task completed in {:?}", total_duration);
    tracing::info!(
        "Performance breakdown: Deserialize: {:?}, Prove: {:?}, Lift: {:?}, Serialize: {:?}, Store: {:?}",
        deserialize_duration, prove_duration, lift_duration, serialize_duration, store_duration
    );

    Ok(())
}
