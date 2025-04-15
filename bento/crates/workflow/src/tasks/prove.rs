// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    tasks::{serialize_obj, RECUR_RECEIPT_PATH},
    Agent,
};
use anyhow::{Context, Result};
use std::time::Instant;
use task_queue::Task;

/// Run a prove request
pub async fn prove(agent: &Agent, task: &Task) -> Result<()> {
    let start_time = Instant::now();
    let job_id = task.job_id;
    let task_id = &task.task_id;

    let deserialize_start = Instant::now();
    let segment = bincode::deserialize(&task.data)?;
    let deserialize_duration = deserialize_start.elapsed();
    tracing::info!("Deserialized segment in {:?}", deserialize_duration);

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
    tracing::info!("Serialized lift receipt in {:?}", serialize_duration);

    let store_start = Instant::now();
    agent.set_in_redis(&output_key, &lift_asset, Some(agent.args.redis_ttl)).await?;
    let store_duration = store_start.elapsed();
    tracing::info!("Stored lift receipt in Redis in {:?}", store_duration);

    let total_duration = start_time.elapsed();
    tracing::info!("Total prove+lift task completed in {:?}", total_duration);
    tracing::info!("Performance breakdown: Deserialize: {:?}, Prove: {:?}, Lift: {:?}, Serialize: {:?}, Store: {:?}",
                 deserialize_duration, prove_duration, lift_duration, serialize_duration, store_duration);

    Ok(())
}
