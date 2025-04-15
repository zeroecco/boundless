// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    tasks::{serialize_obj, RECUR_RECEIPT_PATH},
    Agent,
};
use anyhow::{Context, Result};
use task_queue::Task;

/// Run a prove request
pub async fn prove(agent: &Agent, task: &Task) -> Result<()> {
    let job_id = task.job_id;
    let task_id = &task.task_id;

    // Extract task data from the task object
    let task_def = &task.task_def;
    let index = match task_def.get("index") {
        Some(idx) => idx.as_u64().context("Index is not a number")? as usize,
        None => return Err(anyhow::anyhow!("Missing field 'index' in task definition")),
    };

    let segment = bincode::deserialize(&task.data)?;

    let job_prefix = format!("job:{job_id}");

    tracing::info!("Starting proof of idx: {job_id} - {index}");

    let segment_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from prove task")?
        .prove_segment(&agent.verifier_ctx, &segment)
        .context("Failed to prove segment")?;

    tracing::info!("Completed proof: {job_id} - {index}");

    tracing::info!("lifting {job_id} - {index}");
    let lift_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from resolve task")?
        .lift(&segment_receipt)
        .with_context(|| format!("Failed to lift segment {index}"))?;

    tracing::info!("lifting complete {job_id} - {index}");

    let output_key = format!("{job_prefix}:{RECUR_RECEIPT_PATH}:{task_id}");
    // Write out lifted receipt
    let lift_asset = serialize_obj(&lift_receipt).expect("Failed to serialize the segment");

    agent.set_in_redis(&output_key, &lift_asset, Some(agent.args.redis_ttl)).await?;

    Ok(())
}
