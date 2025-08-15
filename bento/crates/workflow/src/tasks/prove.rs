// Copyright 2025 RISC Zero, Inc.
//
// Use of this source code is governed by the Business Source License
// as found in the LICENSE-BSL file.

use crate::{
    redis,
    tasks::{deserialize_obj, serialize_obj, RECUR_RECEIPT_PATH},
    Agent,
};
use anyhow::{Context, Result};
use uuid::Uuid;
use workflow_common::ProveReq;

/// Run a prove request
pub async fn prover(agent: &Agent, job_id: &Uuid, task_id: &str, request: &ProveReq) -> Result<()> {
    let index = request.index;

    tracing::debug!("Starting proof of idx: {job_id} - {index}");

    // Use segment data from task definition instead of Redis
    let segment = deserialize_obj(&request.data).context("Failed to deserialize segment data from task definition")?;

    let segment_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from prove task")?
        .prove_segment(&agent.verifier_ctx, &segment)
        .context("Failed to prove segment")?;

    tracing::debug!("Completed proof: {job_id} - {index}");

    tracing::debug!("lifting {job_id} - {index}");
    let lift_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from resolve task")?
        .lift(&segment_receipt)
        .with_context(|| format!("Failed to lift segment {index}"))?;

    tracing::debug!("lifting complete {job_id} - {index}");

    let mut conn = agent.redis_pool.get().await?;
    let output_key = format!("job:{job_id}:{RECUR_RECEIPT_PATH}:{task_id}");
    // Write out lifted receipt
    let lift_asset = serialize_obj(&lift_receipt).expect("Failed to serialize the segment");
    redis::set_key_with_expiry(
        &mut conn,
        &output_key,
        lift_asset,
        Some(agent.args.redis_ttl),
    )
    .await?;

    Ok(())
}
