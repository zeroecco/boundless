// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj, RECUR_RECEIPT_PATH, SEGMENTS_PATH},
    Agent,
};
use anyhow::{Context, Result};
use uuid::Uuid;
use workflow_common::ProveReq;
use zstd;

/// Run a prove request
pub async fn prover(agent: &Agent, job_id: &Uuid, task_id: &str, request: &ProveReq) -> Result<()> {
    let index = request.index;
    let mut conn = redis::get_connection(&agent.redis_pool).await?;
    let job_prefix = format!("job:{job_id}");
    let segment_key = format!("{job_prefix}:{SEGMENTS_PATH}:{index}");

    tracing::info!("Starting proof of idx: {job_id} - {index}");
    let segment_vec: Vec<u8> = conn
        .get::<_, Vec<u8>>(&segment_key)
        .await
        .with_context(|| format!("segment data not found for segment key: {segment_key}"))?;
    let segment =
        deserialize_obj(&segment_vec).context("Failed to deserialize segment data from redis")?;

    let segment_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from prove task")?
        .prove_segment(&agent.verifier_ctx, &segment)
        .context("Failed to prove segment")?;

    tracing::info!("Completed proof: {job_id} - {index}");

    let output_key = format!("{job_prefix}:{RECUR_RECEIPT_PATH}:{task_id}");
    // Write out lifted receipt
    let segment_asset = serialize_obj(&segment_receipt).expect("Failed to serialize the segment");
    let compressed_receipt = zstd::encode_all(&segment_asset[..], 0)
        .context("Failed to compress the segment receipt")?;

    redis::set_key_with_expiry(&mut conn, &output_key, compressed_receipt, Some(agent.args.redis_ttl))
        .await?;

    Ok(())
}
