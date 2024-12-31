// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj, RECUR_RECEIPT_PATH},
    Agent,
};
use anyhow::{Context, Result};
use risc0_zkvm::ReceiptClaim;
use risc0_zkvm::SuccinctReceipt;
use uuid::Uuid;
use workflow_common::JoinReq;


async fn lift_receipt(
    agent: &Agent,
    prefix: &str,
    idx: usize,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
    let mut conn = redis::get_connection(&agent.redis_pool).await?;
    let key = format!("{prefix}:{idx}");
    let receipt: Vec<u8> = conn
        .get(&key)
        .await
        .with_context(|| format!("segment data not found for key: {key}"))?;

    let segment_receipt = deserialize_obj(&receipt)
        .with_context(|| format!("Failed to deserialize receipt for {key}"))?;

    agent
        .prover
        .as_ref()
        .context("Missing prover from resolve task")?
        .lift(&segment_receipt)
        .with_context(|| format!("Failed to lift segment {key}"))
}

/// Run the join operation
pub async fn join(agent: &Agent, job_id: &Uuid, request: &JoinReq) -> Result<()> {
    let mut conn = redis::get_connection(&agent.redis_pool).await?;
    // Build the redis keys for the right and left joins
    let job_prefix = format!("job:{job_id}");
    let recur_receipts_prefix = format!("{job_prefix}:{RECUR_RECEIPT_PATH}");

    let (lifted_left, lifted_right) = tokio::try_join!(
        lift_receipt(&agent, &recur_receipts_prefix, request.left),
        lift_receipt(&agent, &recur_receipts_prefix, request.right)
    )?;


    tracing::info!("Joining {job_id} - {} + {} -> {}", request.left, request.right, request.idx);

    let joined = agent
        .prover
        .as_ref()
        .context("Missing prover from join task")?
        .join(&lifted_left, &lifted_right)?;

    let join_result = serialize_obj(&joined)?;
    let output_key = format!("{recur_receipts_prefix}:{}", request.idx);

    redis::set_key_with_expiry::<Vec<u8>>(&mut conn, &output_key, join_result, Some(agent.args.redis_ttl))
        .await?;

    tracing::info!("Join Complete {job_id} - {}", request.left);

    Ok(())
}
