// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj, RECUR_RECEIPT_PATH},
    Agent,
};
use anyhow::{Context, Result};
use risc0_zkvm::{ReceiptClaim, SegmentReceipt, SuccinctReceipt};
use std::rc::Rc;
use uuid::Uuid;
use workflow_common::JoinReq;

/// Run the join operation
pub async fn join(agent: &Agent, job_id: &Uuid, request: &JoinReq) -> Result<()> {
    // Build the redis keys for the right and left joins
    let job_prefix = format!("job:{job_id}");
    let recur_receipts_prefix = format!("{job_prefix}:{RECUR_RECEIPT_PATH}");

    let left_path_key = format!("{recur_receipts_prefix}:{}", request.left);
    let right_path_key = format!("{recur_receipts_prefix}:{}", request.right);
    let output_key = format!("{recur_receipts_prefix}:{}", request.idx);

    // Get the prover for lifting operations
    let prover = agent.prover.as_ref().context("Missing prover from join task")?;
    let prover_clone = Rc::clone(prover);

    // Get a single Redis connection for reuse
    let mut conn = agent.get_redis_connection().await?;

    tracing::info!(
        "Processing join {job_id} - {} + {} -> {}",
        request.left,
        request.right,
        request.idx
    );

    // Fetch both receipts in parallel with a single connection using mget
    let receipts: Vec<Vec<u8>> =
        conn.mget(&[&left_path_key, &right_path_key]).await.context("Failed to fetch receipts")?;

    let left_bytes = &receipts[0];
    let right_bytes = &receipts[1];

    // Process left receipt
    let left_receipt = if let Ok(segment) = deserialize_obj::<SegmentReceipt>(left_bytes) {
        tracing::info!("Lifting left receipt {job_id} - {}", request.left);
        let lifted = prover
            .lift(&segment)
            .with_context(|| format!("Failed to lift left segment {}", request.left))?;
        tracing::info!("Left receipt lifted {job_id} - {}", request.left);
        lifted
    } else {
        // Try to deserialize as already-lifted SuccinctReceipt
        deserialize_obj::<SuccinctReceipt<ReceiptClaim>>(left_bytes)
            .context("Failed to deserialize left receipt")?
    };

    // Process right receipt
    let right_receipt = if let Ok(segment) = deserialize_obj::<SegmentReceipt>(right_bytes) {
        tracing::info!("Lifting right receipt {job_id} - {}", request.right);
        let lifted = prover_clone
            .lift(&segment)
            .with_context(|| format!("Failed to lift right segment {}", request.right))?;
        tracing::info!("Right receipt lifted {job_id} - {}", request.right);
        lifted
    } else {
        // Try to deserialize as already-lifted SuccinctReceipt
        deserialize_obj::<SuccinctReceipt<ReceiptClaim>>(right_bytes)
            .context("Failed to deserialize right receipt")?
    };

    // Join the receipts
    tracing::info!(
        "Joining receipts {job_id} - {} + {} -> {}",
        request.left,
        request.right,
        request.idx
    );
    let joined = agent
        .prover
        .as_ref()
        .context("Missing prover from join task")?
        .join(&left_receipt, &right_receipt)?;

    // Serialize and store in separate future to return quickly
    let job_id_clone = *job_id;
    let left_idx = request.left;
    let ttl = agent.args.redis_ttl;
    let redis_pool = agent.redis_pool.clone();
    let output_key_clone = output_key.clone();

    // Use spawn_local if available to reduce thread creation overhead
    tokio::task::spawn(async move {
        // Serialize result
        let join_result = match serialize_obj(&joined) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to serialize joined receipt: {}", e);
                return;
            }
        };

        // Store result - reuse the existing connection if possible
        let mut conn = match redis::get_connection(&redis_pool).await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("Failed to get Redis connection for storage: {}", e);
                return;
            }
        };

        if let Err(e) =
            redis::set_key_with_expiry(&mut conn, &output_key_clone, join_result, Some(ttl)).await
        {
            tracing::error!("Failed to store joined receipt: {}", e);
            return;
        }

        tracing::info!("Join result stored for {job_id_clone} - {left_idx}");
    });

    tracing::info!("Join computation complete {job_id} - {}", request.left);
    Ok(())
}
