// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj, RECEIPT_PATH, RECUR_RECEIPT_PATH},
    Agent,
};
use anyhow::{Context, Result};
use futures::{stream, StreamExt};
use risc0_zkvm::{ReceiptClaim, SegmentReceipt, SuccinctReceipt, Unknown};
use std::sync::Arc;
use uuid::Uuid;
use workflow_common::ResolveReq;

/// Run the resolve operation
pub async fn resolver(agent: &Agent, job_id: &Uuid, request: &ResolveReq) -> Result<Option<u64>> {
    tracing::info!("Starting resolve for job_id: {job_id}");

    let max_idx = &request.max_idx;
    let job_prefix = format!("job:{job_id}");
    let receipts_key = format!("{job_prefix}:{RECEIPT_PATH}");
    let root_receipt_key = format!("{job_prefix}:{RECUR_RECEIPT_PATH}:{max_idx}");

    let mut conn = redis::get_connection(&agent.redis_pool).await?;
    let receipt: Vec<u8> = conn.get::<_, Vec<u8>>(&root_receipt_key).await.with_context(|| {
        format!("segment data not found for root receipt key: {root_receipt_key}")
    })?;

    // Deserialize receipt, handling both direct SuccinctReceipt and SegmentReceipt that needs lifting
    let mut conditional_receipt: SuccinctReceipt<ReceiptClaim> =
        if let Ok(res) = deserialize_obj::<SuccinctReceipt<ReceiptClaim>>(&receipt) {
            res
        } else {
            tracing::info!("Deserializing receipt to SegmentReceipt");
            let segment_receipt: SegmentReceipt = deserialize_obj(&receipt)
                .context("could not deserialize the root receipt to SegmentReceipt")?;

            tracing::info!("Lifting SegmentReceipt");
            agent
                .prover
                .as_ref()
                .context("Missing prover from resolve task")?
                .lift(&segment_receipt)
                .context("Failed to lift SegmentReceipt")?
        };

    let mut assumptions_len: Option<u64> = None;
    if conditional_receipt.claim.clone().as_value()?.output.is_some() {
        if let Some(guest_output) =
            conditional_receipt.claim.clone().as_value()?.output.as_value()?
        {
            if !guest_output.assumptions.is_empty() {
                let assumptions = guest_output.assumptions.as_value()?.iter().collect::<Vec<_>>();
                tracing::info!("Resolving {} assumption(s)", assumptions.len());
                assumptions_len = Some(assumptions.len().try_into()?);

                // Handle union receipt if present
                let mut already_processed_union = false;
                if let Some(idx) = request.union_max_idx {
                    let union_receipt_key = format!("{job_prefix}:{RECEIPT_PATH}:{idx}");
                    tracing::info!("Processing union receipt key: {union_receipt_key}");

                    let union_receipt_bytes: Vec<u8> = conn
                        .get(&union_receipt_key)
                        .await
                        .context("Failed to get union receipt from Redis")?;

                    let union_receipt: SuccinctReceipt<Unknown> =
                        deserialize_obj(&union_receipt_bytes)
                            .context("Failed to deserialize to SuccinctReceipt<Unknown> type")?;

                    // Resolve union receipt first
                    tracing::info!("Resolving union receipt");
                    conditional_receipt = agent
                        .prover
                        .as_ref()
                        .context("Missing prover from resolve task")?
                        .resolve(&conditional_receipt, &union_receipt)
                        .context("Failed to resolve the union receipt")?;

                    already_processed_union = true;
                }

                // Prepare assumption data for processing
                let mut assumption_tasks = Vec::new();

                // First, fetch all assumption data concurrently
                for assumption in assumptions {
                    // Skip union if already processed
                    if already_processed_union {
                        // Only process each assumption once
                        already_processed_union = false;
                        continue;
                    }

                    let assumption_claim = assumption.as_value()?.claim.to_string();
                    let assumption_key = format!("{receipts_key}:{assumption_claim}");
                    assumption_tasks.push((assumption_key, assumption_claim));
                }

                // Process all assumptions - fetch concurrently but resolve sequentially
                if !assumption_tasks.is_empty() {
                    // Use a buffered stream to process multiple Redis fetches concurrently
                    let concurrency_limit = 4; // Adjust based on system capabilities

                    // Wrap the pool in an Arc for thread-safe sharing
                    let pool = Arc::new(agent.redis_pool.clone());

                    let results = stream::iter(assumption_tasks)
                        .map(|(key, claim)| {
                            let pool = Arc::clone(&pool);
                            async move {
                                tracing::info!("Fetching assumption with key: {key}");
                                // Create a new connection for each task
                                let mut task_conn = redis::get_connection(&pool).await?;
                                let bytes =
                                    task_conn.get::<_, Vec<u8>>(&key).await.with_context(|| {
                                        format!("corroborating receipt not found: key {key}")
                                    })?;

                                let receipt: SuccinctReceipt<Unknown> = deserialize_obj(&bytes)
                                    .with_context(|| {
                                        format!("could not deserialize assumption receipt: {key}")
                                    })?;

                                Ok::<_, anyhow::Error>((receipt, claim))
                            }
                        })
                        .buffer_unordered(concurrency_limit)
                        .collect::<Vec<_>>()
                        .await;

                    // Process results sequentially (resolving must be sequential)
                    for (i, result) in results.into_iter().enumerate() {
                        let (assumption_receipt, claim) = result
                            .with_context(|| format!("Failed to process assumption {}", i))?;

                        tracing::info!("Resolving assumption: {claim}");
                        conditional_receipt = agent
                            .prover
                            .as_ref()
                            .context("Missing prover from resolve task")?
                            .resolve(&conditional_receipt, &assumption_receipt)
                            .context("Failed to resolve assumption")?;
                    }
                }

                tracing::info!("Resolve complete");
            }
        }
    }

    // Write out the resolved receipt
    let serialized_asset =
        serialize_obj(&conditional_receipt).context("Failed to serialize the asset")?;

    redis::set_key_with_expiry(
        &mut conn,
        &root_receipt_key,
        serialized_asset,
        Some(agent.args.redis_ttl),
    )
    .await
    .context("Failed to set root receipt key with expiry")?;

    Ok(assumptions_len)
}
