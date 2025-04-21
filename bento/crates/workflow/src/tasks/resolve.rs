// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{tasks::{RECEIPT_PATH, RECUR_RECEIPT_PATH}, Agent};
use anyhow::{Context, Result};
use risc0_zkvm::{ReceiptClaim, SuccinctReceipt, Unknown};
use uuid::Uuid;
use workflow_common::{ResolveReq, KECCAK_WORK_TYPE as KECCAK_RECEIPT_PATH};

pub async fn resolver(
    agent: &Agent,
    job_id: &Uuid,
    request: &ResolveReq,
) -> Result<Option<u64>> {
    let max_idx = request.max_idx;
    let job_prefix = format!("job:{}", job_id);
    let root_key = format!("{}:{}:{}", job_prefix, RECUR_RECEIPT_PATH, max_idx);
    let receipts_prefix = format!("{}:{}", job_prefix, RECEIPT_PATH);

    tracing::info!("Resolving receipts for job={} at index={}", job_id, max_idx);

    // 1) Fetch and deserialize the root receipt
    let root_bytes: Vec<u8> = agent.get_from_redis(&root_key)
        .await
        .context("Failed to fetch root receipt from Redis")?;
    let mut receipt: SuccinctReceipt<ReceiptClaim> = bincode::deserialize(&root_bytes)
        .context("Failed to deserialize root receipt")?;

    // 2) Optionally apply the union receipt (for keccak path)
    if let Some(union_idx) = request.union_max_idx {
        let union_key = format!("{}:{}:{}", job_prefix, KECCAK_RECEIPT_PATH, union_idx);
        tracing::info!("Applying union receipt from key {}", union_key);
        let union_bytes: Vec<u8> = agent.get_from_redis(&union_key)
            .await
            .context("Failed to fetch union receipt")?;
        let union_receipt: SuccinctReceipt<Unknown> = bincode::deserialize(&union_bytes)
            .context("Failed to deserialize union receipt")?;
        receipt = agent.prover.as_ref()
            .context("Missing prover in resolve task")?
            .resolve(&receipt, &union_receipt)
            .context("Failed to resolve union receipt")?;
    }

    // 3) Collect and apply guest assumption receipts
    let mut assumptions_len = None;
    // Extract pruned assumptions into an owned Vec to avoid borrowing `receipt`
    let assumptions: Vec<_> = match receipt.claim.as_value()?.output.as_value()? {
        Some(output) => output.assumptions.as_value()?.to_vec(),
        None => Vec::new(),
    };
    if !assumptions.is_empty() {
        tracing::info!("Resolving {} guest assumption(s)", assumptions.len());
        assumptions_len = Some(assumptions.len() as u64);
        for pruned in assumptions {
            // extract each assumption claim
            let claim_str = pruned.as_value()?.claim.to_string();
            let key = format!("{}:{}", receipts_prefix, claim_str);
            tracing::info!("Resolving assumption receipt from key {}", key);
            let data: Vec<u8> = agent.get_from_redis(&key)
                .await
                .context("Failed to fetch assumption receipt")?;
            let assump_receipt: SuccinctReceipt<Unknown> = bincode::deserialize(&data)
                .context("Failed to deserialize assumption receipt")?;
            receipt = agent.prover.as_ref()
                .context("Missing prover in resolve task")?
                .resolve(&receipt, &assump_receipt)
                .context("Failed to resolve assumption receipt")?;
        }
    }

    // 5) Serialize and store the final resolved receipt
    let final_bytes = bincode::serialize(&receipt)
        .context("Failed to serialize final resolved receipt")?;
    agent.set_in_redis(&root_key, &final_bytes, Some(agent.args.redis_ttl))
        .await
        .context("Failed to store resolved receipt in Redis")?;
    tracing::info!("Successfully stored resolved receipt at key {}", root_key);

    Ok(assumptions_len)
}
