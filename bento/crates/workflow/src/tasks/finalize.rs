// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    tasks::{read_image_id, RECUR_RECEIPT_PATH},
    Agent,
};
use anyhow::{bail, Context, Result};
use risc0_zkvm::{InnerReceipt, Receipt, ReceiptClaim, SuccinctReceipt};
use uuid::Uuid;
use workflow_common::FinalizeReq;

/// Run finalize tasks / cleanup
///
/// Creates the final rollup receipt, uploads that to S3
/// job path
pub async fn finalize(agent: &Agent, job_id: &Uuid, request: &FinalizeReq) -> Result<()> {
    // No need for a connection directly since we use agent methods
    let job_prefix = format!("job:{job_id}");
    let root_receipt_key = format!("{job_prefix}:{RECUR_RECEIPT_PATH}:{}", request.max_idx);

    // Retrieve and process the root receipt
    let root_receipt: Vec<u8> = agent
        .get_from_redis(&root_receipt_key)
        .await
        .with_context(|| format!("failed to get the root receipt key: {root_receipt_key}"))?;

    let root_receipt: SuccinctReceipt<ReceiptClaim> =
        bincode::deserialize(&root_receipt).context("could not deserialize the root receipt")?;

    // Retrieve and process the journal
    let journal_key = format!("{job_prefix}:journal");
    let journal: Vec<u8> = agent
        .get_from_redis(&journal_key)
        .await
        .with_context(|| format!("Journal data not found for key ID: {journal_key}"))?;

    let journal = bincode::deserialize(&journal).context("could not deserialize the journal")?;
    let rollup_receipt = Receipt::new(InnerReceipt::Succinct(root_receipt), journal);

    // Verify the receipt
    let image_key = format!("{job_prefix}:image_id");
    let image_id_string: String = agent
        .get_from_redis(&image_key)
        .await
        .with_context(|| format!("Image ID not found for key ID: {image_key}"))?;
    let image_id = read_image_id(&image_id_string)?;

    rollup_receipt.verify(image_id).context("Receipt verification failed")?;

    if !matches!(rollup_receipt.inner, InnerReceipt::Succinct(_)) {
        bail!("rollup_receipt is not Succinct")
    }

    // Store the final receipt in Redis
    let receipt_key = format!("{job_prefix}:final_receipt");
    let receipt_bytes = bincode::serialize(&rollup_receipt)?;
    tracing::info!("Storing rollup receipt in Redis: {}", receipt_key);
    agent
        .set_in_redis(&receipt_key, &receipt_bytes, Some(agent.args.redis_ttl))
        .await
        .context("Failed to store final receipt in Redis")?;

    // Clean up Redis keys
    tracing::debug!("Deleting the keyspace {job_prefix}:*");
    agent.scan_and_delete(&job_prefix).await.context("Failed to delete all redis keys")?;

    Ok(())
}
