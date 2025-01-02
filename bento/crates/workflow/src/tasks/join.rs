use crate::{
    redis::{self, AsyncCommands},
    tasks::{deserialize_obj, serialize_obj, RECUR_RECEIPT_PATH},
    Agent,
};
use anyhow::{Context, Result};
use deadpool_redis::Connection;
use risc0_zkvm::{ReceiptClaim, SegmentReceipt, SuccinctReceipt};
use uuid::Uuid;
use workflow_common::JoinReq;

async fn lift_receipt(
    agent: &Agent,
    conn: &mut Connection,
    prefix: &str,
    idx: usize,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
    let key = format!("{prefix}:{idx}");
    let compressed_segment: Vec<u8> = conn
        .get(&key)
        .await
        .with_context(|| format!("segment data not found for key: {key}"))?;

    let receipt_bytes = zstd::decode_all(&compressed_segment[..])
        .context("Failed to decompress segment data")?;
    // Attempt to parse as SegmentReceipt
    match deserialize_obj::<SegmentReceipt>(&receipt_bytes) {
        Ok(segment_receipt) => {
            // If it's a SegmentReceipt, lift it
            agent
                .prover
                .as_ref()
                .context("Missing prover from resolve task")?
                .lift(&segment_receipt)
                .with_context(|| format!("Failed to lift segment {key}"))
        }
        Err(_) => {
            // Otherwise parse as a SuccinctReceipt<ReceiptClaim> directly
            deserialize_obj::<SuccinctReceipt<ReceiptClaim>>(&receipt_bytes)
                .with_context(|| format!(
                    "Failed to deserialize as either SegmentReceipt or \
                     SuccinctReceipt<ReceiptClaim> for {key}"
                ))
        }
    }
}

/// Run the join operation
pub async fn join(agent: &Agent, job_id: &Uuid, request: &JoinReq) -> Result<()> {
    // Get two separate connections
    let mut conn_left = redis::get_connection(&agent.redis_pool).await?;
    let mut conn_right = redis::get_connection(&agent.redis_pool).await?;
    let recur_receipts_prefix = format!("job:{job_id}:{RECUR_RECEIPT_PATH}");

    // Get both receipts concurrently using the same connection
    let (lifted_left, lifted_right) = tokio::try_join!(
        lift_receipt(&agent, &mut conn_left, &recur_receipts_prefix, request.left),
        lift_receipt(&agent, &mut conn_right, &recur_receipts_prefix, request.right)
    )?;

    tracing::info!("Joining {job_id} - {} + {} -> {}", request.left, request.right, request.idx);

    let joined = agent
        .prover
        .as_ref()
        .context("Missing prover from join task")?
        .join(&lifted_left, &lifted_right)?;

    let output_key = format!("{recur_receipts_prefix}:{}", request.idx);
    let join_result = serialize_obj(&joined)?;

    redis::set_key_with_expiry::<Vec<u8>>(&mut conn_left, &output_key, join_result, Some(agent.args.redis_ttl))
        .await?;

    tracing::info!("Join Complete {job_id} - {}", request.left);

    Ok(())
}
