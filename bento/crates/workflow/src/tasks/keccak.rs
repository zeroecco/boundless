// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{
    tasks::{serialize_obj, COPROC_CB_PATH},
    TaskType,
    Agent,
};
use anyhow::{anyhow, bail, Context, Result};
use redis::AsyncCommands;
use risc0_zkvm::ProveKeccakRequest;
use std::time::Instant;
use task_queue::Task;
use workflow_common::{KeccakReq, KECCAK_RECEIPT_PATH};

fn try_keccak_bytes_to_input(input: &[u8]) -> Result<Vec<[u64; 25]>> {
    let chunks = input.chunks_exact(std::mem::size_of::<[u64; 25]>());
    if !chunks.remainder().is_empty() {
        bail!("Input length must be a multiple of KeccakState size");
    }
    chunks
        .map(bytemuck::try_pod_read_unaligned)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("Failed to convert input bytes to KeccakState: {}", e))
}

/// Run a keccak task
pub async fn keccak(agent: &Agent, task: &Task) -> Result<()> {
    let start_time = Instant::now();
    let job_id = task.job_id;
    let task_id = &task.task_id;

    // Parse task definition to get KeccakReq
    let parse_start = Instant::now();
    let keccak_req: KeccakReq = match serde_json::from_value(task.task_def.clone()) {
        Ok(TaskType::Keccak(req)) => req,
        Ok(_) => anyhow::bail!("Task is not a Keccak task"),
        Err(e) => anyhow::bail!("Failed to parse task definition: {}", e),
    };
    let parse_duration = parse_start.elapsed();
    tracing::info!("Task parsing completed in {:?}", parse_duration);

    let mut conn = agent.redis_conn.clone();

    // Get input data from Redis
    let keccak_input_path = format!("job:{}:{}:{}", job_id, COPROC_CB_PATH, keccak_req.claim_digest);
    tracing::info!("Fetching keccak input from Redis with key: {}", keccak_input_path);

    let fetch_start = Instant::now();
    let keccak_input: Vec<u8> = conn
        .get::<_, Vec<u8>>(&keccak_input_path)
        .await
        .with_context(|| format!("Keccak input data not found for key: {keccak_input_path}"))?;
    let fetch_duration = fetch_start.elapsed();

    tracing::info!("Successfully retrieved keccak input of size: {} bytes in {:?}", keccak_input.len(), fetch_duration);

    // Create ProveKeccakRequest
    let convert_start = Instant::now();
    let keccak_request = ProveKeccakRequest {
        claim_digest: keccak_req.claim_digest,
        po2: keccak_req.po2,
        control_root: keccak_req.control_root,
        input: try_keccak_bytes_to_input(&keccak_input)?,
    };
    let convert_duration = convert_start.elapsed();
    tracing::info!("Converted keccak input to request in {:?}", convert_duration);

    if keccak_request.input.is_empty() {
        anyhow::bail!("Received empty keccak input with claim_digest: {}", keccak_req.claim_digest);
    }

    tracing::info!("Starting keccak proof for digest: {}", keccak_req.claim_digest);

    // Prove keccak
    let prove_start = Instant::now();
    let keccak_receipt = agent
        .prover
        .as_ref()
        .context("Missing prover from keccak task")?
        .prove_keccak(&keccak_request)
        .context("Failed to prove keccak")?;
    let prove_duration = prove_start.elapsed();

    tracing::info!("Completed keccak proof for digest: {} in {:?}", keccak_req.claim_digest, prove_duration);

    // Store receipt in Redis
    let job_prefix = format!("job:{}", job_id);
    let receipt_key = format!("{job_prefix}:{KECCAK_RECEIPT_PATH}:{task_id}");

    let serialize_start = Instant::now();
    let receipt_bytes = serialize_obj(&keccak_receipt)
        .context("Failed to serialize keccak receipt")?;
    let serialize_duration = serialize_start.elapsed();
    tracing::info!("Serialized keccak receipt in {:?}", serialize_duration);

    tracing::info!("Storing keccak receipt in Redis with key: {}", receipt_key);

    let store_start = Instant::now();
    agent
        .set_in_redis(&receipt_key, &receipt_bytes, Some(agent.args.redis_ttl))
        .await
        .context("Failed to store keccak receipt in Redis")?;
    let store_duration = store_start.elapsed();
    tracing::info!("Stored keccak receipt in Redis in {:?}", store_duration);

    let total_duration = start_time.elapsed();
    tracing::info!("Successfully stored keccak receipt for task: {} in total time: {:?}", task_id, total_duration);
    tracing::info!("Performance breakdown: Parse: {:?}, Fetch: {:?}, Convert: {:?}, Prove: {:?}, Serialize: {:?}, Store: {:?}",
                 parse_duration, fetch_duration, convert_duration, prove_duration, serialize_duration, store_duration);

    Ok(())
}
