// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::{Agent, tasks::serialize_obj};
use anyhow::{Context, Result};
use bytemuck;
use redis::AsyncCommands;
use risc0_zkvm::ProveKeccakRequest;
use std::time::Instant;
use std::sync::atomic::{AtomicUsize, Ordering};
use task_queue::Task;

// Static counter to track keccak segment indices
static KECCAK_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Process a keccak request
pub async fn keccak(agent: &Agent, task: &Task) -> Result<()> {
    let start_time = Instant::now();
    let job_id = task.job_id;

    // Debug log the raw task_def to see what we're trying to deserialize
    tracing::debug!("Raw keccak task_def to deserialize: {:?}", task.task_def);

    // First, deserialize the task_def as a TaskType
    let task_type: workflow_common::TaskType = serde_json::from_value(task.task_def.clone())
        .context("Failed to deserialize TaskType from task_def")?;

    // Then, extract the KeccakReq from the TaskType
    let req = match task_type {
        workflow_common::TaskType::Keccak(req) => req,
        _ => return Err(anyhow::anyhow!("Expected Keccak task type, got {:?}", task_type)),
    };

    // Use an incrementing counter for segment indices
    let segment_idx = KECCAK_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;

    let deserialize_start = Instant::now();
    // Convert input bytes to keccak states
    let keccak_states_bytes = &task.data;
    let deserialize_duration = deserialize_start.elapsed();
    tracing::debug!("Processing keccak input of size: {} bytes", keccak_states_bytes.len());

    tracing::info!("Processing keccak for job {} segment {} with claim_digest {:?}",
                  job_id, segment_idx, req.claim_digest);

    // Convert bytes to KeccakState vector
    let state_size = std::mem::size_of::<[u64; 25]>();
    let input_states = if keccak_states_bytes.len() % state_size == 0 {
        let mut states = Vec::with_capacity(keccak_states_bytes.len() / state_size);
        for chunk in keccak_states_bytes.chunks_exact(state_size) {
            let state: [u64; 25] = bytemuck::pod_read_unaligned(chunk);
            states.push(state);
        }
        states
    } else {
        return Err(anyhow::anyhow!("Invalid keccak state size: expected multiple of {} bytes", state_size));
    };

    // Create the keccak request
    let keccak_request = ProveKeccakRequest {
        claim_digest: req.claim_digest,
        po2: req.po2,
        control_root: req.control_root,
        input: input_states,
    };

    // Process keccak work here
    let process_start = Instant::now();
    let keccak_result = agent
        .prover
        .as_ref()
        .context("Missing prover from keccak task")?
        .prove_keccak(&keccak_request)
        .context("Failed to prove keccak segment")?;
    let process_duration = process_start.elapsed();

    tracing::info!("Completed keccak: job {} segment {} in {:?}", job_id, segment_idx, process_duration);

    let serialize_start = Instant::now();
    let keccak_asset = serialize_obj(&keccak_result).expect("Failed to serialize the keccak result");
    let serialize_duration = serialize_start.elapsed();
    tracing::debug!("Serialized keccak result in {:?}", serialize_duration);

    // Store result in Redis with consistent key format
    let job_prefix = format!("job:{}", job_id);
    let keccak_key = format!("{job_prefix}:keccak:{}", segment_idx);

    // Store the receipt in Redis
    let mut conn = agent.redis_conn.clone();
    conn.set_ex::<_, _, ()>(&keccak_key, &keccak_asset, 3600).await
        .context("Failed to store keccak result in Redis")?;
    tracing::info!("Stored keccak result for segment {} in Redis", segment_idx);

    // If this is the first segment, we need to create a union task that will start the union process
    if segment_idx == 1 {
        tracing::info!("First keccak segment completed, starting the union process");

        // Create a union task that will poll for additional receipts as they become available
        let union_task = Task {
            job_id,
            task_id: format!("union:{}", job_id),
            task_def: serde_json::to_value(workflow_common::TaskType::Union(workflow_common::UnionReq {
                idx: 1,  // Starting index doesn't matter for our polling approach
                left: 0,  // These values aren't used in the new union implementation
                right: 0,
            })).unwrap(),
            data: keccak_asset,  // Pass our keccak receipt as the starting point
            prereqs: vec![],
            max_retries: 3,
        };

        tracing::info!("Enqueuing union task to begin incremental unioning");
        task_queue::enqueue_task(&mut conn, workflow_common::KECCAK_WORK_TYPE, union_task)
            .await
            .context("Failed to enqueue union task")?;
    }

    let total_duration = start_time.elapsed();
    tracing::info!("Total keccak task completed in {:?}", total_duration);
    tracing::info!(
        "Performance breakdown: Deserialize: {:?}, Process: {:?}, Serialize: {:?}",
        deserialize_duration, process_duration, serialize_duration
    );

    Ok(())
}
