// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use std::{collections::HashMap, sync::Arc};
use anyhow::{Context, Result};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, Journal, NullSegmentRef, Segment, CoprocessorCallback, ProveKeccakRequest, ProveZkrRequest};
use serde::Serialize;
use task_queue::Task;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;
use workflow_common::{KeccakReq, ProveReq, ResolveReq, FinalizeReq, TaskType};

const V2_ELF_MAGIC: &[u8] = b"R0BF";

// Helper to get data from Redis with error context
async fn fetch_redis_data(conn: &mut ConnectionManager, key: &str) -> Result<Vec<u8>> {
    conn.get(key)
        .await
        .with_context(|| format!("Failed to fetch data from Redis with key: {}", key))
}

// Helper to store data in Redis with error context
async fn store_redis_data(
    conn: &mut ConnectionManager,
    key: &str,
    data: &[u8],
    ttl_seconds: u64,
) -> Result<()> {
    conn.set_ex(key, data, ttl_seconds)
        .await
        .with_context(|| format!("Failed to store data to Redis with key: {}", key))
}

#[derive(Serialize)]
struct SessionData {
    segment_count: usize,
    user_cycles: u64,
    total_cycles: u64,
    journal: Option<Journal>,
}

// Coprocessor callback to forward Keccak requests to the planner task.
struct PlannerCoprocessor {
    tx: mpsc::Sender<SenderType>,
}

impl CoprocessorCallback for PlannerCoprocessor {
    fn prove_zkr(&mut self, _req: ProveZkrRequest) -> Result<()> {
        // No-op for ZKR requests.
        Ok(())
    }

    fn prove_keccak(&mut self, req: ProveKeccakRequest) -> Result<()> {
        // Send Keccak request to planner with input states
        let keccak_req = KeccakReq {
            claim_digest: req.claim_digest,
            po2: req.po2,
            control_root: req.control_root,
        };

        // Convert input states to flat raw bytes without any serialization metadata
        // This ensures the bytes will be exactly KeccakState size multiples
        let mut input_states_bytes = Vec::new();
        for state in &req.input {
            // Use bytemuck to safely convert each KeccakState to bytes
            let state_bytes = bytemuck::bytes_of(state);
            input_states_bytes.extend_from_slice(state_bytes);
        }

        if let Err(e) = self.tx.blocking_send(SenderType::Keccak((keccak_req, input_states_bytes))) {
            println!("Planner keccak send error: {}", e);
        }
        Ok(())
    }
}

enum SenderType {
    Segment(()),
    Keccak((KeccakReq, Vec<u8>)), // Now includes both request metadata and serialized input states
}

/// Entry point for executor tasks
pub async fn executor(
    mut conn: ConnectionManager,
    task: Task,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let job_id = task.job_id;
    let task_type: workflow_common::TaskType = serde_json::from_value(task.task_def)?;

    // Fetch ELF binary using helper, then validate it
    let elf_key = format!("elf:{}", job_id);
    tracing::info!("Fetching ELF binary from Redis with key: {}", elf_key);
    let elf_data = fetch_redis_data(&mut conn, &elf_key).await?;
    if elf_data.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ELF data is too small",
        )
        .into());
    }
    let magic = &elf_data[0..4];
    tracing::debug!("ELF magic bytes: {:?}", magic);
    if magic != b"\x7fELF" && magic != V2_ELF_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid ELF magic bytes: {:?}", magic),
        )
        .into());
    }

    // Fetch input data using helper
    let input_key = format!("input:{}", job_id);
    tracing::info!("Fetching input data from Redis with key: {}", input_key);
    let input_data = fetch_redis_data(&mut conn, &input_key).await?;

    // Only run for Executor task types
    if let workflow_common::TaskType::Executor(_) = task_type {
        tracing::info!("Setting up executor environment with input size: {}", input_data.len());

        // Channels for receiving segments and notifications (keccak events can be enqueued later)
        let (planner_tx, planner_rx) = mpsc::channel::<SenderType>(100);
        let segment_map = Arc::new(Mutex::new(HashMap::new()));
        let (seg_tx, mut seg_rx) = mpsc::channel(100);

        // Clone variables for the blocking task and planner
        let elf_data_clone = elf_data.clone();
        let input_data_clone = input_data.clone();
        let job_id_clone = job_id;
        let conn_planner = conn.clone();
        let planner_tx_clone = planner_tx.clone();

        // Spawn blocking executor task to run the ELF and capture segments
        let executor_handle = tokio::task::spawn_blocking(move || {
            // Build executor environment with coprocessor callback for Keccak.
            let mut env_builder = ExecutorEnv::builder();
            env_builder.write_slice(&input_data_clone);
            env_builder.coprocessor_callback(PlannerCoprocessor {
                tx: planner_tx_clone.clone(),
            });
            let env = env_builder
                .build()
                .map_err(|e| e.to_string())?;
            let mut exec = ExecutorImpl::from_elf(env, &elf_data_clone).map_err(|e| e.to_string())?;
            let mut segment_idx = 0;

            let session = exec
                .run_with_callback(move |segment| {
                    // Send segment index and segment over the channel; on failure print error
                    if let Err(e) = seg_tx.blocking_send((segment_idx, segment)) {
                        println!("Segment send error: {}", e);
                    }
                    // Notify planner about a new segment
                    if let Err(e) = planner_tx_clone.blocking_send(SenderType::Segment(())) {
                        println!("Planner notification error: {}", e);
                    }
                    segment_idx += 1;
                    Ok(Box::new(NullSegmentRef {}))
                })
                .map_err(|e| e.to_string())?;

            Ok::<_, String>((session.user_cycles, session.total_cycles, session.journal))
        });

        // Process segments as they arrive asynchronously
        let process_segments = async {
            let mut segment_count = 0;
            while let Some((_idx, segment)) = seg_rx.recv().await {
                segment_count += 1;
                tracing::debug!("Received segment {} in real-time", segment_count);
                segment_map.lock().await.insert(segment_count, segment.clone());
                let segment_bytes = bincode::serialize(&segment)
                    .with_context(|| format!("Failed to serialize segment {}", segment_count)).unwrap();

                // Enqueue prove task for the segment
                if let Err(e) = enqueue_task(&mut conn, job_id_clone, segment_count, segment_bytes, workflow_common::TaskType::Prove(ProveReq { index: segment_count })).await {
                    tracing::error!("Prove task enqueue failed for segment {}: {}", segment_count, e);
                } else {
                    tracing::debug!("Enqueued prove task for segment {}", segment_count);
                }
            }
            tracing::info!("Finished processing {} segments", segment_count);
            segment_count
        };

        // Start the planner task (handles keccak events and other notifications)
        let planner_handle = tokio::spawn(run_planner(planner_rx, conn_planner, job_id_clone, segment_map.clone()));

        let segment_count = process_segments.await;

        // Await the executor result and handle errors
        let (user_cycles, total_cycles, journal) = executor_handle.await??;

        // Signal the planner task that no more messages will come
        drop(planner_tx);
        if let Err(e) = planner_handle.await {
            tracing::error!("Planner task failed: {}", e);
        }

        tracing::info!("Execution completed with {} segments", segment_count);

        // Create session data and store it into Redis
        let session_key = format!("session:{}", job_id);
        let session_data = SessionData { segment_count, user_cycles, total_cycles, journal };
        let session_bytes = bincode::serialize(&session_data)
            .context("Failed to serialize session data")?;
        store_redis_data(&mut conn, &session_key, &session_bytes, 7200).await?;
        tracing::info!("Stored session info for job {}", job_id);

        // Enqueue resolve and finalize tasks with dependencies
        {
            // Resolve should run after the initial join task
            let join_id = format!("join:{}", job_id);
            let resolve_req = ResolveReq { max_idx: segment_count, union_max_idx: None };
            let resolve_task = Task {
                job_id,
                task_id: format!("resolve:{}", job_id),
                task_def: serde_json::to_value(TaskType::Resolve(resolve_req))?,
                data: vec![],
                prereqs: vec![join_id.clone()],
                max_retries: 3,
            };
            tracing::info!("Enqueuing resolve task {}", resolve_task.task_id);
            task_queue::enqueue_task(&mut conn, "resolve", resolve_task).await?;

            // Finalize should run after resolve completes
            let finalize_req = FinalizeReq { max_idx: segment_count };
            let finalize_task = Task {
                job_id,
                task_id: format!("finalize:{}", job_id),
                task_def: serde_json::to_value(TaskType::Finalize(finalize_req))?,
                data: vec![],
                prereqs: vec![format!("resolve:{}", job_id)],
                max_retries: 0,
            };
            tracing::info!("Enqueuing finalize task {}", finalize_task.task_id);
            task_queue::enqueue_task(&mut conn, "finalize", finalize_task).await?;
        }

    } else {
        tracing::info!("Skipping non-executor task type");
    }

    Ok(())
}

/// The planner listens for task events; when it receives a Keccak event, it processes it separately.
async fn run_planner(
    mut rx: mpsc::Receiver<SenderType>,
    mut conn: ConnectionManager,
    job_id: Uuid,
    _segment_map: Arc<Mutex<HashMap<usize, Segment>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Use a counter dedicated to keccak tasks.
    let mut keccak_count = 0;
    while let Some(sender_event) = rx.recv().await {
        match sender_event {
            SenderType::Segment(_) => {
                // The segment events are handled directly in the executor branch.
            }
            SenderType::Keccak((keccak_req, input_states_bytes)) => {
                keccak_count += 1;
                enqueue_keccak_task(&mut conn, job_id, keccak_req, input_states_bytes, keccak_count).await?;
            }
        }
    }
    tracing::info!("Planner task completed");
    Ok(())
}

/// Enqueue a keccak proof task into the coprocessor queue
async fn enqueue_keccak_task(
    conn: &mut ConnectionManager,
    job_id: Uuid,
    keccak_req: KeccakReq,
    input_states_bytes: Vec<u8>,
    keccak_idx: usize,
) -> Result<()> {
    tracing::info!(
        "Processing keccak request for claim_digest: {} at index: {}",
        keccak_req.claim_digest,
        keccak_idx
    );

    // Create a unique task ID for keccak task
    let task_id = format!("keccak:{}:{}:{}", job_id, keccak_req.claim_digest, keccak_idx);

    // Check if input size is correct (should be a multiple of KeccakState size: 25 u64s = 200 bytes)
    let state_size = std::mem::size_of::<[u64; 25]>();
    if input_states_bytes.len() % state_size != 0 {
        tracing::warn!(
            "Input bytes size {} is not a multiple of KeccakState size {}",
            input_states_bytes.len(),
            state_size
        );
    }
    let state_count = input_states_bytes.len() / state_size;
    tracing::info!(
        "Using raw keccak input states: {} bytes for {} states",
        input_states_bytes.len(),
        state_count
    );

    // Create the keccak task definition
    let task_def = serde_json::to_value(workflow_common::TaskType::Keccak(keccak_req))
        .context("Failed to serialize keccak task definition")?;

    // Build the Task with data payload
    let keccak_task = Task {
        job_id,
        task_id,
        task_def,
        data: input_states_bytes,
        prereqs: vec![],
        max_retries: 3,
    };

    // Enqueue the keccak task into coprocessor work stream
    task_queue::enqueue_task(conn, "keccak", keccak_task)
        .await
        .context("Failed to enqueue keccak task")?;
    tracing::info!("Enqueued keccak task");

    Ok(())
}

async fn enqueue_task(
    conn: &mut ConnectionManager,
    job_id: Uuid,
    segment_idx: usize,
    segment: Vec<u8>,
    task_type: workflow_common::TaskType,
) -> Result<()> {
    let task_id = format!("prove:{}:{}", job_id, segment_idx);
    let task_def = serde_json::to_value(task_type)
        .with_context(|| "Failed to serialize prove task definition")?;

    // Add debug logging to see the actual task_def JSON
    tracing::debug!("Task definition JSON for segment {}: {:?}", segment_idx, task_def);

    let prove_task = Task {
        job_id,
        task_id,
        task_def,
        data: segment,
        prereqs: vec![],
        max_retries: 3,
    };

    tracing::debug!("Enqueuing prove task for segment {}", segment_idx);
    task_queue::enqueue_task(conn, workflow_common::PROVE_WORK_TYPE, prove_task)
        .await
        .with_context(|| format!("Failed to enqueue prove task for segment {}", segment_idx))?;
    Ok(())
}
