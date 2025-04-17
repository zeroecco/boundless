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
use workflow_common::{FinalizeReq, KeccakReq, ProveReq, JoinReq, COPROC_WORK_TYPE, JOIN_WORK_TYPE}; // import JoinReq and join queue constant

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
        // Send Keccak request to planner
        let keccak_req = KeccakReq {
            claim_digest: req.claim_digest,
            po2: req.po2,
            control_root: req.control_root,
        };
        if let Err(e) = self.tx.blocking_send(SenderType::Keccak(keccak_req)) {
            println!("Planner keccak send error: {}", e);
        }
        Ok(())
    }
}

enum SenderType {
    Segment(()),
    Keccak(KeccakReq),
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
            while let Some((idx, segment)) = seg_rx.recv().await {
                segment_count += 1;
                tracing::info!("Received segment {} in real-time", idx);
                segment_map.lock().await.insert(idx, segment.clone());
                let segment_bytes = bincode::serialize(&segment)
                    .with_context(|| format!("Failed to serialize segment {}", idx)).unwrap();

                // Enqueue prove task for the segment
                if let Err(e) = enqueue_task(&mut conn, job_id_clone, idx, segment_bytes, workflow_common::TaskType::Prove(ProveReq { index: idx })).await {
                    tracing::error!("Prove task enqueue failed for segment {}: {}", idx, e);
                } else {
                    tracing::info!("Enqueued prove task for segment {}", idx);
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

        // Schedule initial join tasks for odd-indexed segment pairs
        if segment_count > 1 {
            let mut conn_join = conn.clone();
            for i in 1..segment_count {
                if i % 2 == 1 {
                    let join_req = JoinReq { idx: i, left: i - 1, right: i };
                    let task_def = serde_json::to_value(workflow_common::TaskType::Join(join_req.clone()))
                        .context("Failed to serialize initial JoinReq")?;
                    let join_task = Task {
                        job_id,
                        task_id: format!("join:{}:{}", job_id, i),
                        task_def,
                        prereqs: vec![],
                        max_retries: 3,
                        data: vec![],
                    };
                    task_queue::enqueue_task(&mut conn_join, JOIN_WORK_TYPE, join_task)
                        .await
                        .context("Failed to enqueue initial join task")?;
                    tracing::info!("Enqueued initial join task for segments {} and {}", i - 1, i);
                }
            }
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
            SenderType::Keccak(keccak_req) => {
                keccak_count += 1;
                enqueue_keccak_task(&mut conn, job_id, keccak_req, keccak_count).await?;
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
    keccak_idx: usize,
) -> Result<()> {
    tracing::info!(
        "Processing keccak request for claim_digest: {} at index: {}",
        keccak_req.claim_digest,
        keccak_idx
    );

    // Create a unique task ID for keccak task
    let task_id = format!("keccak:{}:{}:{}", job_id, keccak_req.claim_digest, keccak_idx);

    // Create a proper Keccak state (25 u64 values)
    let keccak_state: [u64; 25] = [0u64; 25];

    // Convert to bytes ensuring proper size and alignment
    let state_bytes = bytemuck::bytes_of(&keccak_state).to_vec();

    tracing::info!("Created keccak state data of size: {} bytes", state_bytes.len());

    // Create the keccak task definition
    let task_def = serde_json::to_value(workflow_common::TaskType::Keccak(keccak_req))
        .context("Failed to serialize keccak task definition")?;

    // Build the Task with data payload
    let keccak_task = Task {
        job_id,
        task_id,
        task_def,
        data: state_bytes,
        prereqs: vec![],
        max_retries: 3,
    };

    // Enqueue the keccak task into coprocessor work stream
    task_queue::enqueue_task(conn, COPROC_WORK_TYPE, keccak_task)
        .await
        .context("Failed to enqueue keccak task")?;
    tracing::info!("Enqueued keccak task");

    Ok(())
}

/// Helper to enqueue a generic task into Redis
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
    let prove_task = Task {
        job_id,
        task_id,
        task_def,
        data: segment,
        prereqs: vec![],
        max_retries: 3,
    };

    tracing::info!("Enqueuing prove task for segment {}", segment_idx);
    task_queue::enqueue_task(conn, "prove", prove_task)
        .await
        .with_context(|| format!("Failed to enqueue prove task for segment {}", segment_idx))?;
    Ok(())
}
