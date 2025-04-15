// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use crate::TaskType;
use anyhow::Result;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, Journal, NullSegmentRef, Segment};
use task_queue::Task;
use tokio::sync::mpsc;
use uuid::Uuid;
use workflow_common::ProveReq;

const V2_ELF_MAGIC: &[u8] = b"R0BF"; // const V1_ ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

#[derive(serde::Serialize)]
struct SessionData {
    segment_count: usize,
    user_cycles: u64,
    total_cycles: u64,
    journal: Option<Journal>,
}

pub async fn executor(
    mut conn: ConnectionManager,
    task: Task,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let job_id = task.job_id;
    let task_type: TaskType = serde_json::from_value(task.task_def)?;

    // Get ELF binary from Redis
    let elf_key = format!("elf:{}", job_id);
    tracing::info!("Fetching ELF binary from Redis with key: {}", elf_key);
    let elf_data: Vec<u8> = match conn.get::<_, Vec<u8>>(&elf_key).await {
        Ok(data) => {
            tracing::info!("Successfully retrieved ELF binary of size: {} bytes", data.len());
            data
        }
        Err(err) => {
            tracing::error!("Failed to retrieve ELF binary: {}", err);
            return Err(err.to_string().into());
        }
    };

    // Validate ELF data
    if elf_data.len() < 4 {
        tracing::error!("ELF data is too small: {} bytes", elf_data.len());
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ELF data is too small",
        )));
    }

    // Check magic bytes for ELF
    let magic = &elf_data[0..4];
    tracing::debug!("ELF magic bytes: {:?}", magic);
    if magic != b"\x7fELF" && magic != V2_ELF_MAGIC {
        tracing::error!("Invalid ELF magic bytes: {:?}", magic);
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid ELF magic bytes: {:?}", magic),
        )));
    }

    // Get input data from Redis
    let input_key = format!("input:{}", job_id);
    tracing::info!("Fetching input data from Redis with key: {}", input_key);
    let input_data: Vec<u8> = match conn.get::<_, Vec<u8>>(&input_key).await {
        Ok(data) => {
            tracing::info!("Successfully retrieved input data of size: {} bytes", data.len());
            data
        }
        Err(err) => {
            tracing::error!("Failed to retrieve input data: {}", err);
            return Err(err.to_string().into());
        }
    };

    // Execute task based on type
    match task_type {
        TaskType::Executor(_) => {
            tracing::info!(
                "Creating executor environment with input data of size: {}",
                input_data.len()
            );

            // Create a channel for segments
            let (tx, mut rx) = mpsc::channel(100);

            // Clone what we need for the tokio tasks
            let elf_data_clone = elf_data.clone();
            let input_data_clone = input_data.clone();
            let job_id_clone = job_id;

            // Create a separate task for executing the ELF
            let executor_handle = tokio::task::spawn_blocking(move || {
                // Create the executor environment
                let env = match ExecutorEnv::builder().write_slice(&input_data_clone).build() {
                    Ok(env) => env,
                    Err(e) => return Err(e.to_string()),
                };

                // Create executor from ELF
                let mut exec = match ExecutorImpl::from_elf(env, &elf_data_clone) {
                    Ok(exec) => exec,
                    Err(e) => return Err(e.to_string()),
                };

                // Counter for segment indices
                let mut segment_idx = 0;

                // Run with callback to capture segments
                let session = match exec.run_with_callback(move |segment| {
                    let idx = segment_idx;
                    segment_idx += 1;

                    // Blocking send to tokio channel
                    if let Err(e) = tx.blocking_send((idx, segment)) {
                        println!("Failed to send segment to channel: {}", e);
                    }

                    Ok(Box::new(NullSegmentRef {}))
                }) {
                    Ok(session) => session,
                    Err(e) => return Err(e.to_string()),
                };

                Ok::<_, String>((session.user_cycles, session.total_cycles, session.journal))
            });

            // Process segments as they arrive
            let process_segments = async {
                let mut segment_count = 0;
                while let Some((idx, segment)) = rx.recv().await {
                    segment_count += 1;
                    tracing::info!("Received segment {} in real-time", idx);
                    match enqueue_prove_task(&mut conn, job_id_clone, idx, segment).await {
                        Ok(_) => {
                            tracing::info!("Successfully enqueued segment {} for proving", idx)
                        }
                        Err(e) => tracing::error!("Failed to enqueue segment {}: {}", idx, e),
                    }
                }

                tracing::info!("Finished processing {} segments", segment_count);
                segment_count
            };

            // Wait for both tasks to complete
            let segment_count = process_segments.await;

            // Get session info from executor
            let (user_cycles, total_cycles, journal) = match executor_handle.await {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    tracing::error!("Executor task failed: {}", e);
                    return Err(e.into());
                }
                Err(e) => {
                    tracing::error!("Failed to join executor task: {}", e);
                    return Err(e.to_string().into());
                }
            };

            tracing::info!("Execution completed with {} segments", segment_count);

            // Store session info in Redis
            let session_key = format!("session:{}", job_id);
            tracing::info!("Creating session data with {} segments", segment_count);
            let session_data = SessionData { segment_count, user_cycles, total_cycles, journal };

            tracing::debug!("Serializing session data");
            let session_bytes = match bincode::serialize(&session_data) {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::error!("Failed to serialize session data: {}", err);
                    return Err(err.to_string().into());
                }
            };

            tracing::debug!("Storing session data with key: {}", session_key);
            match conn.set_ex::<_, _, ()>(&session_key, session_bytes, 60 * 60 * 2).await {
                Ok(_) => (),
                Err(err) => {
                    tracing::error!("Failed to store session data: {}", err);
                    return Err(err.to_string().into());
                }
            }

            tracing::info!("Stored session info for job {}", job_id);
        }
        _ => {
            // Handle other task types...
            tracing::info!("Skipping non-executor task type");
        }
    }

    Ok(())
}

// Helper function to enqueue prove tasks with segment data
async fn enqueue_prove_task(
    conn: &mut ConnectionManager,
    job_id: Uuid,
    segment_idx: usize,
    segment: Segment,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Generate a task ID that includes all needed information
    let task_id = format!("prove:{}:{}", job_id, segment_idx);

    tracing::debug!("Serializing segment {}", segment_idx);
    let segment_bytes = match bincode::serialize(&segment) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!("Failed to serialize segment {}: {}", segment_idx, err);
            return Err(err.to_string().into());
        }
    };

    // Create ProveReq
    let task_def = serde_json::to_value(TaskType::Prove(ProveReq { index: segment_idx }))
        .map_err(|e| e.to_string())?;

    tracing::debug!("Creating task for job_id: {}, segment_idx: {}", job_id, segment_idx);

    // Create Task with embedded segment data
    let task = Task {
        job_id,
        task_id: task_id.clone(),
        task_def,
        data: segment_bytes,
        prereqs: vec![],
        max_retries: 3,
    };

    tracing::info!("Enqueuing prove task for segment {} with embedded data", segment_idx);
    task_queue::enqueue_task(conn, "prove", task).await.map_err(|e| e.to_string().into())
}

// ... existing code ...
