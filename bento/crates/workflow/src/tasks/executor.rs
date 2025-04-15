// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use std::sync::{Arc, Mutex};

use crate::TaskType;
use anyhow::Result;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, Journal, Segment};
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

            // Create a channel to communicate between the segment_callback and our async code
            let (tx, mut rx) = mpsc::channel(10);
            let job_id_clone = job_id;
            let conn_clone = conn.clone();

            // Spawn a task that will receive segments and process them as they arrive
            let segment_handler = tokio::spawn(async move {
                let mut segment_count = 0;
                while let Some((i, segment)) = rx.recv().await {
                    segment_count += 1;
                    tracing::info!("Received segment {} in real-time", i);

                    // Process this segment immediately
                    if let Err(err) = enqueue_prove_task(&mut conn_clone.clone(), job_id_clone, i, segment).await {
                        tracing::error!("Failed to enqueue prove task for segment {}: {}", i, err);
                    } else {
                        tracing::info!("Successfully enqueued segment {} for proving", i);
                    }
                }
                tracing::info!("Processed {} segments in real-time", segment_count);
            });

            // Create a channel-based segment callback
            let tx_clone = tx.clone();
            let segment_counter = Arc::new(Mutex::new(0usize));

            // Create the executor environment
            let mut env_builder = ExecutorEnv::builder();
            env_builder.write_slice(&input_data);

            let env = match env_builder.build() {
                Ok(env) => env,
                Err(err) => {
                    tracing::error!("Failed to build executor environment: {}", err);
                    return Err(err.to_string().into());
                }
            };

            // Execute the program
            tracing::info!("Executing program from ELF of size: {}", elf_data.len());
            let mut exec = match ExecutorImpl::from_elf(env, &elf_data) {
                Ok(exec) => exec,
                Err(err) => {
                    tracing::error!("Failed to create executor from ELF: {}", err);
                    return Err(err.to_string().into());
                }
            };

            // Use run_with_callback to process segments as they're created
            let session = match exec.run_with_callback(|segment| {
                let tx = tx_clone.clone();
                let counter = segment_counter.clone();
                let mut count = counter.lock().unwrap();
                let idx = *count;
                *count += 1;

                // Send the segment through our channel to be processed asynchronously
                tokio::task::spawn(async move {
                    if let Err(e) = tx.send((idx, segment)).await {
                        tracing::error!("Failed to send segment to handler: {}", e);
                    }
                });

                // Return a null segment reference to the executor
                Ok(Box::new(risc0_zkvm::NullSegmentRef {}))
            }) {
                Ok(session) => session,
                Err(err) => {
                    tracing::error!("Failed to run executor: {}", err);
                    return Err(err.to_string().into());
                }
            };

            tracing::info!("Execution completed with {} segments", session.segments.len());

            // Drop the sender to signal completion to our segment handler
            drop(tx);

            // Wait for all segment processing to complete
            match segment_handler.await {
                Ok(_) => tracing::info!("Segment handler completed successfully"),
                Err(e) => tracing::error!("Segment handler failed: {}", e),
            }

            // Store session info in Redis
            let session_key = format!("session:{}", job_id);
            tracing::info!("Creating session data with {} segments", session.segments.len());
            let session_data = SessionData {
                segment_count: session.segments.len(),
                user_cycles: session.user_cycles,
                total_cycles: session.total_cycles,
                journal: session.journal,
            };

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
        segment: segment_bytes, // Directly include segment data in the task
        prereqs: vec![],
        max_retries: 3,
    };

    tracing::info!("Enqueuing prove task for segment {} with embedded data", segment_idx);
    task_queue::enqueue_task(conn, "prove", task).await.map_err(|e| e.to_string().into())
}

// ... existing code ...
