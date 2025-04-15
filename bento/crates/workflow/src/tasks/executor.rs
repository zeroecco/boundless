// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use std::sync::Arc;
use std::path::Path;

use crate::{
    tasks::{read_image_id, serialize_obj, COPROC_CB_PATH, RECEIPT_PATH, SEGMENTS_PATH},
    Agent, Args, TaskType,
};
use anyhow::{bail, Context, Result};
use risc0_zkvm::{
    compute_image_id, sha::Digestible, CoprocessorCallback, ExecutorEnv, ExecutorImpl,
    InnerReceipt, Journal, NullSegmentRef, ProveKeccakRequest, ProveZkrRequest, Receipt, Segment,
};
use task_queue::Task;
use tempfile::NamedTempFile;
use serde_json::json;
use workflow_common::{
    s3::{
        ELF_BUCKET_DIR, EXEC_LOGS_BUCKET_DIR, INPUT_BUCKET_DIR, PREFLIGHT_JOURNALS_BUCKET_DIR,
        RECEIPT_BUCKET_DIR, STARK_BUCKET_DIR,
    },
    CompressType, ExecutorReq, ExecutorResp, FinalizeReq, JoinReq, KeccakReq, ProveReq, ResolveReq,
    SnarkReq, UnionReq, AUX_WORK_TYPE, COPROC_WORK_TYPE, JOIN_WORK_TYPE, PROVE_WORK_TYPE,
    SNARK_WORK_TYPE,
};
use tokio::task::{JoinHandle, JoinSet};
use uuid::Uuid;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use redis::Value;
use crate::tasks::prove::prove_task;
use crate::tasks::join::join_task;
use crate::tasks::union::union_task;
use crate::tasks::finalize::finalize_task;
use crate::tasks::keccak::keccak_task;
use bincode;

const V2_ELF_MAGIC: &[u8] = b"R0BF"; // const V1_ ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
const TASK_QUEUE_SIZE: usize = 100; // TODO: could be bigger, but requires testing IRL
const CONCURRENT_SEGMENTS: usize = 50; // This peaks around ~4GB

#[derive(serde::Serialize)]
struct SessionData {
    segment_count: usize,
    user_cycles: u64,
    total_cycles: u64,
    journal: Option<Journal>,
}

struct Coprocessor {
    tx: tokio::sync::mpsc::Sender<SenderType>,
}

impl Coprocessor {
    fn new(tx: tokio::sync::mpsc::Sender<SenderType>) -> Self {
        Self { tx }
    }
}

impl CoprocessorCallback for Coprocessor {
    fn prove_keccak(&mut self, request: ProveKeccakRequest) -> Result<()> {
        self.tx.blocking_send(SenderType::Keccak(request))?;
        Ok(())
    }
    fn prove_zkr(&mut self, _request: ProveZkrRequest) -> Result<()> {
        unreachable!()
    }
}

enum SenderType {
    Segment(u32),
    Keccak(ProveKeccakRequest),
    Fault,
}

/// Run the executor emitting the segments and session to hot storage
///
/// Writes out all segments async using tokio tasks then waits for all
/// tasks to complete before exiting.
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
        },
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
            "ELF data is too small"
        )));
    }

    // Check magic bytes for ELF
    let magic = &elf_data[0..4];
    tracing::debug!("ELF magic bytes: {:?}", magic);
    if magic != b"\x7fELF" && magic != V2_ELF_MAGIC {
        tracing::error!("Invalid ELF magic bytes: {:?}", magic);
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid ELF magic bytes: {:?}", magic)
        )));
    }

    // Get input data from Redis
    let input_key = format!("input:{}", job_id);
    tracing::info!("Fetching input data from Redis with key: {}", input_key);
    let input_data: Vec<u8> = match conn.get::<_, Vec<u8>>(&input_key).await {
        Ok(data) => {
            tracing::info!("Successfully retrieved input data of size: {} bytes", data.len());
            data
        },
        Err(err) => {
            tracing::error!("Failed to retrieve input data: {}", err);
            return Err(err.to_string().into());
        }
    };

    // Execute task based on type
    match task_type {
        TaskType::Executor(_) => {
            tracing::info!("Creating executor environment with input data of size: {}", input_data.len());
            // Create executor environment
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

            let session = match exec.run() {
                Ok(session) => session,
                Err(err) => {
                    tracing::error!("Failed to run executor: {}", err);
                    return Err(err.to_string().into());
                }
            };

            tracing::info!("Execution completed. Storing {} segments", session.segments.len());

            // Store segments in Redis
            for (i, segment_ref) in session.segments.iter().enumerate() {
                let segment_key = format!("{}:segment:{}", job_id, i);
                tracing::debug!("Resolving segment {}", i);
                let segment_data = match segment_ref.resolve() {
                    Ok(data) => data,
                    Err(err) => {
                        tracing::error!("Failed to resolve segment {}: {}", i, err);
                        return Err(err.to_string().into());
                    }
                };

                tracing::debug!("Serializing segment {}", i);
                let segment_bytes = match bincode::serialize(&segment_data) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        tracing::error!("Failed to serialize segment {}: {}", i, err);
                        return Err(err.to_string().into());
                    }
                };

                tracing::debug!("Storing segment {} with key: {}", i, segment_key);
                match conn.set_ex::<_, _, ()>(&segment_key, segment_bytes, 60 * 60 * 2).await {
                    Ok(_) => (),
                    Err(err) => {
                        tracing::error!("Failed to store segment {}: {}", i, err);
                        return Err(err.to_string().into());
                    }
                }
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
        },
        _ => {
            // Handle other task types...
            tracing::info!("Skipping non-executor task type");
        }
    }

    Ok(())
}

// Helper function to store data in Redis
pub async fn store_data_in_redis(
    conn: &mut ConnectionManager,
    key: &str,
    data: &[u8],
) -> Result<()> {
    conn.set(key, data).await
        .context("Failed to store data in Redis")?;
    Ok(())
}

// Helper function to get data from Redis
pub async fn get_data_from_redis(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<Vec<u8>> {
    let data: Vec<u8> = conn.get(key).await
        .context("Failed to get data from Redis")?;
    Ok(data)
}

pub async fn get_elf_data(job_id: &str) -> Result<Vec<u8>> {
    // TODO: Implement getting ELF data from Redis
    Ok(Vec::new())
}

pub async fn get_input_data(job_id: &str) -> Result<Vec<u8>> {
    // TODO: Implement getting input data from Redis
    Ok(Vec::new())
}

pub async fn execute_task(task: Task) -> Result<()> {
    let task_type: TaskType = serde_json::from_value(task.task_def)?;

    // Get ELF and input data from Redis
    let elf_data = get_elf_data(&task.job_id.to_string()).await?;
    let input_data = get_input_data(&task.job_id.to_string()).await?;

    // Write ELF and input to temporary files
    let elf_path = Path::new("/tmp/elf.bin");
    let input_path = Path::new("/tmp/input.bin");
    std::fs::write(elf_path, elf_data)?;
    std::fs::write(input_path, input_data)?;

    // Execute task based on type
    match task_type {
        TaskType::Join(_) => {
            join_task(elf_path, input_path).await?;
            Ok(())
        },
        TaskType::Union(_) => {
            union_task(elf_path, input_path).await?;
            Ok(())
        },
        TaskType::Finalize(_) => {
            finalize_task(elf_path, input_path).await?;
            Ok(())
        },
        TaskType::Keccak(_) => {
            keccak_task(elf_path, input_path).await?;
            Ok(())
        },
        TaskType::Executor(_) => {
            // TODO: Implement executor task logic
            Ok(())
        },
        TaskType::Resolve(_) => {
            // TODO: Implement resolve task logic
            Ok(())
        },
        TaskType::Snark(_) => {
            // TODO: Implement snark task logic
            Ok(())
        },
        TaskType::Prove(_) => {
            // TODO: Implement prove task logic
            Ok(())
        },
    }
}

// ... existing code ...
