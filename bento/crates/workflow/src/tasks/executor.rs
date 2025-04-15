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

const V2_ELF_MAGIC: &[u8] = b"R0BF"; // const V1_ ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
const TASK_QUEUE_SIZE: usize = 100; // TODO: could be bigger, but requires testing IRL
const CONCURRENT_SEGMENTS: usize = 50; // This peaks around ~4GB

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
    let task_id = task.task_id;
    let task_type: TaskType = serde_json::from_value(task.task_def)?;

    // Get ELF binary from Redis
    let elf_key = format!("elf:{}", job_id);
    let elf_data: Vec<u8> = conn.get(&elf_key).await?;

    // Get input data from Redis
    let input_key = format!("input:{}", job_id);
    let input_data: Vec<u8> = conn.get(&input_key).await?;

    // Create temporary directory for ELF and input files
    let temp_dir = tempfile::tempdir()?;
    let elf_path = temp_dir.path().join("program.elf");
    let input_path = temp_dir.path().join("input.bin");

    // Write ELF and input data to files
    tokio::fs::write(&elf_path, elf_data).await?;
    tokio::fs::write(&input_path, input_data).await?;

    // Execute task based on type
    match task_type {
        TaskType::Prove(_) => prove_task(&elf_path, &input_path).await?,
        TaskType::Join(_) => join_task(&elf_path, &input_path).await?,
        TaskType::Union(_) => union_task(&elf_path, &input_path).await?,
        TaskType::Finalize(_) => finalize_task(&elf_path, &input_path).await?,
        TaskType::Keccak(_) => keccak_task(&elf_path, &input_path).await?,
        TaskType::Executor(_) => {
            // TODO: Implement executor task logic
            ()
        },
        TaskType::Resolve(_) => {
            // TODO: Implement resolve task logic
            ()
        },
        TaskType::Snark(_) => {
            // TODO: Implement snark task logic
            ()
        },
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
