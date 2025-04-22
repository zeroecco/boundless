// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use anyhow::{Context, Error as AnyhowErr, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Path, State},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};

use bonsai_sdk::responses::{
    CreateSessRes, ImgUploadRes, ProofReq, ReceiptDownload, SessionStatusRes, SnarkReq,
    SnarkStatusRes, UploadRes,
};
use clap::Parser;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use risc0_zkvm::compute_image_id;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use task_queue::Task;
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;
use workflow_common::{
    CompressType, ExecutorReq, SnarkReq as WorkflowSnarkReq, TaskType,
};

// TaskEntry is the format expected by the workflow crate's worker
#[derive(Debug, Deserialize, Serialize)]
pub struct Task {
    pub job_id: Uuid,
    pub task_id: String,
    pub task_def: serde_json::Value,
    pub prereqs: Vec<String>,
    pub max_retries: i32,
    pub data: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrMsg {
    pub r#type: String,
    pub msg: String,
}
impl ErrMsg {
    pub fn new(r#type: &str, msg: &str) -> Self {
        Self { r#type: r#type.into(), msg: msg.into() }
    }
}
impl std::fmt::Display for ErrMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error_type: {} msg: {}", self.r#type, self.msg)
    }
}

// TODO: Add authn/z to get a userID
const USER_ID: &str = "default_user";
const MAX_UPLOAD_SIZE: usize = 250 * 1024 * 1024; // 250 mb

const IMAGE_UPLOAD_PATH: &str = "/images/upload/{image_id}";
async fn image_upload(
    State(state): State<Arc<AppState>>,
    Path(image_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ImgUploadRes>, AppError> {
    tracing::info!("Handling image upload request for image_id: {}", image_id);

    // Get hostname from header
    let hostname = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    // Check if image already exists in Redis
    let mut conn = state.redis_client.lock().await;
    let elf_key = format!("elf:{}", image_id);

    let exists: bool =
        conn.exists(&elf_key).await.context("Failed to check if image exists in Redis")?;

    if exists {
        tracing::warn!("Image with ID {} already exists in Redis", image_id);
        return Err(AppError::ImgAlreadyExists(image_id));
    }

    tracing::info!("Image ID {} is available for upload", image_id);
    Ok(Json(ImgUploadRes { url: format!("http://{hostname}/images/upload/{image_id}") }))
}

async fn image_upload_put(
    State(state): State<Arc<AppState>>,
    Path(image_id): Path<String>,
    body: Body,
) -> Result<(), AppError> {
    tracing::info!("Starting ELF upload for image_id: {}", image_id);
    let body_bytes =
        to_bytes(body, MAX_UPLOAD_SIZE).await.context("Failed to convert body to bytes")?;
    tracing::debug!("Received {} bytes for ELF", body_bytes.len());

    // Validate ELF data
    if body_bytes.len() < 4 {
        tracing::error!("ELF data is too small: {} bytes", body_bytes.len());
        return Err(AppError::ImageInvalid(format!(
            "ELF data is too small: {} bytes",
            body_bytes.len()
        )));
    }

    // Check magic bytes for standard ELF or RISC0 format
    let magic = &body_bytes[0..4];
    tracing::debug!("ELF magic bytes: {:?}", magic);

    let is_elf = magic == b"\x7fELF" || magic == b"R0BF";
    if !is_elf {
        tracing::error!("Invalid ELF magic bytes: {:?}", magic);
        return Err(AppError::ImageInvalid("Invalid ELF magic bytes".to_string()));
    }
    tracing::info!("ELF binary appears valid with magic: {:?}", magic);

    let comp_img_id =
        compute_image_id(&body_bytes).context("Failed to compute image id")?.to_string();
    if comp_img_id != image_id {
        tracing::error!("Image ID mismatch: requested={}, computed={}", image_id, comp_img_id);
        return Err(AppError::ImageIdMismatch(image_id, comp_img_id));
    }
    tracing::info!("Image ID verified: {}", image_id);

    let mut conn = state.redis_client.lock().await;
    let elf_key = format!("elf:{}", image_id);

    // Store as raw bytes, don't manipulate the data
    if let Err(e) = conn.set_ex::<_, _, ()>(&elf_key, body_bytes.to_vec(), 60 * 60 * 2).await {
        tracing::error!("Failed to store ELF in Redis: {}", e);
        return Err(AppError::InternalErr(anyhow::anyhow!("Failed to store ELF: {}", e)));
    }

    tracing::info!("Successfully stored ELF in Redis with key: {}", elf_key);

    // Verify we can read it back
    let verification: Result<Vec<u8>, _> = conn.get(&elf_key).await;
    match verification {
        Ok(data) => {
            if data.len() != body_bytes.len() {
                tracing::error!(
                    "Verification failed: size mismatch. Original: {}, Retrieved: {}",
                    body_bytes.len(),
                    data.len()
                );
            } else {
                tracing::info!("Verification successful: read back {} bytes", data.len());
            }
        }
        Err(e) => {
            tracing::error!("Verification failed: couldn't read back ELF data: {}", e);
        }
    }

    Ok(())
}

const INPUT_UPLOAD_PATH: &str = "/inputs/upload";
async fn input_upload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<UploadRes>, AppError> {
    let input_id = Uuid::new_v4();
    tracing::info!("Generated new input_id: {}", input_id);

    // Get hostname from header
    let hostname = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    // Check if input already exists in Redis (should never happen with UUID)
    let mut conn = state.redis_client.lock().await;
    let input_key = format!("input:{}", input_id);

    let exists: bool =
        conn.exists(&input_key).await.context("Failed to check if input exists in Redis")?;

    if exists {
        tracing::warn!("Input with ID {} already exists in Redis (unlikely with UUID)", input_id);
        return Err(AppError::InputAlreadyExists(input_id.to_string()));
    }

    tracing::info!("Input ID {} is available for upload", input_id);
    Ok(Json(UploadRes {
        url: format!("http://{hostname}/inputs/upload/{input_id}"),
        uuid: input_id.to_string(),
    }))
}

const INPUT_UPLOAD_PUT_PATH: &str = "/inputs/upload/{input_id}";
async fn input_upload_put(
    State(state): State<Arc<AppState>>,
    Path(input_id): Path<String>,
    body: Body,
) -> Result<(), AppError> {
    tracing::info!("Starting input upload for input_id: {}", input_id);
    let body_bytes =
        to_bytes(body, MAX_UPLOAD_SIZE).await.context("Failed to convert body to bytes")?;
    tracing::debug!("Received {} bytes for input", body_bytes.len());

    let mut conn = state.redis_client.lock().await;
    let input_key = format!("input:{}", input_id);
    conn.set_ex(&input_key, body_bytes.to_vec(), 60 * 60 * 2)
        .await
        .context("Failed to store input in Redis")?;
    tracing::info!("Successfully stored input in Redis with key: {}", input_key);

    Ok(())
}

const RECEIPT_UPLOAD_PATH: &str = "/receipts/upload";
async fn receipt_upload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<UploadRes>, AppError> {
    let receipt_id = Uuid::new_v4();
    tracing::info!("Generated new receipt_id: {}", receipt_id);

    // Get hostname from header
    let hostname = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    // Check if receipt already exists in Redis (should never happen with UUID)
    let mut conn = state.redis_client.lock().await;
    let receipt_key = format!("receipt:{}", receipt_id);

    let exists: bool =
        conn.exists(&receipt_key).await.context("Failed to check if receipt exists in Redis")?;

    if exists {
        tracing::warn!(
            "Receipt with ID {} already exists in Redis (unlikely with UUID)",
            receipt_id
        );
        return Err(AppError::ReceiptAlreadyExists(receipt_id.to_string()));
    }

    tracing::info!("Receipt ID {} is available for upload", receipt_id);
    Ok(Json(UploadRes {
        url: format!("http://{hostname}/receipts/upload/{receipt_id}"),
        uuid: receipt_id.to_string(),
    }))
}

const RECEIPT_UPLOAD_PUT_PATH: &str = "/receipts/upload/{receipt_id}";
async fn receipt_upload_put(
    State(state): State<Arc<AppState>>,
    Path(receipt_id): Path<String>,
    body: Body,
) -> Result<(), AppError> {
    let body_bytes =
        to_bytes(body, MAX_UPLOAD_SIZE).await.context("Failed to convert body to bytes")?;

    let mut conn = state.redis_client.lock().await;
    let receipt_key = format!("receipt:{}", receipt_id);
    conn.set_ex(&receipt_key, body_bytes.to_vec(), 60 * 60 * 2)
        .await
        .context("Failed to store receipt in Redis")?;

    Ok(())
}

// Stark routes

const STARK_PROVING_START_PATH: &str = "/sessions/create";
async fn prove_stark(
    State(state): State<Arc<AppState>>,
    Json(start_req): Json<ProofReq>,
) -> Result<Json<CreateSessRes>, AppError> {
    tracing::info!(
        "Starting STARK proof request for image: {}, input: {}",
        start_req.img,
        start_req.input
    );

    // Get ELF and input data from Redis first
    let mut conn = state.redis_client.lock().await;

    let elf_key = format!("elf:{}", start_req.img);
    tracing::info!("Fetching ELF data from Redis with key: {}", elf_key);
    let elf_data: Vec<u8> =
        conn.get(&elf_key).await.context("Failed to get ELF data from Redis")?;
    tracing::debug!("Retrieved {} bytes of ELF data", elf_data.len());

    let input_key = format!("input:{}", start_req.input);
    tracing::info!("Fetching input data from Redis with key: {}", input_key);
    let input_data: Vec<u8> =
        conn.get(&input_key).await.context("Failed to get input data from Redis")?;
    tracing::debug!("Retrieved {} bytes of input data", input_data.len());

    let job_id = Uuid::new_v4();
    tracing::info!("Generated new job_id: {}", job_id);

    // Store data with job_id keys
    let job_elf_key = format!("elf:{}", job_id);
    tracing::info!("Storing ELF data with job key: {}", job_elf_key);
    conn.set_ex(&job_elf_key, elf_data, 60 * 60 * 2)
        .await
        .context("Failed to store ELF with job_id")?;

    let job_input_key = format!("input:{}", job_id);
    tracing::info!("Storing input data with job key: {}", job_input_key);
    conn.set_ex(&job_input_key, input_data, 60 * 60 * 2)
        .await
        .context("Failed to store input with job_id")?;

    // Initialize job status in Redis
    let status_key = format!("status:{}", job_id);
    conn.set(&status_key, "pending")
        .await
        .context("Failed to initialize job status")?;

    // Store start time
    let start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let start_time_key = format!("start_time:{}", job_id);
    conn.set(&start_time_key, start_time.to_string())
        .await
        .context("Failed to store job start time")?;

    let task_def = serde_json::to_value(TaskType::Executor(ExecutorReq {
        image: start_req.img,
        input: start_req.input,
        user_id: USER_ID.to_string(),
        assumptions: start_req.assumptions,
        execute_only: start_req.execute_only,
        compress: workflow_common::CompressType::None,
        exec_limit: start_req.exec_cycle_limit,
    }))
    .context("Failed to serialize ExecutorReq")?;
    tracing::debug!("Created task definition: {:?}", task_def);

    let task = Task {
        job_id,
        task_id: "executor".to_string(),
        task_def,
        prereqs: vec![],
        max_retries: 3,
        data: vec![],
    };
    tracing::info!("Created task with job_id: {}", job_id);

    // Initialize task status
    let task_status_key = format!("task_status:{}:executor", job_id);
    conn.set(&task_status_key, "pending")
        .await
        .context("Failed to initialize task status")?;

    // Enqueue the task
    let queue_key = format!("queue:executor");
    let task_json = serde_json::to_string(&task)
        .context("Failed to serialize task to JSON")?;
    conn.rpush(&queue_key, task_json)
        .await
        .context("Failed to push task to Redis queue")?;
    tracing::info!("Successfully enqueued task to 'executor' queue");

    Ok(Json(CreateSessRes { uuid: job_id.to_string() }))
}

const STARK_STATUS_PATH: &str = "/sessions/status/{job_id}";
async fn stark_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<Uuid>,
) -> Result<Json<SessionStatusRes>, AppError> {
    tracing::info!("Checking status for STARK job: {}", job_id);

    let mut conn = state.redis_client.lock().await;

    // Get job status from Redis
    let status_key = format!("status:{}", job_id);
    let status: Option<String> = conn.get(&status_key).await.ok();

    let status = status.unwrap_or_else(|| "unknown".to_string());
    tracing::debug!("Job {} status: {}", job_id, status);

    // Check if we have a result for completed jobs
    let receipt_url = if status == "completed" {
        // Generate download URL
        let hostname = headers.get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");

        Some(format!("http://{}/receipts/stark/receipt/{}", hostname, job_id))
    } else {
        None
    };

    // Check for multiple possible error locations
    let mut error_msg = None;
    if status == "failed" {
        // Check direct error key
        let error_key = format!("error:{}", job_id);
        if let Ok(Some(msg)) = conn.get::<_, Option<String>>(&error_key).await {
            tracing::debug!("Found error message in error:{} key: {}", job_id, msg);
            error_msg = Some(msg);
        } else {
            // Check workflow error key
            let workflow_error_key = format!("workflow:error:{}", job_id);
            if let Ok(Some(msg)) = conn.get::<_, Option<String>>(&workflow_error_key).await {
                tracing::debug!("Found error message in workflow:error:{} key: {}", job_id, msg);
                error_msg = Some(msg);
            } else {
                // Check executor error key
                let exec_error_key = format!("executor:error:{}", job_id);
                if let Ok(Some(msg)) = conn.get::<_, Option<String>>(&exec_error_key).await {
                    tracing::debug!("Found error message in executor:error:{} key: {}", job_id, msg);
                    error_msg = Some(msg);
                } else {
                    // Default error message if none found
                    tracing::debug!("No specific error message found for job {}", job_id);
                    error_msg = Some("Task failed with unknown error".to_string());
                }
            }
        }
    }

    // Get job statistics if available
    let exec_stats = if status == "completed" {
        let stats_key = format!("stats:{}", job_id);
        match conn.get::<_, Option<String>>(&stats_key).await {
            Ok(Some(stats_json)) => serde_json::from_str(&stats_json).ok(),
            _ => None,
        }
    } else {
        None
    };

    // Calculate elapsed time
    let elapsed_time = match conn.get::<_, Option<String>>(&format!("start_time:{}", job_id)).await {
        Ok(Some(start_time)) => {
            if let Ok(start) = start_time.parse::<u64>() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                Some((now - start) as f64)
            } else {
                None
            }
        },
        _ => None,
    };

    // Check queue for pending tasks related to this job
    let mut progress_info = String::new();

    if status == "pending" || status == "processing" {
        // Check number of tasks in queues
        for queue_name in &["executor", "prove", "join"] {
            let queue_key = format!("queue:{}", queue_name);
            if let Ok(len) = conn.llen::<_, i64>(&queue_key).await {
                if len > 0 {
                    progress_info.push_str(&format!("{} tasks in {} queue. ", len, queue_name));
                }
            }
        }

        // Get task-specific status
        for task_type in &["executor", "prove", "join"] {
            let task_status_key = format!("task_status:{}:{}", job_id, task_type);
            if let Ok(Some(task_status)) = conn.get::<_, Option<String>>(&task_status_key).await {
                progress_info.push_str(&format!("{} task status: {}. ", task_type, task_status));
            }
        }

        if progress_info.is_empty() {
            progress_info = format!("Job {} is {}", job_id, status);
        }
    } else if status == "completed" {
        progress_info = "Job completed successfully".to_string();
    } else if status == "failed" {
        if let Some(err) = &error_msg {
            progress_info = format!("Job failed: {}", err);
        } else {
            progress_info = "Job failed with unknown error".to_string();
        }
    } else {
        progress_info = "Job status unknown".to_string();
    }

    Ok(Json(SessionStatusRes {
        state: Some(status.clone()),
        receipt_url,
        error_msg,
        status: progress_info,
        elapsed_time,
        stats: exec_stats,
    }))
}

const GET_STARK_PATH: &str = "/receipts/stark/receipt/{job_id}";

async fn stark_download(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
) -> Result<Vec<u8>, AppError> {
    tracing::info!("Downloading STARK receipt for job: {}", job_id);

    let mut conn = state.redis_client.lock().await;

    // Check if job has completed
    let status_key = format!("status:{}", job_id);
    let status: Option<String> = conn.get(&status_key).await.ok();

    if status != Some("completed".to_string()) {
        tracing::error!("Cannot download receipt for job {} with status {:?}", job_id, status);
        return Err(AppError::ReceiptMissing(job_id.to_string()));
    }

    // Get result data
    let result_key = format!("result:{}", job_id);
    let exists: bool = conn.exists(&result_key).await.unwrap_or(false);

    if !exists {
        tracing::error!("Receipt data not found for job {}", job_id);
        return Err(AppError::ReceiptMissing(job_id.to_string()));
    }

    match conn.get::<_, Vec<u8>>(&result_key).await {
        Ok(data) => {
            tracing::info!("Successfully retrieved STARK receipt data ({} bytes)", data.len());
            Ok(data)
        },
        Err(e) => {
            tracing::error!("Failed to retrieve receipt data for job {}: {}", job_id, e);
            Err(AppError::InternalErr(anyhow::anyhow!("Failed to retrieve receipt: {}", e)))
        }
    }
}

const RECEIPT_DOWNLOAD_PATH: &str = "/receipts/{job_id}";
async fn receipt_download(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ReceiptDownload>, AppError> {
    tracing::info!("Generating receipt download URL for job: {}", job_id);

    let mut conn = state.redis_client.lock().await;

    // Check job status
    let status_key = format!("status:{}", job_id);
    let status: Option<String> = conn.get(&status_key).await.ok();

    // If job failed, return error with the error message
    if status == Some("failed".to_string()) {
        // Try to get the error message
        let error_message = {
            // Check multiple possible error locations
            let error_key = format!("error:{}", job_id);
            if let Ok(Some(msg)) = conn.get::<_, Option<String>>(&error_key).await {
                msg
            } else {
                let workflow_error_key = format!("workflow:error:{}", job_id);
                if let Ok(Some(msg)) = conn.get::<_, Option<String>>(&workflow_error_key).await {
                    msg
                } else {
                    let exec_error_key = format!("executor:error:{}", job_id);
                    if let Ok(Some(msg)) = conn.get::<_, Option<String>>(&exec_error_key).await {
                        msg
                    } else {
                        "Task failed with unknown error".to_string()
                    }
                }
            }
        };

        tracing::error!("Cannot generate download URL for failed job {}: {}", job_id, error_message);
        return Err(AppError::ReceiptMissing(format!("Job failed: {}", error_message)));
    }

    // If job is not completed yet, return error
    if status != Some("completed".to_string()) {
        tracing::error!("Cannot generate download URL for job {} with status {:?}", job_id, status);
        return Err(AppError::ReceiptMissing(job_id.to_string()));
    }

    // Verify that result exists
    let result_key = format!("result:{}", job_id);
    let exists: bool = conn.exists(&result_key).await.unwrap_or(false);

    if !exists {
        tracing::error!("Receipt data not found for job {}", job_id);
        return Err(AppError::ReceiptMissing(job_id.to_string()));
    }

    // Get hostname from header
    let hostname = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    // Generate download URL
    let url = format!("http://{}/receipts/stark/receipt/{}", hostname, job_id);

    tracing::info!("Generated receipt download URL: {}", url);
    Ok(Json(ReceiptDownload { url }))
}

const GET_JOURNAL_PATH: &str = "/sessions/exec_only_journal/{job_id}";
async fn preflight_journal(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
) -> Result<Vec<u8>, AppError> {
    tracing::info!("Retrieving execution journal for job: {}", job_id);

    let mut conn = state.redis_client.lock().await;

    // Check job status
    let status_key = format!("status:{}", job_id);
    let status: Option<String> = conn.get(&status_key).await.ok();

    // For preflight, we may need journal data even if the job is still in progress or failed
    // Try to get the journal data regardless of status

    // Get journal data from Redis
    let journal_key = format!("journal:{}", job_id);
    let exists: bool = conn.exists(&journal_key).await.unwrap_or(false);

    if !exists {
        // If journal doesn't exist but we have an error, include error info in response
        if status == Some("failed".to_string()) {
            let error_key = format!("error:{}", job_id);
            if let Ok(Some(error_msg)) = conn.get::<_, Option<String>>(&error_key).await {
                tracing::warn!("Job failed with error: {}", error_msg);
                // Return a special error format that includes the error message
                return Err(AppError::JournalMissing(format!("Job failed: {}", error_msg)));
            }
        }

        tracing::error!("Journal not found for job {} with status {:?}", job_id, status);
        return Err(AppError::JournalMissing(job_id.to_string()));
    }

    match conn.get::<_, Vec<u8>>(&journal_key).await {
        Ok(data) => {
            tracing::info!("Successfully retrieved journal data ({} bytes)", data.len());
            Ok(data)
        },
        Err(e) => {
            tracing::error!("Failed to retrieve journal data for job {}: {}", job_id, e);
            Err(AppError::InternalErr(anyhow::anyhow!("Failed to retrieve journal: {}", e)))
        }
    }
}

// Snark routes

const SNARK_START_PATH: &str = "/snark/create";
async fn prove_groth16(
    State(state): State<Arc<AppState>>,
    Json(start_req): Json<SnarkReq>,
) -> Result<Json<CreateSessRes>, AppError> {
    tracing::info!("Starting Groth16 proof request for receipt: {}", start_req.session_id);

    let task_def = serde_json::to_value(TaskType::Snark(WorkflowSnarkReq {
        receipt: start_req.session_id,
        compress_type: CompressType::Groth16,
    }))
    .context("Failed to serialize ExecutorReq")?;
    tracing::debug!("Created task definition: {:?}", task_def);

    let job_id = Uuid::new_v4();
    let task = Task {
        job_id,
        task_id: "snark".to_string(),
        task_def,
        prereqs: vec![],
        max_retries: 3,
        data: vec![],
    };
    tracing::info!("Created task with job_id: {}", job_id);

    let mut conn = state.redis_client.lock().await;

    // Initialize job status in Redis
    let status_key = format!("status:{}", job_id);
    conn.set(&status_key, "pending")
        .await
        .context("Failed to initialize job status")?;

    // Store start time
    let start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let start_time_key = format!("start_time:{}", job_id);
    conn.set(&start_time_key, start_time.to_string())
        .await
        .context("Failed to store job start time")?;

    // Initialize task status
    let task_status_key = format!("task_status:{}:snark", job_id);
    conn.set(&task_status_key, "pending")
        .await
        .context("Failed to initialize task status")?;

    // Enqueue the task
    tracing::info!("Attempting to enqueue task to 'snark' queue");
    let queue_key = format!("queue:snark");
    let task_json = serde_json::to_string(&task)
        .context("Failed to serialize task to JSON")?;
    conn.rpush(&queue_key, task_json)
        .await
        .context("Failed to push task to Redis queue")?;
    tracing::info!("Successfully enqueued task to 'snark' queue");

    Ok(Json(CreateSessRes { uuid: job_id.to_string() }))
}

const SNARK_STATUS_PATH: &str = "/snark/status/{job_id}";
async fn groth16_status(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SnarkStatusRes>, AppError> {
    tracing::info!("Checking status for SNARK job: {}", job_id);

    let mut conn = state.redis_client.lock().await;

    // Get job status from Redis
    let status_key = format!("status:{}", job_id);
    let status: Option<String> = conn.get(&status_key).await.ok();

    let status = status.unwrap_or_else(|| "unknown".to_string());
    tracing::debug!("SNARK job {} status: {}", job_id, status);

    // Check for multiple possible error locations
    let mut error_msg = None;
    if status == "failed" {
        // Check direct error key
        let error_key = format!("error:{}", job_id);
        if let Ok(Some(msg)) = conn.get::<_, Option<String>>(&error_key).await {
            tracing::debug!("Found error message in error:{} key: {}", job_id, msg);
            error_msg = Some(msg);
        } else {
            // Check workflow error key
            let workflow_error_key = format!("workflow:error:{}", job_id);
            if let Ok(Some(msg)) = conn.get::<_, Option<String>>(&workflow_error_key).await {
                tracing::debug!("Found error message in workflow:error:{} key: {}", job_id, msg);
                error_msg = Some(msg);
            } else {
                // Check snark error key
                let snark_error_key = format!("snark:error:{}", job_id);
                if let Ok(Some(msg)) = conn.get::<_, Option<String>>(&snark_error_key).await {
                    tracing::debug!("Found error message in snark:error:{} key: {}", job_id, msg);
                    error_msg = Some(msg);
                } else {
                    // Default error message if none found
                    tracing::debug!("No specific error message found for SNARK job {}", job_id);
                    error_msg = Some("SNARK task failed with unknown error".to_string());
                }
            }
        }
    }

    // Check if we have a result
    let output = if status == "completed" {
        // Generate download URL
        let hostname = headers.get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");

        Some(format!("http://{}/receipts/groth16/receipt/{}", hostname, job_id))
    } else {
        None
    };

    // Add progress information to status
    let mut status_with_progress = status.clone();
    if status == "pending" || status == "processing" {
        // Check task-specific status
        let task_status_key = format!("task_status:{}:snark", job_id);
        if let Ok(Some(task_status)) = conn.get::<_, Option<String>>(&task_status_key).await {
            status_with_progress = format!("{} - SNARK task: {}", status, task_status);
        }

        // Check queue length
        let queue_key = "queue:snark";
        if let Ok(len) = conn.llen::<_, i64>(queue_key).await {
            if len > 0 {
                status_with_progress.push_str(&format!(". {} tasks in queue", len));
            }
        }

        // Add elapsed time if available
        if let Ok(Some(start_time)) = conn.get::<_, Option<String>>(&format!("start_time:{}", job_id)).await {
            if let Ok(start) = start_time.parse::<u64>() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                status_with_progress.push_str(&format!(". Running for {} seconds", now - start));
            }
        }
    } else if status == "completed" {
        status_with_progress = "completed - SNARK proof generation successful".to_string();
    } else if status == "failed" {
        if let Some(err) = &error_msg {
            status_with_progress = format!("failed - SNARK proof generation failed: {}", err);
        } else {
            status_with_progress = "failed - SNARK proof generation failed with unknown error".to_string();
        }
    }

    Ok(Json(SnarkStatusRes {
        status: status_with_progress,
        error_msg,
        output
    }))
}

const GET_GROTH16_PATH: &str = "/receipts/groth16/receipt/{job_id}";
async fn groth16_download(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
) -> Result<Vec<u8>, AppError> {
    tracing::info!("Downloading Groth16 proof for job: {}", job_id);

    let mut conn = state.redis_client.lock().await;

    // Check if job has completed
    let status_key = format!("status:{}", job_id);
    let status: Option<String> = conn.get(&status_key).await.ok();

    if status != Some("completed".to_string()) {
        tracing::error!("Cannot download Groth16 proof for job {} with status {:?}", job_id, status);
        return Err(AppError::ReceiptMissing(job_id.to_string()));
    }

    // Get result data
    let result_key = format!("result:{}", job_id);
    let exists: bool = conn.exists(&result_key).await.unwrap_or(false);

    if !exists {
        tracing::error!("Groth16 proof data not found for job {}", job_id);
        return Err(AppError::ReceiptMissing(job_id.to_string()));
    }

    match conn.get::<_, Vec<u8>>(&result_key).await {
        Ok(data) => {
            tracing::info!("Successfully retrieved Groth16 proof data ({} bytes)", data.len());
            Ok(data)
        },
        Err(e) => {
            tracing::error!("Failed to retrieve Groth16 proof data for job {}: {}", job_id, e);
            Err(AppError::InternalErr(anyhow::anyhow!("Failed to retrieve Groth16 proof: {}", e)))
        }
    }
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        // Image routes - combine GET and PUT handlers
        .route(IMAGE_UPLOAD_PATH,
               get(image_upload)
               .put(image_upload_put))
        // Input routes
        .route(INPUT_UPLOAD_PATH, get(input_upload))
        .route(INPUT_UPLOAD_PUT_PATH, put(input_upload_put))
        // Receipt routes
        .route(RECEIPT_UPLOAD_PATH, get(receipt_upload))
        .route(RECEIPT_UPLOAD_PUT_PATH, put(receipt_upload_put))
        // STARK routes
        .route(STARK_PROVING_START_PATH, post(prove_stark))
        .route(STARK_STATUS_PATH, get(stark_status))
        .route(GET_STARK_PATH, get(stark_download))
        // Other routes
        .route(RECEIPT_DOWNLOAD_PATH, get(receipt_download))
        .route(GET_JOURNAL_PATH, get(preflight_journal))
        // SNARK routes
        .route(SNARK_START_PATH, post(prove_groth16))
        .route(SNARK_STATUS_PATH, get(groth16_status))
        .route(GET_GROTH16_PATH, get(groth16_download))
        .with_state(state)
}

pub async fn run(args: &Args) -> Result<()> {
    let app_state = AppState::new(args).await.context("Failed to initialize AppState")?;
    let listener = tokio::net::TcpListener::bind(&args.bind_addr)
        .await
        .context("Failed to bind a TCP listener")?;

    tracing::info!("REST API listening on: {}", args.bind_addr);
    axum::serve(listener, self::app(app_state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("REST API service failed")?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("the image name is invalid: {0}")]
    ImageInvalid(String),

    #[error("The provided imageid already exists: {0}")]
    ImgAlreadyExists(String),

    #[error("The image id does not match the computed id, req: {0} comp: {1}")]
    ImageIdMismatch(String, String),

    #[error("The provided inputid already exists: {0}")]
    InputAlreadyExists(String),

    #[error("The provided receiptid already exists: {0}")]
    ReceiptAlreadyExists(String),

    #[error("receipt does not exist: {0}")]
    ReceiptMissing(String),

    #[error("preflight journal does not exist: {0}")]
    JournalMissing(String),

    #[error("internal error")]
    InternalErr(AnyhowErr),
}

impl AppError {
    fn type_str(&self) -> String {
        match self {
            Self::ImageInvalid(_) => "ImageInvalid",
            Self::ImgAlreadyExists(_) => "ImgAlreadyExists",
            Self::ImageIdMismatch(_, _) => "ImageIdMismatch",
            Self::InputAlreadyExists(_) => "InputAlreadyExists",
            Self::ReceiptAlreadyExists(_) => "ReceiptAlreadyExists",
            Self::ReceiptMissing(_) => "ReceiptMissing",
            Self::JournalMissing(_) => "JournalMissing",
            Self::InternalErr(_) => "InternalErr",
        }
        .into()
    }
}

impl From<AnyhowErr> for AppError {
    fn from(err: AnyhowErr) -> Self {
        Self::InternalErr(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = match self {
            Self::ImageInvalid(_) | Self::ImageIdMismatch(_, _) => StatusCode::BAD_REQUEST,
            Self::ImgAlreadyExists(_)
            | Self::InputAlreadyExists(_)
            | Self::ReceiptAlreadyExists(_) => StatusCode::NO_CONTENT,
            Self::ReceiptMissing(_) | Self::JournalMissing(_) => StatusCode::NOT_FOUND,
            Self::InternalErr(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        match self {
            Self::ImgAlreadyExists(_) => tracing::warn!("api warn, code: {code}, {self:?}"),
            _ => tracing::error!("api error, code {code}: {self:?}"),
        }

        (code, Json(ErrMsg { r#type: self.type_str(), msg: self.to_string() })).into_response()
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Bind address for REST api
    #[clap(long, default_value = "0.0.0.0:8080")]
    bind_addr: String,

    /// Redis URL
    #[clap(env)]
    redis_url: String,

    /// Executor timeout in seconds
    #[clap(long, default_value_t = 4 * 60 * 60)]
    exec_timeout: i32,

    /// Executor retries
    #[clap(long, default_value_t = 0)]
    exec_retries: i32,

    /// Snark timeout in seconds
    #[clap(long, default_value_t = 60 * 2)]
    snark_timeout: i32,

    /// Snark retries
    #[clap(long, default_value_t = 0)]
    snark_retries: i32,
}

pub struct AppState {
    redis_client: Arc<Mutex<ConnectionManager>>,
}

impl AppState {
    pub async fn new(args: &Args) -> Result<Arc<Self>> {
        let redis_client =
            redis::Client::open(args.redis_url.clone())?.get_connection_manager().await?;

        Ok(Arc::new(Self { redis_client: Arc::new(Mutex::new(redis_client))}))
    }
}
