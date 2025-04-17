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
    s3::{
        S3Client, GROTH16_BUCKET_DIR, ELF_BUCKET_DIR, INPUT_BUCKET_DIR,
        PREFLIGHT_JOURNALS_BUCKET_DIR, RECEIPT_BUCKET_DIR, STARK_BUCKET_DIR,
    },
    CompressType, ExecutorReq, SnarkReq as WorkflowSnarkReq, TaskType,
};

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

const IMAGE_UPLOAD_PATH: &str = "/images/upload/:image_id";
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

const INPUT_UPLOAD_PUT_PATH: &str = "/inputs/upload/:input_id";
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

const RECEIPT_UPLOAD_PUT_PATH: &str = "/receipts/upload/:receipt_id";
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

    task_queue::enqueue_task(&mut conn, "executor", task)
        .await
        .context("Failed to create exec / init task")?;
    tracing::info!("Successfully enqueued task to 'executor' queue");

    Ok(Json(CreateSessRes { uuid: job_id.to_string() }))
}

const STARK_STATUS_PATH: &str = "/sessions/status/:job_id";
async fn stark_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<Uuid>,
) -> Result<Json<SessionStatusRes>, AppError> {
    // Get hostname from header
    let hostname = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let (exec_stats, receipt_url) = (None, None);

    Ok(Json(SessionStatusRes {
        state: Some("".into()), // TODO
        receipt_url,
        error_msg: None,    // TODO
        status: "".into(),  // TODO
        elapsed_time: None, // TODO
        stats: exec_stats,
    }))
}

const GET_STARK_PATH: &str = "/receipts/stark/receipt/:job_id";

async fn stark_download(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
) -> Result<Vec<u8>, AppError> {
    let receipt_key = format!("{RECEIPT_BUCKET_DIR}/{STARK_BUCKET_DIR}/{job_id}.bincode");
    if !state
        .s3_client
        .object_exists(&receipt_key)
        .await
        .context("Failed to check if object exists")?
    {
        return Err(AppError::ReceiptMissing(job_id.to_string()));
    }

    let receipt = state
        .s3_client
        .read_buf_from_s3(&receipt_key)
        .await
        .context("Failed to read from object store")?;

    Ok(receipt)
}

const RECEIPT_DOWNLOAD_PATH: &str = "/receipts/:job_id";
async fn receipt_download(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ReceiptDownload>, AppError> {
    let receipt_key = format!("{RECEIPT_BUCKET_DIR}/{STARK_BUCKET_DIR}/{job_id}.bincode");
    if !state
        .s3_client
        .object_exists(&receipt_key)
        .await
        .context("Failed to check if object exists")?
    {
        return Err(AppError::ReceiptMissing(job_id.to_string()));
    }

    // Get hostname from header
    let hostname = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    Ok(Json(ReceiptDownload { url: format!("http://{hostname}/receipts/stark/receipt/{job_id}") }))
}

const GET_JOURNAL_PATH: &str = "/sessions/exec_only_journal/:job_id";
async fn preflight_journal(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
) -> Result<Vec<u8>, AppError> {
    let journal_key = format!("{PREFLIGHT_JOURNALS_BUCKET_DIR}/{job_id}.bin");
    if !state
        .s3_client
        .object_exists(&journal_key)
        .await
        .context("Failed to check if object exists")?
    {
        return Err(AppError::ReceiptMissing(job_id.to_string()));
    }

    let receipt = state
        .s3_client
        .read_buf_from_s3(&journal_key)
        .await
        .context("Failed to read from object store")?;

    Ok(receipt)
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
    tracing::info!("Attempting to enqueue task to 'snark' queue");
    task_queue::enqueue_task(&mut conn, "snark", task)
        .await
        .context("Failed to create exec / init task")?;
    tracing::info!("Successfully enqueued task to 'snark' queue");

    Ok(Json(CreateSessRes { uuid: job_id.to_string() }))
}

const SNARK_STATUS_PATH: &str = "/snark/status/:job_id";
async fn groth16_status(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SnarkStatusRes>, AppError> {
    // Get hostname from header
    let hostname = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let (error_msg, output) = (None, None); // TODO
    Ok(Json(SnarkStatusRes { status: "".into(), error_msg, output }))
}

const GET_GROTH16_PATH: &str = "/receipts/groth16/receipt/:job_id";
async fn groth16_download(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
) -> Result<Vec<u8>, AppError> {
    let receipt_key = format!("{RECEIPT_BUCKET_DIR}/{GROTH16_BUCKET_DIR}/{job_id}.bincode");
    if !state
        .s3_client
        .object_exists(&receipt_key)
        .await
        .context("Failed to check if object exists")?
    {
        return Err(AppError::ReceiptMissing(job_id.to_string()));
    }

    let receipt = state
        .s3_client
        .read_buf_from_s3(&receipt_key)
        .await
        .context("Failed to read from object store")?;

    Ok(receipt)
}

pub fn app(state: Arc<AppState>) -> Router {
    // Build the router step by step
    let mut router = Router::new();

    // Add routes explicitly one by one
    router = router.route(IMAGE_UPLOAD_PATH, get(image_upload));
    router = router.route(IMAGE_UPLOAD_PATH, put(image_upload_put));
    router = router.route(INPUT_UPLOAD_PATH, get(input_upload));
    router = router.route(INPUT_UPLOAD_PUT_PATH, put(input_upload_put));
    router = router.route(RECEIPT_UPLOAD_PATH, get(receipt_upload));
    router = router.route(RECEIPT_UPLOAD_PUT_PATH, put(receipt_upload_put));
    router = router.route(STARK_PROVING_START_PATH, post(prove_stark));
    router = router.route(STARK_STATUS_PATH, get(stark_status));
    router = router.route(GET_STARK_PATH, get(stark_download));
    router = router.route(RECEIPT_DOWNLOAD_PATH, get(receipt_download));
    router = router.route(GET_JOURNAL_PATH, get(preflight_journal));
    router = router.route(SNARK_START_PATH, post(prove_groth16));
    router = router.route(SNARK_STATUS_PATH, get(groth16_status));
    router = router.route(GET_GROTH16_PATH, get(groth16_download));

    // Add the state at the end
    router.with_state(state)
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

    /// S3 / Minio bucket
    #[clap(env)]
    s3_bucket: String,

    /// S3 / Minio access key
    #[clap(env)]
    s3_access_key: String,

    /// S3 / Minio secret key
    #[clap(env)]
    s3_secret_key: String,

    /// S3 / Minio url
    #[clap(env)]
    s3_url: String,

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
    s3_client: S3Client,
}

impl AppState {
    pub async fn new(args: &Args) -> Result<Arc<Self>> {
        let redis_client =
            redis::Client::open(args.redis_url.clone())?.get_connection_manager().await?;

        let s3_client = S3Client::from_minio(
            &args.s3_url,
            &args.s3_bucket,
            &args.s3_access_key,
            &args.s3_secret_key,
        )
        .await
        .context("Failed to initialize s3 client / bucket")?;

        Ok(Arc::new(Self { redis_client: Arc::new(Mutex::new(redis_client)), s3_client }))
    }
}
