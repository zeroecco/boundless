// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use anyhow::{Context, Error as AnyhowErr, Result};
use axum::{
    async_trait,
    extract::{FromRequestParts, Host, Path, State, multipart},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bonsai_sdk::responses::{
    ImgUploadRes, ReceiptDownload, UploadRes,
};
use clap::Parser;
use redis::aio::ConnectionManager;
use risc0_zkvm::compute_image_id;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use task_queue::Task;
use thiserror::Error;
use uuid::Uuid;
use workflow_common::{
    s3::{
        S3Client, ELF_BUCKET_DIR, INPUT_BUCKET_DIR,
        PREFLIGHT_JOURNALS_BUCKET_DIR, RECEIPT_BUCKET_DIR, STARK_BUCKET_DIR,
    },
    CompressType, ExecutorReq, SnarkReq as WorkflowSnarkReq, TaskType,
};

mod helpers;

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

#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    BadRequest(AnyhowErr),
    TaskQueueError(task_queue::TaskQueueError),
    InternalError(String),
    Unauthorized(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::BadRequest(anyhow_err) => write!(f, "bad request: {}", anyhow_err),
            Self::TaskQueueError(task_err) => write!(f, "task queue error: {}", task_err),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
            Self::Unauthorized(msg) => write!(f, "unauthorized: {msg}"),
        }
    }
}

impl From<AnyhowErr> for ApiError {
    fn from(error: AnyhowErr) -> Self {
        ApiError::BadRequest(error)
    }
}

impl From<task_queue::TaskQueueError> for ApiError {
    fn from(error: task_queue::TaskQueueError) -> Self {
        ApiError::TaskQueueError(error)
    }
}

impl From<multipart::MultipartError> for ApiError {
    fn from(error: multipart::MultipartError) -> Self {
        ApiError::BadRequest(error.into())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        ApiError::BadRequest(error.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, err_msg) = match self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, ErrMsg::new("not_found", &msg)),
            Self::BadRequest(err) => (StatusCode::BAD_REQUEST, ErrMsg::new("bad_request", &err.to_string())),
            Self::TaskQueueError(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrMsg::new("task_queue_error", &err.to_string()),
            ),
            Self::InternalError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrMsg::new("internal_server_error", &msg),
            ),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, ErrMsg::new("unauthorized", &msg)),
        };

        (status, Json(err_msg)).into_response()
    }
}

#[derive(Debug, Error)]
pub enum JobError {
    #[error("not found")]
    NotFound,
    #[error("internal error: {0}")]
    Internal(String),
}

/// JobState represents the current state of a job
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// Job is waiting for work
    Queued,
    /// Job is currently in progress and has been assigned to a worker
    Running,
    /// Job has completed successfully with a receipt
    Done,
    /// Job has been cancelled
    Cancelled,
    /// Job has failed
    Failed,
}

impl Default for JobState {
    fn default() -> Self {
        Self::Queued
    }
}

pub struct AppState {
    redis_conn: ConnectionManager,
    s3_client: S3Client,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            redis_conn: self.redis_conn.clone(),
            s3_client: S3Client::clone_state(&self.s3_client),
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Bind address for the HTTP server
    #[arg(long, default_value = "0.0.0.0")]
    pub bind_address: String,

    /// Port to listen on
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,

    /// Timeout for HTTP requests (seconds)
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,

    /// S3 / Minio bucket
    #[clap(env, default_value = "bento")]
    pub s3_bucket: String,

    /// S3 / Minio access key
    #[clap(env, default_value = "minioadmin")]
    pub s3_access_key: String,

    /// S3 / Minio secret key
    #[clap(env, default_value = "minioadmin")]
    pub s3_secret_key: String,

    /// S3 / Minio url
    #[clap(env, default_value = "http://localhost:9000")]
    pub s3_url: String,

    /// redis connection URL
    #[clap(env, default_value = "redis://localhost")]
    pub redis_url: String,

    /// Max RAM use limit for agent, in MB
    #[clap(long, default_value_t = 16 * 1024)]
    pub max_ram_mb: i64,

    /// Executor limit, in millions of cycles
    #[clap(long, default_value_t = 100_000)]
    pub exec_cycle_limit: u64,

    /// Uploads directory for ELFs and inputs
    ///
    /// If not specified, creates temporary directory
    #[clap(short, long)]
    pub uploads_dir: Option<String>,

    /// Enable CORS (dev mode)
    #[clap(long, default_value_t = false)]
    pub cors_enable: bool,

    /// Task retries for executors
    #[clap(long, default_value_t = 0)]
    pub executor_retries: i32,

    /// Task retries for provers
    #[clap(long, default_value_t = 0)]
    pub prover_retries: i32,

    /// Task retries for snarks
    #[clap(long, default_value_t = 0)]
    pub snark_retries: i32,

    /// Redis TTL, seconds before objects expire automatically
    ///
    /// Defaults to 8 hours
    #[clap(long, default_value_t = 8 * 60 * 60)]
    pub redis_ttl: u64,
}

struct ApiKey(String);

#[async_trait]
impl<S> FromRequestParts<S> for ApiKey
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> std::result::Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrMsg::new("missing_authorization", "missing authorization header")),
                )
                    .into_response()
            })?
            .to_str()
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrMsg::new(
                        "invalid_authorization",
                        "authorization header contains invalid characters",
                    )),
                )
                    .into_response()
            })?;
        // Verify Bearer scheme with optional "Bearer " prefix for compatibility
        let prefix = if auth_header.starts_with("Bearer ") { "Bearer " } else { "" };

        let api_key = auth_header
            .strip_prefix(prefix)
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrMsg::new(
                        "invalid_api_key",
                        "authorization header must be a valid API key",
                    )),
                )
                    .into_response()
            })?
            .to_string();
        Ok(Self(api_key))
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct JobResponse {
    pub job_id: Uuid,
    pub job_state: JobState,
}

impl JobResponse {
    pub fn new(job_id: Uuid, job_state: JobState) -> Self {
        Self { job_id, job_state }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct JobStateResponse {
    pub job_id: Uuid,
    pub job_state: JobState,
    pub error: Option<String>,
}

impl JobStateResponse {
    pub fn new(job_id: Uuid, job_state: JobState, error: Option<String>) -> Self {
        Self { job_id, job_state, error }
    }
}

#[derive(Deserialize, Debug)]
struct ExecuteOptions {
    image_id: String,
    input_id: String,
    compress_type: Option<CompressType>,
    exec_cycle_limit: Option<u64>,
    assumption_receipt_ids: Option<Vec<String>>,
    execute_only: Option<bool>,
}

#[derive(Deserialize, Debug)]
struct SnarkOptions {
    receipt: String,
    compress_type: Option<CompressType>,
}

#[derive(Deserialize, Debug)]
struct PreflightOptions {
    image_id: String,
    input_id: String,
    exec_cycle_limit: Option<u64>,
    assumption_receipt_ids: Option<Vec<String>>,
}

pub async fn run_app(args: Args) -> Result<()> {
    // No need to initialize s3_client here, it will be created in the AppState

    // Create the router
    let app = create_router(&args).await?;

    // run our app with hyper, listening globally on port 8080
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", args.bind_address, args.port))
        .await
        .context("Failed to bind to port")?;
    tracing::info!("Listening on {}", listener.local_addr()?);

    // Handle graceful shutdown by waiting for either ctrl+c or sigterm
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    // Handle Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
        let _ = shutdown_tx_clone.send(());
    });

    // Handle SIGTERM
    tokio::spawn(async move {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
        let _ = shutdown_tx.send(());
    });

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(async {
            let mut rx = shutdown_rx;
            let _ = rx.recv().await;
            tracing::info!("Received shutdown, exiting...");
        })
        .await?;

    Ok(())
}

/// Create the API router
async fn create_router(args: &Args) -> Result<Router> {
    // Initialize REST API clients
    let redis_client = redis::Client::open(args.redis_url.clone())?;
    let redis_conn = redis_client.get_connection_manager().await?;

    // Define app state
    let state = Arc::new(AppState {
        redis_conn,
        s3_client: S3Client::from_minio(
            &args.s3_url,
            &args.s3_bucket,
            &args.s3_access_key,
            &args.s3_secret_key,
        )
        .await
        .context("Failed to init s3 client")?
    });

    // Build router with routes
    let mut router = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/jobs/:job_id", get(get_job))
        .route("/api/v1/receipt/:job_id", get(get_receipt))
        .route("/api/v1/journal/:job_id", get(get_journal))
        .route("/api/v1/jobs/execute", post(create_execute_task))
        .route("/api/v1/jobs/snark", post(create_snark_task))
        .route("/api/v1/jobs/preflight", post(run_preflight))
        .route("/api/v1/elf", post(upload_elf))
        .route("/api/v1/input", post(upload_input))
        .with_state(state);

    if args.cors_enable {
        router = router.layer(
            tower_http::cors::CorsLayer::new()
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any)
                .allow_origin(tower_http::cors::Any),
        );
    }

    // We'll use fixed retries instead of passing args

    Ok(router)
}

// Helper function to extract value from a multipart field
async fn read_field(field: &mut multipart::Field<'_>) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    while let Some(chunk) = field.chunk().await? {
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

async fn health_check() -> impl IntoResponse {
    "OK"
}

async fn get_receipt(
    Path(job_id): Path<Uuid>,
    _key: ApiKey,
    State(state): State<Arc<AppState>>,
    Host(host): Host,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!("GET /api/v1/receipt/{job_id}");

    let receipt_key = format!("{RECEIPT_BUCKET_DIR}/{STARK_BUCKET_DIR}/{job_id}.bincode");

    if !state.s3_client.object_exists(&receipt_key).await? {
        return Err(ApiError::NotFound(format!(
            "Receipt not found for job: {}",
            job_id
        )));
    }

    let url = format!("https://{}/api/v1/receipt/{job_id}/download", host);

    Ok(Json(ReceiptDownload {
        url,
    }))
}

async fn get_journal(
    Path(job_id): Path<Uuid>,
    _key: ApiKey,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!("GET /api/v1/journal/{job_id}");

    let journal_key = format!("{PREFLIGHT_JOURNALS_BUCKET_DIR}/{job_id}.bin");

    if !state.s3_client.object_exists(&journal_key).await? {
        return Err(ApiError::NotFound(format!(
            "Journal not found for job: {}",
            job_id
        )));
    }

    let journal_bytes = state.s3_client.read_buf_from_s3(&journal_key).await?;

    // Create owned strings to avoid reference issues
    let content_type = "application/octet-stream".to_string();
    let content_disposition = format!("attachment; filename=\"{job_id}.journal\"");

    let headers = [
        ("Content-Type", content_type),
        ("Content-Disposition", content_disposition),
    ];

    Ok((headers, journal_bytes))
}

async fn get_job(
    Path(job_id): Path<Uuid>,
    _key: ApiKey,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!("GET /api/v1/jobs/{job_id}");

    // Check if the receipt exists to determine job state
    let receipt_key = format!("{RECEIPT_BUCKET_DIR}/{STARK_BUCKET_DIR}/{job_id}.bincode");
    let journal_key = format!("{PREFLIGHT_JOURNALS_BUCKET_DIR}/{job_id}.bin");

    // Job is considered done if either:
    // 1. Receipt exists (regular execution)
    // 2. Journal exists (preflight execution)
    let receipt_exists = state.s3_client.object_exists(&receipt_key).await?;
    let journal_exists = state.s3_client.object_exists(&journal_key).await?;

    if receipt_exists || journal_exists {
        Ok(Json(JobStateResponse::new(job_id, JobState::Done, None)))
    } else {
        // For now we'll just return "queued" status but in the future this should check Redis
        // to determine the actual job state
        Ok(Json(JobStateResponse::new(job_id, JobState::Queued, None)))
    }
}

async fn create_execute_task(
    _key: ApiKey,
    State(state): State<Arc<AppState>>,
    Json(options): Json<ExecuteOptions>,
) -> Result<impl IntoResponse, ApiError> {
    // We're not using args anymore, just setting a fixed value for retries
    // For now, we'll use a fixed retry value
    let executor_retries = 0;
    tracing::info!("POST /api/v1/jobs/execute");

    let job_id = Uuid::new_v4();

    // Set up execute request
    let execute_req = ExecutorReq {
        image: options.image_id,
        input: options.input_id,
        user_id: "default".to_string(),
        exec_limit: options.exec_cycle_limit,
        compress: options.compress_type.unwrap_or(CompressType::Groth16),
        assumptions: options.assumption_receipt_ids.unwrap_or_default(),
        execute_only: options.execute_only.unwrap_or(false),
    };

    let task = Task {
        job_id,
        task_id: format!("execute:{}", job_id),
        task_def: serde_json::to_value(TaskType::Executor(execute_req))?,
        prereqs: vec![],
        max_retries: executor_retries,
    };

    let mut conn = state.redis_conn.clone();
    let queue_name = "queue:cpu";

    task_queue::enqueue_task(&mut conn, queue_name, task).await?;

    Ok(Json(JobResponse::new(job_id, JobState::Queued)))
}

async fn create_snark_task(
    _key: ApiKey,
    State(state): State<Arc<AppState>>,
    Json(options): Json<SnarkOptions>,
) -> Result<impl IntoResponse, ApiError> {
    // For now, we'll use a fixed retry value
    let snark_retries = 0;
    tracing::info!("POST /api/v1/jobs/snark");

    let job_id = Uuid::new_v4();

    // Set up snark request
    let snark_req = WorkflowSnarkReq {
        receipt: options.receipt,
        compress_type: options.compress_type.unwrap_or(CompressType::Groth16),
    };

    let task = Task {
        job_id,
        task_id: format!("snark:{}", job_id),
        task_def: serde_json::to_value(TaskType::Snark(snark_req))?,
        prereqs: vec![],
        max_retries: snark_retries,
    };

    let mut conn = state.redis_conn.clone();
    let queue_name = "queue:snark";

    task_queue::enqueue_task(&mut conn, queue_name, task).await?;

    Ok(Json(JobResponse::new(job_id, JobState::Queued)))
}

async fn run_preflight(
    _key: ApiKey,
    State(state): State<Arc<AppState>>,
    Json(options): Json<PreflightOptions>,
) -> Result<impl IntoResponse, ApiError> {
    // For now, we'll use a fixed retry value
    let executor_retries = 0;
    tracing::info!("POST /api/v1/jobs/preflight");

    let job_id = Uuid::new_v4();

    // Set up execute request with execute_only=true
    let execute_req = ExecutorReq {
        image: options.image_id,
        input: options.input_id,
        user_id: "default".to_string(),
        exec_limit: options.exec_cycle_limit,
        compress: CompressType::Groth16,
        assumptions: options.assumption_receipt_ids.unwrap_or_default(),
        execute_only: true,  // Preflight means execute only, no proving
    };

    let task = Task {
        job_id,
        task_id: format!("execute:{}", job_id),
        task_def: serde_json::to_value(TaskType::Executor(execute_req))?,
        prereqs: vec![],
        max_retries: executor_retries,
    };

    let mut conn = state.redis_conn.clone();
    let queue_name = "queue:cpu";

    task_queue::enqueue_task(&mut conn, queue_name, task).await?;

    Ok(Json(JobResponse::new(job_id, JobState::Queued)))
}

async fn upload_elf(
    _key: ApiKey,
    State(state): State<Arc<AppState>>,
    mut multipart: multipart::Multipart,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!("POST /api/v1/elf");

    let mut elf_data = Vec::new();
    let mut _file_name = String::new();

    while let Some(mut field) = multipart.next_field().await? {
        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            _file_name = field.file_name().unwrap_or("unknown.elf").to_string();
            elf_data = read_field(&mut field).await?;
        }
    }

    if elf_data.is_empty() {
        return Err(ApiError::BadRequest(anyhow::anyhow!("No ELF file found in upload")));
    }

    // Generate a unique ID for the ELF
    let elf_id = format!("{}", Uuid::new_v4());
    let elf_key = format!("{ELF_BUCKET_DIR}/{elf_id}");

    // Compute image ID before uploading
    let image_id = compute_image_id(&elf_data)?;

    // Upload to S3
    state.s3_client.write_buf_to_s3(&elf_key, elf_data).await?;
    // Format Digest as hex string
    let image_id_hex = format!("{}", image_id);

    // Create response with available ImgUploadRes fields (url only)
    let url = format!("/api/v1/elf/{elf_id}");
    // Return image_id_hex in the logs
    tracing::info!("Uploaded ELF with image ID: {image_id_hex}");
    Ok(Json(ImgUploadRes { url }))
}

async fn upload_input(
    _key: ApiKey,
    State(state): State<Arc<AppState>>,
    mut multipart: multipart::Multipart,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!("POST /api/v1/input");

    let mut input_data = Vec::new();
    let mut _file_name = String::new();

    while let Some(mut field) = multipart.next_field().await? {
        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            _file_name = field.file_name().unwrap_or("unknown.input").to_string();
            input_data = read_field(&mut field).await?;
        }
    }

    if input_data.is_empty() {
        return Err(ApiError::BadRequest(anyhow::anyhow!("No input file found in upload")));
    }

    // Generate a unique ID for the input
    let input_id = format!("{}", Uuid::new_v4());
    let input_key = format!("{INPUT_BUCKET_DIR}/{input_id}");

    // Upload to S3
    state.s3_client.write_buf_to_s3(&input_key, input_data).await?;

    // Create response with available UploadRes fields (url and uuid)
    let url = format!("/api/v1/input/{input_id}");
    let uuid = input_id;
    Ok(Json(UploadRes { url, uuid }))
}
