// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use anyhow::{Context, Error as AnyhowErr, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri},
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
use std::net::SocketAddr;
use std::sync::Arc;
use task_queue::Task;
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;
use workflow_common::s3::S3Client;

use async_trait::async_trait;

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

// Simplified API key extractor that just returns the default user ID
// We'll add proper authentication later
pub struct ApiKey(pub String);

impl ApiKey {
    pub fn get_user_id(&self) -> &str {
        &self.0
    }

    pub fn from_headers(headers: &axum::http::HeaderMap) -> Self {
        match headers.get("x-api-key") {
            Some(header) => match header.to_str() {
                Ok(value) => ApiKey(value.to_string()),
                Err(_) => ApiKey(USER_ID.to_string()),
            },
            None => ApiKey(USER_ID.to_string()),
        }
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

async fn image_upload(
    State(state): State<Arc<AppState>>,
    Path(image_id): Path<String>,
    uri: Uri,
) -> Result<Json<ImgUploadRes>, AppError> {
    // Extract the API key from the headers, but we don't actually need it for this endpoint
    // let api_key = ApiKey::from_headers(&parts.headers);

    tracing::info!("Handling image upload request for image_id: {}", image_id);

    // Check if image already exists in Redis
    let mut conn = state.redis_client.lock().await;
    let elf_key = format!("elf:{}", image_id);

    let exists: bool =
        conn.exists(&elf_key).await.context("Failed to check if image exists in Redis")?;

    if exists {
        tracing::warn!("Image with ID {} already exists in Redis", image_id);
        return Err(AppError::ImgAlreadyExists(image_id));
    }

    // Extract hostname from authority or use a default
    let host = uri.authority().map(|a| a.as_str()).unwrap_or("localhost");

    tracing::info!("Image ID {} is available for upload", image_id);
    Ok(Json(ImgUploadRes { url: format!("http://{host}/images/upload/{image_id}") }))
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

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route(IMAGE_UPLOAD_PATH, get(image_upload))
        .route(IMAGE_UPLOAD_PATH, put(image_upload_put))
        .with_state(state)
}

pub async fn run(args: &Args) -> Result<()> {
    let app_state = AppState::new(args).await.context("Failed to initialize AppState")?;
    // Parse the bind address
    let addr: SocketAddr = args.bind_addr.parse().context("Invalid bind address")?;

    tracing::info!("REST API listening on: {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Failed to bind TCP listener")?;

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

// The rest of the file's route handlers remain unchanged
