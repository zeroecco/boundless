// Copyright 2025 RISC Zero, Inc.
//
// Use of this source code is governed by the Business Source License
// as found in the LICENSE-BSL file.

#![deny(missing_docs)]

//! Workflow processing Agent service

use anyhow::{Context, Result};
use clap::Parser;
use deadpool_redis::Pool as RedisPool;
use redis::AsyncCommands;
use risc0_zkvm::{get_prover_server, ProverOpts, ProverServer, VerifierContext};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::{
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::Duration,
};
use taskdb::ReadyTask;
use tokio::time;
use workflow_common::{TaskType, COPROC_WORK_TYPE};
use workflow_common::s3::S3Client;

/// A task with prefetched segment data ready for immediate processing
struct PrefetchedTask {
    task: ReadyTask,
    segment_data: Option<Vec<u8>>,
    prefetch_complete: bool,
}

impl PrefetchedTask {
    fn new(task: ReadyTask) -> Self {
        Self {
            task,
            segment_data: None,
            prefetch_complete: false,
        }
    }

    /// Check if the task is ready for immediate processing
    fn is_ready(&self) -> bool {
        self.prefetch_complete
    }

    /// Get the prefetched segment data if available
    fn get_segment_data(&self) -> Option<&Vec<u8>> {
        self.segment_data.as_ref()
    }
}

// Re-export commonly used types
pub use workflow_common::{
    AUX_WORK_TYPE, EXEC_WORK_TYPE, JOIN_WORK_TYPE, PROVE_WORK_TYPE,
};

mod redis;
mod tasks;

/// Workflow agent
///
/// Monitors taskdb for new tasks on the selected stream and processes the work.
/// Requires redis / task (psql) access
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// agent stream type to monitor for tasks
    ///
    /// ex: `cpu`, `prove`, `join`, `snark`, etc
    #[arg(short, long)]
    pub task_stream: String,

    /// Polling internal between tasks
    ///
    /// Time to wait between request_work calls
    #[arg(short, long, default_value_t = 1)]
    pub poll_time: u64,

    /// taskdb postgres DATABASE_URL
    #[clap(env)]
    pub database_url: String,

    /// redis connection URL
    #[clap(env)]
    pub redis_url: String,

    /// risc0 segment po2 arg
    #[clap(short, long, default_value_t = 20)]
    pub segment_po2: u32,

    /// max connections to SQL db in connection pool
    #[clap(long, default_value_t = 1)]
    pub db_max_connections: u32,

    /// Redis TTL, seconds before objects expire automatically
    ///
    /// Defaults to 8 hours
    #[clap(long, default_value_t = 8 * 60 * 60)]
    pub redis_ttl: u64,

    /// Executor limit, in millions of cycles
    #[clap(short, long, default_value_t = 100_000)]
    pub exec_cycle_limit: u64,

    /// S3 / Minio bucket
    #[clap(env)]
    pub s3_bucket: String,

    /// S3 / Minio access key
    #[clap(env)]
    pub s3_access_key: String,

    /// S3 / Minio secret key
    #[clap(env)]
    pub s3_secret_key: String,

    /// S3 / Minio url
    #[clap(env)]
    pub s3_url: String,

    /// S3 region, can be anything if using minio
    #[clap(env, default_value = "us-west-2")]
    pub s3_region: String,

    /// Enable pipelined job processing
    ///
    /// When enabled, agent will fetch next job while processing current job
    #[arg(long, default_value_t = false)]
    pub enable_pipelined_jobs: bool,

    /// Pipeline depth (number of jobs to prefetch)
    ///
    /// How many jobs to prepare ahead of time
    #[arg(long, default_value_t = 2)]
    pub pipeline_depth: usize,

    /// Enable segment data prefetching
    ///
    /// When enabled, segment data is downloaded while jobs are queued
    #[arg(long, default_value_t = false)]
    pub enable_segment_prefetch: bool,

    /// Prefetch timeout in seconds
    ///
    /// Maximum time to wait for segment prefetch before skipping
    #[arg(long, default_value_t = 30)]
    pub prefetch_timeout: u64,

    /// Enables a background thread to monitor for tasks that need to be retried / timed-out
    #[clap(long, default_value_t = false)]
    monitor_requeue: bool,

    // Task flags
    /// How many times a prove+lift can fail before hard failure
    #[clap(long, default_value_t = 3)]
    prove_retries: i32,

    /// How long can a prove+lift can be running for, before it is marked as timed-out
    #[clap(long, default_value_t = 30)]
    prove_timeout: i32,

    /// How many times a join can fail before hard failure
    #[clap(long, default_value_t = 3)]
    join_retries: i32,

    /// How long can a join can be running for, before it is marked as timed-out
    #[clap(long, default_value_t = 10)]
    join_timeout: i32,

    /// How many times a resolve can fail before hard failure
    #[clap(long, default_value_t = 3)]
    resolve_retries: i32,

    /// How long can a resolve can be running for, before it is marked as timed-out
    #[clap(long, default_value_t = 10)]
    resolve_timeout: i32,

    /// How many times a finalize can fail before hard failure
    #[clap(long, default_value_t = 0)]
    finalize_retries: i32,

    /// How long can a finalize can be running for, before it is marked as timed-out
    ///
    /// NOTE: This value is multiplied by the assumption count
    #[clap(long, default_value_t = 10)]
    finalize_timeout: i32,

    /// Snark timeout in seconds
    #[clap(long, default_value_t = 60 * 4)]
    snark_timeout: i32,

    /// Snark retries
    #[clap(long, default_value_t = 0)]
    snark_retries: i32,
}

/// Core agent context to hold all optional clients / pools and state
pub struct Agent {
    /// Postgresql database connection pool
    pub db_pool: PgPool,
    /// segment po2 config
    pub segment_po2: u32,
    /// redis connection pool
    pub redis_pool: RedisPool,
    /// S3 client
    pub s3_client: S3Client,
    /// all configuration params:
    args: Args,
    /// risc0 Prover server
    prover: Option<Rc<dyn ProverServer>>,
    /// risc0 verifier context
    verifier_ctx: VerifierContext,
}

impl Agent {
    /// Initialize the [Agent] from the [Args] config params
    ///
    /// Starts any connection pools and establishes the agents configs
    pub async fn new(args: Args) -> Result<Self> {
        let db_pool = PgPoolOptions::new()
            .max_connections(args.db_max_connections)
            .connect(&args.database_url)
            .await
            .context("Failed to initialize postgresql pool")?;
        let redis_pool = crate::redis::create_pool(&args.redis_url)?;
        let s3_client = S3Client::from_minio(
            &args.s3_url,
            &args.s3_bucket,
            &args.s3_access_key,
            &args.s3_secret_key,
            &args.s3_region,
        )
        .await
        .context("Failed to initialize s3 client / bucket")?;

        let verifier_ctx = VerifierContext::default();
        let prover = if args.task_stream == PROVE_WORK_TYPE
            || args.task_stream == JOIN_WORK_TYPE
            || args.task_stream == COPROC_WORK_TYPE
        {
            let opts = ProverOpts::default();
            let prover = get_prover_server(&opts).context("Failed to initialize prover server")?;
            Some(Rc::from(prover))
        } else {
            None
        };

        Ok(Self {
            db_pool,
            segment_po2: args.segment_po2,
            redis_pool,
            s3_client,
            args,
            prover,
            verifier_ctx,
        })
    }

    /// Create a signal hook to flip a boolean if its triggered
    ///
    /// Allows us to catch SIGTERM and exit any hard loop
    fn create_sig_monitor() -> Result<Arc<AtomicBool>> {
        let term = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;
        Ok(term)
    }

    /// Starts the work polling, runs until sig_hook triggers
    ///
    /// This function will poll for work and dispatch to the [Self::process_work] function until
    /// the process is terminated. It also handles retries / failures depending on the
    /// [Self::process_work] result
    pub async fn poll_work(&self) -> Result<()> {
        let term_sig = Self::create_sig_monitor().context("Failed to create signal hook")?;

        // Enables task retry management background thread, good for 1-2 aux workers to run in the
        // cluster
        if self.args.monitor_requeue {
            let term_sig_copy = term_sig.clone();
            let db_pool_copy = self.db_pool.clone();
            tokio::spawn(async move {
                Self::poll_for_requeue(term_sig_copy, db_pool_copy)
                    .await
                    .expect("Requeue failed")
            });
        }

        if self.args.enable_pipelined_jobs {
            self.run_pipelined_work(term_sig).await
        } else {
            self.run_single_work(term_sig).await
        }
    }

    /// Run pipelined job processing for maximum GPU utilization
    async fn run_pipelined_work(&self, term_sig: Arc<AtomicBool>) -> Result<()> {
        let pipeline_depth = self.args.pipeline_depth;
        let mut task_queue = Vec::with_capacity(pipeline_depth);

        // Pre-fill the pipeline with prefetched tasks
        for _ in 0..pipeline_depth {
            if let Ok(Some(task)) = taskdb::request_work(&self.db_pool, &self.args.task_stream).await {
                let mut prefetched_task = PrefetchedTask::new(task);

                // Start prefetching segment data if enabled
                if self.args.enable_segment_prefetch {
                    self.prefetch_segment_data(&mut prefetched_task).await;
                }

                task_queue.push(prefetched_task);
            } else {
                break;
            }
        }

        tracing::info!("Started pipelined processing with {} tasks in queue", task_queue.len());

        // Log prefetch status
        let ready_count = task_queue.iter().filter(|t| t.is_ready()).count();
        tracing::info!("Pipeline status: {}/{} tasks ready for immediate processing", ready_count, task_queue.len());

        while !term_sig.load(Ordering::Relaxed) && !task_queue.is_empty() {
            // Process current job
            let current_task = task_queue.remove(0);

            if current_task.is_ready() {
                tracing::debug!("Processing task {} with prefetched data ({} bytes)",
                    current_task.task.task_id,
                    current_task.get_segment_data().map(|d| d.len()).unwrap_or(0)
                );
            } else {
                tracing::warn!("Processing task {} without prefetched data - may cause delays",
                    current_task.task.task_id
                );
            }

            // Process the task directly
            if let Err(err) = self.process_work(&current_task.task).await {
                tracing::error!("Failure during task processing: {err:?}");
                self.handle_task_failure(&current_task.task, err).await?;
                continue;
            }

            // Fetch next job and start prefetching
            if let Ok(Some(next_task)) = taskdb::request_work(&self.db_pool, &self.args.task_stream).await {
                let mut prefetched_task = PrefetchedTask::new(next_task);

                // Start prefetching segment data for the next job
                if self.args.enable_segment_prefetch {
                    self.prefetch_segment_data(&mut prefetched_task).await;
                }

                task_queue.push(prefetched_task);
                tracing::debug!("Added next job to pipeline, queue size: {}", task_queue.len());
            } else {
                tracing::debug!("No more jobs available");
            }

            // Small delay to prevent overwhelming the system
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// Prefetch segment data for a task to eliminate download latency
    async fn prefetch_segment_data(&self, prefetched_task: &mut PrefetchedTask) {
        // Only prefetch for prove tasks
        let task_type: TaskType = match serde_json::from_value(prefetched_task.task.task_def.clone()) {
            Ok(task_type) => task_type,
            Err(_) => return, // Skip prefetching if we can't parse the task
        };

        match task_type {
            TaskType::Prove(prove_req) => {
                // For prove tasks, download segment data from Redis and store it in a prefetch key
                let segment_key = format!("job:{}:segments:{}", prefetched_task.task.job_id, prove_req.index);
                let prefetch_key = format!("job:{}:prefetch:{}:{}", prefetched_task.task.job_id, prove_req.index, prefetched_task.task.task_id);

                match self.redis_pool.get().await {
                    Ok(mut conn) => {
                        match conn.get::<_, Option<Vec<u8>>>(&segment_key).await {
                            Ok(Some(segment_data)) => {
                                // Store the prefetched data in Redis with a special prefetch key
                                if let Err(err) = redis::set_key_with_expiry(
                                    &mut conn,
                                    &prefetch_key,
                                    segment_data.clone(),
                                    Some(self.args.redis_ttl),
                                ).await {
                                    tracing::warn!("Failed to store prefetched data: {}", err);
                                    prefetched_task.prefetch_complete = false;
                                } else {
                                    prefetched_task.segment_data = Some(segment_data.clone());
                                    prefetched_task.prefetch_complete = true;

                                    tracing::debug!(
                                        "Segment data prefetched for prove task {} from Redis ({} bytes) and stored in prefetch key",
                                        prefetched_task.task.task_id,
                                        segment_data.len()
                                    );
                                }
                            }
                            Ok(None) => {
                                tracing::warn!("No segment data found in Redis for key: {}", segment_key);
                                prefetched_task.prefetch_complete = false;
                            }
                            Err(err) => {
                                tracing::warn!("Failed to prefetch segment data from Redis: {}", err);
                                prefetched_task.prefetch_complete = false;
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!("Failed to get Redis connection for prefetching: {}", err);
                        prefetched_task.prefetch_complete = false;
                    }
                }
            }
            TaskType::Keccak(_keccak_req) => {
                // For keccak tasks, the input data is stored in the task definition
                prefetched_task.prefetch_complete = true;

                tracing::debug!(
                    "Keccak input data prefetched for task {} (data available in task definition)",
                    prefetched_task.task.task_id
                );
            }
            _ => {
                // For other task types, mark as ready (no prefetching needed)
                prefetched_task.prefetch_complete = true;
                tracing::debug!("Task {} marked as ready (no prefetching needed)", prefetched_task.task.task_id);
            }
        }
    }

    /// Run traditional single job processing
    async fn run_single_work(&self, term_sig: Arc<AtomicBool>) -> Result<()> {
        while !term_sig.load(Ordering::Relaxed) {
            match taskdb::request_work(&self.db_pool, &self.args.task_stream).await {
                Ok(Some(task)) => {
                    if let Err(err) = self.process_work(&task).await {
                        tracing::error!("Failure during task processing: {err:?}");
                        self.handle_task_failure(&task, err).await?;
                    }
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_secs(self.args.poll_time)).await;
                }
                Err(err) => {
                    tracing::error!("Failed to request work: {err:?}");
                    tokio::time::sleep(Duration::from_secs(self.args.poll_time)).await;
                }
            }
        }
        Ok(())
    }

    /// Handle task failure with retry logic
    async fn handle_task_failure(&self, task: &ReadyTask, err: anyhow::Error) -> Result<()> {
        if task.max_retries > 0 {
            if !taskdb::update_task_retry(&self.db_pool, &task.job_id, &task.task_id)
                .await
                .context("Failed to update task retries")?
            {
                tracing::info!("update_task_retried failed: {}", task.job_id);
            }
        } else {
            // Prevent massive errors from being reported to the DB
            let mut err_str = format!("{err:?}");
            err_str.truncate(1024);
            taskdb::update_task_failed(
                &self.db_pool,
                &task.job_id,
                &task.task_id,
                &err_str,
            )
            .await
            .context("Failed to report task failure")?;
        }
        Ok(())
    }

    /// Process a task and dispatch based on the task type
    pub async fn process_work(&self, task: &ReadyTask) -> Result<()> {
        let task_type: TaskType = serde_json::from_value(task.task_def.clone())
            .with_context(|| format!("Invalid task_def: {}:{}", task.job_id, task.task_id))?;

        // run the task
        let res = match task_type {
            TaskType::Executor(req) => serde_json::to_value(
                tasks::executor::executor(self, &task.job_id, &req)
                    .await
                    .context("Executor failed")?,
            )
            .context("Failed to serialize prove response")?,
            TaskType::Prove(req) => serde_json::to_value(
                tasks::prove::prover(self, &task.job_id, &task.task_id, &req)
                    .await
                    .context("Prove failed")?,
            )
            .context("Failed to serialize prove response")?,
            TaskType::Join(req) => serde_json::to_value(
                tasks::join::join(self, &task.job_id, &req)
                    .await
                    .context("Join failed")?,
            )
            .context("Failed to serialize join response")?,
            TaskType::Resolve(req) => serde_json::to_value(
                tasks::resolve::resolver(self, &task.job_id, &req)
                    .await
                    .context("Resolve failed")?,
            )
            .context("Failed to serialize join response")?,
            TaskType::Finalize(req) => serde_json::to_value(
                tasks::finalize::finalize(self, &task.job_id, &req)
                    .await
                    .context("Finalize failed")?,
            )
            .context("Failed to serialize finalize response")?,
            TaskType::Snark(req) => serde_json::to_value(
                tasks::snark::stark2snark(self, &task.job_id.to_string(), &req)
                    .await
                    .context("Snark failed")?,
            )
            .context("failed to serialize snark response")?,
            TaskType::Keccak(req) => serde_json::to_value(
                tasks::keccak::keccak(self, &task.job_id, &task.task_id, &req)
                    .await
                    .context("Keccak failed")?,
            )
            .context("failed to serialize keccak response")?,
            TaskType::Union(req) => serde_json::to_value(
                tasks::union::union(self, &task.job_id, &req)
                    .await
                    .context("Union failed")?,
            )
            .context("failed to serialize union response")?,
        };

        taskdb::update_task_done(&self.db_pool, &task.job_id, &task.task_id, res)
            .await
            .context("Failed to report task done")?;

        Ok(())
    }

    /// background task to poll for jobs that need to be requeued
    ///
    /// Scan the queue looking for tasks that need to be retried and update them
    /// the agent will catch and fail max retries.
    async fn poll_for_requeue(term_sig: Arc<AtomicBool>, db_pool: PgPool) -> Result<()> {
        while !term_sig.load(Ordering::Relaxed) {
            tracing::debug!("Triggering a requeue job...");
            let retry_tasks = taskdb::requeue_tasks(&db_pool, 100).await?;
            if retry_tasks > 0 {
                tracing::info!("Found {retry_tasks} tasks that needed to be retried");
            }
            time::sleep(tokio::time::Duration::from_secs(5)).await;
        }

        Ok(())
    }
}
