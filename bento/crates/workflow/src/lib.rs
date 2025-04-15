// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

#![deny(missing_docs)]

//! Workflow processing Agent service

use anyhow::{Context, Result};
use clap::Parser;
use redis::aio::ConnectionManager;
use risc0_zkvm::{get_prover_server, ProverOpts, ProverServer, VerifierContext};
use std::{
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use task_queue::{Task, TaskQueueError};
use tokio::time;
use workflow_common::TaskType;
use uuid::Uuid;

mod tasks;

pub use workflow_common::{
    s3::S3Client, AUX_WORK_TYPE, EXEC_WORK_TYPE, JOIN_WORK_TYPE, PROVE_WORK_TYPE, SNARK_WORK_TYPE,
    COPROC_WORK_TYPE,
};

/// Workflow agent
///
/// Monitors task queue for new tasks on the selected stream and processes the work.
/// Requires redis access
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

    /// redis connection URL
    #[clap(env)]
    pub redis_url: String,

    /// risc0 segment po2 arg
    #[clap(short, long, default_value_t = 20)]
    pub segment_po2: u32,

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

    // Task flags
    /// How many times a prove+lift can fail before hard failure
    #[clap(long, default_value_t = 3)]
    prove_retries: i32,

    /// How many times a join can fail before hard failure
    #[clap(long, default_value_t = 3)]
    join_retries: i32,

    /// How many times a resolve can fail before hard failure
    #[clap(long, default_value_t = 3)]
    resolve_retries: i32,

    /// How many times a finalize can fail before hard failure
    #[clap(long, default_value_t = 0)]
    finalize_retries: i32,

    /// Snark retries
    #[clap(long, default_value_t = 0)]
    snark_retries: i32,
}

/// Core agent context to hold all optional clients / pools and state
pub struct Agent {
    /// segment po2 config
    pub segment_po2: u32,
    /// redis connection manager
    pub redis_conn: ConnectionManager,
    /// all configuration params:
    pub args: Args,
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
        let client = redis::Client::open(args.redis_url.clone())
            .context("Failed to create Redis client")?;
        let redis_conn = client.get_connection_manager().await
            .context("Failed to get Redis connection manager")?;

        let verifier_ctx = VerifierContext::default();
        let prover = if args.task_stream == PROVE_WORK_TYPE
            || args.task_stream == JOIN_WORK_TYPE
            || args.task_stream == COPROC_WORK_TYPE
        {
            let opts = ProverOpts::default();
            let prover = get_prover_server(&opts).context("Failed to initialize prover server")?;
            Some(prover)
        } else {
            None
        };

        Ok(Self {
            segment_po2: args.segment_po2,
            redis_conn,
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
        let mut conn = self.redis_conn.clone();
        let queue_name = format!("queue:{}", self.args.task_stream);
        tracing::info!("Starting work polling for queue: {}", queue_name);
        tracing::info!("Agent configuration - task_stream: {}, poll_time: {}s", self.args.task_stream, self.args.poll_time);

        while !term_sig.load(Ordering::Relaxed) {
            tracing::debug!("Polling for new tasks in queue: {}", queue_name);

            // Try to get a task from the queue
            let task = task_queue::dequeue_task(&mut conn, &queue_name).await
                .context("Failed to dequeue task")?;

            // If no task, sleep and try again
            if task.is_none() {
                tracing::debug!("No tasks found in queue: {}, sleeping for {} seconds", queue_name, self.args.poll_time);
                time::sleep(time::Duration::from_secs(self.args.poll_time)).await;
                continue;
            }

            let task = task.unwrap();
            tracing::info!("Found task in queue: {} - job_id: {}, task_id: {}", queue_name, task.job_id, task.task_id);

            // Process the task
            let task_clone = task.clone();
            if let Err(err) = self.process_work(task).await {
                tracing::error!("Failure during task processing: {err:?}");
                // If the task has retries left, requeue it with decremented retries
                if task_clone.max_retries > 0 {
                    let mut retry_task = task_clone.clone();
                    retry_task.max_retries -= 1;
                    tracing::info!("Requeuing failed task with remaining retries: {}", retry_task.max_retries);
                    if let Err(e) = task_queue::enqueue_task(&mut conn, &queue_name, retry_task).await {
                        tracing::error!("Failed to requeue task: {e:?}");
                    }
                } else {
                    // Log the failure
                    tracing::error!("Task failed with no retries left: job_id={}, task_id={}", task_clone.job_id, task_clone.task_id);
                }
                continue;
            }
        }
        tracing::warn!("Handled SIGTERM, shutting down...");

        Ok(())
    }

    /// Process a task and dispatch based on the task type
    pub async fn process_work(&self, task: Task) -> Result<()> {
        let task_clone = task.clone();
        tracing::info!("Processing task: job_id={}, task_id={}", task_clone.job_id, task_clone.task_id);

        let task_def: TaskType = serde_json::from_value(task.task_def.clone())
            .with_context(|| format!("Invalid task_def: {}:{}", task_clone.job_id, task_clone.task_id))?;
        tracing::debug!("Task definition parsed: {:?}", task_def);

        // run the task
        match task_def {
            TaskType::Executor(_req) => {
                tracing::info!("Starting executor task for job_id={}", task_clone.job_id);
                tasks::executor::executor(self.redis_conn.clone(), task)
                    .await
                    .map_err(|e| {
                        tracing::error!("Executor failed for job_id={}: {}", task_clone.job_id, e);
                        anyhow::anyhow!("Executor failed: {}", e)
                    })?;
                tracing::info!("Executor task completed for job_id={}", task_clone.job_id);
            },
            TaskType::Prove(req) => {
                tracing::info!("Starting prove task for job_id={}", task_clone.job_id);
                tasks::prove::prover(self, &task_clone.job_id, &task_clone.task_id, &req)
                    .await
                    .context("Prove failed")?;
                tracing::info!("Prove task completed for job_id={}", task_clone.job_id);
            },
            TaskType::Join(req) => {
                tracing::info!("Starting join task for job_id={}", task_clone.job_id);
                tasks::join::join(self, &task_clone.job_id, &req)
                    .await
                    .context("Join failed")?;
                tracing::info!("Join task completed for job_id={}", task_clone.job_id);
            },
            TaskType::Resolve(req) => {
                tracing::info!("Starting resolve task for job_id={}", task_clone.job_id);
                tasks::resolve::resolver(self, &task_clone.job_id, &req)
                    .await
                    .context("Resolve failed")?;
                tracing::info!("Resolve task completed for job_id={}", task_clone.job_id);
            },
            TaskType::Finalize(req) => {
                tracing::info!("Starting finalize task for job_id={}", task_clone.job_id);
                tasks::finalize::finalize(self, &task_clone.job_id, &req)
                    .await
                    .context("Finalize failed")?;
                tracing::info!("Finalize task completed for job_id={}", task_clone.job_id);
            },
            TaskType::Snark(req) => {
                tracing::info!("Starting snark task for job_id={}", task_clone.job_id);
                tasks::snark::stark2snark(self, &task_clone.job_id.to_string(), &req)
                    .await
                    .context("Snark failed")?;
                tracing::info!("Snark task completed for job_id={}", task_clone.job_id);
            },
            TaskType::Keccak(req) => {
                tracing::info!("Starting keccak task for job_id={}", task_clone.job_id);
                tasks::keccak::keccak(self, &task_clone.job_id, &task_clone.task_id, &req)
                    .await
                    .context("Keccak failed")?;
                tracing::info!("Keccak task completed for job_id={}", task_clone.job_id);
            },
            TaskType::Union(req) => {
                tracing::info!("Starting union task for job_id={}", task_clone.job_id);
                tasks::union::union(self, &task_clone.job_id, &req)
                    .await
                    .context("Union failed")?;
                tracing::info!("Union task completed for job_id={}", task_clone.job_id);
            },
        };

        tracing::info!("Task processing completed successfully for job_id={}", task_clone.job_id);
        Ok(())
    }

    /// Enqueue a new task to be processed
    pub async fn enqueue_task(&self, queue_name: &str, task_type: TaskType, prereqs: Vec<String>, max_retries: i32) -> Result<(), TaskQueueError> {
        let mut conn = self.redis_conn.clone();
        let task = Task {
            job_id: Uuid::new_v4(),
            task_id: format!("task:{}", Uuid::new_v4()),
            task_def: serde_json::to_value(task_type)?,
            prereqs,
            max_retries,
        };

        task_queue::enqueue_task(&mut conn, queue_name, task).await
    }

    /// Helper to get and deserialize a value from Redis
    pub async fn get_from_redis<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T> {
        let mut conn = self.redis_conn.clone();
        let result: Option<String> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .context("Failed to get value from Redis")?;

        match result {
            Some(value) => Ok(serde_json::from_str(&value).context("Failed to deserialize value")?),
            None => anyhow::bail!("Key not found in Redis: {}", key),
        }
    }

    /// Helper to set a value in Redis with optional expiry
    pub async fn set_in_redis(&self, key: &str, value: &[u8], expiry_seconds: Option<u64>) -> Result<()> {
        let mut conn = self.redis_conn.clone();

        if let Some(seconds) = expiry_seconds {
            let _: () = redis::cmd("SETEX")
                .arg(key)
                .arg(seconds)
                .arg(value)
                .query_async(&mut conn)
                .await
                .context("Failed to set value in Redis with expiry")?;
        } else {
            let _: () = redis::cmd("SET")
                .arg(key)
                .arg(value)
                .query_async(&mut conn)
                .await
                .context("Failed to set value in Redis")?;
        }

        Ok(())
    }

    /// Helper to scan for keys matching a pattern and delete them
    pub async fn scan_and_delete(&self, pattern: &str) -> Result<u64> {
        let mut conn = self.redis_conn.clone();
        let mut count = 0;

        let mut cursor = 0;
        loop {
            let (next_cursor, keys): (i64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{}*", pattern))
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .context("Failed to scan Redis")?;

            cursor = next_cursor;

            if !keys.is_empty() {
                let deleted: u64 = redis::cmd("DEL")
                    .arg(keys)
                    .query_async(&mut conn)
                    .await
                    .context("Failed to delete keys")?;
                count += deleted;
            }

            if cursor == 0 {
                break;
            }
        }

        Ok(count)
    }
}
