use crate::{enqueue_task, dequeue_task, Task};
use redis::{aio::ConnectionManager, RedisResult, AsyncCommands};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;
use uuid::Uuid;
use redis::RedisError;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::num::NonZero;
use std::convert::Infallible;

const PEAKS_KEY: &str = "planner:peaks";
const KECCAK_PEAKS_KEY: &str = "planner:keccak_peaks";
const CONSUMER_POSITION_KEY: &str = "planner:consumer_position";
const LAST_TASK_KEY: &str = "planner:last_task";
const TASKS_QUEUE_KEY: &str = "planner:tasks";

#[derive(Error, Debug)]
pub enum RedisPlannerErr {
    #[error("Planning not yet started")]
    PlanNotStarted,
    #[error("Cannot add segment to finished plan")]
    PlanFinalized,
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Task not found: {0}")]
    TaskNotFound(String),
    #[error("Invalid task format: {0}")]
    InvalidTaskFormat(String),
}

#[derive(Error, Debug)]
pub enum PlannerError {
    #[error("Planning not yet started")]
    PlanNotStarted,
    #[error("Cannot add segment to finished plan")]
    PlanFinalized,
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Task not found: {0}")]
    TaskNotFound(usize),
    #[error("Invalid task format: {0}")]
    InvalidTaskFormat(String),
}

impl From<RedisResult<()>> for PlannerError {
    fn from(err: RedisResult<()>) -> Self {
        match err {
            Ok(_) => unreachable!(),
            Err(e) => PlannerError::RedisError(e),
        }
    }
}

impl From<RedisResult<usize>> for PlannerError {
    fn from(err: RedisResult<usize>) -> Self {
        match err {
            Ok(_) => unreachable!(),
            Err(e) => PlannerError::RedisError(e),
        }
    }
}

impl From<RedisResult<Option<usize>>> for PlannerError {
    fn from(err: RedisResult<Option<usize>>) -> Self {
        match err {
            Ok(_) => unreachable!(),
            Err(e) => PlannerError::RedisError(e),
        }
    }
}

impl From<RedisResult<Option<Task>>> for PlannerError {
    fn from(err: RedisResult<Option<Task>>) -> Self {
        match err {
            Ok(_) => unreachable!(),
            Err(e) => PlannerError::RedisError(e),
        }
    }
}

impl From<RedisPlannerErr> for PlannerError {
    fn from(err: RedisPlannerErr) -> Self {
        match err {
            RedisPlannerErr::RedisError(e) => PlannerError::RedisError(e),
            RedisPlannerErr::SerializationError(e) => PlannerError::SerializationError(e),
            RedisPlannerErr::TaskNotFound(s) => PlannerError::TaskNotFound(s.parse().unwrap_or(0)),
            RedisPlannerErr::InvalidTaskFormat(s) => PlannerError::InvalidTaskFormat(s),
            RedisPlannerErr::PlanNotStarted => PlannerError::PlanNotStarted,
            RedisPlannerErr::PlanFinalized => PlannerError::PlanFinalized,
        }
    }
}

impl From<redis::RedisError> for PlannerError {
    fn from(err: redis::RedisError) -> Self {
        PlannerError::RedisError(err)
    }
}

impl From<serde_json::Error> for PlannerError {
    fn from(err: serde_json::Error) -> Self {
        PlannerError::SerializationError(err)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskType {
    Segment,
    Keccak,
    Join,
    Union,
    Finalize,
}

impl Task {
    pub fn new_segment(job_id: Uuid, task_number: usize) -> Self {
        Self {
            job_id,
            task_id: format!("segment:{}", task_number),
            task_def: serde_json::to_value(TaskType::Segment).unwrap(),
            prereqs: serde_json::to_value(None::<()>).unwrap(),
            max_retries: 3,
        }
    }

    pub fn new_keccak(job_id: Uuid, task_number: usize) -> Self {
        Self {
            job_id,
            task_id: format!("keccak:{}", task_number),
            task_def: serde_json::to_value(TaskType::Keccak).unwrap(),
            prereqs: serde_json::to_value(None::<()>).unwrap(),
            max_retries: 3,
        }
    }

    pub fn new_join(job_id: Uuid, task_number: usize, task_height: u32, left: usize, right: usize) -> Self {
        Self {
            job_id,
            task_id: format!("join:{}", task_number),
            task_def: serde_json::to_value((TaskType::Join, task_height)).unwrap(),
            prereqs: serde_json::to_value((left, right)).unwrap(),
            max_retries: 3,
        }
    }

    pub fn new_union(job_id: Uuid, task_number: usize, task_height: u32, left: usize, right: usize) -> Self {
        Self {
            job_id,
            task_id: format!("union:{}", task_number),
            task_def: serde_json::to_value((TaskType::Union, task_height)).unwrap(),
            prereqs: serde_json::to_value((left, right)).unwrap(),
            max_retries: 3,
        }
    }

    pub fn new_finalize(
        job_id: Uuid,
        task_number: usize,
        task_height: u32,
        depends_on: usize,
        keccak_depends_on: Option<VecDeque<usize>>,
    ) -> Self {
        Self {
            job_id,
            task_id: format!("finalize:{}", task_number),
            task_def: serde_json::to_value((TaskType::Finalize, task_height)).unwrap(),
            prereqs: serde_json::to_value((depends_on, keccak_depends_on)).unwrap(),
            max_retries: 3,
        }
    }
}

pub struct RedisPlanner {
    conn: Arc<Mutex<ConnectionManager>>,
    job_id: Uuid,
}

impl RedisPlanner {
    pub async fn new(redis_url: &str) -> Result<Self, PlannerError> {
        let client = redis::Client::open(redis_url).map_err(PlannerError::RedisError)?;
        let conn = client.get_connection_manager().await.map_err(PlannerError::RedisError)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            job_id: Uuid::new_v4(),
        })
    }
}
