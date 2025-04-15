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

    pub async fn enqueue_segment(&mut self) -> Result<(), PlannerError> {
        let mut conn = self.conn.lock().await;
        let last_task_id: Option<String> = conn.get(LAST_TASK_KEY).await.map_err(|e| PlannerError::RedisError(e))?;
        let task_id = last_task_id.map_or(0, |id| id.parse().unwrap_or(0)) + 1;

        let task = Task {
            job_id: self.job_id,
            task_id,
            task_def: self.current_segment.clone(),
            prereqs: vec![],
            max_retries: 3,
        };

        let task_json = serde_json::to_string(&task).map_err(|e| PlannerError::SerializationError(e))?;
        conn.set(LAST_TASK_KEY, task_id.to_string()).await.map_err(|e| PlannerError::RedisError(e))?;
        conn.lpush(PEAKS_KEY, task_json).await.map_err(|e| PlannerError::RedisError(e))?;
        Ok(())
    }

    pub async fn enqueue_keccak(&mut self) -> Result<(), PlannerError> {
        let mut conn = self.conn.lock().await;
        let last_task_id: Option<String> = conn.get(LAST_TASK_KEY).await.map_err(|e| PlannerError::RedisError(e))?;
        let task_id = last_task_id.map_or(0, |id| id.parse().unwrap_or(0)) + 1;
        conn.set(LAST_TASK_KEY, task_id.to_string()).await.map_err(|e| PlannerError::RedisError(e))?;
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<(), PlannerError> {
        let mut conn = self.conn.lock().await;
        conn.del(PEAKS_KEY).await.map_err(|e| PlannerError::RedisError(e))?;
        conn.del(KECCAK_PEAKS_KEY).await.map_err(|e| PlannerError::RedisError(e))?;
        conn.del(LAST_TASK_KEY).await.map_err(|e| PlannerError::RedisError(e))?;
        Ok(())
    }

    pub async fn get_next_task(&mut self) -> Result<Option<Task>, PlannerError> {
        let mut conn = self.conn.lock().await;
        let task_str: Option<String> = conn.rpop(PEAKS_KEY, Some(NonZero::<usize>::new(1).unwrap())).await.map_err(|e| PlannerError::RedisError(e))?;

        if let Some(task_str) = task_str {
            let task: Task = serde_json::from_str(&task_str).map_err(|e| PlannerError::SerializationError(e))?;
            Ok(Some(task))
        } else {
            Ok(None)
        }
    }

    pub async fn get_next_keccak(&self) -> Result<Option<Task>, PlannerError> {
        let mut conn = self.conn.lock().await;
        let task_str: Option<String> = conn.rpop(KECCAK_PEAKS_KEY, Some(NonZero::<usize>::new(1).unwrap())).await.map_err(|e| PlannerError::RedisError(e))?;

        if let Some(task_str) = task_str {
            let task: Task = serde_json::from_str(&task_str).map_err(|e| PlannerError::SerializationError(e))?;
            Ok(Some(task))
        } else {
            Ok(None)
        }
    }

    pub async fn add_task(&mut self, task: Task) -> Result<(), PlannerError> {
        let mut conn = self.conn.lock().await;
        let task_str = serde_json::to_string(&task).map_err(|e| PlannerError::SerializationError(e))?;
        conn.rpush(PEAKS_KEY, task_str).await.map_err(|e| PlannerError::RedisError(e))?;
        Ok(())
    }

    pub async fn add_keccak(&mut self, task: Task) -> Result<(), PlannerError> {
        let mut conn = self.conn.lock().await;
        let task_str = serde_json::to_string(&task).map_err(|e| PlannerError::SerializationError(e))?;
        conn.rpush(KECCAK_PEAKS_KEY, task_str).await.map_err(|e| PlannerError::RedisError(e))?;
        Ok(())
    }

    pub async fn task_count(&mut self) -> Result<usize, PlannerError> {
        let mut conn = self.conn.lock().await;
        conn.llen::<_, usize>(TASKS_QUEUE_KEY).await.map_err(|e| PlannerError::RedisError(e))
    }

    async fn get_task_height(&mut self, task_number: usize) -> Result<u32, PlannerError> {
        let task = self.get_task(task_number).await?;
        let (_, height): (TaskType, u32) = serde_json::from_value(task.task_def)
            .map_err(|e| PlannerError::InvalidTaskFormat(e.to_string()))?;
        Ok(height)
    }

    pub async fn get_task(&mut self, task_number: usize) -> Result<Task, PlannerError> {
        let mut conn = self.conn.lock().await;
        let task = dequeue_task(&mut *conn, TASKS_QUEUE_KEY).await?;
        if let Some(task) = task {
            if task.task_id.split(':').nth(1).and_then(|s| s.parse::<usize>().ok()) == Some(task_number) {
                // Re-enqueue the task since we just peeked at it
                enqueue_task(&mut *conn, TASKS_QUEUE_KEY, task.clone()).await?;
                Ok(task)
            } else {
                // Re-enqueue and continue searching
                enqueue_task(&mut *conn, TASKS_QUEUE_KEY, task).await?;
                self.get_task(task_number).await
            }
        } else {
            Err(PlannerError::TaskNotFound(task_number))
        }
    }

    pub async fn next_task(&mut self) -> Result<Option<Task>, PlannerError> {
        let mut conn = self.conn.lock().await;
        let consumer_position: usize = conn.get::<_, Option<usize>>(CONSUMER_POSITION_KEY).await?.unwrap_or(0);
        let task_count = self.task_count().await?;

        if consumer_position < task_count {
            let task = dequeue_task(&mut *conn, TASKS_QUEUE_KEY).await?;
            if let Some(task) = task {
                // Re-enqueue the task since we just peeked at it
                enqueue_task(&mut *conn, TASKS_QUEUE_KEY, task.clone()).await?;
                conn.set(CONSUMER_POSITION_KEY, consumer_position + 1).await?;
                Ok(Some(task))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn enqueue_join(&mut self, left: usize, right: usize) -> Result<usize, PlannerError> {
        let task_number = self.next_task_number().await?;
        let left_height = self.get_task_height(left).await?;
        let right_height = self.get_task_height(right).await?;
        let task_height = 1 + u32::max(left_height, right_height);

        let task = Task::new_join(self.job_id, task_number, task_height, left, right);
        let mut conn = self.conn.lock().await;
        enqueue_task(&mut *conn, TASKS_QUEUE_KEY, task).await?;
        Ok(task_number)
    }

    async fn enqueue_union(&mut self, left: usize, right: usize) -> Result<usize, PlannerError> {
        let task_number = self.next_task_number().await?;
        let left_height = self.get_task_height(left).await?;
        let right_height = self.get_task_height(right).await?;
        let task_height = 1 + u32::max(left_height, right_height);

        let task = Task::new_union(self.job_id, task_number, task_height, left, right);
        let mut conn = self.conn.lock().await;
        enqueue_task(&mut *conn, TASKS_QUEUE_KEY, task).await?;
        Ok(task_number)
    }

    async fn enqueue_finalize(
        &mut self,
        depends_on: usize,
        keccak_depends_on: Option<VecDeque<usize>>,
    ) -> Result<usize, PlannerError> {
        let task_number = self.next_task_number().await?;
        let mut task_height = 1 + self.get_task_height(depends_on).await?;

        if let Some(val) = &keccak_depends_on {
            if let Some(highest_peak) = val.iter().max().copied() {
                task_height = task_height.max(1 + self.get_task_height(highest_peak).await?);
            }
        }

        let task = Task::new_finalize(self.job_id, task_number, task_height, depends_on, keccak_depends_on);
        let mut conn = self.conn.lock().await;
        enqueue_task(&mut *conn, TASKS_QUEUE_KEY, task).await?;
        Ok(task_number)
    }

    async fn next_task_number(&mut self) -> Result<usize, PlannerError> {
        Ok(self.task_count().await?)
    }
}
