// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use std::{collections::VecDeque, sync::Arc};
use anyhow::{Context, Result};
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::planner::task::{Task, Command};
use task_queue::enqueue_task;

const TASKS_KEY: &str = "planner:tasks:";
const PEAKS_KEY: &str = "planner:peaks:";
const KECCAK_PEAKS_KEY: &str = "planner:keccak_peaks:";
const CONSUMER_POSITION_KEY: &str = "planner:consumer_position:";
const LAST_TASK_KEY: &str = "planner:last_task:";

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
    #[error("Invalid comparison")]
    InvalidComparison,
    #[error("Task not found: {0}")]
    TaskNotFound(usize),
}

pub struct RedisPlanner {
    conn: Arc<Mutex<ConnectionManager>>,
    job_id: Uuid,
}

impl RedisPlanner {
    pub async fn new(conn: ConnectionManager, job_id: Uuid) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
            job_id,
        }
    }

    /// Prefixes Redis keys with the job ID
    fn key(&self, key: &str) -> String {
        format!("{}:{}", key, self.job_id)
    }

    /// Gets a task by its number
    pub async fn get_task(&self, task_number: usize) -> Result<Task, RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let task_key = format!("{}:{}", self.key(TASKS_KEY), task_number);

        let task_data: Option<String> = conn.get(&task_key).await?;
        match task_data {
            Some(data) => {
                let task: Task = serde_json::from_str(&data)?;
                Ok(task)
            },
            None => Err(RedisPlannerErr::TaskNotFound(task_number)),
        }
    }

    /// Gets the next task number
    async fn next_task_number(&self) -> Result<usize, RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let tasks_key = self.key(TASKS_KEY);

        // Get the number of tasks using KEYS pattern matching and counting
        let task_keys: Vec<String> = conn.keys(format!("{}:*", tasks_key)).await?;
        Ok(task_keys.len())
    }

    /// Adds a task to Redis
    async fn add_task(&self, task: Task) -> Result<(), RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let task_key = format!("{}:{}", self.key(TASKS_KEY), task.task_number);

        let serialized = serde_json::to_string(&task)?;
        conn.set(task_key, serialized).await?;
        Ok(())
    }

    /// Gets the peaks (tasks that no other join tasks depend on)
    async fn get_peaks(&self) -> Result<Vec<usize>, RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let peaks_key = self.key(PEAKS_KEY);

        let peaks_data: Option<String> = conn.get(&peaks_key).await?;
        match peaks_data {
            Some(data) => {
                let peaks: Vec<usize> = serde_json::from_str(&data)?;
                Ok(peaks)
            },
            None => Ok(Vec::new()),
        }
    }

    /// Updates the peaks
    async fn update_peaks(&self, peaks: &[usize]) -> Result<(), RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let peaks_key = self.key(PEAKS_KEY);

        let serialized = serde_json::to_string(peaks)?;
        conn.set(peaks_key, serialized).await?;
        Ok(())
    }

    /// Gets the keccak peaks
    async fn get_keccak_peaks(&self) -> Result<VecDeque<usize>, RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let keccak_peaks_key = self.key(KECCAK_PEAKS_KEY);

        let peaks_data: Option<String> = conn.get(&keccak_peaks_key).await?;
        match peaks_data {
            Some(data) => {
                let peaks: VecDeque<usize> = serde_json::from_str(&data)?;
                Ok(peaks)
            },
            None => Ok(VecDeque::new()),
        }
    }

    /// Updates the keccak peaks
    async fn update_keccak_peaks(&self, peaks: &VecDeque<usize>) -> Result<(), RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let keccak_peaks_key = self.key(KECCAK_PEAKS_KEY);

        let serialized = serde_json::to_string(peaks)?;
        conn.set(keccak_peaks_key, serialized).await?;
        Ok(())
    }

    /// Gets the consumer position
    async fn get_consumer_position(&self) -> Result<usize, RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let position_key = self.key(CONSUMER_POSITION_KEY);

        let position: Option<String> = conn.get(&position_key).await?;
        match position {
            Some(pos) => Ok(pos.parse().unwrap_or(0)),
            None => Ok(0),
        }
    }

    /// Updates the consumer position
    async fn update_consumer_position(&self, position: usize) -> Result<(), RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let position_key = self.key(CONSUMER_POSITION_KEY);

        conn.set(position_key, position.to_string()).await?;
        Ok(())
    }

    /// Gets the last task
    async fn get_last_task(&self) -> Result<Option<usize>, RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let last_task_key = self.key(LAST_TASK_KEY);

        let last_task: Option<String> = conn.get(&last_task_key).await?;
        match last_task {
            Some(task) => Ok(Some(task.parse().unwrap_or(0))),
            None => Ok(None),
        }
    }

    /// Sets the last task
    async fn set_last_task(&self, task_number: usize) -> Result<(), RedisPlannerErr> {
        let mut conn = self.conn.lock().await;
        let last_task_key = self.key(LAST_TASK_KEY);

        conn.set(last_task_key, task_number.to_string()).await?;
        Ok(())
    }

    /// Adds a segment task to the plan
    pub async fn enqueue_segment(&self) -> Result<usize, RedisPlannerErr> {
        // Check if plan is already finalized
        if let Some(_) = self.get_last_task().await? {
            return Err(RedisPlannerErr::PlanFinalized);
        }

        // Create and add the segment task
        let task_number = self.next_task_number().await?;
        let task = Task::new_segment(task_number);
        self.add_task(task).await?;

        // Update peaks
        let mut peaks = self.get_peaks().await?;
        let mut new_peak = task_number;

        // Merge with existing peaks of equal height
        while let Some(smallest_peak) = peaks.last().copied() {
            let new_task = self.get_task(new_peak).await?;
            let smallest_peak_task = self.get_task(smallest_peak).await?;

            let new_height = new_task.task_height;
            let smallest_peak_height = smallest_peak_task.task_height;

            if new_height < smallest_peak_height {
                break;
            } else if new_height == smallest_peak_height {
                peaks.pop();
                new_peak = self.enqueue_join(smallest_peak, new_peak).await?;
            } else {
                return Err(RedisPlannerErr::InvalidComparison);
            }
        }

        peaks.push(new_peak);
        self.update_peaks(&peaks).await?;

        // Enqueue task in the task queue
        let task = self.get_task(task_number).await?;
        let task_id = format!("segment:{}:{}", self.job_id, task_number);
        let task_def = serde_json::to_value(task).context("Failed to serialize task")?;

        let mut redis_conn = self.conn.lock().await;
        let queue_task = task_queue::Task {
            job_id: self.job_id,
            task_id,
            task_def,
            data: vec![],
            prereqs: vec![],
            max_retries: 3,
        };

        task_queue::enqueue_task(&mut redis_conn, "segment", queue_task).await
            .map_err(|e| redis::RedisError::from_error(&e))?;

        Ok(task_number)
    }

    /// Adds a keccak task to the plan
    pub async fn enqueue_keccak(&self) -> Result<usize, RedisPlannerErr> {
        // Check if plan is already finalized
        if let Some(_) = self.get_last_task().await? {
            return Err(RedisPlannerErr::PlanFinalized);
        }

        // Create and add the keccak task
        let task_number = self.next_task_number().await?;
        let task = Task::new_keccak(task_number);
        self.add_task(task).await?;

        // Update keccak peaks
        let mut keccak_peaks = self.get_keccak_peaks().await?;
        let mut new_peak = task_number;

        // Merge with existing peaks of equal height
        while let Some(smallest_peak) = keccak_peaks.back().copied() {
            let new_task = self.get_task(new_peak).await?;
            let smallest_peak_task = self.get_task(smallest_peak).await?;

            let new_height = new_task.task_height;
            let smallest_peak_height = smallest_peak_task.task_height;

            if new_height < smallest_peak_height {
                break;
            } else if new_height == smallest_peak_height {
                keccak_peaks.pop_back();
                new_peak = self.enqueue_union(smallest_peak, new_peak).await?;
            } else {
                return Err(RedisPlannerErr::InvalidComparison);
            }
        }

        keccak_peaks.push_back(new_peak);
        self.update_keccak_peaks(&keccak_peaks).await?;

        // Enqueue task in the task queue
        let task = self.get_task(task_number).await?;
        let task_id = format!("keccak:{}:{}", self.job_id, task_number);
        let task_def = serde_json::to_value(task).context("Failed to serialize task")?;

        let mut redis_conn = self.conn.lock().await;
        let queue_task = task_queue::Task {
            job_id: self.job_id,
            task_id,
            task_def,
            data: vec![],
            prereqs: vec![],
            max_retries: 3,
        };

        task_queue::enqueue_task(&mut redis_conn, "keccak", queue_task).await
            .map_err(|e| redis::RedisError::from_error(&e))?;

        Ok(task_number)
    }

    /// Adds a join task to the plan
    async fn enqueue_join(&self, left: usize, right: usize) -> Result<usize, RedisPlannerErr> {
        let task_number = self.next_task_number().await?;

        let left_task = self.get_task(left).await?;
        let right_task = self.get_task(right).await?;

        let task_height = 1 + std::cmp::max(left_task.task_height, right_task.task_height);
        let task = Task::new_join(task_number, task_height, left, right);
        self.add_task(task).await?;

        // Enqueue task in the task queue
        let task_id = format!("join:{}:{}", self.job_id, task_number);
        let task_def = serde_json::to_value(task).context("Failed to serialize task")?;

        let left_task_id = format!("segment:{}:{}", self.job_id, left);
        let right_task_id = format!("segment:{}:{}", self.job_id, right);

        let mut redis_conn = self.conn.lock().await;
        let queue_task = task_queue::Task {
            job_id: self.job_id,
            task_id,
            task_def,
            data: vec![],
            prereqs: vec![left_task_id, right_task_id],
            max_retries: 3,
        };

        task_queue::enqueue_task(&mut redis_conn, "join", queue_task).await
            .map_err(|e| redis::RedisError::from_error(&e))?;

        Ok(task_number)
    }

    /// Adds a union task to the plan
    async fn enqueue_union(&self, left: usize, right: usize) -> Result<usize, RedisPlannerErr> {
        let task_number = self.next_task_number().await?;

        let left_task = self.get_task(left).await?;
        let right_task = self.get_task(right).await?;

        let task_height = 1 + std::cmp::max(left_task.task_height, right_task.task_height);
        let task = Task::new_union(task_number, task_height, left, right);
        self.add_task(task).await?;

        // Enqueue task in the task queue
        let task_id = format!("union:{}:{}", self.job_id, task_number);
        let task_def = serde_json::to_value(task).context("Failed to serialize task")?;

        let left_task_id = format!("keccak:{}:{}", self.job_id, left);
        let right_task_id = format!("keccak:{}:{}", self.job_id, right);

        let mut redis_conn = self.conn.lock().await;
        let queue_task = task_queue::Task {
            job_id: self.job_id,
            task_id,
            task_def,
            data: vec![],
            prereqs: vec![left_task_id, right_task_id],
            max_retries: 3,
        };

        task_queue::enqueue_task(&mut redis_conn, "union", queue_task).await
            .map_err(|e| redis::RedisError::from_error(&e))?;

        Ok(task_number)
    }

    /// Adds a finalize task to the plan
    async fn enqueue_finalize(
        &self,
        depends_on: usize,
        keccak_depends_on: Option<VecDeque<usize>>,
    ) -> Result<usize, RedisPlannerErr> {
        let task_number = self.next_task_number().await?;

        let depends_on_task = self.get_task(depends_on).await?;
        let mut task_height = 1 + depends_on_task.task_height;

        // If there are keccak dependencies, determine the highest peak
        if let Some(val) = &keccak_depends_on {
            for &peak in val.iter() {
                let peak_task = self.get_task(peak).await?;
                task_height = std::cmp::max(task_height, 1 + peak_task.task_height);
            }
        }

        let task = Task::new_finalize(task_number, task_height, depends_on, keccak_depends_on);
        self.add_task(task).await?;

        // Enqueue task in the task queue
        let task_id = format!("finalize:{}:{}", self.job_id, task_number);
        let task_def = serde_json::to_value(task).context("Failed to serialize task")?;

        let mut prereqs = vec![];
        let join_task_id = format!("join:{}:{}", self.job_id, depends_on);
        prereqs.push(join_task_id);

        if let Some(keccak_deps) = &keccak_depends_on {
            for &keccak_peak in keccak_deps.iter() {
                let keccak_task_id = format!("union:{}:{}", self.job_id, keccak_peak);
                prereqs.push(keccak_task_id);
            }
        }

        let mut redis_conn = self.conn.lock().await;
        let queue_task = task_queue::Task {
            job_id: self.job_id,
            task_id,
            task_def,
            data: vec![],
            prereqs,
            max_retries: 3,
        };

        task_queue::enqueue_task(&mut redis_conn, "finalize", queue_task).await
            .map_err(|e| redis::RedisError::from_error(&e))?;

        Ok(task_number)
    }

    /// Finish unions in the plan
    async fn finish_unions(&self) -> Result<Option<VecDeque<usize>>, RedisPlannerErr> {
        let mut keccak_peaks = self.get_keccak_peaks().await?;

        // If there are no keccak peaks, return None
        if keccak_peaks.is_empty() {
            return Ok(None);
        }

        // Join remaining peaks if using union
        while 2 <= keccak_peaks.len() {
            let peak_0 = keccak_peaks.pop_front().unwrap();
            let peak_1 = keccak_peaks.pop_front().unwrap();

            let peak_3 = self.enqueue_union(peak_1, peak_0).await?;
            keccak_peaks.push_front(peak_3);
            self.update_keccak_peaks(&keccak_peaks).await?;
        }

        // Return only highest peak
        Ok(Some(VecDeque::from([keccak_peaks[0]])))
    }

    /// Finish the plan
    pub async fn finish(&self) -> Result<usize, RedisPlannerErr> {
        // Return error if plan has not yet started
        let peaks = self.get_peaks().await?;
        if peaks.is_empty() {
            return Err(RedisPlannerErr::PlanNotStarted);
        }

        // Check if plan is already finished
        if let Some(last_task) = self.get_last_task().await? {
            return Ok(last_task);
        }

        // Finish unions
        let keccak_depends_on = self.finish_unions().await?;

        // Join remaining peaks
        let mut peaks = self.get_peaks().await?;
        while 2 <= peaks.len() {
            let peak_0 = peaks.pop().unwrap();
            let peak_1 = peaks.pop().unwrap();

            let peak_3 = self.enqueue_join(peak_1, peak_0).await?;
            peaks.push(peak_3);
            self.update_peaks(&peaks).await?;
        }

        // Add the Finalize task
        let finalize_task = self.enqueue_finalize(peaks[0], keccak_depends_on).await?;

        // Set the last task
        self.set_last_task(finalize_task).await?;

        Ok(finalize_task)
    }

    /// Get the next task in the plan
    pub async fn next_task(&self) -> Result<Option<Task>, RedisPlannerErr> {
        let position = self.get_consumer_position().await?;
        let task_count = self.next_task_number().await?;

        if position < task_count {
            let task = self.get_task(position).await?;
            self.update_consumer_position(position + 1).await?;
            Ok(Some(task))
        } else {
            Ok(None)
        }
    }

    /// Get the count of tasks in the plan
    pub async fn task_count(&self) -> Result<usize, RedisPlannerErr> {
        self.next_task_number().await
    }
}
