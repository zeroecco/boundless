// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use redis::{aio::ConnectionManager, RedisError};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub job_id: Uuid,
    pub task_id: String,
    pub task_def: JsonValue,
    pub prereqs: Vec<String>,
    pub max_retries: i32,
}

#[derive(Error, Debug)]
pub enum TaskQueueError {
    #[error("Redis error: {0}")]
    RedisError(#[from] RedisError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

pub async fn enqueue_task(
    conn: &mut ConnectionManager,
    queue_name: &str,
    task: Task,
) -> Result<(), TaskQueueError> {
    let task_json = serde_json::to_string(&task)?;
    let _: () = redis::cmd("RPUSH")
        .arg(queue_name)
        .arg(&task_json)
        .query_async(conn)
        .await?;
    Ok(())
}

pub async fn dequeue_task(
    conn: &mut ConnectionManager,
    queue_name: &str,
) -> Result<Option<Task>, TaskQueueError> {
    let result: Option<String> = redis::cmd("LPOP")
        .arg(queue_name)
        .query_async(conn)
        .await?;
    
    match result {
        Some(json) => Ok(Some(serde_json::from_str(&json)?)),
        None => Ok(None),
    }
}

pub async fn peek_task(
    conn: &mut ConnectionManager,
    queue_name: &str,
) -> Result<Option<Task>, TaskQueueError> {
    let result: Option<String> = redis::cmd("LINDEX")
        .arg(queue_name)
        .arg(0)
        .query_async(conn)
        .await?;
    
    match result {
        Some(json) => Ok(Some(serde_json::from_str(&json)?)),
        None => Ok(None),
    }
}

pub async fn queue_length(
    conn: &mut ConnectionManager,
    queue_name: &str,
) -> Result<usize, TaskQueueError> {
    let length: usize = redis::cmd("LLEN")
        .arg(queue_name)
        .query_async(conn)
        .await?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // These tests require a running Redis instance
    // Run with `REDIS_URL=redis://localhost:6379 cargo test`
    #[tokio::test]
    async fn test_queue_operations() {
        let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
        let client = redis::Client::open(redis_url).unwrap();
        let mut conn = client.get_connection_manager().await.unwrap();
        
        // Clean up any existing test queue
        let _: () = redis::cmd("DEL")
            .arg("test_queue")
            .query_async(&mut conn)
            .await
            .unwrap();
        
        // Test queue is initially empty
        let len = queue_length(&mut conn, "test_queue").await.unwrap();
        assert_eq!(len, 0);
        
        // Create a test task
        let task = Task {
            job_id: Uuid::new_v4(),
            task_id: "test-task-1".to_string(),
            task_def: json!({"operation": "test"}),
            prereqs: vec![],
            max_retries: 3,
        };
        
        // Enqueue the task
        enqueue_task(&mut conn, "test_queue", task.clone()).await.unwrap();
        
        // Check queue length
        let len = queue_length(&mut conn, "test_queue").await.unwrap();
        assert_eq!(len, 1);
        
        // Peek at the task
        let peeked_task = peek_task(&mut conn, "test_queue").await.unwrap().unwrap();
        assert_eq!(peeked_task.task_id, task.task_id);
        
        // Queue length should still be 1 after peeking
        let len = queue_length(&mut conn, "test_queue").await.unwrap();
        assert_eq!(len, 1);
        
        // Dequeue the task
        let dequeued_task = dequeue_task(&mut conn, "test_queue").await.unwrap().unwrap();
        assert_eq!(dequeued_task.task_id, task.task_id);
        
        // Queue should now be empty
        let len = queue_length(&mut conn, "test_queue").await.unwrap();
        assert_eq!(len, 0);
    }
}