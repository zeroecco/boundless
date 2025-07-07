use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePool, Row};
use std::path::Path;

/// Order status as stored in the broker database
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum OrderStatus {
    PendingProving,
    Proving,
    PendingAgg,
    Aggregating,
    SkipAggregation,
    PendingSubmission,
    Done,
    Failed,
    Skipped,
}

/// Simplified order structure for diagnostics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticOrder {
    pub id: String,
    pub request_id: String,
    pub status: String,
    pub updated_at: DateTime<Utc>,
    pub chain_id: u64,
    pub fulfillment_type: String,
    pub total_cycles: Option<u64>,
    pub proving_started_at: Option<DateTime<Utc>>,
    pub proof_id: Option<String>,
    pub compressed_proof_id: Option<String>,
    pub lock_price: Option<String>,
    pub error_msg: Option<String>,
    pub expire_timestamp: Option<DateTime<Utc>>,
    pub requestor: Option<String>,
    pub offer_price: Option<String>,
}

/// Batch information for aggregation diagnostics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticBatch {
    pub id: usize,
    pub status: String,
    pub deadline: Option<DateTime<Utc>>,
    pub order_count: usize,
    pub total_fee: Option<String>,
    pub groth16_proof_id: Option<String>,
}

/// Database reader for broker SQLite database
pub struct BrokerDbReader {
    pool: SqlitePool,
}

impl BrokerDbReader {
    /// Create a new database reader
    pub async fn new(db_path: &Path) -> Result<Self> {
        let db_url = format!("sqlite://{}", db_path.display());
        
        let pool = SqlitePool::connect(&db_url)
            .await
            .with_context(|| format!("Failed to connect to database: {}", db_path.display()))?;
        
        Ok(Self { pool })
    }
    
    /// Get order by ID (full or partial)
    pub async fn get_order(&self, order_id: &str) -> Result<Option<DiagnosticOrder>> {
        let query = if order_id.contains('-') {
            // Full order ID provided
            sqlx::query("SELECT id, data FROM orders WHERE id = ?")
                .bind(order_id)
        } else {
            // Partial ID (request ID prefix)
            let pattern = format!("0x{}%", order_id.trim_start_matches("0x"));
            sqlx::query("SELECT id, data FROM orders WHERE id LIKE ? LIMIT 1")
                .bind(pattern)
        };
        
        let row = query.fetch_optional(&self.pool).await?;
        
        if let Some(row) = row {
            let id: String = row.get("id");
            let data: String = row.get("data");
            
            let order = self.parse_order_data(&id, &data)?;
            Ok(Some(order))
        } else {
            Ok(None)
        }
    }
    
    /// Get multiple orders by various criteria
    pub async fn get_orders(&self, criteria: OrderCriteria) -> Result<Vec<DiagnosticOrder>> {
        let mut query = String::from("SELECT id, data FROM orders WHERE 1=1");
        let mut params = Vec::new();
        
        if let Some(status) = criteria.status {
            query.push_str(" AND json_extract(data, '$.status') = ?");
            params.push(status);
        }
        
        if let Some(start) = criteria.start_time {
            query.push_str(" AND json_extract(data, '$.updated_at') >= ?");
            params.push(start.to_rfc3339());
        }
        
        if let Some(end) = criteria.end_time {
            query.push_str(" AND json_extract(data, '$.updated_at') <= ?");
            params.push(end.to_rfc3339());
        }
        
        if let Some(requestor) = criteria.requestor {
            query.push_str(" AND json_extract(data, '$.request.requester') = ?");
            params.push(requestor);
        }
        
        query.push_str(" ORDER BY json_extract(data, '$.updated_at') DESC");
        
        if let Some(limit) = criteria.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }
        
        let mut stmt = sqlx::query(&query);
        for param in params {
            stmt = stmt.bind(param);
        }
        
        let rows = stmt.fetch_all(&self.pool).await?;
        
        let mut orders = Vec::new();
        for row in rows {
            let id: String = row.get("id");
            let data: String = row.get("data");
            
            if let Ok(order) = self.parse_order_data(&id, &data) {
                orders.push(order);
            }
        }
        
        Ok(orders)
    }
    
    /// Get all active orders (not completed or failed)
    pub async fn get_active_orders(&self) -> Result<Vec<DiagnosticOrder>> {
        let query = r#"
            SELECT id, data FROM orders 
            WHERE json_extract(data, '$.status') NOT IN ('Done', 'Failed', 'Skipped')
            ORDER BY json_extract(data, '$.updated_at') DESC
        "#;
        
        let rows = sqlx::query(query).fetch_all(&self.pool).await?;
        
        let mut orders = Vec::new();
        for row in rows {
            let id: String = row.get("id");
            let data: String = row.get("data");
            
            if let Ok(order) = self.parse_order_data(&id, &data) {
                orders.push(order);
            }
        }
        
        Ok(orders)
    }
    
    /// Get batch information
    pub async fn get_batch(&self, batch_id: usize) -> Result<Option<DiagnosticBatch>> {
        let query = "SELECT id, data FROM batches WHERE id = ?";
        let row = sqlx::query(query)
            .bind(batch_id as i64)
            .fetch_optional(&self.pool)
            .await?;
        
        if let Some(row) = row {
            let id: i64 = row.get("id");
            let data: String = row.get("data");
            
            let batch = self.parse_batch_data(id as usize, &data)?;
            Ok(Some(batch))
        } else {
            Ok(None)
        }
    }
    
    /// Get all batches
    pub async fn get_batches(&self) -> Result<Vec<DiagnosticBatch>> {
        let query = "SELECT id, data FROM batches ORDER BY id DESC";
        let rows = sqlx::query(query).fetch_all(&self.pool).await?;
        
        let mut batches = Vec::new();
        for row in rows {
            let id: i64 = row.get("id");
            let data: String = row.get("data");
            
            if let Ok(batch) = self.parse_batch_data(id as usize, &data) {
                batches.push(batch);
            }
        }
        
        Ok(batches)
    }
    
    /// Get performance metrics over a time range
    pub async fn get_performance_metrics(
        &self,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<PerformanceMetrics> {
        // Count orders by status
        let status_query = r#"
            SELECT 
                json_extract(data, '$.status') as status,
                COUNT(*) as count
            FROM orders 
            WHERE json_extract(data, '$.updated_at') BETWEEN ? AND ?
            GROUP BY json_extract(data, '$.status')
        "#;
        
        let status_rows = sqlx::query(status_query)
            .bind(start_time.to_rfc3339())
            .bind(end_time.to_rfc3339())
            .fetch_all(&self.pool)
            .await?;
        
        let mut status_counts = std::collections::HashMap::new();
        for row in status_rows {
            let status: String = row.get("status");
            let count: i64 = row.get("count");
            status_counts.insert(status, count as usize);
        }
        
        // Calculate average proving time
        let proving_time_query = r#"
            SELECT 
                AVG(
                    (json_extract(data, '$.updated_at') - json_extract(data, '$.proving_started_at'))
                ) as avg_proving_time
            FROM orders 
            WHERE json_extract(data, '$.status') = 'Done'
                AND json_extract(data, '$.proving_started_at') IS NOT NULL
                AND json_extract(data, '$.updated_at') BETWEEN ? AND ?
        "#;
        
        let avg_proving_time: Option<f64> = sqlx::query_scalar(proving_time_query)
            .bind(start_time.to_rfc3339())
            .bind(end_time.to_rfc3339())
            .fetch_optional(&self.pool)
            .await?;
        
        // Calculate total cycles and fees
        let totals_query = r#"
            SELECT 
                SUM(json_extract(data, '$.total_cycles')) as total_cycles,
                COUNT(DISTINCT json_extract(data, '$.request.requester')) as unique_requestors
            FROM orders 
            WHERE json_extract(data, '$.updated_at') BETWEEN ? AND ?
        "#;
        
        let totals_row = sqlx::query(totals_query)
            .bind(start_time.to_rfc3339())
            .bind(end_time.to_rfc3339())
            .fetch_one(&self.pool)
            .await?;
        
        let total_cycles: Option<i64> = totals_row.try_get("total_cycles").ok();
        let unique_requestors: i64 = totals_row.get("unique_requestors");
        
        Ok(PerformanceMetrics {
            time_range: (start_time, end_time),
            status_counts,
            avg_proving_time_seconds: avg_proving_time,
            total_cycles: total_cycles.map(|c| c as u64),
            unique_requestors: unique_requestors as usize,
        })
    }
    
    /// Parse order JSON data into DiagnosticOrder
    fn parse_order_data(&self, id: &str, data: &str) -> Result<DiagnosticOrder> {
        let value: serde_json::Value = serde_json::from_str(data)?;
        
        // Extract request ID from the full order ID
        let request_id = id.split('-').next().unwrap_or(id).to_string();
        
        Ok(DiagnosticOrder {
            id: id.to_string(),
            request_id,
            status: value["status"].as_str().unwrap_or("Unknown").to_string(),
            updated_at: DateTime::parse_from_rfc3339(
                value["updated_at"].as_str().unwrap_or("1970-01-01T00:00:00Z")
            )?.with_timezone(&Utc),
            chain_id: value["chain_id"].as_u64().unwrap_or(0),
            fulfillment_type: value["fulfillment_type"].as_str().unwrap_or("Unknown").to_string(),
            total_cycles: value["total_cycles"].as_u64(),
            proving_started_at: value["proving_started_at"].as_u64()
                .map(|ts| DateTime::from_timestamp(ts as i64, 0))
                .flatten(),
            proof_id: value["proof_id"].as_str().map(|s| s.to_string()),
            compressed_proof_id: value["compressed_proof_id"].as_str().map(|s| s.to_string()),
            lock_price: value["lock_price"].as_str().map(|s| s.to_string()),
            error_msg: value["error_msg"].as_str().map(|s| s.to_string()),
            expire_timestamp: value["expire_timestamp"].as_u64()
                .map(|ts| DateTime::from_timestamp(ts as i64, 0))
                .flatten(),
            requestor: value["request"]["requester"].as_str().map(|s| s.to_string()),
            offer_price: value["request"]["offer"].as_str().map(|s| s.to_string()),
        })
    }
    
    /// Parse batch JSON data into DiagnosticBatch
    fn parse_batch_data(&self, id: usize, data: &str) -> Result<DiagnosticBatch> {
        let value: serde_json::Value = serde_json::from_str(data)?;
        
        Ok(DiagnosticBatch {
            id,
            status: value["status"].as_str().unwrap_or("Unknown").to_string(),
            deadline: value["deadline"].as_u64()
                .map(|ts| DateTime::from_timestamp(ts as i64, 0))
                .flatten(),
            order_count: value["orders"].as_array().map(|a| a.len()).unwrap_or(0),
            total_fee: value["fee"].as_str().map(|s| s.to_string()),
            groth16_proof_id: value["groth16_proof_id"].as_str().map(|s| s.to_string()),
        })
    }
}

/// Criteria for querying orders
#[derive(Debug, Default)]
pub struct OrderCriteria {
    pub status: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub requestor: Option<String>,
    pub limit: Option<usize>,
}

/// Performance metrics over a time range
#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub time_range: (DateTime<Utc>, DateTime<Utc>),
    pub status_counts: std::collections::HashMap<String, usize>,
    pub avg_proving_time_seconds: Option<f64>,
    pub total_cycles: Option<u64>,
    pub unique_requestors: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[tokio::test]
    async fn test_db_reader_creation() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let result = BrokerDbReader::new(temp_file.path()).await;
        
        // Should fail because it's not a valid SQLite database
        assert!(result.is_err());
        
        Ok(())
    }
}