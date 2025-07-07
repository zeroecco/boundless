use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::config::{ChainConfig, Config};
use crate::db::{BrokerDbReader, OrderCriteria};

/// Main service that handles all diagnostic tools
pub struct BoundlessDiagnosticsService {
    config: Config,
    db_readers: HashMap<PathBuf, Arc<BrokerDbReader>>,
    chain_providers: HashMap<u64, Arc<dyn Provider>>,
}

impl BoundlessDiagnosticsService {
    pub async fn new(config: Config) -> Result<Self> {
        let mut db_readers = HashMap::new();

        // Initialize database readers
        for db_path in &config.mcp.broker_dbs {
            if db_path.exists() {
                match BrokerDbReader::new(db_path).await {
                    Ok(reader) => {
                        info!("Connected to broker database: {:?}", db_path);
                        db_readers.insert(db_path.clone(), Arc::new(reader));
                    }
                    Err(e) => {
                        warn!("Failed to connect to database {:?}: {}", db_path, e);
                    }
                }
            }
        }

        // Initialize chain providers
        let mut chain_providers = HashMap::new();
        for (_name, chain_config) in &config.chains {
            let rpc_url = &chain_config.rpc_url;
            match ProviderBuilder::new().connect_http(rpc_url.parse()?) {
                provider => {
                    info!("Connected to chain {} at {}", chain_config.chain_id, rpc_url);
                    chain_providers
                        .insert(chain_config.chain_id, Arc::new(provider) as Arc<dyn Provider>);
                }
            }
        }

        Ok(Self { config, db_readers, chain_providers })
    }

    /// Get the first available database reader
    fn get_db_reader(&self) -> Result<&Arc<BrokerDbReader>> {
        self.db_readers.values().next().ok_or_else(|| anyhow!("No broker database available"))
    }

    /// Get chain provider by chain ID
    fn get_chain_provider(&self, chain_id: u64) -> Result<&Arc<dyn Provider>> {
        self.chain_providers
            .get(&chain_id)
            .ok_or_else(|| anyhow!("No provider for chain ID {}", chain_id))
    }

    /// Get chain configuration
    fn get_chain_config(&self, chain_id: u64) -> Result<&ChainConfig> {
        self.config
            .get_chain(chain_id)
            .ok_or_else(|| anyhow!("No configuration for chain ID {}", chain_id))
    }

    /// Parse time range string (e.g., "1h", "24h", "7d") into duration
    fn parse_time_range(&self, range: &str) -> Result<Duration> {
        let (num_str, unit) = range.split_at(range.len() - 1);
        let num: i64 = num_str.parse()?;

        match unit {
            "h" => Ok(Duration::hours(num)),
            "d" => Ok(Duration::days(num)),
            "m" => Ok(Duration::minutes(num)),
            _ => Err(anyhow!("Invalid time unit: {}", unit)),
        }
    }

    /// Handle order_status tool
    async fn handle_order_status(&self, params: Value) -> Result<Value> {
        let order_id =
            params["order_id"].as_str().ok_or_else(|| anyhow!("order_id parameter required"))?;

        let db = self.get_db_reader()?;
        let order = db
            .get_order(order_id)
            .await?
            .ok_or_else(|| anyhow!("Order not found: {}", order_id))?;

        // Get on-chain data if provider is available
        let chain_data = if let Ok(provider) = self.get_chain_provider(order.chain_id) {
            match self
                .get_on_chain_order_data(
                    &order.request_id,
                    provider,
                    &self.get_chain_config(order.chain_id)?.boundless_market_address,
                )
                .await
            {
                Ok(data) => Some(data),
                Err(e) => {
                    warn!("Failed to get on-chain data: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(json!({
            "order": order,
            "chain_data": chain_data,
            "chain_name": self.config.get_chain(order.chain_id)
                .and_then(|c| c.name.as_ref())
                .unwrap_or(&format!("Chain {}", order.chain_id)),
        }))
    }

    /// Handle order_timeline tool
    async fn handle_order_timeline(&self, params: Value) -> Result<Value> {
        let order_id =
            params["order_id"].as_str().ok_or_else(|| anyhow!("order_id parameter required"))?;

        let db = self.get_db_reader()?;
        let order = db
            .get_order(order_id)
            .await?
            .ok_or_else(|| anyhow!("Order not found: {}", order_id))?;

        let mut events = vec![];

        // Add database events
        events.push(json!({
            "timestamp": order.updated_at,
            "event": "Order Updated",
            "status": order.status,
            "details": order.error_msg,
        }));

        if let Some(started_at) = order.proving_started_at {
            events.push(json!({
                "timestamp": started_at,
                "event": "Proving Started",
            }));
        }

        // Get on-chain events if provider is available
        if let Ok(provider) = self.get_chain_provider(order.chain_id) {
            if let Ok(chain_config) = self.get_chain_config(order.chain_id) {
                // Query logs for this request ID
                match self
                    .get_order_events(
                        &order.request_id,
                        provider,
                        &chain_config.boundless_market_address,
                    )
                    .await
                {
                    Ok(chain_events) => events.extend(chain_events),
                    Err(e) => warn!("Failed to get on-chain events: {}", e),
                }
            }
        }

        // Sort events by timestamp
        events.sort_by(|a, b| {
            let ta = a["timestamp"].as_str().or(a["timestamp"].as_u64().map(|_| "0"));
            let tb = b["timestamp"].as_str().or(b["timestamp"].as_u64().map(|_| "0"));
            ta.cmp(&tb)
        });

        Ok(json!({
            "order_id": order.id,
            "request_id": order.request_id,
            "events": events,
        }))
    }

    /// Handle order_cost_analysis tool
    async fn handle_order_cost_analysis(&self, params: Value) -> Result<Value> {
        let order_id =
            params["order_id"].as_str().ok_or_else(|| anyhow!("order_id parameter required"))?;

        let db = self.get_db_reader()?;
        let order = db
            .get_order(order_id)
            .await?
            .ok_or_else(|| anyhow!("Order not found: {}", order_id))?;

        let cycles_mcycles = order.total_cycles.map(|c| c as f64 / 1_000_000.0);

        let mut analysis = json!({
            "order_id": order.id,
            "total_cycles": order.total_cycles,
            "total_mcycles": cycles_mcycles,
            "offer_price": order.offer_price,
            "lock_price": order.lock_price,
        });

        // Temporarily simplified profitability calculation
        if let (Some(offer), Some(lock)) = (&order.offer_price, &order.lock_price) {
            if let (Ok(offer_val), Ok(lock_val)) = (offer.parse::<u128>(), lock.parse::<u128>()) {
                let profitable = offer_val >= lock_val;
                let margin = if offer_val > lock_val {
                    Some(((offer_val - lock_val) as f64 / lock_val as f64) * 100.0)
                } else {
                    None
                };

                analysis["profitable"] = json!(profitable);
                analysis["profit_margin_percent"] = json!(margin);
            }
        }

        Ok(analysis)
    }

    /// Handle batch_order_summary tool
    async fn handle_batch_order_summary(&self, params: Value) -> Result<Value> {
        let requestor_address = params["requestor_address"]
            .as_str()
            .ok_or_else(|| anyhow!("requestor_address parameter required"))?;

        let start_time = params["start_time"]
            .as_str()
            .map(|s| DateTime::parse_from_rfc3339(s))
            .transpose()?
            .map(|dt| dt.with_timezone(&Utc));

        let end_time = params["end_time"]
            .as_str()
            .map(|s| DateTime::parse_from_rfc3339(s))
            .transpose()?
            .map(|dt| dt.with_timezone(&Utc))
            .or_else(|| Some(Utc::now()));

        let db = self.get_db_reader()?;
        let criteria = OrderCriteria {
            requestor: Some(requestor_address.to_string()),
            start_time,
            end_time,
            ..Default::default()
        };

        let orders = db.get_orders(criteria).await?;

        let total_orders = orders.len();
        let completed = orders.iter().filter(|o| o.status == "Done").count();
        let failed = orders.iter().filter(|o| o.status == "Failed").count();
        let pending = orders
            .iter()
            .filter(|o| !["Done", "Failed", "Skipped"].contains(&o.status.as_str()))
            .count();

        let total_cycles: u64 = orders.iter().filter_map(|o| o.total_cycles).sum();
        let total_mcycles = total_cycles as f64 / 1_000_000.0;

        Ok(json!({
            "requestor": requestor_address,
            "time_range": {
                "start": start_time,
                "end": end_time,
            },
            "summary": {
                "total_orders": total_orders,
                "completed": completed,
                "failed": failed,
                "pending": pending,
                "total_cycles": total_cycles,
                "total_mcycles": total_mcycles,
            },
            "orders": orders,
        }))
    }

    /// Handle order_internal_status tool
    async fn handle_order_internal_status(&self, params: Value) -> Result<Value> {
        let order_id =
            params["order_id"].as_str().ok_or_else(|| anyhow!("order_id parameter required"))?;

        let db = self.get_db_reader()?;
        let order = db
            .get_order(order_id)
            .await?
            .ok_or_else(|| anyhow!("Order not found: {}", order_id))?;

        // Add additional internal details
        let mut details = json!({
            "order": order,
            "database_path": self.db_readers.keys().next(),
        });

        // Check if order is in any batch
        let batches = db.get_batches().await?;
        for batch in batches {
            // This is a simplified check - in reality we'd need to parse batch orders
            if batch.order_count > 0 {
                details["batch_info"] = json!({
                    "batch_id": batch.id,
                    "batch_status": batch.status,
                    "groth16_proof_id": batch.groth16_proof_id,
                });
                break;
            }
        }

        Ok(details)
    }

    /// Handle order_prove_history tool
    async fn handle_order_prove_history(&self, params: Value) -> Result<Value> {
        let order_id =
            params["order_id"].as_str().ok_or_else(|| anyhow!("order_id parameter required"))?;

        let db = self.get_db_reader()?;
        let order = db
            .get_order(order_id)
            .await?
            .ok_or_else(|| anyhow!("Order not found: {}", order_id))?;

        let mut history = vec![];

        // Add current state
        history.push(json!({
            "timestamp": order.updated_at,
            "status": order.status,
            "proof_id": order.proof_id,
            "compressed_proof_id": order.compressed_proof_id,
            "total_cycles": order.total_cycles,
            "error": order.error_msg,
        }));

        // Calculate proving duration if applicable
        let proving_duration = if let (Some(started), true) =
            (order.proving_started_at, ["Done", "Failed"].contains(&order.status.as_str()))
        {
            Some((order.updated_at - started).num_seconds())
        } else {
            None
        };

        Ok(json!({
            "order_id": order.id,
            "request_id": order.request_id,
            "prove_history": history,
            "proving_duration_seconds": proving_duration,
            "total_mcycles": order.total_cycles.map(|c| c as f64 / 1_000_000.0),
        }))
    }

    /// Handle prover_performance tool
    async fn handle_prover_performance(&self, params: Value) -> Result<Value> {
        let start_time = params["start_time"]
            .as_str()
            .ok_or_else(|| anyhow!("start_time parameter required"))?;
        let end_time =
            params["end_time"].as_str().ok_or_else(|| anyhow!("end_time parameter required"))?;

        let start = DateTime::parse_from_rfc3339(start_time)?.with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339(end_time)?.with_timezone(&Utc);

        let db = self.get_db_reader()?;
        let metrics = db.get_performance_metrics(start, end).await?;

        let success_rate = if let (Some(done), Some(total)) = (
            metrics.status_counts.get("Done"),
            metrics.status_counts.values().sum::<usize>().into(),
        ) {
            if total > 0 {
                Some((*done as f64 / total as f64) * 100.0)
            } else {
                None
            }
        } else {
            None
        };

        Ok(json!({
            "time_range": {
                "start": start_time,
                "end": end_time,
            },
            "metrics": {
                "status_distribution": metrics.status_counts,
                "success_rate_percent": success_rate,
                "avg_proving_time_seconds": metrics.avg_proving_time_seconds,
                "total_cycles": metrics.total_cycles,
                "total_mcycles": metrics.total_cycles.map(|c| c as f64 / 1_000_000.0),
                "unique_requestors": metrics.unique_requestors,
            },
        }))
    }

    /// Handle order_search_logs tool
    async fn handle_order_search_logs(&self, params: Value) -> Result<Value> {
        let order_id =
            params["order_id"].as_str().ok_or_else(|| anyhow!("order_id parameter required"))?;

        let log_path = params["log_path"]
            .as_str()
            .map(PathBuf::from)
            .or_else(|| self.config.find_log_paths().first().map(|p| (*p).clone()))
            .ok_or_else(|| anyhow!("No log files available"))?;

        let time_range =
            params["time_range"].as_str().unwrap_or(&self.config.mcp.default_log_search_range);

        let duration = self.parse_time_range(time_range)?;
        let since = Utc::now() - duration;

        // Search logs using grep or ripgrep
        let mut logs = vec![];

        if log_path.is_file() {
            logs.extend(self.search_log_file(&log_path, order_id, since).await?);
        } else if log_path.is_dir() {
            // Search all log files in directory
            let mut entries = fs::read_dir(&log_path).await?;
            while let Some(entry) = entries.next_entry().await? {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("log") {
                    logs.extend(self.search_log_file(&entry.path(), order_id, since).await?);
                }
            }
        }

        // Limit results
        logs.truncate(self.config.mcp.max_log_lines);

        Ok(json!({
            "order_id": order_id,
            "log_path": log_path,
            "time_range": time_range,
            "entries": logs,
            "entry_count": logs.len(),
        }))
    }

    /// Handle order_failure_diagnosis tool
    async fn handle_order_failure_diagnosis(&self, params: Value) -> Result<Value> {
        let order_id =
            params["order_id"].as_str().ok_or_else(|| anyhow!("order_id parameter required"))?;

        let db = self.get_db_reader()?;
        let order = db
            .get_order(order_id)
            .await?
            .ok_or_else(|| anyhow!("Order not found: {}", order_id))?;

        let mut diagnosis = json!({
            "order_id": order.id,
            "status": order.status,
            "error_message": order.error_msg,
        });

        // Analyze the failure
        let mut recommendations = vec![];

        if let Some(error) = &order.error_msg {
            if error.contains("B-BAL-STK") || error.contains("stake balance") {
                recommendations.push("Insufficient stake balance - deposit more stake tokens");
            }
            if error.contains("B-SUB-003") || error.contains("timeout") {
                recommendations.push("Transaction timeout - check network congestion");
            }
            if error.contains("B-PRO-501") || error.contains("proving failed") {
                recommendations.push("Proving failed - check image ID and input validity");
            }
            if error.contains("expired") {
                recommendations.push("Order expired - consider increasing expiry time");
            }
        }

        // Check for common issues
        if order.status == "Failed" && order.error_msg.is_none() {
            recommendations.push("Generic failure - check logs for more details");
        }

        if let Some(expire) = order.expire_timestamp {
            if expire < Utc::now() {
                recommendations.push("Order has expired");
            }
        }

        diagnosis["recommendations"] = json!(recommendations);
        diagnosis["expired"] =
            json!(order.expire_timestamp.map(|e| e < Utc::now()).unwrap_or(false));

        Ok(diagnosis)
    }

    /// Handle broker_health_check tool
    async fn handle_broker_health_check(&self, _params: Value) -> Result<Value> {
        let db = self.get_db_reader()?;

        // Get active orders
        let active_orders = db.get_active_orders().await?;

        // Count by status
        let mut status_counts = HashMap::new();
        for order in &active_orders {
            *status_counts.entry(order.status.clone()).or_insert(0) += 1;
        }

        // Check for recent failures
        let recent_failures = active_orders
            .iter()
            .filter(|o| o.status == "Failed" && o.updated_at > Utc::now() - Duration::hours(1))
            .collect::<Vec<_>>();

        // Get current batches
        let batches = db.get_batches().await?;
        let active_batches =
            batches.iter().filter(|b| !["Complete", "Failed"].contains(&b.status.as_str())).count();

        let health_status = if recent_failures.len() > 5 {
            "Unhealthy - High failure rate"
        } else if active_orders.is_empty() {
            "Idle - No active orders"
        } else {
            "Healthy"
        };

        Ok(json!({
            "status": health_status,
            "active_orders": {
                "total": active_orders.len(),
                "by_status": status_counts,
            },
            "recent_failures": {
                "count": recent_failures.len(),
                "orders": recent_failures.iter().map(|o| json!({
                    "id": &o.id,
                    "error": &o.error_msg,
                    "updated_at": &o.updated_at,
                })).collect::<Vec<_>>(),
            },
            "active_batches": active_batches,
            "database_paths": self.db_readers.keys().collect::<Vec<_>>(),
        }))
    }

    /// Handle docker_compose_logs tool
    async fn handle_docker_compose_logs(&self, params: Value) -> Result<Value> {
        let service = params["service"].as_str().unwrap_or("broker"); // Default to broker service

        let since = params["since"].as_str().unwrap_or("1h"); // Default to last hour

        let tail = params["tail"].as_u64().unwrap_or(100); // Default to last 100 lines

        let profile = params["profile"].as_str().unwrap_or("broker"); // Default to broker profile

        let working_dir = params["working_dir"].as_str().unwrap_or("/home/austin/boundless"); // Default to boundless directory

        // Run docker compose logs command
        let output = Command::new("docker")
            .args(&[
                "compose",
                "--profile",
                profile,
                "logs",
                "--since",
                since,
                "--tail",
                &tail.to_string(),
                service,
            ])
            .current_dir(working_dir)
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let lines: Vec<&str> = stdout.lines().collect();

        Ok(json!({
            "service": service,
            "since": since,
            "tail": tail,
            "profile": profile,
            "working_dir": working_dir,
            "lines": lines,
            "line_count": lines.len(),
            "stderr": if stderr.is_empty() { None } else { Some(stderr.to_string()) },
            "exit_code": output.status.code(),
        }))
    }

    /// Handle search_docker_logs tool - search for patterns in docker compose logs
    async fn handle_search_docker_logs(&self, params: Value) -> Result<Value> {
        let pattern =
            params["pattern"].as_str().ok_or_else(|| anyhow!("pattern parameter required"))?;

        let service = params["service"].as_str().unwrap_or("broker");

        let since = params["since"].as_str().unwrap_or("1h");

        let profile = params["profile"].as_str().unwrap_or("broker");

        let working_dir = params["working_dir"].as_str().unwrap_or("/home/austin/boundless");

        let case_insensitive = params["case_insensitive"].as_bool().unwrap_or(true);

        // First get the logs
        let logs_output = Command::new("docker")
            .args(&["compose", "--profile", profile, "logs", "--since", since, service])
            .current_dir(working_dir)
            .output()
            .await?;

        if !logs_output.status.success() {
            return Err(anyhow!(
                "Failed to get docker logs: {}",
                String::from_utf8_lossy(&logs_output.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&logs_output.stdout);

        // Search for pattern in the logs
        let mut matches = vec![];
        for (line_num, line) in stdout.lines().enumerate() {
            let matches_pattern = if case_insensitive {
                line.to_lowercase().contains(&pattern.to_lowercase())
            } else {
                line.contains(pattern)
            };

            if matches_pattern {
                matches.push(json!({
                    "line_number": line_num + 1,
                    "content": line,
                    "timestamp": self.extract_timestamp_from_log_line(line),
                }));
            }
        }

        Ok(json!({
            "pattern": pattern,
            "service": service,
            "since": since,
            "profile": profile,
            "working_dir": working_dir,
            "case_insensitive": case_insensitive,
            "matches": matches,
            "match_count": matches.len(),
            "total_lines_searched": stdout.lines().count(),
        }))
    }

    /// Handle search_order_activity tool - search for specific order activity in logs
    async fn handle_search_order_activity(&self, params: Value) -> Result<Value> {
        let activity_type = params["activity_type"].as_str().ok_or_else(|| {
            anyhow!("activity_type parameter required (e.g., 'LockAndFulfill', 'Skipped', 'Done')")
        })?;

        let service = params["service"].as_str().unwrap_or("broker");

        let since = params["since"].as_str().unwrap_or("1h");

        let profile = params["profile"].as_str().unwrap_or("broker");

        let working_dir = params["working_dir"].as_str().unwrap_or("/home/austin/boundless");

        let limit = params["limit"].as_u64().unwrap_or(50); // Default to 50 matches

        // Get docker logs
        let logs_output = Command::new("docker")
            .args(&["compose", "--profile", profile, "logs", "--since", since, service])
            .current_dir(working_dir)
            .output()
            .await?;

        if !logs_output.status.success() {
            return Err(anyhow!(
                "Failed to get docker logs: {}",
                String::from_utf8_lossy(&logs_output.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&logs_output.stdout);

        // Search for activity patterns
        let mut matches = vec![];
        let patterns = match activity_type {
            "LockAndFulfill" => vec!["LockAndFulfill", "Locked request", "locking order"],
            "Skipped" => vec!["Skipped", "skipping order", "order skipped"],
            "Done" => vec!["Done", "successfully completed", "order completed"],
            "Failed" => vec!["Failed", "order failed", "error"],
            "Pricing" => vec!["Pricing order", "price calculation", "target price"],
            "Proving" => vec!["Proving order", "proof generation", "started proving"],
            _ => vec![activity_type], // Use the provided activity type as is
        };

        for (line_num, line) in stdout.lines().enumerate() {
            let line_lower = line.to_lowercase();
            let has_pattern =
                patterns.iter().any(|pattern| line_lower.contains(&pattern.to_lowercase()));

            if has_pattern {
                matches.push(json!({
                    "line_number": line_num + 1,
                    "content": line,
                    "timestamp": self.extract_timestamp_from_log_line(line),
                    "extracted_order_id": self.extract_order_id_from_log_line(line),
                }));

                if matches.len() >= limit as usize {
                    break;
                }
            }
        }

        Ok(json!({
            "activity_type": activity_type,
            "service": service,
            "since": since,
            "profile": profile,
            "working_dir": working_dir,
            "limit": limit,
            "matches": matches,
            "match_count": matches.len(),
            "total_lines_searched": stdout.lines().count(),
            "patterns_searched": patterns,
        }))
    }

    /// Extract timestamp from log line (if present)
    fn extract_timestamp_from_log_line(&self, line: &str) -> Option<String> {
        // Try to find ISO8601 timestamp pattern
        if let Some(start) = line.find('[') {
            if let Some(end) = line[start..].find(']') {
                let potential_ts = &line[start + 1..start + end];
                if potential_ts.len() > 19 && potential_ts.contains('T') {
                    return Some(potential_ts.to_string());
                }
            }
        }

        // Try to find other timestamp patterns
        if let Some(start) = line.find("2025-") {
            if let Some(end) = line[start..].find(' ') {
                let potential_date = &line[start..start + end];
                if potential_date.len() >= 10 {
                    return Some(potential_date.to_string());
                }
            }
        }

        None
    }

    /// Extract order ID from log line (if present)
    fn extract_order_id_from_log_line(&self, line: &str) -> Option<String> {
        // Look for hex patterns that look like order IDs (0x followed by hex chars)
        if let Some(start) = line.find("0x") {
            let hex_part = &line[start + 2..];
            let end = hex_part.chars().take_while(|c| c.is_ascii_hexdigit()).count();

            if end >= 40 {
                // Order IDs are typically 40+ hex chars
                return Some(format!("0x{}", &hex_part[..end]));
            }
        }
        None
    }

    /// Helper: Get on-chain order data
    async fn get_on_chain_order_data(
        &self,
        _request_id: &str,
        provider: &Arc<dyn Provider>,
        contract_address: &str,
    ) -> Result<Value> {
        // This is a simplified version - in reality would use contract ABI
        let block_number = provider.get_block_number().await?;

        Ok(json!({
            "current_block": block_number,
            "contract_address": contract_address,
            "note": "Full on-chain data requires contract ABI integration",
        }))
    }

    /// Helper: Get order events from chain
    async fn get_order_events(
        &self,
        _request_id: &str,
        provider: &Arc<dyn Provider>,
        _contract_address: &str,
    ) -> Result<Vec<Value>> {
        // This is a simplified version - would use proper event filtering with ABI
        let mut events = vec![];

        // For now, just return a placeholder indicating we can connect
        let block_number = provider.get_block_number().await?;
        events.push(json!({
            "timestamp": Utc::now().to_rfc3339(),
            "event": "Chain Query",
            "block_number": block_number,
            "note": "Full event decoding requires contract ABI integration"
        }));

        Ok(events)
    }

    /// Helper: Search a single log file
    async fn search_log_file(
        &self,
        path: &Path,
        order_id: &str,
        since: DateTime<Utc>,
    ) -> Result<Vec<Value>> {
        // Try to use ripgrep first, fall back to grep
        let output = if which::which("rg").is_ok() {
            Command::new("rg").arg("-i").arg("--json").arg(order_id).arg(path).output().await?
        } else {
            Command::new("grep").arg("-i").arg(order_id).arg(path).output().await?
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut results = vec![];

        for line in stdout.lines() {
            // Try to parse structured logs
            if let Ok(log_entry) = serde_json::from_str::<Value>(line) {
                // Check timestamp if available
                if let Some(ts_str) = log_entry["timestamp"].as_str() {
                    if let Ok(ts) = DateTime::parse_from_rfc3339(ts_str) {
                        if ts.with_timezone(&Utc) < since {
                            continue;
                        }
                    }
                }
                results.push(log_entry);
            } else {
                // Plain text log line
                results.push(json!({
                    "message": line,
                    "file": path.to_string_lossy(),
                }));
            }
        }

        Ok(results)
    }
}

impl BoundlessDiagnosticsService {
    pub async fn handle_tool_call(&self, tool_name: &str, arguments: Value) -> Result<Value> {
        info!("Handling tool call: {}", tool_name);
        debug!("Parameters: {:?}", arguments);

        match tool_name {
            "order_status" => self.handle_order_status(arguments).await,
            "order_timeline" => self.handle_order_timeline(arguments).await,
            "order_cost_analysis" => self.handle_order_cost_analysis(arguments).await,
            "batch_order_summary" => self.handle_batch_order_summary(arguments).await,
            "order_internal_status" => self.handle_order_internal_status(arguments).await,
            "order_prove_history" => self.handle_order_prove_history(arguments).await,
            "prover_performance" => self.handle_prover_performance(arguments).await,
            "order_search_logs" => self.handle_order_search_logs(arguments).await,
            "order_failure_diagnosis" => self.handle_order_failure_diagnosis(arguments).await,
            "broker_health_check" => self.handle_broker_health_check(arguments).await,
            "docker_compose_logs" => self.handle_docker_compose_logs(arguments).await,
            "search_docker_logs" => self.handle_search_docker_logs(arguments).await,
            "search_order_activity" => self.handle_search_order_activity(arguments).await,
            _ => Err(anyhow!("Unknown tool: {}", tool_name)),
        }
    }
}
