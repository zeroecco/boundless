use anyhow::Result;
use clap::Parser;
use serde_json::json;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

mod config;
mod db;
mod tools;

use crate::config::Config;
use crate::tools::BoundlessDiagnosticsService;

#[derive(Parser, Debug)]
#[command(author, version, about = "Boundless MCP Server for diagnostics", long_about = None)]
struct Args {
    /// Configuration file path
    #[clap(short, long, default_value = "mcp-config.toml")]
    config_file: PathBuf,

    /// Enable debug logging
    #[clap(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.debug {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();

    info!("Starting Boundless MCP Server");

    // Load configuration
    let config = Config::from_file(&args.config_file)?;
    info!("Loaded configuration from {:?}", args.config_file);

    // Create the service
    let service = BoundlessDiagnosticsService::new(config).await?;

    // Send server info
    let server_info = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "boundless-diagnostics",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });

    println!("{}", server_info);
    io::stdout().flush()?;

    info!("MCP server initialized, starting main loop");

    // Main loop - read JSON-RPC messages from stdin
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        debug!("Received: {}", line);

        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(request) => {
                let response = handle_request(&service, request).await;
                println!("{}", serde_json::to_string(&response)?);
                io::stdout().flush()?;
            }
            Err(e) => {
                error!("Failed to parse request: {}", e);
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": "Parse error"
                    }
                });
                println!("{}", serde_json::to_string(&error_response)?);
                io::stdout().flush()?;
            }
        }
    }

    Ok(())
}

async fn handle_request(
    service: &BoundlessDiagnosticsService,
    request: serde_json::Value,
) -> serde_json::Value {
    let method = request["method"].as_str().unwrap_or("");
    let id = request["id"].clone();

    match method {
        "tools/list" => {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "order_status",
                            "description": "Get comprehensive order status from blockchain",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "order_id": {
                                        "type": "string",
                                        "description": "Full order ID or request ID prefix"
                                    }
                                },
                                "required": ["order_id"]
                            }
                        },
                        {
                            "name": "order_timeline",
                            "description": "Show order lifecycle events chronologically",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "order_id": {
                                        "type": "string",
                                        "description": "Full order ID or request ID prefix"
                                    }
                                },
                                "required": ["order_id"]
                            }
                        },
                        {
                            "name": "order_cost_analysis",
                            "description": "Analyze order costs including gas and cycles",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "order_id": {
                                        "type": "string",
                                        "description": "Full order ID or request ID prefix"
                                    }
                                },
                                "required": ["order_id"]
                            }
                        },
                        {
                            "name": "batch_order_summary",
                            "description": "Query multiple orders by requestor and time range",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "requestor_address": {
                                        "type": "string",
                                        "description": "Ethereum address of the requestor"
                                    },
                                    "start_time": {
                                        "type": "string",
                                        "description": "Start time in ISO 8601 format (optional)"
                                    },
                                    "end_time": {
                                        "type": "string",
                                        "description": "End time in ISO 8601 format (optional)"
                                    }
                                },
                                "required": ["requestor_address"]
                            }
                        },
                        {
                            "name": "order_internal_status",
                            "description": "Get broker's internal view of order status from database",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "order_id": {
                                        "type": "string",
                                        "description": "Full order ID or request ID prefix"
                                    }
                                },
                                "required": ["order_id"]
                            }
                        },
                        {
                            "name": "order_prove_history",
                            "description": "Track proving attempts and cycle counts",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "order_id": {
                                        "type": "string",
                                        "description": "Full order ID or request ID prefix"
                                    }
                                },
                                "required": ["order_id"]
                            }
                        },
                        {
                            "name": "prover_performance",
                            "description": "Analyze prover metrics over time",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "start_time": {
                                        "type": "string",
                                        "description": "Start time in ISO 8601 format"
                                    },
                                    "end_time": {
                                        "type": "string",
                                        "description": "End time in ISO 8601 format"
                                    }
                                },
                                "required": ["start_time", "end_time"]
                            }
                        },
                        {
                            "name": "order_search_logs",
                            "description": "Search local broker logs for order-related entries",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "order_id": {
                                        "type": "string",
                                        "description": "Full order ID or request ID prefix"
                                    },
                                    "log_path": {
                                        "type": "string",
                                        "description": "Path to log file or directory (optional, uses config default)"
                                    },
                                    "time_range": {
                                        "type": "string",
                                        "description": "Time range in format '1h', '24h', '7d' (optional, default 24h)"
                                    }
                                },
                                "required": ["order_id"]
                            }
                        },
                        {
                            "name": "order_failure_diagnosis",
                            "description": "Analyze why an order failed with recommendations",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "order_id": {
                                        "type": "string",
                                        "description": "Full order ID or request ID prefix"
                                    }
                                },
                                "required": ["order_id"]
                            }
                        },
                        {
                            "name": "broker_health_check",
                            "description": "Check broker system health and recent issues",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        },
                        {
                            "name": "docker_compose_logs",
                            "description": "Get docker compose logs for broker services",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "service": {
                                        "type": "string",
                                        "description": "Service name (default: 'broker')"
                                    },
                                    "since": {
                                        "type": "string",
                                        "description": "Time range like '1h', '30m', '24h' (default: '1h')"
                                    },
                                    "tail": {
                                        "type": "number",
                                        "description": "Number of lines to show (default: 100)"
                                    },
                                    "profile": {
                                        "type": "string",
                                        "description": "Docker compose profile (default: 'broker')"
                                    },
                                    "working_dir": {
                                        "type": "string",
                                        "description": "Working directory (default: '/home/austin/boundless')"
                                    }
                                }
                            }
                        },
                        {
                            "name": "search_docker_logs",
                            "description": "Search for patterns in docker compose logs",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "pattern": {
                                        "type": "string",
                                        "description": "Search pattern to look for in logs"
                                    },
                                    "service": {
                                        "type": "string",
                                        "description": "Service name (default: 'broker')"
                                    },
                                    "since": {
                                        "type": "string",
                                        "description": "Time range like '1h', '30m', '24h' (default: '1h')"
                                    },
                                    "profile": {
                                        "type": "string",
                                        "description": "Docker compose profile (default: 'broker')"
                                    },
                                    "case_insensitive": {
                                        "type": "boolean",
                                        "description": "Case insensitive search (default: true)"
                                    },
                                    "working_dir": {
                                        "type": "string",
                                        "description": "Working directory (default: '/home/austin/boundless')"
                                    }
                                },
                                "required": ["pattern"]
                            }
                        },
                        {
                            "name": "search_order_activity",
                            "description": "Search for specific order activity types in docker logs",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "activity_type": {
                                        "type": "string",
                                        "description": "Activity type: 'LockAndFulfill', 'Skipped', 'Done', 'Failed', 'Pricing', 'Proving'"
                                    },
                                    "service": {
                                        "type": "string",
                                        "description": "Service name (default: 'broker')"
                                    },
                                    "since": {
                                        "type": "string",
                                        "description": "Time range like '1h', '30m', '24h' (default: '1h')"
                                    },
                                    "profile": {
                                        "type": "string",
                                        "description": "Docker compose profile (default: 'broker')"
                                    },
                                    "limit": {
                                        "type": "number",
                                        "description": "Maximum number of matches to return (default: 50)"
                                    },
                                    "working_dir": {
                                        "type": "string",
                                        "description": "Working directory (default: '/home/austin/boundless')"
                                    }
                                },
                                "required": ["activity_type"]
                            }
                        }
                    ]
                }
            })
        }
        "tools/call" => {
            let params = &request["params"];
            let tool_name = params["name"].as_str().unwrap_or("");
            let arguments = params["arguments"].clone();

            let result = service.handle_tool_call(tool_name, arguments).await;

            match result {
                Ok(content) => {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&content).unwrap_or_else(|_| "Error serializing result".to_string())
                                }
                            ]
                        }
                    })
                }
                Err(e) => {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32603,
                            "message": format!("Tool execution failed: {}", e)
                        }
                    })
                }
            }
        }
        _ => {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "Method not found"
                }
            })
        }
    }
}
