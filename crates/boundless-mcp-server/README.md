# Boundless MCP Server

A Model Context Protocol (MCP) server that provides comprehensive diagnostic capabilities for the Boundless universal ZK protocol platform. This server enables both requestors and provers to diagnose order lifecycle issues and troubleshoot problems.

## Current Implementation Status

✅ **Core Infrastructure**: Complete
- MCP JSON-RPC server implementation
- Configuration management with TOML files
- SQLite database reader for broker data
- Local log file parsing and searching

✅ **Database Diagnostic Tools**: Complete
- Order status from broker database
- Order history and proving attempts
- Performance metrics analysis
- Failure diagnosis with recommendations
- Broker health checking

✅ **Log Analysis Tools**: Complete
- Local log file searching with ripgrep/grep
- Structured log parsing
- Time-based filtering
- Error code identification

🚧 **On-chain Integration**: Planned
- Blockchain data retrieval (requires alloy integration)
- Event timeline reconstruction
- Gas cost analysis
- Transaction tracking

The server currently provides full database and log analysis capabilities, with on-chain features to be added in a future update.

## Features

### For Requestors (On-chain Diagnostics)
- **Order Status**: Get comprehensive order status from blockchain
- **Order Timeline**: Show chronological order lifecycle events
- **Cost Analysis**: Analyze order costs including gas and cycles
- **Batch Summary**: Query multiple orders by requestor and time range

### For Provers (Database & Log Diagnostics)
- **Internal Status**: Get broker's internal view of order status
- **Prove History**: Track proving attempts and cycle counts
- **Performance Metrics**: Analyze prover performance over time
- **Log Search**: Search local broker logs for order-related entries
- **Failure Diagnosis**: Analyze why orders failed with recommendations
- **Health Check**: Monitor broker system health

## Installation

### Build from Source

```bash
# From the workspace root
cargo build --release --bin boundless-mcp-server

# Or build just this crate
cd crates/boundless-mcp-server
cargo build --release
```

### Configuration

Create a configuration file (default: `mcp-config.toml`):

```toml
[mcp]
# List of broker database paths to monitor
broker_dbs = [
    "/path/to/broker1.db",
    "/path/to/broker2.db",
    "./broker.db"
]

# Log file locations
log_paths = [
    "/var/log/boundless/broker.log",
    "./logs/broker.log"
]

# Default log search time range
default_log_search_range = "24h"

# Maximum number of log lines to return
max_log_lines = 1000

# Chain configurations
[chains.sepolia]
rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
chain_id = 11155111
boundless_market_address = "0x7B97cb8448B069c3Dc00069211c9d1BA42F59Df6"
name = "Ethereum Sepolia"

[chains.base_sepolia]
rpc_url = "https://base-sepolia-rpc.publicnode.com"
chain_id = 84532
boundless_market_address = "0xef2c15a68897E15d556faD8F95a1a58076C96e44"
name = "Base Sepolia"

[chains.local]
rpc_url = "http://localhost:8545"
chain_id = 31337
boundless_market_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
name = "Local Development"
```

## Usage

### Start the MCP Server

```bash
# Default configuration
boundless-mcp-server

# Custom configuration
boundless-mcp-server --config ./my-config.toml

# Enable debug logging
boundless-mcp-server --debug
```

### Use with MCP Client

Once the server is running, you can use any MCP-compatible client to interact with it:

```bash
# Example using mcp CLI (install mcp client first)
mcp --server boundless-mcp-server call order_status --order-id "0x927623523caf64b05f5b75d8a1086f77d272daf1ab5244f7"
```

## Available Tools

### 1. order_status
Get comprehensive order status from blockchain.

**Parameters:**
- `order_id` (required): Full order ID or request ID prefix

**Example:**
```bash
mcp call order_status --order-id "0x927623523caf64b05f5b75d8a1086f77d272daf1ab5244f7"
```

### 2. order_timeline
Show chronological order lifecycle events.

**Parameters:**
- `order_id` (required): Full order ID or request ID prefix

**Example:**
```bash
mcp call order_timeline --order-id "0x927623523caf64b05f5b75d8a1086f77d272daf1ab5244f7"
```

### 3. order_cost_analysis
Analyze order costs including gas and cycles.

**Parameters:**
- `order_id` (required): Full order ID or request ID prefix

**Example:**
```bash
mcp call order_cost_analysis --order-id "0x927623523caf64b05f5b75d8a1086f77d272daf1ab5244f7"
```

### 4. batch_order_summary
Query multiple orders by requestor and time range.

**Parameters:**
- `requestor_address` (required): Ethereum address of the requestor
- `start_time` (optional): Start time in ISO 8601 format
- `end_time` (optional): End time in ISO 8601 format

**Example:**
```bash
mcp call batch_order_summary --requestor-address "0x1234567890123456789012345678901234567890" --start-time "2024-01-01T00:00:00Z"
```

### 5. order_internal_status
Get broker's internal view of order status from database.

**Parameters:**
- `order_id` (required): Full order ID or request ID prefix

**Example:**
```bash
mcp call order_internal_status --order-id "0x927623523caf64b05f5b75d8a1086f77d272daf1ab5244f7"
```

### 6. order_prove_history
Track proving attempts and cycle counts.

**Parameters:**
- `order_id` (required): Full order ID or request ID prefix

**Example:**
```bash
mcp call order_prove_history --order-id "0x927623523caf64b05f5b75d8a1086f77d272daf1ab5244f7"
```

### 7. prover_performance
Analyze prover metrics over time.

**Parameters:**
- `start_time` (required): Start time in ISO 8601 format
- `end_time` (required): End time in ISO 8601 format

**Example:**
```bash
mcp call prover_performance --start-time "2024-01-01T00:00:00Z" --end-time "2024-01-07T00:00:00Z"
```

### 8. order_search_logs
Search local broker logs for order-related entries.

**Parameters:**
- `order_id` (required): Full order ID or request ID prefix
- `log_path` (optional): Path to log file or directory
- `time_range` (optional): Time range in format '1h', '24h', '7d' (default: 24h)

**Example:**
```bash
mcp call order_search_logs --order-id "0x927623523caf64b05f5b75d8a1086f77d272daf1ab5244f7" --time-range "48h"
```

### 9. order_failure_diagnosis
Analyze why an order failed with recommendations.

**Parameters:**
- `order_id` (required): Full order ID or request ID prefix

**Example:**
```bash
mcp call order_failure_diagnosis --order-id "0x927623523caf64b05f5b75d8a1086f77d272daf1ab5244f7"
```

### 10. broker_health_check
Check broker system health and recent issues.

**Parameters:** None

**Example:**
```bash
mcp call broker_health_check
```

## Integration with Boundless CLI

The MCP server can be integrated with the Boundless CLI for enhanced diagnostics:

```bash
# Add to your shell profile
export MCP_SERVER="boundless-mcp-server --config ./mcp-config.toml"

# Then use with boundless CLI
boundless request diagnose --order-id "0x927623523caf64b05f5b75d8a1086f77d272daf1ab5244f7"
```

## Architecture

The MCP server consists of several key components:

1. **Configuration Module**: Handles TOML configuration files and default settings
2. **Database Reader**: Read-only access to broker SQLite databases
3. **Chain Providers**: Ethereum RPC connections for on-chain data
4. **Log Parser**: Local log file search and parsing
5. **Tools Module**: Implements all diagnostic tools

### Order ID Format

Orders in Boundless have a specific format:
- **Request ID**: 40-character hex string (20 bytes)
- **Full Order ID**: `{request_id}-{tx_hash}-{fulfillment_type}`
- **Example**: `0x927623523caf64b05f5b75d8a1086f77d272daf1ab5244f7-0xc1e0a7dc540418586f8efe725a5594b057a2ae120a7a7219043d0a8658198a81-LockAndFulfill`

You can use either the full order ID or just the request ID prefix for most queries.

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check that the broker database path is correct
   - Ensure the database file exists and is readable
   - Verify the database isn't locked by another process

2. **RPC Connection Failed**
   - Check that the RPC URL is correct and accessible
   - Verify your network connection
   - Try using a different RPC endpoint

3. **Log Files Not Found**
   - Check that log paths in configuration are correct
   - Ensure log files exist and are readable
   - Verify the log file permissions

4. **Order Not Found**
   - Verify the order ID is correct
   - Check that you're using the right database
   - Try using just the request ID prefix

### Debug Mode

Enable debug logging to see detailed information:

```bash
boundless-mcp-server --debug
```

This will show:
- Database connection attempts
- RPC calls and responses
- Log file searches
- Tool parameter validation

## Development

### Running Tests

```bash
cargo test
```

### Building Documentation

```bash
cargo doc --open
```

### Code Style

The project follows standard Rust formatting:

```bash
cargo fmt
cargo clippy
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run tests and ensure they pass
6. Submit a pull request

## License

This project is licensed under the same terms as the Boundless protocol platform.