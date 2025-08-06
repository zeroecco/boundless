# Kailua Order Generator Infrastructure

This Pulumi infrastructure deploys Kailua order generator services on AWS ECS Fargate. The service runs Kailua CLI containers that generate and manage order proposals for blockchain rollups.

## Overview

The infrastructure deploys two separate Kailua order generator services:
- **Optimism**: Main service for Optimism chain
- **Unichain**: Additional service for Unichain

Each service includes:
- ECS Fargate containers with Kailua CLI
- Comprehensive monitoring and alerting
- AWS Secrets Manager for secure configuration
- VPC networking with security groups
- CloudWatch alarms for health monitoring

## Prerequisites

- Pulumi CLI (>= v3): https://www.pulumi.com/docs/get-started/install/
- Node.js (>= 14): https://nodejs.org/
- AWS credentials configured (e.g., via `aws configure` or environment variables)
- Docker for building container images
- Access to RISC Zero toolchain

## Architecture

### Components
- **ECS Fargate Services**: Containerized Kailua CLI applications
- **ECR Repository**: Docker image storage with lifecycle policies
- **Secrets Manager**: Secure storage for private keys, RPC URLs, and JWT tokens
- **CloudWatch**: Logging, metrics, and alarms
- **VPC**: Network isolation and security groups
- **IAM Roles**: Least privilege access for ECS tasks

### Monitoring
- **Container Health**: Restart detection, memory/CPU utilization
- **Service Availability**: Running task count monitoring
- **Network Errors**: Packet drop detection
- **Application Logs**: Error and fatal log filtering
- **Resource Utilization**: Memory and CPU threshold alerts

## Configuration

### Base Configuration (`kailua-order-generator-base`)

| Key | Description | Required |
|-----|-------------|----------|
| `CHAIN_ID` | Blockchain chain ID | Yes |
| `PINATA_JWT` | Pinata JWT token for IPFS | Yes |
| `ETH_RPC_URL` | Ethereum RPC endpoint | Yes |
| `BOUNDLESS_WALLET_KEY` | Private key for transactions | Yes |
| `BOUNDLESS_RPC_URL` | Boundless RPC endpoint | Yes |
| `LOG_LEVEL` | Application log level | Yes |
| `DOCKER_DIR` | Path to Docker build context | Yes |
| `DOCKER_TAG` | Docker image tag | Yes |
| `SET_VERIFIER_ADDR` | Verifier contract address | Yes |
| `BOUNDLESS_MARKET_ADDR` | Market contract address | Yes |
| `IPFS_GATEWAY_URL` | IPFS gateway URL | Yes |
| `BASE_STACK` | Reference to base infrastructure stack | Yes |
| `SLACK_ALERTS_TOPIC_ARN` | Slack notifications SNS topic | No |
| `PAGERDUTY_ALERTS_TOPIC_ARN` | PagerDuty notifications SNS topic | No |

### Offchain Configuration (`kailua-order-generator-offchain`)

| Key | Description | Default |
|-----|-------------|---------|
| `AUTO_DEPOSIT` | Enable auto deposit functionality | Required |
| `WARN_BALANCE_BELOW` | ETH balance warning threshold | Optional |
| `ERROR_BALANCE_BELOW` | ETH balance error threshold | Optional |
| `INPUT_MAX_MCYCLES` | Maximum mega cycles for input | Optional |
| `RAMP_UP` | Ramp up configuration | Optional |
| `LOCK_TIMEOUT` | Lock timeout duration | Optional |
| `TIMEOUT` | General timeout duration | Optional |
| `SECONDS_PER_MCYCLE` | Seconds per mega cycle | Optional |
| `INTERVAL` | Processing interval | Optional |

### Kailua-Specific Configuration

| Key | Description | Default |
|-----|-------------|---------|
| `KAILUA_L1_URL` | L1 RPC URL | Required |
| `KAILUA_L2_URL` | L2 RPC URL | Required |
| `KAILUA_DATA_DIR` | Data directory path | Required |
| `NUM_CONCURRENT_PROVERS` | Number of concurrent provers | 8 |
| `NUM_CONCURRENT_PROOFS` | Number of concurrent proofs | 1 |
| `SKIP_AWAIT_PROOF` | Skip proof awaiting | true |
| `SKIP_DERIVATION_PROOF` | Skip derivation proof | true |
| `NTH_PROOF_TO_PROCESS` | Nth proof to process | 10 |
| `ENABLE_EXPERIMENTAL_WITNESS_ENDPOINT` | Enable experimental witness | true |
| `BOUNDLESS_LOOK_BACK` | Enable look back functionality | true |
| `BOUNDLESS_ORDER_BID_DELAY_FACTOR` | Order bid delay factor | 0.1 |
| `BOUNDLESS_ORDER_RAMP_UP_FACTOR` | Order ramp up factor | 0.2 |
| `BOUNDLESS_ORDER_LOCK_TIMEOUT_FACTOR` | Order lock timeout factor | 0.2 |
| `BOUNDLESS_ORDER_EXPIRY_FACTOR` | Order expiry factor | 1 |
| `BOUNDLESS_MEGA_CYCLE_STAKE` | Mega cycle stake amount | 1500 |
| `BOUNDLESS_CYCLE_MAX_WEI` | Cycle max Wei amount | 65000 |
| `RUST_BACKTRACE` | Rust backtrace level | full |
| `RISC0_INFO` | RISC0 info level | 1 |
| `STORAGE_PROVIDER` | Storage provider type | pinata |

## Getting Started

1. **Set up configuration**:
   ```bash
   # Base configuration
   pulumi config set kailua-order-generator-base:CHAIN_ID <chain-id>
   pulumi config set kailua-order-generator-base:PINATA_JWT <jwt-token> --secret
   pulumi config set kailua-order-generator-base:ETH_RPC_URL <rpc-url> --secret
   # ... set other required configuration
   ```

2. **Deploy the infrastructure**:
   ```bash
   pulumi preview
   pulumi up
   ```

3. **Monitor the services**:
   - Check CloudWatch logs for application output
   - Monitor alarms for service health
   - Verify ECS service status in AWS console

4. **Clean up** (when finished):
   ```bash
   pulumi destroy
   ```

## Service Monitoring

### Alarms
- **SEV2 Alarms**: Container restarts, high resource usage, network errors
- **SEV1 Alarms**: Service unavailability, critical resource usage (production only)

### Logs
- Application logs in CloudWatch Log Groups
- Error and fatal log filtering
- Balance monitoring logs

### Metrics
- ECS service metrics (CPU, memory, network)
- Custom application metrics
- Container health metrics

## Docker Image

The service uses a custom Docker image built from `dockerfiles/kailua-cli.dockerfile` with:
- Rust 1.88.0 toolchain
- RISC Zero toolchain for proving
- sccache for faster compilation
- Kailua CLI binary
- Health checks and proper entrypoint

## Security

- **Secrets Management**: All sensitive data stored in AWS Secrets Manager
- **IAM Roles**: Least privilege access for ECS tasks
- **VPC Isolation**: Services run in private subnets
- **Security Groups**: Restricted network access
- **Encryption**: Data encrypted in transit and at rest

## Troubleshooting

### Common Issues
1. **Container restarts**: Check logs for application errors
2. **High memory usage**: Monitor proving workload and adjust resources
3. **Network errors**: Verify RPC endpoint connectivity
4. **Secret access**: Ensure IAM roles have proper permissions

### Debug Commands
```bash
# Check service status
aws ecs describe-services --cluster <cluster-name> --services <service-name>

# View logs
aws logs tail <log-group-name> --follow

# Check alarms
aws cloudwatch describe-alarms --alarm-names <alarm-name>
```

## Contributing

If you encounter any issues or have suggestions, please open an issue in this repository.
