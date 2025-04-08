#!/bin/bash

# Start anvil
anvil -a 1 --block-time 2 --host 0.0.0.0 --port 8545 &
sleep 3

# Deploy the contracts
DEPLOYER_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
CHAIN_KEY="anvil"
RISC0_DEV_MODE="1"
ADMIN_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

RISC0_DEV_MODE=$RISC0_DEV_MODE BOUNDLESS_MARKET_OWNER=$ADMIN_ADDRESS forge script contracts/scripts/Deploy.s.sol \
    --rpc-url "http://0.0.0.0:8545" \
    --broadcast -vv \
    --private-key $DEPLOYER_PRIVATE_KEY \
    --chain-id $CHAIN_KEY || { echo 'Could not deploy contracts' ; exit 1; }

# Wait for anvil
wait