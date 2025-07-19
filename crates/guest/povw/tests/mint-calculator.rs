// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

#![allow(unused_imports)] // DO NOT MERGE

use alloy::{
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{DynProvider, Provider, ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
    sol,
};
use risc0_ethereum_contracts::{encode_seal, selector::Selector};

mod setup;

#[tokio::test]
async fn basic() -> anyhow::Result<()> {
    // 1. Setup the test context
    // 1. Post a single work log update to the PoVW contract.
    // 2. Advance time by 1 epoch.
    // 3. Finalize the epoch.
    // 4. Query for WorkLogUpdated and EpochFinalized events, recording the block numbers that
    //    include these events.
    // 5. Preflight the Steel queries that the guest will make to assemble the guest input.
    // 6. Run the mint calculator guest.
    // 9. Assemble a fake receipt and use it to call the mint function on the Mint contract.
    // 10. Verify that the minted values are as expected.
    todo!("Steps 3-10 to be implemented next")
}
