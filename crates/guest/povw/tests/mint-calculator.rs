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
    // 2. Post a single work log update to the PoVW contract.
    // 3. Advance time by 1 epoch.
    // 4. Finalize the epoch.
    // 5. Query for WorkLogUpdated and EpochFinalized events, recording the block numbers that
    //    include these events.
    // 6. Use the Input::build(...) method with the block numbers that have events to create the
    //    input we need for the mint calculator guest.
    // 7. Run the mint calculator guest.
    // 8. Assemble a fake receipt and use it to call the mint function on the Mint contract.
    // 9. Verify that the minted values are as expected.
    todo!("Steps 3-10 to be implemented next")
}
