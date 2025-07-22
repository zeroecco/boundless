// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

#![allow(unused_imports)] // DO NOT MERGE

use std::collections::BTreeSet;

use alloy::{
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::{utils::Unit, Address, Bytes, FixedBytes, U256},
    providers::{ext::AnvilApi, DynProvider, Provider, ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_sol_types::SolValue;
use risc0_ethereum_contracts::{encode_seal, selector::Selector};

use boundless_povw_guests::{
    log_updater::{Input as LogUpdaterInput, LogBuilderJournal, WorkLogUpdate},
    mint_calculator::Input as MintCalculatorInput,
    BOUNDLESS_POVW_LOG_UPDATER_ID, BOUNDLESS_POVW_MINT_CALCULATOR_ID,
};
use risc0_povw::WorkLog;
use risc0_povw_guests::RISC0_POVW_LOG_BUILDER_ID;
use risc0_steel::ethereum::ANVIL_CHAIN_SPEC;
use risc0_zkvm::{Digest, FakeReceipt, Receipt, ReceiptClaim};

mod common;

#[tokio::test]
async fn basic() -> anyhow::Result<()> {
    // Setup test context
    let ctx = common::text_ctx().await?;
    println!("Test context setup complete:");
    println!("  PoVW contract: {:?}", ctx.povw_contract.address());
    println!("  Mint contract: {:?}", ctx.mint_contract.address());

    let initial_epoch = ctx.povw_contract.currentEpoch().call().await?;
    println!("  Initial epoch: {}", initial_epoch);

    // Post a work log update
    let signer = PrivateKeySigner::random();
    let update = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 25, // Work value for this update
        work_log_id: signer.address().into(),
    };

    let work_log_event = ctx.post_work_log_update(&signer, &update).await?;
    println!("Work log update posted for epoch {}", work_log_event.epochNumber);

    // Advance time and finalize epoch
    ctx.advance_epochs(1).await?;
    let finalized_event = ctx.finalize_epoch().await?;

    assert_eq!(finalized_event.epoch, U256::from(initial_epoch));
    assert_eq!(finalized_event.totalWork, U256::from(25)); // Our work log update value
    println!(
        "EpochFinalized event verified: epoch={}, totalWork={}",
        finalized_event.epoch, finalized_event.totalWork
    );

    let mint_receipt = ctx.run_mint().await?;
    println!("Mint transaction succeeded with {} gas used", mint_receipt.gas_used);

    let final_balance = ctx.token_contract.balanceOf(signer.address()).call().await?;
    let expected_mint_amount = Unit::ETHER.wei() * U256::from(100); // 100 ether for full epoch participation

    assert_eq!(
        final_balance, expected_mint_amount,
        "Minted amount should match expected calculation"
    );
    println!("✅ Successfully minted {} tokens to {:?}", final_balance, signer.address());

    Ok(())
}
