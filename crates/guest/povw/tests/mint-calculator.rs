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
    // 1. Setup the test context
    let ctx = common::text_ctx().await?;
    println!("Test context setup complete:");
    println!("  PoVW contract: {:?}", ctx.povw_contract.address());
    println!("  Mint contract: {:?}", ctx.mint_contract.address());

    let initial_epoch = ctx.povw_contract.currentEpoch().call().await?;
    println!("  Initial epoch: {}", initial_epoch);

    // 2. Post a single work log update to the PoVW contract.

    let signer = PrivateKeySigner::random();
    let chain_id = ctx.anvil.chain_id();
    let contract_address = *ctx.povw_contract.address();

    let update = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 25, // Work value for this update
        work_log_id: signer.address().into(),
    };

    let signature =
        WorkLogUpdate::from(update.clone()).sign(&signer, contract_address, chain_id).await?;

    // Execute the log updater guest to get a verified journal
    let log_input = LogUpdaterInput {
        update: update.clone(),
        signature: signature.as_bytes().to_vec(),
        contract_address,
        chain_id,
    };

    let journal = common::execute_log_updater_guest(&log_input)?;

    // Create receipt and call updateWorkLog
    let fake_receipt: Receipt =
        FakeReceipt::new(ReceiptClaim::ok(BOUNDLESS_POVW_LOG_UPDATER_ID, journal.abi_encode()))
            .try_into()?;

    let update_tx = ctx
        .povw_contract
        .updateWorkLog(
            journal.update.workLogId,
            journal.update.updatedCommit,
            journal.update.updateWork,
            common::encode_seal(&fake_receipt)?.into(),
        )
        .send()
        .await?;

    println!("Work log update posted: {:?}", update_tx.tx_hash());

    // 3. Advance time by 1 epoch.
    let epoch_length = ctx.povw_contract.EPOCH_LENGTH().call().await?;
    let advance_time = epoch_length.to::<u64>() + 1; // Advance by more than one epoch

    ctx.provider.anvil_increase_time(advance_time).await?;
    ctx.provider.anvil_mine(Some(1), None).await?;

    let new_epoch = ctx.povw_contract.currentEpoch().call().await?;
    assert_eq!(new_epoch, initial_epoch + 1, "Epoch should have advanced by 1");
    println!("Time advanced: epoch {} -> {}", initial_epoch, new_epoch);

    // 4. Finalize the epoch.
    let finalize_tx = ctx.povw_contract.finalizeEpoch().send().await?;
    println!("finalizeEpoch transaction sent: {:?}", finalize_tx.tx_hash());

    // Verify EpochFinalized event was emitted
    let finalize_receipt = finalize_tx.get_receipt().await?;
    let finalize_logs = finalize_receipt.logs();

    let epoch_finalized_events = finalize_logs
        .iter()
        .filter_map(|log| log.log_decode::<common::PoVW::EpochFinalized>().ok())
        .collect::<Vec<_>>();

    assert_eq!(epoch_finalized_events.len(), 1, "Expected exactly one EpochFinalized event");
    let finalized_event = &epoch_finalized_events[0].inner.data;

    assert_eq!(finalized_event.epoch, U256::from(initial_epoch));
    assert_eq!(finalized_event.totalWork, U256::from(25)); // Our work log update value
    println!(
        "EpochFinalized event verified: epoch={}, totalWork={}",
        finalized_event.epoch, finalized_event.totalWork
    );

    // 5. Query for WorkLogUpdated and EpochFinalized events, recording the block numbers that include these events.

    // Get the current block number to query up to
    let latest_block = ctx.provider.get_block_number().await?;
    println!("Latest block number: {}", latest_block);

    // Query for WorkLogUpdated events
    let work_log_filter =
        ctx.povw_contract.WorkLogUpdated_filter().from_block(0).to_block(latest_block);
    let work_log_events = work_log_filter.query().await?;
    println!("Found {} WorkLogUpdated events", work_log_events.len());

    // Query for EpochFinalized events
    let epoch_finalized_filter =
        ctx.povw_contract.EpochFinalized_filter().from_block(0).to_block(latest_block);
    let epoch_finalized_events = epoch_finalized_filter.query().await?;
    println!("Found {} EpochFinalized events", epoch_finalized_events.len());

    // Collect unique block numbers that contain events (automatically sorted)
    let mut block_numbers = BTreeSet::new();
    for (_, log) in &work_log_events {
        if let Some(block_number) = log.block_number {
            block_numbers.insert(block_number);
            println!("WorkLogUpdated event at block {}", block_number);
        }
    }
    for (_, log) in &epoch_finalized_events {
        if let Some(block_number) = log.block_number {
            block_numbers.insert(block_number);
            println!("EpochFinalized event at block {}", block_number);
        }
    }

    let sorted_blocks: Vec<u64> = block_numbers.into_iter().collect();
    println!("Block numbers with events: {:?}", sorted_blocks);

    // 6. Use the Input::build(...) method with the block numbers that have events to create the
    //    input we need for the mint calculator guest.

    let mint_input = MintCalculatorInput::build(
        contract_address, // PoVW contract address
        ctx.provider.clone(),
        &ANVIL_CHAIN_SPEC,
        sorted_blocks,
    )
    .await?;

    println!("Mint calculator input built successfully with {} blocks", mint_input.env.0.len());

    // 7. Run the mint calculator guest.
    let mint_journal = common::execute_mint_calculator_guest(&mint_input)?;
    println!("Mint calculator guest executed successfully");
    println!("  Number of mints: {}", mint_journal.mints.len());
    println!("  Number of updates: {}", mint_journal.updates.len());
    println!("  PoVW contract address: {:?}", mint_journal.povwContractAddress);

    // 8. Assemble a fake receipt and use it to call the mint function on the Mint contract.
    let mint_receipt: Receipt = FakeReceipt::new(ReceiptClaim::ok(
        BOUNDLESS_POVW_MINT_CALCULATOR_ID,
        mint_journal.abi_encode(),
    ))
    .try_into()?;

    let mint_tx = ctx
        .mint_contract
        .mint(mint_journal.abi_encode().into(), common::encode_seal(&mint_receipt)?.into())
        .send()
        .await?;

    println!("Mint transaction sent: {:?}", mint_tx.tx_hash());

    // 9. Verify that the minted values are as expected.
    let mint_receipt = mint_tx.get_receipt().await?;
    println!("Mint transaction succeeded with {} gas used", mint_receipt.gas_used);

    // Query the token balance of our signer who should have received the mint

    let final_balance = ctx.token_contract.balanceOf(signer.address()).call().await?;
    println!("Final token balance for {:?}: {}", signer.address(), final_balance);

    // Verify the minted amount matches our expectations
    // Expected calculation: (work_value / epoch_total_work) * EPOCH_REWARD
    // work_value = 25, epoch_total_work = 25, EPOCH_REWARD = 100 * 10^18
    // So expected mint = (25/25) * 100 * 10^18 = 1.0 * 100 ether = 100 ether
    let expected_mint_amount = Unit::ETHER.wei() * U256::from(100);
    assert_eq!(
        final_balance, expected_mint_amount,
        "Minted amount should match expected calculation"
    );

    println!("✅ All steps completed successfully!");
    println!("   - Posted work log update with 25 work units");
    println!("   - Advanced time and finalized epoch");
    println!("   - Executed mint calculator guest successfully");
    println!("   - Minted {} tokens to {:?}", final_balance, signer.address());

    Ok(())
}
