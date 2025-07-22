// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

#![allow(unused_imports)] // DO NOT MERGE

use std::collections::BTreeSet;

use alloy::{
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::{address, utils::Unit, Address, Bytes, FixedBytes, B256, U256},
    providers::{ext::AnvilApi, DynProvider, Provider, ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_sol_types::SolValue;
use risc0_ethereum_contracts::{encode_seal, selector::Selector};

use boundless_povw_guests::{
    log_updater::{Input as LogUpdaterInput, LogBuilderJournal, WorkLogUpdate},
    mint_calculator::{
        FixedPoint, Input as MintCalculatorInput, MintCalculatorJournal, MintCalculatorMint,
        MintCalculatorUpdate,
    },
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

    let initial_epoch = ctx.povw_contract.currentEpoch().call().await?;
    println!("Initial epoch: {}", initial_epoch);

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
    Ok(())
}

#[tokio::test]
async fn proportional_rewards_same_epoch() -> anyhow::Result<()> {
    let ctx = common::text_ctx().await?;

    let initial_epoch = ctx.povw_contract.currentEpoch().call().await?;
    println!("Initial epoch: {}", initial_epoch);

    let signer1 = PrivateKeySigner::random();
    let signer2 = PrivateKeySigner::random();

    // First update: 30 work units
    let update1 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 30,
        work_log_id: signer1.address().into(),
    };

    // Second update: 70 work units (different log ID)
    let update2 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 70,
        work_log_id: signer2.address().into(),
    };

    let event1 = ctx.post_work_log_update(&signer1, &update1).await?;
    let event2 = ctx.post_work_log_update(&signer2, &update2).await?;

    println!("Update 1: {} work units for {:?}", event1.work, event1.workLogId);
    println!("Update 2: {} work units for {:?}", event2.work, event2.workLogId);

    // Advance time and finalize epoch
    ctx.advance_epochs(1).await?;
    let finalized_event = ctx.finalize_epoch().await?;

    // Total work should be 30 + 70 = 100
    assert_eq!(finalized_event.totalWork, U256::from(100));
    println!("Total work in epoch: {}", finalized_event.totalWork);

    // Run mint calculation
    let mint_receipt = ctx.run_mint().await?;
    println!("Mint transaction succeeded with {} gas used", mint_receipt.gas_used);

    // Check balances - should be proportional to work done
    let balance1 = ctx.token_contract.balanceOf(signer1.address()).call().await?;
    let balance2 = ctx.token_contract.balanceOf(signer2.address()).call().await?;

    // Expected: signer1 gets 30% (30 tokens), signer2 gets 70% (70 tokens)
    let expected1 = Unit::ETHER.wei() * U256::from(30); // 30% of 100 tokens
    let expected2 = Unit::ETHER.wei() * U256::from(70); // 70% of 100 tokens

    // Allow for small rounding errors in fixed-point arithmetic (within 10 wei)
    // TODO(povw): Try to avoid these rounding errors.
    let tolerance = U256::from(10);
    assert!(
        balance1.abs_diff(expected1) <= tolerance,
        "Signer1 should receive ~30 tokens, got {}, expected {}",
        balance1,
        expected1
    );
    assert!(
        balance2.abs_diff(expected2) <= tolerance,
        "Signer2 should receive ~70 tokens, got {}, expected {}",
        balance2,
        expected2
    );

    println!(
        "Proportional rewards verified: {} tokens to signer1, {} tokens to signer2",
        balance1, balance2
    );
    Ok(())
}

#[tokio::test]
async fn sequential_mints_per_epoch() -> anyhow::Result<()> {
    let ctx = common::text_ctx().await?;

    let first_epoch = ctx.povw_contract.currentEpoch().call().await?;
    println!("Starting epoch: {}", first_epoch);

    let signer = PrivateKeySigner::random();

    // First epoch update
    let update1 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 50,
        work_log_id: signer.address().into(),
    };

    let event1 = ctx.post_work_log_update(&signer, &update1).await?;
    println!("Update 1: {} work units in epoch {}", event1.work, event1.epochNumber);

    // Advance to next epoch and finalize first epoch
    ctx.advance_epochs(1).await?;
    let finalized_event1 = ctx.finalize_epoch().await?;
    assert_eq!(finalized_event1.totalWork, U256::from(50));

    // First mint for first epoch
    let mint_receipt1 = ctx.run_mint_for_epochs(&[first_epoch]).await?;
    println!("First mint completed with {} gas used", mint_receipt1.gas_used);

    let balance_after_first_mint = ctx.token_contract.balanceOf(signer.address()).call().await?;
    let expected_first = Unit::ETHER.wei() * U256::from(100); // Full epoch reward

    assert_eq!(
        balance_after_first_mint, expected_first,
        "After first mint should have exactly 100 tokens"
    );
    println!("Balance after first mint: {} tokens", balance_after_first_mint);

    // Second epoch update (chained from first)
    let second_epoch = ctx.povw_contract.currentEpoch().call().await?;
    let update2 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: update1.updated_commit, // Chain from first update
        updated_commit: Digest::new(rand::random()),
        update_value: 75,
        work_log_id: signer.address().into(),
    };

    let event2 = ctx.post_work_log_update(&signer, &update2).await?;
    println!("Update 2: {} work units in epoch {}", event2.work, event2.epochNumber);

    // Advance to next epoch and finalize second epoch
    ctx.advance_epochs(1).await?;
    let finalized_event2 = ctx.finalize_epoch().await?;
    assert_eq!(finalized_event2.epoch, U256::from(second_epoch));
    assert_eq!(finalized_event2.totalWork, U256::from(75));

    // Second mint for second epoch
    let mint_receipt2 = ctx.run_mint_for_epochs(&[second_epoch]).await?;
    println!("Second mint completed with {} gas used", mint_receipt2.gas_used);

    let final_balance = ctx.token_contract.balanceOf(signer.address()).call().await?;
    let expected_total = Unit::ETHER.wei() * U256::from(200); // 100 + 100 tokens (both full epoch rewards)

    assert_eq!(final_balance, expected_total, "Final balance should be exactly 200 tokens");
    println!("Final balance after both mints: {} tokens", final_balance);

    Ok(())
}

#[tokio::test]
async fn cross_epoch_mint() -> anyhow::Result<()> {
    let ctx = common::text_ctx().await?;

    let first_epoch = ctx.povw_contract.currentEpoch().call().await?;
    println!("Starting epoch: {}", first_epoch);

    let signer = PrivateKeySigner::random();

    // First epoch update
    let update1 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 40,
        work_log_id: signer.address().into(),
    };

    let event1 = ctx.post_work_log_update(&signer, &update1).await?;
    println!("Update 1: {} work units in epoch {}", event1.work, event1.epochNumber);

    // Advance to next epoch and finalize first epoch
    ctx.advance_epochs(1).await?;
    let finalized_event1 = ctx.finalize_epoch().await?;
    assert_eq!(finalized_event1.totalWork, U256::from(40));

    // Second epoch update (chained from first)
    let second_epoch = ctx.povw_contract.currentEpoch().call().await?;
    let update2 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: update1.updated_commit, // Chain from first update
        updated_commit: Digest::new(rand::random()),
        update_value: 60,
        work_log_id: signer.address().into(),
    };

    let event2 = ctx.post_work_log_update(&signer, &update2).await?;
    println!("Update 2: {} work units in epoch {}", event2.work, event2.epochNumber);

    // Advance to next epoch and finalize second epoch
    ctx.advance_epochs(1).await?;
    let finalized_event2 = ctx.finalize_epoch().await?;
    assert_eq!(finalized_event2.epoch, U256::from(second_epoch));
    assert_eq!(finalized_event2.totalWork, U256::from(60));

    // Single mint covering both epochs
    let mint_receipt = ctx.run_mint_for_epochs(&[first_epoch, second_epoch]).await?;
    println!("Cross-epoch mint completed with {} gas used", mint_receipt.gas_used);

    let final_balance = ctx.token_contract.balanceOf(signer.address()).call().await?;
    let expected_total = Unit::ETHER.wei() * U256::from(200); // 100 + 100 tokens (both full epoch rewards)

    assert_eq!(
        final_balance, expected_total,
        "Final balance should be exactly 200 tokens from both epochs"
    );
    println!("Final balance after cross-epoch mint: {} tokens", final_balance);

    Ok(())
}

#[tokio::test]
async fn reject_invalid_steel_commitment() -> anyhow::Result<()> {
    let ctx = common::text_ctx().await?;
    let signer = PrivateKeySigner::random();

    // Setup a basic work log and epoch
    let update = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 25,
        work_log_id: signer.address().into(),
    };

    let _work_log_event = ctx.post_work_log_update(&signer, &update).await?;
    ctx.advance_epochs(1).await?;
    let _finalized_event = ctx.finalize_epoch().await?;

    // Create a mint journal with invalid Steel commitment
    let mint_journal = MintCalculatorJournal {
        mints: vec![MintCalculatorMint {
            recipient: signer.address(),
            value: FixedPoint { value: U256::from(1) },
        }],
        updates: vec![MintCalculatorUpdate {
            workLogId: signer.address(),
            initialCommit: B256::from(<[u8; 32]>::from(update.initial_commit)),
            finalCommit: B256::from(<[u8; 32]>::from(update.updated_commit)),
        }],
        povwContractAddress: *ctx.povw_contract.address(),
        steelCommit: risc0_steel::Commitment::default(), // Invalid/empty Steel commitment
    };

    // Create fake receipt and try to submit
    let fake_receipt = FakeReceipt::new(ReceiptClaim::ok(
        BOUNDLESS_POVW_MINT_CALCULATOR_ID,
        mint_journal.abi_encode(),
    ));
    let receipt: Receipt = fake_receipt.try_into()?;

    let result = ctx
        .mint_contract
        .mint(mint_journal.abi_encode().into(), common::encode_seal(&receipt)?.into())
        .send()
        .await;

    assert!(result.is_err(), "Should reject invalid Steel commitment");
    let err = result.unwrap_err();
    println!("Contract correctly rejected invalid Steel commitment: {err}");
    // Check for InvalidSteelCommitment error selector 0x36ce79a0
    assert!(err.to_string().contains("0x36ce79a0"));

    Ok(())
}

#[tokio::test]
async fn reject_wrong_povw_address() -> anyhow::Result<()> {
    let ctx1 = common::text_ctx().await?;
    let ctx2 = common::test_ctx_with(ctx1.anvil.clone(), 1).await?;

    let signer = PrivateKeySigner::random();
    let update = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 25, // Work value for this update
        work_log_id: signer.address().into(),
    };

    // Using deployment #1, build the mint inputs.
    ctx1.post_work_log_update(&signer, &update).await?;
    ctx1.advance_epochs(1).await?;
    ctx1.finalize_epoch().await?;

    let mint_input = ctx1.build_mint_input().await?;

    // Execute the mint calculator guest
    let mint_journal = common::execute_mint_calculator_guest(&mint_input)?;

    // Assemble a fake receipt and use it to call the mint function on the Mint contract.
    let mint_receipt: Receipt = FakeReceipt::new(ReceiptClaim::ok(
        BOUNDLESS_POVW_MINT_CALCULATOR_ID,
        mint_journal.abi_encode(),
    ))
    .try_into()?;

    // Submit the mint to deployment #2. This should fail as the contract address for the PoVW
    // contract is wrong.
    let result = ctx2
        .mint_contract
        .mint(mint_journal.abi_encode().into(), common::encode_seal(&mint_receipt)?.into())
        .send()
        .await;

    assert!(result.is_err(), "Should reject wrong PoVW contract address");
    let err = result.unwrap_err();
    println!("Contract correctly rejected wrong PoVW address: {err}");
    // Check for IncorrectPovwAddress error selector 0x82db2de2
    assert!(err.to_string().contains("0x82db2de2"));

    Ok(())
}

#[tokio::test]
async fn reject_mint_with_only_latter_epoch() -> anyhow::Result<()> {
    let ctx = common::text_ctx().await?;
    let signer = PrivateKeySigner::random();

    let _first_epoch = ctx.povw_contract.currentEpoch().call().await?;

    // First update in first epoch
    let update1 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 30,
        work_log_id: signer.address().into(),
    };

    ctx.post_work_log_update(&signer, &update1).await?;
    ctx.advance_epochs(1).await?;
    ctx.finalize_epoch().await?;

    let second_epoch = ctx.povw_contract.currentEpoch().call().await?;

    // Second update in second epoch (chained from first)
    let update2 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: update1.updated_commit,
        updated_commit: Digest::new(rand::random()),
        update_value: 40,
        work_log_id: signer.address().into(),
    };

    ctx.post_work_log_update(&signer, &update2).await?;
    ctx.advance_epochs(1).await?;
    ctx.finalize_epoch().await?;

    // Try to mint using only the second epoch - should fail
    let result = ctx.run_mint_for_epochs(&[second_epoch]).await;
    assert!(result.is_err(), "Should reject mint with incomplete chain");
    let err = result.unwrap_err();
    println!("Contract correctly rejected incomplete chain: {err}");
    // Check for IncorrectInitialUpdateCommit error selector 0xf4a2b615
    assert!(err.to_string().contains("0xf4a2b615"));

    Ok(())
}

#[tokio::test]
async fn reject_mint_with_skipped_epoch() -> anyhow::Result<()> {
    let ctx = common::text_ctx().await?;
    let signer = PrivateKeySigner::random();

    let first_epoch = ctx.povw_contract.currentEpoch().call().await?;

    // First update in first epoch
    let update1 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 20,
        work_log_id: signer.address().into(),
    };

    ctx.post_work_log_update(&signer, &update1).await?;
    ctx.advance_epochs(1).await?;
    ctx.finalize_epoch().await?;

    let _second_epoch = ctx.povw_contract.currentEpoch().call().await?;

    // Second update in second epoch (chained from first)
    let update2 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: update1.updated_commit,
        updated_commit: Digest::new(rand::random()),
        update_value: 30,
        work_log_id: signer.address().into(),
    };

    ctx.post_work_log_update(&signer, &update2).await?;
    ctx.advance_epochs(1).await?;
    ctx.finalize_epoch().await?;

    let third_epoch = ctx.povw_contract.currentEpoch().call().await?;

    // Third update in third epoch (chained from second)
    let update3 = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: update2.updated_commit,
        updated_commit: Digest::new(rand::random()),
        update_value: 50,
        work_log_id: signer.address().into(),
    };

    ctx.post_work_log_update(&signer, &update3).await?;
    ctx.advance_epochs(1).await?;
    ctx.finalize_epoch().await?;

    // Try to mint using first and third epochs (skipping second) - should fail
    let result = ctx.run_mint_for_epochs(&[first_epoch, third_epoch]).await;
    assert!(result.is_err(), "Should reject mint with skipped epoch");
    let err = result.unwrap_err();
    println!("Contract correctly rejected skipped epoch: {err}");
    // Check for guest panic about non-chaining updates
    assert!(
        err.to_string().contains("multiple update events")
            && err.to_string().contains("do not form a chain")
    );

    Ok(())
}

#[tokio::test]
async fn reject_mint_with_unfinalized_epoch() -> anyhow::Result<()> {
    let ctx = common::text_ctx().await?;
    let signer = PrivateKeySigner::random();

    let current_epoch = ctx.povw_contract.currentEpoch().call().await?;

    // Post work log update but don't finalize the epoch
    let update = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 25,
        work_log_id: signer.address().into(),
    };

    ctx.post_work_log_update(&signer, &update).await?;

    // Advance time but DO NOT finalize the epoch
    ctx.advance_epochs(1).await?;

    // Try to mint without finalizing the epoch - should fail
    let result = ctx.run_mint_for_epochs(&[current_epoch]).await;
    assert!(result.is_err(), "Should reject mint with unfinalized epoch");
    let err = result.unwrap_err();
    println!("Contract correctly rejected unfinalized epoch: {err}");
    // The mint calculator guest should fail because there's no EpochFinalized event
    assert!(err.to_string().contains("no epoch finalized event processed"));

    Ok(())
}
