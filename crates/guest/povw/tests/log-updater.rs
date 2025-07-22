// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

// TODO(povw): This test is fragile to changes in the RISC0_POVW_LOG_BUILDER_ID, because the ID
// used here and the one used in the log updater guest may drift. Running the following command may
// fix a drift if it appears.
//
// ```
// cargo update -p risc0-povw-guests --manifest-path Cargo.toml && cargo update -p risc0-povw-guests --manifest-path crates/guest/povw/log-updater/Cargo.toml
// ```

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{address, aliases::U96, Address, B256, U256};
use boundless_povw_guests::log_updater::{Input, LogBuilderJournal, WorkLogUpdate};
use risc0_povw::WorkLog;
use risc0_povw_guests::RISC0_POVW_LOG_BUILDER_ID;
use risc0_zkvm::Digest;

mod common;

#[tokio::test]
async fn basic() -> anyhow::Result<()> {
    let signer = PrivateKeySigner::random();
    let chain_id = 31337;
    let contract_address = address!("0x0000000000000000000000000000000000000f00");

    let update = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: Digest::new(rand::random()),
        updated_commit: Digest::new(rand::random()),
        update_value: 5,
        work_log_id: signer.address().into(),
    };

    let signature =
        WorkLogUpdate::from(update.clone()).sign(&signer, contract_address, chain_id).await?;

    let input = Input {
        update: update.clone(),
        signature: signature.as_bytes().to_vec(),
        contract_address,
        chain_id,
    };
    let journal = common::execute_log_updater_guest(&input)?;

    assert_eq!(journal.update.workLogId, signer.address());
    assert_eq!(journal.update.initialCommit, B256::from(<[u8; 32]>::from(update.initial_commit)));
    assert_eq!(journal.update.updatedCommit, B256::from(<[u8; 32]>::from(update.updated_commit)));
    assert_eq!(journal.update.updateWork, update.update_value);
    assert_eq!(
        journal.eip712Domain,
        WorkLogUpdate::eip712_domain(contract_address, chain_id).hash_struct()
    );
    Ok(())
}

#[tokio::test]
async fn reject_wrong_signer() -> anyhow::Result<()> {
    let signer = PrivateKeySigner::random();
    let chain_id = 31337;
    let contract_address = address!("0x0000000000000000000000000000000000000f00");

    let update = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: Digest::new(rand::random()),
        updated_commit: Digest::new(rand::random()),
        update_value: 5,
        work_log_id: signer.address().into(),
    };

    let wrong_signer = PrivateKeySigner::random();
    let signature =
        WorkLogUpdate::from(update.clone()).sign(&wrong_signer, contract_address, chain_id).await?;

    let input = Input {
        update: update.clone(),
        signature: signature.as_bytes().to_vec(),
        contract_address,
        chain_id,
    };
    let err = common::execute_log_updater_guest(&input).unwrap_err();
    println!("execute_log_updater_guest failed with: {err}");
    assert!(err.to_string().contains("recovered signer does not match expected"));

    Ok(())
}

#[tokio::test]
async fn contract_integration() -> anyhow::Result<()> {
    let ctx = common::text_ctx().await?;

    let initial_epoch = ctx.povw_contract.currentEpoch().call().await?;
    println!("Initial epoch: {}", initial_epoch);

    // Construct and sign a WorkLogUpdate.
    let signer = PrivateKeySigner::random();
    let update = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 10,
        work_log_id: signer.address().into(),
    };

    let update_event = ctx.post_work_log_update(&signer, &update).await?;

    println!("WorkLogUpdated event: {:?}", update_event);
    assert_eq!(update_event.workLogId, Address::from(update.work_log_id));
    assert_eq!(update_event.epochNumber, U256::from(initial_epoch));
    assert_eq!(update_event.initialCommit.as_slice(), update.initial_commit.as_bytes());
    assert_eq!(update_event.updatedCommit.as_slice(), update.updated_commit.as_bytes());
    assert_eq!(update_event.work, U256::from(update.update_value));

    // Advance time to the next epoch and finalize the initial epoch.
    let new_epoch = ctx.advance_epochs(1).await?;
    let finalized_event = ctx.finalize_epoch().await?;

    println!("EpochFinalized event: {:?}", finalized_event);
    assert_eq!(finalized_event.epoch, U256::from(initial_epoch));
    assert_eq!(finalized_event.totalWork, U256::from(update.update_value));

    let pending_epoch = ctx.povw_contract.pendingEpoch().call().await?;
    assert_eq!(pending_epoch.number, new_epoch);
    assert_eq!(pending_epoch.totalWork, U96::ZERO);

    Ok(())
}
