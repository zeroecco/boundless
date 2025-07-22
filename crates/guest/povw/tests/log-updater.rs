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

use alloy::providers::ext::AnvilApi;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{address, aliases::U96, B256, U256};
use alloy_sol_types::SolValue;
use boundless_povw_guests::{
    log_updater::{Input, LogBuilderJournal, WorkLogUpdate},
    BOUNDLESS_POVW_LOG_UPDATER_ID,
};
use risc0_povw::WorkLog;
use risc0_povw_guests::RISC0_POVW_LOG_BUILDER_ID;
use risc0_zkvm::{Digest, FakeReceipt, Receipt, ReceiptClaim};

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
    let chain_id = ctx.anvil.chain_id();
    let contract_address = *ctx.povw_contract.address();

    let update = LogBuilderJournal {
        self_image_id: RISC0_POVW_LOG_BUILDER_ID.into(),
        initial_commit: WorkLog::EMPTY.commit(),
        updated_commit: Digest::new(rand::random()),
        update_value: 10,
        work_log_id: signer.address().into(),
    };

    let signature =
        WorkLogUpdate::from(update.clone()).sign(&signer, contract_address, chain_id).await?;

    // Use execute_log_updater_guest to get a Journal.
    let input = Input {
        update: update.clone(),
        signature: signature.as_bytes().to_vec(),
        contract_address,
        chain_id,
    };
    let journal = common::execute_log_updater_guest(&input)?;
    println!("Guest execution completed, journal: {:#?}", journal);

    let fake_receipt: Receipt =
        FakeReceipt::new(ReceiptClaim::ok(BOUNDLESS_POVW_LOG_UPDATER_ID, journal.abi_encode()))
            .try_into()?;

    // Call the PoVW.updateWorkLog function and confirm that it does not revert.
    let tx_result = ctx
        .povw_contract
        .updateWorkLog(
            journal.update.workLogId,
            journal.update.updatedCommit,
            journal.update.updateWork,
            common::encode_seal(&fake_receipt)?.into(),
        )
        .send()
        .await?;
    println!("updateWorkLog transaction sent: {:?}", tx_result.tx_hash());

    // Query for the expected WorkLogUpdated event.
    let receipt = tx_result.get_receipt().await?;
    let logs = receipt.logs();

    // Find the WorkLogUpdated event
    let work_log_updated_events = logs
        .iter()
        .filter_map(|log| log.log_decode::<common::PoVW::WorkLogUpdated>().ok())
        .collect::<Vec<_>>();

    assert_eq!(work_log_updated_events.len(), 1, "Expected exactly one WorkLogUpdated event");
    let update_event = &work_log_updated_events[0].inner.data;

    println!("WorkLogUpdated event: {:?}", update_event);
    assert_eq!(update_event.workLogId, journal.update.workLogId);
    assert_eq!(update_event.epochNumber, U256::from(initial_epoch));
    assert_eq!(update_event.initialCommit, journal.update.initialCommit);
    assert_eq!(update_event.updatedCommit, journal.update.updatedCommit);
    assert_eq!(update_event.work, U256::from(journal.update.updateWork));

    // Advance time on the Anvil instance, forward to the next epoch.
    let epoch_length = ctx.povw_contract.EPOCH_LENGTH().call().await?;
    let advance_time = epoch_length.to::<u64>();

    ctx.provider.anvil_increase_time(advance_time).await?;
    ctx.provider.anvil_mine(Some(1), None).await?;

    let new_epoch = ctx.povw_contract.currentEpoch().call().await?;
    assert_eq!(new_epoch, initial_epoch + 1, "Epoch should have advanced by 1");
    println!("Time advanced: epoch {} -> {}", initial_epoch, new_epoch);

    // Call finalizeEpoch().
    let finalize_tx = ctx.povw_contract.finalizeEpoch().send().await?;
    println!("finalizeEpoch transaction sent: {:?}", finalize_tx.tx_hash());

    // Check for the epoch number to be advanced and the EpochFinalized event to be emitted.
    let finalize_receipt = finalize_tx.get_receipt().await?;
    let finalize_logs = finalize_receipt.logs();

    // Find the EpochFinalized event
    let epoch_finalized_events = finalize_logs
        .iter()
        .filter_map(|log| log.log_decode::<common::PoVW::EpochFinalized>().ok())
        .collect::<Vec<_>>();

    assert_eq!(epoch_finalized_events.len(), 1, "Expected exactly one EpochFinalized event");
    let finalized_event = &epoch_finalized_events[0].inner.data;

    println!("EpochFinalized event: {:?}", finalized_event);
    assert_eq!(finalized_event.epoch, U256::from(initial_epoch));
    assert_eq!(finalized_event.totalWork, U256::from(journal.update.updateWork));

    let pending_epoch = ctx.povw_contract.pendingEpoch().call().await?;
    assert_eq!(pending_epoch.number, new_epoch);
    assert_eq!(pending_epoch.totalWork, U96::ZERO);

    Ok(())
}
