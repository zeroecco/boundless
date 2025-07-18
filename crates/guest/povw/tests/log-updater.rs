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
use alloy_primitives::{address, B256};
use alloy_sol_types::SolValue;
use boundless_povw_guests::{
    log_updater::{Input, Journal, LogBuilderJournal, WorkLogUpdate},
    BOUNDLESS_POVW_LOG_UPDATER_ELF,
};
use risc0_povw_guests::RISC0_POVW_LOG_BUILDER_ID;
use risc0_zkvm::{default_executor, Digest, ExecutorEnv, ExitCode, FakeReceipt, ReceiptClaim};

mod setup;

// TODO: Add rejection tests

fn execute_guest(input: &Input) -> anyhow::Result<Journal> {
    println!("log updater input: {input:#?}");
    let log_builder_receipt = FakeReceipt::new(ReceiptClaim::ok(
        RISC0_POVW_LOG_BUILDER_ID,
        borsh::to_vec(&input.update)?,
    ));
    let env = ExecutorEnv::builder()
        .write_frame(&borsh::to_vec(input)?)
        .add_assumption(log_builder_receipt)
        .build()?;
    // NOTE: Use the executor to run tests without proving.
    let session_info = default_executor().execute(env, BOUNDLESS_POVW_LOG_UPDATER_ELF)?;
    assert_eq!(session_info.exit_code, ExitCode::Halted(0));

    println!("foo");

    let decoded_journal = Journal::abi_decode(&session_info.journal.bytes)?;
    println!("log updater journal: {decoded_journal:#?}");

    Ok(decoded_journal)
}

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
    let journal = execute_guest(&input)?;

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
    let err = execute_guest(&input).unwrap_err();
    println!("execute_guest failed with: {err}");
    assert!(err.to_string().contains("recovered signer does not match expected"));

    Ok(())
}

#[tokio::test]
async fn contract_integration() -> anyhow::Result<()> {
    let ctx = setup::text_ctx().await?;

    // 1. Check the current epoch.
    // 2. Construct and sign a WorkLogUpdate.
    // 3. Use execute_guest to get a Journal.
    // 4. Create a FakeReceipt for the journal.
    // 5. Call the PoVW.updateWorkLog function and confirm that it does not revert.
    // 6. Query for the expected WorkLogUpdated event.
    // 7. Check for the expected change to the workLogRoots.
    // 8. Advance time on the AnvilInstance (using the AnvilApi trait on the provider).
    // 9. Call finalizeEpoch().
    // 10. Check for the epoch number to be advanced and the EpochFinalized event to be emitted.
    todo!()
}
