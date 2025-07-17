// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

#![allow(unused_imports)] // DO NOT MERGE

// TODO(povw): This test is fragile to changes in the RISC0_POVW_LOG_BUILDER_ID, because the ID
// used here and the one used in the log updater guest may drift. Running the following command may
// fix a drift if it appears.
//
// ```
// cargo update -p risc0-povw-guests --manifest-path Cargo.toml && cargo update -p risc0-povw-guests --manifest-path crates/guest/povw/log-updater/Cargo.toml
// ```

use boundless_povw_guests::{BOUNDLESS_POVW_LOG_UPDATER_ELF, BOUNDLESS_POVW_LOG_UPDATER_ID};
use risc0_povw_guests::{RISC0_POVW_LOG_BUILDER_ELF, RISC0_POVW_LOG_BUILDER_ID};
use risc0_zkvm::{
    default_executor, Digest, ExecutorEnv, ExitCode, FakeReceipt, MaybePruned, ReceiptClaim,
    Unknown, Work, WorkClaim,
};

// TODO: Add rejection tests

fn execute_guest() -> anyhow::Result<()> {
    let env = ExecutorEnv::builder().build()?;
    // NOTE: Use the executor to run tests without proving.
    let session_info = default_executor().execute(env, BOUNDLESS_POVW_LOG_UPDATER_ELF)?;
    assert_eq!(session_info.exit_code, ExitCode::Halted(0));

    let decoded_journal: [u8; 32] = session_info.journal.bytes.try_into().unwrap();
    println!("decoded_journal: {decoded_journal:?}");

    assert_eq!(bytemuck::cast::<_, [u32; 8]>(decoded_journal), RISC0_POVW_LOG_BUILDER_ID);
    Ok(())
}

#[test]
fn smoke() -> anyhow::Result<()> {
    execute_guest()
}
