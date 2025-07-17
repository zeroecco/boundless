use alloy_sol_types::sol;
use risc0_zkvm::guest::env;
// TODO: Provide a way to fix this value to a reproducible build for deployment.
use risc0_povw_guests::RISC0_POVW_LOG_BUILDER_ID;

// NOTE: Copied from PoVW.sol. Must be kept in sync.
// TODO: Avoid copying this data type here.
sol! {
    struct WorkLogUpdate {
        address workLogId;
        bytes32 initialCommit;
        bytes32 updatedCommit;
        uint64 updateWork;
    }
}

fn main() {
    // TODO: Implement this guest:
    // 1. Verify one or more claims from the povw-log-builder.
    // 2. Combine the work log updates with the same work log ID into a single update per ID.
    // 3. Verify a signature from the log owner (workLogId) over the final update.
    // 4. ABI encode and commit the results.
    env::commit_slice(&RISC0_POVW_LOG_BUILDER_ID);
}
