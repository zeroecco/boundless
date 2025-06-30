// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

#[tokio::test]
async fn basic() -> anyhow::Result<()> {
    // 1. Create an Anvil instance.
    // 2. Deploy PoVW and Mint contracts to the Anvil instance, using a MockRiscZeroVerifier and a
    //    basic ERC-20.
    // 3. Post a single work log update to the PoVW contract.
    // 4. Advance time by 1 epoch.
    // 5. Finalize the epoch.
    // 6. Query for WorkLogUpdated and EpochFinalized events, recording the block numbers that
    //    include these events.
    // 7. Preflight the Steel queries that the guest will make to assemble the guest input.
    // 8. Run the mint calculator guest.
    // 9. Assemble a fake receipt and use it to call the mint function on the Mint contract.
    // 10. Verify that the minted values are as expected.
    todo!()
}
