// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "risc0/IRiscZeroSetVerifier.sol";

struct WorkLogUpdate {
    address id;
    bytes32 initialRoot;
    bytes32 updatedRoot;
    uint64 updateValue;
}

contract PoVW {
    IRiscZeroVerifier internal immutable VERIFIER;

    /// Image ID of the work log builder guest. The log builder ensures:
    /// * Update authorization is signed by the ECDSA key associated with the log ID.
    /// * State transition from initial to updated root is append-only.
    /// * The update value is equal to the sum of work associated with new proofs.
    bytes32 internal immutable LOG_BUILDER_ID;

    mapping(address => bytes32) internal workLogRoots;

    uint256 internal pendingEpoch;
    uint256 internal pendingEpochTotal;

    event EpochFinalized(uint256 indexed epoch, uint256 totalWork);
    event WorkLogUpdated(address indexed id, uint256 epoch, uint256 work);

    constructor(IRiscZeroVerifier verifier, bytes32 logBuilderId) {
        VERIFIER = verifier;
        LOG_BUILDER_ID = logBuilderId;

        pendingEpoch = currentEpoch();
    }

    function currentEpoch() public view returns (uint256) {
        return block.timestamp / 1 days;
    }

    /// Finalize the pending epoch, logging the finalized epoch number and total work.
    function finalizeEpoch() public {
        require(pendingEpoch < currentEpoch());

        // Emit the epoch finalized event, accessed with Steel to construct the mint authorization.
        emit EpochFinalized(pendingEpoch, pendingEpochTotal);

        // NOTE: This may cause the epoch number to increase by more than 1, if no updates occurred in
        // an interim epoch. Any interim epoch that was skipped will have no work associated with it.
        pendingEpoch = currentEpoch();
        pendingEpochTotal = 0;
    }

    /// Update a work log and log an event with the associated update value (i.e. the work that was
    /// completed since the last update).
    ///
    /// This stored work log root is updated, preventing the same nonce from being counted twice.
    /// Work reported in this update will be assigned to the current epoch. A receipt from the work
    /// log builder is used to ensure the integrity of the update.
    ///
    /// If an epoch is pending finalization, this occurs atomically with this call.
    function updateWorkLog(address id, bytes32 updatedRoot, uint64 updateValue, bytes calldata seal) public {
        if (pendingEpoch < currentEpoch()) {
            finalizeEpoch();
        }

        // Verify the receipt from the work log builder, binding the initial root as the currently
        // stored value. Note that for a new work log, this will be all zeroes.
        WorkLogUpdate memory update =
            WorkLogUpdate({id: id, initialRoot: workLogRoots[id], updatedRoot: updatedRoot, updateValue: updateValue});
        VERIFIER.verify(seal, LOG_BUILDER_ID, sha256(abi.encode(update)));

        workLogRoots[id] = updatedRoot;

        // Emit the update event, accessed with Steel to construct the mint authorization.
        // Note that there is no restriction on multiple updates in the same epoch. Posting more than
        // one update in an epoch strictly increases the gas costs and proving work required for mint.
        emit WorkLogUpdated(id, currentEpoch(), updateValue);
    }
}
