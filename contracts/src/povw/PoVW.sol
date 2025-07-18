// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "risc0/IRiscZeroSetVerifier.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

struct WorkLogUpdate {
    address workLogId;
    bytes32 initialCommit;
    bytes32 updatedCommit;
    uint64 updateWork;
}

struct Journal {
    WorkLogUpdate update;
    /// EIP712 domain digest. The verifying contract must validate this to be equal to it own
    /// expected EIP712 domain digest.
    bytes32 eip712Domain;
}

struct PendingEpoch {
    uint96 totalWork;
    uint32 number;
}

contract PoVW is EIP712 {
    IRiscZeroVerifier public immutable VERIFIER;

    /// Precomputed value of the empty work log root. This is expected to be the initial commit of any new log.
    bytes32 public constant EMPTY_LOG_ROOT = hex"180fedca06656cb910077013ad2679695090269fad1589e290162fe90e97d4aa";

    // TODO: Update this with the work log updater. Should the updater commit the builder ID to make it more flexible?
    /// Image ID of the work log builder guest. The log builder ensures:
    /// * Update authorization is signed by the ECDSA key associated with the log ID.
    /// * State transition from initial to updated root is append-only.
    /// * The update value is equal to the sum of work associated with new proofs.
    bytes32 public immutable LOG_UPDATER_ID;

    uint256 public constant EPOCH_LENGTH = 7 days;

    mapping(address => bytes32) internal workLogRoots;

    PendingEpoch internal pendingEpoch;

    event EpochFinalized(uint256 indexed epoch, uint256 totalWork);
    // TODO: Compress the data in this event? epochNumber is a simple view function of the block timestamp.
    /// @notice Event emitted when when a work log update is processed.
    /// @param workLogId The work log identifier, which also serves as an authentication public key.
    /// @param epochNumber The number of the epoch in which the update is processed.
    ///        The value of the update will be weighted against the total work completed in this epoch.
    /// @param initialCommit The initial work log commitment for the update.
    /// @param updatedCommit The updated work log commitment after the update has been processed.
    /// @param work Value of the work in this update.
    event WorkLogUpdated(
        address indexed workLogId, uint256 epochNumber, bytes32 initialCommit, bytes32 updatedCommit, uint256 work
    );

    constructor(IRiscZeroVerifier verifier, bytes32 logUpdaterId) EIP712("PoVW", "1") {
        VERIFIER = verifier;
        LOG_UPDATER_ID = logUpdaterId;

        pendingEpoch = PendingEpoch({number: currentEpoch(), totalWork: 0});
    }

    function currentEpoch() public view returns (uint32) {
        // NOTE: Casting to uint32 should never overflow with the value block.timestamp being a UNIX
        // timestamp (seconds since Jan 1 1970) and the epoch length being a day or more.
        return uint32(block.timestamp / EPOCH_LENGTH);
    }

    /// Finalize the pending epoch, logging the finalized epoch number and total work.
    function finalizeEpoch() public {
        require(pendingEpoch.number < currentEpoch(), "pending epoch has not ended");

        // Emit the epoch finalized event, accessed with Steel to construct the mint authorization.
        emit EpochFinalized(uint256(pendingEpoch.number), uint256(pendingEpoch.totalWork));

        // NOTE: This may cause the epoch number to increase by more than 1, if no updates occurred in
        // an interim epoch. Any interim epoch that was skipped will have no work associated with it.
        pendingEpoch = PendingEpoch({number: currentEpoch(), totalWork: 0});
    }

    /// Update a work log and log an event with the associated update value (i.e. the work that was
    /// completed since the last update).
    ///
    /// This stored work log root is updated, preventing the same nonce from being counted twice.
    /// Work reported in this update will be assigned to the current epoch. A receipt from the work
    /// log builder is used to ensure the integrity of the update.
    ///
    /// If an epoch is pending finalization, this occurs atomically with this call.
    function updateWorkLog(address workLogId, bytes32 updatedCommit, uint64 updateWork, bytes calldata seal) public {
        if (pendingEpoch.number < currentEpoch()) {
            finalizeEpoch();
        }

        // Fetch the initial commit value, substituting with the precomputed empty root if new.
        bytes32 initialCommit = workLogRoots[workLogId];
        if (initialCommit == bytes32(0)) {
            initialCommit = EMPTY_LOG_ROOT;
        }

        // Verify the receipt from the work log builder, binding the initial root as the currently
        // stored value. Note that for a new work log, this will be all zeroes.
        WorkLogUpdate memory update = WorkLogUpdate({
            workLogId: workLogId,
            initialCommit: initialCommit,
            updatedCommit: updatedCommit,
            updateWork: updateWork
        });
        Journal memory journal = Journal({update: update, eip712Domain: _domainSeparatorV4()});
        VERIFIER.verify(seal, LOG_UPDATER_ID, sha256(abi.encode(journal)));

        workLogRoots[workLogId] = updatedCommit;
        pendingEpoch.totalWork += updateWork;

        // Emit the update event, accessed with Steel to construct the mint authorization.
        // Note that there is no restriction on multiple updates in the same epoch. Posting more than
        // one update in an epoch strictly increases the gas costs and proving work required for mint.
        emit WorkLogUpdated(workLogId, currentEpoch(), update.initialCommit, update.updatedCommit, uint256(updateWork));
    }
}
