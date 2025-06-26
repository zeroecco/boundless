// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "risc0/IRiscZeroSetVerifier.sol";
import {Steel} from "risc0/steel/Steel.sol";
import {IERC20} from "openzeppelin/contracts/token/ERC20/ERC20.sol";

interface IERC20Mint is IERC20 {
    /// A sender-authorized mint function as a placeholder for a real minting mechanism.
    function mint(address to, uint256 value) external;
}

struct MintCalculatorUpdate {
    address workLogId;
    uint256 initialEpoch;
    uint256 finalEpoch;
}

struct MintCalculatorJournal {
    address recipient;
    uint256 value;
    MintCalculatorUpdate[] updates;
    Steel.Commitment steelCommit;
}

contract Mint {
    IRiscZeroVerifier internal immutable VERIFIER;
    IERC20Mint internal immutable TOKEN;

    /// Image ID of the mint calculator guest. The mint calculator ensures:
    /// * Mint authorization is signed by the ECDSA key associated with each included work log.
    /// * An event was logged by the PoVW contract for each log update and epoch finalization.
    ///   * Events are logged by the expected contract on the expected network.
    ///   * Each event is counted at most once.
    /// * Mint value is calculated correctly from the PoVW totals in each included epoch.
    bytes32 internal immutable MINT_CALCULATOR_ID;

    /// Mapping from work log ID to the most recent epoch for which a mint has occurred. Each time
    /// a mint occurs associated with a work log, this value ratchets forward.
    mapping(address => uint256) internal lastMintEpoch;

    constructor(IRiscZeroVerifier verifier, bytes32 mintCalculatorId, IERC20Mint token) {
        VERIFIER = verifier;
        MINT_CALCULATOR_ID = mintCalculatorId;
        TOKEN = token;
    }

    function mint(MintCalculatorJournal calldata journal, bytes calldata seal) external {
        VERIFIER.verify(seal, MINT_CALCULATOR_ID, sha256(abi.encode(journal)));
        require(Steel.validateCommitment(journal.steelCommit));

        // Ensure the initial epoch for each update is correct and update the lastMintEpoch.
        for (uint256 i = 0; i < journal.updates.length; i++) {
            MintCalculatorUpdate calldata update = journal.updates[i];
            require(update.initialEpoch == lastMintEpoch[update.workLogId]);
            lastMintEpoch[update.workLogId] = update.finalEpoch;
        }

        TOKEN.mint(journal.recipient, journal.value);
    }
}
