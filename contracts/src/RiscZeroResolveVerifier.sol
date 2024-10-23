// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

pragma solidity ^0.8.20;

import {MerkleProof} from "openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {
    IRiscZeroVerifier, Receipt, ReceiptClaim, ReceiptClaimLib, VerificationFailed
} from "risc0/IRiscZeroVerifier.sol";

import {IImageInfo} from "./IImageInfo.sol";

/// @notice Error raised when this verifier receives a receipt with a selector that does not match
///         its own. The selector value is calculated from the verifier parameters, and so this
///         usually indicates a mismatch between the version of the prover and this verifier.
error SelectorMismatch(bytes4 received, bytes4 expected);

/// @notice RiscZeroResolveVerifier is a
contract RiscZeroResolveVerifier is IRiscZeroVerifier, IImageInfo {
    using ReceiptClaimLib for ReceiptClaim;

    /// @notice A short key attached to the seal to select the correct verifier implementation.
    /// @dev The selector is taken from the hash of the verifier parameters including the Groth16
    ///      verification key and the control IDs that commit to the RISC Zero circuits. If two
    ///      receipts have different selectors (i.e. different verifier parameters), then it can
    ///      generally be assumed that they need distinct verifier implementations. This is used as
    ///      part of the RISC Zero versioning mechanism.
    ///
    ///      A selector is not intended to be collision resistant, in that it is possible to find
    ///      two preimages that result in the same selector. This is acceptable since it's purpose
    ///      to a route a request among a set of trusted verifiers, and to make errors of sending a
    ///      receipt to a mismatching verifiers easier to debug. It is analogous to the ABI
    ///      function selectors.
    bytes4 public immutable SELECTOR;

    IRiscZeroVerifier public immutable VERIFIER;
    bytes32 private immutable IMAGE_ID;
    string private imageUrl;

    constructor(IRiscZeroVerifier verifier, bytes32 imageId, string memory _imageUrl) {
        VERIFIER = verifier;
        IMAGE_ID = imageId;
        imageUrl = _imageUrl;

        SELECTOR = bytes4(
            sha256(
                abi.encodePacked(
                    // tag
                    sha256("risc0.ResolveReceiptVerifierParameters"),
                    // down
                    imageId,
                    // down length
                    uint16(1) << 8
                )
            )
        );
    }

    /// @inheritdoc IRiscZeroVerifier
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) public view {
        _verifyIntegrity(seal, ReceiptClaimLib.ok(imageId, journalDigest).digest());
    }

    /// @inheritdoc IRiscZeroVerifier
    function verifyIntegrity(Receipt calldata receipt) public view {
        _verifyIntegrity(receipt.seal, receipt.claimDigest);
    }

    /// @notice internal implementation of verifyIntegrity, factored to avoid copying calldata bytes to memory.
    function _verifyIntegrity(bytes calldata seal, bytes32 claimDigest) internal view {
        // Check that the seal has a matching selector. Mismatch generally indicates that the
        // prover and this verifier are using different parameters, and so the verification
        // will not succeed.
        if (SELECTOR != bytes4(seal[:4])) {
            revert SelectorMismatch({received: bytes4(seal[:4]), expected: SELECTOR});
        }

        // Call the underlying RISC Zero verifier to with the Resolve guest
        // image ID to check that the guest verified a receipt with a matching
        // claim digest.
        VERIFIER.verify(seal[4:], IMAGE_ID, sha256(abi.encodePacked(claimDigest)));
    }

    /// @inheritdoc IImageInfo
    function imageInfo() external view returns (bytes32, string memory) {
        return (IMAGE_ID, imageUrl);
    }
}
