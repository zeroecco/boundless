// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.
pragma solidity ^0.8.20;

import {RequestId} from "./RequestId.sol";
import {PredicateType} from "./Predicate.sol";

using FulfillmentLibrary for Fulfillment global;

/// @title Fulfillment Struct and Library
/// @notice Represents the information posted by the prover to fulfill a request and get paid.
struct Fulfillment {
    /// @notice ID of the request that is being fulfilled.
    RequestId id;
    /// @notice EIP-712 digest of request struct.
    bytes32 requestDigest;
    /// @notice The `PredicateType` of the request that is being fulfilled.
    /// @dev When the `PredicateType` is `ClaimDigestMatch`, the imageIdOrClaimDigest field is the claim digest,
    /// and otherwise it is the image ID of the guest that was executed.
    PredicateType predicateType;
    /// @notice Image ID of the guest that was verifiably executed to satisfy the request or claim digest.
    /// @dev Must match the value in the request's requirements. If the journal and journal digest do not need
    /// to be delivered to the client, imageId is replaced with claim digest, since it is captured in the
    /// requirements on the request, checked by the Assessor guest.
    bytes32 imageIdOrClaimDigest;
    /// @notice Journal committed by the guest program execution.
    /// @dev The journal is checked to satisfy the predicate specified on the request's requirements.
    bytes journal;
    /// @notice Cryptographic proof for the validity of the execution results.
    /// @dev This will be sent to the `IRiscZeroVerifier` associated with this contract.
    bytes seal;
}

library FulfillmentLibrary {}
