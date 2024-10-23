// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

pragma solidity ^0.8.20;

interface IImageInfo {
    /// Returns the imageId and public URL for the associated guest binary (ELF).
    function imageInfo() external view returns (bytes32, string memory);
}
