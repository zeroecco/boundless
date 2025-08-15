// Copyright 2025 RISC Zero, Inc.
//
// Use of this source code is governed by the Business Source License
// as found in the LICENSE-BSL file.

use anyhow::{Context, Result};
use hex::FromHex;
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};
use lz4::block::{compress, decompress};

pub(crate) mod executor;
pub(crate) mod finalize;
pub(crate) mod join;
pub(crate) mod keccak;
pub(crate) mod prove;
pub(crate) mod resolve;
pub(crate) mod snark;
pub(crate) mod union;

/// Recursion receipts key prefix
pub(crate) const RECUR_RECEIPT_PATH: &str = "recur_receipts";

/// Receipts key prefix for redis
pub(crate) const RECEIPT_PATH: &str = "receipts";

/// Reads the [`IMAGE_ID_FILE`] and returns a [Digest]
pub(crate) fn read_image_id(image_id: &str) -> Result<Digest> {
    Digest::from_hex(image_id).context("Failed to convert imageId file to digest from_hex")
}

/// Serializes an object into a Vec<u8> using bincode.
pub(crate) fn serialize_obj<T: Serialize>(item: &T) -> Result<Vec<u8>> {
    bincode::serialize(item).map_err(anyhow::Error::new)
}

/// Serializes and compresses an object using LZ4 for efficient storage.
/// This is much faster than gzip and provides good compression for binary data.
pub(crate) fn serialize_obj_compressed<T: Serialize>(item: &T) -> Result<Vec<u8>> {
    let serialized = bincode::serialize(item)?;
    let compressed = compress(&serialized, None, true)?;

    // Log compression ratio for monitoring
    let compression_ratio = compressed.len() as f64 / serialized.len() as f64;
    if serialized.len() > 1024 { // Only log for data larger than 1KB
        tracing::debug!(
            "Compression: {} -> {} bytes ({:.1}% of original size)",
            serialized.len(),
            compressed.len(),
            compression_ratio * 100.0
        );
    }

    Ok(compressed)
}

/// Deserializes an encoded function
pub(crate) fn deserialize_obj<T: for<'de> Deserialize<'de>>(encoded: &[u8]) -> Result<T> {
    let decoded = bincode::deserialize(encoded)?;
    Ok(decoded)
}

/// Smart deserialization that automatically detects if data is compressed.
/// This provides backward compatibility with both compressed and uncompressed data.
pub(crate) fn deserialize_obj_smart<T: for<'de> Deserialize<'de>>(encoded: &[u8]) -> Result<T> {
    // Try to decompress first (LZ4 compressed data)
    if let Ok(decompressed) = decompress(encoded, None) {
        // If decompression succeeds, deserialize the decompressed data
        let decoded = bincode::deserialize(&decompressed)?;
        return Ok(decoded);
    }

    // If decompression fails, try to deserialize directly (uncompressed data)
    let decoded = bincode::deserialize(encoded)?;
    Ok(decoded)
}
