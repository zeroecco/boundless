// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

//! Shared library for the Log Updater guest between guest and host.

use alloy_primitives::{Address, Signature, B256};
use alloy_sol_types::{eip712_domain, sol, Eip712Domain, SolStruct};
use anyhow::bail;

use borsh::{BorshDeserialize, BorshSerialize};
// Re-export types from risc0_povw for use in the log updater guest.
pub use risc0_povw::guest::Journal as LogBuilderJournal;
pub use risc0_povw_guests::RISC0_POVW_LOG_BUILDER_ID;
use ruint::aliases::U160;
use serde::{Deserialize, Serialize};

// TODO(povw): Provide a way to fix RISC0_POVW_LOG_BUILDER_ID value to a reproducible build for deployment.

// NOTE: Copied from PoVW.sol. Must be kept in sync.
// TODO(povw): Avoid copying this data type here.
sol! {
    #[derive(Debug)]
    struct WorkLogUpdate {
        address workLogId;
        bytes32 initialCommit;
        bytes32 updatedCommit;
        uint64 updateWork;
    }

    #[derive(Debug)]
    struct Journal {
        WorkLogUpdate update;
        /// EIP712 domain digest. The verifying contract must validate this to be equal to it own
        /// expected EIP712 domain digest.
        bytes32 eip712Domain;
    }
}

impl WorkLogUpdate {
    pub fn eip712_domain(contract_addr: Address, chain_id: u64) -> Eip712Domain {
        eip712_domain! {
            name: "PoVW",
            version: "1",
            chain_id: chain_id,
            verifying_contract: contract_addr,
        }
    }

    /// Returns the EIP-712 signing hash for the [WorkLogUpdate].
    pub fn signing_hash(&self, contract_addr: Address, chain_id: u64) -> B256 {
        self.eip712_signing_hash(&Self::eip712_domain(contract_addr, chain_id))
    }

    /// Signs the request with the given signer and EIP-712 domain derived from the given
    /// contract address and chain ID.
    #[cfg(feature = "signer")]
    pub async fn sign(
        &self,
        signer: &impl alloy_signer::Signer,
        contract_addr: Address,
        chain_id: u64,
    ) -> Result<Signature, alloy_signer::Error> {
        signer.sign_hash(&self.signing_hash(contract_addr, chain_id)).await
    }

    /// Verifies the [WorkLogUpdate] signature with the given signer and EIP-712 domain derived
    /// from the given contract address and chain ID.
    pub fn verify_signature(
        &self,
        signer: Address,
        signature: impl AsRef<[u8]>,
        contract_addr: Address,
        chain_id: u64,
    ) -> anyhow::Result<()> {
        let sig = Signature::try_from(signature.as_ref())?;
        let addr = sig.recover_address_from_prehash(&self.signing_hash(contract_addr, chain_id))?;
        if addr == signer {
            Ok(())
        } else {
            bail!("recovered signer does not match expected: {addr} != {signer}")
        }
    }
}

impl From<LogBuilderJournal> for WorkLogUpdate {
    fn from(value: LogBuilderJournal) -> Self {
        Self {
            workLogId: value.work_log_id.into(),
            initialCommit: <[u8; 32]>::from(value.initial_commit).into(),
            updatedCommit: <[u8; 32]>::from(value.updated_commit).into(),
            updateWork: value.update_value,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Input {
    pub update: LogBuilderJournal,
    pub signature: Vec<u8>,
    #[borsh(
        deserialize_with = "borsh_deserialize_address",
        serialize_with = "borsh_serialize_address"
    )]
    pub contract_address: Address,
    pub chain_id: u64,
}

fn borsh_deserialize_address(
    reader: &mut impl borsh::io::Read,
) -> Result<Address, borsh::io::Error> {
    Ok(<U160 as BorshDeserialize>::deserialize_reader(reader)?.into())
}

fn borsh_serialize_address(
    address: &Address,
    writer: &mut impl borsh::io::Write,
) -> Result<(), borsh::io::Error> {
    <U160 as BorshSerialize>::serialize(&(*address).into(), writer)?;
    Ok(())
}
