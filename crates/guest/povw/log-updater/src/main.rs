use alloy_primitives::{Address, Signature, B256};
use alloy_sol_types::{eip712_domain, sol, Eip712Domain, SolStruct, SolValue};
use anyhow::{bail, Context};
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_povw::guest::Journal as LogBuilderJournal;
use risc0_povw_guests::RISC0_POVW_LOG_BUILDER_ID;
use risc0_zkvm::guest::env;
use ruint::aliases::U160;
use serde::{Deserialize, Serialize};

// TODO(povw): Provide a way to fix this value to a reproducible build for deployment.

// NOTE: Copied from PoVW.sol. Must be kept in sync.
// TODO: Avoid copying this data type here.
sol! {
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

    /* TODO
    /// Signs the request with the given signer and EIP-712 domain derived from the given
    /// contract address and chain ID.
    pub async fn sign_request(
        &self,
        signer: &impl Signer,
        contract_addr: Address,
        chain_id: u64,
    ) -> Result<Signature, alloy::signers::Error> {
        signer
            .sign_hash(&self.signing_hash(contract_addr, chain_id))
            .await
    }
    */

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

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Input {
    update: LogBuilderJournal,
    signature: Vec<u8>,
    #[borsh(
        deserialize_with = "borsh_deserialize_address",
        serialize_with = "borsh_serialize_address"
    )]
    contract_address: Address,
    chain_id: u64,
}

fn main() -> anyhow::Result<()> {
    let input: Input = borsh::from_slice(&env::read_frame())?;

    // Verify that the update was produced by the work log builder.
    // NOTE: The povw log builder supports self-recursion by accepting its own image ID as input.
    // This means the verifier must check the value `self_image_id` written to the journal.
    env::verify(RISC0_POVW_LOG_BUILDER_ID, &borsh::to_vec(&input.update)?)?;
    assert_eq!(input.update.self_image_id, RISC0_POVW_LOG_BUILDER_ID.into());

    // Convert the input to the Solidity struct and verify the EIP-712 signature, using the work
    // log ID as the authenticating party.
    let update = WorkLogUpdate::from(input.update);
    update
        .verify_signature(
            update.workLogId,
            &input.signature,
            input.contract_address,
            input.chain_id,
        )
        .context("failed to verify signature on work log update")?;

    // Write the journal, including the EIP-712 domain hash for the verifying contract.
    let journal = Journal {
        update,
        eip712Domain: WorkLogUpdate::eip712_domain(input.contract_address, input.chain_id)
            .hash_struct(),
    };
    env::commit_slice(&journal.abi_encode());
    Ok(())
}
