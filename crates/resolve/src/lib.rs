// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;

use aggregation_set::SetInclusionReceipt;
use risc0_binfmt::Digestible;
use risc0_zkvm::{sha, sha::Digest, ReceiptClaim};
use serde::{Deserialize, Serialize};

/// Receipt attesting to the validity of an assumption.
///
/// This enum is an extension of [risc0_zkvm::AssumptionReceipt], adding a variant to support
/// [SetInclusionReceipt] so that aggregated receipts can be used to resolve assumptions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AssumptionReceipt<Claim>
where
    Claim: Digestible + Debug + Clone + Serialize,
{
    Base(risc0_zkvm::AssumptionReceipt),
    // TODO(victor): Use Unknown here when upgrading to 1.1, to match risc0_zkvm.
    SetInclusion(SetInclusionReceipt<Claim>),
}

impl<Claim> AssumptionReceipt<Claim>
where
    Claim: Digestible + Debug + Clone + Serialize,
{
    /// Returns the digest of the claim for this [AssumptionReceipt].
    pub fn claim_digest(&self) -> Result<Digest, anyhow::Error> {
        Ok(match self {
            Self::Base(r) => r.claim_digest()?,
            Self::SetInclusion(r) => r.claim.digest::<sha::Impl>(),
        })
    }
}

/// Input of the Resolve guest.
///
/// Resolve guest takes as input two claims, one that is conditional on the other. It verifies both
/// there is a proof for the conditional claim, and that there is a proof for the assumption and
/// then removes the assumption from the conditional claim, as it is no longer assumed, it is
/// proven.
// TODO(victor) Accept a self_image_id as inpput and commit as output in order to use resolve
// multiple times on the same receipt, and/or add the ability to pass in multiple assumption
// receipts to resolve all the assumptions in one go.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolveInput {
    /// Conditional claim on which we want to resolve an assumption.
    ///
    /// The conditional claim will be verified by composition, using the recursion circuit to
    /// verify the existence of a [SuccinctReceipt][risc0_zkvm::SuccinctReceipt] attesting to the
    /// validity of the claim. This receipt should be added to the
    /// [ExecutorEnv][risc0_zkvm::ExecutorEnv] when proving the (rv32im) resolve program.
    pub conditional: ReceiptClaim,
    /// Receipt attesting to the validity of the assumption.
    ///
    /// If the given receipt is `AssumptionReceipt::Unresolved`, it will be verified via
    /// composition, adding an assumption to the resulting receipt.
    // TODO(victor): Handling of unresolved receipts is sound, although not particularly useful
    // outside of testing. Consider dropping this by using InnerAssumptionReceipt instead of a
    // AssumptionReceipt as the base enum.
    pub assumption: AssumptionReceipt<ReceiptClaim>,
}

impl ResolveInput {
    // TOOD: Use write_frame instead of generating the concatenated buffer here.
    pub fn to_vec(&self) -> Vec<u8> {
        let bytes = postcard::to_allocvec(self).unwrap();
        let length = bytes.len() as u32;
        let mut result = Vec::with_capacity(4 + bytes.len());
        result.extend_from_slice(&length.to_le_bytes());
        result.extend_from_slice(&bytes);
        result
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use aggregation_set::{SetInclusionReceipt, SET_BUILDER_GUEST_ELF, SET_BUILDER_GUEST_ID};
    use alloy_sol_types::SolValue;
    use anyhow::anyhow;
    use guest_resolve::{RESOLVE_GUEST_ELF, RESOLVE_GUEST_ID};
    use guest_util::{ECHO_ELF, ECHO_ID, IDENTITY_ELF, IDENTITY_ID};
    use rand::Rng;
    use risc0_zkvm::{
        default_prover, get_prover_server,
        sha::{Digest, Digestible},
        ExecutorEnv, ExecutorImpl, InnerReceipt, ProveInfo, ProverOpts, Receipt, VerifierContext,
    };
    use test_log::test;

    use super::*;

    /// Produce a receipt for the guest execution.
    fn prove(env: ExecutorEnv, elf: &[u8]) -> anyhow::Result<Receipt> {
        tracing::debug!("starting proving");
        let ProveInfo { receipt, stats } =
            default_prover().prove_with_opts(env, elf, &ProverOpts::succinct())?;
        tracing::debug!("finished proving: {:#?}", stats);
        Ok(receipt)
    }

    fn echo(input: &str) -> anyhow::Result<Receipt> {
        let env = ExecutorEnv::builder().write(&input.as_bytes())?.build()?;
        prove(env, ECHO_ELF)
    }

    /// Run the identity guest with the given receipt, leaving the assumption unresolved.
    fn identity_conditional(input: &Receipt) -> anyhow::Result<Receipt> {
        let claim = input.claim()?.value()?;
        let env = ExecutorEnv::builder().write(&claim)?.add_assumption(claim).build()?;

        if risc0_zkvm::is_dev_mode() {
            return prove(env, IDENTITY_ELF);
        }

        // TODO(victor): Figure out a way to get a conditional receipt without using the prover server
        // or api client directly. Also make prove_segment work in dev mode, because there is no
        // reason it shouldn't.
        // Compress the segments, but don't resolve any assumptions.
        let session = ExecutorImpl::from_elf(env, IDENTITY_ELF)?.run()?;
        let prover = get_prover_server(&ProverOpts::succinct())?;
        let conditional_receipt = session
            .segments
            .iter()
            .map(|segment| {
                let segment_receipt =
                    prover.prove_segment(&VerifierContext::default(), &segment.resolve()?)?;
                prover.lift(&segment_receipt)
            })
            .reduce(|left, right| prover.join(&left?, &right?))
            .expect("empty session")?;

        Ok(Receipt::new(
            InnerReceipt::Succinct(conditional_receipt),
            session.journal.unwrap().bytes,
        ))
    }

    /// Produce receipt for an aggregation of the given list of receipts.
    fn build_set(mut receipts: Vec<Receipt>) -> anyhow::Result<Receipt> {
        match receipts.len() {
            0 => Err(anyhow!("Receipt list is empty, cannot compute Merkle root")),
            1 => singleton_set(receipts.pop().unwrap()),
            _ => {
                // Split the list into two halves
                let mut right = receipts;
                let left = right.split_off(right.len().next_power_of_two() / 2);
                let left_set = build_set(left)?;
                let right_set = build_set(right)?;
                join_set(left_set, right_set)
            }
        }
    }

    fn singleton_set(receipt: Receipt) -> anyhow::Result<Receipt> {
        let guest_input = aggregation_set::GuestInput::Singleton {
            self_image_id: Digest::from(SET_BUILDER_GUEST_ID),
            claim: receipt.claim().unwrap().value().unwrap(),
        };
        let env = ExecutorEnv::builder()
            .write(&guest_input)
            .unwrap()
            .add_assumption(receipt)
            .build()
            .unwrap();
        prove(env, SET_BUILDER_GUEST_ELF)
    }

    fn join_set(left_set: Receipt, right_set: Receipt) -> anyhow::Result<Receipt> {
        let left_set_out = aggregation_set::GuestOutput::abi_decode(&left_set.journal.bytes, true)?;
        let right_set_out =
            aggregation_set::GuestOutput::abi_decode(&right_set.journal.bytes, true)?;
        let guest_input = aggregation_set::GuestInput::Join {
            self_image_id: Digest::from(SET_BUILDER_GUEST_ID),
            left_set_root: left_set_out.root(),
            right_set_root: right_set_out.root(),
        };
        let env = ExecutorEnv::builder()
            .write(&guest_input)
            .unwrap()
            .add_assumption(left_set)
            .add_assumption(right_set)
            .build()
            .unwrap();
        prove(env, SET_BUILDER_GUEST_ELF)
    }

    #[test]
    fn basic() {
        let echo_receipt = echo("echo... echo... echo...").unwrap();
        echo_receipt.verify(ECHO_ID).unwrap();

        let conditional_receipt = identity_conditional(&echo_receipt).unwrap();
        conditional_receipt.verify(IDENTITY_ID).unwrap_err();

        let input = ResolveInput {
            conditional: conditional_receipt.claim().unwrap().value().unwrap(),
            assumption: AssumptionReceipt::Base(
                echo_receipt.claim().unwrap().value().unwrap().into(),
            ),
        };

        // Proving should fail if the assumption receipt is not provided.
        let env = ExecutorEnv::builder()
            .write_slice(&input.to_vec())
            .add_assumption(conditional_receipt.clone())
            .build()
            .unwrap();
        let err = prove(env, RESOLVE_GUEST_ELF).unwrap_err();
        assert!(err.to_string().contains("no receipt found to resolve assumption"));

        // Proving should fail if the conditional_receipt is not provided.
        let env = ExecutorEnv::builder()
            .write_slice(&input.to_vec())
            .add_assumption(echo_receipt.clone())
            .build()
            .unwrap();
        let err = prove(env, RESOLVE_GUEST_ELF).unwrap_err();
        assert!(err.to_string().contains("no receipt found to resolve assumption"));

        let env = ExecutorEnv::builder()
            .write_slice(&input.to_vec())
            .add_assumption(conditional_receipt)
            .add_assumption(echo_receipt)
            .build()
            .unwrap();
        let receipt = prove(env, RESOLVE_GUEST_ELF).unwrap();
        receipt.verify(RESOLVE_GUEST_ID).unwrap();

        let resolved_claim_digest = Digest::try_from(receipt.journal.bytes).unwrap();
        assert_eq!(resolved_claim_digest, ReceiptClaim::ok(IDENTITY_ID, vec![]).digest());
    }

    #[test]
    fn resolve_with_singleton_set_inclusion() {
        let echo_receipt = echo("echo... echo... echo...").unwrap();
        echo_receipt.verify(ECHO_ID).unwrap();
        let echo_claim = echo_receipt.claim().unwrap();

        // Produce the conditional receipt. Verifying it should fail.
        let conditional_receipt = identity_conditional(&echo_receipt).unwrap();
        conditional_receipt.verify(IDENTITY_ID).unwrap_err();

        let singleton_receipt = singleton_set(echo_receipt.clone()).unwrap();
        // NOTE: A root is not provided since we'll resolve the root assumption via composition. We
        // use fake receipts in this test, but this mirrors the case where the prover has a STARK
        // receipt for the root.
        let singleton_inclusion_receipt = SetInclusionReceipt::from_path(
            echo_claim.clone(),
            aggregation_set::merkle_path(&[echo_claim.digest()], 0).unwrap(),
        );

        let input = ResolveInput {
            conditional: conditional_receipt.claim().unwrap().value().unwrap(),
            assumption: AssumptionReceipt::SetInclusion(singleton_inclusion_receipt),
        };

        // Run with the conditional receipt, and the set receipt for the singleton as assumptions.
        let env = ExecutorEnv::builder()
            .write_slice(&input.to_vec())
            .add_assumption(conditional_receipt)
            .add_assumption(singleton_receipt)
            .build()
            .unwrap();
        let receipt = prove(env, RESOLVE_GUEST_ELF).unwrap();
        receipt.verify(RESOLVE_GUEST_ID).unwrap();

        let resolved_claim_digest = Digest::try_from(receipt.journal.bytes).unwrap();
        assert_eq!(resolved_claim_digest, ReceiptClaim::ok(IDENTITY_ID, vec![]).digest());
    }

    #[test]
    #[ignore = "does not work in dev mode"]
    fn resolve_with_singleton_set_inclusion_with_root() {
        let echo_receipt = echo("echo... echo... echo...").unwrap();
        echo_receipt.verify(ECHO_ID).unwrap();
        let echo_claim = echo_receipt.claim().unwrap();

        // Produce the conditional receipt. Verifying it should fail.
        let conditional_receipt = identity_conditional(&echo_receipt).unwrap();
        conditional_receipt.verify(IDENTITY_ID).unwrap_err();

        let singleton_receipt = singleton_set(echo_receipt.clone()).unwrap();
        let singleton_inclusion_receipt = SetInclusionReceipt::from_path(
            echo_claim.clone(),
            aggregation_set::merkle_path(&[echo_claim.digest()], 0).unwrap(),
        )
        .with_root(singleton_receipt);

        let input = ResolveInput {
            conditional: conditional_receipt.claim().unwrap().value().unwrap(),
            assumption: AssumptionReceipt::SetInclusion(singleton_inclusion_receipt),
        };

        // HACK: You can turn on dev mode at this point to avoid proving the recursive verification.
        // std::env::set_var("RISC0_DEV_MODE", "1");

        // Run with the conditional receipt as an assumptions and the set receipt containing a
        // succinct STARK receipt for direct verification of the root.
        // NOTE: Direct verification of a poseidon2 SuccinctReceipt takes about 300M cycles.
        let env = ExecutorEnv::builder()
            .write_slice(&input.to_vec())
            .add_assumption(conditional_receipt)
            .build()
            .unwrap();
        let receipt = prove(env, RESOLVE_GUEST_ELF).unwrap();
        receipt.verify(RESOLVE_GUEST_ID).unwrap();

        let resolved_claim_digest = Digest::try_from(receipt.journal.bytes).unwrap();
        assert_eq!(resolved_claim_digest, ReceiptClaim::ok(IDENTITY_ID, vec![]).digest());
    }

    #[test]
    fn resolve_with_set_inclusion() {
        let echo_receipt = echo("echo... echo... echo...").unwrap();
        echo_receipt.verify(ECHO_ID).unwrap();
        let echo_claim = echo_receipt.claim().unwrap();

        // Produce the conditional receipt. Verifying it should fail.
        let conditional_receipt = identity_conditional(&echo_receipt).unwrap();
        conditional_receipt.verify(IDENTITY_ID).unwrap_err();

        // Generate a list of random receipts and insert the echo receipt at a random index.
        let mut rng = rand::thread_rng();
        let mut receipt_set: Vec<Receipt> = (0..rng.gen_range(2..32))
            .map(|i| echo(&format!("{}", i)))
            .collect::<Result<_, _>>()
            .unwrap();
        let echo_index = rng.gen_range(0..receipt_set.len());
        receipt_set[echo_index] = echo_receipt;

        let set_receipt = build_set(receipt_set.clone()).unwrap();
        let set_inclusion_receipt = SetInclusionReceipt::from_path(
            echo_claim,
            aggregation_set::merkle_path(
                &receipt_set.iter().map(|r| r.claim().unwrap().digest()).collect::<Vec<_>>(),
                echo_index,
            )
            .unwrap(),
        );

        let input = ResolveInput {
            conditional: conditional_receipt.claim().unwrap().value().unwrap(),
            assumption: AssumptionReceipt::SetInclusion(set_inclusion_receipt),
        };

        // Run with the conditional receipt, and the set root receipt as assumptions.
        let env = ExecutorEnv::builder()
            .write_slice(&input.to_vec())
            .add_assumption(conditional_receipt)
            .add_assumption(set_receipt)
            .build()
            .unwrap();
        let receipt = prove(env, RESOLVE_GUEST_ELF).unwrap();
        receipt.verify(RESOLVE_GUEST_ID).unwrap();

        let resolved_claim_digest = Digest::try_from(receipt.journal.bytes).unwrap();
        assert_eq!(resolved_claim_digest, ReceiptClaim::ok(IDENTITY_ID, vec![]).digest());
    }
}
