// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

use alloy_sol_types::SolValue;
use boundless_market::contracts::ResolveJournal;
use resolve::{AssumptionReceipt, ResolveInput};
use risc0_aggregation::{RecursionVerifierParamters, SetInclusionReceiptVerifierParameters};
use risc0_zkvm::{
    guest::env,
    sha::{Digest, Digestible},
    SuccinctReceiptVerifierParameters, VerifierContext,
};

fn main() {
    let bytes = env::read_frame();
    let input: ResolveInput = postcard::from_bytes(&bytes).expect("failed to deserialize input");

    // Verify the integrity of the conditional and assumption claims.
    // NOTE: We do not use `verify_integrity` here because that method does not allow for
    // verification of conditional receipts. This is to prevent a footgun in that verifying a
    // conditional receipt tells you nothing unless you also verify the assumptions. Here, we also
    // verify the assumption also potentially through composition and are committing the full
    // receipt claim, making this semantically consistent.
    env::log("verify conditional");
    env::verify_assumption(input.conditional.digest(), Digest::ZERO).unwrap();

    // Remove the head of the assumptions list from the conditional claim.
    let mut claim = input.conditional;
    let assumption = claim
        .output
        .as_value_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .assumptions
        .as_value_mut()
        .unwrap()
        .0
        .remove(0)
        .value()
        .unwrap();

    // Construct the appropriate verifier context, using the control root from the
    // assumption, or default if zero, and the default for other parameters.
    // TODO(victor) Add a `with_control_root` builder method on VerifierContext to do this.
    // NOTE: This guest is bound to the version of the zkVM it was compiled with. Assumptions may
    // have a control root of all zeroes, resolved during recursive verification, howevever we need
    // to supply a concrete control root when directly verifying. Either use the risc0-zkvm
    // default, or the one supplied on the assumption.
    // TODO(victor) Building the Groth16 verifier parameters is really slow. Need to either speed
    // it up dramatically or calculate the verifier parameters at build-time.
    let verifier_context = VerifierContext::empty()
        .with_suites(VerifierContext::default_hash_suites())
        .with_succinct_verifier_parameters({
            let default = SuccinctReceiptVerifierParameters::default();
            SuccinctReceiptVerifierParameters {
                control_root: match assumption.control_root {
                    Digest::ZERO => default.control_root,
                    _ => assumption.control_root,
                },
                ..default
            }
        });
    //    .with_groth16_verifier_parameters({
    //        let default = Groth16ReceiptVerifierParameters::default();
    //        Groth16ReceiptVerifierParameters {
    //            // NOTE: Assumptions may have a control root of all zeroes, resolved during recursive
    //            // verification, howevever we need to supply a concrete control root when directly
    //            // verifying. Either use the risc0-zkvm default, or the one supplied on the
    //            // assumption.
    //            control_root: match assumption.control_root {
    //                Digest::ZERO => default.control_root,
    //                _ => assumption.control_root,
    //            },
    //            ..default
    //        }
    //    });

    // Verify the provided assumption receipt, handling the cases of no receipt provided (by making
    // an assumption), a risc0_zkvm::InnerAssumptionReceipt is provided, and a SetInclusionReceipt
    // is provided.
    match input.assumption {
        AssumptionReceipt::Base(receipt) => {
            let receipt_claim_digest = receipt.claim_digest().unwrap();
            assert_eq!(receipt_claim_digest, assumption.claim, "provided assumption receipt claim digest is not consistent with assumption list on conditional receipt: {} != {}", receipt_claim_digest, assumption.claim);
            env::log("verify base");
            receipt.verify_integrity_with_context(&verifier_context).unwrap();
        }
        AssumptionReceipt::SetInclusion{image_id, receipt} => {
            let receipt_claim_digest = receipt.claim.digest();
            assert_eq!(receipt_claim_digest, assumption.claim, "provided assumption receipt claim digest is not consistent with assumption list on conditional receipt: {} != {}", receipt_claim_digest, assumption.claim);
            env::log("verify set");
            receipt
                .verify_integrity_with_context(
                    &verifier_context,
                    SetInclusionReceiptVerifierParameters { image_id },
                    Some(RecursionVerifierParamters {
                        control_root: (assumption.control_root != Digest::ZERO)
                            .then_some(assumption.control_root),
                    }),
                )
                .unwrap();
        }
        _ => unimplemented!("resolve with the given assumption receipt type is unimplemented"),
    }

    let journal = ResolveJournal {
        claimDigest: <[u8; 32]>::from(claim.digest()).into(),
    };

    env::commit_slice(&journal.abi_encode());
}
