// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

//! Shared library for the Mint Calculator guest between guest and host.

use std::ops::{Add, AddAssign};

use alloy_primitives::{Address, U256};
use alloy_sol_types::sol;
use risc0_steel::{ethereum::EthEvmInput, Commitment};
use serde::{Deserialize, Serialize};

sol! {
    // Copied from contracts/src/povw/PoVW.sol
    interface IPoVW {
        event EpochFinalized(uint256 indexed epoch, uint256 totalWork);
        event WorkLogUpdated(
            address indexed logId, uint256 epochNumber, bytes32 initialCommit, bytes32 updatedCommit, uint256 work
        );
    }

    // Copied from contracts/src/povw/Mint.sol
    struct MintCalculatorUpdate {
        address workLogId;
        bytes32 initialCommit;
        bytes32 finalCommit;
    }

    #[derive(Default)]
    struct FixedPoint {
        uint256 value;
    }

    struct MintCalculatorMint {
        address recipient;
        FixedPoint value;
    }

    struct MintCalculatorJournal {
        MintCalculatorMint[] mints;
        MintCalculatorUpdate[] updates;
        address povwContractAddress;
        Commitment steelCommit;
    }
}

#[derive(Serialize, Deserialize)]
pub struct Input {
    /// Address of the PoVW contract to query.
    ///
    /// It is not possible to be assured that this is the correct contract when the guest is
    /// running, and so the behavior of the contract may deviate from expected. If the prover did
    /// supply the wrong address, the proof will be rejected by the Mint contract when it checks
    /// the address written to the journal.
    pub povw_contract_address: Address,
    /// Vec of [EthEvmInput] for each block accessed in this execution.
    pub env: Vec<EthEvmInput>,
}

impl FixedPoint {
    const BASE: U256 = U256::ONE.checked_shl(64).unwrap();

    /// Construct a fixed-point representation of a fractional value.
    ///
    /// # Panics
    ///
    /// Panics if the given numerator is too close to U256::MAX, or if the represented fraction
    /// greater than one (e.g. numerator > denominator).
    pub fn fraction(num: U256, dem: U256) -> Self {
        let fraction = num.checked_mul(Self::BASE).unwrap() / dem;
        assert!(fraction <= Self::BASE, "expected fractional value is greater than one");
        Self { value: fraction }
    }
}

impl Add for FixedPoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self { value: self.value + rhs.value }
    }
}

impl AddAssign for FixedPoint {
    fn add_assign(&mut self, rhs: Self) {
        self.value += rhs.value
    }
}
