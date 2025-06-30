use std::{
    collections::{btree_map, BTreeMap},
    ops::{Add, AddAssign},
};

use risc0_zkvm::guest::env;

use alloy_primitives::{address, Address, B256, U256};
use alloy_sol_types::{sol, SolValue};
use risc0_steel::{
    ethereum::{EthEvmEnv, EthEvmInput, ETH_SEPOLIA_CHAIN_SPEC},
    Commitment, Contract, Event, EvmBlockHeader, EvmEnv, SteelVerifier,
};
use serde::{Deserialize, Serialize};

/// Address of the deployed contract to query.
const POVW_CONTRACT_ADDRESS: Address = address!("0x0000000000000000000000000000000000000001");

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

    struct MintCalculatorMint {
        address recipient;
        uint256 value;
    }

    struct MintCalculatorJournal {
        MintCalculatorMint[] mints;
        MintCalculatorUpdate[] updates;
        Commitment steelCommit;
    }
}

#[derive(Serialize, Deserialize)]
struct Input {
    /// Vec of [EthEvmInput] for each block accessed in this execution.
    pub env: Vec<EthEvmInput>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
struct FixedPoint(U256);

impl FixedPoint {
    const DECIMALS: usize = 18;

    /// Construct a fixed-point representation of a fractional value.
    ///
    /// # Panics
    ///
    /// Panics if the given numerator is too close to U256::MAX, or if the represented fraction
    /// greater than one (e.g. numerator > denominator).
    fn fraction(num: U256, dem: U256) -> Self {
        let base = U256::from(10).pow(U256::from(Self::DECIMALS));
        let fraction = num.checked_mul(base).unwrap() / dem;
        assert!(fraction <= base, "expected fractional value is greater than one");
        Self(fraction)
    }
}

impl Add for FixedPoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for FixedPoint {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

// The mint calculator ensures:
// * An event was logged by the PoVW contract for each log update and epoch finalization.
//   * Each event is counted at most once.
//   * Events from an unbroken chain from initialCommit to finalCommit. This constitutes an
//     exhaustiveness check such that the prover cannot exclude updates, and thereby deny a reward.
// * Mint value is calculated correctly from the PoVW totals in each included epoch.
//   * An event was logged by the PoVW contract for epoch finalization.
//   * The total work from the epoch finalization event is used in the mint calculation.
//   * The mint recipient is set correctly.
fn main() {
    // Read the input from the guest environment.
    // TODO: Use postcard or another codec instead of the default.
    let input: Input = env::read();

    // Converts the input into a `EvmEnv` structs for execution.
    let envs: BTreeMap<u64, EthEvmEnv<_, _>> = input
        .env
        .into_iter()
        .map(|env_input| {
            let env = env_input.into_env(&ETH_SEPOLIA_CHAIN_SPEC);
            (env.header().number(), env)
        })
        .collect();

    // Ensure that the envs form a valid chain from the earlier block to the latest block.
    let mut env_prev =
        envs.values().nth(1).expect("mint calculator requires at least one block as input");
    for env in envs.values() {
        SteelVerifier::new(env).verify(env_prev.commitment());
        env_prev = env;
    }

    // Construct a mapping with the total work value for each finalized epoch.
    let mut epochs = BTreeMap::<u32, U256>::new();
    for env in envs.values() {
        // Query all `EpochFinalized` events of the PoVW contract.
        // TODO: This is possibly wasteful, in that only a subset will have this event.
        let epoch_finalized_events =
            Event::new::<IPoVW::EpochFinalized>(env).address(POVW_CONTRACT_ADDRESS).query();

        for epoch_finalized_event in epoch_finalized_events {
            let epoch_number = epoch_finalized_event.epoch.to::<u32>();
            let None = epochs.insert(epoch_number, epoch_finalized_event.totalWork) else {
                panic!("multiple epoch finalized events for epoch {epoch_number}");
            };
        }
    }

    // Construct the mapping of mints, as recipient address to mint proportion pairs, and the
    // mapping of work log id to (initial commit, final commit) pairs.
    let mut mints = BTreeMap::<Address, FixedPoint>::new();
    let mut updates = BTreeMap::<Address, (B256, B256)>::new();
    for env in envs.values() {
        // Query all `WorkLogUpdated` events of the PoVW contract.
        // TODO: This is possibly wasteful, in that only a subset will have this event.
        let update_events =
            Event::new::<IPoVW::WorkLogUpdated>(env).address(POVW_CONTRACT_ADDRESS).query();

        for update_event in update_events {
            match updates.entry(update_event.logId) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((update_event.initialCommit, update_event.updatedCommit));
                }
                btree_map::Entry::Occupied(mut entry) => {
                    assert_eq!(
                        entry.get().1,
                        update_event.initialCommit,
                        "multiple update events for {} that do not form a chain",
                        update_event.logId
                    );
                    entry.get_mut().1 = update_event.updatedCommit;
                }
            }

            // TODO: Consider minting to an address that is not nessesarily the log id.
            let epoch_number = update_event.epochNumber.to::<u32>();
            let epoch_total_work = *epochs.get(&epoch_number).unwrap_or_else(|| {
                panic!("no epoch finalized event processed for epoch number {epoch_number}")
            });
            *mints.entry(update_event.logId).or_default() +=
                FixedPoint::fraction(update_event.work, epoch_total_work);
        }
    }

    let journal = MintCalculatorJournal {
        mints: mints
            .into_iter()
            .map(|(recipient, value)| MintCalculatorMint { recipient, value: value.0 })
            .collect(),
        updates: updates
            .into_iter()
            .map(|(log_id, commits)| MintCalculatorUpdate {
                workLogId: log_id,
                initialCommit: commits.0,
                finalCommit: commits.1,
            })
            .collect(),
        steelCommit: envs.values().last().unwrap().commitment().clone(),
    };
    env::commit_slice(&journal.abi_encode());
}
