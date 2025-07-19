use std::collections::{btree_map, BTreeMap};

use risc0_zkvm::guest::env;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolValue;
use boundless_povw_guests::mint_calculator::{
    FixedPoint, IPoVW, Input, MintCalculatorJournal, MintCalculatorMint, MintCalculatorUpdate,
};
use risc0_steel::{
    ethereum::{EthEvmEnv, ETH_SEPOLIA_CHAIN_SPEC},
    Event, EvmBlockHeader, SteelVerifier,
};

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
    // TODO(povw): Use borsh.
    let input: Input = env::read();

    // Converts the input into a `EvmEnv` structs for execution.
    let envs = input.envs.into_env();

    // Construct a mapping with the total work value for each finalized epoch.
    let mut epochs = BTreeMap::<u32, U256>::new();
    for env in envs.0.values() {
        // Query all `EpochFinalized` events of the PoVW contract.
        // TODO(povw): This is possibly wasteful, in that only a subset will have this event.
        let epoch_finalized_events =
            Event::new::<IPoVW::EpochFinalized>(env).address(input.povw_contract_address).query();

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
    for env in envs.0.values() {
        // Query all `WorkLogUpdated` events of the PoVW contract.
        // TODO(povw): This is possibly wasteful, in that only a subset will have this event.
        let update_events =
            Event::new::<IPoVW::WorkLogUpdated>(env).address(input.povw_contract_address).query();

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
            .map(|(recipient, value)| MintCalculatorMint { recipient, value })
            .collect(),
        updates: updates
            .into_iter()
            .map(|(log_id, commits)| MintCalculatorUpdate {
                workLogId: log_id,
                initialCommit: commits.0,
                finalCommit: commits.1,
            })
            .collect(),
        povwContractAddress: input.povw_contract_address,
        steelCommit: envs.commitment().clone(),
    };
    env::commit_slice(&journal.abi_encode());
}
