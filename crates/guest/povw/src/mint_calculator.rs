// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

//! Shared library for the Mint Calculator guest between guest and host.

use std::{
    collections::BTreeMap,
    ops::{Add, AddAssign},
};

use alloy_primitives::{Address, U256};
use alloy_sol_types::sol;
use risc0_steel::{
    ethereum::{EthChainSpec, EthEvmEnv, EthEvmInput},
    Commitment, StateDb, SteelVerifier,
};
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

#[derive(Clone, Serialize, Deserialize)]
pub struct MutltiblockEthEvmInput(pub Vec<EthEvmInput>);

impl MutltiblockEthEvmInput {
    pub fn into_env(self, chain_spec: &EthChainSpec) -> MultiblockEthEvmEnv<StateDb, Commitment> {
        // Converts the input into `EvmEnv` structs for execution.
        let mut multiblock_env = MultiblockEthEvmEnv(Default::default());
        for env_input in self.0 {
            let env = env_input.into_env(chain_spec);
            if let Some(collision) = multiblock_env.0.insert(env.header().number, env) {
                // NOTE: This could instead be handled via extending the original, if that was
                // available in the guest. But keeping things constrained is reasonable.
                panic!("more than one env input provided for block {}", collision.header().number);
            };
        }
        // Verify the the envs form a subsequence of a since chain. This is a required check, and so
        // we do it here before returning the env for the user to make queries.
        multiblock_env.verify_continuity();
        multiblock_env
    }
}

/// An ordered map of block numbers to [EthEvmEnv] that form a subsequence in a single chain.
pub struct MultiblockEthEvmEnv<Db, Commit>(pub BTreeMap<u64, EthEvmEnv<Db, Commit>>);

impl MultiblockEthEvmEnv<StateDb, Commitment> {
    /// Ensure that the [EthEvmEnv] in this multiblock env form a subsequence of blocks from a since
    /// chain, all blocks being an ancestor of the latest block.
    fn verify_continuity(&mut self) {
        // NOTE: We don't check that the map is non-empty here.
        self.0.values().reduce(|env_prev, env| {
            SteelVerifier::new(env).verify(env_prev.commitment());
            env
        });
    }

    /// Return the commitment to the last block in the subsequence, which indirectly commitment to
    /// all blocks in this environment.
    pub fn commitment(&self) -> Option<&Commitment> {
        self.0.values().last().map(|env| env.commitment())
    }
}

#[cfg(feature = "host")]
pub mod host {
    use alloy_provider::Provider;
    use anyhow::Context;
    use risc0_steel::{
        alloy::network::Ethereum,
        beacon::BeaconCommit,
        ethereum::{EthBlockHeader, EthEvmFactory},
        host::{
            db::{ProofDb, ProviderDb},
            Beacon, BlockNumberOrTag, EvmEnvBuilder, HostCommit,
        },
        BlockHeaderCommit,
    };

    use super::*;

    impl<P, C> MultiblockEthEvmEnv<ProofDb<ProviderDb<Ethereum, P>>, HostCommit<C>>
    where
        P: Provider + Clone + 'static,
        C: Clone + BlockHeaderCommit<EthBlockHeader>,
    {
        /// Preflight the verification that the blocks in the multiblock environment form a
        /// subsequence of a single chain.
        ///
        /// NOTE: The verify call within the guest occurs atomically with
        /// [MutltiblockEthEvmInput::into_env]. If this method is not called by the host, the
        /// conversion of the input into an env will fail in the guest, as the required Merkle
        /// proofs will not be available.
        pub async fn preflight_verify_continuity(&mut self) -> anyhow::Result<()> {
            let mut env_iter = self.0.values_mut();
            let Some(mut env_prev) = env_iter.next() else {
                // If the env is empty, return early as it is a trivial subsequence.
                return Ok(());
            };
            for env in env_iter {
                SteelVerifier::preflight(env)
                    .verify(&env_prev.commitment())
                    .await
                    .with_context(|| format!("failed to preflight SteelVerifier verify of commit for {} using env of block {}", env.header().number, env_prev.header().number))?;
                env_prev = env;
            }
            Ok(())
        }
    }

    // TODO(povw): Based on how this is implemented right now, the caller must provide a chain of block
    // number that can be verified via chaining with SteelVerifier. This means, for example, if there
    // is a 3 days gap in the subsequence of blocks I am processing, I need to additionally provide 2-3
    // more blocks in the middle of that gap. Additionally, using the history feature for the final
    // commit is not supported, so if the last block is e.g. 36 days ago an additional block needs to be
    // provided at the end that is within the EIP-4788 expiration time.
    pub struct MultiblockEthEvmEnvBuilder<P, B> {
        builder: EvmEnvBuilder<P, EthEvmFactory, &'static EthChainSpec, B>,
        block_refs: Vec<BlockNumberOrTag>,
    }

    impl<P, B> MultiblockEthEvmEnvBuilder<P, B> {
        pub fn block_numbers<Id: Into<BlockNumberOrTag>>(
            self,
            numbers: impl IntoIterator<Item = Id>,
        ) -> Self {
            Self { block_refs: numbers.into_iter().map(Into::into).collect(), ..self }
        }
    }

    impl<P: Provider + Clone> MultiblockEthEvmEnvBuilder<P, ()> {
        pub async fn build(
            self,
        ) -> anyhow::Result<MultiblockEthEvmEnv<ProofDb<ProviderDb<Ethereum, P>>, HostCommit<()>>>
        {
            let mut multiblock_env = MultiblockEthEvmEnv(Default::default());
            for block_ref in self.block_refs {
                let mut env = self.builder.clone().block_number_or_tag(block_ref).build().await?;
                let block_number = env.header().number;
                // If the name block is specified multiple times, merge the envs.
                if let Some(existing_env) = multiblock_env.0.remove(&block_number) {
                    env = existing_env.merge(env).with_context(|| {
                        format!("conflicting blocks with number {block_number}")
                    })?;
                };
                multiblock_env.0.insert(block_number, env).unwrap();
            }
            Ok(multiblock_env)
        }
    }

    // TODO(povw): Deduplicate these two blocks. They are duplicated right now due to type system
    // challenges.
    impl<P: Provider + Clone> MultiblockEthEvmEnvBuilder<P, Beacon> {
        pub async fn build(
            self,
        ) -> anyhow::Result<
            MultiblockEthEvmEnv<ProofDb<ProviderDb<Ethereum, P>>, HostCommit<BeaconCommit>>,
        > {
            let mut multiblock_env = MultiblockEthEvmEnv(Default::default());
            for block_ref in self.block_refs {
                let mut env = self.builder.clone().block_number_or_tag(block_ref).build().await?;
                let block_number = env.header().number;
                // If the name block is specified multiple times, merge the envs.
                if let Some(existing_env) = multiblock_env.0.remove(&block_number) {
                    env = existing_env.merge(env).with_context(|| {
                        format!("conflicting blocks with number {block_number}")
                    })?;
                };
                multiblock_env.0.insert(block_number, env).unwrap();
            }
            Ok(multiblock_env)
        }
    }

    type EthEvmEnvBuilder<P, B> =
        EvmEnvBuilder<ProofDb<ProviderDb<Ethereum, P>>, EthEvmFactory, &'static EthChainSpec, B>;

    impl<P: Provider> From<EthEvmEnvBuilder<P, Beacon>>
        for MultiblockEthEvmEnvBuilder<ProofDb<ProviderDb<Ethereum, P>>, Beacon>
    {
        fn from(builder: EthEvmEnvBuilder<P, Beacon>) -> Self {
            Self { builder, block_refs: Vec::new() }
        }
    }

    impl<P: Provider> From<EthEvmEnvBuilder<P, ()>>
        for MultiblockEthEvmEnvBuilder<ProofDb<ProviderDb<Ethereum, P>>, ()>
    {
        fn from(builder: EthEvmEnvBuilder<P, ()>) -> Self {
            Self { builder, block_refs: Vec::new() }
        }
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
    /// Input for constructing a [MultiblockEthEvmEnv] to query a sequence of blocks.
    pub env: MutltiblockEthEvmInput,
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
