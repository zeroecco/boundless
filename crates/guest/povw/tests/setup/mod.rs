// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

#![allow(unused_imports)] // DO NOT MERGE

use alloy::{
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{DynProvider, Provider, ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_primitives::B256;
use anyhow::bail;
use boundless_povw_guests::{
    mint_calculator::host::IMint::IMintInstance, BOUNDLESS_POVW_LOG_UPDATER_ID,
    BOUNDLESS_POVW_MINT_CALCULATOR_ID,
};
use risc0_ethereum_contracts::selector::Selector;
use risc0_zkvm::{sha::Digestible, InnerReceipt};

// Import the Solidity contracts using alloy's sol! macro
// Use the compiled contracts output to allow for deploying the contracts.
// NOTE: This requires running `forge build` before running this test.
// TODO: Work on making this more robust.
sol!(
    #[sol(rpc)]
    MockRiscZeroVerifier,
    "../../../out/RiscZeroMockVerifier.sol/RiscZeroMockVerifier.json"
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    MockERC20Mint,
    "../../../out/MockERC20Mint.sol/MockERC20Mint.json"
);

sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    PoVW,
    "../../../out/PoVW.sol/PoVW.json"
);

sol!(
    #[sol(rpc)]
    Mint,
    "../../../out/Mint.sol/Mint.json"
);

pub struct TextCtx {
    pub anvil: AnvilInstance,
    pub provider: DynProvider,
    pub povw_contract: PoVW::PoVWInstance<DynProvider>,
    pub mint_contract: IMintInstance<DynProvider>,
}

pub async fn text_ctx() -> anyhow::Result<TextCtx> {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint_url();

    // Create wallet and provider
    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url).erased();

    // Deploy PoVW and Mint contracts to the Anvil instance, using a MockRiscZeroVerifier and a
    // basic ERC-20.

    // Deploy MockRiscZeroVerifier
    let mock_verifier =
        MockRiscZeroVerifier::deploy(provider.clone(), FixedBytes([0xFFu8; 4])).await?;
    println!("MockRiscZeroVerifier deployed at: {:?}", mock_verifier.address());

    // Deploy MockERC20 token
    let mock_token = MockERC20Mint::deploy(provider.clone()).await?;
    println!("MockERC20 deployed at: {:?}", mock_token.address());

    // Deploy PoVW contract (needs verifier and log builder ID)
    let povw_contract = PoVW::deploy(
        provider.clone(),
        *mock_verifier.address(),
        bytemuck::cast::<_, [u8; 32]>(BOUNDLESS_POVW_LOG_UPDATER_ID).into(),
    )
    .await?;
    println!("PoVW contract deployed at: {:?}", povw_contract.address());

    // Deploy Mint contract (needs verifier, povw, mint calculator ID, and token)
    let mint_contract = Mint::deploy(
        provider.clone(),
        *mock_verifier.address(),
        *povw_contract.address(),
        bytemuck::cast::<_, [u8; 32]>(BOUNDLESS_POVW_MINT_CALCULATOR_ID).into(),
        *mock_token.address(),
    )
    .await?;
    println!("Mint contract deployed at: {:?}", mint_contract.address());

    // Cast the deployed MintInstance to an IMintInstance from the source crate, which is
    // considered a fully independent type by Rust.
    let mint_interface = IMintInstance::new(*mint_contract.address(), provider.clone());

    Ok(TextCtx { anvil, provider, povw_contract, mint_contract: mint_interface })
}

// TODO(povw): This is copied from risc0_ethereum_contracts to work around version conflict
// issues. Remove this when we use a published version of risc0.
pub fn encode_seal(receipt: &risc0_zkvm::Receipt) -> anyhow::Result<Vec<u8>> {
    let seal = match receipt.inner.clone() {
        InnerReceipt::Fake(receipt) => {
            let seal = receipt.claim.digest().as_bytes().to_vec();
            let selector = &[0xFFu8; 4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(&seal);
            selector_seal
        }
        _ => bail!("Unsupported receipt type"),
    };
    Ok(seal)
}

// Execute the log updater guest with the given input
pub fn execute_log_updater_guest(
    input: &boundless_povw_guests::log_updater::Input,
) -> anyhow::Result<boundless_povw_guests::log_updater::Journal> {
    use alloy_sol_types::SolValue;
    use boundless_povw_guests::BOUNDLESS_POVW_LOG_UPDATER_ELF;
    use risc0_povw_guests::RISC0_POVW_LOG_BUILDER_ID;
    use risc0_zkvm::{default_executor, ExecutorEnv, ExitCode, FakeReceipt, ReceiptClaim};

    let log_builder_receipt = FakeReceipt::new(ReceiptClaim::ok(
        RISC0_POVW_LOG_BUILDER_ID,
        borsh::to_vec(&input.update)?,
    ));
    let env = ExecutorEnv::builder()
        .write_frame(&borsh::to_vec(input)?)
        .add_assumption(log_builder_receipt)
        .build()?;
    let session_info = default_executor().execute(env, BOUNDLESS_POVW_LOG_UPDATER_ELF)?;
    assert_eq!(session_info.exit_code, ExitCode::Halted(0));

    let decoded_journal =
        boundless_povw_guests::log_updater::Journal::abi_decode(&session_info.journal.bytes)?;
    Ok(decoded_journal)
}

// Execute the mint calculator guest with the given input
pub fn execute_mint_calculator_guest(
    input: &boundless_povw_guests::mint_calculator::Input,
) -> anyhow::Result<boundless_povw_guests::mint_calculator::MintCalculatorJournal> {
    use alloy_sol_types::SolValue;
    use boundless_povw_guests::BOUNDLESS_POVW_MINT_CALCULATOR_ELF;
    use risc0_zkvm::{default_executor, ExecutorEnv, ExitCode};

    let env = ExecutorEnv::builder().write(input)?.build()?;
    let session_info = default_executor().execute(env, BOUNDLESS_POVW_MINT_CALCULATOR_ELF)?;
    assert_eq!(session_info.exit_code, ExitCode::Halted(0));

    let decoded_journal =
        boundless_povw_guests::mint_calculator::MintCalculatorJournal::abi_decode(
            &session_info.journal.bytes,
        )?;
    Ok(decoded_journal)
}
