// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use std::{path::PathBuf, sync::Arc, time::Duration};

use alloy::{
    consensus::Transaction,
    primitives::{utils::parse_ether, Address, Bytes, U256},
    providers::{network::EthereumWallet, Provider, ProviderBuilder, WalletProvider, WsConnect},
    rpc::types::Log,
    signers::local::PrivateKeySigner,
    sol_types::SolCall,
};
use alloy_chains::NamedChain;
use anyhow::{bail, Context, Result};
use balance_alerts_layer::{BalanceAlertConfig, BalanceAlertLayer};
use boundless_cli::DefaultProver;
use boundless_market::{
    contracts::{boundless_market::BoundlessMarketService, IBoundlessMarket},
    order_stream_client::{order_stream, Client as OrderStreamClient},
};
use broker::{
    config::{ConfigLock, ConfigWatcher},
    provers::{self, ProverObj},
};
use clap::Parser;
use futures::StreamExt;
use libroker::{now_timestamp_secs, Order, OrderLockTiming, PriceOrderErr, State};
use risc0_ethereum_contracts::set_verifier::SetVerifierService;
use tokio::{
    sync::{watch, Semaphore},
    task::JoinSet,
};
use url::Url;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// RPC URL
    #[clap(long, env, default_value = "ws://localhost:8545")]
    rpc_ws_url: Url,

    /// Order stream server URL
    #[clap(long, env)]
    order_stream_url: Option<Url>,

    /// wallet key
    #[clap(long, env)]
    private_key: PrivateKeySigner,

    /// Boundless market address
    #[clap(long, env)]
    boundless_market_address: Address,

    /// Risc zero Set verifier address
    // TODO: Get this from the market contract via view call
    #[clap(long, env)]
    set_verifier_address: Address,

    /// local prover API (Bento)
    ///
    /// Setting this value toggles using Bento for proving and disables Bonsai
    #[clap(long, env, default_value = "http://localhost:8081", conflicts_with_all = ["bonsai_api_url", "bonsai_api_key"])]
    bento_api_url: Option<Url>,

    /// Bonsai API URL
    ///
    /// Toggling this disables Bento proving and uses Bonsai as a backend
    #[clap(long, env, conflicts_with = "bento_api_url")]
    bonsai_api_url: Option<Url>,

    /// Bonsai API Key
    ///
    /// Required if using BONSAI_API_URL
    #[clap(long, env, conflicts_with = "bento_api_url")]
    bonsai_api_key: Option<String>,

    /// Config file path
    #[clap(short, long, default_value = "broker.toml")]
    config_file: PathBuf,

    /// Pre deposit amount
    ///
    /// Amount of HP tokens to pre-deposit into the contract for staking eg: 100
    #[clap(short, long)]
    deposit_amount: Option<U256>,
    // /// RPC HTTP retry rate limit max retry
    // ///
    // /// From the `RetryBackoffLayer` of Alloy
    // #[clap(long, default_value_t = 10)]
    // rpc_retry_max: u32,

    // /// RPC HTTP retry backoff (in ms)
    // ///
    // /// From the `RetryBackoffLayer` of Alloy
    // #[clap(long, default_value_t = 1000)]
    // rpc_retry_backoff: u64,

    // /// RPC HTTP retry compute-unit per second
    // ///
    // /// From the `RetryBackoffLayer` of Alloy
    // #[clap(long, default_value_t = 100)]
    // rpc_retry_cu: u64,
    // /// Set to skip caching of images
    // ///
    // /// By default images are cached locally in cache_dir. Set this flag to redownload them every time
    // #[arg(long, action = ArgAction::SetTrue)]
    // nocache: bool,

    // /// Cache directory for storing downloaded images and inputs
    // #[clap(long, default_value = "/tmp/broker_cache", conflicts_with = "nocache")]
    // cache_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config_watcher =
        ConfigWatcher::new(&args.config_file).await.context("Failed to load broker config")?;
    let config = config_watcher.config.clone();

    let wallet = EthereumWallet::from(args.private_key.clone());
    let broker_address = args.private_key.address();

    let (balance_warn_threshold, balance_error_threshold, max_concurrent_locks, tx_timeout) = {
        let config = config.lock_all()?;
        (
            config.market.balance_warn_threshold.clone(),
            config.market.balance_error_threshold.clone(),
            config.market.max_concurrent_locks,
            config.batcher.txn_timeout,
        )
    };
    // let rpc_client = RpcClient::builder().layer(retry_layer).http(args.rpc_url.clone());
    let balance_alerts_layer = BalanceAlertLayer::new(BalanceAlertConfig {
        watch_address: wallet.default_signer().address(),
        warn_threshold: balance_warn_threshold.map(|s| parse_ether(&s)).transpose()?,
        error_threshold: balance_error_threshold.map(|s| parse_ether(&s)).transpose()?,
    });

    let ws = WsConnect::new(args.rpc_ws_url.clone());
    let provider = ProviderBuilder::new()
        .layer(balance_alerts_layer)
        .wallet(wallet)
        .with_chain(NamedChain::Sepolia)
        .on_ws(ws)
        .await?;

    let chain_id = provider.get_chain_id().await.context("Failed to get chain ID")?;

    let prover = get_prover(&config, &args)?;

    // Order Stream
    let client = args
        .order_stream_url
        .clone()
        .map(|url| OrderStreamClient::new(url, args.boundless_market_address, chain_id))
        // TODO make order stream optional
        .unwrap();
    let socket = client.connect_async(&args.private_key).await?;
    let mut orders = order_stream(socket);

    // Chain Monitoring
    let mut blocks_stream = provider.subscribe_blocks().await?.into_stream();

    let boundless_market = BoundlessMarketService::new(
        args.boundless_market_address,
        provider.clone(),
        broker_address,
    );

    let mut locked_requests =
        boundless_market.instance().RequestLocked_filter().watch().await?.into_stream();
    let mut submitted_requests =
        boundless_market.instance().RequestSubmitted_filter().watch().await?.into_stream();

    // let mut set_verifier =
    //     SetVerifierService::new(args.set_verifier_address, provider.clone(), broker_address);
    // if let Some(tx_timeout) = tx_timeout {
    //     set_verifier = set_verifier.with_timeout(Duration::from_secs(tx_timeout));
    // }
    // let (_, set_builder_url) = set_verifier.image_info().await?;
    // tracing::debug!("Fetching SetBuilder ELF from {}", set_builder_url);
    // let set_builder_elf = fetch_url(&set_builder_url).await?;

    // let (_, market_url) = boundless_market.image_info().await?;
    // tracing::debug!("Fetching Assessor ELF from {}", market_url);
    // let assessor_elf = fetch_url(&market_url).await?;
    // let domain = boundless_market.eip712_domain().await?;

    // let set_prover = DefaultProver::new(set_builder_elf, assessor_elf, broker_address, domain)?;

    // TODO: just kept for convenience for running `just localnet`. Ideally remove later.
    if let Some(deposit_amount) = args.deposit_amount.as_ref() {
        tracing::info!("pre-depositing {deposit_amount} HP into the market contract");
        boundless_market
            .deposit_stake_with_permit(*deposit_amount, &args.private_key)
            .await
            .context("Failed to deposit to market")?;
    }

    let block_number = provider.get_block_number().await?;
    let (block_number_sender, block_number_receiver) = watch::channel(block_number);

    // Construct state that can be used across order tasks.

    let concurrent_locks =
        Arc::new(Semaphore::new(max_concurrent_locks.unwrap_or(u32::MAX) as usize));
    let state = Arc::new(State {
        block_number_receiver,
        prover,
        config,
        market: boundless_market,
        concurrent_locks,
    });

    let mut pricing_tasks = JoinSet::new();

    loop {
        tokio::select! {
            // Biased for now to prioritize certain events
            biased;

            block = blocks_stream.next() => {
                if let Some(block) = block {
                    tracing::trace!("block: {:?}", block.number);
                    block_number_sender.send(block.number).unwrap();
                } else {
                    tracing::warn!("blocks stream disconnected, reconnecting...");
                    blocks_stream = provider.subscribe_blocks().await?.into_stream();
                }
            }
            // TODO reconnect mechanisms for orders, locked_requests, submitted_requests streams
            Some(locked_request) = locked_requests.next() => {
                match locked_request {
                    Ok(locked_request) => {
                        tracing::trace!("locked_request: {:?}", locked_request);
                    }
                    Err(e) => {
                        tracing::error!("locked request stream error: {:?}", e);
                    }
                }
            }
            Some(pricing_result) = pricing_tasks.join_next() => {
                let (order, order_price_result): (Order, PricingTaskResult) = pricing_result?;
                match order_price_result {
                    Ok(Some(order_lock_timing)) => {
                        tracing::trace!("order lock timing for {:x}: {:?}", order.request.id, order_lock_timing);
                        lock_and_fulfill_order(state.clone(), order, order_lock_timing).await?;
                    }
                    Ok(None) => {
                        tracing::trace!("order not priced: {:?}", order.request.id);
                    }
                    Err(e) => {
                        tracing::error!("pricing error for order {:x}: {:?}", order.request.id, e);
                    }
                }
            }
            Some(os_order) = orders.next() => {
                match os_order {
                    Ok(os_order) => {
                        let order = Order::new(os_order.order.request, os_order.order.signature.as_bytes().into());
                        tracing::trace!("received order from order stream: {:?}", order);
                        process_order(state.clone(), order, &mut pricing_tasks).await?;
                    }
                    Err(e) => {
                        tracing::error!("order stream error: {:?}", e);
                    }
                }
            }

            Some(submitted_request) = submitted_requests.next() => {
                let (event, log) = submitted_request?;
                match process_log(event, log, state.provider(), args.boundless_market_address, chain_id).await {
                    Ok(order) => {
                        tracing::trace!("received order from on-chain: {:?}", order);
                        process_order(state.clone(), order, &mut pricing_tasks).await?;
                    },
                    Err(e) => {
                        tracing::warn!("failed to process order: {:?}", e);
                        continue;
                    }
                };
            }
        }
    }
}

fn get_prover(config: &ConfigLock, args: &Args) -> Result<ProverObj> {
    // Construct the prover object interface
    let prover: ProverObj = if risc0_zkvm::is_dev_mode() {
        tracing::warn!(
            "WARNING: Running the Broker in dev mode does not generate valid receipts. \
        Receipts generated from this process are invalid and should never be used in production."
        );
        Arc::new(provers::MockProver::default())
    } else if let (Some(bonsai_api_key), Some(bonsai_api_url)) =
        (args.bonsai_api_key.as_ref(), args.bonsai_api_url.as_ref())
    {
        tracing::info!("Configured to run with Bonsai backend");

        Arc::new(
            provers::Bonsai::new(config.clone(), bonsai_api_url.as_ref(), bonsai_api_key)
                .context("Failed to construct Bonsai client")?,
        )
    } else if let Some(bento_api_url) = args.bento_api_url.as_ref() {
        tracing::info!("Configured to run with Bento backend");

        Arc::new(
            provers::Bonsai::new(config.clone(), bento_api_url.as_ref(), "")
                .context("Failed to initialize Bento client")?,
        )
    } else if cfg!(test) {
        Arc::new(provers::MockProver::default())
    } else {
        anyhow::bail!("Failed to select a proving backend");
    };

    Ok(prover)
}

async fn process_log<P: Provider>(
    event: IBoundlessMarket::RequestSubmitted,
    log: Log,
    provider: &P,
    market_addr: Address,
    chain_id: u64,
) -> Result<Order> {
    tracing::info!("Detected new request {:x}", event.requestId);

    let tx_hash = log.transaction_hash.context("Missing transaction hash")?;
    let tx_data =
        provider.get_transaction_by_hash(tx_hash).await?.context("Missing transaction data")?;

    let calldata = IBoundlessMarket::submitRequestCall::abi_decode(tx_data.input(), true)
        .context("Failed to decode calldata")?;

    calldata
        .request
        .verify_signature(&calldata.clientSignature, market_addr, chain_id)
        .with_context(|| {
            format!("Failed to validate order signature: 0x{:x}", calldata.request.id)
        })?;

    Ok(Order::new(calldata.request, calldata.clientSignature))
}

type PricingTaskResult = Result<Option<OrderLockTiming>, PriceOrderErr>;

async fn process_order<P>(
    state: Arc<State<P>>,
    mut order: Order,
    pricing_tasks: &mut JoinSet<(Order, PricingTaskResult)>,
) -> anyhow::Result<()>
where
    P: Provider + 'static + Clone + WalletProvider,
{
    let order_id = order.request.id;
    let concurrent_locks = state.concurrent_locks.clone();
    pricing_tasks.spawn(async move {
        let _permit = concurrent_locks.acquire_owned().await.expect("Semaphore closed");
        order.semaphore_permit = Some(_permit);
        let order_price = state.price_order(order_id, &order).await;
        (order, order_price)
    });

    Ok(())
}

async fn lock_and_fulfill_order<P>(
    state: Arc<State<P>>,
    order: Order,
    pricing: OrderLockTiming,
) -> Result<()>
where
    P: Provider + 'static + Clone + WalletProvider,
{
    // TODO this is all a shortcut to just lock and submit single orders, burn all of this.
    tokio::task::spawn(async move {
        let target_timestamp = pricing.target_timestamp_secs;
        let time_until_lock = target_timestamp.saturating_sub(now_timestamp_secs());
        // TODO this time is bad, as the time until lock is system time, but tokio time is monotonic
        //      and will desync and possibly sleep for longer than the deadline.
        tracing::debug!(
            "Sleeping for {} seconds until order {:x} should be locked",
            time_until_lock,
            order.request.id
        );
        tokio::time::sleep(Duration::from_secs(time_until_lock)).await;

        if let Err(e) = state.lock_order(&order).await {
            tracing::error!("Failed to lock order {:x}: {:?}", order.request.id, e);
        }
        tracing::info!("Order {:x} locked", order.request.id);
    });

    Ok(())
}

// // TODO deduplicate some code with the fulfill logic in boundless-cli
// async fn fulfill_order<P>(state: Arc<State<P>>, order: Order) -> Result<()>
// where
//     P: Provider + 'static + Clone + WalletProvider,
// {

//     // let client = ClientBuilder::default()
//     //     .with_private_key(args.private_key.clone())
//     //     .with_rpc_url(args.rpc_url.clone())
//     //     .with_boundless_market_address(args.boundless_market_address)
//     //     .with_set_verifier_address(args.set_verifier_address)
//     //     .with_order_stream_url(order_stream_url.clone())
//     //     .with_timeout(args.tx_timeout)
//     //     .build()
//     //     .await?;

//     let (fill, root_receipt, _, assessor_receipt) =
//         state.prover.fulfill(order.clone(), require_payment).await?;
//     let order_fulfilled = OrderFulfilled::new(fill, root_receipt, assessor_receipt, caller)?;
//     set_verifier.submit_merkle_root(order_fulfilled.root, order_fulfilled.seal).await?;

//     // If the request is not locked in, we need to "price" which checks the requirements
//     // and assigns a price. Otherwise, we don't. This vec will be a singleton if not locked
//     // and empty if the request is locked.
//     let requests_to_price: Vec<ProofRequest> =
//         (!state.market.is_locked(request_id).await?).then_some(order.request).into_iter().collect();
//     match state.market.fulfill_batch(order_fulfilled.fills, order_fulfilled.assessorReceipt).await {
//         Ok(_) => {
//             tracing::info!("Fulfilled request 0x{:x}", request_id);
//         }
//         Err(e) => {
//             tracing::error!("Failed to fulfill request 0x{:x}: {}", request_id, e);
//         }
//     }
//     Ok(())
// }

/// Fetches the content of a URL.
/// Supported URL schemes are `http`, `https`, and `file`.
// TODO duplicate logic with boundless-cli
pub async fn fetch_url(url_str: &str) -> Result<Vec<u8>> {
    tracing::debug!("Fetching URL: {}", url_str);
    let url = Url::parse(url_str)?;

    match url.scheme() {
        "http" | "https" => fetch_http(&url).await,
        "file" => fetch_file(&url).await,
        _ => bail!("unsupported URL scheme: {}", url.scheme()),
    }
}

async fn fetch_http(url: &Url) -> Result<Vec<u8>> {
    let response = reqwest::get(url.as_str()).await?;
    let status = response.status();
    if !status.is_success() {
        bail!("HTTP request failed with status: {}", status);
    }

    Ok(response.bytes().await?.to_vec())
}

async fn fetch_file(url: &Url) -> Result<Vec<u8>> {
    let path = std::path::Path::new(url.path());
    let data = tokio::fs::read(path).await?;
    Ok(data)
}
