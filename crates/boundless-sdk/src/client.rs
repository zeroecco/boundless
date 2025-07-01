// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{str::FromStr, time::Duration};

use alloy_primitives::{Bytes, U256};
use alloy_signer::Signer;
use alloy_signer_local::{LocalSignerError, PrivateKeySigner};
use anyhow::{anyhow, bail, Context, Result};

use url::Url;

use crate::{
    contracts::{ProofRequest, RequestError},
    deployments::Deployment,
    request_builder::{
        FinalizerConfigBuilder, OfferLayer, OfferLayerConfigBuilder, RequestBuilder,
        RequestIdLayer, RequestIdLayerConfigBuilder, StandardRequestBuilder,
        StandardRequestBuilderBuilderError, StorageLayer, StorageLayerConfigBuilder,
    },
    rpc::{self, RpcProvider},
    storage::{
        StandardStorageProvider, StandardStorageProviderError, StorageProvider,
        StorageProviderConfig,
    },
    util::NotProvided,
};

/// Builder for the [Client] with standard implementations for the required components.
#[derive(Clone)]
pub struct ClientBuilder<St = NotProvided, Si = NotProvided> {
    deployment: Option<Deployment>,
    rpc_url: Option<Url>,
    signer: Option<Si>,
    storage_provider: Option<St>,
    tx_timeout: Option<std::time::Duration>,
    /// Configuration builder for [OfferLayer], part of [StandardRequestBuilder].
    pub offer_layer_config: OfferLayerConfigBuilder,
    /// Configuration builder for [StorageLayer], part of [StandardRequestBuilder].
    pub storage_layer_config: StorageLayerConfigBuilder,
    /// Configuration builder for [RequestIdLayer], part of [StandardRequestBuilder].
    pub request_id_layer_config: RequestIdLayerConfigBuilder,
    /// Configuration builder for [Finalizer][crate::request_builder::Finalizer], part of [StandardRequestBuilder].
    pub request_finalizer_config: FinalizerConfigBuilder,
}

impl<St, Si> Default for ClientBuilder<St, Si> {
    fn default() -> Self {
        Self {
            deployment: None,
            rpc_url: None,
            signer: None,
            storage_provider: None,
            tx_timeout: None,
            offer_layer_config: Default::default(),
            storage_layer_config: Default::default(),
            request_id_layer_config: Default::default(),
            request_finalizer_config: Default::default(),
        }
    }
}

impl ClientBuilder {
    /// Create a new client builder.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<St, Si> ClientBuilder<St, Si> {
    /// Build the client
    pub async fn build(self) -> Result<Client<St, StandardRequestBuilder<NotProvided, St>, Si>>
    where
        St: Clone,
    {
        let rpc_url = self.rpc_url.clone().context("rpc_url is not set on ClientBuilder")?;
        let chain_id = RpcProvider::new(rpc_url.clone())
            .chain_id()
            .await
            .context("failed to get chain ID from RPC provider")?;

        // Resolve the deployment information.

        let deployment =
            self.deployment.clone().or_else(|| Deployment::from_chain_id(chain_id)).with_context(
                || format!("no deployment provided for unknown chain_id {chain_id}"),
            )?;

        // Check that the chain ID is matches the deployment, to avoid misconfigurations.
        if deployment.chain_id.map(|id| id != chain_id).unwrap_or(false) {
            bail!("provided deployment does not match chain_id reported by RPC provider: {chain_id} != {}", deployment.chain_id.unwrap());
        }

        // Build the RequestBuilder.
        let request_builder = StandardRequestBuilder::builder()
            .storage_layer(StorageLayer::new(
                self.storage_provider.clone(),
                self.storage_layer_config.build()?,
            ))
            .offer_layer(OfferLayer::new(self.offer_layer_config.build()?))
            .request_id_layer(RequestIdLayer::new(self.request_id_layer_config.build()?))
            .finalizer(self.request_finalizer_config.build()?)
            .build()?;

        let mut client = Client {
            storage_provider: self.storage_provider,
            signer: self.signer,
            request_builder: Some(request_builder),
            deployment,
        };

        if let Some(timeout) = self.tx_timeout {
            client = client.with_timeout(timeout);
        }

        Ok(client)
    }

    /// Set the [Deployment] of the Boundless Market that this client will use.
    ///
    /// If `None`, the builder will attempt to infer the deployment from the chain ID.
    pub fn with_deployment(self, deployment: impl Into<Option<Deployment>>) -> Self {
        Self { deployment: deployment.into(), ..self }
    }

    /// Set the RPC URL
    pub fn with_rpc_url(self, rpc_url: Url) -> Self {
        Self { rpc_url: Some(rpc_url), ..self }
    }

    /// Set the signer from the given private key as a string.
    /// ```rust
    /// # use boundless_sdk::Client;
    ///
    /// Client::builder().with_private_key_str(
    ///     "0x1cee2499e12204c2ed600d780a22a67b3c5fff3310d984cca1f24983d565265c"
    /// ).unwrap();
    /// ```
    pub fn with_private_key_str(
        self,
        private_key: impl AsRef<str>,
    ) -> Result<ClientBuilder<St, PrivateKeySigner>, LocalSignerError> {
        Ok(self.with_signer(PrivateKeySigner::from_str(private_key.as_ref())?))
    }

    /// Set the transaction timeout in seconds
    pub fn with_timeout(self, tx_timeout: impl Into<Option<Duration>>) -> Self {
        Self { tx_timeout: tx_timeout.into(), ..self }
    }

    /// Set the storage provider.
    ///
    /// The returned [ClientBuilder] will be generic over the provider [StorageProvider] type.
    pub fn with_storage_provider<Z: StorageProvider>(
        self,
        storage_provider: Option<Z>,
    ) -> ClientBuilder<Z, Si> {
        // NOTE: We can't use the ..self syntax here because return is not Self.
        ClientBuilder {
            storage_provider,
            deployment: self.deployment,
            rpc_url: self.rpc_url,
            signer: self.signer,
            tx_timeout: self.tx_timeout,
            request_finalizer_config: self.request_finalizer_config,
            request_id_layer_config: self.request_id_layer_config,
            storage_layer_config: self.storage_layer_config,
            offer_layer_config: self.offer_layer_config,
        }
    }

    /// Set the storage provider from the given config
    pub fn with_storage_provider_config(
        self,
        config: &StorageProviderConfig,
    ) -> Result<ClientBuilder<StandardStorageProvider, Si>, StandardStorageProviderError> {
        let storage_provider = match StandardStorageProvider::from_config(config) {
            Ok(storage_provider) => Some(storage_provider),
            Err(StandardStorageProviderError::NoProvider) => None,
            Err(e) => return Err(e),
        };
        Ok(self.with_storage_provider(storage_provider))
    }

    /// Modify the [OfferLayer] configuration used in the [StandardRequestBuilder].
    ///
    /// ```rust
    /// # use boundless_market::client::ClientBuilder;
    /// use alloy::primitives::utils::parse_units;
    ///
    /// ClientBuilder::new().config_offer_layer(|config| config
    ///     .max_price_per_cycle(parse_units("0.1", "gwei").unwrap())
    ///     .ramp_up_period(36)
    ///     .lock_timeout(120)
    ///     .timeout(300)
    /// );
    /// ```
    pub fn config_offer_layer(
        mut self,
        f: impl FnOnce(&mut OfferLayerConfigBuilder) -> &mut OfferLayerConfigBuilder,
    ) -> Self {
        f(&mut self.offer_layer_config);
        self
    }

    /// Modify the [RequestIdLayer] configuration used in the [StandardRequestBuilder].
    ///
    /// ```rust
    /// # use boundless_market::client::ClientBuilder;
    /// use boundless_market::request_builder::RequestIdLayerMode;
    ///
    /// ClientBuilder::new().config_request_id_layer(|config| config
    ///     .mode(RequestIdLayerMode::Nonce)
    /// );
    /// ```
    pub fn config_request_id_layer(
        mut self,
        f: impl FnOnce(&mut RequestIdLayerConfigBuilder) -> &mut RequestIdLayerConfigBuilder,
    ) -> Self {
        f(&mut self.request_id_layer_config);
        self
    }

    /// Modify the [StorageLayer] configuration used in the [StandardRequestBuilder].
    ///
    /// ```rust
    /// # use boundless_market::client::ClientBuilder;
    /// ClientBuilder::new().config_storage_layer(|config| config
    ///     .inline_input_max_bytes(10240)
    /// );
    /// ```
    pub fn config_storage_layer(
        mut self,
        f: impl FnOnce(&mut StorageLayerConfigBuilder) -> &mut StorageLayerConfigBuilder,
    ) -> Self {
        f(&mut self.storage_layer_config);
        self
    }

    /// Modify the [Finalizer][crate::request_builder::Finalizer] configuration used in the [StandardRequestBuilder].
    pub fn config_request_finalizer(
        mut self,
        f: impl FnOnce(&mut FinalizerConfigBuilder) -> &mut FinalizerConfigBuilder,
    ) -> Self {
        f(&mut self.request_finalizer_config);
        self
    }
}

#[derive(Clone)]
#[non_exhaustive]
/// Client for interacting with the boundless market.
pub struct Client<St = StandardStorageProvider, R = StandardRequestBuilder, Si = PrivateKeySigner> {
    /// [StorageProvider] to upload programs and inputs.
    ///
    /// If not provided, this client will not be able to upload programs or inputs.
    pub storage_provider: Option<St>,
    /// Alloy [Signer] for signing requests.
    ///
    /// If not provided, requests must be pre-signed handing them to this client.
    pub signer: Option<Si>,
    /// [RequestBuilder] to construct [ProofRequest].
    ///
    /// If not provided, requests must be fully constructed before handing them to this client.
    pub request_builder: Option<R>,
    /// Deployment of Boundless that this client is connected to.
    pub deployment: Deployment,
}

/// Alias for a [Client] instantiated with the standard implementations provided by this crate.
pub type StandardClient =
    Client<StandardStorageProvider, StandardRequestBuilder<NotProvided>, PrivateKeySigner>;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
/// Client error
pub enum ClientError {
    /// Storage provider error
    #[error("Storage provider error {0}")]
    StorageProviderError(#[from] StandardStorageProviderError),
    /// Request error
    #[error("RequestError {0}")]
    RequestError(#[from] RequestError),
    /// Error when trying to construct a [RequestBuilder].
    #[error("Error building RequestBuilder {0}")]
    BuilderError(#[from] StandardRequestBuilderBuilderError),
    /// General error
    #[error("Error {0}")]
    Error(#[from] anyhow::Error),
}

impl Client<NotProvided, NotProvided, NotProvided> {
    /// Create a [ClientBuilder] to construct a [Client].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }
}

impl Client<NotProvided, NotProvided, NotProvided> {
    /// Create a new client
    pub fn new() -> Self {}
}

impl<St, R, Si> Client<St, R, Si> {
    /// Set the storage provider
    pub fn with_storage_provider(self, storage_provider: St) -> Self
    where
        St: StorageProvider,
    {
        Self { storage_provider: Some(storage_provider), ..self }
    }

    /// Set the transaction timeout
    pub fn with_timeout(self, tx_timeout: Duration) -> Self {
        Self { ..self }
    }

    /// Set the signer that will be used for signing [ProofRequest].
    /// ```rust
    /// # use boundless_sdk::Client;
    /// # use std::str::FromStr;
    /// # |client: Client| {
    /// use alloy_signers_local::PrivateKeySigner;
    ///
    /// client.with_signer(PrivateKeySigner::from_str(
    ///     "0x1cee2499e12204c2ed600d780a22a67b3c5fff3310d984cca1f24983d565265c")
    ///     .unwrap());
    /// # };
    /// ```
    pub fn with_signer<Zi>(self, signer: Zi) -> Client<St, R, Zi> {
        // NOTE: We can't use the ..self syntax here because return is not Self.
        Client {
            signer: Some(signer),
            storage_provider: self.storage_provider,
            request_builder: self.request_builder,
            deployment: self.deployment,
        }
    }

    /// Upload a program binary to the storage provider.
    pub async fn upload_program(&self, program: &[u8]) -> Result<Url, ClientError>
    where
        St: StorageProvider,
    {
        Ok(self
            .storage_provider
            .as_ref()
            .context("Storage provider not set")?
            .upload_program(program)
            .await
            .map_err(|_| anyhow!("Failed to upload program"))?)
    }

    /// Upload input to the storage provider.
    pub async fn upload_input(&self, input: &[u8]) -> Result<Url, ClientError>
    where
        St: StorageProvider,
    {
        Ok(self
            .storage_provider
            .as_ref()
            .context("Storage provider not set")?
            .upload_input(input)
            .await
            .map_err(|_| anyhow!("Failed to upload input"))?)
    }

    /// Initial parameters that will be used to build a [ProofRequest] using the [RequestBuilder].
    pub fn new_request<Params>(&self) -> Params
    where
        R: RequestBuilder<Params>,
        Params: Default,
    {
        Params::default()
    }

    /// Build a proof request from the given parameters.
    ///
    /// Requires a a [RequestBuilder] to be provided.
    pub async fn build_request<Params>(
        &self,
        params: impl Into<Params>,
    ) -> Result<ProofRequest, ClientError>
    where
        R: RequestBuilder<Params>,
        R::Error: Into<anyhow::Error>,
    {
        let request_builder =
            self.request_builder.as_ref().context("request_builder is not set on Client")?;
        tracing::debug!("Building request");
        let request = request_builder.build(params).await.map_err(Into::into)?;
        tracing::debug!("Built request with id {:x}", request.id);
        Ok(request)
    }

    /// Build and submit a proof request by sending an onchain transaction.
    ///
    /// Requires a [Signer] to be provided to sign the request, and a [RequestBuilder] to be
    /// provided to build the request from the given parameters.
    pub async fn submit_onchain<Params>(
        &self,
        params: impl Into<Params>,
    ) -> Result<(U256, u64), ClientError>
    where
        Si: Signer,
        R: RequestBuilder<Params>,
        R::Error: Into<anyhow::Error>,
    {
        let signer = self.signer.as_ref().context("signer is set on Client")?;
        self.submit_request_onchain_with_signer(&self.build_request(params).await?, signer).await
    }

    /// Submit a proof request in an onchain transaction.
    ///
    /// Requires a signer to be set to sign the request.
    pub async fn submit_request_onchain(
        &self,
        request: &ProofRequest,
    ) -> Result<(U256, u64), ClientError>
    where
        Si: Signer,
    {
        let signer = self.signer.as_ref().context("signer not set")?;
        self.submit_request_onchain_with_signer(request, signer).await
    }

    /// Submit a proof request in a transaction.
    ///
    /// Accepts a signer to sign the request. Note that the transaction will be signed by the alloy
    /// [Provider] on this [Client].
    pub async fn submit_request_onchain_with_signer(
        &self,
        request: &ProofRequest,
        signer: &impl Signer,
    ) -> Result<(U256, u64), ClientError> {
        let mut request = request.clone();

        if request.id == U256::ZERO {
            request.id = self.boundless_market.request_id_from_rand().await?;
        };
        let client_address = request.client_address();
        if client_address != signer.address() {
            return Err(RequestError::AddressMismatch(client_address, signer.address()))?;
        };

        request.validate()?;

        let request_id = self.boundless_market.submit_request(&request, signer).await?;
        Ok((request_id, request.expires_at()))
    }

    /// Submit a pre-signed proof in an onchain transaction.
    ///
    /// Accepts a signature bytes to be used as the request signature.
    pub async fn submit_request_onchain_with_signature(
        &self,
        request: &ProofRequest,
        signature: impl Into<Bytes>,
    ) -> Result<(U256, u64), ClientError> {
        let request = request.clone();
        request.validate()?;

        let request_id =
            self.boundless_market.submit_request_with_signature(&request, signature).await?;
        Ok((request_id, request.expires_at()))
    }

    /// Build and submit a proof request offchain via the order stream service.
    ///
    /// Requires a [Signer] to be provided to sign the request, and a [RequestBuilder] to be
    /// provided to build the request from the given parameters.
    pub async fn submit_offchain<Params>(
        &self,
        params: impl Into<Params>,
    ) -> Result<(U256, u64), ClientError>
    where
        Si: Signer,
        R: RequestBuilder<Params>,
        R::Error: Into<anyhow::Error>,
    {
        let signer = self.signer.as_ref().context("signer is set on Client")?;
        self.submit_request_offchain_with_signer(&self.build_request(params).await?, signer).await
    }

    /// Submit a proof request offchain via the order stream service.
    ///
    /// Requires a signer to be set to sign the request.
    pub async fn submit_request_offchain(
        &self,
        request: &ProofRequest,
    ) -> Result<(U256, u64), ClientError>
    where
        Si: Signer,
    {
        let signer = self.signer.as_ref().context("signer not set")?;
        self.submit_request_offchain_with_signer(request, signer).await
    }

    /// Submit a proof request offchain via the order stream service.
    ///
    /// Accepts a signer to sign the request.
    pub async fn submit_request_offchain_with_signer(
        &self,
        request: &ProofRequest,
        signer: &impl Signer,
    ) -> Result<(U256, u64), ClientError> {
        let offchain_client = self
            .offchain_client
            .as_ref()
            .context("Order stream client not available. Please provide an order stream URL")?;
        let mut request = request.clone();

        if request.id == U256::ZERO {
            request.id = self.boundless_market.request_id_from_rand().await?;
        };
        let client_address = request.client_address();
        if client_address != signer.address() {
            return Err(RequestError::AddressMismatch(client_address, signer.address()))?;
        };
        // Ensure address' balance is sufficient to cover the request
        let balance = self.boundless_market.balance_of(client_address).await?;
        if balance < U256::from(request.offer.maxPrice) {
            return Err(ClientError::Error(anyhow!(
                "Insufficient balance to cover request: {} < {}.\nMake sure to top up your balance by depositing on the Boundless Market.",
                balance,
                request.offer.maxPrice
            )));
        }

        let order = offchain_client.submit_request(&request, signer).await?;

        Ok((order.request.id, request.expires_at()))
    }

    /// Wait for a request to be fulfilled.
    ///
    /// The check interval is the time between each check for fulfillment.
    /// The timeout is the maximum time to wait for the request to be fulfilled.
    pub async fn wait_for_request_fulfillment(
        &self,
        request_id: U256,
        check_interval: std::time::Duration,
        expires_at: u64,
    ) -> Result<(Bytes, Bytes), ClientError> {
        todo!()
    }
}
