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

use alloy::{
    network::Ethereum,
    providers::{PendingTransactionBuilder, Provider, ProviderLayer, RootProvider},
    rpc::types::TransactionRequest,
    transports::TransportResult,
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
/// A layer that serialize transactions.
///
/// It uses a mutex to ensure that only one transaction is processed at a time.
pub struct MutexLayer {
    nonce_lock: Arc<Mutex<()>>,
}

impl<P: Provider<Ethereum>> ProviderLayer<P> for MutexLayer {
    type Provider = MutexProvider<P>;

    fn layer(&self, inner: P) -> Self::Provider {
        MutexProvider { inner: Arc::new(inner), nonce_lock: Arc::clone(&self.nonce_lock) }
    }
}

#[derive(Clone)]
/// A provider that ensure that only one transaction is processed at a time.
pub struct MutexProvider<P> {
    inner: Arc<P>,
    nonce_lock: Arc<Mutex<()>>,
}

#[async_trait::async_trait]
impl<P> Provider<Ethereum> for MutexProvider<P>
where
    P: Provider<Ethereum> + Send + Sync,
{
    fn root(&self) -> &RootProvider {
        self.inner.root()
    }

    async fn send_raw_transaction(
        &self,
        encoded_tx: &[u8],
    ) -> TransportResult<PendingTransactionBuilder<Ethereum>> {
        tracing::trace!("MutexProvider::send_raw_transaction - locking nonce");
        let _lock = self.nonce_lock.lock().await;
        tracing::trace!("MutexProvider:: nonce locked, sending raw tx");
        let pending_tx = self.inner.send_raw_transaction(encoded_tx).await?;
        tracing::trace!("MutexProvider::raw transaction sent: {:?}", pending_tx.tx_hash());

        Ok(pending_tx)
    }

    async fn send_transaction(
        &self,
        request: TransactionRequest,
    ) -> TransportResult<PendingTransactionBuilder<Ethereum>> {
        tracing::trace!("MutexProvider::send_transaction - locking nonce");
        let _lock = self.nonce_lock.lock().await;
        tracing::trace!("MutexProvider:: nonce locked, sending tx");
        let pending_tx = self.inner.send_transaction(request).await?;
        tracing::trace!("MutexProvider::transaction sent: {:?}", pending_tx.tx_hash());

        Ok(pending_tx)
    }
}
