// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use alloy::{
    rpc::json_rpc::{RequestPacket, ResponsePacket},
    transports::{TransportError, TransportFut},
};
use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tower::{Layer, Service};

mod blanket_outage_policy;
pub use blanket_outage_policy::BlanketOutagePolicy;

/// A trait that describes how to introduce specific errors for testing.
/// This is stateful so allows expression conditions such as
/// - error after 5 requests for the next 10 request then start working again
/// - error on the 10th request of a specific type
/// - error on all requests of a specific type
trait ErrorGeneratingPolicy: Clone {
    fn should_error(&mut self, request: &RequestPacket) -> Option<TransportError>;
}

/// A transport layer that can introduce specific Alloy transport faults on request for testing purposes
/// This must be installed first (e.g. the first layer added) if you want to test how other layers
/// handle transport errors
#[derive(Clone)]
pub struct NetworkTestingLayer<P: Clone> {
    policy: Arc<Mutex<P>>,
}

impl<P: Clone> NetworkTestingLayer<P> {
    /// Create a new `NetworkTestingLayer`
    pub fn new(policy: P) -> Self {
        NetworkTestingLayer { policy: Arc::new(Mutex::new(policy)) }
    }
}

impl<S, P> Layer<S> for NetworkTestingLayer<P>
where
    P: ErrorGeneratingPolicy,
{
    type Service = NetworkTestingService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        NetworkTestingService { inner, policy: self.policy.clone() }
    }
}

#[derive(Clone)]
pub struct NetworkTestingService<S, P> {
    inner: S,
    policy: Arc<Mutex<P>>,
}

impl<S, P> Service<RequestPacket> for NetworkTestingService<S, P>
where
    S: Service<RequestPacket, Future = TransportFut<'static>, Error = TransportError>
        + Send
        + 'static
        + Clone,
    P: ErrorGeneratingPolicy,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        if let Some(err) = self.policy.lock().unwrap().should_error(&request) {
            Box::pin(async move { Err(err) })
        } else {
            self.inner.call(request)
        }
    }
}
