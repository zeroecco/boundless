// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use alloy::rpc::json_rpc::{ErrorPayload, Id, RequestPacket, Response, ResponsePacket};
use alloy::transports::{
    layers::{RateLimitRetryPolicy, RetryPolicy},
    TransportError, TransportErrorKind,
};
use alloy::transports::{BoxFuture, RpcError};
use futures_util::FutureExt;
use serde_json::Value;
use std::{
    fmt::Debug,
    future::{Future, IntoFuture},
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service};

#[derive(Debug, Copy, Clone, Default)]
pub struct CustomRetryPolicy;

/// The retry policy for the RPC provider used throughout
///
/// This 'extends' the default retry policy to include a retry for
/// OS error 104 which is believed to be behind a number of issues
/// https://github.com/boundless-xyz/boundless/issues/240
impl RetryPolicy for CustomRetryPolicy {
    fn should_retry(&self, error: &TransportError) -> bool {
        let should_retry = match error {
            TransportError::Transport(TransportErrorKind::Custom(err)) => {
                // easier to match against the debug format string because this is what we see in the logs
                let err_debug_str = format!("{:?}", err);
                err_debug_str.contains("os error 104") || err_debug_str.contains("reset by peer")
            }
            _ => false,
        };
        should_retry || RateLimitRetryPolicy::default().should_retry(error)
    }

    fn backoff_hint(&self, error: &TransportError) -> Option<Duration> {
        RateLimitRetryPolicy::default().backoff_hint(error)
    }
}

struct ErrorCatchingLayer;

impl<S> Layer<S> for ErrorCatchingLayer {
    type Service = ErrorCatchingMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ErrorCatchingMiddleware { inner }
    }
}

struct ErrorCatchingMiddleware<S> {
    inner: S,
}

impl<S> Service<RequestPacket> for ErrorCatchingMiddleware<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError>
        + Sync
        + Send
        + Clone
        + 'static,
    S::Future: Send,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let (method_name, id) = get_method_name_and_id(&request);

        let fut = self.inner.call(request);
        async move {
            let response = fut.await;
            let response_return = match &response {
                Ok(_resp) => response,
                Err(err) => {
                    match err {
                        TransportError::ErrorResp(ErrorPayload { code, message, data: None })
                            if (method_name == "eth_sendTransaction" || method_name  == "eth_sendRawTransaction") && *code == -32603 && message.contains("already known") =>
                        {
                            tracing::warn!("Detected 'already known' rpc error suggesting that the txn has already been submitted: {err:?}, transforming to success response");
                            // TODO: result should be the tx hash
                            let response = format!(
                                r#"{{
                                    "jsonrpc": "2.0",
                                    "result": "",
                                    "id": {}
                                }}"#,
                                id
                            );
                            Ok(ResponsePacket::Single(serde_json::from_str(&response).unwrap()))
                        }
                        _ => response,
                    }
                }
            };
            response_return
        }
        .boxed()
    }
}

/// Get the method name from the request
fn get_method_name_and_id(req: &RequestPacket) -> (String, Id) {
    match req {
        RequestPacket::Single(request) => (request.method().to_string(), request.id().clone()),
        RequestPacket::Batch(_) => {
            // can't extract method name for batch.
            ("batch".to_string(), Id::None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::transports::{layers::RetryPolicy, RpcError, TransportErrorKind};
    use std::fmt;

    struct MockError;

    impl fmt::Debug for MockError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("reqwest::Error { kind: Request, source: hyper_util::client::legacy::Error(SendRequest, hyper::Error(Io, Os { code: 104, kind: ConnectionReset, message: \"Connection reset by peer\" })) }")
        }
    }

    impl fmt::Display for MockError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Mock Error")
        }
    }

    impl std::error::Error for MockError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            None
        }
    }

    #[test]
    fn retries_on_os_error_104() {
        let policy = CustomRetryPolicy;
        let error = RpcError::Transport(TransportErrorKind::Custom(Box::new(MockError)));
        assert!(policy.should_retry(&error));
    }
}
