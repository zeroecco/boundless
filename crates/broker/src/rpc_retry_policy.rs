// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use alloy::rpc::json_rpc::ErrorPayload;
use alloy::transports::{layers::RetryPolicy, TransportError, TransportErrorKind};
use std::time::Duration;

#[derive(Debug, Copy, Clone, Default)]
pub struct CustomRetryPolicy;

/// The retry policy for the RPC provider used throughout
///
/// This 'extends' the default retry policy to include a retry for
/// OS error 104 which is believed to be behind a number of issues
/// https://github.com/boundless-xyz/boundless/issues/240
impl RetryPolicy for CustomRetryPolicy {
    fn should_retry(&self, error: &TransportError) -> bool {
        match error {
            TransportError::Transport(TransportErrorKind::Custom(err)) => {
                let msg = err.to_string();
                msg.contains("os error 104)")
            }
            TransportError::Transport(e) => e.is_retry_err(),
            TransportError::DeserError { text, .. } => {
                if let Ok(resp) = serde_json::from_str::<ErrorPayload>(text) {
                    return resp.is_retry_err();
                }
                // some providers send invalid JSON RPC in the error case (no `id:u64`), but the
                // text should be a `JsonRpcError`
                #[derive(serde::Deserialize)]
                struct Resp {
                    error: ErrorPayload,
                }
                if let Ok(resp) = serde_json::from_str::<Resp>(text) {
                    return resp.error.is_retry_err();
                }
                false
            }
            TransportError::ErrorResp(e) => e.is_retry_err(),
            TransportError::NullResp => true,
            _ => false,
        }
    }

    fn backoff_hint(&self, error: &TransportError) -> Option<Duration> {
        if let TransportError::ErrorResp(resp) = error {
            let data = resp.try_data_as::<serde_json::Value>();
            if let Some(Ok(data)) = data {
                // if daily rate limit exceeded, infura returns the requested backoff in the error
                // response
                let backoff_seconds = &data["rate"]["backoff_seconds"];
                // infura rate limit error
                if let Some(seconds) = backoff_seconds.as_u64() {
                    return Some(std::time::Duration::from_secs(seconds));
                }
                if let Some(seconds) = backoff_seconds.as_f64() {
                    return Some(std::time::Duration::from_secs(seconds as u64 + 1));
                }
            }
        }
        None
    }
}
