// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use alloy::{
    rpc::json_rpc::RequestPacket,
    transports::{TransportError, TransportErrorKind},
};

fn e() -> TransportError {
    TransportError::Transport(TransportErrorKind::Custom(Box::new(
        std::io::Error::from_raw_os_error(104),
    )))
}

/// A policy that the provider should wait for X requests, then error for Y requests, the start working again
#[derive(Debug, Clone)]
pub struct BlanketOutagePolicy {
    lead_in: usize,
    error_for: usize,
    err_on_methods: Vec<&'static str>,

    request_counter: usize,
}

impl BlanketOutagePolicy {
    pub fn new(lead_in: usize, error_for: usize, err_on_methods: Vec<&'static str>) -> Self {
        BlanketOutagePolicy { lead_in, error_for, request_counter: 0, err_on_methods }
    }
}

impl crate::ErrorGeneratingPolicy for BlanketOutagePolicy {
    fn should_error(&mut self, request: &RequestPacket) -> Option<TransportError> {
        let response = match self.request_counter {
            n if n < self.lead_in => {
                tracing::info!(
                    "BlanketOutagePolicy: Allowing request number {}: {}",
                    n,
                    request.clone().serialize().unwrap()
                );
                None
            }
            n if n < self.lead_in + self.error_for => match request {
                RequestPacket::Single(r) => {
                    if self.err_on_methods.contains(&&*r.meta().method) {
                        tracing::info!(
                            "BlanketOutagePolicy: Erroring request number {}: {:?}",
                            n,
                            r
                        );
                        Some(e())
                    } else {
                        None
                    }
                }
                _ => None,
            },
            _ => None,
        };

        self.request_counter += 1;
        response
    }
}
