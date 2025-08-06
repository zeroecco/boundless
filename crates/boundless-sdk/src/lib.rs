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

use std::io::Write;
use std::process::Command;

use alloy_primitives::{
    utils::{format_ether, parse_ether, parse_units},
    Address, Bytes, U256,
};
use anyhow::{Context, Error, Ok, Result};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::{contracts::ProofRequest, deployments::Deployment};

pub mod contracts;
pub mod deployments;
pub mod input;
pub mod util;

/// Status of a proof request
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq)]
pub enum RequestStatus {
    /// The request has expired.
    Expired,
    /// The request is locked in and waiting for fulfillment.
    Locked,
    /// The request has been fulfilled.
    Fulfilled,
    /// The request has an unknown status.
    ///
    /// This is used to represent the status of a request
    /// with no evidence in the state. The request may be
    /// open for bidding or it may not exist.
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "command", rename_all = "kebab-case")]
enum Output {
    Ok,
    AccountAmount { amount_eth: String },
    AccountStakeAmount { amount: String, decimals: u8, symbol: String },
    RequestStatus { status: RequestStatus },
    RequestSubmitted { request_id: U256, expires_at: u64 },
    RequestFulfilled { journal: Bytes, seal: Bytes },
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CliResponse<T: Serialize> {
    pub(crate) success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Client {
    pub rpc_url: String,
    pub deployment: Option<Deployment>,
    pub private_key: Option<String>,
}

impl Client {
    /// Submit a proof request in an onchain transaction.
    pub async fn submit_request_onchain(
        &self,
        request: &ProofRequest,
    ) -> Result<(U256, u64), Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg(
                "Deployment is not set. Please set the deployment before submitting a request.",
            )
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            Error::msg(
                "Private key is not set. Please set the private key before submitting a request.",
            )
        })?;

        let temp_file = create_proof_request_yaml_temp_file(request)?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--private-key")
            .arg(private_key)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--json")
            .arg("request")
            .arg("submit")
            .arg(temp_file.path());
        let output = cmd.output().context("Failed to execute command to submit request onchain")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to submit request onchain: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from request submission")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from request submission")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Request submission failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::RequestSubmitted { request_id, expires_at }) = response.data {
            return Ok((request_id, expires_at));
        }
        Err(Error::msg("Request submission failed"))
    }

    /// Submit a proof request offchain via the order stream service.
    pub fn submit_request_offchain(&self, request: &ProofRequest) -> Result<(U256, u64), Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg(
                "Deployment is not set. Please set the deployment before submitting a request.",
            )
        })?;
        let order_stream_url = deployment.order_stream_url.as_ref().ok_or_else(|| {
            Error::msg(
                "Order stream URL is not set. Please set the order stream URL before submitting a request offchain.",
            )
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            Error::msg(
                "Private key is not set. Please set the private key before submitting a request.",
            )
        })?;

        let temp_file = create_proof_request_yaml_temp_file(request)?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--private-key")
            .arg(private_key)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--order-stream-url")
            .arg(order_stream_url.to_string())
            .arg("--json")
            .arg("request")
            .arg("submit")
            .arg(temp_file.path())
            .arg("--offchain");
        let output =
            cmd.output().context("Failed to execute command to submit request offchain")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to submit request offchain: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from request submission")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from request submission")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Request submission failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::RequestSubmitted { request_id, expires_at }) = response.data {
            return Ok((request_id, expires_at));
        }
        Err(Error::msg("Request submission failed"))
    }

    pub fn status(
        &self,
        request_id: U256,
        expires_at: Option<u64>,
    ) -> Result<RequestStatus, Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg(
                "Deployment is not set. Please set the deployment before checking request status.",
            )
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--json")
            .arg("request")
            .arg("status")
            .arg(format!("0x{request_id:x}"));
        if let Some(expires_at) = expires_at {
            cmd.arg(format!("{expires_at}"));
        }
        let output = cmd.output().context("Failed to execute command to get request status")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to get request status: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from request status")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from request status")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Request status check failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::RequestStatus { status }) = response.data {
            return Ok(status);
        }
        Err(Error::msg("Request status check failed"))
    }

    /// Wait for a request to be fulfilled.
    ///
    /// The check interval is the time between each check for fulfillment.
    /// `expires_at` is the maximum time to wait for the request to be fulfilled.
    pub async fn wait_for_request_fulfillment(
        &self,
        request_id: U256,
        check_interval: std::time::Duration,
        expires_at: u64,
    ) -> Result<(Bytes, Bytes), Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg(
                "Deployment is not set. Please set the deployment before submitting a request.",
            )
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--json")
            .arg("request")
            .arg("get-proof")
            .arg(format!("0x{request_id:x}"));
        loop {
            let status = &self.status(request_id, Some(expires_at))?;
            match status {
                RequestStatus::Expired => return Err(Error::msg("Request has expired")),
                RequestStatus::Fulfilled => {
                    break;
                }
                _ => {
                    tokio::time::sleep(check_interval).await;
                    continue;
                }
            }
        }
        let output =
            cmd.output().context("Failed to execute command to fetch request fulfillment")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to fetch request fulfillment: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from request fulfillment")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from request fulfillment")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Request fulfillment failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::RequestFulfilled { journal, seal }) = response.data {
            return Ok((journal, seal));
        }
        Err(Error::msg("Request fulfillment failed"))
    }

    pub fn lock_request(&self, request_id: U256) -> Result<(), Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg(
                "Deployment is not set. Please set the deployment before submitting a request.",
            )
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            Error::msg(
                "Private key is not set. Please set the private key before locking a request.",
            )
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--private-key")
            .arg(private_key)
            .arg("--json")
            .arg("proving")
            .arg("lock")
            .arg("--request-id")
            .arg(format!("0x{request_id:x}"));
        let output = cmd.output().context("Failed to execute command to lock request")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to lock request: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout =
            String::from_utf8(output.stdout).context("Failed to parse output from request lock")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from request lock")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Request lock failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::Ok) = response.data {
            return Ok(());
        }
        Err(Error::msg("Request lock failed"))
    }

    pub fn fulfill(&self, request_id: U256) -> Result<(), Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg(
                "Deployment is not set. Please set the deployment before fulfilling a request.",
            )
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            Error::msg(
                "Private key is not set. Please set the private key before fulfilling a request.",
            )
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--private-key")
            .arg(private_key)
            .arg("--json")
            .arg("proving")
            .arg("fulfill")
            .arg("--request-ids")
            .arg(format!("0x{request_id:x}"));
        let output = cmd.output().context("Failed to execute command to fulfill request")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to fulfill request: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from request fulfillment")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from request fulfillment")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Request fulfillment failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::Ok) = response.data {
            return Ok(());
        }
        Err(Error::msg("Request fulfillment failed"))
    }

    pub fn balance_of(&self, address: Address) -> Result<U256, Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg("Deployment is not set. Please set the deployment before checking balance.")
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--json")
            .arg("account")
            .arg("balance")
            .arg(format!("0x{address:x}"));
        let output = cmd.output().context("Failed to execute command to get account balance")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to get account balance: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from account balance")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from account balance")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Account balance check failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::AccountAmount { amount_eth }) = response.data {
            return Ok(parse_ether(&amount_eth).context("Invalid balance format")?);
        }
        Err(Error::msg("Account balance check failed"))
    }

    pub fn deposit(&self, amount: U256) -> Result<U256, Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg("Deployment is not set. Please set the deployment before depositing.")
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            Error::msg("Private key is not set. Please set the private key before depositing.")
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--private-key")
            .arg(private_key)
            .arg("--json")
            .arg("account")
            .arg("deposit")
            .arg(format_ether(amount).as_str());
        let output = cmd.output().context("Failed to execute command to deposit")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to deposit: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from account deposit")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from account deposit")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Account deposit failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::AccountAmount { amount_eth }) = response.data {
            return Ok(parse_ether(&amount_eth).context("Invalid amount format")?);
        }
        Err(Error::msg("Account deposit check failed"))
    }

    pub fn withdraw(&self, amount: U256) -> Result<U256, Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg("Deployment is not set. Please set the deployment before withdrawing.")
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            Error::msg("Private key is not set. Please set the private key before withdrawing.")
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--private-key")
            .arg(private_key)
            .arg("--json")
            .arg("account")
            .arg("withdraw")
            .arg(format_ether(amount).as_str());
        let output = cmd.output().context("Failed to execute command to withdraw")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to withdraw: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from account withdrawal")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from account withdrawal")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Account withdrawal failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::AccountAmount { amount_eth }) = response.data {
            return Ok(parse_ether(&amount_eth).context("Invalid amount format")?);
        }
        Err(Error::msg("Account withdrawal check failed"))
    }

    pub fn stake_balance_of(&self, address: Address) -> Result<U256, Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg(
                "Deployment is not set. Please set the deployment before checking stake balance.",
            )
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--json")
            .arg("account")
            .arg("stake-balance")
            .arg(format!("0x{address:x}"));
        let output =
            cmd.output().context("Failed to execute command to get account stake balance")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to get account stake balance: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from account stake balance")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from account stake balance")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Account stake balance check failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::AccountStakeAmount { amount, symbol: _, decimals }) = response.data {
            return Ok(parse_units(&amount, decimals)
                .context("Invalid stake balance format")?
                .into());
        }
        Err(Error::msg("Account stake balance check failed"))
    }

    pub fn deposit_stake(&self, amount: String) -> Result<U256, Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg("Deployment is not set. Please set the deployment before depositing stake.")
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            Error::msg(
                "Private key is not set. Please set the private key before depositing stake.",
            )
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--private-key")
            .arg(private_key)
            .arg("--json")
            .arg("account")
            .arg("deposit-stake")
            .arg(amount);
        let output = cmd.output().context("Failed to execute command to deposit stake")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to deposit stake: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from account stake deposit")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from account stake deposit")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Account stake deposit failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::AccountStakeAmount { amount, symbol: _, decimals }) = response.data {
            return Ok(parse_units(&amount, decimals).context("Invalid amount format")?.into());
        }
        Err(Error::msg("Account stake deposit check failed"))
    }

    pub fn withdraw_stake(&self, amount: String) -> Result<U256, Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg("Deployment is not set. Please set the deployment before withdrawing stake.")
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            Error::msg(
                "Private key is not set. Please set the private key before withdrawing stake.",
            )
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--private-key")
            .arg(private_key)
            .arg("--json")
            .arg("account")
            .arg("withdraw-stake")
            .arg(amount);
        let output = cmd.output().context("Failed to execute command to withdraw stake")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to withdraw stake: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from account stake withdrawal")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from account stake withdrawal")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Account stake withdrawal failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::AccountStakeAmount { amount, symbol: _, decimals }) = response.data {
            return Ok(parse_units(&amount, decimals).context("Invalid amount format")?.into());
        }
        Err(Error::msg("Account stake withdrawal check failed"))
    }

    pub fn slash(&self, request_id: U256) -> Result<(), Error> {
        check_boundless_cli_installed()?;
        let deployment = self.deployment.as_ref().ok_or_else(|| {
            Error::msg("Deployment is not set. Please set the deployment before slashing.")
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            Error::msg("Private key is not set. Please set the private key before slashing.")
        })?;
        let mut boundless = Command::new("boundless");
        let cmd = boundless
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--boundless-market-address")
            .arg(deployment.boundless_market_address.to_string())
            .arg("--set-verifier-address")
            .arg(deployment.set_verifier_address.to_string())
            .arg("--private-key")
            .arg(private_key)
            .arg("--json")
            .arg("ops")
            .arg("slash")
            .arg(format!("0x{request_id:x}"));
        let output = cmd.output().context("Failed to execute command to slash")?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "Failed to slash: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Failed to parse output from request slashing")?;
        let response = serde_json::from_str::<CliResponse<Output>>(&stdout)
            .context("Failed to deserialize output from request slashing")?;
        if !response.success {
            return Err(Error::msg(format!(
                "Request slashing failed: {}",
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }
        if let Some(Output::Ok) = response.data {
            return Ok(());
        }
        Err(Error::msg("Request slashing failed"))
    }
}

fn check_boundless_cli_installed() -> Result<()> {
    if Command::new("boundless").arg("--version").output().is_err() {
        let error_message = "The 'boundless' CLI tool is not installed or not in your PATH.\n\
            Please install it by running 'cargo install --locked boundless-cli'.";
        return Err(Error::msg(error_message));
    }
    Ok(())
}

fn create_proof_request_yaml_temp_file(proof_request: &ProofRequest) -> Result<NamedTempFile> {
    let yaml_string =
        serde_yaml::to_string(proof_request).context("Failed to serialize ProofRequest to YAML")?;
    let mut temp_file = NamedTempFile::new().context("Failed to create temporary file")?;
    temp_file
        .write_all(yaml_string.as_bytes())
        .context("Failed to write YAML to temporary file")?;
    temp_file.flush().context("Failed to flush temporary file")?;

    Ok(temp_file)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    use crate::{
        contracts::{Offer, Predicate, PredicateType, RequestId, RequestInput, Requirements},
        util::now_timestamp,
    };
    use alloy::{
        node_bindings::{Anvil, AnvilInstance},
        providers::{Provider, WalletProvider},
    };
    use boundless_market::contracts::hit_points::default_allowance;
    use boundless_market::Deployment as BoundlessMarketDeployment;
    use boundless_market_test_utils::{create_test_ctx, TestCtx, ECHO_ID, ECHO_PATH};
    use risc0_zkvm::Digest;

    fn to_deployment(dep: BoundlessMarketDeployment) -> Deployment {
        Deployment {
            chain_id: dep.chain_id,
            boundless_market_address: dep.boundless_market_address,
            verifier_router_address: dep.verifier_router_address,
            set_verifier_address: dep.set_verifier_address,
            stake_token_address: dep.stake_token_address,
            order_stream_url: dep.order_stream_url,
        }
    }

    // generate a test request
    fn generate_request(id: u32, addr: &Address) -> ProofRequest {
        ProofRequest::new(
            RequestId::new(*addr, id),
            Requirements::new(
                Digest::from(ECHO_ID),
                Predicate { predicate_type: PredicateType::PrefixMatch, data: Default::default() },
            ),
            format!("file://{ECHO_PATH}"),
            RequestInput::builder().write_slice(&[0x41, 0x41, 0x41, 0x41]).build_inline().unwrap(),
            Offer {
                min_price: U256::from(20000000000000u64),
                max_price: U256::from(40000000000000u64),
                bidding_start: now_timestamp(),
                timeout: 420,
                lock_timeout: 420,
                ramp_up_period: 1,
                lock_stake: U256::from(0),
            },
        )
    }

    enum AccountOwner {
        Customer,
        Prover,
    }

    /// Test setup helper that creates common test infrastructure
    async fn setup_test_env(
        owner: AccountOwner,
    ) -> (TestCtx<impl Provider + WalletProvider + Clone + 'static>, AnvilInstance, Client) {
        let anvil = Anvil::new().spawn();

        let ctx = create_test_ctx(&anvil).await.unwrap();

        let private_key = match owner {
            AccountOwner::Customer => {
                ctx.prover_market
                    .deposit_stake_with_permit(default_allowance(), &ctx.prover_signer)
                    .await
                    .unwrap();
                ctx.customer_signer.clone()
            }
            AccountOwner::Prover => ctx.prover_signer.clone(),
        };

        let client = Client {
            rpc_url: anvil.endpoint_url().to_string(),
            private_key: Some(hex::encode(private_key.to_bytes())),
            deployment: Some(to_deployment(ctx.deployment.clone())),
        };

        (ctx, anvil, client)
    }

    #[tokio::test]
    async fn test_account() {
        let (ctx, _anvil, client) = setup_test_env(AccountOwner::Prover).await;

        let amount = client.deposit(parse_ether("1").unwrap()).unwrap();
        assert_eq!(amount, parse_ether("1").unwrap());

        let balance = client.balance_of(ctx.prover_signer.address()).unwrap();
        assert_eq!(balance, amount);

        let amount = client.withdraw(parse_ether("0.5").unwrap()).unwrap();
        assert_eq!(amount, parse_ether("0.5").unwrap());

        let balance = client.balance_of(ctx.prover_signer.address()).unwrap();
        assert_eq!(balance, parse_ether("0.5").unwrap());
    }

    #[tokio::test]
    async fn test_account_stake() {
        let (ctx, _anvil, client) = setup_test_env(AccountOwner::Prover).await;

        let amount = client.deposit_stake("1".into()).unwrap();
        assert_eq!(amount, parse_ether("1").unwrap());

        let balance = client.stake_balance_of(ctx.prover_signer.address()).unwrap();
        assert_eq!(balance, amount);

        let amount = client.withdraw_stake("0.5".into()).unwrap();
        assert_eq!(amount, parse_ether("0.5").unwrap());

        let balance = client.stake_balance_of(ctx.prover_signer.address()).unwrap();
        assert_eq!(balance, parse_ether("0.5").unwrap());
    }

    #[tokio::test]
    #[ignore = "Requires RISC0_DEV_MODE=1"]
    async fn test_slash() {
        let (ctx, _anvil, client) = setup_test_env(AccountOwner::Customer).await;

        let mut request = generate_request(1, &ctx.customer_signer.address());
        request.offer.timeout = 30;
        request.offer.lock_timeout = 30;

        let (request_id, expires_at) = client.submit_request_onchain(&request).await.unwrap();

        client.lock_request(request_id).unwrap();

        loop {
            // Wait for the timeout to expire
            tokio::time::sleep(Duration::from_secs(1)).await;
            let status = client.status(request_id, Some(expires_at)).unwrap();
            if status == RequestStatus::Expired {
                break;
            }
        }

        client.slash(request_id).unwrap();
    }

    #[tokio::test]
    #[ignore = "Requires RISC0_DEV_MODE=1"]
    async fn test_e2e() {
        let (ctx, _anvil, client) = setup_test_env(AccountOwner::Customer).await;

        let request = generate_request(1, &ctx.customer_signer.address());

        let (request_id, expires_at) = client.submit_request_onchain(&request).await.unwrap();
        assert_eq!(request_id, request.id.into());

        let status = client.status(request_id, Some(expires_at)).unwrap();
        assert_eq!(status, RequestStatus::Unknown);
        client.lock_request(request_id).unwrap();
        let status = client.status(request_id, Some(expires_at)).unwrap();
        assert_eq!(status, RequestStatus::Locked);
        client.fulfill(request_id).unwrap();
        let (_journal, _seal) = client
            .wait_for_request_fulfillment(request_id, std::time::Duration::from_secs(1), expires_at)
            .await
            .unwrap();
        let status = client.status(request_id, Some(expires_at)).unwrap();
        assert_eq!(status, RequestStatus::Fulfilled);
    }
}
