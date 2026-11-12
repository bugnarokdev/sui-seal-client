use std::str::FromStr;
use std::time::Duration;

use sui_sdk_types::Address;

use crate::error::{Error, Result};

/// Mysten Labs open key server `mysten-testnet-1` (Seal docs, Pricing page).
pub const MYSTEN_TESTNET_1: &str =
    "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75";
/// Mysten Labs open key server `mysten-testnet-2` (Seal docs, Pricing page).
pub const MYSTEN_TESTNET_2: &str =
    "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8";
/// Public Sui testnet fullnode (gRPC).
pub const TESTNET_FULLNODE: &str = "https://fullnode.testnet.sui.io:443";

/// Retry policy for key server requests.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Total attempts per server, first try included.
    pub max_attempts: u32,
    /// Delay before the first retry; doubled after each attempt.
    pub initial_backoff: Duration,
    /// Upper bound for a single delay.
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(8),
        }
    }
}

impl RetryPolicy {
    pub(crate) fn delay(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX);
        self.initial_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }
}

/// Client configuration.
#[derive(Debug, Clone)]
pub struct SealConfig {
    /// Key server object ids. Their URL and public key are read onchain.
    pub key_servers: Vec<Address>,
    /// Number of key servers needed to decrypt.
    pub threshold: u8,
    /// Sui fullnode gRPC endpoint.
    pub fullnode_url: String,
    /// Fetch `/v1/service` from each server and verify its proof of possession.
    pub verify_key_servers: bool,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
    /// Retry policy for `/v1/fetch_key`.
    pub retry: RetryPolicy,
}

impl SealConfig {
    /// Mysten open testnet servers, threshold 2 of 2.
    pub fn testnet() -> Self {
        Self {
            key_servers: vec![
                Address::from_str(MYSTEN_TESTNET_1).expect("valid constant"),
                Address::from_str(MYSTEN_TESTNET_2).expect("valid constant"),
            ],
            threshold: 2,
            fullnode_url: TESTNET_FULLNODE.to_string(),
            verify_key_servers: true,
            timeout: Duration::from_secs(20),
            retry: RetryPolicy::default(),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.key_servers.is_empty() {
            return Err(Error::InvalidInput("no key servers configured".into()));
        }
        if self.key_servers.len() > u8::MAX as usize {
            return Err(Error::InvalidInput("too many key servers".into()));
        }
        let mut sorted = self.key_servers.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != self.key_servers.len() {
            return Err(Error::InvalidInput("duplicate key server ids".into()));
        }
        validate_threshold(self.threshold, self.key_servers.len())
    }
}

pub(crate) fn validate_threshold(threshold: u8, servers: usize) -> Result<()> {
    if threshold == 0 || threshold as usize > servers {
        return Err(Error::InvalidInput(format!(
            "threshold {threshold} must be between 1 and the number of key servers ({servers})"
        )));
    }
    Ok(())
}
