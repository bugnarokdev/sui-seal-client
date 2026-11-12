use std::collections::BTreeMap;
use std::fmt;
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
/// Mysten Labs decentralized (committee) key server on testnet, 3-of-5 internally
/// (Seal docs, Pricing page, "Verified decentralized key servers"). BETA.
pub const MYSTEN_TESTNET_COMMITTEE: &str =
    "0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98";
/// Aggregator in front of [`MYSTEN_TESTNET_COMMITTEE`], run by Mysten Labs.
pub const MYSTEN_TESTNET_AGGREGATOR: &str = "https://seal-aggregator-testnet.mystenlabs.com";
/// Public Sui testnet fullnode (gRPC).
pub const TESTNET_FULLNODE: &str = "https://fullnode.testnet.sui.io:443";

/// Largest total weight: the encrypted object holds one share per unit of weight and
/// counts them in a `u8`.
pub const MAX_TOTAL_WEIGHT: usize = u8::MAX as usize;

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

/// An HTTP header sent to a permissioned key server (for example an API key issued by
/// its operator). The value is redacted from `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKey {
    /// Header name, as given by the key server operator.
    pub header: String,
    /// Header value. Treat as a secret.
    pub value: String,
}

impl ApiKey {
    pub fn new(header: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            value: value.into(),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        reqwest::header::HeaderName::from_bytes(self.header.as_bytes())
            .map_err(|e| Error::InvalidInput(format!("API key header name: {e}")))?;
        reqwest::header::HeaderValue::from_str(&self.value)
            .map_err(|_| Error::InvalidInput("API key value is not a valid header value".into()))?;
        Ok(())
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("header", &self.header)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Per-key-server options. BETA (v0.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyServerOptions {
    /// Number of shares this server holds (1 by default). A server of weight `w` counts
    /// `w` times toward the threshold, as `weight` in `@mysten/seal`.
    pub weight: u8,
    /// Aggregator URL. Required for committee (decentralized) key servers, refused for
    /// independent ones.
    pub aggregator_url: Option<String>,
    /// Header sent with every request to this server (permissioned servers).
    pub api_key: Option<ApiKey>,
}

impl Default for KeyServerOptions {
    fn default() -> Self {
        Self {
            weight: 1,
            aggregator_url: None,
            api_key: None,
        }
    }
}

impl KeyServerOptions {
    pub fn weight(mut self, weight: u8) -> Self {
        self.weight = weight;
        self
    }

    pub fn aggregator_url(mut self, url: impl Into<String>) -> Self {
        self.aggregator_url = Some(url.into());
        self
    }

    pub fn api_key(mut self, key: ApiKey) -> Self {
        self.api_key = Some(key);
        self
    }
}

/// Client configuration.
///
/// Build it with [`SealConfig::builder`], or start from a preset
/// ([`SealConfig::testnet`], [`SealConfig::testnet_committee`]).
#[derive(Debug, Clone)]
pub struct SealConfig {
    /// Key server object ids. Their URL and public key are read onchain.
    pub key_servers: Vec<Address>,
    /// Total weight of the key servers needed to decrypt (number of servers when every
    /// weight is 1).
    pub threshold: u8,
    /// Sui fullnode gRPC endpoint.
    pub fullnode_url: String,
    /// Fetch `/v1/service` from each independent server and verify its proof of
    /// possession. Committee servers have no proof of possession; their keys are still
    /// verified against the onchain committee public key.
    pub verify_key_servers: bool,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
    /// Retry policy for `/v1/fetch_key`.
    pub retry: RetryPolicy,
    /// Options of individual servers (weight, aggregator URL, API key). Servers without
    /// an entry use [`KeyServerOptions::default`]. BETA (v0.2).
    pub server_options: BTreeMap<Address, KeyServerOptions>,
}

impl SealConfig {
    /// Mysten open testnet servers, threshold 2 of 2. Same as v0.1.
    pub fn testnet() -> Self {
        Self {
            key_servers: vec![
                Address::from_str(MYSTEN_TESTNET_1).expect("valid constant"),
                Address::from_str(MYSTEN_TESTNET_2).expect("valid constant"),
            ],
            threshold: 2,
            ..Self::base()
        }
    }

    /// Mysten testnet committee (3-of-5 behind the Mysten aggregator), seen by the
    /// client as one server: threshold 1. BETA.
    pub fn testnet_committee() -> Self {
        Self::builder()
            .committee(
                Address::from_str(MYSTEN_TESTNET_COMMITTEE).expect("valid constant"),
                MYSTEN_TESTNET_AGGREGATOR,
            )
            .threshold(1)
            .build()
            .expect("valid preset")
    }

    /// Empty builder with the testnet fullnode, verification on, 20 s timeout and the
    /// default retry policy. Add servers and set a threshold, then call `build`.
    pub fn builder() -> SealConfigBuilder {
        SealConfigBuilder {
            config: Self {
                key_servers: Vec::new(),
                threshold: 0,
                ..Self::base()
            },
        }
    }

    fn base() -> Self {
        Self {
            key_servers: Vec::new(),
            threshold: 0,
            fullnode_url: TESTNET_FULLNODE.to_string(),
            verify_key_servers: true,
            timeout: Duration::from_secs(20),
            retry: RetryPolicy::default(),
            server_options: BTreeMap::new(),
        }
    }

    /// Options of `id` (defaults when not set).
    pub fn options_for(&self, id: &Address) -> KeyServerOptions {
        self.server_options.get(id).cloned().unwrap_or_default()
    }

    /// Sum of the weights of the configured servers.
    pub fn total_weight(&self) -> usize {
        self.key_servers
            .iter()
            .map(|id| usize::from(self.options_for(id).weight))
            .sum()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.key_servers.is_empty() {
            return Err(Error::InvalidInput("no key servers configured".into()));
        }
        let mut sorted = self.key_servers.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != self.key_servers.len() {
            return Err(Error::InvalidInput("duplicate key server ids".into()));
        }
        for id in self.server_options.keys() {
            if !self.key_servers.contains(id) {
                return Err(Error::InvalidInput(format!(
                    "options given for {id}, which is not a configured key server"
                )));
            }
        }
        for (id, opts) in &self.server_options {
            if opts.weight == 0 {
                return Err(Error::InvalidInput(format!("key server {id}: weight 0")));
            }
            if let Some(url) = &opts.aggregator_url {
                validate_url(url)?;
            }
            if let Some(key) = &opts.api_key {
                key.validate()?;
            }
        }
        validate_weights(self.total_weight(), self.threshold)
    }
}

fn validate_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| Error::InvalidInput(format!("aggregator URL {url}: {e}")))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(Error::InvalidInput(format!(
            "aggregator URL {url}: scheme must be http or https"
        )));
    }
    Ok(())
}

/// Checks `1 <= threshold <= total_weight <= 255`.
pub(crate) fn validate_weights(total_weight: usize, threshold: u8) -> Result<()> {
    if total_weight > MAX_TOTAL_WEIGHT {
        return Err(Error::InvalidInput(format!(
            "total key server weight {total_weight} exceeds {MAX_TOTAL_WEIGHT}"
        )));
    }
    if threshold == 0 || usize::from(threshold) > total_weight {
        return Err(Error::InvalidInput(format!(
            "threshold {threshold} must be between 1 and the total key server weight ({total_weight})"
        )));
    }
    Ok(())
}

/// Builder for [`SealConfig`]. BETA (v0.2).
///
/// ```
/// use sui_seal_client::{Address, SealConfig, MYSTEN_TESTNET_1, MYSTEN_TESTNET_COMMITTEE,
///     MYSTEN_TESTNET_AGGREGATOR};
/// # fn main() -> sui_seal_client::Result<()> {
/// // Hybrid: the Mysten committee and one independent server, both needed.
/// let config = SealConfig::builder()
///     .committee(MYSTEN_TESTNET_COMMITTEE.parse::<Address>().unwrap(), MYSTEN_TESTNET_AGGREGATOR)
///     .key_server(MYSTEN_TESTNET_1.parse::<Address>().unwrap())
///     .threshold(2)
///     .build()?;
/// assert_eq!(config.total_weight(), 2);
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct SealConfigBuilder {
    config: SealConfig,
}

impl SealConfigBuilder {
    /// Adds an independent key server with default options (weight 1).
    pub fn key_server(self, id: Address) -> Self {
        self.key_server_with(id, KeyServerOptions::default())
    }

    /// Adds a key server with explicit options. Order matters: it is the order of the
    /// shares in encrypted objects.
    pub fn key_server_with(mut self, id: Address, options: KeyServerOptions) -> Self {
        self.config.key_servers.push(id);
        if options == KeyServerOptions::default() {
            self.config.server_options.remove(&id);
        } else {
            self.config.server_options.insert(id, options);
        }
        self
    }

    /// Adds a committee (decentralized) key server reached through `aggregator_url`.
    pub fn committee(self, id: Address, aggregator_url: impl Into<String>) -> Self {
        self.key_server_with(
            id,
            KeyServerOptions::default().aggregator_url(aggregator_url),
        )
    }

    /// Total weight needed to decrypt.
    pub fn threshold(mut self, threshold: u8) -> Self {
        self.config.threshold = threshold;
        self
    }

    pub fn fullnode_url(mut self, url: impl Into<String>) -> Self {
        self.config.fullnode_url = url.into();
        self
    }

    pub fn verify_key_servers(mut self, verify: bool) -> Self {
        self.config.verify_key_servers = verify;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.config.retry = retry;
        self
    }

    /// Validates and returns the configuration.
    pub fn build(self) -> Result<SealConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(n: u8) -> Address {
        Address::new([n; 32])
    }

    #[test]
    fn testnet_preset_is_unchanged() {
        let c = SealConfig::testnet();
        assert_eq!(c.key_servers.len(), 2);
        assert_eq!(c.key_servers[0].to_string(), MYSTEN_TESTNET_1);
        assert_eq!(c.key_servers[1].to_string(), MYSTEN_TESTNET_2);
        assert_eq!(c.threshold, 2);
        assert!(c.verify_key_servers);
        assert!(c.server_options.is_empty());
        assert_eq!(c.total_weight(), 2);
        c.validate().unwrap();
    }

    #[test]
    fn committee_preset() {
        let c = SealConfig::testnet_committee();
        assert_eq!(c.key_servers.len(), 1);
        assert_eq!(c.key_servers[0].to_string(), MYSTEN_TESTNET_COMMITTEE);
        assert_eq!(c.threshold, 1);
        assert_eq!(
            c.options_for(&c.key_servers[0]).aggregator_url.as_deref(),
            Some(MYSTEN_TESTNET_AGGREGATOR)
        );
    }

    #[test]
    fn builder_weights_and_threshold() {
        let c = SealConfig::builder()
            .key_server_with(a(1), KeyServerOptions::default().weight(2))
            .key_server(a(2))
            .threshold(3)
            .build()
            .unwrap();
        assert_eq!(c.total_weight(), 3);
        assert_eq!(c.options_for(&a(1)).weight, 2);
        assert_eq!(c.options_for(&a(2)), KeyServerOptions::default());
        assert!(!c.server_options.contains_key(&a(2)));

        let err = |b: SealConfigBuilder| b.build().unwrap_err().to_string();
        assert!(err(SealConfig::builder().threshold(1)).contains("no key servers"));
        assert!(err(SealConfig::builder().key_server(a(1))).contains("threshold 0"));
        assert!(err(SealConfig::builder().key_server(a(1)).threshold(2)).contains("threshold 2"));
        assert!(
            err(SealConfig::builder()
                .key_server(a(1))
                .key_server(a(1))
                .threshold(1))
            .contains("duplicate")
        );
        assert!(
            err(SealConfig::builder()
                .key_server_with(a(1), KeyServerOptions::default().weight(0))
                .threshold(1))
            .contains("weight 0")
        );
        assert!(
            err(SealConfig::builder()
                .key_server_with(a(1), KeyServerOptions::default().weight(200))
                .key_server_with(a(2), KeyServerOptions::default().weight(100))
                .threshold(1))
            .contains("exceeds")
        );
        assert!(
            err(SealConfig::builder()
                .committee(a(1), "ftp://x")
                .threshold(1))
            .contains("scheme")
        );
        assert!(
            err(SealConfig::builder()
                .committee(a(1), "not a url")
                .threshold(1))
            .contains("aggregator URL")
        );
    }

    #[test]
    fn options_for_unknown_server_rejected() {
        let mut c = SealConfig::testnet();
        c.server_options
            .insert(a(9), KeyServerOptions::default().weight(2));
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("not a configured")
        );
    }

    #[test]
    fn api_key_is_redacted_and_validated() {
        let k = ApiKey::new("x-api-key", "s3cr3t-value");
        let dbg = format!("{:?}", KeyServerOptions::default().api_key(k.clone()));
        assert!(dbg.contains("x-api-key"));
        assert!(!dbg.contains("s3cr3t"));
        k.validate().unwrap();
        assert!(ApiKey::new("bad header", "v").validate().is_err());
        assert!(ApiKey::new("h", "line\nbreak").validate().is_err());
        assert!(
            SealConfig::builder()
                .key_server_with(
                    a(1),
                    KeyServerOptions::default().api_key(ApiKey::new("bad header", "v"))
                )
                .threshold(1)
                .build()
                .is_err()
        );
    }

    #[test]
    fn struct_update_syntax_from_v01_still_works() {
        let c = SealConfig {
            key_servers: vec![a(1), a(2), a(3)],
            threshold: 2,
            ..SealConfig::testnet()
        };
        c.validate().unwrap();
        assert_eq!(c.total_weight(), 3);
    }
}
