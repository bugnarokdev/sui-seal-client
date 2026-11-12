//! High-level Rust client for [Seal](https://github.com/MystenLabs/seal): threshold
//! encryption with access control enforced by Move policies on Sui.
//!
//! This crate is a thin layer over Mysten's own primitives (`crypto` and `seal-sdk`
//! from `MystenLabs/seal`, pinned by commit). It adds no cryptography of its own: it
//! reads key servers onchain, builds and signs session certificates and requests, calls
//! `/v1/fetch_key`, retries, and combines keys.
//!
//! **BETA, testnet only.** v0.2 adds configurable key servers (weights, API keys),
//! committee key servers behind an aggregator, policy helpers ([`policy`]) and offline
//! test helpers (feature `testing`). See the README for the roadmap.
//!
//! ```no_run
//! # async fn demo() -> sui_seal_client::Result<()> {
//! use sui_seal_client::{ApprovalTx, SealClient, SealConfig};
//! # let (package_id, allowlist_id, signer): (sui_sdk_types::Address, sui_sdk_types::Address, sui_crypto::ed25519::Ed25519PrivateKey) = todo!();
//! let client = SealClient::connect(SealConfig::testnet()).await?;
//! let id = b"some-key-id";
//! let encrypted = client.encrypt(package_id, id, b"hello")?;
//!
//! let session = client.session_key(package_id, 10, &signer).await?;
//! let list = client.shared_object(allowlist_id).await?;
//! let approval = ApprovalTx::new(package_id).call("allowlist", "seal_approve", id, vec![list])?;
//! let plaintext = client.fetch_and_decrypt(&encrypted, &session, &approval).await?;
//! # Ok(()) }
//! ```

mod approval;
mod client;
mod config;
mod error;
mod key_server;
pub mod policy;
mod rpc;
mod session;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use approval::{ApprovalArg, ApprovalTx};
pub use client::{DerivedKeys, EncryptedInfo, SealClient, parse_encrypted_object};
pub use config::{
    ApiKey, KeyServerOptions, MAX_TOTAL_WEIGHT, MYSTEN_TESTNET_1, MYSTEN_TESTNET_2,
    MYSTEN_TESTNET_AGGREGATOR, MYSTEN_TESTNET_COMMITTEE, RetryPolicy, SealConfig,
    SealConfigBuilder, TESTNET_FULLNODE,
};
pub use error::{Error, Failures, KeyServerErrorKind, Result};
pub use key_server::{KeyServer, KeyServerKind};
pub use session::{CLOCK_SKEW_ALLOWANCE_MS, MAX_TTL_MIN, PersonalMessageSigner, SessionKey};

/// Re-exported so callers use the same types as this crate.
pub use sui_sdk_types::Address;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub(crate) const SDK_TYPE: &str = "rust";
pub(crate) const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
