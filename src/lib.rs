//! High-level Rust client for [Seal](https://github.com/MystenLabs/seal): threshold
//! encryption with access control enforced by Move policies on Sui.
//!
//! This crate is a thin layer over Mysten's own primitives (`crypto` and `seal-sdk`
//! from `MystenLabs/seal`, pinned by commit). It adds no cryptography of its own: it
//! reads key servers onchain, builds and signs session certificates and requests, calls
//! `/v1/fetch_key`, retries, and combines keys.
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
mod rpc;
mod session;

pub use approval::{ApprovalArg, ApprovalTx};
pub use client::{DerivedKeys, EncryptedInfo, SealClient, parse_encrypted_object};
pub use config::{MYSTEN_TESTNET_1, MYSTEN_TESTNET_2, RetryPolicy, SealConfig, TESTNET_FULLNODE};
pub use error::{Error, Failures, KeyServerErrorKind, Result};
pub use key_server::KeyServer;
pub use session::{CLOCK_SKEW_ALLOWANCE_MS, MAX_TTL_MIN, PersonalMessageSigner, SessionKey};

/// Re-exported so callers use the same types as this crate.
pub use sui_sdk_types::Address;

pub(crate) const SDK_TYPE: &str = "rust";
pub(crate) const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
