//! Session keys: a short-lived Ed25519 key, certified by the user's Sui key.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519Signature};
use fastcrypto::traits::{KeyPair, Signer};
use seal_sdk::types::{ElGamalPublicKey, ElgamalVerificationKey};
use seal_sdk::{Certificate, signed_message, signed_request};
use sui_sdk_types::{Address, PersonalMessage, ProgrammableTransaction, UserSignature};

use crate::error::{Error, Result};

/// Maximum TTL accepted by the TypeScript SDK and the default key server config.
pub const MAX_TTL_MIN: u16 = 30;
/// Safety margin before expiry, as in the TypeScript SDK.
const EXPIRY_MARGIN_MS: u64 = 10_000;
/// The certificate's creation time is set this far in the past. Key servers reject a
/// creation time in the future with no tolerance, so a client clock running slightly
/// ahead of the server's would otherwise get `InvalidCertificate`. The cost is a session
/// that lasts this much less than `ttl_min`.
pub const CLOCK_SKEW_ALLOWANCE_MS: u64 = 5_000;

/// Anything that can sign a Sui personal message for a given address.
pub trait PersonalMessageSigner {
    /// The Sui address the signature authenticates.
    fn sui_address(&self) -> Address;
    /// Signs `message` as a Sui personal message (intent scope 3).
    fn sign_personal_message(&self, message: &[u8]) -> std::result::Result<UserSignature, String>;
}

impl PersonalMessageSigner for sui_crypto::ed25519::Ed25519PrivateKey {
    fn sui_address(&self) -> Address {
        self.public_key().derive_address()
    }

    fn sign_personal_message(&self, message: &[u8]) -> std::result::Result<UserSignature, String> {
        sui_crypto::SuiSigner::sign_personal_message(
            self,
            &PersonalMessage(std::borrow::Cow::Borrowed(message)),
        )
        .map_err(|e| e.to_string())
    }
}

/// A Seal session key for one package.
///
/// The user signs one personal message per session; each key request is then signed by
/// the ephemeral session key. The session secret never leaves this struct.
pub struct SessionKey {
    address: Address,
    package_id: Address,
    mvr_name: Option<String>,
    creation_time_ms: u64,
    ttl_min: u16,
    session: Ed25519KeyPair,
    signature: UserSignature,
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKey")
            .field("address", &self.address)
            .field("package_id", &self.package_id)
            .field("mvr_name", &self.mvr_name)
            .field("creation_time_ms", &self.creation_time_ms)
            .field("ttl_min", &self.ttl_min)
            .finish_non_exhaustive()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl SessionKey {
    /// Creates a session key for `package_id` and has `signer` certify it.
    ///
    /// Prefer [`crate::SealClient::session_key`], which also checks onchain that
    /// `package_id` is the first version of the package, as key servers require.
    pub fn new(
        package_id: Address,
        ttl_min: u16,
        signer: &impl PersonalMessageSigner,
    ) -> Result<Self> {
        Self::with_mvr_name(package_id, None, ttl_min, signer)
    }

    /// Same as [`SessionKey::new`] with an optional MVR package name.
    pub fn with_mvr_name(
        package_id: Address,
        mvr_name: Option<String>,
        ttl_min: u16,
        signer: &impl PersonalMessageSigner,
    ) -> Result<Self> {
        if !(1..=MAX_TTL_MIN).contains(&ttl_min) {
            return Err(Error::InvalidInput(format!(
                "ttl_min {ttl_min} must be between 1 and {MAX_TTL_MIN}"
            )));
        }
        let session = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let creation_time_ms = now_ms().saturating_sub(CLOCK_SKEW_ALLOWANCE_MS);
        let package_name = mvr_name.clone().unwrap_or_else(|| package_id.to_string());
        let message = signed_message(package_name, session.public(), creation_time_ms, ttl_min);
        let signature = signer
            .sign_personal_message(message.as_bytes())
            .map_err(Error::Signer)?;
        Ok(Self {
            address: signer.sui_address(),
            package_id,
            mvr_name,
            creation_time_ms,
            ttl_min,
            session,
            signature,
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn package_id(&self) -> Address {
        self.package_id
    }

    pub fn ttl_min(&self) -> u16 {
        self.ttl_min
    }

    /// Expired, or within 10 seconds of expiry.
    pub fn is_expired(&self) -> bool {
        self.creation_time_ms + u64::from(self.ttl_min) * 60_000 < now_ms() + EXPIRY_MARGIN_MS
    }

    pub(crate) fn certificate(&self) -> Certificate {
        Certificate {
            user: self.address,
            session_vk: self.session.public().clone(),
            creation_time: self.creation_time_ms,
            ttl_min: self.ttl_min,
            signature: self.signature.clone(),
            mvr_name: self.mvr_name.clone(),
        }
    }

    pub(crate) fn sign_request(
        &self,
        ptb: &ProgrammableTransaction,
        enc_key: &ElGamalPublicKey,
        enc_verification_key: &ElgamalVerificationKey,
    ) -> Ed25519Signature {
        self.session
            .sign(&signed_request(ptb, enc_key, enc_verification_key))
    }

    #[cfg(test)]
    pub(crate) fn backdate(&mut self, ms: u64) {
        self.creation_time_ms -= ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::traits::VerifyingKey;
    use sui_crypto::ed25519::Ed25519PrivateKey;

    fn signer() -> Ed25519PrivateKey {
        Ed25519PrivateKey::new([9u8; 32])
    }

    #[test]
    fn ttl_bounds() {
        let s = signer();
        assert!(SessionKey::new(Address::ZERO, 0, &s).is_err());
        assert!(SessionKey::new(Address::ZERO, 31, &s).is_err());
        assert!(SessionKey::new(Address::ZERO, 30, &s).is_ok());
    }

    #[test]
    fn certificate_signature_verifies_and_expiry() {
        use sui_crypto::SuiVerifier;
        let s = signer();
        let pkg = Address::new([3u8; 32]);
        let mut key = SessionKey::new(pkg, 1, &s).unwrap();
        assert_eq!(key.address(), s.sui_address());
        let cert = key.certificate();
        let msg = signed_message(pkg.to_string(), &cert.session_vk, cert.creation_time, 1);
        let verifier = sui_crypto::ed25519::Ed25519Verifier::new();
        verifier
            .verify_personal_message(
                &PersonalMessage(std::borrow::Cow::Borrowed(msg.as_bytes())),
                &cert.signature,
            )
            .unwrap();
        assert!(!key.is_expired());
        key.backdate(55_000 - CLOCK_SKEW_ALLOWANCE_MS);
        assert!(key.is_expired(), "inside the 10 s margin counts as expired");
    }

    #[test]
    fn request_signature_verifies_with_session_vk() {
        let s = signer();
        let key = SessionKey::new(Address::ZERO, 5, &s).unwrap();
        let ptb = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![],
        };
        let (_, pk, vk) = seal_sdk::genkey::<crypto::ibe::UserSecretKey, crypto::ibe::PublicKey, _>(
            &mut rand::thread_rng(),
        );
        let sig = key.sign_request(&ptb, &pk, &vk);
        key.certificate()
            .session_vk
            .verify(&signed_request(&ptb, &pk, &vk), &sig)
            .unwrap();
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let key = SessionKey::new(Address::ZERO, 5, &signer()).unwrap();
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("session:"));
        assert!(!dbg.contains("signature"));
    }
}
