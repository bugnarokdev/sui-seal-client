use std::fmt;

/// Errors returned by this crate.
///
/// Messages never contain key material.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Bad input from the caller (threshold, ids, TTL, configuration).
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// A key server object onchain is missing, malformed or unsupported.
    #[error("invalid key server {object_id}: {reason}")]
    InvalidKeyServer { object_id: String, reason: String },
    /// A key server answered with an error.
    #[error("key server {server} refused: {kind}: {message}")]
    KeyServer {
        server: String,
        kind: KeyServerErrorKind,
        message: String,
    },
    /// Not enough key servers answered to reach the threshold. `got` and `threshold`
    /// are weights (server counts when every weight is 1).
    #[error("threshold not reached: weight {got} of {threshold} answered ({failures})")]
    ThresholdNotReached {
        got: usize,
        threshold: usize,
        failures: Failures,
    },
    /// Network or HTTP transport failure.
    #[error("transport: {0}")]
    Transport(String),
    /// Sui fullnode (gRPC) failure.
    #[error("sui rpc: {0}")]
    Rpc(String),
    /// Encryption, decryption or key verification failed.
    #[error("crypto: {0}")]
    Crypto(String),
    /// Decoding of an encrypted object or a server reply failed.
    #[error("decode: {0}")]
    Decode(String),
    /// The session key has expired.
    #[error("session key expired")]
    SessionExpired,
    /// Signing the session certificate failed.
    #[error("signer: {0}")]
    Signer(String),
}

/// Error codes returned by Seal key servers (`error` field of the JSON reply).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyServerErrorKind {
    InvalidPtb,
    InvalidPackage,
    NoAccess,
    InvalidCertificate,
    InvalidSignature,
    InvalidSessionSignature,
    InvalidParameter,
    InvalidMvrName,
    InvalidSdkVersion,
    DeprecatedSdkVersion,
    MissingRequiredHeader,
    InvalidServiceId,
    UnsupportedPackageId,
    Failure,
    RateLimited,
    Other(String),
}

impl KeyServerErrorKind {
    pub(crate) fn from_code(code: &str) -> Self {
        match code {
            "InvalidPTB" => Self::InvalidPtb,
            "InvalidPackage" => Self::InvalidPackage,
            "NoAccess" => Self::NoAccess,
            "InvalidCertificate" => Self::InvalidCertificate,
            "InvalidSignature" => Self::InvalidSignature,
            "InvalidSessionSignature" => Self::InvalidSessionSignature,
            "InvalidParameter" => Self::InvalidParameter,
            "InvalidMVRName" => Self::InvalidMvrName,
            "InvalidSDKVersion" | "InvalidSDKType" => Self::InvalidSdkVersion,
            "DeprecatedSDKVersion" => Self::DeprecatedSdkVersion,
            "MissingRequiredHeader" => Self::MissingRequiredHeader,
            "InvalidServiceId" => Self::InvalidServiceId,
            "UnsupportedPackageId" => Self::UnsupportedPackageId,
            "Failure" => Self::Failure,
            other => Self::Other(other.to_string()),
        }
    }

    /// Whether a retry may succeed: server failures, rate limits, and
    /// `InvalidParameter`, which the server also returns while a freshly
    /// created object is not yet indexed by its fullnode.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Failure | Self::RateLimited | Self::InvalidParameter
        )
    }
}

impl fmt::Display for KeyServerErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(code) => write!(f, "{code}"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// Text of the key server's (fullnode's) refusal when the approval transaction passes an
/// owned object the session address does not own.
const WRONG_OWNER_MARK: &str = "not signed by the correct sender";

pub(crate) fn is_wrong_owner_message(kind: &KeyServerErrorKind, message: &str) -> bool {
    *kind == KeyServerErrorKind::InvalidParameter && message.contains(WRONG_OWNER_MARK)
}

impl Error {
    /// True when the approval transaction used an owned object (a `PrivateData`, a
    /// `Subscription`...) that the session address does not own. Key servers report it
    /// as `InvalidParameter` before running `seal_approve`; it is not retried. BETA.
    pub fn is_wrong_owner(&self) -> bool {
        match self {
            Error::KeyServer { kind, message, .. } => is_wrong_owner_message(kind, message),
            Error::ThresholdNotReached { failures, .. } => {
                !failures.0.is_empty() && failures.0.iter().all(Error::is_wrong_owner)
            }
            _ => false,
        }
    }

    /// True when the error comes from a policy refusal (`seal_approve` aborted).
    pub fn is_no_access(&self) -> bool {
        match self {
            Error::KeyServer { kind, .. } => *kind == KeyServerErrorKind::NoAccess,
            Error::ThresholdNotReached { failures, .. } => {
                failures.0.iter().any(Error::is_no_access)
            }
            _ => false,
        }
    }
}

/// Per-server failures behind [`Error::ThresholdNotReached`].
#[derive(Debug)]
pub struct Failures(pub Vec<Error>);

impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{e}")?;
        }
        Ok(())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(kind: &str) -> Error {
        Error::KeyServer {
            server: "s".into(),
            kind: KeyServerErrorKind::from_code(kind),
            message: "m".into(),
        }
    }

    #[test]
    fn no_access_detection() {
        assert!(refused("NoAccess").is_no_access());
        assert!(!refused("Failure").is_no_access());
        let e = Error::ThresholdNotReached {
            got: 1,
            threshold: 2,
            failures: Failures(vec![refused("NoAccess")]),
        };
        assert!(e.is_no_access());
        assert!(e.to_string().contains("NoAccess"));
        let e = Error::ThresholdNotReached {
            got: 0,
            threshold: 2,
            failures: Failures(vec![Error::Transport("down".into())]),
        };
        assert!(!e.is_no_access());
    }

    #[test]
    fn wrong_owner_detection() {
        let owned = |m: &str| Error::KeyServer {
            server: "s".into(),
            kind: KeyServerErrorKind::InvalidParameter,
            message: m.into(),
        };
        let msg = "Invalid parameter to PTB: Transaction was not signed by the correct sender: Object 0x1 is owned by account address 0x2";
        assert!(owned(msg).is_wrong_owner());
        assert!(!owned("object not found yet").is_wrong_owner());
        assert!(!refused("NoAccess").is_wrong_owner());
        let all = Error::ThresholdNotReached {
            got: 0,
            threshold: 2,
            failures: Failures(vec![owned(msg), owned(msg)]),
        };
        assert!(all.is_wrong_owner());
        assert!(!all.is_no_access());
        let mixed = Error::ThresholdNotReached {
            got: 0,
            threshold: 2,
            failures: Failures(vec![owned(msg), Error::Transport("x".into())]),
        };
        assert!(!mixed.is_wrong_owner());
    }
}
