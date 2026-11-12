//! Key server discovery (onchain) and proof-of-possession verification.

use std::time::Duration;

use crypto::IBEPublicKeys;
use fastcrypto::bls12381::min_sig::{BLS12381PublicKey, BLS12381Signature};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::{ToFromBytes, VerifyingKey};
use seal_sdk::IBEPublicKey;
use serde::Deserialize;
use sui_sdk_types::Address;

use crate::error::{Error, Result};
use crate::rpc::Rpc;
use crate::{SDK_TYPE, SDK_VERSION};

/// Domain separation tag of the proof of possession (`crypto::DST_POP`).
use crypto::DST_POP;

/// Oldest key server version accepted, as in the TypeScript SDK.
const MIN_SERVER_VERSION: (u64, u64, u64) = (0, 4, 1);
/// Versioned key server layouts this client understands, preferred first.
const SUPPORTED_VERSIONS: [u64; 2] = [2, 1];
const KEY_TYPE_BONEH_FRANKLIN_BLS12381: u8 = 0;
const G2_LEN: usize = 96;

/// An independent Seal key server.
#[derive(Clone, Debug)]
pub struct KeyServer {
    pub object_id: Address,
    pub name: String,
    pub url: String,
    pub(crate) public_key: IBEPublicKey,
}

impl KeyServer {
    /// Builds a key server from known values (no onchain read).
    /// `public_key` is the 96-byte compressed BLS12-381 G2 public key.
    pub fn new(object_id: Address, name: String, url: String, public_key: &[u8]) -> Result<Self> {
        let invalid = |reason: String| Error::InvalidKeyServer {
            object_id: object_id.to_string(),
            reason,
        };
        let raw: &[u8; G2_LEN] = public_key
            .try_into()
            .map_err(|_| invalid(format!("public key must be {G2_LEN} bytes")))?;
        let public_key = IBEPublicKey::from_byte_array(raw)
            .map_err(|e| invalid(format!("public key is not a valid G2 element: {e}")))?;
        Ok(Self {
            object_id,
            name,
            url: url.trim_end_matches('/').to_string(),
            public_key,
        })
    }

    /// Compressed public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_byte_array().to_vec()
    }
}

#[derive(Deserialize)]
struct KeyServerObject {
    _id: Address,
    first_version: u64,
    last_version: u64,
}

#[derive(Deserialize)]
struct KeyServerV1 {
    name: String,
    url: String,
    key_type: u8,
    pk: Vec<u8>,
}

#[derive(Deserialize)]
struct PartialKeyServer {
    _name: String,
    _url: String,
    _partial_pk: Vec<u8>,
    _party_id: u16,
}

#[derive(Deserialize)]
enum ServerType {
    Independent {
        url: String,
    },
    Committee {
        _version: u32,
        _threshold: u16,
        _partial_key_servers: Vec<PartialKeyServer>,
    },
}

#[derive(Deserialize)]
struct KeyServerV2 {
    name: String,
    key_type: u8,
    pk: Vec<u8>,
    server_type: ServerType,
}

pub(crate) async fn retrieve(rpc: &Rpc, object_id: Address) -> Result<KeyServer> {
    let invalid = |reason: String| Error::InvalidKeyServer {
        object_id: object_id.to_string(),
        reason,
    };
    let contents = rpc.object_contents(&object_id).await?;
    let parent: KeyServerObject =
        bcs::from_bytes(&contents).map_err(|e| invalid(format!("not a KeyServer object: {e}")))?;
    let version = SUPPORTED_VERSIONS
        .iter()
        .copied()
        .find(|v| *v >= parent.first_version && *v <= parent.last_version)
        .ok_or_else(|| {
            invalid(format!(
                "supports versions {}..={}, client expects one of {SUPPORTED_VERSIONS:?}",
                parent.first_version, parent.last_version
            ))
        })?;
    let name_bcs = bcs::to_bytes(&version).expect("u64 serializes");
    let value = rpc.dynamic_field_value(&object_id, &name_bcs).await?;
    let (name, url, key_type, pk) = match version {
        2 => {
            let v2: KeyServerV2 =
                bcs::from_bytes(&value).map_err(|e| invalid(format!("KeyServerV2: {e}")))?;
            match v2.server_type {
                ServerType::Independent { url } => (v2.name, url, v2.key_type, v2.pk),
                ServerType::Committee { .. } => {
                    return Err(invalid(
                        "committee key servers (aggregator) are not supported in v0.1".into(),
                    ));
                }
            }
        }
        _ => {
            let v1: KeyServerV1 =
                bcs::from_bytes(&value).map_err(|e| invalid(format!("KeyServerV1: {e}")))?;
            (v1.name, v1.url, v1.key_type, v1.pk)
        }
    };
    if key_type != KEY_TYPE_BONEH_FRANKLIN_BLS12381 {
        return Err(invalid(format!("unsupported key type {key_type}")));
    }
    KeyServer::new(object_id, name, url, &pk)
}

#[derive(Deserialize)]
struct ServiceResponse {
    service_id: String,
    pop: String,
}

/// Fetches `/v1/service` and verifies the server's proof of possession of its master key,
/// bound to its object id. Mirrors `verifyKeyServer` in `@mysten/seal`.
pub(crate) async fn verify(
    http: &reqwest::Client,
    server: &KeyServer,
    timeout: Duration,
) -> Result<()> {
    let invalid = |reason: String| Error::InvalidKeyServer {
        object_id: server.object_id.to_string(),
        reason,
    };
    let url = format!("{}/v1/service?service_id={}", server.url, server.object_id);
    let response = http
        .get(url)
        .header("Request-Id", uuid::Uuid::new_v4().to_string())
        .header("Client-Sdk-Type", SDK_TYPE)
        .header("Client-Sdk-Version", SDK_VERSION)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| Error::Transport(format!("{}: {e}", server.url)))?;
    if !response.status().is_success() {
        return Err(invalid(format!(
            "/v1/service returned {}",
            response.status()
        )));
    }
    check_server_version(&response).map_err(invalid)?;
    let body: ServiceResponse = response
        .json()
        .await
        .map_err(|e| invalid(format!("/v1/service reply: {e}")))?;
    if parse_address(&body.service_id) != Some(server.object_id) {
        return Err(invalid(format!("service id mismatch: {}", body.service_id)));
    }
    let pop = Base64::decode(&body.pop).map_err(|e| invalid(format!("pop encoding: {e}")))?;
    verify_pop(server, &pop).map_err(invalid)
}

fn parse_address(s: &str) -> Option<Address> {
    s.parse().ok()
}

pub(crate) fn verify_pop(server: &KeyServer, pop: &[u8]) -> std::result::Result<(), String> {
    let pk_bytes = server.public_key_bytes();
    let mut msg = DST_POP.to_vec();
    msg.extend_from_slice(&pk_bytes);
    msg.extend_from_slice(server.object_id.as_bytes());
    let pk = BLS12381PublicKey::from_bytes(&pk_bytes).map_err(|e| format!("public key: {e}"))?;
    let sig = BLS12381Signature::from_bytes(pop).map_err(|e| format!("pop: {e}"))?;
    pk.verify(&msg, &sig)
        .map_err(|_| "proof of possession does not verify".to_string())
}

pub(crate) fn check_server_version(
    response: &reqwest::Response,
) -> std::result::Result<(), String> {
    let value = response
        .headers()
        .get("X-KeyServer-Version")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "missing X-KeyServer-Version header".to_string())?;
    let parsed = parse_version(value).ok_or_else(|| format!("bad server version {value}"))?;
    if parsed < MIN_SERVER_VERSION {
        return Err(format!("key server version {value} is too old"));
    }
    Ok(())
}

fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

pub(crate) fn public_keys(servers: &[&KeyServer]) -> IBEPublicKeys {
    IBEPublicKeys::BonehFranklinBLS12381(servers.iter().map(|s| s.public_key).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version("0.4.1"), Some((0, 4, 1)));
        assert_eq!(parse_version("0.6.16-abc"), Some((0, 6, 16)));
        assert_eq!(parse_version("1.2"), None);
        assert!(parse_version("0.4.0").unwrap() < MIN_SERVER_VERSION);
    }

    #[test]
    fn pop_roundtrip_with_mysten_primitives() {
        use rand::thread_rng;
        let (master, pk) = crypto::ibe::generate_key_pair(&mut thread_rng());
        let oid = Address::new([7u8; 32]);
        let pk_raw = pk.to_byte_array().to_vec();
        let server = KeyServer::new(oid, "t".into(), "http://x/".into(), &pk_raw).unwrap();
        assert_eq!(server.url, "http://x");
        assert_eq!(server.public_key_bytes(), pk_raw);
        let pop = crypto::ibe::create_proof_of_possession(&master, oid.as_bytes());
        let pop_raw = pop.to_byte_array().to_vec();
        verify_pop(&server, &pop_raw).unwrap();
        // Bound to the object id: another id must fail.
        let other =
            KeyServer::new(Address::new([8u8; 32]), "t".into(), "u".into(), &pk_raw).unwrap();
        assert!(verify_pop(&other, &pop_raw).is_err());
    }

    #[test]
    fn rejects_bad_public_key() {
        assert!(KeyServer::new(Address::ZERO, "x".into(), "u".into(), &[1u8; 96]).is_err());
        assert!(KeyServer::new(Address::ZERO, "x".into(), "u".into(), &[0u8; 10]).is_err());
    }
}
