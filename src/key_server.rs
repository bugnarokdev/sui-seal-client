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

use crate::config::{ApiKey, KeyServerOptions};
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

/// How a key server is operated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyServerKind {
    /// One operator holding the master key.
    Independent,
    /// Decentralized server: a committee shares the master key (DKG) and an aggregator
    /// combines the partial answers. Seen by clients as a single server. BETA.
    Committee {
        /// Committee version, bumped on member rotation.
        version: u32,
        /// Partial answers the aggregator needs.
        threshold: u16,
        /// Number of committee members.
        members: usize,
    },
}

/// A Seal key server: independent, or a committee behind its aggregator.
#[derive(Clone, Debug)]
pub struct KeyServer {
    pub object_id: Address,
    pub name: String,
    /// Server URL, or the aggregator URL for a committee.
    pub url: String,
    pub(crate) public_key: IBEPublicKey,
    kind: KeyServerKind,
    weight: u8,
    api_key: Option<ApiKey>,
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
            kind: KeyServerKind::Independent,
            weight: 1,
            api_key: None,
        })
    }

    /// Sets the weight (number of shares held by this server, 1 by default). BETA.
    pub fn with_weight(mut self, weight: u8) -> Result<Self> {
        if weight == 0 {
            return Err(Error::InvalidInput(format!(
                "key server {}: weight 0",
                self.object_id
            )));
        }
        self.weight = weight;
        Ok(self)
    }

    /// Sets a header sent with every request to this server. BETA.
    pub fn with_api_key(mut self, key: ApiKey) -> Result<Self> {
        key.validate()?;
        self.api_key = Some(key);
        Ok(self)
    }

    /// Marks this server as a committee behind an aggregator (`url`). BETA.
    pub fn with_kind(mut self, kind: KeyServerKind) -> Self {
        self.kind = kind;
        self
    }

    /// Compressed public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_byte_array().to_vec()
    }

    pub fn kind(&self) -> &KeyServerKind {
        &self.kind
    }

    pub fn is_committee(&self) -> bool {
        matches!(self.kind, KeyServerKind::Committee { .. })
    }

    pub fn weight(&self) -> u8 {
        self.weight
    }

    pub(crate) fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(key) => request.header(key.header.as_str(), key.value.as_str()),
            None => request,
        }
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
        version: u32,
        threshold: u16,
        partial_key_servers: Vec<PartialKeyServer>,
    },
}

#[derive(Deserialize)]
struct KeyServerV2 {
    name: String,
    key_type: u8,
    pk: Vec<u8>,
    server_type: ServerType,
}

pub(crate) async fn retrieve(
    rpc: &Rpc,
    object_id: Address,
    options: &KeyServerOptions,
) -> Result<KeyServer> {
    let contents = rpc.object_contents(&object_id).await?;
    let parent =
        bcs::from_bytes::<KeyServerObject>(&contents).map_err(|e| Error::InvalidKeyServer {
            object_id: object_id.to_string(),
            reason: format!("not a KeyServer object: {e}"),
        })?;
    let version = pick_version(&object_id, parent.first_version, parent.last_version)?;
    let name_bcs = bcs::to_bytes(&version).expect("u64 serializes");
    let value = rpc.dynamic_field_value(&object_id, &name_bcs).await?;
    from_versioned(object_id, version, &value, options)
}

fn pick_version(object_id: &Address, first: u64, last: u64) -> Result<u64> {
    SUPPORTED_VERSIONS
        .iter()
        .copied()
        .find(|v| *v >= first && *v <= last)
        .ok_or_else(|| Error::InvalidKeyServer {
            object_id: object_id.to_string(),
            reason: format!(
                "supports versions {first}..={last}, client expects one of {SUPPORTED_VERSIONS:?}"
            ),
        })
}

/// Decodes the versioned key server value (`KeyServerV1` or `KeyServerV2`) and applies
/// the client-side options. Mirrors `retrieveKeyServers` in `@mysten/seal`.
fn from_versioned(
    object_id: Address,
    version: u64,
    value: &[u8],
    options: &KeyServerOptions,
) -> Result<KeyServer> {
    let invalid = |reason: String| Error::InvalidKeyServer {
        object_id: object_id.to_string(),
        reason,
    };
    let (name, url, key_type, pk, kind) = match version {
        2 => {
            let v2: KeyServerV2 =
                bcs::from_bytes(value).map_err(|e| invalid(format!("KeyServerV2: {e}")))?;
            match v2.server_type {
                ServerType::Independent { url } => {
                    if options.aggregator_url.is_some() {
                        return Err(invalid(
                            "independent server configured with an aggregator URL".into(),
                        ));
                    }
                    (v2.name, url, v2.key_type, v2.pk, KeyServerKind::Independent)
                }
                ServerType::Committee {
                    version,
                    threshold,
                    partial_key_servers,
                } => {
                    let url = options.aggregator_url.clone().ok_or_else(|| {
                        invalid("committee server requires an aggregator URL in its options".into())
                    })?;
                    let kind = KeyServerKind::Committee {
                        version,
                        threshold,
                        members: partial_key_servers.len(),
                    };
                    (v2.name, url, v2.key_type, v2.pk, kind)
                }
            }
        }
        _ => {
            let v1: KeyServerV1 =
                bcs::from_bytes(value).map_err(|e| invalid(format!("KeyServerV1: {e}")))?;
            if options.aggregator_url.is_some() {
                return Err(invalid(
                    "V1 servers are always independent and take no aggregator URL".into(),
                ));
            }
            (
                v1.name,
                v1.url,
                v1.key_type,
                v1.pk,
                KeyServerKind::Independent,
            )
        }
    };
    if key_type != KEY_TYPE_BONEH_FRANKLIN_BLS12381 {
        return Err(invalid(format!("unsupported key type {key_type}")));
    }
    let mut server = KeyServer::new(object_id, name, url, &pk)?
        .with_kind(kind)
        .with_weight(options.weight)?;
    if let Some(key) = &options.api_key {
        server = server.with_api_key(key.clone())?;
    }
    Ok(server)
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
    if server.is_committee() {
        // Aggregators do not serve /v1/service (no single master key, so no proof of
        // possession). `@mysten/seal` skips them too; every key they return is still
        // verified against the onchain committee public key.
        return Ok(());
    }
    let url = format!("{}/v1/service?service_id={}", server.url, server.object_id);
    let response = server
        .authorize(http.get(url))
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

    #[derive(serde::Serialize)]
    struct V1<'a> {
        name: &'a str,
        url: &'a str,
        key_type: u8,
        pk: Vec<u8>,
    }

    #[derive(serde::Serialize)]
    struct Partial {
        name: String,
        url: String,
        partial_pk: Vec<u8>,
        party_id: u16,
    }

    #[derive(serde::Serialize)]
    enum Type {
        Independent {
            url: String,
        },
        Committee {
            version: u32,
            threshold: u16,
            partial_key_servers: Vec<Partial>,
        },
    }

    #[derive(serde::Serialize)]
    struct V2 {
        name: String,
        key_type: u8,
        pk: Vec<u8>,
        server_type: Type,
    }

    fn pk() -> Vec<u8> {
        let (_, pk) = crypto::ibe::generate_key_pair(&mut rand::thread_rng());
        pk.to_byte_array().to_vec()
    }

    fn committee_v2(pk: Vec<u8>) -> Vec<u8> {
        bcs::to_bytes(&V2 {
            name: "committee".into(),
            key_type: 0,
            pk,
            server_type: Type::Committee {
                version: 3,
                threshold: 3,
                partial_key_servers: (0..5)
                    .map(|i| Partial {
                        name: format!("m{i}"),
                        url: format!("https://m{i}"),
                        partial_pk: vec![0; 96],
                        party_id: i,
                    })
                    .collect(),
            },
        })
        .unwrap()
    }

    #[test]
    fn decodes_committee_server_with_aggregator() {
        let id = Address::new([5; 32]);
        let raw = pk();
        let value = committee_v2(raw.clone());
        let opts = KeyServerOptions::default().aggregator_url("https://agg.example/");
        let s = from_versioned(id, 2, &value, &opts).unwrap();
        assert_eq!(s.url, "https://agg.example");
        assert_eq!(s.public_key_bytes(), raw);
        assert_eq!(
            s.kind(),
            &KeyServerKind::Committee {
                version: 3,
                threshold: 3,
                members: 5
            }
        );
        assert!(s.is_committee());
        // No aggregator configured: refused, as in @mysten/seal.
        let err = from_versioned(id, 2, &value, &KeyServerOptions::default()).unwrap_err();
        assert!(err.to_string().contains("aggregator"), "{err}");
    }

    #[test]
    fn decodes_independent_servers_and_options() {
        let id = Address::new([6; 32]);
        let v2 = bcs::to_bytes(&V2 {
            name: "ind".into(),
            key_type: 0,
            pk: pk(),
            server_type: Type::Independent {
                url: "https://ks/".into(),
            },
        })
        .unwrap();
        let opts = KeyServerOptions::default()
            .weight(3)
            .api_key(ApiKey::new("x-api-key", "k"));
        let s = from_versioned(id, 2, &v2, &opts).unwrap();
        assert_eq!(
            (s.url.as_str(), s.weight(), s.is_committee()),
            ("https://ks", 3, false)
        );
        assert!(s.api_key.is_some());
        let with_agg = KeyServerOptions::default().aggregator_url("https://agg");
        assert!(from_versioned(id, 2, &v2, &with_agg).is_err());

        let v1 = bcs::to_bytes(&V1 {
            name: "v1",
            url: "https://v1",
            key_type: 0,
            pk: pk(),
        })
        .unwrap();
        let s = from_versioned(id, 1, &v1, &KeyServerOptions::default()).unwrap();
        assert_eq!(s.kind(), &KeyServerKind::Independent);
        assert!(from_versioned(id, 1, &v1, &with_agg).is_err());

        let bad_type = bcs::to_bytes(&V1 {
            name: "v1",
            url: "u",
            key_type: 1,
            pk: pk(),
        })
        .unwrap();
        assert!(from_versioned(id, 1, &bad_type, &KeyServerOptions::default()).is_err());
        assert!(from_versioned(id, 2, b"junk", &KeyServerOptions::default()).is_err());
    }

    #[test]
    fn version_selection() {
        let id = Address::ZERO;
        assert_eq!(pick_version(&id, 1, 1).unwrap(), 1);
        assert_eq!(pick_version(&id, 1, 2).unwrap(), 2);
        assert_eq!(pick_version(&id, 2, 9).unwrap(), 2);
        assert!(pick_version(&id, 3, 9).is_err());
    }

    #[test]
    fn weight_and_api_key_setters() {
        let s = KeyServer::new(Address::ZERO, "x".into(), "u".into(), &pk()).unwrap();
        assert_eq!(s.weight(), 1);
        assert!(s.clone().with_weight(0).is_err());
        assert_eq!(s.clone().with_weight(4).unwrap().weight(), 4);
        assert!(
            s.clone()
                .with_api_key(ApiKey::new("bad header", "v"))
                .is_err()
        );
        let s = s.with_api_key(ApiKey::new("x-k", "secret-v")).unwrap();
        assert!(!format!("{s:?}").contains("secret-v"));
        let req = s
            .authorize(reqwest::Client::new().get("http://127.0.0.1:1/"))
            .build()
            .unwrap();
        assert_eq!(req.headers().get("x-k").unwrap(), "secret-v");
    }

    #[test]
    fn rejects_bad_public_key() {
        assert!(KeyServer::new(Address::ZERO, "x".into(), "u".into(), &[1u8; 96]).is_err());
        assert!(KeyServer::new(Address::ZERO, "x".into(), "u".into(), &[0u8; 10]).is_err());
    }
}
