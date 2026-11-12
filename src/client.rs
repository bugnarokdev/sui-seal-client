//! High-level client: encrypt, fetch keys, decrypt.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use crypto::ibe::UserSecretKey;
use crypto::{EncryptedObject, EncryptionInput, IBEPublicKeys, IBEUserSecretKeys, ObjectID};
use fastcrypto::encoding::{Base64, Encoding};
use futures::stream::{FuturesUnordered, StreamExt};
use seal_sdk::types::{ElGamalPublicKey, ElgamalVerificationKey};
use seal_sdk::{
    ElGamalSecretKey, FetchKeyRequest, FetchKeyResponse, IBEPublicKey, decrypt_seal_responses,
    seal_encrypt,
};
use serde::Deserialize;
use sui_sdk_types::Address;
use zeroize::Zeroizing;

use crate::approval::{ApprovalArg, ApprovalTx};
use crate::config::{RetryPolicy, SealConfig, validate_weights};
use crate::error::{Error, Failures, KeyServerErrorKind, Result, is_wrong_owner_message};
use crate::key_server::{self, KeyServer};
use crate::rpc::Rpc;
use crate::session::{PersonalMessageSigner, SessionKey};
use crate::{SDK_TYPE, SDK_VERSION};

/// Public header of an encrypted object, readable without any key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedInfo {
    pub package_id: Address,
    /// Inner id (without the package prefix).
    pub id: Vec<u8>,
    pub threshold: u8,
    pub key_servers: Vec<Address>,
}

/// Parses an encrypted object (BCS, the format shared with `@mysten/seal`).
pub fn parse_encrypted_object(bytes: &[u8]) -> Result<EncryptedInfo> {
    let object = decode(bytes)?;
    Ok(EncryptedInfo {
        package_id: object.package_id,
        id: object.id.clone(),
        threshold: object.threshold,
        key_servers: object.services.iter().map(|(id, _)| *id).collect(),
    })
}

fn decode(bytes: &[u8]) -> Result<EncryptedObject> {
    let object: EncryptedObject =
        bcs::from_bytes(bytes).map_err(|e| Error::Decode(format!("encrypted object: {e}")))?;
    if object.version != 0 {
        return Err(Error::Decode(format!(
            "unsupported encrypted object version {}",
            object.version
        )));
    }
    Ok(object)
}

/// User secret keys returned by key servers, already verified against each server's
/// public key. Indexed by full id, then by key server.
#[derive(Default)]
pub struct DerivedKeys {
    pub(crate) keys: HashMap<Vec<u8>, HashMap<ObjectID, UserSecretKey>>,
}

impl fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedKeys")
            .field("ids", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl DerivedKeys {
    /// Number of key servers that returned a key for `package_id || id`.
    pub fn servers_for(&self, package_id: &Address, id: &[u8]) -> usize {
        let full = crypto::create_full_id(&package_id.into_inner(), id);
        self.keys.get(&full).map_or(0, |m| m.len())
    }

    /// Merges keys from another fetch (for example a second batch of ids).
    pub fn extend(&mut self, other: DerivedKeys) {
        for (id, servers) in other.keys {
            self.keys.entry(id).or_default().extend(servers);
        }
    }
}

/// Seal client bound to a set of key servers and a threshold.
#[derive(Clone)]
pub struct SealClient {
    servers: Vec<KeyServer>,
    threshold: u8,
    http: reqwest::Client,
    rpc: Option<Rpc>,
    timeout: Duration,
    retry: RetryPolicy,
}

impl fmt::Debug for SealClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealClient")
            .field("servers", &self.servers)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

impl SealClient {
    /// Reads the key servers onchain and, if configured, verifies each proof of possession.
    pub async fn connect(config: SealConfig) -> Result<Self> {
        config.validate()?;
        let rpc = Rpc::new(&config.fullnode_url)?;
        let http = http_client()?;
        let mut servers = Vec::with_capacity(config.key_servers.len());
        for id in &config.key_servers {
            let server = key_server::retrieve(&rpc, *id, &config.options_for(id)).await?;
            if config.verify_key_servers {
                key_server::verify(&http, &server, config.timeout).await?;
            }
            servers.push(server);
        }
        Ok(Self {
            servers,
            threshold: config.threshold,
            http,
            rpc: Some(rpc),
            timeout: config.timeout,
            retry: config.retry,
        })
    }

    /// Builds a client from known key servers, without onchain reads. Weights and API
    /// keys are taken from each [`KeyServer`]. `session_key` and `shared_object` then
    /// need a fullnode: use [`SealClient::connect`].
    pub fn with_key_servers(servers: Vec<KeyServer>, threshold: u8) -> Result<Self> {
        let config = SealConfig {
            key_servers: servers.iter().map(|s| s.object_id).collect(),
            threshold: 1,
            ..SealConfig::testnet()
        };
        config.validate()?;
        validate_weights(total_weight(&servers), threshold)?;
        Ok(Self {
            servers,
            threshold,
            http: http_client()?,
            rpc: None,
            timeout: config.timeout,
            retry: config.retry,
        })
    }

    /// Overrides the retry policy.
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    pub fn key_servers(&self) -> &[KeyServer] {
        &self.servers
    }

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Sum of the configured server weights.
    pub fn total_weight(&self) -> usize {
        total_weight(&self.servers)
    }

    /// Server ids with multiplicity (one entry per unit of weight), in configuration
    /// order: the share layout of encrypted objects, as in `@mysten/seal`.
    fn weighted_servers(&self) -> Vec<&KeyServer> {
        self.servers
            .iter()
            .flat_map(|s| std::iter::repeat_n(s, usize::from(s.weight())))
            .collect()
    }

    /// Encrypts `plaintext` for `package_id || id` with AES-256-GCM.
    ///
    /// Returns the encrypted object (BCS). The symmetric key produced by the encryption
    /// (the "backup key" of the TypeScript SDK) is wiped before returning and is never
    /// logged or written anywhere.
    pub fn encrypt(&self, package_id: Address, id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_aad(package_id, id, plaintext, None)
    }

    /// Same as [`SealClient::encrypt`] with additional authenticated data.
    pub fn encrypt_with_aad(
        &self,
        package_id: Address,
        id: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if id.is_empty() {
            return Err(Error::InvalidInput("key id must not be empty".into()));
        }
        validate_weights(self.total_weight(), self.threshold)?;
        let refs = self.weighted_servers();
        let input = EncryptionInput::Aes256Gcm {
            data: plaintext.to_vec(),
            aad: aad.map(<[u8]>::to_vec),
        };
        let (object, dem_key) = seal_encrypt(
            package_id,
            id.to_vec(),
            refs.iter().map(|s| s.object_id).collect(),
            &key_server::public_keys(&refs),
            self.threshold,
            input,
        )
        .map_err(|e| Error::Crypto(format!("encrypt: {e}")))?;
        drop(Zeroizing::new(dem_key));
        bcs::to_bytes(&object).map_err(|e| Error::Decode(e.to_string()))
    }

    /// Creates a session key after checking that `package_id` is the first version of
    /// its package (key servers only accept the original package id).
    pub async fn session_key(
        &self,
        package_id: Address,
        ttl_min: u16,
        signer: &impl PersonalMessageSigner,
    ) -> Result<SessionKey> {
        let rpc = self.require_rpc()?;
        let version = rpc.object_version(&package_id).await?;
        if version != 1 {
            return Err(Error::InvalidInput(format!(
                "package {package_id} is at version {version}; use the original package id"
            )));
        }
        SessionKey::new(package_id, ttl_min, signer)
    }

    /// Argument for a shared object, with its initial shared version read onchain.
    pub async fn shared_object(&self, id: Address) -> Result<ApprovalArg> {
        let rpc = self.require_rpc()?;
        Ok(ApprovalArg::Shared {
            id,
            initial_shared_version: rpc.initial_shared_version(&id).await?,
        })
    }

    /// Argument for any object, read onchain: shared objects become
    /// [`ApprovalArg::Shared`], owned and immutable ones [`ApprovalArg::Object`] at their
    /// current version. Owned objects are only accepted by key servers when the session
    /// address owns them. BETA (v0.2).
    pub async fn object_arg(&self, id: Address) -> Result<ApprovalArg> {
        self.require_rpc()?.object_arg(&id).await
    }

    fn require_rpc(&self) -> Result<&Rpc> {
        self.rpc.as_ref().ok_or_else(|| {
            Error::InvalidInput("no fullnode configured; build the client with connect()".into())
        })
    }

    /// Asks the key servers for the keys of every id in `approval`.
    ///
    /// Servers are queried in parallel and the call returns once `threshold` of them
    /// answered. Transient failures (server errors, rate limits, objects not yet indexed)
    /// are retried with exponential backoff; policy refusals are not.
    pub async fn fetch_keys(
        &self,
        session: &SessionKey,
        approval: &ApprovalTx,
    ) -> Result<DerivedKeys> {
        if session.is_expired() {
            return Err(Error::SessionExpired);
        }
        if approval.ids().is_empty() {
            return Err(Error::InvalidInput(
                "approval transaction has no call".into(),
            ));
        }
        if approval.package_id() != session.package_id() {
            return Err(Error::InvalidInput(format!(
                "session key is for package {}, transaction calls {}",
                session.package_id(),
                approval.package_id()
            )));
        }
        let (enc_sk, enc_pk, enc_vk): (ElGamalSecretKey, ElGamalPublicKey, ElgamalVerificationKey) =
            seal_sdk::genkey(&mut rand::thread_rng());
        let request = FetchKeyRequest {
            ptb: Base64::encode(approval.to_bcs()),
            request_signature: session.sign_request(approval.ptb(), &enc_pk, &enc_vk),
            enc_key: enc_pk,
            enc_verification_key: enc_vk,
            certificate: session.certificate(),
        };
        let body = request
            .to_json_string()
            .map_err(|e| Error::Decode(format!("request: {e}")))?;

        let threshold = usize::from(self.threshold);
        let mut pending: FuturesUnordered<_> = self
            .servers
            .iter()
            .map(|server| {
                let body = body.clone();
                async move { (server, self.fetch_from(server, body).await) }
            })
            .collect();
        let mut responses: Vec<(ObjectID, FetchKeyResponse)> = Vec::new();
        let mut failures: Vec<Error> = Vec::new();
        let mut weight = 0usize;
        while let Some((server, result)) = pending.next().await {
            match result {
                Ok(response) => {
                    responses.push((server.object_id, response));
                    weight += usize::from(server.weight());
                    if weight >= threshold {
                        break;
                    }
                }
                Err(e) => failures.push(e),
            }
        }
        drop(pending);
        if weight < threshold {
            return Err(Error::ThresholdNotReached {
                got: weight,
                threshold,
                failures: Failures(failures),
            });
        }
        let pk_map = self.pk_map();
        let keys = decrypt_seal_responses(&enc_sk, &responses, &pk_map)
            .map_err(|e| Error::Crypto(format!("key verification: {e}")))?;
        Ok(DerivedKeys { keys })
    }

    async fn fetch_from(&self, server: &KeyServer, body: String) -> Result<FetchKeyResponse> {
        let mut attempt = 0;
        loop {
            match self.fetch_once(server, body.clone()).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    attempt += 1;
                    let retryable = match &e {
                        Error::KeyServer { kind, message, .. } => {
                            kind.is_retryable() && !is_wrong_owner_message(kind, message)
                        }
                        Error::Transport(_) => true,
                        _ => false,
                    };
                    if !retryable || attempt >= self.retry.max_attempts {
                        return Err(e);
                    }
                    tracing::debug!(server = %server.name, attempt, "retrying fetch_key: {e}");
                    tokio::time::sleep(self.retry.delay(attempt - 1)).await;
                }
            }
        }
    }

    async fn fetch_once(&self, server: &KeyServer, body: String) -> Result<FetchKeyResponse> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let response = server
            .authorize(self.http.post(format!("{}/v1/fetch_key", server.url)))
            .header("Content-Type", "application/json")
            .header("Request-Id", &request_id)
            .header("Client-Sdk-Type", SDK_TYPE)
            .header("Client-Sdk-Version", SDK_VERSION)
            .body(body)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("{}: {e}", server.url)))?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            let (kind, message) = match serde_json::from_str::<ErrorBody>(&text) {
                Ok(b) => (KeyServerErrorKind::from_code(&b.error), b.message),
                Err(_) if status.as_u16() == 429 => {
                    (KeyServerErrorKind::RateLimited, truncate(&text))
                }
                Err(_) if status.is_server_error() => {
                    (KeyServerErrorKind::Failure, truncate(&text))
                }
                Err(_) => (
                    KeyServerErrorKind::Other(status.to_string()),
                    truncate(&text),
                ),
            };
            return Err(Error::KeyServer {
                server: server.name.clone(),
                kind,
                message: format!("{message} (status {status}, request {request_id})"),
            });
        }
        key_server::check_server_version(&response).map_err(|reason| Error::InvalidKeyServer {
            object_id: server.object_id.to_string(),
            reason,
        })?;
        response
            .json::<FetchKeyResponse>()
            .await
            .map_err(|e| Error::Decode(format!("{} reply: {e}", server.name)))
    }

    fn pk_map(&self) -> HashMap<ObjectID, IBEPublicKey> {
        self.servers
            .iter()
            .map(|s| (s.object_id, s.public_key))
            .collect()
    }

    /// Decrypts an encrypted object with keys from [`SealClient::fetch_keys`].
    ///
    /// All key servers listed in the object must be configured in this client (their
    /// public keys are used to check share consistency).
    pub fn decrypt(&self, encrypted: &[u8], keys: &DerivedKeys) -> Result<Vec<u8>> {
        let object = decode(encrypted)?;
        let pk_map = self.pk_map();
        let mut pks = Vec::with_capacity(object.services.len());
        for (id, _) in &object.services {
            let pk = pk_map.get(id).ok_or_else(|| {
                Error::InvalidInput(format!(
                    "encrypted object uses key server {id}, which is not configured"
                ))
            })?;
            pks.push(*pk);
        }
        let full_id = crypto::create_full_id(&object.package_id.into_inner(), &object.id);
        let available = keys.keys.get(&full_id).ok_or_else(|| {
            Error::Crypto("decrypt: no keys for this encrypted object's id".into())
        })?;
        // Weighted servers appear several times in `services`; each occurrence is a share.
        let usks: HashMap<ObjectID, UserSecretKey> = object
            .services
            .iter()
            .filter_map(|(id, _)| available.get(id).map(|k| (*id, *k)))
            .collect();
        let shares = object
            .services
            .iter()
            .filter(|(id, _)| usks.contains_key(id))
            .count();
        if shares < usize::from(object.threshold) {
            return Err(Error::Crypto(format!(
                "decrypt: keys cover {shares} shares, threshold is {}",
                object.threshold
            )));
        }
        crypto::seal_decrypt(
            &object,
            &IBEUserSecretKeys::BonehFranklinBLS12381(usks),
            Some(&IBEPublicKeys::BonehFranklinBLS12381(pks)),
        )
        .map_err(|e| Error::Crypto(format!("decrypt: {e}")))
    }

    /// Fetches the keys for one encrypted object and decrypts it.
    pub async fn fetch_and_decrypt(
        &self,
        encrypted: &[u8],
        session: &SessionKey,
        approval: &ApprovalTx,
    ) -> Result<Vec<u8>> {
        let info = parse_encrypted_object(encrypted)?;
        if info.package_id != approval.package_id() || !approval.ids().contains(&info.id) {
            return Err(Error::InvalidInput(
                "approval transaction does not cover this encrypted object".into(),
            ));
        }
        let keys = self.fetch_keys(session, approval).await?;
        self.decrypt(encrypted, &keys)
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    #[serde(default)]
    message: String,
}

fn total_weight(servers: &[KeyServer]) -> usize {
    servers.iter().map(|s| usize::from(s.weight())).sum()
}

fn truncate(s: &str) -> String {
    s.chars().take(200).collect()
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("sui-seal-client/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::Transport(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ibe;
    use fastcrypto::serde_helpers::ToFromByteArray;
    use rand::thread_rng;

    struct LocalServer {
        master: ibe::MasterKey,
        server: KeyServer,
    }

    fn local_servers(n: u8) -> Vec<LocalServer> {
        (0..n)
            .map(|i| {
                let (master, pk) = ibe::generate_key_pair(&mut thread_rng());
                let server = KeyServer::new(
                    Address::new([i + 1; 32]),
                    format!("local-{i}"),
                    format!("http://127.0.0.1:1/{i}"),
                    &pk.to_byte_array(),
                )
                .unwrap();
                LocalServer { master, server }
            })
            .collect()
    }

    /// Simulates what key servers return after approval: `extract(master, full_id)`.
    fn derive(servers: &[&LocalServer], package_id: &Address, id: &[u8]) -> DerivedKeys {
        let full = crypto::create_full_id(&package_id.into_inner(), id);
        let mut keys = DerivedKeys::default();
        let mut m = HashMap::new();
        for s in servers {
            let usk = ibe::extract(&s.master, &full);
            ibe::verify_user_secret_key(&usk, &full, &s.server.public_key).unwrap();
            m.insert(s.server.object_id, usk);
        }
        keys.keys.insert(full, m);
        keys
    }

    #[test]
    fn encrypt_decrypt_threshold_2_of_3() {
        let locals = local_servers(3);
        let client =
            SealClient::with_key_servers(locals.iter().map(|l| l.server.clone()).collect(), 2)
                .unwrap();
        let pkg = Address::new([0xAB; 32]);
        let id = b"memory-42".to_vec();
        let ct = client.encrypt(pkg, &id, b"the lighthouse key").unwrap();

        let info = parse_encrypted_object(&ct).unwrap();
        assert_eq!(info.package_id, pkg);
        assert_eq!(info.id, id);
        assert_eq!(info.threshold, 2);
        assert_eq!(info.key_servers.len(), 3);

        // Any two servers are enough.
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let keys = derive(&[&locals[pair[0]], &locals[pair[1]]], &pkg, &id);
            assert_eq!(keys.servers_for(&pkg, &id), 2);
            assert_eq!(client.decrypt(&ct, &keys).unwrap(), b"the lighthouse key");
        }
        // One server is not.
        let keys = derive(&[&locals[0]], &pkg, &id);
        assert!(client.decrypt(&ct, &keys).is_err());
    }

    #[test]
    fn keys_for_another_id_do_not_decrypt() {
        let locals = local_servers(2);
        let client =
            SealClient::with_key_servers(locals.iter().map(|l| l.server.clone()).collect(), 2)
                .unwrap();
        let pkg = Address::new([1; 32]);
        let ct = client.encrypt(pkg, b"epoch-1", b"secret").unwrap();
        let keys = derive(&[&locals[0], &locals[1]], &pkg, b"epoch-0");
        assert!(client.decrypt(&ct, &keys).is_err());
        let keys = derive(
            &[&locals[0], &locals[1]],
            &Address::new([2; 32]),
            b"epoch-1",
        );
        assert!(client.decrypt(&ct, &keys).is_err());
    }

    #[test]
    fn aad_is_authenticated() {
        let locals = local_servers(2);
        let client =
            SealClient::with_key_servers(locals.iter().map(|l| l.server.clone()).collect(), 2)
                .unwrap();
        let pkg = Address::new([1; 32]);
        let ct = client
            .encrypt_with_aad(pkg, b"id", b"payload", Some(b"ctx"))
            .unwrap();
        let keys = derive(&[&locals[0], &locals[1]], &pkg, b"id");
        assert_eq!(client.decrypt(&ct, &keys).unwrap(), b"payload");

        // Tamper with the ciphertext blob: GCM must reject it.
        let mut obj: EncryptedObject = bcs::from_bytes(&ct).unwrap();
        if let crypto::Ciphertext::Aes256Gcm { blob, .. } = &mut obj.ciphertext {
            blob[0] ^= 1;
        } else {
            panic!("expected AES-GCM");
        }
        let bad = bcs::to_bytes(&obj).unwrap();
        assert!(client.decrypt(&bad, &keys).is_err());
    }

    #[test]
    fn rejects_unknown_server_and_bad_input() {
        let locals = local_servers(2);
        let a = SealClient::with_key_servers(vec![locals[0].server.clone()], 1).unwrap();
        let b = SealClient::with_key_servers(vec![locals[1].server.clone()], 1).unwrap();
        let ct = a.encrypt(Address::ZERO, b"x", b"y").unwrap();
        let keys = derive(&[&locals[0]], &Address::ZERO, b"x");
        assert!(b.decrypt(&ct, &keys).is_err());
        assert!(a.encrypt(Address::ZERO, b"", b"y").is_err());
        assert!(SealClient::with_key_servers(vec![locals[0].server.clone()], 2).is_err());
        assert!(SealClient::with_key_servers(vec![locals[0].server.clone()], 0).is_err());
        assert!(
            SealClient::with_key_servers(
                vec![locals[0].server.clone(), locals[0].server.clone()],
                1
            )
            .is_err()
        );
        assert!(parse_encrypted_object(b"garbage").is_err());
    }

    #[test]
    fn ciphertexts_are_randomized() {
        let locals = local_servers(2);
        let client =
            SealClient::with_key_servers(locals.iter().map(|l| l.server.clone()).collect(), 2)
                .unwrap();
        let a = client.encrypt(Address::ZERO, b"id", b"same").unwrap();
        let b = client.encrypt(Address::ZERO, b"id", b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn retry_backoff_is_bounded() {
        let p = RetryPolicy {
            max_attempts: 10,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(1),
        };
        assert_eq!(p.delay(0), Duration::from_millis(100));
        assert_eq!(p.delay(1), Duration::from_millis(200));
        assert_eq!(p.delay(3), Duration::from_millis(800));
        assert_eq!(p.delay(4), Duration::from_secs(1));
        assert_eq!(p.delay(40), Duration::from_secs(1));
    }

    #[test]
    fn error_kinds_retryability() {
        assert!(KeyServerErrorKind::from_code("Failure").is_retryable());
        assert!(KeyServerErrorKind::from_code("InvalidParameter").is_retryable());
        assert!(!KeyServerErrorKind::from_code("NoAccess").is_retryable());
        assert!(!KeyServerErrorKind::from_code("InvalidSignature").is_retryable());
    }

    // ---- v0.2: weights, mock HTTP key servers --------------------------------------

    use crate::testing::{LocalKeyServer, derive_keys};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn locals_weighted(weights: &[u8]) -> Vec<LocalKeyServer> {
        weights
            .iter()
            .enumerate()
            .map(|(i, w)| {
                LocalKeyServer::generate(Address::new([0x40 + i as u8; 32]), &format!("w{i}"))
                    .with_weight(*w)
                    .unwrap()
            })
            .collect()
    }

    fn client_of(locals: &[LocalKeyServer], threshold: u8) -> SealClient {
        SealClient::with_key_servers(
            locals.iter().map(|l| l.key_server().clone()).collect(),
            threshold,
        )
        .unwrap()
    }

    #[test]
    fn weighted_server_holds_several_shares() {
        // Weights 2 + 1, threshold 2: the weight-2 server alone is enough, the other is not.
        let locals = locals_weighted(&[2, 1]);
        let client = client_of(&locals, 2);
        assert_eq!(client.total_weight(), 3);
        let pkg = Address::new([7; 32]);
        let ct = client.encrypt(pkg, b"w", b"weighted").unwrap();
        let info = parse_encrypted_object(&ct).unwrap();
        assert_eq!(
            info.key_servers,
            vec![
                locals[0].key_server().object_id,
                locals[0].key_server().object_id,
                locals[1].key_server().object_id
            ]
        );
        let heavy = derive_keys(&[&locals[0]], &pkg, b"w");
        assert_eq!(client.decrypt(&ct, &heavy).unwrap(), b"weighted");
        let light = derive_keys(&[&locals[1]], &pkg, b"w");
        let err = client.decrypt(&ct, &light).unwrap_err().to_string();
        assert!(err.contains("1 shares, threshold is 2"), "{err}");
        let both = derive_keys(&[&locals[0], &locals[1]], &pkg, b"w");
        assert_eq!(client.decrypt(&ct, &both).unwrap(), b"weighted");
    }

    #[test]
    fn weights_are_validated() {
        let locals = locals_weighted(&[2, 1]);
        assert!(SealClient::with_key_servers(vec![locals[0].key_server().clone()], 3).is_err());
        assert!(SealClient::with_key_servers(vec![locals[0].key_server().clone()], 2).is_ok());
        let big = locals_weighted(&[200, 100]);
        assert!(
            SealClient::with_key_servers(big.iter().map(|l| l.key_server().clone()).collect(), 1)
                .is_err()
        );
    }

    #[test]
    fn unweighted_layout_matches_v01() {
        // Weight 1 everywhere: one share per server, in configuration order.
        let locals = locals_weighted(&[1, 1, 1]);
        let ct = client_of(&locals, 2)
            .encrypt(Address::ZERO, b"x", b"y")
            .unwrap();
        let info = parse_encrypted_object(&ct).unwrap();
        let ids: Vec<_> = locals.iter().map(|l| l.key_server().object_id).collect();
        assert_eq!(info.key_servers, ids);
    }

    #[derive(Clone)]
    enum Behaviour {
        Approve,
        Refuse,
        /// Answer `Failure` (503) this many times, then approve.
        FailFirst(usize),
        /// Approve only when this header carries this value.
        RequireHeader(&'static str, &'static str),
        /// Answer like a fullnode rejecting an owned object of someone else.
        WrongOwner,
        /// Answer `InvalidParameter` (object not indexed yet) this many times.
        NotIndexedFirst(usize),
    }

    struct Mock {
        url: String,
        hits: Arc<AtomicUsize>,
    }

    /// Minimal HTTP/1.1 key server: decodes the PTB, extracts the key for every id and
    /// ElGamal-encrypts it to the request's `enc_key`, as a real server does after the
    /// dry run approved.
    async fn spawn_mock(local: Arc<LocalKeyServer>, behaviour: Behaviour) -> Mock {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let local = local.clone();
                let behaviour = behaviour.clone();
                let n = counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    let (head_end, len) = loop {
                        let r = sock.read(&mut chunk).await.unwrap();
                        if r == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..r]);
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                            let len = head
                                .lines()
                                .find_map(|l| {
                                    l.strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            break (p + 4, len);
                        }
                    };
                    while buf.len() < head_end + len {
                        let r = sock.read(&mut chunk).await.unwrap();
                        if r == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..r]);
                    }
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let body = &buf[head_end..];
                    let (status, reply) = answer(&local, &behaviour, n, &head, body);
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nX-KeyServer-Version: 0.6.16\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                        reply.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        Mock { url, hits }
    }

    fn answer(
        local: &LocalKeyServer,
        behaviour: &Behaviour,
        n: usize,
        head: &str,
        body: &[u8],
    ) -> (&'static str, String) {
        let refuse =
            |status, code: &str| (status, format!(r#"{{"error":"{code}","message":"mock"}}"#));
        match behaviour {
            Behaviour::Refuse => return refuse("403 Forbidden", "NoAccess"),
            Behaviour::WrongOwner => {
                return (
                    "403 Forbidden",
                    r#"{"error":"InvalidParameter","message":"Transaction was not signed by the correct sender: Object 0x1 is owned by account address 0x2"}"#.to_string(),
                );
            }
            Behaviour::NotIndexedFirst(k) if n < *k => {
                return refuse("403 Forbidden", "InvalidParameter");
            }
            Behaviour::FailFirst(k) if n < *k => {
                return refuse("503 Service Unavailable", "Failure");
            }
            Behaviour::RequireHeader(name, value) => {
                let want = format!("{}: {}", name.to_lowercase(), value);
                if !head
                    .lines()
                    .any(|l| l.to_lowercase() == want.to_lowercase())
                {
                    return refuse("400 Bad Request", "MissingRequiredHeader");
                }
            }
            _ => {}
        }
        let req: serde_json::Value = serde_json::from_slice(body).unwrap();
        let ptb_bytes = Base64::decode(req["ptb"].as_str().unwrap()).unwrap();
        let ptb: sui_sdk_types::ProgrammableTransaction = bcs::from_bytes(&ptb_bytes).unwrap();
        let enc_key: ElGamalPublicKey = serde_json::from_value(req["enc_key"].clone()).unwrap();
        let mut decryption_keys = Vec::new();
        for cmd in &ptb.commands {
            let sui_sdk_types::Command::MoveCall(call) = cmd else {
                panic!("not a move call")
            };
            let sui_sdk_types::Argument::Input(i) = call.arguments[0] else {
                panic!()
            };
            let sui_sdk_types::Input::Pure(raw) = &ptb.inputs[i as usize] else {
                panic!()
            };
            let id: Vec<u8> = bcs::from_bytes(raw).unwrap();
            let full = crypto::create_full_id(&call.package.into_inner(), &id);
            let usk = local.extract(&full);
            let encrypted_key = crypto::elgamal::encrypt(&mut thread_rng(), &usk, &enc_key);
            decryption_keys.push(seal_sdk::types::DecryptionKey {
                id: full,
                encrypted_key,
            });
        }
        (
            "200 OK",
            serde_json::to_string(&FetchKeyResponse { decryption_keys }).unwrap(),
        )
    }

    fn fast_retry() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(20),
        }
    }

    fn session(pkg: Address) -> SessionKey {
        SessionKey::new(
            pkg,
            5,
            &sui_crypto::ed25519::Ed25519PrivateKey::new([3; 32]),
        )
        .unwrap()
    }

    /// Spawns one mock per weight; returns the key servers (pointing at the mocks).
    async fn mocked(weights: &[u8], behaviours: Vec<Behaviour>) -> (Vec<KeyServer>, Vec<Mock>) {
        let mut servers = Vec::new();
        let mut mocks = Vec::new();
        for (l, b) in locals_weighted(weights).into_iter().zip(behaviours) {
            let l = Arc::new(l);
            let m = spawn_mock(l.clone(), b).await;
            let mut server = l.key_server().clone();
            server.url = m.url.clone();
            servers.push(server);
            mocks.push(m);
        }
        (servers, mocks)
    }

    #[tokio::test]
    async fn fetch_over_http_and_decrypt() {
        let (locals, mocks) = mocked(&[1, 1], vec![Behaviour::Approve, Behaviour::Approve]).await;
        let client = SealClient::with_key_servers(locals.clone(), 2)
            .unwrap()
            .with_retry(fast_retry());
        let pkg = Address::new([0x11; 32]);
        let ct = client.encrypt(pkg, b"id-1", b"over http").unwrap();
        let approval = ApprovalTx::new(pkg)
            .call("m", "seal_approve", b"id-1", vec![])
            .unwrap();
        let pt = client
            .fetch_and_decrypt(&ct, &session(pkg), &approval)
            .await
            .unwrap();
        assert_eq!(pt, b"over http");
        assert!(mocks.iter().all(|m| m.hits.load(Ordering::SeqCst) >= 1));
    }

    #[tokio::test]
    async fn weight_reaches_threshold_without_the_refusing_server() {
        // Weight-2 server approves, weight-1 server refuses; threshold 2 is met.
        let (locals, _m) = mocked(&[2, 1], vec![Behaviour::Approve, Behaviour::Refuse]).await;
        let client = SealClient::with_key_servers(locals.clone(), 2)
            .unwrap()
            .with_retry(fast_retry());
        let pkg = Address::new([0x12; 32]);
        let ct = client.encrypt(pkg, b"id", b"heavy").unwrap();
        let approval = ApprovalTx::new(pkg)
            .call("m", "seal_approve", b"id", vec![])
            .unwrap();
        assert_eq!(
            client
                .fetch_and_decrypt(&ct, &session(pkg), &approval)
                .await
                .unwrap(),
            b"heavy"
        );

        // Reverse: only the weight-1 server approves, threshold 2 is not met.
        let (locals, _m) = mocked(&[2, 1], vec![Behaviour::Refuse, Behaviour::Approve]).await;
        let client = SealClient::with_key_servers(locals.clone(), 2)
            .unwrap()
            .with_retry(fast_retry());
        let err = client
            .fetch_keys(&session(pkg), &approval)
            .await
            .unwrap_err();
        assert!(err.is_no_access(), "{err}");
        assert!(
            matches!(
                err,
                Error::ThresholdNotReached {
                    got: 1,
                    threshold: 2,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn transient_failures_are_retried() {
        let (locals, mocks) = mocked(&[1], vec![Behaviour::FailFirst(2)]).await;
        let client = SealClient::with_key_servers(vec![locals[0].clone()], 1)
            .unwrap()
            .with_retry(fast_retry());
        let pkg = Address::new([0x13; 32]);
        let approval = ApprovalTx::new(pkg)
            .call("m", "seal_approve", b"id", vec![])
            .unwrap();
        let keys = client.fetch_keys(&session(pkg), &approval).await.unwrap();
        assert_eq!(keys.servers_for(&pkg, b"id"), 1);
        assert_eq!(mocks[0].hits.load(Ordering::SeqCst), 3);

        // More failures than attempts: gives up with the last error.
        let (locals, mocks) = mocked(&[1], vec![Behaviour::FailFirst(10)]).await;
        let client = SealClient::with_key_servers(vec![locals[0].clone()], 1)
            .unwrap()
            .with_retry(fast_retry());
        let err = client
            .fetch_keys(&session(pkg), &approval)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Failure"), "{err}");
        assert_eq!(mocks[0].hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn api_key_header_is_sent() {
        let (locals, mocks) =
            mocked(&[1], vec![Behaviour::RequireHeader("x-seal-key", "k-123")]).await;
        let pkg = Address::new([0x14; 32]);
        let approval = ApprovalTx::new(pkg)
            .call("m", "seal_approve", b"id", vec![])
            .unwrap();
        let bare = SealClient::with_key_servers(vec![locals[0].clone()], 1)
            .unwrap()
            .with_retry(fast_retry());
        let err = bare.fetch_keys(&session(pkg), &approval).await.unwrap_err();
        assert!(err.to_string().contains("MissingRequiredHeader"), "{err}");
        assert_eq!(mocks[0].hits.load(Ordering::SeqCst), 1, "not retried");

        let keyed = locals[0]
            .clone()
            .with_api_key(crate::ApiKey::new("x-seal-key", "k-123"))
            .unwrap();
        let client = SealClient::with_key_servers(vec![keyed], 1)
            .unwrap()
            .with_retry(fast_retry());
        let keys = client.fetch_keys(&session(pkg), &approval).await.unwrap();
        assert_eq!(keys.servers_for(&pkg, b"id"), 1);
    }

    #[tokio::test]
    async fn batch_of_ids_in_one_request() {
        let (locals, _m) = mocked(
            &[1, 1, 1],
            vec![Behaviour::Approve, Behaviour::Refuse, Behaviour::Approve],
        )
        .await;
        let client = SealClient::with_key_servers(locals.clone(), 2)
            .unwrap()
            .with_retry(fast_retry());
        let pkg = Address::new([0x15; 32]);
        let ids: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i, 0xEE]).collect();
        let cts: Vec<_> = ids
            .iter()
            .map(|id| client.encrypt(pkg, id, id).unwrap())
            .collect();
        let mut tx = ApprovalTx::new(pkg);
        for id in &ids {
            tx = tx.call("m", "seal_approve", id, vec![]).unwrap();
        }
        let keys = client.fetch_keys(&session(pkg), &tx).await.unwrap();
        for (id, ct) in ids.iter().zip(&cts) {
            assert_eq!(&client.decrypt(ct, &keys).unwrap(), id);
        }
    }

    #[tokio::test]
    async fn wrong_owner_is_not_retried_but_indexing_lag_is() {
        let pkg = Address::new([0x16; 32]);
        let approval = ApprovalTx::new(pkg)
            .call("m", "seal_approve", b"id", vec![])
            .unwrap();
        let (servers, mocks) = mocked(&[1], vec![Behaviour::WrongOwner]).await;
        let client = SealClient::with_key_servers(servers, 1)
            .unwrap()
            .with_retry(fast_retry());
        let err = client
            .fetch_keys(&session(pkg), &approval)
            .await
            .unwrap_err();
        assert!(err.is_wrong_owner(), "{err}");
        assert!(!err.is_no_access());
        assert_eq!(mocks[0].hits.load(Ordering::SeqCst), 1);

        let (servers, mocks) = mocked(&[1], vec![Behaviour::NotIndexedFirst(2)]).await;
        let client = SealClient::with_key_servers(servers, 1)
            .unwrap()
            .with_retry(fast_retry());
        client.fetch_keys(&session(pkg), &approval).await.unwrap();
        assert_eq!(mocks[0].hits.load(Ordering::SeqCst), 3);
    }
}
