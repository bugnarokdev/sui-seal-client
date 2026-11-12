//! High-level client: encrypt, fetch keys, decrypt.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use crypto::ibe::UserSecretKey;
use crypto::{EncryptedObject, EncryptionInput, ObjectID};
use fastcrypto::encoding::{Base64, Encoding};
use futures::stream::{FuturesUnordered, StreamExt};
use seal_sdk::types::{ElGamalPublicKey, ElgamalVerificationKey};
use seal_sdk::{
    ElGamalSecretKey, FetchKeyRequest, FetchKeyResponse, IBEPublicKey, decrypt_seal_responses,
    seal_decrypt_object, seal_encrypt,
};
use serde::Deserialize;
use sui_sdk_types::Address;
use zeroize::Zeroizing;

use crate::approval::{ApprovalArg, ApprovalTx};
use crate::config::{RetryPolicy, SealConfig, validate_threshold};
use crate::error::{Error, Failures, KeyServerErrorKind, Result};
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
    keys: HashMap<Vec<u8>, HashMap<ObjectID, UserSecretKey>>,
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
            let server = key_server::retrieve(&rpc, *id).await?;
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

    /// Builds a client from known key servers, without onchain reads.
    /// `session_key` and `shared_object` then need a fullnode: use [`SealClient::connect`].
    pub fn with_key_servers(servers: Vec<KeyServer>, threshold: u8) -> Result<Self> {
        let config = SealConfig {
            key_servers: servers.iter().map(|s| s.object_id).collect(),
            threshold,
            ..SealConfig::testnet()
        };
        config.validate()?;
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
        validate_threshold(self.threshold, self.servers.len())?;
        let refs: Vec<&KeyServer> = self.servers.iter().collect();
        let input = EncryptionInput::Aes256Gcm {
            data: plaintext.to_vec(),
            aad: aad.map(<[u8]>::to_vec),
        };
        let (object, dem_key) = seal_encrypt(
            package_id,
            id.to_vec(),
            self.servers.iter().map(|s| s.object_id).collect(),
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

        let threshold = self.threshold as usize;
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
        while let Some((server, result)) = pending.next().await {
            match result {
                Ok(response) => {
                    responses.push((server.object_id, response));
                    if responses.len() >= threshold {
                        break;
                    }
                }
                Err(e) => failures.push(e),
            }
        }
        drop(pending);
        if responses.len() < threshold {
            return Err(Error::ThresholdNotReached {
                got: responses.len(),
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
                        Error::KeyServer { kind, .. } => kind.is_retryable(),
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
        let response = self
            .http
            .post(format!("{}/v1/fetch_key", server.url))
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
        for (id, _) in &object.services {
            if !pk_map.contains_key(id) {
                return Err(Error::InvalidInput(format!(
                    "encrypted object uses key server {id}, which is not configured"
                )));
            }
        }
        seal_decrypt_object(&object, &keys.keys, &pk_map)
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
}
