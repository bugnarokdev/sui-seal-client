//! Offline test helpers: in-process key servers. Feature `testing`. BETA.
//!
//! A [`LocalKeyServer`] holds a freshly generated master key and answers like a key
//! server that approved the request. Use it to unit-test code that encrypts and decrypts
//! without testnet. Never use it for real data: the master key lives in memory and
//! approves everything.

use std::collections::HashMap;

use crypto::ibe;
use fastcrypto::serde_helpers::ToFromByteArray;
use sui_sdk_types::Address;

use crate::client::DerivedKeys;
use crate::error::Result;
use crate::key_server::KeyServer;

/// An in-process key server with its master key.
pub struct LocalKeyServer {
    pub(crate) master: ibe::MasterKey,
    server: KeyServer,
}

impl std::fmt::Debug for LocalKeyServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKeyServer")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl LocalKeyServer {
    /// Generates a master key for a server registered under `object_id`.
    pub fn generate(object_id: Address, name: &str) -> Self {
        let (master, pk) = ibe::generate_key_pair(&mut rand::thread_rng());
        let server = KeyServer::new(
            object_id,
            name.to_string(),
            format!("http://127.0.0.1:1/{name}"),
            &pk.to_byte_array(),
        )
        .expect("generated key is valid");
        Self { master, server }
    }

    /// Changes the URL (for example to a local mock HTTP server).
    pub fn with_url(mut self, url: &str) -> Self {
        self.server.url = url.trim_end_matches('/').to_string();
        self
    }

    /// Sets the weight of the public [`KeyServer`].
    pub fn with_weight(mut self, weight: u8) -> Result<Self> {
        self.server = self.server.with_weight(weight)?;
        Ok(self)
    }

    /// The public description, to build a client with
    /// [`crate::SealClient::with_key_servers`].
    pub fn key_server(&self) -> &KeyServer {
        &self.server
    }

    /// User secret key for `package_id || id`, as a key server returns after approval.
    pub(crate) fn extract(&self, full_id: &[u8]) -> ibe::UserSecretKey {
        ibe::extract(&self.master, full_id)
    }
}

/// Keys from `servers` for `package_id || id`, as if each had approved the request.
pub fn derive_keys(servers: &[&LocalKeyServer], package_id: &Address, id: &[u8]) -> DerivedKeys {
    let full = crypto::create_full_id(&package_id.into_inner(), id);
    let mut per_server = HashMap::new();
    for s in servers {
        let usk = s.extract(&full);
        ibe::verify_user_secret_key(&usk, &full, &s.server.public_key)
            .expect("extracted key verifies");
        per_server.insert(s.server.object_id, usk);
    }
    let mut keys = DerivedKeys::default();
    keys.keys.insert(full, per_server);
    keys
}
