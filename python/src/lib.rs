//! Python bindings for `sui-seal-client`. BETA (v0.2).
//!
//! Blocking API: every network call runs on an internal Tokio runtime with the GIL
//! released. Errors map to `SealError` and its subclasses `NoAccessError` (policy
//! refusal) and `WrongOwnerError` (owned object not owned by the session address).

use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;

use ::sui_seal_client as seal;
use ::sui_seal_client::{Address, PersonalMessageSigner};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sui_crypto::ed25519::Ed25519PrivateKey;

create_exception!(
    sui_seal_client,
    SealError,
    PyException,
    "Any sui-seal-client error."
);
create_exception!(
    sui_seal_client,
    NoAccessError,
    SealError,
    "The key servers refused access (seal_approve aborted)."
);
create_exception!(
    sui_seal_client,
    WrongOwnerError,
    SealError,
    "The approval used an owned object that the session address does not own."
);

fn err(e: seal::Error) -> PyErr {
    if e.is_no_access() {
        NoAccessError::new_err(e.to_string())
    } else if e.is_wrong_owner() {
        WrongOwnerError::new_err(e.to_string())
    } else {
        SealError::new_err(e.to_string())
    }
}

fn bad(msg: impl Into<String>) -> PyErr {
    SealError::new_err(format!("invalid input: {}", msg.into()))
}

fn addr(s: &str) -> PyResult<Address> {
    Address::from_str(s).map_err(|e| bad(format!("address {s}: {e}")))
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// Runs a future to completion with the GIL released.
fn block<F, T>(py: Python<'_>, fut: F) -> PyResult<T>
where
    F: std::future::Future<Output = seal::Result<T>> + Send,
    T: Send,
{
    py.detach(|| runtime().block_on(fut)).map_err(err)
}

/// Key server set, threshold and network settings.
#[pyclass(module = "sui_seal_client", frozen)]
#[derive(Clone)]
struct SealConfig {
    inner: seal::SealConfig,
}

#[pymethods]
impl SealConfig {
    /// Builds a configuration.
    ///
    /// `key_servers` is a list of object ids (str) or dicts with keys `object_id`
    /// and optionally `weight`, `aggregator_url`, `api_key_header`, `api_key`.
    #[new]
    #[pyo3(signature = (key_servers, threshold, fullnode_url=None, verify_key_servers=true, timeout_s=20.0))]
    fn new(
        key_servers: Vec<Bound<'_, PyAny>>,
        threshold: u8,
        fullnode_url: Option<String>,
        verify_key_servers: bool,
        timeout_s: f64,
    ) -> PyResult<Self> {
        let mut b = seal::SealConfig::builder()
            .threshold(threshold)
            .verify_key_servers(verify_key_servers)
            .timeout(Duration::from_secs_f64(timeout_s));
        if let Some(url) = fullnode_url {
            b = b.fullnode_url(url);
        }
        for ks in key_servers {
            if let Ok(id) = ks.extract::<String>() {
                b = b.key_server(addr(&id)?);
                continue;
            }
            let id: String = ks.get_item("object_id")?.extract()?;
            let get = |k: &str| -> PyResult<Option<Bound<'_, PyAny>>> {
                match ks.get_item(k) {
                    Ok(v) if !v.is_none() => Ok(Some(v)),
                    _ => Ok(None),
                }
            };
            let mut opts = seal::KeyServerOptions::default();
            if let Some(w) = get("weight")? {
                opts = opts.weight(w.extract()?);
            }
            if let Some(u) = get("aggregator_url")? {
                opts = opts.aggregator_url(u.extract::<String>()?);
            }
            match (get("api_key_header")?, get("api_key")?) {
                (Some(h), Some(v)) => {
                    opts = opts.api_key(seal::ApiKey::new(
                        h.extract::<String>()?,
                        v.extract::<String>()?,
                    ))
                }
                (None, None) => {}
                _ => return Err(bad("api_key_header and api_key go together")),
            }
            b = b.key_server_with(addr(&id)?, opts);
        }
        Ok(Self {
            inner: b.build().map_err(err)?,
        })
    }

    /// Mysten open testnet servers, threshold 2 (same as v0.1).
    #[staticmethod]
    fn testnet() -> Self {
        Self {
            inner: seal::SealConfig::testnet(),
        }
    }

    /// Mysten testnet committee (3-of-5) behind its aggregator, threshold 1. BETA.
    #[staticmethod]
    fn testnet_committee() -> Self {
        Self {
            inner: seal::SealConfig::testnet_committee(),
        }
    }

    #[getter]
    fn threshold(&self) -> u8 {
        self.inner.threshold
    }

    #[getter]
    fn key_servers(&self) -> Vec<String> {
        self.inner
            .key_servers
            .iter()
            .map(|a| a.to_string())
            .collect()
    }

    #[getter]
    fn total_weight(&self) -> usize {
        self.inner.total_weight()
    }

    fn __repr__(&self) -> String {
        format!(
            "SealConfig(key_servers={:?}, threshold={})",
            self.key_servers(),
            self.inner.threshold
        )
    }
}

/// A Sui Ed25519 key that certifies session keys. The secret never leaves Rust.
#[pyclass(module = "sui_seal_client", frozen)]
struct Signer {
    key: Ed25519PrivateKey,
}

#[pymethods]
impl Signer {
    /// From a `suiprivkey1...` string or a base64 keystore entry (`flag || key`).
    #[staticmethod]
    fn from_str(s: &str) -> PyResult<Self> {
        let s = s.trim();
        let key = if s.starts_with("suiprivkey") {
            Ed25519PrivateKey::from_suiprivkey(s)
        } else {
            Ed25519PrivateKey::from_base64(s)
        }
        .map_err(|e| bad(format!("signer key: {e}")))?;
        Ok(Self { key })
    }

    /// Reads a key file (`sui keytool generate` output or a suiprivkey string).
    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| bad(format!("{path}: {e}")))?;
        Self::from_str(&raw)
    }

    #[getter]
    fn address(&self) -> String {
        self.key.sui_address().to_string()
    }

    fn __repr__(&self) -> String {
        format!("Signer(address={})", self.address())
    }
}

/// A session key for one package (TTL at most 30 minutes).
#[pyclass(module = "sui_seal_client", frozen)]
struct SessionKey {
    inner: seal::SessionKey,
}

#[pymethods]
impl SessionKey {
    /// Creates a session key without the onchain package check (offline use).
    #[new]
    fn new(package_id: &str, ttl_min: u16, signer: PyRef<'_, Signer>) -> PyResult<Self> {
        Ok(Self {
            inner: seal::SessionKey::new(addr(package_id)?, ttl_min, &signer.key).map_err(err)?,
        })
    }

    #[getter]
    fn address(&self) -> String {
        self.inner.address().to_string()
    }

    #[getter]
    fn package_id(&self) -> String {
        self.inner.package_id().to_string()
    }

    fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }
}

/// Extra argument of a `seal_approve` call.
#[pyclass(module = "sui_seal_client", frozen)]
#[derive(Clone)]
struct ApprovalArg {
    inner: seal::ApprovalArg,
}

#[pymethods]
impl ApprovalArg {
    /// BCS-encoded pure value.
    #[staticmethod]
    fn pure(bcs: Vec<u8>) -> Self {
        Self {
            inner: seal::ApprovalArg::Pure(bcs),
        }
    }

    /// Shared object with a known initial shared version.
    #[staticmethod]
    fn shared(object_id: &str, initial_shared_version: u64) -> PyResult<Self> {
        Ok(Self {
            inner: seal::ApprovalArg::Shared {
                id: addr(object_id)?,
                initial_shared_version,
            },
        })
    }

    /// The Sui clock `0x6`.
    #[staticmethod]
    fn clock() -> Self {
        Self {
            inner: seal::policy::clock(),
        }
    }

    fn __repr__(&self) -> String {
        format!("ApprovalArg({:?})", self.inner)
    }
}

/// A transaction of `seal_approve*` calls on one package.
#[pyclass(module = "sui_seal_client")]
#[derive(Clone)]
struct ApprovalTx {
    inner: seal::ApprovalTx,
}

#[pymethods]
impl ApprovalTx {
    #[new]
    fn new(package_id: &str) -> PyResult<Self> {
        Ok(Self {
            inner: seal::ApprovalTx::new(addr(package_id)?),
        })
    }

    /// Adds `package::module::function(id, *args)`; returns self for chaining.
    #[pyo3(signature = (module, function, id, args=Vec::new()))]
    fn call<'py>(
        mut slf: PyRefMut<'py, Self>,
        module: &str,
        function: &str,
        id: Vec<u8>,
        args: Vec<PyRef<'py, ApprovalArg>>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let args = args.iter().map(|a| a.inner.clone()).collect();
        let tx = slf
            .inner
            .clone()
            .call(module, function, &id, args)
            .map_err(err)?;
        slf.inner = tx;
        Ok(slf)
    }

    /// Inner ids covered by this transaction.
    fn ids<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.inner
            .ids()
            .iter()
            .map(|i| PyBytes::new(py, i))
            .collect()
    }

    /// BCS of the programmable transaction.
    fn to_bcs<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bcs())
    }
}

/// Keys returned by key servers, already verified.
#[pyclass(module = "sui_seal_client")]
struct DerivedKeys {
    inner: seal::DerivedKeys,
}

#[pymethods]
impl DerivedKeys {
    /// Number of servers that returned a key for `package_id || id`.
    fn servers_for(&self, package_id: &str, id: Vec<u8>) -> PyResult<usize> {
        Ok(self.inner.servers_for(&addr(package_id)?, &id))
    }
}

/// Public header of an encrypted object.
#[pyclass(module = "sui_seal_client", frozen, get_all)]
struct EncryptedInfo {
    package_id: String,
    id: Vec<u8>,
    threshold: u8,
    key_servers: Vec<String>,
}

/// Parses the header of an encrypted object (no key needed).
#[pyfunction]
fn parse_encrypted_object(data: Vec<u8>) -> PyResult<EncryptedInfo> {
    let i = seal::parse_encrypted_object(&data).map_err(err)?;
    Ok(EncryptedInfo {
        package_id: i.package_id.to_string(),
        id: i.id,
        threshold: i.threshold,
        key_servers: i.key_servers.iter().map(|a| a.to_string()).collect(),
    })
}

/// Seal client bound to a set of key servers.
#[pyclass(module = "sui_seal_client", frozen)]
struct SealClient {
    inner: seal::SealClient,
}

#[pymethods]
impl SealClient {
    /// Reads the key servers onchain and verifies them.
    #[staticmethod]
    fn connect(py: Python<'_>, config: PyRef<'_, SealConfig>) -> PyResult<Self> {
        let config = config.inner.clone();
        Ok(Self {
            inner: block(py, seal::SealClient::connect(config))?,
        })
    }

    /// Offline client over in-process key servers (tests only).
    #[staticmethod]
    fn with_local_servers(
        servers: Vec<PyRef<'_, LocalKeyServer>>,
        threshold: u8,
    ) -> PyResult<Self> {
        let servers = servers
            .iter()
            .map(|s| s.inner.key_server().clone())
            .collect();
        Ok(Self {
            inner: seal::SealClient::with_key_servers(servers, threshold).map_err(err)?,
        })
    }

    #[getter]
    fn threshold(&self) -> u8 {
        self.inner.threshold()
    }

    /// `(object_id, name, url, weight, is_committee)` per configured server.
    fn key_servers(&self) -> Vec<(String, String, String, u8, bool)> {
        self.inner
            .key_servers()
            .iter()
            .map(|s| {
                (
                    s.object_id.to_string(),
                    s.name.clone(),
                    s.url.clone(),
                    s.weight(),
                    s.is_committee(),
                )
            })
            .collect()
    }

    /// Encrypts `data` for `package_id || id`. The symmetric key is wiped.
    #[pyo3(signature = (package_id, id, data, aad=None))]
    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        package_id: &str,
        id: Vec<u8>,
        data: Vec<u8>,
        aad: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let ct = self
            .inner
            .encrypt_with_aad(addr(package_id)?, &id, &data, aad.as_deref())
            .map_err(err)?;
        Ok(PyBytes::new(py, &ct))
    }

    /// Session key after checking onchain that `package_id` is an original package id.
    fn session_key(
        &self,
        py: Python<'_>,
        package_id: &str,
        ttl_min: u16,
        signer: PyRef<'_, Signer>,
    ) -> PyResult<SessionKey> {
        let pkg = addr(package_id)?;
        let key = signer.key.clone();
        let inner = block(py, async move {
            self.inner.session_key(pkg, ttl_min, &key).await
        })?;
        Ok(SessionKey { inner })
    }

    /// Shared object argument (initial shared version read onchain).
    fn shared_object(&self, py: Python<'_>, object_id: &str) -> PyResult<ApprovalArg> {
        let id = addr(object_id)?;
        let inner = block(py, self.inner.shared_object(id))?;
        Ok(ApprovalArg { inner })
    }

    /// Any object argument: shared, or owned/immutable at its current version.
    fn object_arg(&self, py: Python<'_>, object_id: &str) -> PyResult<ApprovalArg> {
        let id = addr(object_id)?;
        let inner = block(py, self.inner.object_arg(id))?;
        Ok(ApprovalArg { inner })
    }

    /// Fetches keys for every id of `approval` from a threshold of servers.
    fn fetch_keys(
        &self,
        py: Python<'_>,
        session: PyRef<'_, SessionKey>,
        approval: PyRef<'_, ApprovalTx>,
    ) -> PyResult<DerivedKeys> {
        let tx = approval.inner.clone();
        let s = &session.inner;
        let inner = block(py, async move { self.inner.fetch_keys(s, &tx).await })?;
        Ok(DerivedKeys { inner })
    }

    /// Decrypts with keys from `fetch_keys` (or `derive_keys` in tests).
    fn decrypt<'py>(
        &self,
        py: Python<'py>,
        data: Vec<u8>,
        keys: PyRef<'_, DerivedKeys>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let pt = self.inner.decrypt(&data, &keys.inner).map_err(err)?;
        Ok(PyBytes::new(py, &pt))
    }

    /// Fetches the keys for one encrypted object and decrypts it.
    fn fetch_and_decrypt<'py>(
        &self,
        py: Python<'py>,
        data: Vec<u8>,
        session: PyRef<'_, SessionKey>,
        approval: PyRef<'_, ApprovalTx>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let tx = approval.inner.clone();
        let s = &session.inner;
        let pt = block(py, async move {
            self.inner.fetch_and_decrypt(&data, s, &tx).await
        })?;
        Ok(PyBytes::new(py, &pt))
    }
}

/// In-process key server for offline tests. Approves everything; never use for data.
#[pyclass(module = "sui_seal_client", frozen)]
struct LocalKeyServer {
    inner: seal::testing::LocalKeyServer,
}

#[pymethods]
impl LocalKeyServer {
    #[new]
    #[pyo3(signature = (object_id, name="local", weight=1))]
    fn new(object_id: &str, name: &str, weight: u8) -> PyResult<Self> {
        let inner = seal::testing::LocalKeyServer::generate(addr(object_id)?, name)
            .with_weight(weight)
            .map_err(err)?;
        Ok(Self { inner })
    }

    #[getter]
    fn object_id(&self) -> String {
        self.inner.key_server().object_id.to_string()
    }
}

/// Keys from `servers` for `package_id || id`, as if each had approved (tests only).
#[pyfunction]
fn derive_keys(
    servers: Vec<PyRef<'_, LocalKeyServer>>,
    package_id: &str,
    id: Vec<u8>,
) -> PyResult<DerivedKeys> {
    let refs: Vec<&seal::testing::LocalKeyServer> = servers.iter().map(|s| &s.inner).collect();
    Ok(DerivedKeys {
        inner: seal::testing::derive_keys(&refs, &addr(package_id)?, &id),
    })
}

/// `[list id][epoch u64 LE][nonce]`; random 16-byte nonce when `nonce` is None.
#[pyfunction]
#[pyo3(signature = (list_id, epoch, nonce=None))]
fn allowlist_key_id(list_id: &str, epoch: u64, nonce: Option<Vec<u8>>) -> PyResult<Vec<u8>> {
    let list = addr(list_id)?;
    match nonce {
        Some(n) => seal::policy::allowlist::key_id(&list, epoch, &n).map_err(err),
        None => Ok(seal::policy::allowlist::random_key_id(&list, epoch)),
    }
}

/// `[unlock time u64 LE ms][nonce]`; random 16-byte nonce when `nonce` is None.
#[pyfunction]
#[pyo3(signature = (unlock_ms, nonce=None))]
fn timelock_key_id(unlock_ms: u64, nonce: Option<Vec<u8>>) -> Vec<u8> {
    match nonce {
        Some(n) => seal::policy::timelock::key_id(unlock_ms, &n),
        None => seal::policy::timelock::random_key_id(unlock_ms),
    }
}

/// `[creator address][nonce]`.
#[pyfunction]
fn private_data_key_id(creator: &str, nonce: Vec<u8>) -> PyResult<Vec<u8>> {
    Ok(seal::policy::private_data::key_id(&addr(creator)?, &nonce))
}

/// `[service id][nonce]`; random 16-byte nonce when `nonce` is None.
#[pyfunction]
#[pyo3(signature = (service_id, nonce=None))]
fn subscription_key_id(service_id: &str, nonce: Option<Vec<u8>>) -> PyResult<Vec<u8>> {
    let s = addr(service_id)?;
    match nonce {
        Some(n) => seal::policy::subscription::key_id(&s, &n).map_err(err),
        None => Ok(seal::policy::subscription::random_key_id(&s)),
    }
}

#[pymodule]
fn sui_seal_client(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("MYSTEN_TESTNET_1", seal::MYSTEN_TESTNET_1)?;
    m.add("MYSTEN_TESTNET_2", seal::MYSTEN_TESTNET_2)?;
    m.add("MYSTEN_TESTNET_COMMITTEE", seal::MYSTEN_TESTNET_COMMITTEE)?;
    m.add("MYSTEN_TESTNET_AGGREGATOR", seal::MYSTEN_TESTNET_AGGREGATOR)?;
    m.add("SealError", py.get_type::<SealError>())?;
    m.add("NoAccessError", py.get_type::<NoAccessError>())?;
    m.add("WrongOwnerError", py.get_type::<WrongOwnerError>())?;
    m.add_class::<SealConfig>()?;
    m.add_class::<Signer>()?;
    m.add_class::<SessionKey>()?;
    m.add_class::<ApprovalArg>()?;
    m.add_class::<ApprovalTx>()?;
    m.add_class::<DerivedKeys>()?;
    m.add_class::<EncryptedInfo>()?;
    m.add_class::<SealClient>()?;
    m.add_class::<LocalKeyServer>()?;
    m.add_function(wrap_pyfunction!(parse_encrypted_object, m)?)?;
    m.add_function(wrap_pyfunction!(derive_keys, m)?)?;
    m.add_function(wrap_pyfunction!(allowlist_key_id, m)?)?;
    m.add_function(wrap_pyfunction!(timelock_key_id, m)?)?;
    m.add_function(wrap_pyfunction!(private_data_key_id, m)?)?;
    m.add_function(wrap_pyfunction!(subscription_key_id, m)?)?;
    Ok(())
}
