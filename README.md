# sui-seal-client

High-level Rust client for [Seal](https://github.com/MystenLabs/seal), the decentralized
secrets management service on Sui: data is encrypted client-side to an identity, and a
Move function (`seal_approve*`) decides onchain who may obtain the decryption keys from a
threshold of independent key servers.

Mysten publishes an official TypeScript SDK (`@mysten/seal`). On the Rust side, the
`MystenLabs/seal` repository contains low-level crates (`crypto`, `seal-sdk`) but no
published high-level client. This crate fills that gap.

> **Status: v0.2, BETA, testnet only.** Seal is itself in beta. The API may change
> before 1.0. Not audited. Everything added in v0.2 (committee servers, weights, API
> keys, the `move/policies` package, policy helpers, Python bindings) is BETA as well.
>
> - Not on crates.io yet: Mysten's `seal-sdk` and `crypto` crates are only available by
>   git, and crates.io refuses git dependencies (options in
>   [`docs/crates-io.md`](docs/crates-io.md)). Use it as a git dependency, pinned:
>   `sui-seal-client = { git = "https://github.com/bugnarokdev/sui-seal-client", rev = "<commit>" }`.

## What it does

- **Encrypt** to `package_id || id` with AES-256-GCM and a `t`-of-`n` threshold.
- **Key servers** read onchain (object ids in, URL and BLS public key out), with the
  proof of possession of each server's master key verified on connect.
- **Configurable server sets** (BETA): builder API, per-server weights, API key headers
  for permissioned servers, and **committee (decentralized) key servers** behind an
  aggregator, alone or mixed with independent servers.
- **Session keys**: an ephemeral Ed25519 key certified once by the user's Sui key
  (personal message), then used to sign each key request.
- **`seal_approve` transactions**: a small builder for the PTB key servers dry-run.
- **`/v1/fetch_key`** to all servers in parallel, returning once the threshold is met,
  with exponential backoff on transient errors (server failure, rate limit, objects not
  yet indexed).
- **Decrypt**: every returned key is verified against its server's public key, and share
  consistency is checked against all public keys.
- **Policies** (BETA): Move packages for an allowlist with revocation epochs, a
  time-lock, owner-only data and paid subscriptions, with Rust helpers for their key ids
  and `seal_approve` calls (`sui_seal_client::policy`).
- **Python bindings** (BETA): `python/`, PyO3 + maturin, same engine.

No cryptography is implemented here. Encryption, decryption, key verification and the
request formats come from Mysten's crates, pinned by commit:

| Dependency | Source | Pin |
|---|---|---|
| `crypto`, `seal-sdk` | `github.com/MystenLabs/seal` | tag `seal-v0.6.16`, commit `54eff6a7621b9b45905876a4ffd3e675e03a9bfc` |
| `fastcrypto` | `github.com/MystenLabs/fastcrypto` | commit `076bf5ad8cea140dc7cf5c5861c24a36acdf64ce` (same as seal-v0.6.16) |
| `sui-sdk-types`, `sui-crypto`, `sui-rpc` | crates.io | `0.4` |

Mysten's crates are internal and have no stable API. This crate keeps its own public API
and confines their types to its internals, so a future bump only touches this layer.
The wire formats (encrypted object BCS, key server HTTP API) are checked against the
official TypeScript SDK by the interop tests.

## Usage

```rust,no_run
use sui_seal_client::{ApprovalTx, SealClient, SealConfig};

# async fn demo(
#     package_id: sui_seal_client::Address,
#     allowlist_id: sui_seal_client::Address,
#     signer: sui_crypto::ed25519::Ed25519PrivateKey,
# ) -> sui_seal_client::Result<()> {
// Mysten open testnet servers, threshold 2 of 2.
let client = SealClient::connect(SealConfig::testnet()).await?;

// Encrypt. Anyone can do this; no key server is contacted.
let id = b"...";                       // inner id, see the policy you use
let encrypted = client.encrypt(package_id, id, b"hello")?;

// Decrypt: certify a session key, then prove access through seal_approve.
let session = client.session_key(package_id, 10, &signer).await?;
let list = client.shared_object(allowlist_id).await?;
let approval = ApprovalTx::new(package_id).call("allowlist", "seal_approve", id, vec![list])?;
let plaintext = client.fetch_and_decrypt(&encrypted, &session, &approval).await?;
# Ok(()) }
```

Several ids can go in one `ApprovalTx` (one `call` each); `fetch_keys` then returns
`DerivedKeys` for all of them and `decrypt` can be called per object.

Defaults (`SealConfig::testnet()`, unchanged from v0.1), taken from the Seal docs
(Pricing page):

| Server | Object id | Mode |
|---|---|---|
| mysten-testnet-1 | `0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75` | Open |
| mysten-testnet-2 | `0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8` | Open |

Threshold 2. These servers are free and rate-limited, with no availability guarantee.

### Choosing key servers (BETA)

```rust
use sui_seal_client::{
    Address, ApiKey, KeyServerOptions, SealConfig, MYSTEN_TESTNET_1, MYSTEN_TESTNET_2,
    MYSTEN_TESTNET_AGGREGATOR, MYSTEN_TESTNET_COMMITTEE,
};
# fn main() -> sui_seal_client::Result<()> {
let id = |s: &str| s.parse::<Address>().unwrap();

// The Mysten testnet committee (3-of-5 behind one aggregator): threshold 1.
let committee = SealConfig::testnet_committee();

// Hybrid: committee + one independent server, both required.
let hybrid = SealConfig::builder()
    .committee(id(MYSTEN_TESTNET_COMMITTEE), MYSTEN_TESTNET_AGGREGATOR)
    .key_server(id(MYSTEN_TESTNET_1))
    .threshold(2)
    .build()?;

// Weights: testnet-1 holds two shares, so it alone meets threshold 2.
// API keys are sent as a header to permissioned servers (value redacted in Debug).
let weighted = SealConfig::builder()
    .key_server_with(id(MYSTEN_TESTNET_1), KeyServerOptions::default().weight(2))
    .key_server_with(
        id(MYSTEN_TESTNET_2),
        KeyServerOptions::default().api_key(ApiKey::new("x-api-key", "...")),
    )
    .threshold(2)
    .build()?;
# let _ = (committee, hybrid, weighted);
# Ok(()) }
```

| Testnet server | Object id | Notes |
|---|---|---|
| Mysten committee | `0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98` | 3-of-5 (Mysten Labs, Natsai, Overclock, NodeInfra, Ruby Nodes), aggregator `https://seal-aggregator-testnet.mystenlabs.com` |

Notes:

- The threshold counts weights: a server of weight `w` holds `w` shares. The share
  layout (one entry per unit of weight, in configuration order) is the one
  `@mysten/seal` produces, and the interop suite checks both decrypt each other.
- A committee is one logical server: the aggregator enforces the internal 3-of-5. It
  has no single master key, so no proof of possession: like the TypeScript SDK, the
  client skips `/v1/service` for it. Every returned key is still verified against the
  committee public key read onchain.
- Committee and independent servers are different keys. Data encrypted for one set
  needs the same set to decrypt; migrating means re-encrypting.
- The aggregator runs Seal `0.6.16`, the same tag this crate pins, so no pin change was
  needed for committee support.

## Revocation: what removal does and does not do

A key returned for an id is the key for that id, forever. Seal servers cannot take it
back. Consequences:

1. **Removing a member does not revoke keys they already fetched.** Anything encrypted
   to those ids stays readable by them.
2. **Removing a member is not enough if you keep encrypting to the same id.** A key for
   an id opens everything encrypted to that id, including content written after the
   removal.
3. **So you must rotate the id after a removal.** New content has to be encrypted to an
   id the removed member never obtained a key for.

The allowlist policy shipped in `move/allowlist` does this with an **epoch** that every
removal bumps. Key ids have the form `[allowlist id][epoch: u64 LE][nonce]`, and
`seal_approve` only approves ids whose epoch is at most the current one, for current
members. After removing B:

- B can no longer fetch any key (B is not a member).
- New content, encrypted under the new epoch, is out of B's reach.
- Remaining members still read old content (old epochs stay approvable).
- Nobody can pre-fetch keys for a future epoch.
- What B fetched before the removal, B keeps. The test suites assert this explicitly.

Encryptors must read the current epoch (`allowlist::epoch`) before encrypting. Use a
random nonce per entry, never a counter.

## Policies (BETA)

`move/policies` (package `seal_policies`) holds three policies next to the allowlist.
Key id formats, and the Rust helpers in `sui_seal_client::policy`:

| Module | Key id | Who gets keys | Helper |
|---|---|---|---|
| `allowlist` (`move/allowlist`) | `[list id][epoch u64 LE][nonce]` | current members, epochs up to the current one | `policy::allowlist` |
| `timelock` | `[unlock ms u64 LE][nonce?]` | anyone, once the Sui clock reaches the time | `policy::timelock` |
| `private_data` | `[creator address][nonce]` | the current owner of the `PrivateData` object | `policy::private_data` |
| `subscription` | `[service id][nonce]` | holders of an unexpired `Subscription` to the service | `policy::subscription` |

```rust,no_run
use sui_seal_client::{policy, ApprovalTx, SealClient, SealConfig};
# async fn demo(pkg: sui_seal_client::Address, signer: sui_crypto::ed25519::Ed25519PrivateKey,
#               now_ms: u64) -> sui_seal_client::Result<()> {
let client = SealClient::connect(SealConfig::testnet()).await?;
let id = policy::timelock::random_key_id(now_ms + 3_600_000); // opens in one hour
let encrypted = client.encrypt(pkg, &id, b"sealed bid")?;
// Later, anyone:
let session = client.session_key(pkg, 10, &signer).await?;
let approval = policy::timelock::approve(ApprovalTx::new(pkg), &id)?;
let bid = client.fetch_and_decrypt(&encrypted, &session, &approval).await?;
# Ok(()) }
```

`SealClient::object_arg` reads any object onchain and returns the right argument
(shared, or owned at its current version). Owned objects (`PrivateData`,
`Subscription`) only pass when the session address owns them; otherwise key servers
refuse before running `seal_approve`, which `Error::is_wrong_owner` detects (not
retried). As with every Seal policy, keys fetched before a transfer or an expiry keep
working for the ids they cover.

## Python bindings (BETA)

`python/` builds a `sui_seal_client` Python module with PyO3 and maturin: config
presets and builder, encrypt, session keys, approval transactions, fetch and decrypt,
policy key ids, typed errors (`NoAccessError`, `WrongOwnerError`). Calls block and
release the GIL. See [`python/README.md`](python/README.md).

## Security notes

- The symmetric key produced by `encrypt` (the "backup key" in the TypeScript SDK) is
  wiped immediately and never returned, logged or stored. v0.1 offers no recovery path
  around the key servers.
- The session secret key stays inside `SessionKey` and is not exported. `Debug` output of
  `SessionKey` and `DerivedKeys` contains no key material.
- Session certificates are back-dated by 5 s (`CLOCK_SKEW_ALLOWANCE_MS`): key servers
  reject a creation time in the future with no tolerance.
- Key servers are trusted collectively: any `threshold` of them can decrypt. Choose
  servers and threshold accordingly.
- Committee key servers are supported (BETA). Mainnet is not targeted yet: the API key
  header is in place, but no mainnet preset or test exists.
- The `testing` feature (`LocalKeyServer`, `derive_keys`) runs a key server in memory
  that approves everything. It is for tests only.

## Tests

```sh
cargo test --all-features       # unit tests (incl. mock HTTP key servers) + doctests, offline
cargo clippy --all-targets --all-features -- -D warnings
(cd move/allowlist && sui move test) && (cd move/policies && sui move test)
scripts/testnet-e2e.sh          # testnet: Rust e2e + Rust <-> TypeScript interop
(cd python && maturin develop --release && pytest)   # Python, offline + testnet
```

The interop suite (`tests/interop`, `@mysten/seal` 1.5.4 and `@mysten/sui` 2.39.1, pinned
exactly) runs on testnet against the Mysten servers:

- TypeScript encrypts, Rust decrypts; Rust encrypts, TypeScript decrypts.
- Encrypted object headers are identical on both sides.
- An outsider is refused by both clients.
- After a removal: the removed member is refused for new and old ids, remaining members
  read both, and keys fetched before the removal still open old content.
- Future-epoch ids are refused.
- v0.2 (BETA): committee, hybrid and weighted configurations both ways, with identical
  share layouts; the timelock, private_data and subscription policies both ways, with
  outsiders and non-owners refused by both clients.

`scripts/testnet-e2e.sh` reads `.testnet.env` (not committed); see the script header.

### CI

`.github/workflows/ci.yml` runs on every push and pull request: `cargo fmt --check`,
`cargo clippy -D warnings` (default and all features), `cargo test` (default and all
features, unit + doctests), `cargo doc` with warnings denied, `sui move test` for both
Move packages with warnings treated as errors (sui CLI `testnet-v1.84.0`), and the
Python bindings (clippy, maturin build, offline pytest). The toolchain is pinned in
`rust-toolchain.toml`, actions by commit.

The testnet suites only run on a manual `workflow_dispatch`. They need three repository
secrets, each holding a key file as written by `sui keytool generate` (base64
`flag || private key`):

| Secret | Role |
|---|---|
| `SEAL_KEY_A` | allowlist admin; must hold testnet SUI for gas |
| `SEAL_KEY_B` | member |
| `SEAL_KEY_C` | outsider |

Optional repository variables `SEAL_PACKAGE`, `SEAL_POLICIES` and
`SEAL_POLICIES_VERSION` override the package ids below.

Testnet deployments used by the tests (also recorded in each `Published.toml`), all
published by the project owner address
`0xa0ea7153821aaae60e3251b732533c44f3143df1e07207d18b9276062c2f8c06`, which holds the
`UpgradeCap`s:

| Package | Id | UpgradeCap |
|---|---|---|
| `move/allowlist` | `0xe10fbae08333748f310adc926904980c6ced589a75a774bff4dfc462567d7f1b` | `0xff51af9c9009a3206e1cd52bf88fa3522b33e4eca5d78c7de11a21d9dd6a2780` |
| `move/policies` (BETA) | `0x7b4d1e42efe6673d3687de0b919689b422197d4dc9ac9bfd7ce0c27699e8ae6b` | `0xb3330e0aaa2265148494f86a103e683a648206d4e223baeb997c827e21036e5c` |

`move/policies` also created the shared `subscription::PackageVersion`
`0x64f48808beb2d21f1d7395978a83bb5483a0cc6fb98de977d7f4b035c7698b88` (publish
transaction `AL9ofTpmFc9LmYitbpk6QUagpazrjvACnwK8DZuXkNL8`).

## Roadmap (indicative)

Nothing here is a commitment; order and scope will follow feedback and Seal itself.

- **v0.2 (this release, BETA)**: configurable servers, weights, API keys, committee
  servers, more policies, Python bindings.
- **v0.3**: key cache across calls (as the TypeScript SDK), `async` Python API, MVR
  package names, a mainnet preset once a mainnet committee setup can be tested.
- **v0.4**: Walrus helpers (encrypt-then-store, fetch-then-decrypt), envelope encryption
  for large payloads, more policy patterns (voting, key requests).
- **Before 1.0**: crates.io release (see [`docs/crates-io.md`](docs/crates-io.md)), an
  external review of the client layer, API freeze.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `NOTICE` for the Mysten Labs
code this crate builds on.
