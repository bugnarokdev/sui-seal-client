# sui-seal-client

High-level Rust client for [Seal](https://github.com/MystenLabs/seal), the decentralized
secrets management service on Sui: data is encrypted client-side to an identity, and a
Move function (`seal_approve*`) decides onchain who may obtain the decryption keys from a
threshold of independent key servers.

Mysten publishes an official TypeScript SDK (`@mysten/seal`). On the Rust side, the
`MystenLabs/seal` repository contains low-level crates (`crypto`, `seal-sdk`) but no
published high-level client. This crate fills that gap.

> **Status: v0.1, preview, testnet only.** Seal is itself in beta. The API may change
> before 1.0. Not audited.
>
> - Not on crates.io yet: Mysten's `seal-sdk` and `crypto` crates are only available by
>   git, and crates.io refuses git dependencies. Use it as a git dependency for now:
>   `sui-seal-client = { git = "https://github.com/bugnarokdev/sui-seal-client" }`.

## What it does

- **Encrypt** to `package_id || id` with AES-256-GCM and a `t`-of-`n` threshold.
- **Key servers** read onchain (object ids in, URL and BLS public key out), with the
  proof of possession of each server's master key verified on connect.
- **Session keys**: an ephemeral Ed25519 key certified once by the user's Sui key
  (personal message), then used to sign each key request.
- **`seal_approve` transactions**: a small builder for the PTB key servers dry-run.
- **`/v1/fetch_key`** to all servers in parallel, returning once the threshold is met,
  with exponential backoff on transient errors (server failure, rate limit, objects not
  yet indexed).
- **Decrypt**: every returned key is verified against its server's public key, and share
  consistency is checked against all public keys.

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

Defaults (`SealConfig::testnet()`), taken from the Seal docs (Pricing page):

| Server | Object id | Mode |
|---|---|---|
| mysten-testnet-1 | `0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75` | Open |
| mysten-testnet-2 | `0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8` | Open |

Threshold 2. These servers are free and rate-limited, with no availability guarantee.

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
- Committee (aggregator) key servers and mainnet API keys are not supported yet.

## Tests

```sh
cargo test                      # unit tests, offline
cargo clippy --all-targets -- -D warnings
cd move/allowlist && sui move test
scripts/testnet-e2e.sh          # testnet: Rust e2e + Rust <-> TypeScript interop
```

The interop suite (`tests/interop`, `@mysten/seal` 1.5.4 and `@mysten/sui` 2.39.1, pinned
exactly) runs on testnet against the Mysten servers:

- TypeScript encrypts, Rust decrypts; Rust encrypts, TypeScript decrypts.
- Encrypted object headers are identical on both sides.
- An outsider is refused by both clients.
- After a removal: the removed member is refused for new and old ids, remaining members
  read both, and keys fetched before the removal still open old content.
- Future-epoch ids are refused.

`scripts/testnet-e2e.sh` reads `.testnet.env` (not committed); see the script header.

### CI

`.github/workflows/ci.yml` runs on every push and pull request: `cargo fmt --check`,
`cargo clippy -D warnings`, `cargo test` (unit + doctests), `cargo doc` with warnings
denied, and `sui move test` (sui CLI `testnet-v1.84.0`). The toolchain is pinned in
`rust-toolchain.toml`.

The testnet suites only run on a manual `workflow_dispatch`. They need three repository
secrets, each holding a key file as written by `sui keytool generate` (base64
`flag || private key`):

| Secret | Role |
|---|---|
| `SEAL_KEY_A` | allowlist admin; must hold testnet SUI for gas |
| `SEAL_KEY_B` | member |
| `SEAL_KEY_C` | outsider |

An optional repository variable `SEAL_PACKAGE` overrides the allowlist package id.

Testnet deployment of the allowlist package used by the tests (also recorded in
`move/allowlist/Published.toml`):

- Package: `0xe10fbae08333748f310adc926904980c6ced589a75a774bff4dfc462567d7f1b`
- Published by the project owner address
  `0xa0ea7153821aaae60e3251b732533c44f3143df1e07207d18b9276062c2f8c06`, which holds the
  `UpgradeCap` (`0xff51af9c9009a3206e1cd52bf88fa3522b33e4eca5d78c7de11a21d9dd6a2780`).

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `NOTICE` for the Mysten Labs
code this crate builds on.
