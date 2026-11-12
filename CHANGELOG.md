# Changelog

All notable changes to this project. Versions before 1.0 may break the API.

## 0.2.0 — BETA, testnet (unreleased)

Everything below is BETA.

### Added

- **Configurable key servers**: `SealConfig::builder()`, `KeyServerOptions` (weight,
  aggregator URL, API key), `ApiKey` (value redacted from `Debug`), `SealConfig::total_weight`.
  `SealConfig::testnet()` is unchanged (mysten-testnet-1/-2, threshold 2) and v0.1 struct
  literals with `..SealConfig::testnet()` still work.
- **Weights**: a server of weight `w` holds `w` shares; thresholds count weights. The
  share layout matches `@mysten/seal`.
- **Committee (decentralized) key servers** behind an aggregator, alone or mixed with
  independent servers: `SealConfig::testnet_committee()`, `SealConfigBuilder::committee`,
  `KeyServerKind`, constants `MYSTEN_TESTNET_COMMITTEE` and `MYSTEN_TESTNET_AGGREGATOR`.
  Works with the existing pin (seal-v0.6.16), which is also what the aggregator runs.
- **Policies**: Move package `move/policies` (`timelock`, `private_data`,
  `subscription`, adapted from Mysten's patterns) published on testnet, and
  `sui_seal_client::policy` helpers for all four policies (key ids, `seal_approve`
  calls, `policy::clock()`).
- `SealClient::object_arg`: approval argument for any object (shared, owned, immutable).
- `Error::is_wrong_owner`: the approval used an owned object of someone else. Such
  refusals are no longer retried.
- Feature `testing`: `testing::LocalKeyServer` and `testing::derive_keys` for offline
  tests (never for real data).
- **Python bindings** in `python/` (PyO3 0.30.1, maturin 1.16.0, abi3 >= 3.9).
- Tests: mock HTTP key servers (weights, retries, API key header, batches, wrong owner),
  committee/hybrid/weighted and policy suites on testnet, interop extended from 15 to 38
  checks, pytest (offline + testnet), README code blocks run as doctests.
- CI: all-features clippy and tests, Move tests for both packages with warnings as
  errors, Python job; the manual testnet job also runs the policy and Python suites.
- `docs/crates-io.md`: publication options.

### Changed

- `Error::ThresholdNotReached` reports weights (`got`/`threshold`).
- `seal_cli` example: `SEAL_SERVERS` (independent, committee, hybrid, weighted),
  `decrypt-policy`, exit code 4 for wrong owner.
- `scripts/testnet-e2e.sh` runs the Rust testnet tests on one thread (shared gas coin).

## 0.1.0 — preview, testnet

First release: encrypt, session keys, `seal_approve` transactions, `/v1/fetch_key` with
retries, verified decryption; allowlist policy with revocation epochs; Rust <-> TypeScript
interop suite (15 checks) on testnet.
