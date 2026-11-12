#!/usr/bin/env bash
# Runs the testnet suites: Rust end-to-end, then Rust <-> TypeScript interop.
# Reads its settings from .testnet.env (not committed):
#   SUI_BIN, SUI_CLIENT_CONFIG, SEAL_PACKAGE, KEY_A, KEY_B, KEY_C
# KEY_A must be the active address of SUI_CLIENT_CONFIG and hold testnet SUI.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.testnet.env; set +a
cargo build --example seal_cli
export RUST_CLI="$PWD/target/debug/examples/seal_cli"
cargo test --test testnet -- --ignored --nocapture
(cd tests/interop && npm ci --silent && node interop.mjs)
