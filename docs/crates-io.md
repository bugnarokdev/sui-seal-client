# Publishing on crates.io: options

Status: not published, `publish = false` in `Cargo.toml`. This note records why and
what could change that. Facts checked on 2026-11-12.

## The blocker

crates.io rejects any crate with a git dependency. This crate depends on two Mysten
crates that only exist in the `MystenLabs/seal` repository:

| Crate | On crates.io? | Note |
|---|---|---|
| `seal-sdk` (`crates/seal-sdk`) | no | name free on crates.io |
| `crypto` (`crates/crypto`) | no | the name `crypto` belongs to an unrelated RustCrypto crate |
| `fastcrypto` | yes, 0.1.12 | but `crypto` pins a git revision (`076bf5a…`) |
| `fastcrypto-tbls` | yes, 0.1.0 (2024) | stale compared with the pinned revision |

So even a republished `crypto` would still need git revisions of fastcrypto, or a
version that matches them.

## Options

1. **Mysten publishes `seal-sdk` and its crypto crate.** Best outcome: no forked
   cryptography, versions follow upstream releases. Needs Mysten to rename `crypto`
   (taken) and to publish matching fastcrypto versions. Action on our side: ask
   upstream (an issue on `MystenLabs/seal`), and adapt the dependency lines when it
   happens. Recommended target.
2. **Keep the git dependency (current).** Users add
   `sui-seal-client = { git = "...", rev = "<commit>" }`. Reproducible thanks to exact
   pins, no forked crypto. Costs: no crates.io discoverability, no docs.rs, every
   dependent must also use git. Recommended until option 1.
3. **Republish Mysten's crates under our own names** (Apache-2.0 allows it with
   attribution). Rejected for now: we would ship and maintain a fork of cryptographic
   code, in our name, and would also have to vendor fastcrypto revisions. A security
   fix upstream would reach users only through us.
4. **Reimplement the primitives.** Rejected: the whole point of this crate is to add no
   cryptography of its own and reuse Mysten's audited path.
5. **Publish a reduced crate without the crypto** (approval builder, policy key ids,
   config types). Possible, but of little use alone; it would split the API in two.

## Decision

Option 2 now, option 1 as the path to crates.io. Revisit when `MystenLabs/seal`
publishes crates or when a release tag ships them.
