# sui-seal-client (Python) — BETA

Python bindings for [`sui-seal-client`](../README.md), built with PyO3 and maturin. Same
engine as the Rust crate: Mysten's own `crypto` and `seal-sdk` primitives, pinned by
commit. Testnet only, not audited, API may change.

```sh
cd python
uv venv && . .venv/bin/activate
uv pip install maturin==1.16.0 pytest==8.4.2
maturin develop --release
pytest                       # offline tests; testnet tests run when .testnet.env is present
```

```python
from sui_seal_client import (SealClient, SealConfig, Signer, ApprovalTx,
                             allowlist_key_id, NoAccessError)

client = SealClient.connect(SealConfig.testnet())          # or SealConfig.testnet_committee()
id = allowlist_key_id(list_id, epoch=0)
ct = client.encrypt(package_id, id, b"hello")

signer = Signer.from_file("member.key")
session = client.session_key(package_id, 10, signer)
tx = ApprovalTx(package_id).call("allowlist", "seal_approve", id, [client.shared_object(list_id)])
assert client.fetch_and_decrypt(ct, session, tx) == b"hello"
```

Calls block and release the GIL. Errors raise `SealError`, or its subclasses
`NoAccessError` (policy refusal) and `WrongOwnerError` (owned object of someone else).

`LocalKeyServer` and `derive_keys` are offline test helpers: an in-process key server
that approves everything. Never use them for real data.
