"""Testnet end-to-end (BETA): skipped unless ../.testnet.env exists.

Creates an allowlist with the sui CLI (key A pays), then checks member/outsider access
through the Python bindings, with the independent servers and with the committee.
"""
import json
import os
import pathlib
import subprocess
import time

import pytest

import sui_seal_client as s

ENV_FILE = pathlib.Path(__file__).resolve().parents[2] / ".testnet.env"


def load_env():
    if not ENV_FILE.exists():
        return None
    env = {}
    for line in ENV_FILE.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


ENV = load_env()
pytestmark = [
    pytest.mark.testnet,
    pytest.mark.skipif(ENV is None, reason="no .testnet.env"),
]


def sui_call(pkg, module, function, args):
    out = subprocess.run(
        [ENV["SUI_BIN"], "client", "--client.config", ENV["SUI_CLIENT_CONFIG"], "call",
         "--package", pkg, "--module", module, "--function", function,
         *(["--args", *args] if args else []), "--gas-budget", "20000000", "--json"],
        capture_output=True, text=True, check=True,
    ).stdout
    res = json.loads(out[out.index("{"):])
    assert res["effects"]["status"]["status"] == "success", function
    return res


def created(res, suffix):
    return next(c["objectId"] for c in res["objectChanges"]
                if c["type"] == "created" and c["objectType"].endswith(suffix))


@pytest.fixture(scope="module")
def allowlist():
    pkg = ENV["SEAL_PACKAGE"]
    member = s.Signer.from_file(ENV["KEY_B"])
    res = sui_call(pkg, "allowlist", "create_entry", [])
    list_id, cap = created(res, "::allowlist::Allowlist"), created(res, "::allowlist::Cap")
    sui_call(pkg, "allowlist", "add", [list_id, cap, member.address])
    time.sleep(4)
    return pkg, list_id


@pytest.mark.parametrize("config", ["testnet", "testnet_committee"])
def test_allowlist_member_and_outsider(allowlist, config):
    pkg, list_id = allowlist
    client = s.SealClient.connect(getattr(s.SealConfig, config)())
    member = s.Signer.from_file(ENV["KEY_B"])
    outsider = s.Signer.from_file(ENV["KEY_C"])
    kid = s.allowlist_key_id(list_id, 0)
    ct = client.encrypt(pkg, kid, b"from python " + config.encode())
    tx = s.ApprovalTx(pkg).call("allowlist", "seal_approve", kid, [client.shared_object(list_id)])

    session = client.session_key(pkg, 10, member)
    assert client.fetch_and_decrypt(ct, session, tx) == b"from python " + config.encode()

    with pytest.raises(s.NoAccessError):
        client.fetch_keys(client.session_key(pkg, 10, outsider), tx)


def test_timelock_and_private_data_errors():
    pol = ENV["SEAL_POLICIES"]
    client = s.SealClient.connect(s.SealConfig.testnet())
    anyone = s.Signer.from_file(ENV["KEY_C"])
    session = client.session_key(pol, 10, anyone)
    past = s.timelock_key_id(int(time.time() * 1000) - 60_000)
    ct = client.encrypt(pol, past, b"open")
    tx = s.ApprovalTx(pol).call("timelock", "seal_approve", past, [s.ApprovalArg.clock()])
    assert client.fetch_and_decrypt(ct, session, tx) == b"open"
    future = s.timelock_key_id(int(time.time() * 1000) + 3_600_000)
    tx = s.ApprovalTx(pol).call("timelock", "seal_approve", future, [s.ApprovalArg.clock()])
    with pytest.raises(s.NoAccessError):
        client.fetch_keys(session, tx)

    # An object owned by A, used by C: WrongOwnerError, not retried.
    owner = s.Signer.from_file(ENV["KEY_A"])
    nonce = os.urandom(16)
    res = sui_call(pol, "private_data", "store_entry", ["0x" + nonce.hex(), "0x"])
    obj = created(res, "::private_data::PrivateData")
    time.sleep(4)
    kid = s.private_data_key_id(owner.address, nonce)
    tx = s.ApprovalTx(pol).call("private_data", "seal_approve", kid, [client.object_arg(obj)])
    with pytest.raises(s.WrongOwnerError):
        client.fetch_keys(session, tx)
    ct = client.encrypt(pol, kid, b"mine")
    assert client.fetch_and_decrypt(ct, client.session_key(pol, 10, owner), tx) == b"mine"
