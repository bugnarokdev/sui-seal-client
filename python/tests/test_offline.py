"""Offline tests: in-process key servers, no network."""
import base64

import pytest

import sui_seal_client as s

PKG = "0x" + "ab" * 32


def servers(n, weights=None):
    weights = weights or [1] * n
    return [s.LocalKeyServer("0x" + f"{i + 1:02x}" * 32, f"local-{i}", w) for i, w in enumerate(weights)]


def test_roundtrip_threshold_2_of_3():
    ls = servers(3)
    client = s.SealClient.with_local_servers(ls, 2)
    ct = client.encrypt(PKG, b"memory-42", b"the lighthouse key")
    info = s.parse_encrypted_object(ct)
    assert info.package_id == PKG
    assert info.id == b"memory-42"
    assert info.threshold == 2
    assert info.key_servers == [l.object_id for l in ls]
    for pair in ([0, 1], [0, 2], [1, 2]):
        keys = s.derive_keys([ls[i] for i in pair], PKG, b"memory-42")
        assert keys.servers_for(PKG, b"memory-42") == 2
        assert client.decrypt(ct, keys) == b"the lighthouse key"
    with pytest.raises(s.SealError):
        client.decrypt(ct, s.derive_keys([ls[0]], PKG, b"memory-42"))


def test_wrong_id_and_aad():
    ls = servers(2)
    client = s.SealClient.with_local_servers(ls, 2)
    ct = client.encrypt(PKG, b"epoch-1", b"secret", aad=b"ctx")
    with pytest.raises(s.SealError):
        client.decrypt(ct, s.derive_keys(ls, PKG, b"epoch-0"))
    assert client.decrypt(ct, s.derive_keys(ls, PKG, b"epoch-1")) == b"secret"


def test_ciphertexts_are_randomized():
    client = s.SealClient.with_local_servers(servers(2), 2)
    assert client.encrypt(PKG, b"id", b"x") != client.encrypt(PKG, b"id", b"x")


def test_weights():
    ls = servers(2, [2, 1])
    client = s.SealClient.with_local_servers(ls, 2)
    ct = client.encrypt(PKG, b"w", b"weighted")
    assert len(s.parse_encrypted_object(ct).key_servers) == 3
    assert client.decrypt(ct, s.derive_keys([ls[0]], PKG, b"w")) == b"weighted"
    with pytest.raises(s.SealError):
        client.decrypt(ct, s.derive_keys([ls[1]], PKG, b"w"))


def test_invalid_inputs():
    ls = servers(1)
    with pytest.raises(s.SealError):
        s.SealClient.with_local_servers(ls, 2)
    with pytest.raises(s.SealError):
        s.SealClient.with_local_servers(ls, 1).encrypt(PKG, b"", b"x")
    with pytest.raises(s.SealError):
        s.parse_encrypted_object(b"garbage")
    with pytest.raises(s.SealError):
        s.SealConfig(["0x1"], 2)
    with pytest.raises(s.SealError):
        s.ApprovalTx(PKG).call("m", "approve", b"\x01")


def test_config_presets_and_builder():
    t = s.SealConfig.testnet()
    assert t.threshold == 2 and t.key_servers == [s.MYSTEN_TESTNET_1, s.MYSTEN_TESTNET_2]
    c = s.SealConfig.testnet_committee()
    assert c.threshold == 1 and c.key_servers == [s.MYSTEN_TESTNET_COMMITTEE]
    h = s.SealConfig(
        [
            {"object_id": s.MYSTEN_TESTNET_COMMITTEE, "aggregator_url": s.MYSTEN_TESTNET_AGGREGATOR},
            {"object_id": s.MYSTEN_TESTNET_1, "weight": 2},
        ],
        threshold=2,
    )
    assert h.total_weight == 3
    with pytest.raises(s.SealError):
        s.SealConfig([{"object_id": s.MYSTEN_TESTNET_1, "api_key": "only-value"}], 1)


def test_policy_key_ids():
    list_id = "0x" + "aa" * 32
    kid = s.allowlist_key_id(list_id, 3, b"n")
    assert kid == bytes.fromhex("aa" * 32) + (3).to_bytes(8, "little") + b"n"
    assert len(s.allowlist_key_id(list_id, 0)) == 32 + 8 + 16
    assert s.timelock_key_id(0x0102030405060708, b"x") == bytes([8, 7, 6, 5, 4, 3, 2, 1]) + b"x"
    assert s.private_data_key_id("0x" + "02" * 32, b"nn") == bytes([2] * 32) + b"nn"
    with pytest.raises(s.SealError):
        s.subscription_key_id("0x" + "01" * 32, b"")


def test_approval_tx_and_session_offline():
    # Keystore entry: base64(flag 0x00 || 32-byte Ed25519 secret).
    signer = s.Signer.from_str(base64.b64encode(bytes([0]) + bytes([7] * 32)).decode())
    assert signer.address.startswith("0x")
    session = s.SessionKey(PKG, 5, signer)
    assert session.address == signer.address and not session.is_expired()
    with pytest.raises(s.SealError):
        s.SessionKey(PKG, 31, signer)
    tx = (
        s.ApprovalTx(PKG)
        .call("timelock", "seal_approve", b"\x01" * 8, [s.ApprovalArg.clock()])
        .call("timelock", "seal_approve", b"\x02" * 8, [s.ApprovalArg.clock()])
    )
    assert tx.ids() == [b"\x01" * 8, b"\x02" * 8]
    assert len(tx.to_bcs()) > 0
    assert "secret" not in repr(signer).lower()
