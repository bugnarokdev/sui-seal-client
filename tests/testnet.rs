//! End-to-end test against Sui testnet and the Mysten open key servers.
//!
//! Ignored by default. Run with:
//! `SUI_BIN=... SUI_CLIENT_CONFIG=... SEAL_PACKAGE=... KEY_A=... KEY_B=... KEY_C=... \
//!  cargo test --test testnet -- --ignored --nocapture`
//!
//! Admin transactions (create the allowlist, add, remove) go through the sui CLI.

use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_seal_client::{Address, ApprovalTx, Error, PersonalMessageSigner, SealClient, SealConfig};

const INDEX_WAIT: Duration = Duration::from_secs(4);

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing env {name}"))
}

fn key(var: &str) -> Ed25519PrivateKey {
    let raw = std::fs::read_to_string(env(var)).unwrap();
    Ed25519PrivateKey::from_base64(raw.trim()).unwrap()
}

fn sui_call(pkg: &str, function: &str, args: &[String]) -> serde_json::Value {
    let mut cmd = Command::new(env("SUI_BIN"));
    cmd.args([
        "client",
        "--client.config",
        &env("SUI_CLIENT_CONFIG"),
        "call",
    ])
    .args([
        "--package",
        pkg,
        "--module",
        "allowlist",
        "--function",
        function,
    ]);
    if !args.is_empty() {
        cmd.arg("--args").args(args);
    }
    let out = cmd
        .args(["--gas-budget", "20000000", "--json"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text[text.find('{').unwrap()..]).unwrap();
    assert_eq!(json["effects"]["status"]["status"], "success", "{function}");
    json
}

fn created(json: &serde_json::Value, suffix: &str) -> String {
    json["objectChanges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == "created" && c["objectType"].as_str().unwrap().ends_with(suffix))
        .unwrap()["objectId"]
        .as_str()
        .unwrap()
        .to_string()
}

fn key_id(list: &Address, epoch: u64) -> Vec<u8> {
    let mut id = list.as_bytes().to_vec();
    id.extend_from_slice(&epoch.to_le_bytes());
    id.extend_from_slice(&rand::random::<[u8; 16]>());
    id
}

#[tokio::test]
#[ignore = "needs testnet, a funded admin key and the sui CLI"]
async fn allowlist_share_revoke_and_caveat() {
    let pkg_s = env("SEAL_PACKAGE");
    let pkg = Address::from_str(&pkg_s).unwrap();
    let (a, b, c) = (key("KEY_A"), key("KEY_B"), key("KEY_C"));

    let client = SealClient::connect(SealConfig::testnet()).await.unwrap();
    assert_eq!(client.key_servers().len(), 2);

    let res = sui_call(&pkg_s, "create_entry", &[]);
    let list_s = created(&res, "::allowlist::Allowlist");
    let cap = created(&res, "::allowlist::Cap");
    println!("allowlist {list_s} cap {cap}");
    let list = Address::from_str(&list_s).unwrap();
    for who in [&a, &b] {
        sui_call(
            &pkg_s,
            "add",
            &[list_s.clone(), cap.clone(), who.sui_address().to_string()],
        );
    }
    tokio::time::sleep(INDEX_WAIT).await;
    let list_arg = client.shared_object(list).await.unwrap();
    let approve = |id: &[u8]| {
        ApprovalTx::new(pkg)
            .call("allowlist", "seal_approve", id, vec![list_arg.clone()])
            .unwrap()
    };

    // Epoch 0: two entries, fetched by B in one request.
    let id0a = key_id(&list, 0);
    let id0b = key_id(&list, 0);
    let ct0a = client.encrypt(pkg, &id0a, b"entry 0a").unwrap();
    let ct0b = client.encrypt(pkg, &id0b, b"entry 0b").unwrap();
    let session_b = client.session_key(pkg, 10, &b).await.unwrap();
    let batch = approve(&id0a)
        .call("allowlist", "seal_approve", &id0b, vec![list_arg.clone()])
        .unwrap();
    let keys_b = client.fetch_keys(&session_b, &batch).await.unwrap();
    assert_eq!(keys_b.servers_for(&pkg, &id0a), 2);
    assert_eq!(keys_b.servers_for(&pkg, &id0b), 2);
    assert_eq!(client.decrypt(&ct0a, &keys_b).unwrap(), b"entry 0a");
    assert_eq!(client.decrypt(&ct0b, &keys_b).unwrap(), b"entry 0b");

    // Outsider C is refused.
    let session_c = client.session_key(pkg, 10, &c).await.unwrap();
    let err = client
        .fetch_keys(&session_c, &approve(&id0a))
        .await
        .unwrap_err();
    assert!(err.is_no_access(), "{err}");

    // Session for package X cannot be used with a transaction on package Y.
    let other = ApprovalTx::new(Address::ZERO)
        .call("allowlist", "seal_approve", &id0a, vec![])
        .unwrap();
    assert!(matches!(
        client.fetch_keys(&session_b, &other).await,
        Err(Error::InvalidInput(_))
    ));

    // Revocation: remove B, the epoch moves to 1.
    sui_call(
        &pkg_s,
        "remove",
        &[list_s.clone(), cap.clone(), b.sui_address().to_string()],
    );
    tokio::time::sleep(INDEX_WAIT).await;
    let id1 = key_id(&list, 1);
    let ct1 = client.encrypt(pkg, &id1, b"entry 1").unwrap();

    let session_b2 = client.session_key(pkg, 10, &b).await.unwrap();
    let err = client
        .fetch_keys(&session_b2, &approve(&id1))
        .await
        .unwrap_err();
    assert!(err.is_no_access(), "B must not get new-epoch keys: {err}");
    let err = client
        .fetch_keys(&session_b2, &approve(&id0a))
        .await
        .unwrap_err();
    assert!(
        err.is_no_access(),
        "B must not get any key after removal: {err}"
    );
    assert!(
        client.decrypt(&ct1, &keys_b).is_err(),
        "old keys do not open new-epoch data"
    );

    // CAVEAT: keys fetched before removal keep working for the ids they cover.
    assert_eq!(client.decrypt(&ct0a, &keys_b).unwrap(), b"entry 0a");

    // A keeps reading everything.
    let session_a = client.session_key(pkg, 10, &a).await.unwrap();
    let pa = client
        .fetch_and_decrypt(&ct1, &session_a, &approve(&id1))
        .await
        .unwrap();
    assert_eq!(pa, b"entry 1");
    let pa0 = client
        .fetch_and_decrypt(&ct0b, &session_a, &approve(&id0b))
        .await
        .unwrap();
    assert_eq!(pa0, b"entry 0b");

    // Future epoch: refused even for a member.
    let id9 = key_id(&list, 9);
    let err = client
        .fetch_keys(&session_a, &approve(&id9))
        .await
        .unwrap_err();
    assert!(err.is_no_access(), "{err}");

    // An id whose object is not at version 1 (here the mutated allowlist) is rejected
    // before any request, as key servers only accept original package ids.
    assert!(client.session_key(list, 10, &a).await.is_err());
}
