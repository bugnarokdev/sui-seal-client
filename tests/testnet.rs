//! End-to-end tests against Sui testnet and the Mysten key servers.
//!
//! Ignored by default. Run with:
//! `SUI_BIN=... SUI_CLIENT_CONFIG=... SEAL_PACKAGE=... SEAL_POLICIES=... KEY_A=... KEY_B=... \
//!  KEY_C=... cargo test --test testnet -- --ignored --nocapture --test-threads=1`
//!
//! `--test-threads=1` matters: every admin transaction is paid by key A through the sui
//! CLI, and parallel transactions would compete for the same gas coin.

use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_seal_client::{
    Address, ApprovalTx, Error, KeyServerOptions, MYSTEN_TESTNET_1, MYSTEN_TESTNET_2,
    MYSTEN_TESTNET_AGGREGATOR, MYSTEN_TESTNET_COMMITTEE, PersonalMessageSigner, SealClient,
    SealConfig, policy,
};

const INDEX_WAIT: Duration = Duration::from_secs(4);

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing env {name}"))
}

fn key(var: &str) -> Ed25519PrivateKey {
    let raw = std::fs::read_to_string(env(var)).unwrap();
    Ed25519PrivateKey::from_base64(raw.trim()).unwrap()
}

fn run_sui(args: &[&str], what: &str) -> serde_json::Value {
    let out = Command::new(env("SUI_BIN"))
        .args(["client", "--client.config", &env("SUI_CLIENT_CONFIG")])
        .args(args)
        .args(["--gas-budget", "20000000", "--json"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let start = text
        .find('{')
        .unwrap_or_else(|| panic!("{what}: {}", String::from_utf8_lossy(&out.stderr)));
    let json: serde_json::Value = serde_json::from_str(&text[start..]).unwrap();
    assert_eq!(json["effects"]["status"]["status"], "success", "{what}");
    json
}

fn sui_move(pkg: &str, module: &str, function: &str, args: &[String]) -> serde_json::Value {
    let mut argv = vec![
        "call",
        "--package",
        pkg,
        "--module",
        module,
        "--function",
        function,
    ];
    if !args.is_empty() {
        argv.push("--args");
        argv.extend(args.iter().map(String::as_str));
    }
    run_sui(&argv, function)
}

fn sui_call(pkg: &str, function: &str, args: &[String]) -> serde_json::Value {
    sui_move(pkg, "allowlist", function, args)
}

fn a(s: &str) -> Address {
    Address::from_str(s).unwrap()
}

/// Waits for the fullnodes behind the key servers to index fresh objects.
async fn settle() {
    tokio::time::sleep(INDEX_WAIT).await;
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
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

// ---- v0.2 (BETA): committee, hybrid and weighted configurations ---------------------

fn hybrid() -> SealConfig {
    SealConfig::builder()
        .committee(a(MYSTEN_TESTNET_COMMITTEE), MYSTEN_TESTNET_AGGREGATOR)
        .key_server(a(MYSTEN_TESTNET_1))
        .threshold(2)
        .build()
        .unwrap()
}

fn weighted() -> SealConfig {
    SealConfig::builder()
        .key_server_with(a(MYSTEN_TESTNET_1), KeyServerOptions::default().weight(2))
        .key_server(a(MYSTEN_TESTNET_2))
        .threshold(2)
        .build()
        .unwrap()
}

#[tokio::test]
#[ignore = "needs testnet, a funded admin key and the sui CLI"]
async fn committee_hybrid_and_weighted_configs() {
    let pkg_s = env("SEAL_PACKAGE");
    let pkg = a(&pkg_s);
    let (b, c) = (key("KEY_B"), key("KEY_C"));
    let res = sui_call(&pkg_s, "create_entry", &[]);
    let list_s = created(&res, "::allowlist::Allowlist");
    let cap = created(&res, "::allowlist::Cap");
    sui_call(
        &pkg_s,
        "add",
        &[list_s.clone(), cap, b.sui_address().to_string()],
    );
    settle().await;
    let list = a(&list_s);

    for (name, config, servers, weight) in [
        ("committee", SealConfig::testnet_committee(), 1, 1),
        ("hybrid", hybrid(), 2, 2),
        ("weighted", weighted(), 2, 3),
    ] {
        println!("config {name}");
        let client = SealClient::connect(config).await.unwrap();
        assert_eq!(client.key_servers().len(), servers, "{name}");
        assert_eq!(client.total_weight(), weight, "{name}");
        assert_eq!(
            client
                .key_servers()
                .iter()
                .filter(|s| s.is_committee())
                .count(),
            usize::from(name != "weighted"),
            "{name}"
        );
        let list_arg = client.shared_object(list).await.unwrap();
        let id = policy::allowlist::random_key_id(&list, 0);
        let ct = client.encrypt(pkg, &id, name.as_bytes()).unwrap();
        let info = sui_seal_client::parse_encrypted_object(&ct).unwrap();
        assert_eq!(
            info.key_servers.len(),
            weight,
            "{name}: one share per unit of weight"
        );
        let approval = policy::allowlist::approve(ApprovalTx::new(pkg), &id, list_arg).unwrap();

        let session_b = client.session_key(pkg, 10, &b).await.unwrap();
        let pt = client
            .fetch_and_decrypt(&ct, &session_b, &approval)
            .await
            .unwrap();
        assert_eq!(pt, name.as_bytes(), "{name}: member B decrypts");

        let session_c = client.session_key(pkg, 10, &c).await.unwrap();
        let err = client.fetch_keys(&session_c, &approval).await.unwrap_err();
        assert!(err.is_no_access(), "{name}: outsider C refused: {err}");
    }

    // Data encrypted for the committee cannot be opened by a client that does not know it.
    let committee = SealClient::connect(SealConfig::testnet_committee())
        .await
        .unwrap();
    let independent = SealClient::connect(SealConfig::testnet()).await.unwrap();
    let id = policy::allowlist::random_key_id(&list, 0);
    let ct = committee.encrypt(pkg, &id, b"c").unwrap();
    let keys = sui_seal_client::DerivedKeys::default();
    assert!(matches!(
        independent.decrypt(&ct, &keys),
        Err(Error::InvalidInput(_))
    ));
}

// ---- v0.2 (BETA): policies from move/policies ---------------------------------------

#[tokio::test]
#[ignore = "needs testnet and the seal_policies package"]
async fn timelock_policy() {
    let pkg = a(&env("SEAL_POLICIES"));
    let anyone = key("KEY_C");
    let client = SealClient::connect(SealConfig::testnet()).await.unwrap();
    let session = client.session_key(pkg, 10, &anyone).await.unwrap();
    let open = |id: &[u8]| policy::timelock::approve(ApprovalTx::new(pkg), id).unwrap();

    // Past unlock time: anyone gets the key.
    let past = policy::timelock::random_key_id(now_ms() - 60_000);
    let ct = client.encrypt(pkg, &past, b"already open").unwrap();
    let pt = client
        .fetch_and_decrypt(&ct, &session, &open(&past))
        .await
        .unwrap();
    assert_eq!(pt, b"already open");

    // Far future: refused.
    let far = policy::timelock::random_key_id(now_ms() + 3_600_000);
    let err = client.fetch_keys(&session, &open(&far)).await.unwrap_err();
    assert!(err.is_no_access(), "{err}");

    // Near future: refused now, open once the clock passes it.
    let unlock = now_ms() + 20_000;
    let soon = policy::timelock::random_key_id(unlock);
    let ct = client.encrypt(pkg, &soon, b"opens soon").unwrap();
    let err = client.fetch_keys(&session, &open(&soon)).await.unwrap_err();
    assert!(err.is_no_access(), "locked before unlock time: {err}");
    let wait = unlock.saturating_sub(now_ms()) + 8_000;
    tokio::time::sleep(Duration::from_millis(wait)).await;
    let pt = client
        .fetch_and_decrypt(&ct, &session, &open(&soon))
        .await
        .unwrap();
    assert_eq!(pt, b"opens soon");
}

#[tokio::test]
#[ignore = "needs testnet, a funded admin key and the seal_policies package"]
async fn private_data_policy() {
    let pkg_s = env("SEAL_POLICIES");
    let pkg = a(&pkg_s);
    let (owner, b) = (key("KEY_A"), key("KEY_B"));
    let client = SealClient::connect(SealConfig::testnet()).await.unwrap();

    let nonce = rand::random::<[u8; 16]>();
    let res = sui_move(
        &pkg_s,
        "private_data",
        "store_entry",
        &[format!("0x{}", hex::encode(nonce)), "0x".into()],
    );
    let obj = a(&created(&res, "::private_data::PrivateData"));
    println!("private data {obj}");
    settle().await;
    let id = policy::private_data::key_id(&owner.sui_address(), &nonce);
    let ct = client.encrypt(pkg, &id, b"for the owner").unwrap();
    let approval = |arg| policy::private_data::approve(ApprovalTx::new(pkg), &id, arg).unwrap();

    let session_a = client.session_key(pkg, 10, &owner).await.unwrap();
    let arg = client.object_arg(obj).await.unwrap();
    assert!(matches!(arg, sui_seal_client::ApprovalArg::Object(_)));
    let pt = client
        .fetch_and_decrypt(&ct, &session_a, &approval(arg.clone()))
        .await
        .unwrap();
    assert_eq!(pt, b"for the owner");

    // B does not own the object: the dry run fails.
    let session_b = client.session_key(pkg, 10, &b).await.unwrap();
    let err = client
        .fetch_keys(&session_b, &approval(arg))
        .await
        .unwrap_err();
    println!("B before transfer: {err}");
    assert!(
        matches!(err, Error::ThresholdNotReached { got: 0, .. }),
        "{err}"
    );

    // Wrong id for this object: NoAccess even for the owner.
    let wrong = policy::private_data::key_id(&owner.sui_address(), b"other-nonce");
    let arg = client.object_arg(obj).await.unwrap();
    let tx = policy::private_data::approve(ApprovalTx::new(pkg), &wrong, arg).unwrap();
    let err = client.fetch_keys(&session_a, &tx).await.unwrap_err();
    assert!(err.is_no_access(), "{err}");

    // Transfer to B: B gets access, A loses it for new requests.
    run_sui(
        &[
            "transfer",
            "--object-id",
            &obj.to_string(),
            "--to",
            &b.sui_address().to_string(),
        ],
        "transfer",
    );
    settle().await;
    let arg = client.object_arg(obj).await.unwrap();
    let pt = client
        .fetch_and_decrypt(&ct, &session_b, &approval(arg.clone()))
        .await
        .unwrap();
    assert_eq!(pt, b"for the owner");
    let err = client
        .fetch_keys(&session_a, &approval(arg))
        .await
        .unwrap_err();
    println!("A after transfer: {err}");
    assert!(
        matches!(err, Error::ThresholdNotReached { got: 0, .. }),
        "{err}"
    );
}

#[tokio::test]
#[ignore = "needs testnet, a funded admin key and the seal_policies package"]
async fn subscription_policy() {
    let pkg_s = env("SEAL_POLICIES");
    let pkg = a(&pkg_s);
    let version = a(&env("SEAL_POLICIES_VERSION"));
    let (owner, b, c) = (key("KEY_A"), key("KEY_B"), key("KEY_C"));
    let client = SealClient::connect(SealConfig::testnet()).await.unwrap();
    const FEE: u64 = 1_000;
    const TTL_MS: u64 = 40_000;

    let res = sui_move(
        &pkg_s,
        "subscription",
        "create_service_entry",
        &[FEE.to_string(), TTL_MS.to_string()],
    );
    let service_s = created(&res, "::subscription::Service");
    let service = a(&service_s);
    println!("service {service}");
    settle().await;

    // A pays the fee and sends the subscription to B.
    let target = format!("{pkg_s}::subscription::subscribe_entry");
    let to = b.sui_address().to_string();
    let res = run_sui(
        &[
            "ptb",
            "--split-coins",
            "gas",
            &format!("[{FEE}]"),
            "--assign",
            "fee",
            "--move-call",
            &target,
            "fee.0",
            &format!("@{service_s}"),
            "@0x6",
            &format!("@{to}"),
        ],
        "subscribe",
    );
    let sub = a(&created(&res, "::subscription::Subscription"));
    let subscribed_at = now_ms();
    println!("subscription {sub} for B");
    settle().await;

    let id = policy::subscription::random_key_id(&service);
    let ct = client.encrypt(pkg, &id, b"subscribers only").unwrap();
    let approval = |sub_arg| async {
        policy::subscription::approve(
            ApprovalTx::new(pkg),
            &id,
            client.shared_object(version).await.unwrap(),
            sub_arg,
            client.shared_object(service).await.unwrap(),
        )
        .unwrap()
    };

    let session_b = client.session_key(pkg, 10, &b).await.unwrap();
    let sub_arg = client.object_arg(sub).await.unwrap();
    let pt = client
        .fetch_and_decrypt(&ct, &session_b, &approval(sub_arg.clone()).await)
        .await
        .unwrap();
    assert_eq!(pt, b"subscribers only");

    // An id under another prefix is refused even with a valid subscription.
    let foreign = policy::subscription::random_key_id(&a(&env("SEAL_PACKAGE")));
    let tx = policy::subscription::approve(
        ApprovalTx::new(pkg),
        &foreign,
        client.shared_object(version).await.unwrap(),
        sub_arg.clone(),
        client.shared_object(service).await.unwrap(),
    )
    .unwrap();
    let err = client.fetch_keys(&session_b, &tx).await.unwrap_err();
    assert!(err.is_no_access(), "{err}");

    // C (and the payer A) do not hold the subscription.
    for (who, k) in [("C", &c), ("A", &owner)] {
        let s = client.session_key(pkg, 10, k).await.unwrap();
        let err = client
            .fetch_keys(&s, &approval(sub_arg.clone()).await)
            .await
            .unwrap_err();
        println!("{who} without subscription: {err}");
        assert!(
            matches!(err, Error::ThresholdNotReached { got: 0, .. }),
            "{err}"
        );
    }

    // After expiry B is refused for new requests.
    let wait = (subscribed_at + TTL_MS + 8_000).saturating_sub(now_ms());
    tokio::time::sleep(Duration::from_millis(wait)).await;
    let err = client
        .fetch_keys(&session_b, &approval(sub_arg).await)
        .await
        .unwrap_err();
    assert!(err.is_no_access(), "expired subscription: {err}");
}
