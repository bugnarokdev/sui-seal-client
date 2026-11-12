//! Small command line used by the interop tests (and as a usage example).
//!
//! ```text
//! seal_cli servers
//! seal_cli encrypt <package> <id-hex> <in> <out>
//! seal_cli decrypt <package> <allowlist> <in> <out>      # key file in SEAL_KEY_FILE
//! seal_cli decrypt-policy <package> <module> <in> <out> [object-id|clock ...]
//! seal_cli address                                       # address of SEAL_KEY_FILE
//! ```
//! `decrypt-policy` calls `<module>::seal_approve(id, args...)`; each object id is read
//! onchain (shared, owned or immutable) and `clock` is the Sui clock `0x6`.
//!
//! `SEAL_SERVERS` selects the key servers (BETA, v0.2):
//! - `independent` (default): mysten-testnet-1 and -2, threshold 2
//! - `committee`: the Mysten testnet committee behind its aggregator, threshold 1
//! - `hybrid`: committee + mysten-testnet-1, threshold 2
//! - `weighted`: mysten-testnet-1 (weight 2) + mysten-testnet-2 (weight 1), threshold 2
//!
//! Exit code 3 means the key servers refused access (`NoAccess`); exit code 4 means the
//! approval used an owned object the caller does not own.

use std::process::ExitCode;
use std::str::FromStr;

use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_seal_client::{
    Address, ApprovalArg, ApprovalTx, KeyServerOptions, MYSTEN_TESTNET_1, MYSTEN_TESTNET_2,
    MYSTEN_TESTNET_AGGREGATOR, MYSTEN_TESTNET_COMMITTEE, PersonalMessageSigner, SealClient,
    SealConfig, policy,
};

fn load_key() -> Result<Ed25519PrivateKey, String> {
    let path = std::env::var("SEAL_KEY_FILE").map_err(|_| "SEAL_KEY_FILE is not set")?;
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let raw = raw.trim();
    if raw.starts_with("suiprivkey") {
        Ed25519PrivateKey::from_suiprivkey(raw).map_err(|e| e.to_string())
    } else {
        Ed25519PrivateKey::from_base64(raw).map_err(|e| e.to_string())
    }
}

fn addr(s: &str) -> Result<Address, String> {
    Address::from_str(s).map_err(|e| format!("{s}: {e}"))
}

fn config() -> Result<SealConfig, sui_seal_client::Error> {
    let a = |s: &str| Address::from_str(s).expect("valid constant");
    let mode = std::env::var("SEAL_SERVERS").unwrap_or_else(|_| "independent".into());
    match mode.as_str() {
        "independent" => Ok(SealConfig::testnet()),
        "committee" => Ok(SealConfig::testnet_committee()),
        "hybrid" => SealConfig::builder()
            .committee(a(MYSTEN_TESTNET_COMMITTEE), MYSTEN_TESTNET_AGGREGATOR)
            .key_server(a(MYSTEN_TESTNET_1))
            .threshold(2)
            .build(),
        "weighted" => SealConfig::builder()
            .key_server_with(a(MYSTEN_TESTNET_1), KeyServerOptions::default().weight(2))
            .key_server(a(MYSTEN_TESTNET_2))
            .threshold(2)
            .build(),
        other => Err(sui_seal_client::Error::InvalidInput(format!(
            "SEAL_SERVERS={other}: expected independent, committee, hybrid or weighted"
        ))),
    }
}

async fn run(args: Vec<String>) -> Result<(), sui_seal_client::Error> {
    let bad = |m: &str| sui_seal_client::Error::InvalidInput(m.to_string());
    let io = |e: std::io::Error| sui_seal_client::Error::InvalidInput(e.to_string());
    match args.first().map(String::as_str) {
        Some("address") => {
            println!("{}", load_key().map_err(|e| bad(&e))?.sui_address());
        }
        Some("servers") => {
            let client = SealClient::connect(config()?).await?;
            for s in client.key_servers() {
                let check = if s.is_committee() {
                    "committee"
                } else {
                    "pop=verified"
                };
                println!(
                    "{} {} {} weight={} {check}",
                    s.object_id,
                    s.name,
                    s.url,
                    s.weight()
                );
            }
        }
        Some("encrypt") if args.len() == 5 => {
            let client = SealClient::connect(config()?).await?;
            let package = addr(&args[1]).map_err(|e| bad(&e))?;
            let id =
                hex::decode(args[2].trim_start_matches("0x")).map_err(|e| bad(&e.to_string()))?;
            let data = std::fs::read(&args[3]).map_err(io)?;
            let ct = client.encrypt(package, &id, &data)?;
            std::fs::write(&args[4], ct).map_err(io)?;
        }
        Some("decrypt") if args.len() == 5 => {
            let key = load_key().map_err(|e| bad(&e))?;
            let client = SealClient::connect(config()?).await?;
            let package = addr(&args[1]).map_err(|e| bad(&e))?;
            let list = client
                .shared_object(addr(&args[2]).map_err(|e| bad(&e))?)
                .await?;
            let ct = std::fs::read(&args[3]).map_err(io)?;
            let info = sui_seal_client::parse_encrypted_object(&ct)?;
            let session = client.session_key(package, 5, &key).await?;
            let approval = policy::allowlist::approve(ApprovalTx::new(package), &info.id, list)?;
            let pt = client.fetch_and_decrypt(&ct, &session, &approval).await?;
            std::fs::write(&args[4], pt).map_err(io)?;
        }
        Some("decrypt-policy") if args.len() >= 5 => {
            let key = load_key().map_err(|e| bad(&e))?;
            let client = SealClient::connect(config()?).await?;
            let package = addr(&args[1]).map_err(|e| bad(&e))?;
            let mut extra: Vec<ApprovalArg> = Vec::new();
            for a in &args[5..] {
                extra.push(if a == "clock" {
                    policy::clock()
                } else {
                    client.object_arg(addr(a).map_err(|e| bad(&e))?).await?
                });
            }
            let ct = std::fs::read(&args[3]).map_err(io)?;
            let info = sui_seal_client::parse_encrypted_object(&ct)?;
            let session = client.session_key(package, 5, &key).await?;
            let approval =
                ApprovalTx::new(package).call(&args[2], "seal_approve", &info.id, extra)?;
            let pt = client.fetch_and_decrypt(&ct, &session, &approval).await?;
            std::fs::write(&args[4], pt).map_err(io)?;
        }
        _ => {
            return Err(bad(
                "usage: seal_cli servers|address|encrypt|decrypt|decrypt-policy ...",
            ));
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.is_no_access() => {
            eprintln!("no access: {e}");
            ExitCode::from(3)
        }
        Err(e) if e.is_wrong_owner() => {
            eprintln!("not the owner: {e}");
            ExitCode::from(4)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
