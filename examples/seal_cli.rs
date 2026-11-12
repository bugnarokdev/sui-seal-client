//! Small command line used by the interop tests (and as a usage example).
//!
//! ```text
//! seal_cli servers
//! seal_cli encrypt <package> <id-hex> <in> <out>
//! seal_cli decrypt <package> <allowlist> <in> <out>      # key file in SEAL_KEY_FILE
//! seal_cli address                                       # address of SEAL_KEY_FILE
//! ```
//! Exit code 3 means the key servers refused access (`NoAccess`).

use std::process::ExitCode;
use std::str::FromStr;

use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_seal_client::{Address, ApprovalTx, PersonalMessageSigner, SealClient, SealConfig};

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

async fn run(args: Vec<String>) -> Result<(), sui_seal_client::Error> {
    let bad = |m: &str| sui_seal_client::Error::InvalidInput(m.to_string());
    let io = |e: std::io::Error| sui_seal_client::Error::InvalidInput(e.to_string());
    match args.first().map(String::as_str) {
        Some("address") => {
            println!("{}", load_key().map_err(|e| bad(&e))?.sui_address());
        }
        Some("servers") => {
            let client = SealClient::connect(SealConfig::testnet()).await?;
            for s in client.key_servers() {
                println!("{} {} {} pop=verified", s.object_id, s.name, s.url);
            }
        }
        Some("encrypt") if args.len() == 5 => {
            let client = SealClient::connect(SealConfig::testnet()).await?;
            let package = addr(&args[1]).map_err(|e| bad(&e))?;
            let id =
                hex::decode(args[2].trim_start_matches("0x")).map_err(|e| bad(&e.to_string()))?;
            let data = std::fs::read(&args[3]).map_err(io)?;
            let ct = client.encrypt(package, &id, &data)?;
            std::fs::write(&args[4], ct).map_err(io)?;
        }
        Some("decrypt") if args.len() == 5 => {
            let key = load_key().map_err(|e| bad(&e))?;
            let client = SealClient::connect(SealConfig::testnet()).await?;
            let package = addr(&args[1]).map_err(|e| bad(&e))?;
            let list = client
                .shared_object(addr(&args[2]).map_err(|e| bad(&e))?)
                .await?;
            let ct = std::fs::read(&args[3]).map_err(io)?;
            let info = sui_seal_client::parse_encrypted_object(&ct)?;
            let session = client.session_key(package, 5, &key).await?;
            let approval =
                ApprovalTx::new(package).call("allowlist", "seal_approve", &info.id, vec![list])?;
            let pt = client.fetch_and_decrypt(&ct, &session, &approval).await?;
            std::fs::write(&args[4], pt).map_err(io)?;
        }
        _ => return Err(bad("usage: seal_cli servers|address|encrypt|decrypt ...")),
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
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
