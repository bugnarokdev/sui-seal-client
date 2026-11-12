//! Key id and approval helpers for the Move policies shipped in `move/`. BETA (v0.2).
//!
//! Each submodule mirrors one Move module: how to build key ids, and how to add the
//! matching `seal_approve` call to an [`ApprovalTx`]. The Move code is the source of
//! truth; these helpers only encode its id formats.
//!
//! | Module | Package | Who gets keys |
//! |---|---|---|
//! | [`allowlist`] | `move/allowlist` | current members, for ids up to the current epoch |
//! | [`timelock`] | `move/policies` | anyone, once the Sui clock reaches the unlock time |
//! | [`private_data`] | `move/policies` | the owner of a `PrivateData` object |
//! | [`subscription`] | `move/policies` | holders of an unexpired `Subscription` |

use sui_sdk_types::Address;

use crate::approval::{ApprovalArg, ApprovalTx};
use crate::error::{Error, Result};

/// Nonce length used by the `random_*` helpers.
pub const NONCE_LEN: usize = 16;

fn random_nonce() -> [u8; NONCE_LEN] {
    rand::random()
}

/// The Sui clock (`0x6`), a shared object created at genesis.
pub fn clock() -> ApprovalArg {
    ApprovalArg::Shared {
        id: Address::from_static("0x6"),
        initial_shared_version: 1,
    }
}

/// Revocable allowlist with epochs (`move/allowlist`).
pub mod allowlist {
    use super::*;

    pub const MODULE: &str = "allowlist";

    /// `[list id][epoch u64 LE][nonce]`. `nonce` must not be empty.
    pub fn key_id(list: &Address, epoch: u64, nonce: &[u8]) -> Result<Vec<u8>> {
        if nonce.is_empty() {
            return Err(Error::InvalidInput("allowlist key id needs a nonce".into()));
        }
        let mut id = list.as_bytes().to_vec();
        id.extend_from_slice(&epoch.to_le_bytes());
        id.extend_from_slice(nonce);
        Ok(id)
    }

    /// Key id with a random 16-byte nonce.
    pub fn random_key_id(list: &Address, epoch: u64) -> Vec<u8> {
        key_id(list, epoch, &random_nonce()).expect("non-empty nonce")
    }

    /// `(list id, epoch)` of a key id, if well formed.
    pub fn parse_key_id(id: &[u8]) -> Option<(Address, u64)> {
        if id.len() < 32 + 8 + 1 {
            return None;
        }
        let list = Address::new(id[..32].try_into().ok()?);
        let epoch = u64::from_le_bytes(id[32..40].try_into().ok()?);
        Some((list, epoch))
    }

    /// Adds `allowlist::seal_approve(id, list)`. `list` comes from
    /// [`crate::SealClient::shared_object`].
    pub fn approve(tx: ApprovalTx, id: &[u8], list: ApprovalArg) -> Result<ApprovalTx> {
        tx.call(MODULE, "seal_approve", id, vec![list])
    }
}

/// Time-lock (`move/policies`, module `timelock`).
pub mod timelock {
    use super::*;

    pub const MODULE: &str = "timelock";

    /// `[unlock time u64 LE (ms)][nonce]`; the nonce may be empty.
    pub fn key_id(unlock_ms: u64, nonce: &[u8]) -> Vec<u8> {
        let mut id = unlock_ms.to_le_bytes().to_vec();
        id.extend_from_slice(nonce);
        id
    }

    /// Key id with a random 16-byte nonce.
    pub fn random_key_id(unlock_ms: u64) -> Vec<u8> {
        key_id(unlock_ms, &random_nonce())
    }

    /// Unlock time of a key id, if well formed.
    pub fn unlock_time(id: &[u8]) -> Option<u64> {
        Some(u64::from_le_bytes(id.get(..8)?.try_into().ok()?))
    }

    /// Adds `timelock::seal_approve(id, clock)`.
    pub fn approve(tx: ApprovalTx, id: &[u8]) -> Result<ApprovalTx> {
        tx.call(MODULE, "seal_approve", id, vec![clock()])
    }
}

/// Owner-only data (`move/policies`, module `private_data`).
pub mod private_data {
    use super::*;

    pub const MODULE: &str = "private_data";

    /// `[creator address][nonce]`. Must match the `PrivateData` object's fields.
    pub fn key_id(creator: &Address, nonce: &[u8]) -> Vec<u8> {
        let mut id = creator.as_bytes().to_vec();
        id.extend_from_slice(nonce);
        id
    }

    /// Adds `private_data::seal_approve(id, object)`. `object` comes from
    /// [`crate::SealClient::object_arg`] and must be owned by the session address.
    pub fn approve(tx: ApprovalTx, id: &[u8], object: ApprovalArg) -> Result<ApprovalTx> {
        tx.call(MODULE, "seal_approve", id, vec![object])
    }
}

/// Paid, time-limited subscriptions (`move/policies`, module `subscription`).
pub mod subscription {
    use super::*;

    pub const MODULE: &str = "subscription";

    /// `[service id][nonce]`. `nonce` must not be empty.
    pub fn key_id(service: &Address, nonce: &[u8]) -> Result<Vec<u8>> {
        if nonce.is_empty() {
            return Err(Error::InvalidInput(
                "subscription key id needs a nonce".into(),
            ));
        }
        let mut id = service.as_bytes().to_vec();
        id.extend_from_slice(nonce);
        Ok(id)
    }

    /// Key id with a random 16-byte nonce.
    pub fn random_key_id(service: &Address) -> Vec<u8> {
        key_id(service, &random_nonce()).expect("non-empty nonce")
    }

    /// Adds `subscription::seal_approve(id, package_version, subscription, service, clock)`.
    /// `package_version` and `service` are shared objects, `subscription` an owned one
    /// (see [`crate::SealClient::object_arg`]).
    pub fn approve(
        tx: ApprovalTx,
        id: &[u8],
        package_version: ApprovalArg,
        subscription: ApprovalArg,
        service: ApprovalArg,
    ) -> Result<ApprovalTx> {
        tx.call(
            MODULE,
            "seal_approve",
            id,
            vec![package_version, subscription, service, clock()],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sui_sdk_types::{Command, Input};

    #[test]
    fn allowlist_ids_round_trip() {
        let list = Address::new([0xAA; 32]);
        let id = allowlist::key_id(&list, 3, b"n").unwrap();
        assert_eq!(id.len(), 41);
        assert_eq!(allowlist::parse_key_id(&id), Some((list, 3)));
        assert_eq!(&id[32..40], &3u64.to_le_bytes());
        assert!(allowlist::key_id(&list, 0, b"").is_err());
        assert_eq!(allowlist::parse_key_id(&id[..40]), None);
        let r = allowlist::random_key_id(&list, 1);
        assert_eq!(r.len(), 32 + 8 + NONCE_LEN);
        assert_ne!(r, allowlist::random_key_id(&list, 1));
    }

    #[test]
    fn timelock_ids_match_move_encoding() {
        // Same bytes as `bcs::to_bytes(&t)` + nonce in timelock.move.
        let id = timelock::key_id(0x0102030405060708, b"x");
        assert_eq!(id, [8, 7, 6, 5, 4, 3, 2, 1, b'x']);
        assert_eq!(timelock::unlock_time(&id), Some(0x0102030405060708));
        assert_eq!(timelock::unlock_time(&id[..7]), None);
        assert_eq!(timelock::key_id(5, b"").len(), 8);
        assert_eq!(timelock::random_key_id(5).len(), 8 + NONCE_LEN);
    }

    #[test]
    fn subscription_and_private_ids() {
        let s = Address::new([1; 32]);
        assert!(subscription::key_id(&s, b"").is_err());
        assert_eq!(subscription::key_id(&s, b"n").unwrap()[..32], *s.as_bytes());
        let c = Address::new([2; 32]);
        assert_eq!(private_data::key_id(&c, b"nn").len(), 34);
    }

    #[test]
    fn approvals_carry_the_clock_and_objects() {
        let pkg = Address::new([9; 32]);
        let tx = timelock::approve(ApprovalTx::new(pkg), &timelock::key_id(1, b"")).unwrap();
        let ptb: sui_sdk_types::ProgrammableTransaction = bcs::from_bytes(&tx.to_bcs()).unwrap();
        assert!(
            matches!(&ptb.inputs[1], Input::Shared(s) if s.object_id() == Address::from_static("0x6"))
        );
        let Command::MoveCall(call) = &ptb.commands[0] else {
            panic!()
        };
        assert_eq!(call.module.as_str(), "timelock");
        assert_eq!(call.arguments.len(), 2);

        let shared = |b| ApprovalArg::Shared {
            id: Address::new([b; 32]),
            initial_shared_version: 3,
        };
        let tx = subscription::approve(
            ApprovalTx::new(pkg),
            &subscription::key_id(&Address::new([4; 32]), b"n").unwrap(),
            shared(1),
            shared(2),
            shared(4),
        )
        .unwrap();
        let ptb: sui_sdk_types::ProgrammableTransaction = bcs::from_bytes(&tx.to_bcs()).unwrap();
        let Command::MoveCall(call) = &ptb.commands[0] else {
            panic!()
        };
        assert_eq!(call.arguments.len(), 5);
        assert_eq!(ptb.inputs.len(), 5);
    }
}
