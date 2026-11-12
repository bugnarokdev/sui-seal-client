// SPDX-License-Identifier: MIT OR Apache-2.0

/// Revocable allowlist for Seal.
///
/// Adapted from the `whitelist` pattern in MystenLabs/seal (Apache-2.0), with the
/// "revocation version" variant described in its `seal_approve` notes: every removal
/// bumps `epoch`, and key ids carry the epoch they were encrypted under.
///
/// Key id format: [allowlist object id (32 bytes)][epoch (u64, BCS little-endian)][nonce]
///
/// - A member can fetch keys for any id whose epoch is <= the current epoch, so
///   remaining members keep reading older content after a removal.
/// - Nobody can fetch keys for a future epoch, so a member cannot pre-fetch keys for
///   content that will be written after their removal.
/// - Keys a removed member already fetched keep working for the ids they cover.
///   Removal only protects content encrypted under the new epoch.
module seal_allowlist::allowlist;

use sui::bcs;
use sui::table::{Self, Table};

const ENoAccess: u64 = 1;
const EInvalidCap: u64 = 2;
const EDuplicate: u64 = 3;
const ENotMember: u64 = 4;

public struct Allowlist has key {
    id: UID,
    epoch: u64,
    members: Table<address, bool>,
}

public struct Cap has key, store {
    id: UID,
    list_id: ID,
}

public fun create(ctx: &mut TxContext): (Cap, Allowlist) {
    let list = Allowlist { id: object::new(ctx), epoch: 0, members: table::new(ctx) };
    let cap = Cap { id: object::new(ctx), list_id: object::id(&list) };
    (cap, list)
}

public fun share(list: Allowlist) {
    transfer::share_object(list);
}

/// Creates a shared allowlist and sends its admin cap to the sender.
entry fun create_entry(ctx: &mut TxContext) {
    let (cap, list) = create(ctx);
    share(list);
    transfer::public_transfer(cap, ctx.sender());
}

public fun add(list: &mut Allowlist, cap: &Cap, account: address) {
    assert!(cap.list_id == object::id(list), EInvalidCap);
    assert!(!list.members.contains(account), EDuplicate);
    list.members.add(account, true);
}

/// Removes a member and bumps the epoch. Encryptors must read the new epoch and use it
/// in the key id of everything they encrypt from now on.
public fun remove(list: &mut Allowlist, cap: &Cap, account: address) {
    assert!(cap.list_id == object::id(list), EInvalidCap);
    assert!(list.members.contains(account), ENotMember);
    list.members.remove(account);
    list.epoch = list.epoch + 1;
}

/// Bumps the epoch without removing anyone (for example after a suspected key leak).
public fun rotate(list: &mut Allowlist, cap: &Cap) {
    assert!(cap.list_id == object::id(list), EInvalidCap);
    list.epoch = list.epoch + 1;
}

public fun epoch(list: &Allowlist): u64 { list.epoch }

public fun is_member(list: &Allowlist, account: address): bool { list.members.contains(account) }

/// The key id prefix for a given epoch: [list id][epoch as BCS u64].
public fun prefix(list: &Allowlist, epoch: u64): vector<u8> {
    let mut out = object::id(list).to_bytes();
    out.append(bcs::to_bytes(&epoch));
    out
}

fun check_policy(caller: address, id: &vector<u8>, list: &Allowlist): bool {
    let list_id = object::id(list).to_bytes();
    let n = list_id.length();
    // list id (32) + epoch (8) + at least one nonce byte.
    if (id.length() < n + 9) {
        return false
    };
    let mut i = 0;
    while (i < n) {
        if (list_id[i] != id[i]) {
            return false
        };
        i = i + 1;
    };
    let mut epoch: u64 = 0;
    let mut j = 0;
    while (j < 8) {
        epoch = epoch | ((id[n + j] as u64) << ((8 * j) as u8));
        j = j + 1;
    };
    if (epoch > list.epoch) {
        return false
    };
    list.members.contains(caller)
}

entry fun seal_approve(id: vector<u8>, list: &Allowlist, ctx: &TxContext) {
    assert!(check_policy(ctx.sender(), &id, list), ENoAccess);
}

#[test_only]
public fun destroy_for_testing(list: Allowlist, cap: Cap) {
    let Allowlist { id, epoch: _, members } = list;
    members.drop();
    object::delete(id);
    let Cap { id, .. } = cap;
    object::delete(id);
}

#[test_only]
fun key_id(list: &Allowlist, epoch: u64, nonce: u8): vector<u8> {
    let mut id = list.prefix(epoch);
    id.push_back(nonce);
    id
}

#[test]
fun member_passes_outsider_refused() {
    let ctx = &mut tx_context::dummy();
    let (cap, mut list) = create(ctx);
    list.add(&cap, @0xB);
    let id = key_id(&list, 0, 7);
    assert!(check_policy(@0xB, &id, &list), 0);
    assert!(!check_policy(@0xC, &id, &list), 1);
    destroy_for_testing(list, cap);
}

#[test]
fun wrong_prefix_or_short_id_refused() {
    let ctx = &mut tx_context::dummy();
    let (cap, mut list) = create(ctx);
    list.add(&cap, @0xB);
    let mut bad = key_id(&list, 0, 7);
    *&mut bad[0] = bad[0] ^ 1;
    assert!(!check_policy(@0xB, &bad, &list), 0);
    // Prefix without nonce is too short.
    let short = list.prefix(0);
    assert!(!check_policy(@0xB, &short, &list), 1);
    assert!(!check_policy(@0xB, &b"123", &list), 2);
    destroy_for_testing(list, cap);
}

#[test]
fun removal_bumps_epoch_and_drops_access() {
    let ctx = &mut tx_context::dummy();
    let (cap, mut list) = create(ctx);
    list.add(&cap, @0xA);
    list.add(&cap, @0xB);
    let old = key_id(&list, 0, 1);
    list.remove(&cap, @0xB);
    assert!(list.epoch() == 1, 0);
    let new = key_id(&list, 1, 1);
    // B is out for both old and new ids (it may still hold keys fetched before).
    assert!(!check_policy(@0xB, &old, &list), 1);
    assert!(!check_policy(@0xB, &new, &list), 2);
    // A keeps access to old and new content.
    assert!(check_policy(@0xA, &old, &list), 3);
    assert!(check_policy(@0xA, &new, &list), 4);
    destroy_for_testing(list, cap);
}

#[test]
fun future_epoch_refused() {
    let ctx = &mut tx_context::dummy();
    let (cap, mut list) = create(ctx);
    list.add(&cap, @0xB);
    let future = key_id(&list, 1, 1);
    assert!(!check_policy(@0xB, &future, &list), 0);
    list.rotate(&cap);
    assert!(check_policy(@0xB, &future, &list), 1);
    destroy_for_testing(list, cap);
}

#[test, expected_failure(abort_code = EInvalidCap)]
fun foreign_cap_rejected() {
    let ctx = &mut tx_context::dummy();
    let (cap1, list1) = create(ctx);
    let (cap2, mut list2) = create(ctx);
    list2.add(&cap1, @0xB);
    destroy_for_testing(list1, cap1);
    destroy_for_testing(list2, cap2);
}

#[test, expected_failure(abort_code = EDuplicate)]
fun duplicate_add_rejected() {
    let ctx = &mut tx_context::dummy();
    let (cap, mut list) = create(ctx);
    list.add(&cap, @0xB);
    list.add(&cap, @0xB);
    destroy_for_testing(list, cap);
}

#[test, expected_failure(abort_code = ENotMember)]
fun remove_non_member_rejected() {
    let ctx = &mut tx_context::dummy();
    let (cap, mut list) = create(ctx);
    list.remove(&cap, @0xB);
    destroy_for_testing(list, cap);
}
