// SPDX-License-Identifier: MIT OR Apache-2.0

/// Time-lock policy for Seal. BETA.
///
/// Adapted from the `tle` pattern in MystenLabs/seal (Apache-2.0). Difference: the key
/// id may carry a nonce after the time, so items unlocking at the same moment get
/// distinct keys.
///
/// Key id format: [unlock time (u64 ms, BCS little-endian)][optional nonce]
///
/// - Anyone can encrypt to a future time; no onchain object is needed.
/// - Anyone can fetch the key once the Sui clock has reached the unlock time.
/// - Before that, every request is refused, including the encryptor's.
module seal_policies::timelock;

use sui::bcs;
use sui::clock::Clock;

const ENoAccess: u64 = 1;

/// Key id for `unlock_ms` with a nonce (may be empty).
public fun key_id(unlock_ms: u64, nonce: vector<u8>): vector<u8> {
    let mut id = bcs::to_bytes(&unlock_ms);
    id.append(nonce);
    id
}

/// Unlock time encoded in a key id, if well formed.
public fun unlock_time(id: &vector<u8>): Option<u64> {
    if (id.length() < 8) {
        return option::none()
    };
    let mut t: u64 = 0;
    let mut i = 0;
    while (i < 8) {
        t = t | ((id[i] as u64) << ((8 * i) as u8));
        i = i + 1;
    };
    option::some(t)
}

fun check_policy(id: &vector<u8>, now_ms: u64): bool {
    let t = unlock_time(id);
    t.is_some() && now_ms >= t.destroy_some()
}

entry fun seal_approve(id: vector<u8>, c: &Clock) {
    assert!(check_policy(&id, c.timestamp_ms()), ENoAccess);
}

#[test]
fun locked_until_time_then_open() {
    let id = key_id(1_000, b"n");
    assert!(!check_policy(&id, 0), 0);
    assert!(!check_policy(&id, 999), 1);
    assert!(check_policy(&id, 1_000), 2);
    assert!(check_policy(&id, 5_000), 3);
}

#[test]
fun nonce_is_optional_and_ignored_by_policy() {
    assert!(check_policy(&key_id(7, vector[]), 7), 0);
    assert!(check_policy(&key_id(7, b"abc"), 7), 1);
    assert!(unlock_time(&key_id(0x0102030405060708, b"x")) == option::some(0x0102030405060708), 2);
}

#[test]
fun short_id_refused() {
    assert!(!check_policy(&b"1234567", 1 << 62), 0);
    assert!(unlock_time(&vector[]).is_none(), 1);
}

#[test]
fun seal_approve_with_clock() {
    // The test clock starts at 0.
    seal_approve(key_id(0, b"k"), sui::clock::borrow());
}

#[test, expected_failure(abort_code = ENoAccess)]
fun seal_approve_aborts_before_time() {
    seal_approve(key_id(1, b"k"), sui::clock::borrow());
}
