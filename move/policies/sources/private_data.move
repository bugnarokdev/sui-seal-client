// SPDX-License-Identifier: MIT OR Apache-2.0

/// Owner policy for Seal: whoever owns a `PrivateData` object can decrypt the content
/// bound to it. BETA.
///
/// Adapted from the `private_data` pattern in MystenLabs/seal (Apache-2.0).
///
/// Key id format: [creator address (32 bytes)][nonce]
///
/// - Only the current owner can pass the object to `seal_approve` (enforced by the
///   Move VM during the key servers' dry run), so only the owner gets keys.
/// - Transferring the object moves access to the new owner for future requests. Keys
///   the previous owner already fetched keep working, as with every Seal policy.
/// - The creator address in the id stops anyone from minting an object that matches
///   someone else's id.
module seal_policies::private_data;

const ENoAccess: u64 = 1;

public struct PrivateData has key, store {
    id: UID,
    creator: address,
    nonce: vector<u8>,
    /// Optional payload (for example the encrypted object itself, or a Walrus blob id).
    data: vector<u8>,
}

public fun key_id(creator: address, nonce: vector<u8>): vector<u8> {
    let mut id = creator.to_bytes();
    id.append(nonce);
    id
}

public fun store(nonce: vector<u8>, data: vector<u8>, ctx: &mut TxContext): PrivateData {
    PrivateData { id: object::new(ctx), creator: ctx.sender(), nonce, data }
}

/// Creates a `PrivateData` and sends it to the sender.
entry fun store_entry(nonce: vector<u8>, data: vector<u8>, ctx: &mut TxContext) {
    transfer::public_transfer(store(nonce, data, ctx), ctx.sender());
}

public fun creator(p: &PrivateData): address { p.creator }

public fun nonce(p: &PrivateData): vector<u8> { p.nonce }

public fun data(p: &PrivateData): vector<u8> { p.data }

fun check_policy(id: &vector<u8>, p: &PrivateData): bool {
    key_id(p.creator, p.nonce) == *id
}

entry fun seal_approve(id: vector<u8>, p: &PrivateData) {
    assert!(check_policy(&id, p), ENoAccess);
}

#[test_only]
public fun destroy_for_testing(p: PrivateData) {
    let PrivateData { id, .. } = p;
    object::delete(id);
}

#[test]
fun matching_id_passes_others_fail() {
    let ctx = &mut tx_context::dummy();
    let p = store(b"nonce", b"payload", ctx);
    assert!(check_policy(&key_id(ctx.sender(), b"nonce"), &p), 0);
    assert!(!check_policy(&key_id(ctx.sender(), b"other"), &p), 1);
    assert!(!check_policy(&key_id(@0xBAD, b"nonce"), &p), 2);
    assert!(!check_policy(&b"nonce", &p), 3);
    assert!(p.data() == b"payload" && p.nonce() == b"nonce" && p.creator() == ctx.sender(), 4);
    destroy_for_testing(p);
}

#[test, expected_failure(abort_code = ENoAccess)]
fun seal_approve_aborts_on_wrong_id() {
    let ctx = &mut tx_context::dummy();
    let p = store(b"nonce", vector[], ctx);
    seal_approve(b"wrong", &p);
    destroy_for_testing(p);
}

#[test]
fun ownership_is_enforced_by_the_vm() {
    use sui::test_scenario;
    let (alice, bob) = (@0xA, @0xB);
    let mut sc = test_scenario::begin(alice);
    store_entry(b"n1", vector[], sc.ctx());
    sc.next_tx(alice);
    {
        let p = sc.take_from_sender<PrivateData>();
        seal_approve(key_id(alice, b"n1"), &p);
        transfer::public_transfer(p, bob);
    };
    sc.next_tx(bob);
    {
        // Bob owns it now and passes the same policy check.
        let p = sc.take_from_sender<PrivateData>();
        seal_approve(key_id(alice, b"n1"), &p);
        sc.return_to_sender(p);
    };
    sc.next_tx(alice);
    assert!(!sc.has_most_recent_for_sender<PrivateData>(), 0);
    sc.end();
}
