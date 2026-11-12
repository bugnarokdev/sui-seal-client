// SPDX-License-Identifier: MIT OR Apache-2.0

/// Subscription policy for Seal: holders of an unexpired `Subscription` to a `Service`
/// can decrypt the content of that service. BETA.
///
/// Adapted from the `subscription` pattern in MystenLabs/seal (Apache-2.0), including
/// its package-wide versioning (`PackageVersion`).
///
/// Key id format: [service object id (32 bytes)][nonce (at least 1 byte)]
///
/// - A subscription costs `fee` MIST, paid to the service owner, and lasts `ttl_ms`.
/// - Subscriptions are owned objects: only their owner can pass them to `seal_approve`.
///   They can be transferred, never shared or wrapped.
/// - Keys fetched while subscribed keep working after expiry for the ids they cover.
module seal_policies::subscription;

use sui::clock::Clock;
use sui::coin::Coin;
use sui::sui::SUI;

const ENoAccess: u64 = 1;
const EInvalidFee: u64 = 2;
const EWrongVersion: u64 = 3;
const ENotOwner: u64 = 4;

const VERSION: u64 = 1;

/// Version against which `seal_approve` is evaluated (see Sui versioned shared objects).
public struct PackageVersion has key {
    id: UID,
    version: u64,
}

public struct PackageVersionCap has key {
    id: UID,
}

public struct Service has key {
    id: UID,
    fee: u64,
    ttl_ms: u64,
    owner: address,
}

public struct Subscription has key {
    id: UID,
    service_id: ID,
    created_at_ms: u64,
}

fun init(ctx: &mut TxContext) {
    transfer::share_object(PackageVersion { id: object::new(ctx), version: VERSION });
    transfer::transfer(PackageVersionCap { id: object::new(ctx) }, ctx.sender());
}

public fun create_service(fee: u64, ttl_ms: u64, ctx: &mut TxContext): Service {
    Service { id: object::new(ctx), fee, ttl_ms, owner: ctx.sender() }
}

/// Creates and shares a service.
entry fun create_service_entry(fee: u64, ttl_ms: u64, ctx: &mut TxContext) {
    transfer::share_object(create_service(fee, ttl_ms, ctx));
}

public fun subscribe(
    fee: Coin<SUI>,
    service: &Service,
    c: &Clock,
    ctx: &mut TxContext,
): Subscription {
    assert!(fee.value() == service.fee, EInvalidFee);
    transfer::public_transfer(fee, service.owner);
    Subscription {
        id: object::new(ctx),
        service_id: object::id(service),
        created_at_ms: c.timestamp_ms(),
    }
}

/// Pays `fee` and sends the new subscription to `to`.
entry fun subscribe_entry(
    fee: Coin<SUI>,
    service: &Service,
    c: &Clock,
    to: address,
    ctx: &mut TxContext,
) {
    transfer::transfer(subscribe(fee, service, c, ctx), to);
}

public fun transfer(sub: Subscription, to: address) {
    transfer::transfer(sub, to);
}

/// Changes the fee of future subscriptions (service owner only).
public fun set_fee(service: &mut Service, fee: u64, ctx: &TxContext) {
    assert!(service.owner == ctx.sender(), ENotOwner);
    service.fee = fee;
}

public fun fee(s: &Service): u64 { s.fee }

public fun ttl_ms(s: &Service): u64 { s.ttl_ms }

public fun expires_at_ms(sub: &Subscription, s: &Service): u64 { sub.created_at_ms + s.ttl_ms }

fun check_policy(
    id: &vector<u8>,
    pkg_version: &PackageVersion,
    sub: &Subscription,
    service: &Service,
    now_ms: u64,
): bool {
    assert!(pkg_version.version == VERSION, EWrongVersion);
    if (object::id(service) != sub.service_id) {
        return false
    };
    if (now_ms > sub.created_at_ms + service.ttl_ms) {
        return false
    };
    let prefix = object::id(service).to_bytes();
    let n = prefix.length();
    if (id.length() <= n) {
        return false
    };
    let mut i = 0;
    while (i < n) {
        if (prefix[i] != id[i]) {
            return false
        };
        i = i + 1;
    };
    true
}

entry fun seal_approve(
    id: vector<u8>,
    pkg_version: &PackageVersion,
    sub: &Subscription,
    service: &Service,
    c: &Clock,
) {
    assert!(check_policy(&id, pkg_version, sub, service, c.timestamp_ms()), ENoAccess);
}

#[test_only]
public fun versions_for_testing(ctx: &mut TxContext): (PackageVersion, PackageVersionCap) {
    (PackageVersion { id: object::new(ctx), version: VERSION }, PackageVersionCap { id: object::new(ctx) })
}

#[test_only]
public fun destroy_for_testing(
    v: PackageVersion,
    cap: PackageVersionCap,
    service: Service,
    sub: Subscription,
) {
    let PackageVersion { id, .. } = v;
    object::delete(id);
    let PackageVersionCap { id } = cap;
    object::delete(id);
    let Service { id, .. } = service;
    object::delete(id);
    let Subscription { id, .. } = sub;
    object::delete(id);
}

#[test_only]
fun key(service: &Service, nonce: u8): vector<u8> {
    let mut id = object::id(service).to_bytes();
    id.push_back(nonce);
    id
}

#[test]
fun active_subscription_passes_until_expiry() {
    use sui::coin;
    let ctx = &mut tx_context::dummy();
    let (v, cap) = versions_for_testing(ctx);
    let service = create_service(10, 500, ctx);
    // Created at the test clock's time, 0.
    let sub = subscribe(coin::mint_for_testing<SUI>(10, ctx), &service, sui::clock::borrow(), ctx);
    let id = key(&service, 1);
    assert!(check_policy(&id, &v, &sub, &service, 0), 0);
    assert!(check_policy(&id, &v, &sub, &service, 500), 1);
    assert!(!check_policy(&id, &v, &sub, &service, 501), 2);
    assert!(sub.expires_at_ms(&service) == 500, 3);
    seal_approve(id, &v, &sub, &service, sui::clock::borrow());
    destroy_for_testing(v, cap, service, sub);
}

#[test]
fun wrong_service_or_prefix_refused() {
    use sui::coin;
    let ctx = &mut tx_context::dummy();
    let c = sui::clock::borrow();
    let (v, cap) = versions_for_testing(ctx);
    let service = create_service(0, 1_000, ctx);
    let other = create_service(0, 1_000, ctx);
    let sub = subscribe(coin::mint_for_testing<SUI>(0, ctx), &service, c, ctx);
    // Subscription to `service` does not open `other`'s ids, even with `other` passed.
    assert!(!check_policy(&key(&other, 1), &v, &sub, &other, 0), 0);
    // Prefix alone (no nonce) and a tampered prefix are refused.
    assert!(!check_policy(&object::id(&service).to_bytes(), &v, &sub, &service, 0), 1);
    let mut bad = key(&service, 1);
    *&mut bad[3] = bad[3] ^ 0xff;
    assert!(!check_policy(&bad, &v, &sub, &service, 0), 2);
    let Service { id, .. } = other;
    object::delete(id);
    destroy_for_testing(v, cap, service, sub);
}

#[test, expected_failure(abort_code = EInvalidFee)]
fun wrong_fee_rejected() {
    use sui::coin;
    let ctx = &mut tx_context::dummy();
    let (v, cap) = versions_for_testing(ctx);
    let service = create_service(10, 1, ctx);
    let sub = subscribe(coin::mint_for_testing<SUI>(9, ctx), &service, sui::clock::borrow(), ctx);
    destroy_for_testing(v, cap, service, sub);
}

#[test, expected_failure(abort_code = ENoAccess)]
fun seal_approve_aborts_for_another_service() {
    use sui::coin;
    let ctx = &mut tx_context::dummy();
    let (v, cap) = versions_for_testing(ctx);
    let service = create_service(1, 100, ctx);
    let other = create_service(1, 100, ctx);
    let sub = subscribe(coin::mint_for_testing<SUI>(1, ctx), &service, sui::clock::borrow(), ctx);
    seal_approve(key(&other, 9), &v, &sub, &other, sui::clock::borrow());
    let Service { id, .. } = other;
    object::delete(id);
    destroy_for_testing(v, cap, service, sub);
}

#[test, expected_failure(abort_code = EWrongVersion)]
fun wrong_package_version_aborts() {
    use sui::coin;
    let ctx = &mut tx_context::dummy();
    let (mut v, cap) = versions_for_testing(ctx);
    v.version = 2;
    let service = create_service(0, 100, ctx);
    let sub = subscribe(coin::mint_for_testing<SUI>(0, ctx), &service, sui::clock::borrow(), ctx);
    check_policy(&key(&service, 1), &v, &sub, &service, 0);
    destroy_for_testing(v, cap, service, sub);
}

#[test, expected_failure(abort_code = ENotOwner)]
fun only_owner_sets_fee() {
    use sui::test_scenario;
    let mut sc = test_scenario::begin(@0xA);
    create_service_entry(5, 10, sc.ctx());
    sc.next_tx(@0xB);
    let mut s = sc.take_shared<Service>();
    s.set_fee(0, sc.ctx());
    test_scenario::return_shared(s);
    sc.end();
}

#[test]
fun fee_goes_to_owner_and_sub_to_recipient() {
    use sui::{coin, test_scenario};
    let (owner, payer, reader) = (@0xA, @0xB, @0xC);
    let mut sc = test_scenario::begin(owner);
    create_service_entry(7, 1_000, sc.ctx());
    sc.next_tx(payer);
    {
        let s = sc.take_shared<Service>();
        subscribe_entry(coin::mint_for_testing<SUI>(7, sc.ctx()), &s, sui::clock::borrow(), reader, sc.ctx());
        test_scenario::return_shared(s);
    };
    sc.next_tx(owner);
    {
        let paid = sc.take_from_sender<Coin<SUI>>();
        assert!(paid.value() == 7, 0);
        sc.return_to_sender(paid);
    };
    sc.next_tx(reader);
    assert!(sc.has_most_recent_for_sender<Subscription>(), 1);
    sc.end();
}
