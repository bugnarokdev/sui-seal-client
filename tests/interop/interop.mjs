// Cross-compatibility between sui-seal-client (Rust) and @mysten/seal (TypeScript) on testnet.
//
// Env: SUI_BIN, SUI_CLIENT_CONFIG (admin = key A, funded), SEAL_PACKAGE (allowlist package),
//      SEAL_POLICIES, SEAL_POLICIES_VERSION (seal_policies package and its PackageVersion),
//      KEY_A, KEY_B, KEY_C (key files), RUST_CLI (target/.../examples/seal_cli).
//
// Sections 1-7 are the v0.1 suite (allowlist, independent servers). Sections 8-13 are
// v0.2 (BETA): committee, hybrid and weighted configurations, then the timelock,
// private_data and subscription policies.
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
const toHexRandom = (n) => randomBytes(n).toString('hex');
import { SealClient, SessionKey, EncryptedObject, InvalidParameterError, NoAccessError } from '@mysten/seal';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Transaction } from '@mysten/sui/transactions';
import { check, createAllowlist, createdId, env, keyId, loadKeypair, rust, sleep, sui, suiCall, summary } from './lib.mjs';

const SERVERS = [
	'0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75',
	'0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8',
];
const PKG = env('SEAL_PACKAGE');
const POL = env('SEAL_POLICIES');
const POL_VERSION = env('SEAL_POLICIES_VERSION');
const COMMITTEE = {
	objectId: '0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98',
	aggregatorUrl: 'https://seal-aggregator-testnet.mystenlabs.com',
	weight: 1,
};
// Same server sets as SEAL_SERVERS in examples/seal_cli.rs.
const CONFIGS = {
	committee: { servers: [COMMITTEE], threshold: 1 },
	hybrid: { servers: [COMMITTEE, { objectId: SERVERS[0], weight: 1 }], threshold: 2 },
	weighted: { servers: [{ objectId: SERVERS[0], weight: 2 }, { objectId: SERVERS[1], weight: 1 }], threshold: 2 },
};
const INDEX_WAIT_MS = 4000;
const dir = mkdtempSync(join(tmpdir(), 'seal-interop-'));
const keys = { A: env('KEY_A'), B: env('KEY_B'), C: env('KEY_C') };
const kp = Object.fromEntries(Object.entries(keys).map(([k, f]) => [k, loadKeypair(f)]));
const addr = Object.fromEntries(Object.entries(kp).map(([k, v]) => [k, v.toSuiAddress()]));

const grpc = new SuiGrpcClient({ network: 'testnet', baseUrl: 'https://fullnode.testnet.sui.io:443' });
const newSeal = () =>
	new SealClient({
		suiClient: grpc,
		serverConfigs: SERVERS.map((objectId) => ({ objectId, weight: 1 })),
		verifyKeyServers: true,
	});

async function tsDecrypt(seal, who, list, bytes) {
	const sessionKey = await SessionKey.create({
		address: addr[who], packageId: PKG, ttlMin: 5, signer: kp[who], suiClient: grpc,
	});
	const id = EncryptedObject.parse(bytes).id;
	const tx = new Transaction();
	tx.moveCall({
		target: `${PKG}::allowlist::seal_approve`,
		arguments: [tx.pure.vector('u8', Buffer.from(id, 'hex')), tx.object(list)],
	});
	const txBytes = await tx.build({ client: grpc, onlyTransactionKind: true });
	return seal.decrypt({ data: bytes, sessionKey, txBytes });
}

const sealFor = (mode) =>
	new SealClient({ suiClient: grpc, serverConfigs: CONFIGS[mode].servers, verifyKeyServers: true });

// Decrypts with any policy: `call(tx, idBytes)` adds the seal_approve call.
async function tsDecryptWith(seal, who, pkg, bytes, call) {
	const sessionKey = await SessionKey.create({
		address: addr[who], packageId: pkg, ttlMin: 5, signer: kp[who], suiClient: grpc,
	});
	const id = EncryptedObject.parse(bytes).id;
	const tx = new Transaction();
	call(tx, tx.pure.vector('u8', Buffer.from(id, 'hex')));
	const txBytes = await tx.build({ client: grpc, onlyTransactionKind: true });
	return seal.decrypt({ data: bytes, sessionKey, txBytes });
}

async function tsOutcome(promise) {
	try {
		await promise;
		return 'decrypted';
	} catch (e) {
		if (e instanceof NoAccessError) return 'NoAccess';
		// The TS SDK reports an owned object of someone else as InvalidParameter.
		if (e instanceof InvalidParameterError) return 'InvalidParameter';
		return `${e.constructor.name}: ${e.message}`;
	}
}

function rustEncryptAs(mode, pkg, id, plaintext) {
	const inp = join(dir, `pt-${randomBytes(4).toString('hex')}`);
	const out = inp + '.ct';
	writeFileSync(inp, plaintext);
	const r = rust(['encrypt', pkg, id, inp, out], null, { SEAL_SERVERS: mode });
	if (r.code !== 0) throw new Error(`rust encrypt (${mode}): ${r.stderr}`);
	return new Uint8Array(readFileSync(out));
}

function rustDecryptPolicy(mode, who, pkg, module, bytes, args) {
	const inp = join(dir, `in-${randomBytes(4).toString('hex')}`);
	const out = inp + '.out';
	writeFileSync(inp, bytes);
	const r = rust(['decrypt-policy', pkg, module, inp, out, ...args], keys[who], { SEAL_SERVERS: mode });
	return { code: r.code, stderr: r.stderr, plaintext: r.code === 0 ? readFileSync(out) : null };
}

const same = (a, b) => a !== null && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
const enc = (s) => new TextEncoder().encode(s);
const u64le = (n) => {
	const b = Buffer.alloc(8);
	b.writeBigUInt64LE(BigInt(n));
	return b.toString('hex');
};

async function tsDenied(seal, who, list, bytes) {
	try {
		await tsDecrypt(seal, who, list, bytes);
		return 'decrypted';
	} catch (e) {
		return e instanceof NoAccessError ? 'NoAccess' : `${e.constructor.name}: ${e.message}`;
	}
}

function rustEncrypt(id, plaintext) {
	const inp = join(dir, `pt-${id.slice(-8)}`);
	const out = join(dir, `ct-${id.slice(-8)}`);
	writeFileSync(inp, plaintext);
	const r = rust(['encrypt', PKG, id, inp, out]);
	if (r.code !== 0) throw new Error(`rust encrypt: ${r.stderr}`);
	return new Uint8Array(readFileSync(out));
}

function rustDecrypt(who, list, bytes) {
	const inp = join(dir, `in-${randomBytes(4).toString('hex')}`);
	const out = inp + '.out';
	writeFileSync(inp, bytes);
	const r = rust(['decrypt', PKG, list, inp, out], keys[who]);
	return { code: r.code, stderr: r.stderr, plaintext: r.code === 0 ? readFileSync(out) : null };
}

const sameHeader = (a, b) =>
	a.packageId === b.packageId && a.id === b.id && a.threshold === b.threshold &&
	JSON.stringify(a.services) === JSON.stringify(b.services);

async function main() {
	console.log(`package ${PKG}`);
	console.log(`A ${addr.A}\nB ${addr.B}\nC ${addr.C}`);
	const addrOut = rust(['address'], keys.B).stdout.trim();
	check('rust and ts derive the same address from the same key', addrOut === addr.B, addrOut);

	const { list, cap, digest } = createAllowlist(PKG);
	console.log(`allowlist ${list} cap ${cap} (tx ${digest})`);
	suiCall(PKG, 'add', [list, cap, addr.A]);
	suiCall(PKG, 'add', [list, cap, addr.B]);
	await sleep(INDEX_WAIT_MS);

	const seal = newSeal();
	const m1 = new TextEncoder().encode(`ts->rust ${Date.now()} ${'x'.repeat(1000)}`);
	const m2 = new TextEncoder().encode(`rust->ts ${Date.now()}`);

	// 1. TypeScript encrypts, Rust decrypts.
	const id1 = keyId(list, 0);
	const { encryptedObject: ct1 } = await seal.encrypt({ threshold: 2, packageId: PKG, id: id1, data: m1 });
	const r1 = rustDecrypt('B', list, ct1);
	check('TS encrypt -> Rust decrypt (member B)', r1.code === 0 && Buffer.compare(r1.plaintext, Buffer.from(m1)) === 0, r1.stderr);

	// 2. Rust encrypts, TypeScript decrypts.
	const id2 = keyId(list, 0);
	const ct2 = rustEncrypt(id2, m2);
	const h2 = EncryptedObject.parse(ct2);
	check('Rust ciphertext parses with the TS BCS schema', h2.id === id2 && h2.threshold === 2 && h2.packageId === PKG);
	check('Rust ciphertext lists both key servers in order', JSON.stringify(h2.services.map((s) => s[0])) === JSON.stringify(SERVERS));
	const sealB = newSeal();
	const p2 = await tsDecrypt(sealB, 'B', list, ct2);
	check('Rust encrypt -> TS decrypt (member B)', Buffer.compare(Buffer.from(p2), Buffer.from(m2)) === 0);

	// 3. Header parity on both sides.
	const ct1b = rustEncrypt(id1, m1);
	check('Rust and TS headers match for the same id', sameHeader(EncryptedObject.parse(ct1), EncryptedObject.parse(ct1b)));

	// 4. Outsider C is refused by both clients.
	const rc = rustDecrypt('C', list, ct1);
	check('Rust refuses outsider C (exit 3 = NoAccess)', rc.code === 3, `code ${rc.code} ${rc.stderr}`);
	check('TS refuses outsider C', (await tsDenied(newSeal(), 'C', list, ct2)) === 'NoAccess');

	// 5. Revocation: A removes B, epoch goes to 1.
	suiCall(PKG, 'remove', [list, cap, addr.B]);
	await sleep(INDEX_WAIT_MS);
	const id3 = keyId(list, 1);
	const m3 = new TextEncoder().encode(`after revocation ${Date.now()}`);
	const ct3 = rustEncrypt(id3, m3);
	const rb = rustDecrypt('B', list, ct3);
	check('after removal, Rust: B cannot read new-epoch content', rb.code === 3, `code ${rb.code} ${rb.stderr}`);
	check('after removal, TS: B cannot read new-epoch content', (await tsDenied(newSeal(), 'B', list, ct3)) === 'NoAccess');
	const rbo = rustDecrypt('B', list, ct1);
	check('after removal, B cannot fetch keys for old content either', rbo.code === 3, `code ${rbo.code}`);
	const pa3 = await tsDecrypt(newSeal(), 'A', list, ct3);
	check('after removal, TS: member A reads new-epoch content', Buffer.compare(Buffer.from(pa3), Buffer.from(m3)) === 0);
	const ra1 = rustDecrypt('A', list, ct1);
	check('after removal, Rust: member A still reads old TS content', ra1.code === 0 && Buffer.compare(ra1.plaintext, Buffer.from(m1)) === 0, ra1.stderr);

	// 6. Caveat, stated as a test: keys B fetched before removal still open old content.
	const cached = await tsDecrypt(sealB, 'B', list, ct2);
	check('CAVEAT: keys B fetched before removal still decrypt old content (TS cache)', Buffer.compare(Buffer.from(cached), Buffer.from(m2)) === 0);

	// 7. Nobody can pre-fetch keys for a future epoch.
	const ct5 = rustEncrypt(keyId(list, 5), new TextEncoder().encode('future'));
	const rf = rustDecrypt('A', list, ct5);
	check('future-epoch id refused even for member A', rf.code === 3, `code ${rf.code}`);

	// ---- v0.2 (BETA) ----------------------------------------------------------------
	// A is still a member (epoch 1), C is an outsider. Ids use the current epoch.

	// 8. Committee: one logical server behind the aggregator, threshold 1.
	{
		const id = keyId(list, 1);
		const m = enc(`committee ts->rust ${Date.now()}`);
		const { encryptedObject: ct } = await sealFor('committee').encrypt({ threshold: 1, packageId: PKG, id, data: m });
		const r = rustDecryptPolicy('committee', 'A', PKG, 'allowlist', ct, [list]);
		check('committee: TS encrypt -> Rust decrypt (member A)', r.code === 0 && same(r.plaintext, m), r.stderr);
		const m2 = enc(`committee rust->ts ${Date.now()}`);
		const ct2 = rustEncryptAs('committee', PKG, id, m2);
		check('committee: Rust and TS headers match', sameHeader(EncryptedObject.parse(ct), EncryptedObject.parse(ct2)));
		const p2 = await tsDecryptWith(sealFor('committee'), 'A', PKG, ct2, (tx, idArg) =>
			tx.moveCall({ target: `${PKG}::allowlist::seal_approve`, arguments: [idArg, tx.object(list)] }));
		check('committee: Rust encrypt -> TS decrypt (member A)', same(p2, m2));
		const rc = rustDecryptPolicy('committee', 'C', PKG, 'allowlist', ct, [list]);
		check('committee: Rust refuses outsider C', rc.code === 3, `code ${rc.code} ${rc.stderr}`);
		const tc = await tsOutcome(tsDecryptWith(sealFor('committee'), 'C', PKG, ct2, (tx, idArg) =>
			tx.moveCall({ target: `${PKG}::allowlist::seal_approve`, arguments: [idArg, tx.object(list)] })));
		check('committee: TS refuses outsider C', tc === 'NoAccess', tc);
	}

	// 9. Hybrid (committee + mysten-testnet-1, threshold 2) and weighted (2 + 1, threshold 2).
	for (const mode of ['hybrid', 'weighted']) {
		const id = keyId(list, 1);
		const m = enc(`${mode} ts->rust ${Date.now()}`);
		const { encryptedObject: ct } = await sealFor(mode).encrypt({ threshold: 2, packageId: PKG, id, data: m });
		const r = rustDecryptPolicy(mode, 'A', PKG, 'allowlist', ct, [list]);
		check(`${mode}: TS encrypt -> Rust decrypt`, r.code === 0 && same(r.plaintext, m), r.stderr);
		const m2 = enc(`${mode} rust->ts ${Date.now()}`);
		const ct2 = rustEncryptAs(mode, PKG, id, m2);
		check(`${mode}: Rust and TS share layouts match`, sameHeader(EncryptedObject.parse(ct), EncryptedObject.parse(ct2)));
		const p2 = await tsDecryptWith(sealFor(mode), 'A', PKG, ct2, (tx, idArg) =>
			tx.moveCall({ target: `${PKG}::allowlist::seal_approve`, arguments: [idArg, tx.object(list)] }));
		check(`${mode}: Rust encrypt -> TS decrypt`, same(p2, m2));
	}

	// 10. Timelock: open after the unlock time, for anyone (C); refused before.
	{
		const approve = (tx, idArg) => tx.moveCall({ target: `${POL}::timelock::seal_approve`, arguments: [idArg, tx.object('0x6')] });
		const past = u64le(Date.now() - 60_000) + toHexRandom(16);
		const m = enc(`timelock ts->rust ${Date.now()}`);
		const { encryptedObject: ct } = await newSeal().encrypt({ threshold: 2, packageId: POL, id: past, data: m });
		const r = rustDecryptPolicy('independent', 'C', POL, 'timelock', ct, ['clock']);
		check('timelock: TS encrypt -> Rust decrypt after unlock', r.code === 0 && same(r.plaintext, m), r.stderr);
		const m2 = enc(`timelock rust->ts ${Date.now()}`);
		const p2 = await tsDecryptWith(newSeal(), 'C', POL, rustEncryptAs('independent', POL, past, m2), approve);
		check('timelock: Rust encrypt -> TS decrypt after unlock', same(p2, m2));
		const future = u64le(Date.now() + 3_600_000) + toHexRandom(16);
		const ctf = rustEncryptAs('independent', POL, future, enc('later'));
		const rf = rustDecryptPolicy('independent', 'C', POL, 'timelock', ctf, ['clock']);
		check('timelock: Rust refuses before unlock', rf.code === 3, `code ${rf.code} ${rf.stderr}`);
		const tf = await tsOutcome(tsDecryptWith(newSeal(), 'C', POL, ctf, approve));
		check('timelock: TS refuses before unlock', tf === 'NoAccess', tf);
	}

	// 11. private_data: only the owner of the object gets keys.
	{
		const nonce = toHexRandom(16);
		const res = suiCall(POL, 'store_entry', [`0x${nonce}`, '0x'], 'private_data');
		const obj = createdId(res, '::private_data::PrivateData');
		console.log(`private data ${obj}`);
		await sleep(INDEX_WAIT_MS);
		const id = addr.A.replace(/^0x/, '') + nonce;
		const approve = (tx, idArg) => tx.moveCall({ target: `${POL}::private_data::seal_approve`, arguments: [idArg, tx.object(obj)] });
		const m = enc(`private ts->rust ${Date.now()}`);
		const { encryptedObject: ct } = await newSeal().encrypt({ threshold: 2, packageId: POL, id, data: m });
		const r = rustDecryptPolicy('independent', 'A', POL, 'private_data', ct, [obj]);
		check('private_data: TS encrypt -> Rust decrypt (owner A)', r.code === 0 && same(r.plaintext, m), r.stderr);
		const m2 = enc(`private rust->ts ${Date.now()}`);
		const p2 = await tsDecryptWith(newSeal(), 'A', POL, rustEncryptAs('independent', POL, id, m2), approve);
		check('private_data: Rust encrypt -> TS decrypt (owner A)', same(p2, m2));
		const rb = rustDecryptPolicy('independent', 'B', POL, 'private_data', ct, [obj]);
		check('private_data: Rust refuses non-owner B (exit 4 = wrong owner)', rb.code === 4, `code ${rb.code} ${rb.stderr}`);
		const tb = await tsOutcome(tsDecryptWith(newSeal(), 'B', POL, ct, approve));
		check('private_data: TS refuses non-owner B (InvalidParameter)', tb === 'InvalidParameter', tb);
	}

	// 12. subscription: A pays and gives the subscription to B; C has none.
	{
		const FEE = 1000;
		const res = suiCall(POL, 'create_service_entry', [String(FEE), String(600_000)], 'subscription');
		const service = createdId(res, '::subscription::Service');
		await sleep(INDEX_WAIT_MS);
		const subRes = sui([
			'ptb', '--split-coins', 'gas', `[${FEE}]`, '--assign', 'fee',
			'--move-call', `${POL}::subscription::subscribe_entry`, 'fee.0', `@${service}`, '@0x6', `@${addr.B}`,
		], 'subscribe');
		const sub = createdId(subRes, '::subscription::Subscription');
		console.log(`service ${service} subscription ${sub}`);
		await sleep(INDEX_WAIT_MS);
		const id = service.replace(/^0x/, '') + toHexRandom(16);
		const approve = (tx, idArg) => tx.moveCall({
			target: `${POL}::subscription::seal_approve`,
			arguments: [idArg, tx.object(POL_VERSION), tx.object(sub), tx.object(service), tx.object('0x6')],
		});
		const m = enc(`subscription ts->rust ${Date.now()}`);
		const { encryptedObject: ct } = await newSeal().encrypt({ threshold: 2, packageId: POL, id, data: m });
		const args = [POL_VERSION, sub, service, 'clock'];
		const r = rustDecryptPolicy('independent', 'B', POL, 'subscription', ct, args);
		check('subscription: TS encrypt -> Rust decrypt (subscriber B)', r.code === 0 && same(r.plaintext, m), r.stderr);
		const m2 = enc(`subscription rust->ts ${Date.now()}`);
		const p2 = await tsDecryptWith(newSeal(), 'B', POL, rustEncryptAs('independent', POL, id, m2), approve);
		check('subscription: Rust encrypt -> TS decrypt (subscriber B)', same(p2, m2));
		const rc = rustDecryptPolicy('independent', 'C', POL, 'subscription', ct, args);
		check('subscription: Rust refuses C without subscription', rc.code === 4, `code ${rc.code} ${rc.stderr}`);
		const tc = await tsOutcome(tsDecryptWith(newSeal(), 'C', POL, ct, approve));
		check('subscription: TS refuses C without subscription (InvalidParameter)', tc === 'InvalidParameter', tc);
	}

	console.log(`\ntestnet objects: allowlist ${list}, cap ${cap}`);
	if (!summary()) process.exit(1);
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
