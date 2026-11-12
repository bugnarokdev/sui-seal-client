// Cross-compatibility between sui-seal-client (Rust) and @mysten/seal (TypeScript) on testnet.
//
// Env: SUI_BIN, SUI_CLIENT_CONFIG (admin = key A, funded), SEAL_PACKAGE (allowlist package),
//      KEY_A, KEY_B, KEY_C (key files), RUST_CLI (target/.../examples/seal_cli).
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { SealClient, SessionKey, EncryptedObject, NoAccessError } from '@mysten/seal';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Transaction } from '@mysten/sui/transactions';
import { check, createAllowlist, env, keyId, loadKeypair, rust, sleep, suiCall, summary } from './lib.mjs';

const SERVERS = [
	'0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75',
	'0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8',
];
const PKG = env('SEAL_PACKAGE');
const INDEX_WAIT_MS = 4000;
const dir = mkdtempSync(join(tmpdir(), 'seal-interop-'));
const keys = { A: env('KEY_A'), B: env('KEY_B'), C: env('KEY_C') };
const kp = Object.fromEntries(Object.entries(keys).map(([k, f]) => [k, loadKeypair(f)]));
const addr = Object.fromEntries(Object.entries(kp).map(([k, v]) => [k, v.toSuiAddress()]));

const sui = new SuiGrpcClient({ network: 'testnet', baseUrl: 'https://fullnode.testnet.sui.io:443' });
const newSeal = () =>
	new SealClient({
		suiClient: sui,
		serverConfigs: SERVERS.map((objectId) => ({ objectId, weight: 1 })),
		verifyKeyServers: true,
	});

async function tsDecrypt(seal, who, list, bytes) {
	const sessionKey = await SessionKey.create({
		address: addr[who], packageId: PKG, ttlMin: 5, signer: kp[who], suiClient: sui,
	});
	const id = EncryptedObject.parse(bytes).id;
	const tx = new Transaction();
	tx.moveCall({
		target: `${PKG}::allowlist::seal_approve`,
		arguments: [tx.pure.vector('u8', Buffer.from(id, 'hex')), tx.object(list)],
	});
	const txBytes = await tx.build({ client: sui, onlyTransactionKind: true });
	return seal.decrypt({ data: bytes, sessionKey, txBytes });
}

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

	console.log(`\ntestnet objects: allowlist ${list}, cap ${cap}`);
	if (!summary()) process.exit(1);
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
