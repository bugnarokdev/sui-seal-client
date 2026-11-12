// Shared helpers for the interop tests: sui CLI admin calls, key loading, assertions.
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { fromBase64, toHex } from '@mysten/sui/utils';

export function env(name) {
	const v = process.env[name];
	if (!v) throw new Error(`missing env ${name}`);
	return v;
}

export function loadKeypair(path) {
	const raw = readFileSync(path, 'utf8').trim();
	if (raw.startsWith('suiprivkey')) return Ed25519Keypair.fromSecretKey(raw);
	const bytes = fromBase64(raw);
	if (bytes.length !== 33 || bytes[0] !== 0) throw new Error(`${path}: not an Ed25519 keystore entry`);
	return Ed25519Keypair.fromSecretKey(bytes.slice(1));
}

// Admin transactions go through the sui CLI with an isolated client config.
export function sui(argv, what) {
	const out = execFileSync(
		env('SUI_BIN'),
		['client', '--client.config', env('SUI_CLIENT_CONFIG'), ...argv, '--gas-budget', '20000000', '--json'],
		{ encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
	);
	const json = JSON.parse(out.slice(out.indexOf('{')));
	if (json.effects?.status?.status !== 'success') throw new Error(`${what} failed: ${JSON.stringify(json.effects?.status)}`);
	return json;
}

export function suiCall(pkg, fn, args, module = 'allowlist') {
	return sui(
		['call', '--package', pkg, '--module', module, '--function', fn, ...(args.length ? ['--args', ...args] : [])],
		fn,
	);
}

export function createdId(res, suffix) {
	return res.objectChanges.find((c) => c.type === 'created' && c.objectType.endsWith(suffix)).objectId;
}

export function createAllowlist(pkg) {
	const res = suiCall(pkg, 'create_entry', []);
	const created = res.objectChanges.filter((c) => c.type === 'created');
	const list = created.find((c) => c.objectType.endsWith('::allowlist::Allowlist')).objectId;
	const cap = created.find((c) => c.objectType.endsWith('::allowlist::Cap')).objectId;
	return { list, cap, digest: res.digest };
}

// Key id: [list id][epoch u64 LE][16 random bytes]
export function keyId(list, epoch) {
	const e = Buffer.alloc(8);
	e.writeBigUInt64LE(BigInt(epoch));
	return list.replace(/^0x/, '') + e.toString('hex') + toHex(randomBytes(16));
}

export function rust(args, keyFile, extraEnv = {}) {
	const r = spawnSync(env('RUST_CLI'), args, {
		encoding: 'utf8',
		env: { ...process.env, ...(keyFile ? { SEAL_KEY_FILE: keyFile } : {}), ...extraEnv },
	});
	return { code: r.status, stderr: r.stderr, stdout: r.stdout };
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let passed = 0;
let failed = 0;
export function check(name, cond, detail = '') {
	if (cond) {
		passed++;
		console.log(`ok   ${name}`);
	} else {
		failed++;
		console.log(`FAIL ${name} ${detail}`);
	}
}
export function summary() {
	console.log(`\n${passed} passed, ${failed} failed`);
	return failed === 0 && passed > 0;
}
