/**
 * `extract_ips` is offered by BOTH servers — the npm one in `src/mcp/tools.ts`
 * and the Rust one in `crate/src/mcp/extract.rs`. One tool name, one schema,
 * two implementations, so the contract is identical output.
 *
 * `crate/fixtures/mcp-extract-ips.json` pins the cases somebody thought of.
 * This generates them: documents in every format carrying IPv4, IPv6 in every
 * spelling, CIDR blocks, MACs, the six refusals and the runs that must stay
 * silent — ports, clock times, versions, hashes — under keys that do and do not
 * name an address or a version, because the key is evidence. Broken JSON is
 * generated too, so the parser's own message and position are compared.
 *
 * Run: bun scripts/check-extraction-differential.ts
 *   IPS_LE_DIFFERENTIAL_SEED=<n>  reproduce a specific failure
 *   IPS_LE_DIFFERENTIAL_CASES=<n> how many documents (default 1500)
 *   IPS_LE_BIN=<path>             the Rust binary (default the release build)
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { TOOLS } from '../src/mcp/tools';

const ROOT = join(import.meta.dir, '..');
const BINARY = process.env.IPS_LE_BIN ?? join(ROOT, 'crate', 'target', 'release', 'ips-le');
const SEED = Number(process.env.IPS_LE_DIFFERENTIAL_SEED ?? 20261004);
const CASES = Number(process.env.IPS_LE_DIFFERENTIAL_CASES ?? 1500);

function seeded(seed: number): () => number {
	let state = seed >>> 0;
	return () => {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

function address(random: () => number): string {
	const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)] as T;
	const int = (n: number) => Math.floor(random() * n);
	const octet = () => String(pick([0, 1, 10, 127, 169, 172, 192, 198, 203, 224, 240, 255, int(256), int(256), int(300)]));
	const v4 = () => `${octet()}.${octet()}.${octet()}.${octet()}`;
	const group = () => pick(['0', '0000', 'db8', '2001', 'fe80', 'ff02', 'fc00', 'ffff', 'FFFF', int(65536).toString(16), int(65536).toString(16).padStart(4, '0'), '1', '00001', 'g1']);
	const v6 = () => {
		const groups = Array.from({ length: 8 }, group);
		const r = random();
		if (r < 0.3) return groups.join(':');
		if (r < 0.6) {
			const at = int(8);
			const length = 1 + int(8 - at);
			return `${groups.slice(0, at).join(':')}::${groups.slice(at + length).join(':')}`;
		}
		if (r < 0.75) return `::ffff:${v4()}`;
		if (r < 0.85) return `${groups.slice(0, 6).join(':')}:${v4()}`;
		return pick(['::', '::1', '1::', '::1:2:3:4:5:6:7', '1:2:3:4:5:6:7::', '1:::2', '1:2:3:4:5:6:7:8:9', '::ffff:01.2.3.4', ':1', '1:2']);
	};
	const mac = () => {
		const sep = pick([':', '-', ':', '.']);
		const groups = Array.from({ length: pick([6, 6, 6, 5, 7]) }, () => pick(['00', 'ff', 'FF', 'aa', '01', '0a', int(256).toString(16).padStart(2, '0'), 'a']));
		return random() < 0.1 ? groups.join(':').replace(/:/, '-') : groups.join(sep);
	};
	const roll = random();
	if (roll < 0.25) return v4();
	if (roll < 0.45) return random() < 0.5 ? v6() : `[${v6()}]:${int(65536)}`;
	if (roll < 0.6) return `${random() < 0.6 ? v4() : v6()}/${pick([0, 8, 16, 24, 32, 33, 48, 64, 128, 129, int(1000), 999])}`;
	if (roll < 0.7) return mac();
	if (roll < 0.8) return pick(['010.1.1.1', '0177.0.0.1', '10.0.1', '1.2.3', '2130706433', '3232235777', '99999999999', 'deadbeefcafe', 'DEADBEEFCAFE', '123456789012', '10.0.0.0/33', '1.2.3.4.5', '256.1.1.1']);
	if (roll < 0.9) return pick(['2026-08-12T10:30:00Z', '10:30:00', 'host:8080', '127.0.0.1:5432', '10.0.0.1-10.0.0.9', 'v1.2.3.4', 'x10.0.0.1', 'Ipv6Addr::from_str', '2026-08-12', 'a1b2c3d4e5f60718', '1/2', 'src/v1.2', '::f', 'e3b0c442']);
	return `${v4()}${pick(['.', '-', ':', '..', ',', ')'])}`;
}

const KEYS = ['ip', 'bind_ip', 'remote_addr', 'REMOTE_ADDR', 'host', 'gateway', 'subnet', 'cidr', 'version', 'ver', 'rev', 'app.version', 'name', 'timeout', 'peer', 'upstream', 'mac', 'note', 'café', 'url'];

type Builder = (pairs: ReadonlyArray<readonly [string, string]>, random: () => number) => string;

const FORMATS: ReadonlyArray<readonly [string, Builder]> = [
	['json', (p, r) => `{\n${p.map(([k, v], i) => (i % 3 === 2 && r() < 0.5 ? `  "list": ["${v}", {"${k}": "${v}"}]` : `  "${k}": ${/^\d+$/.test(v) && r() < 0.5 ? v : `"${v}"`}`)).join(',\n')}${r() < 0.2 ? ',' : ''}\n  // ${p[0]?.[1] ?? ''}\n}\n`],
	['json', (p, r) => {
		const good = `{${p.map(([k, v]) => `"${k}": "${v}"`).join(', ')}}`;
		const breakage = [`{"a": 1 "b": 2} ${p[0]?.[1]}`, `${good} extra`, `{"a": 'x'}`, `{a: "${p[0]?.[1]}"}`, `{"a": +1}`, `{"a": 0x1F}`, `{"a": "\\q"}`, `{"a": "\\ud800x"}`, `[1, 2,, 3]`, `{"a": [1 2]}`, `{"a": -}`, `{"a": 1.}`, `{"a": 1e}`, `/* open`, `{"a": tru}`, `{"a" 1}`, `{"a":}`, `[`, `{`, `"open`, `{"é😀": 1, "b": 01}`, `{"a": "\\udc00"}`, `{"a": "\\ud800\\u0041"}`, `{"a": "\\u12"}`, `{"a": #}`, `{"a": 1}}`, `]`, `,`, `:`, `{"a": "${p[0]?.[1]}" /* c */ , }`, good.slice(0, Math.max(1, Math.floor(r() * good.length)))];
		return breakage[Math.floor(r() * breakage.length)] as string;
	}],
	['yaml', (p, r) => `${p.map(([k, v], i) => (i % 2 ? `items:\n  - ${k}: ${v}\n    peer: ${v}  # ${v}\n  - ${v}` : `${k}: ${r() < 0.3 ? `"${v}"` : v}`)).join('\n')}\n---\n\u3000\u3000nested: ${p[0]?.[1] ?? ''}\n`],
	['toml', (p) => `[server]\n${p.map(([k, v]) => `${k.replace(/[.$]/g, '_')} = "${v}" # ${v}`).join('\n')}\nallow = [\n  "${p[0]?.[1] ?? ''}",\n]\n[[peers]]\nip = ${p[0]?.[1] ?? '1'}\n`],
	['ini', (p) => `; ${p[0]?.[1] ?? ''}\n[section]\n${p.map(([k, v], i) => (i % 2 ? `${k}: ${v}` : `${k} = ${v} ; note ${v}`)).join('\n')}\n`],
	['env', (p) => `${p.map(([k, v], i) => `${i % 2 ? 'export ' : ''}${k.replace(/[^A-Za-z0-9_]/g, '_').toUpperCase()}=${i % 3 ? `"${v} # x"` : `${v} # ${v}`}`).join('\n')}\n`],
	['csv', (p) => `${p.map(([k]) => k).join(',')}\n\n${p.map(([, v], i) => (i % 2 ? `"${v},${v}"` : v)).join(',')}\n`],
	['tsv', (p) => `${p.map(([k]) => k).join('\t')}\n${p.map(([, v]) => v).join('\t')}\n`],
	['log', (p, r) => p.map(([k, v], i) => (i % 3 === 0 ? `{"ts":"2026-08-12T10:30:00Z","${k}":"${v}","msg":"x"}${r() < 0.2 ? ' trailing' : ''}` : `2026-08-12T10:30:00Z level=info ${k.replace(/[^A-Za-z0-9_.-]/g, '')}=${r() < 0.5 ? `"${v} x"` : v} msg="from ${v}" dur=12ms`)).join('\n')],
	['text', (p) => p.map(([k, v]) => `The ${k} is ${v}, see (${v}).`).join('\n')],
];

interface Generated {
	readonly name: string;
	readonly args: Record<string, unknown>;
}

function generate(count: number, seed: number): Generated[] {
	const random = seeded(seed);
	const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)] as T;
	const out: Generated[] = [];
	for (let index = 0; index < count; index++) {
		const [format, build] = pick(FORMATS);
		const pairs = Array.from({ length: 1 + Math.floor(random() * 6) }, () => [pick(KEYS), address(random)] as const);
		let content = build(pairs, random);
		if (random() < 0.1) content = content.replace(/\n/g, '\r\n');
		if (random() < 0.1) content = `é😀 ${content}`;
		if (random() < 0.05) content = `\u00a0${content}\u2028`;
		const args: Record<string, unknown> = { content };
		const addressing = random();
		if (addressing < 0.5) args.format = format;
		else if (addressing < 0.75) args.filename = pick([`config.${format}`, 'access.log.1', '.env', 'notes.md', 'x.conf', 'data.jsonl']);
		if (random() < 0.1) args.kind = [pick(['ipv4', 'ipv6', 'cidr', 'mac'])];
		if (random() < 0.1) args.class = [pick(['private', 'global', 'loopback', 'documentation', 'reserved'])];
		if (random() < 0.08) args.maxResults = 1 + Math.floor(random() * 3);
		out.push({ name: `${index}:${format}`, args });
	}
	return out;
}

function canonical(value: unknown): string {
	if (value === null || typeof value !== 'object') return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
	const entries = Object.entries(value as Record<string, unknown>)
		.filter(([, item]) => item !== undefined)
		.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
}

async function fromNpm(documents: readonly Generated[]): Promise<string[]> {
	const tool = TOOLS.find((candidate) => candidate.name === 'extract_ips');
	if (!tool) throw new Error('the npm server no longer offers extract_ips');
	const answers: string[] = [];
	for (const document of documents) {
		try {
			answers.push(canonical(JSON.parse(JSON.stringify(await tool.handler(document.args)))));
		} catch (error) {
			answers.push(`error: ${error instanceof Error ? error.message : String(error)}`);
		}
	}
	return answers;
}

async function fromCrate(documents: readonly Generated[]): Promise<string[]> {
	if (!existsSync(BINARY)) throw new Error(`no binary at ${BINARY} — build it first: cd crate && cargo build --release`);
	const child = Bun.spawn([BINARY, 'mcp'], { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' });
	const draining = new Response(child.stdout).text();
	child.stdin.write(
		`${documents
			.map((document, id) =>
				JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'extract_ips', arguments: document.args } }),
			)
			.join('\n')}\n`,
	);
	child.stdin.end();
	const stdout = await draining;
	await child.exited;
	const answers: string[] = new Array(documents.length);
	for (const line of stdout.split('\n')) {
		if (line.trim().length === 0) continue;
		const response = JSON.parse(line) as {
			id: number;
			result?: { structuredContent?: unknown; isError?: boolean; content?: { text: string }[] };
			error?: unknown;
		};
		if (response.error !== undefined) throw new Error(`the crate server refused document ${response.id}: ${JSON.stringify(response.error)}`);
		answers[response.id] = response.result?.isError
			? `error: ${response.result.content?.[0]?.text}`
			: canonical(response.result?.structuredContent);
	}
	const missing = answers.findIndex((answer) => answer === undefined);
	if (missing !== -1) throw new Error(`the crate server never answered document ${missing}: ${await new Response(child.stderr).text()}`);
	return answers;
}

const documents = generate(CASES, SEED);
console.log(`differential: ${documents.length} generated documents, seed ${SEED}, binary ${BINARY.replace(ROOT, '.')}`);
const [npm, crate] = await Promise.all([fromNpm(documents), fromCrate(documents)]);
const failures: string[] = [];
let addresses = 0;
let refused = 0;
let unparsed = 0;
for (const [index, document] of documents.entries()) {
	const ours = npm[index] as string;
	if (!ours.startsWith('error:')) {
		const answer = JSON.parse(ours);
		addresses += answer.data.addresses.length;
		refused += answer.data.refused;
		unparsed += answer.diagnostics.length;
	}
	if (ours !== crate[index]) {
		failures.push(
			`the two extract_ips servers disagree on "${document.name}"\n  arguments: ${JSON.stringify(document.args).slice(0, 700)}\n  npm:   ${ours.slice(0, 900)}\n  crate: ${(crate[index] as string).slice(0, 900)}`,
		);
	}
}
console.log(`  ${addresses} findings, ${refused} of them refusals, ${unparsed} broken JSON documents, across every format`);
if (failures.length > 0) {
	console.error(`\nDIFFERENTIAL FAILED — ${failures.length} problem(s):\n`);
	for (const failure of failures.slice(0, 8)) console.error(`${failure}\n`);
	process.exit(1);
}
console.log('OK: both extract_ips servers gave identical answers on every document.');
