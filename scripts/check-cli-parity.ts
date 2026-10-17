/**
 * Requires the npm command line to behave exactly as the Rust one does.
 *
 * Both install a command named `ips-le`, so a person or a CI step cannot tell
 * which one they have. This is a different contract from
 * `check-extraction-parity.ts`, which holds the extension's engine equal to
 * the crate's: here the whole terminal surface is compared, the walk, the
 * addresses and refusals, the key paths, the exit codes, stdout and stderr
 * byte for byte, and every reply `ips-le mcp` writes, byte for byte too.
 *
 * Every case runs both binaries over one generated tree with stdout piped,
 * which is how a script sees them. `--version` is compared too: every surface
 * carries one version, and two binaries of one name disagreeing about it is
 * the first thing a person comparing them would see.
 *
 * Run: bun run build:cli && cargo build --locked --manifest-path crate/Cargo.toml
 *      bun scripts/check-cli-parity.ts
 */
import { spawnSync } from 'node:child_process';
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	rmdirSync,
	symlinkSync,
	unlinkSync,
	writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const RUST =
	process.env.IPS_LE_BIN ??
	join(
		ROOT,
		'crate',
		'target',
		'debug',
		`ips-le${process.platform === 'win32' ? '.exe' : ''}`,
	);
const NODE_CLI = join(ROOT, 'cli', 'cli.js');
/**
 * Node, by name, not `process.execPath`: this script runs under Bun, and the
 * package is run by Node wherever `npx` runs it. Bun's errors are not Node's.
 */
const NODE = process.env.NODE_BIN ?? 'node';

interface Case {
	readonly args: readonly string[];
	readonly stdin?: string | Buffer;
}

interface Outcome {
	readonly status: number | null;
	readonly stdout: string;
	readonly stderr: string;
}

for (const [label, path] of [
	['the Rust binary', RUST],
	['cli/cli.js', NODE_CLI],
] as const) {
	if (!existsSync(path)) {
		console.error(`FAIL: ${label} is missing at ${path}. Build it first.`);
		process.exit(1);
	}
}

const tree = mkdtempSync(join(tmpdir(), 'ips-le-cli-parity-'));
const created: string[] = [];
const dirs: string[] = [tree];

function dir(relative: string): void {
	mkdirSync(join(tree, relative));
	dirs.push(join(tree, relative));
}

function file(relative: string, content: string | Buffer): void {
	writeFileSync(join(tree, relative), content);
	created.push(join(tree, relative));
}

function link(relative: string, target: string): void {
	// Windows grants symlinks to administrators and developer mode only, and
	// both binaries then see the same tree without the link.
	try {
		symlinkSync(target, join(tree, relative));
	} catch {
		return;
	}
	created.push(join(tree, relative));
}

const canLock = process.platform !== 'win32' && process.getuid?.() !== 0;

const IPS = [
	'v4 10.0.0.5, 8.8.8.8, 127.0.0.1, 169.254.1.1, 100.64.0.1, 224.0.0.1',
	'more 255.255.255.255 240.0.0.1 192.0.2.1 0.0.0.0',
	'v6 2001:0db8::0001 ::1 fe80::1 fc00::1 ff02::1 2606:4700::1111 ::ffff:10.0.0.1',
	'cidr 192.168.0.0/24 10.0.0.0/8 2001:db8::/32 10.0.0.1/33 2001:db8::/129',
	'mac 00:1A:2B:3C:4D:5E 00-1a-2b-3c-4d-5e 001a.2b3c.4d5e 001A2B3C4D5E',
	'refusals 010.1.1.1 1.2.3 2130706433 300.1.1.1 1.2.3.4.5',
	'ünïcödé then 9.9.9.9 and é 1.1.1.1',
	'',
].join('\n');

function build(): void {
	dir('repo');
	dir('repo/.git');
	file('repo/.gitignore', 'ignored.txt\nbuild/\n');
	file('repo/.ignore', 'dot-ignored.txt\n');
	file('repo/ips.txt', IPS);
	file('repo/config.json', '{"db": {"host": "10.0.0.5", "hosts": ["2001:0db8::0001", "010.1.1.1"]}, "version": "1.2.3"}\n');
	file('repo/broken.json', '{"db": {"host": "10.0.0.5",\n');
	file('repo/config.yaml', 'db:\n  host: 10.0.0.5\n  hosts:\n    - fe80::1\n');
	file('repo/settings.toml', '[db]\nhost = "10.0.0.5"\nport = 2130706433\n');
	file('repo/setup.ini', '[a]\nhost = 192.168.1.1\n');
	file('repo/.env', 'HOST=10.0.0.5\nMAC=00:1A:2B:3C:4D:5E\n');
	file('repo/app.env', 'HOST=8.8.8.8\n');
	file('repo/rows.csv', 'name,ip\nalpha,10.0.0.1\n');
	file('repo/rows.tsv', 'name\tip\nbeta\t2001:db8::1\n');
	file('repo/access.log', '2026-10-17T00:00:00Z client=203.0.113.9 status=200\n');
	file('repo/main.tf', 'cidr_block = "10.0.0.0/16"\n');
	file('repo/bom.json', '\uFEFF{"ip": "10.0.0.1"}\n');
	file('repo/crlf.txt', '10.0.0.1\r\nnext 10.0.0.2\r\n');
	file('repo/clean.md', 'no addresses here\n');
	file('repo/empty.txt', '');
	file('repo/latin1.txt', Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x0a]));
	file('repo/binary.dat', Buffer.from([0x00, 0x01, 0x02, 0x03]));
	// ripgrep's sniff reads 8 KiB: a NUL inside it is binary, one past it is not.
	file('repo/late-nul.dat', Buffer.concat([Buffer.alloc(100, 0x61), Buffer.from([0])]));
	file('repo/past-sniff.txt', Buffer.concat([Buffer.from('10.0.0.1 '), Buffer.alloc(8192, 0x61), Buffer.from([0])]));
	file('repo/ünïcödé.txt', '10.0.0.1\n');
	file('repo/ignored.txt', '10.0.0.1\n');
	file('repo/dot-ignored.txt', '10.0.0.1\n');
	file('repo/.hidden.txt', '10.0.0.1\n');
	dir('repo/build');
	file('repo/build/out.txt', '10.0.0.1\n');
	dir('repo/nested');
	file('repo/nested/.gitignore', 'local.txt\n');
	file('repo/nested/local.txt', '10.0.0.1\n');
	file('repo/nested/kept.txt', '8.8.4.4\n');
	link('repo/linked.txt', 'ips.txt');
	link('repo/linked-dir', 'nested');
	dir('none');
	file('none/plain.txt', 'nothing to see\n');
	dir('refusals');
	file('refusals/only.txt', '010.1.1.1\n');
	dir('many');
	file('many/big.txt', `${IPS}`.repeat(800));
	if (canLock) {
		file('repo/locked.txt', 'x\n');
		chmodSync(join(tree, 'repo', 'locked.txt'), 0o000);
		dir('closed');
		dir('closed/shut');
		file('closed/shut/inside.txt', 'x\n');
		dir('closed/.hidden-shut');
		file('closed/.hidden-shut/inside.txt', 'x\n');
		dir('closed/b-shut.json');
		file('closed/b-shut.json/inside.txt', 'x\n');
		file('closed/open.txt', '10.0.0.1\n');
		chmodSync(join(tree, 'closed', 'shut'), 0o000);
		chmodSync(join(tree, 'closed', '.hidden-shut'), 0o000);
		chmodSync(join(tree, 'closed', 'b-shut.json'), 0o000);
		dir('sealed');
		file('sealed/inside.txt', 'x\n');
		chmodSync(join(tree, 'sealed'), 0o000);
	}
}

function cases(): readonly Case[] {
	const repo = join(tree, 'repo');
	const at = (name: string) => join(repo, name);
	const corpus = join(ROOT, 'crate', 'fixtures', 'documents');
	return [
		{ args: ['--help'] },
		{ args: ['-h'] },
		{ args: ['--version'] },
		{ args: ['-V'] },
		{ args: [repo, '--help'] },
		{ args: [] },
		{ args: [repo] },
		{ args: [`${repo}/`] },
		{ args: ['repo'] },
		{ args: ['./repo/nested/'] },
		{ args: [repo, '--hidden'] },
		{ args: [repo, '--no-ignore'] },
		{ args: [repo, '--hidden', '--no-ignore'] },
		{ args: [repo, '--strict'] },
		{ args: [repo, '--kind', 'ipv6'] },
		{ args: [repo, '--kind', 'IPv4', '--kind', 'mac'] },
		{ args: [repo, '--class', 'private', '--class', 'Global'] },
		{ args: [repo, '--kind', 'cidr', '--class', 'documentation'] },
		{ args: [repo, '--kind', 'ip'] },
		{ args: [repo, '--class', 'public'] },
		{ args: [repo, '--kind', 'ipv4,ipv6'] },
		{ args: [repo, '--kind'] },
		{ args: [repo, '--class'] },
		{ args: [repo, '--format', 'json'] },
		{ args: [repo, '--format', '.YAML'] },
		{ args: [repo, '--format', 'handwriting'] },
		{ args: [repo, '--format'] },
		{ args: [repo, '--nope'] },
		{ args: [repo, '-'] },
		{ args: [at('ips.txt')] },
		{ args: [at('config.json'), at('broken.json'), at('config.yaml'), at('settings.toml')] },
		{ args: [at('setup.ini'), at('.env'), at('app.env'), at('rows.csv'), at('rows.tsv')] },
		{ args: [at('access.log'), at('main.tf'), at('bom.json'), at('crlf.txt')] },
		{ args: [at('clean.md'), at('empty.txt'), at('latin1.txt'), at('binary.dat')] },
		{ args: [at('latin1.txt'), '--strict'] },
		{ args: [at('binary.dat'), '--strict'] },
		{ args: [at('ünïcödé.txt')] },
		{ args: [at('ignored.txt'), at('.hidden.txt'), at('dot-ignored.txt')] },
		{ args: [at('ips.txt'), at('ips.txt')] },
		{ args: [at('nested'), at('nested/kept.txt')] },
		{ args: [at('linked.txt')] },
		{ args: [at('linked-dir')] },
		{ args: [join(tree, 'none')] },
		{ args: [join(tree, 'refusals')] },
		{ args: [join(tree, 'refusals'), '--strict'] },
		{ args: [join(tree, 'refusals'), '--kind', 'mac'] },
		{ args: [join(tree, 'many')] },
		...(canLock
			? [
					{ args: [join(tree, 'closed')] },
					{ args: [join(tree, 'closed'), '--hidden'] },
					{ args: [join(tree, 'closed'), '--strict'] },
					{ args: [join(tree, 'closed'), '--format', 'yaml'] },
					{ args: [join(tree, 'closed'), join(tree, 'closed')] },
					{ args: [join(tree, 'sealed')] },
					{ args: [join(tree, 'closed', 'shut')] },
					{ args: [at('locked.txt')] },
					{ args: [at('locked.txt'), '--strict'] },
				]
			: []),
		{ args: [join(tree, 'missing')] },
		{ args: [repo, join(tree, 'missing')] },
		{ args: [join(tree, 'mïssing')] },
		{ args: ['--stdin'] },
		{ args: ['--stdin', repo] },
		{ args: ['--stdin'], stdin: IPS },
		{ args: ['--stdin', '--kind', 'mac'], stdin: IPS },
		{ args: ['--stdin', '--format', 'json'], stdin: '{"a": {"b": "10.0.0.1"}}' },
		{ args: ['--stdin', '--format', 'json'], stdin: '{"a": ' },
		{ args: ['--stdin'], stdin: `\uFEFF${IPS}` },
		{ args: ['--stdin'], stdin: Buffer.from([0x63, 0xe9, 0x0a]) },
		{ args: ['--stdin'], stdin: Buffer.from([0x61, 0x00, 0x62]) },
		{ args: ['--stdin'], stdin: '' },
		{ args: [corpus] },
		{ args: [corpus, '--hidden', '--no-ignore', '--strict'] },
	];
}

function run(command: readonly string[], testCase: Case): Outcome {
	const [program, ...rest] = command as [string, ...string[]];
	const result = spawnSync(program, [...rest, ...testCase.args], {
		input: testCase.stdin ?? '',
		cwd: tree,
		maxBuffer: 256 * 1024 * 1024,
	});
	return {
		status: result.status,
		stdout: result.stdout.toString('utf8'),
		stderr: result.stderr.toString('utf8'),
	};
}

function compareCli(): string[] {
	const failures: string[] = [];
	for (const testCase of cases()) {
		const rust = run([RUST], testCase);
		const node = run([NODE, NODE_CLI], testCase);
		for (const field of ['status', 'stdout', 'stderr'] as const) {
			if (rust[field] === node[field]) continue;
			failures.push(
				`ips-le ${testCase.args.join(' ')}\n  ${field} differs\n` +
					describeDifference(String(rust[field]), String(node[field])),
			);
		}
	}
	return failures;
}

function mcpLines(): readonly string[] {
	const repo = join(tree, 'repo');
	let id = 0;
	const request = (method: string, params?: unknown) =>
		JSON.stringify({
			jsonrpc: '2.0',
			id: ++id,
			method,
			...(params === undefined ? {} : { params }),
		});
	const call = (name: string, args?: unknown) =>
		request('tools/call', args === undefined ? { name } : { name, arguments: args });
	const extract = (args: Record<string, unknown>) => call('extract_ips', args);
	const scan = (args: Record<string, unknown>) => call('ips_le_scan', args);
	return [
		request('initialize', { protocolVersion: '2024-11-05' }),
		JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
		request('tools/list'),
		request('ping'),
		request('resources/list'),
		request('tools/call'),
		request('tools/call', { arguments: {} }),
		request('tools/call', null),
		call('no_such_tool', {}),
		JSON.stringify({ jsonrpc: '2.0', id: 'tëxt-id', method: 'ping' }),
		JSON.stringify({ jsonrpc: '2.0', id: null, method: 'ping' }),
		JSON.stringify({ id: 77, method: 'ping' }),
		JSON.stringify({ jsonrpc: '2.0', id: 78 }),
		'not json',
		'',
		'   ',
		'[1, 2]',
		`${request('ping')}\r`,
		extract({ content: IPS }),
		extract({ content: IPS, kind: ['ipv6'], maxResults: 2 }),
		extract({ content: IPS, class: ['PRIVATE'] }),
		extract({ content: IPS, kind: ['ip'] }),
		extract({ content: IPS, kind: 'ipv4' }),
		extract({ content: '{"a": "10.0.0.1"}', format: 'json' }),
		extract({ content: 7 }),
		extract({}),
		call('extract_ips', null),
		scan({ path: repo }),
		scan({ paths: [repo, join(tree, 'none')], kind: ['mac'] }),
		scan({ path: repo, hidden: true, ignored: true }),
		scan({ path: repo, format: 'json' }),
		scan({ path: repo, format: 7 }),
		scan({ path: repo, class: ['nope'] }),
		scan({ path: repo, kind: 'ipv4' }),
		scan({ path: join(repo, 'ips.txt'), hidden: 'yes' }),
		scan({ path: join(tree, 'refusals') }),
		scan({ paths: [] }),
		scan({ paths: [3] }),
		scan({ path: 3, paths: [join(repo, 'clean.md')] }),
		scan({}),
		scan({ path: join(tree, 'missing') }),
		...(canLock
			? [scan({ path: join(tree, 'closed'), hidden: true }), scan({ path: join(tree, 'sealed') })]
			: []),
	];
}

function serve(command: readonly string[], input: string | Buffer): Outcome {
	const [program, ...rest] = command as [string, ...string[]];
	const result = spawnSync(program, [...rest, 'mcp'], { input, cwd: tree });
	return {
		status: result.status,
		stdout: result.stdout.toString('utf8'),
		stderr: result.stderr.toString('utf8'),
	};
}

function compareMcp(): string[] {
	const failures: string[] = [];
	const lines = mcpLines();
	const sessions: readonly (readonly [string, string | Buffer])[] = [
		['the whole session', `${lines.join('\n')}\n`],
		['a last line with no newline', lines[3] as string],
		[
			'a line that is not UTF-8',
			Buffer.concat([
				Buffer.from(`${lines[3]}\n`),
				Buffer.from([0x7b, 0xff, 0x7d, 0x0a]),
				Buffer.from(`${lines[3]}\n`),
			]),
		],
	];
	for (const [label, input] of sessions) {
		const rust = serve([RUST], input);
		const node = serve([NODE, NODE_CLI], input);
		for (const field of ['status', 'stdout', 'stderr'] as const) {
			if (rust[field] === node[field]) continue;
			failures.push(
				`ips-le mcp, ${label}\n  ${field} differs\n` +
					describeDifference(String(rust[field]), String(node[field])),
			);
		}
	}
	return failures;
}

/** The first differing line, which is the one worth reading in a long output. */
function describeDifference(rust: string, node: string): string {
	const left = rust.split('\n');
	const right = node.split('\n');
	const index = left.findIndex((line, at) => line !== right[at]);
	const at = index === -1 ? left.length : index;
	const clip = (line: string | undefined) =>
		line === undefined || line.length <= 2000 ? line : `${line.slice(0, 2000)}…`;
	return `  line ${at + 1}\n  rust: ${clip(left[at])}\n  node: ${clip(right[at])}`;
}

function cleanUp(): void {
	const unlock: readonly (readonly [string, number])[] = [
		[join(tree, 'repo', 'locked.txt'), 0o600],
		[join(tree, 'closed', 'shut'), 0o700],
		[join(tree, 'closed', '.hidden-shut'), 0o700],
		[join(tree, 'closed', 'b-shut.json'), 0o700],
		[join(tree, 'sealed'), 0o700],
	];
	for (const [path, mode] of unlock) if (existsSync(path)) chmodSync(path, mode);
	for (const path of created) unlinkSync(path);
	for (const path of [...dirs].reverse()) rmdirSync(path);
}

build();
let failures: string[];
try {
	failures = [...compareCli(), ...compareMcp()];
} finally {
	cleanUp();
}

if (failures.length > 0) {
	console.error(failures.join('\n\n'));
	console.error(`\nFAIL: ${failures.length} difference(s) between the npm and Rust CLIs`);
	process.exit(1);
}
console.log(
	`OK: the npm CLI matches the Rust CLI on ${cases().length} commands and ${mcpLines().length} MCP lines`,
);
