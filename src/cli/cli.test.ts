import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { parse } from './args';
import { serve } from './mcp';
import { run, summary } from './run';
import { exitCode, describe as line, scanContent } from './scan';
import { FLAGS, USAGE } from './usage';

const EVERYTHING = { format: null, kinds: [], classes: [] };

describe('usage', () => {
	it('names every flag the parser accepts, and no other', () => {
		const named = new Set(
			USAGE.split(/\s+/)
				.filter((word) => word.startsWith('--'))
				.map((word) => word.replace(/[,.:;)]+$/, ''))
				.filter((word) => word !== '--version' && word !== '--help'),
		);
		expect([...named].sort()).toEqual([...FLAGS].sort());
	});
});

describe('parse', () => {
	it('lowercases a kind or a class, and repeats them', () => {
		const cli = parse([
			'--kind',
			'IPv4',
			'--kind',
			'mac',
			'--class',
			'Global',
			'x',
		]);
		expect([cli.scan.kinds, cli.scan.classes]).toEqual([
			['ipv4', 'mac'],
			['global'],
		]);
	});

	it('refuses what the crate refuses, in its words', () => {
		expect(() => parse(['--kind', 'ip', 'x'])).toThrow(
			'ip is not a kind. Try ipv4, ipv6, cidr, mac.',
		);
		expect(() => parse(['--class'])).toThrow('--class needs a value');
		expect(() => parse(['--stdin', 'x'])).toThrow('takes no file arguments');
		expect(() => parse([])).toThrow('name a file or a directory to read');
	});
});

describe('scanContent', () => {
	it('keeps a refusal through every filter', () => {
		const report = scanContent('10.0.0.1 010.1.1.1', 'a', 'unknown', {
			format: null,
			kinds: ['mac'],
			classes: ['global'],
		});
		expect(report.summary).toEqual({ addresses: 0, refused: 1 });
	});

	it('words a refusal with the reason as Rust prints the variant', () => {
		const report = scanContent('010.1.1.1', 'a.txt', 'unknown', EVERYTHING);
		const [refused] = report.addresses;
		expect(refused && line(report, refused)).toMatch(
			/^a\.txt:1:1 {2}010\.1\.1\.1 {2}refused OctalHazard — /,
		);
	});
});

describe('exitCode', () => {
	it('follows grep, and fails a refusal only under --strict', () => {
		const found = scanContent('10.0.0.1', 'a', 'unknown', EVERYTHING);
		const refused = scanContent('010.1.1.1', 'b', 'unknown', EVERYTHING);
		expect(exitCode([found], false)).toBe(0);
		expect(exitCode([refused], false)).toBe(1);
		expect(exitCode([found, refused], true)).toBe(2);
		expect(summary([found, refused], 1)).toMatch(
			/1 address in 2 files\n1 refused\n1 binary file skipped\n$/,
		);
	});
});

describe('run', () => {
	it('reads stdin with the key paths of a forced format', async () => {
		const out: string[] = [];
		const code = await run(['--stdin', '--format', 'json'], {
			stdout: (text) => out.push(text),
			stderr: () => {},
			stdoutIsTerminal: false,
			readStdin: async () => Buffer.from('{"db": {"host": "2001:0db8::0001"}}'),
			version: '9.9.9',
		});
		expect(code).toBe(0);
		const report = JSON.parse(out.join(''));
		expect(report.addresses[0]).toMatchObject({
			key: 'db.host',
			normalized: '2001:db8::1',
		});
	});
});

describe('mcp: the crate framing', () => {
	// The protocol around the tools answers as the extension's server and
	// the crate's answer, so a client cannot tell the three apart by what it
	// sent. Replies are parsed: key order is the crate's concern, not this one.
	async function session(
		lines: readonly (string | Uint8Array)[],
	): Promise<{ status: number; replies: unknown[] }> {
		const written: string[] = [];
		const input = Readable.from(lines.map((item) => Buffer.from(item)));
		const status = await serve(
			input,
			(line) => {
				written.push(line);
				return undefined;
			},
			'9.9.9',
		);
		return { status, replies: written.map((line) => JSON.parse(line)) };
	}

	it("answers a malformed frame in the extension server's words and serves the next line", async () => {
		// A frame that is not JSON, or not UTF-8, was dropped without a word,
		// and a client lost every request it then waited on.
		const { status, replies } = await session([
			'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n',
			'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
			'not json\n',
			Uint8Array.from([0x7b, 0xff, 0x7d, 0x0a]),
			'   \n',
			'{"jsonrpc":"2.0","id":2,"method":"nope"}\n',
		]);
		expect(status).toBe(0);
		expect(replies).toEqual([
			{
				jsonrpc: '2.0',
				id: 1,
				result: {
					protocolVersion: '2025-06-18',
					capabilities: { tools: {} },
					serverInfo: { name: 'ips-le', version: '9.9.9' },
				},
			},
			{
				jsonrpc: '2.0',
				id: null,
				error: { code: -32700, message: 'Invalid JSON' },
			},
			{
				jsonrpc: '2.0',
				id: null,
				error: { code: -32700, message: 'Invalid JSON' },
			},
			{
				jsonrpc: '2.0',
				id: 2,
				error: { code: -32601, message: 'Unknown method: nope' },
			},
		]);
	});

	it('refuses malformed frames in the words the other two servers use, and a null id is a notification', async () => {
		const { replies } = await session([
			'{"id":1,"method":"ping"}\n',
			'{"jsonrpc":"1.0","id":2,"method":"ping"}\n',
			'[{"jsonrpc":"2.0","id":3,"method":"ping"}]\n',
			'{"jsonrpc":"2.0","id":null,"method":"ping"}\n',
			'{"jsonrpc":"2.0","id":4,"method":"notifications/initialized"}\n',
			'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":5}\n',
			'{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope"}}\n',
			'{"jsonrpc":"2.0","id":7,"method":"tools/call"}\n',
			'{"jsonrpc":"2.0","id":8,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}\n',
		]);
		const refused = {
			jsonrpc: '2.0',
			id: null,
			error: { code: -32700, message: 'Not a JSON-RPC 2.0 request' },
		};
		expect(replies).toEqual([
			refused,
			refused,
			refused,
			{
				jsonrpc: '2.0',
				id: 4,
				error: {
					code: -32601,
					message: 'Unknown method: notifications/initialized',
				},
			},
			{
				jsonrpc: '2.0',
				id: 5,
				error: { code: -32602, message: 'tools/call requires a string `name`' },
			},
			{
				jsonrpc: '2.0',
				id: 6,
				error: { code: -32602, message: 'Unknown tool: nope' },
			},
			{
				jsonrpc: '2.0',
				id: 7,
				error: { code: -32602, message: 'tools/call requires a string `name`' },
			},
			{
				jsonrpc: '2.0',
				id: 8,
				result: {
					capabilities: { tools: {} },
					protocolVersion: '2025-06-18',
					serverInfo: { name: 'ips-le', version: '9.9.9' },
				},
			},
		]);
	});

	it('waits for the pipe to drain before reading the next frame', async () => {
		const lines: string[] = [];
		let drained = 0;
		const input = Readable.from([
			Buffer.from(
				'{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n',
			),
		]);
		const write = (line: string) => {
			lines.push(line);
			return new Promise<void>((resolve) =>
				setTimeout(() => {
					drained += 1;
					resolve();
				}, 1),
			);
		};
		await serve(input, write, '9.9.9');
		expect(lines).toHaveLength(2);
		expect(drained).toBe(2);
	});
});
