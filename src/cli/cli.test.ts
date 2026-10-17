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

describe('mcp', () => {
	it('drops a frame that is not UTF-8 and answers the next', async () => {
		const written: string[] = [];
		const ping = `${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping' })}\n`;
		await serve(
			Readable.from([
				Buffer.concat([
					Buffer.from([0x7b, 0xff, 0x7d, 0x0a]),
					Buffer.from(ping),
				]),
			]),
			(reply) => written.push(reply),
			'9.9.9',
		);
		expect(written).toEqual(['{"id":2,"jsonrpc":"2.0","result":{}}\n']);
	});
});
