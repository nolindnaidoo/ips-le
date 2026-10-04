import { describe, expect, it } from 'vitest';
import { find, parseError, resolveFormat, survives } from './index';
import { formatIpv6, parseIpv4, parseIpv6 } from './net';

/** Every expectation here was read back from the crate's server, not written from the Rust. */
describe('positions and key paths', () => {
	it('counts columns in UTF-16 code units, as an editor does', () => {
		expect(find('é😀 10.0.0.1', 'unknown')[0]?.column).toBe(5);
	});

	it('measures YAML indentation in bytes, as the crate does', () => {
		// Two U+3000 are six bytes, deeper than the two-space `ip`.
		expect(
			find('a:\n  ip: x\n\u3000\u3000host: 10.0.0.1\n', 'yaml')[0]?.key,
		).toBe('a.ip.host');
	});

	it('finds an address inside a URL and a bracketed IPv6 with a port', () => {
		const found = find(
			'postgres://10.0.0.5:5432/app [2001:db8::1]:8080',
			'unknown',
		);
		expect(found.map((one) => [one.text, one.column, one.class])).toEqual([
			['10.0.0.5', 12, 'private'],
			['2001:db8::1', 31, 'documentation'],
		]);
	});
});

describe('Rust std, transcribed', () => {
	it('prints an IPv4-mapped address with its dotted tail, and classifies it as IPv4', () => {
		const [one] = find('peer ::FFFF:7f00:1 up', 'unknown');
		expect([one?.normalized, one?.class]).toEqual([
			'::ffff:127.0.0.1',
			'loopback',
		]);
	});

	it('refuses a leading zero in IPv4 and in an embedded IPv4, and more than three digits', () => {
		expect(parseIpv4('01.2.3.4')).toBeUndefined();
		expect(parseIpv4('1.2.3.0004')).toBeUndefined();
		expect(parseIpv6('::ffff:01.2.3.4')).toBeUndefined();
		expect(parseIpv6('1:::2')).toBeUndefined();
	});

	it('compresses the first longest zero run, and never a single zero group', () => {
		expect(formatIpv6(parseIpv6('1:0:0:2:0:0:0:3') as number[])).toBe(
			'1:0:0:2::3',
		);
		expect(formatIpv6(parseIpv6('1:0:2:3:4:5:6:7') as number[])).toBe(
			'1:0:2:3:4:5:6:7',
		);
	});

	it('counts the 2^128 addresses in ::/0 exactly', () => {
		expect(find('route ::/0 via x', 'unknown')[0]?.cidr?.hosts).toBe(
			'340282366920938463463374607431768211456',
		);
	});
});

describe('context decides the conditional refusals', () => {
	it('is silent on a dotted triple under a version key and refuses it elsewhere', () => {
		const found = find('version: 10.0.1\nnote: 10.0.1\n', 'yaml');
		expect(found.map((one) => [one.key, one.refused?.reason])).toEqual([
			['note', 'ambiguous_version'],
		]);
	});

	it('refuses a bare integer only under a key naming an address', () => {
		const found = find('bind_ip = 2130706433\ntimeout = 2130706433\n', 'ini');
		expect(found.map((one) => [one.key, one.refused?.reason])).toEqual([
			['bind_ip', 'integer_form'],
		]);
		expect(found[0]?.refused?.detail).toContain('127.0.0.1');
	});
});

describe('a refusal survives every filter', () => {
	it('keeps refusals that name a kind under a kind filter that excludes it', () => {
		const found = find('8.8.8.8 010.1.1.1 10.0.0.0/33', 'unknown').filter(
			(one) => survives(one, ['ipv6'], []),
		);
		expect(found.map((one) => one.refused?.reason)).toEqual([
			'octal_hazard',
			'prefix_out_of_range',
		]);
	});
});

describe('JSON', () => {
	it('reports a broken document in the parser’s own words, and still finds its addresses', () => {
		const text = '{"a": 1 "b": 2} 10.0.0.5';
		expect(parseError(text, 'json')).toBe(
			'could not read this as JSON, so no key paths are reported: Expected comma on line 1 column 8',
		);
		expect(find(text, 'json').map((one) => [one.text, one.key])).toEqual([
			['10.0.0.5', null],
		]);
	});

	it('says nothing about an empty document', () => {
		expect(parseError('  \n', 'json')).toBeUndefined();
	});
});

describe('format resolution', () => {
	it('reads a rotated log as a log, and log.txt as text', () => {
		expect(resolveFormat(undefined, 'access.log.1')).toBe('log');
		expect(resolveFormat(undefined, 'log.txt')).toBe('unknown');
		expect(resolveFormat(' .YML', undefined)).toBe('yaml');
		expect(resolveFormat('handwriting', '.env')).toBe('env');
	});
});
