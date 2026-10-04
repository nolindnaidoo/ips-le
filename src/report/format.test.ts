import { describe, expect, it } from 'vitest';
import { find } from '../extract';
import { formatReport } from './format';

describe('the report', () => {
	it('says when a document holds no addresses', () => {
		expect(
			formatReport({
				file: 'a.md',
				format: 'unknown',
				rows: [],
				unparsed: undefined,
			}),
		).toContain('No addresses found.');
	});

	it('shows a MAC canonicalized, an IPv6 block without a broadcast, and the kind a refusal claims', () => {
		const rows = find('AA-BB-CC-DD-EE-FF 2001:db8::/32 10.0.0.0/33', 'unknown');
		const text = formatReport({
			file: 'a.txt',
			format: 'unknown',
			rows,
			unparsed: undefined,
		});
		expect(text).toContain(
			'`AA-BB-CC-DD-EE-FF` · → `aa:bb:cc:dd:ee:ff` · global',
		);
		expect(text).toContain(
			'`2001:db8::`–`2001:db8:ffff:ffff:ffff:ffff:ffff:ffff` · 79228162514264337593543950336 addresses',
		);
		expect(text).toContain('`10.0.0.0/33` · cidr');
		expect(text).toContain(
			'prefix_out_of_range: an IPv4 prefix is 0 to 32; 10.0.0.0/33 names 33.',
		);
	});

	it('leaves out the key of a root-level JSON value, which is the empty path', () => {
		const rows = find('"10.0.0.1"', 'json');
		expect(rows[0]?.key).toBe('');
		expect(
			formatReport({
				file: 'a.json',
				format: 'json',
				rows,
				unparsed: undefined,
			}),
		).not.toContain('key ``');
	});
});
