import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { find } from './index';
import { contextFromKey, read } from './policy';

/**
 * The crate's `fixtures/extraction.json`, run through the port: the same four
 * sections `crate/src/extract/corpus.rs` checks.
 */
const FIXTURES = join(__dirname, '..', '..', 'crate', 'fixtures');
const corpus = JSON.parse(
	readFileSync(join(FIXTURES, 'extraction.json'), 'utf8'),
);
const none = { version: false, address: false };

describe('the shared corpus', () => {
	it('normalizes every pinned form per RFC 5952', () => {
		for (const c of corpus.normalization) {
			const reading = read(c.input, none);
			expect(
				reading?.reading === 'address' && reading.normalized,
				`${c.input}: ${c.why}`,
			).toBe(c.expected);
		}
	});

	it('classifies every pinned address', () => {
		for (const c of corpus.classification) {
			const reading = read(c.input, none);
			expect(
				reading?.reading === 'address'
					? [reading.kind, reading.class]
					: reading,
				c.input,
			).toEqual([c.kind, c.class]);
		}
	});

	it('refuses every ambiguous case by name', () => {
		for (const c of corpus.ambiguity) {
			const reading = read(c.input, contextFromKey(c.key ?? null));
			expect(
				reading?.reading === 'refused' ? reading.refusal.reason : reading,
				c.input,
			).toBe(c.reason);
		}
	});

	for (const document of corpus.documents) {
		it(`reproduces ${document.name}`, () => {
			const found = find(
				readFileSync(join(FIXTURES, 'documents', document.file), 'utf8'),
				document.format,
			).map((one) => ({
				text: one.text,
				line: one.line,
				column: one.column,
				key: one.key,
				normalized: one.normalized,
				class: one.class,
				refused: one.refused?.reason ?? null,
			}));
			expect(found).toEqual(document.expected);
		});
	}
});
