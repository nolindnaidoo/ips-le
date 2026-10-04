import { canonical } from './format';
import {
	type Block,
	type Class,
	contextFromKey,
	type Kind,
	type Refusal,
	read,
} from './policy';
import {
	csvKeys,
	dotenvKeys,
	iniKeys,
	jsonKeys,
	jsonParseError,
	type KeySpan,
	logKeys,
	tomlKeys,
	yamlKeys,
} from './readers';
import { candidates } from './scanner';

export { FALLBACK_FORMAT, resolveFormat, SUPPORTED_FORMATS } from './format';
export {
	type Block,
	CLASSES,
	type Class,
	KINDS,
	type Kind,
	type Reason,
	type Refusal,
} from './policy';

/**
 * One finding: an address, or a refusal to call something an address — the
 * crate's `Found`, field for field and in its order. **Every field is always
 * present**, nulls included.
 */
export interface Found {
	readonly kind: Kind | null;
	readonly text: string;
	readonly line: number;
	/** 1-based, in UTF-16 code units, as an editor counts. */
	readonly column: number;
	readonly key: string | null;
	readonly normalized: string | null;
	readonly class: Class | null;
	readonly cidr: Block | null;
	readonly refused: Refusal | null;
}

function keys(text: string, format: string): KeySpan[] {
	switch (canonical(format)) {
		case 'json':
			return jsonKeys(text);
		case 'yaml':
			return yamlKeys(text);
		case 'toml':
			return tomlKeys(text);
		case 'ini':
			return iniKeys(text);
		case 'env':
			return dotenvKeys(text);
		case 'csv':
			return csvKeys(text, ',');
		case 'tsv':
			return csvKeys(text, '\t');
		case 'log':
			return logKeys(text);
		default:
			return [];
	}
}

function keyAt(spans: readonly KeySpan[], offset: number): string | null {
	let low = 0;
	let high = spans.length;
	while (low < high) {
		const mid = (low + high) >>> 1;
		if ((spans[mid] as KeySpan).start <= offset) low = mid + 1;
		else high = mid;
	}
	const span = spans[low - 1];
	return span !== undefined && offset < span.end ? span.path : null;
}

/** Every address and every refusal in a document, in document order. */
export function find(text: string, format: string): Found[] {
	const spans = keys(text, format);
	const lineStarts = [0];
	for (let at = text.indexOf('\n'); at !== -1; at = text.indexOf('\n', at + 1))
		lineStarts.push(at + 1);

	const out: Found[] = [];
	for (const candidate of candidates(text)) {
		const key = keyAt(spans, candidate.offset);
		const reading = read(candidate.text, contextFromKey(key));
		if (reading === undefined) continue;
		const line = lineOf(lineStarts, candidate.offset);
		const located = {
			text: candidate.text,
			line: line + 1,
			column: candidate.offset - (lineStarts[line] as number) + 1,
			key,
		};
		out.push(
			reading.reading === 'address'
				? {
						kind: reading.kind,
						...located,
						normalized: reading.normalized,
						class: reading.class,
						cidr: reading.block,
						refused: null,
					}
				: {
						kind: reading.kind,
						...located,
						normalized: null,
						class: null,
						cidr: null,
						refused: reading.refusal,
					},
		);
	}
	return out;
}

function lineOf(lineStarts: readonly number[], offset: number): number {
	let low = 0;
	let high = lineStarts.length;
	while (low < high) {
		const mid = (low + high) >>> 1;
		if ((lineStarts[mid] as number) <= offset) low = mid + 1;
		else high = mid;
	}
	return low - 1;
}

/** **A refusal survives every filter.** Empty means every value. */
export function survives(
	found: Found,
	kinds: readonly Kind[],
	classes: readonly Class[],
): boolean {
	if (found.refused !== null) return true;
	const kindOk =
		kinds.length === 0 || (found.kind !== null && kinds.includes(found.kind));
	const classOk =
		classes.length === 0 ||
		(found.class !== null && classes.includes(found.class));
	return kindOk && classOk;
}

/** Why a document yielded no key paths, when the reason is a parse failure. Only JSON can say. */
export function parseError(text: string, format: string): string | undefined {
	return canonical(format) === 'json' ? jsonParseError(text) : undefined;
}
