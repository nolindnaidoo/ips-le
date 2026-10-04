import { JsoncError, type JsonValue, parseJsonc } from './jsonc';
import { byteLength, isWhitespace, trim, trimStart } from './text';

/**
 * Key paths, by format — the crate's `json.rs`, `yaml.rs`, `toml.rs`,
 * `ini.rs`, `dotenv.rs`, `csv.rs`, `log.rs` and the helpers in `mod.rs`.
 *
 * A key is a locator, not a claim, but it is also evidence: the policy reads
 * it to decide whether `10.0.1` is a version and whether `2130706433` is in an
 * address field. Offsets are UTF-16 indices; the one width compared across
 * lines, YAML's indentation, is measured in UTF-8 bytes as the crate does.
 */

export interface KeySpan {
	readonly start: number;
	readonly end: number;
	readonly path: string;
}

/** Every line with its starting offset, a trailing `\n`/`\r` run removed. */
function lines(text: string): Array<[number, string]> {
	const out: Array<[number, string]> = [];
	let offset = 0;
	while (offset < text.length) {
		const newline = text.indexOf('\n', offset);
		const end = newline === -1 ? text.length : newline + 1;
		out.push([offset, text.slice(offset, end).replace(/[\n\r]+$/, '')]);
		offset = end;
	}
	return out;
}

/** The part of a line before its comment, quote-aware. */
function stripComment(
	line: string,
	markers: string,
	afterSpace: boolean,
): string {
	let quote: string | undefined;
	let previous = ' ';
	let index = 0;
	for (const character of line) {
		if (quote !== undefined && character === quote) quote = undefined;
		else if (quote === undefined && (character === '"' || character === "'"))
			quote = character;
		else if (
			quote === undefined &&
			markers.includes(character) &&
			(!afterSpace || isWhitespace(previous))
		) {
			return line.slice(0, index);
		}
		previous = character;
		index += character.length;
	}
	return line;
}

const dotted = (prefix: string, key: string) =>
	prefix === '' ? key : `${prefix}.${key}`;

// ---------------------------------------------------------------- JSON

export function jsonKeys(text: string): KeySpan[] {
	let root: JsonValue | undefined;
	try {
		root = parseJsonc(text);
	} catch (error) {
		if (error instanceof JsoncError) return [];
		throw error;
	}
	const spans: KeySpan[] = [];
	if (root !== undefined) visit(root, [], spans);
	return spans;
}

/** Why a JSON document yields no key paths, when it does not parse. */
export function jsonParseError(text: string): string | undefined {
	if (trim(text) === '') return undefined;
	try {
		parseJsonc(text);
		return undefined;
	} catch (error) {
		if (!(error instanceof JsoncError)) throw error;
		return `could not read this as JSON, so no key paths are reported: ${error.message}`;
	}
}

function visit(value: JsonValue, path: string[], spans: KeySpan[]): void {
	if (value.type === 'array') {
		for (const [index, element] of value.elements.entries())
			visit(element, [...path, `[${index}]`], spans);
	} else if (value.type === 'object') {
		for (const property of value.properties)
			visit(property.value, [...path, property.name], spans);
	} else {
		spans.push({ start: value.start, end: value.end, path: path.join('.') });
	}
}

// ---------------------------------------------------------------- YAML

export function yamlKeys(text: string): KeySpan[] {
	const stack: Array<[number, string]> = [];
	const spans: KeySpan[] = [];
	const pathOf = () => stack.map(([, key]) => key).join('.');

	for (const [offset, line] of lines(text)) {
		const content = stripComment(line, '#', true);
		const trimmed = trimStart(content);
		if (trimmed === '' || trimmed.startsWith('#') || trimmed === '-') continue;
		if (trimmed.startsWith('---') || trimmed.startsWith('...')) {
			stack.length = 0;
			continue;
		}
		const indentUnits = content.length - trimmed.length;
		const entry = trimmed.startsWith('- ')
			? trimStart(trimmed.slice(2))
			: trimmed;
		const columnUnits = indentUnits + (trimmed.length - entry.length);
		const depth = byteLength(content.slice(0, columnUnits));

		while (stack.length > 0 && (stack.at(-1) as [number, string])[0] >= depth)
			stack.pop();

		const separator = keySeparator(entry);
		if (separator === undefined) {
			if (stack.length > 0)
				spans.push({
					start: offset + columnUnits,
					end: offset + content.length,
					path: pathOf(),
				});
			continue;
		}
		const key = trim(entry.slice(0, separator)).replace(/^["']+|["']+$/g, '');
		stack.push([depth, key]);

		const valueAt = columnUnits + separator + 1;
		if (trim(content.slice(Math.min(valueAt, content.length))) === '') continue;
		spans.push({
			start: offset + valueAt,
			end: offset + content.length,
			path: pathOf(),
		});
	}
	return spans;
}

/** The `:` followed by a space or the end of the line. */
function keySeparator(entry: string): number | undefined {
	for (let index = 0; index < entry.length; index++) {
		if (entry.charAt(index) !== ':') continue;
		if (index + 1 === entry.length || entry.charAt(index + 1) === ' ')
			return index;
	}
	return undefined;
}

// ---------------------------------------------------------------- TOML

export function tomlKeys(text: string): KeySpan[] {
	let table = '';
	let open: [string, number] | undefined;
	const spans: KeySpan[] = [];

	for (const [offset, line] of lines(text)) {
		const content = stripComment(line, '#', false);
		const trimmed = trim(content);

		if (open !== undefined) {
			const [path, depth] = open;
			open = undefined;
			spans.push({ start: offset, end: offset + content.length, path });
			const next = depth + bracketDepth(content);
			if (next > 0) open = [path, next];
			continue;
		}
		if (trimmed === '') continue;
		const header = tableHeader(trimmed);
		if (header !== undefined) {
			table = header;
			continue;
		}
		const separator = content.indexOf('=');
		if (separator === -1) continue;
		const key = trim(content.slice(0, separator));
		if (key === '') continue;
		const path = dotted(table, key);
		spans.push({
			start: offset + separator + 1,
			end: offset + content.length,
			path,
		});
		const depth = bracketDepth(content.slice(separator));
		if (depth > 0) open = [path, depth];
	}
	return spans;
}

function tableHeader(trimmed: string): string | undefined {
	if (!trimmed.startsWith('[')) return undefined;
	const afterOpen = trimmed.slice(1);
	if (!afterOpen.endsWith(']')) return undefined;
	const inner = afterOpen.slice(0, -1);
	if (inner.startsWith('[')) {
		const rest = inner.slice(1);
		if (rest.endsWith(']')) return trim(rest.slice(0, -1));
	}
	return trim(inner);
}

function bracketDepth(text: string): number {
	let depth = 0;
	for (const character of text) {
		if (character === '[') depth++;
		else if (character === ']') depth--;
	}
	return depth;
}

// ----------------------------------------------------------------- INI

export function iniKeys(text: string): KeySpan[] {
	let section = '';
	const spans: KeySpan[] = [];
	for (const [offset, line] of lines(text)) {
		const content = stripComment(line, ';#', true);
		const trimmed = trim(content);
		if (trimmed === '') continue;
		if (trimmed.startsWith('[')) {
			const rest = trimmed.slice(1);
			if (rest.endsWith(']')) {
				section = trim(rest.slice(0, -1));
				continue;
			}
		}
		const separator = content.search(/[=:]/);
		if (separator === -1) continue;
		const key = trim(content.slice(0, separator));
		if (key === '') continue;
		spans.push({
			start: offset + separator + 1,
			end: offset + content.length,
			path: dotted(section, key),
		});
	}
	return spans;
}

// -------------------------------------------------------------- dotenv

export function dotenvKeys(text: string): KeySpan[] {
	const spans: KeySpan[] = [];
	for (const [offset, raw] of lines(text)) {
		const line = stripComment(raw, '#', true);
		const trimmed = trimStart(line);
		if (trimmed === '') continue;
		const content = trimmed.startsWith('export ')
			? trimmed.slice('export '.length)
			: trimmed;
		const lead = line.length - content.length;
		const equals = content.indexOf('=');
		if (equals === -1) continue;
		const key = trim(content.slice(0, equals));
		if (key === '') continue;
		spans.push({
			start: offset + lead + equals + 1,
			end: offset + line.length,
			path: key,
		});
	}
	return spans;
}

// ----------------------------------------------------------------- CSV

export function csvKeys(text: string, delimiter: string): KeySpan[] {
	const spans: KeySpan[] = [];
	lines(text).forEach(([offset, line], row) => {
		if (trim(line) === '') return;
		cells(line, delimiter).forEach(([start, end], column) => {
			spans.push({
				start: offset + start,
				end: offset + end,
				path: `[${row}][${column}]`,
			});
		});
	});
	return spans;
}

function cells(line: string, delimiter: string): Array<[number, number]> {
	const out: Array<[number, number]> = [];
	let start = 0;
	let quoted = false;
	for (let index = 0; index < line.length; index++) {
		const character = line.charAt(index);
		if (character === '"') {
			quoted = !quoted;
			continue;
		}
		if (character === delimiter && !quoted) {
			out.push([start, index]);
			start = index + 1;
		}
	}
	out.push([start, line.length]);
	return out;
}

// ----------------------------------------------------------------- log

export function logKeys(text: string): KeySpan[] {
	const spans: KeySpan[] = [];
	for (const [offset, line] of lines(text)) {
		const trimmed = trimStart(line);
		if (trimmed.startsWith('{')) {
			const lead = offset + (line.length - trimmed.length);
			for (const span of jsonKeys(trimmed))
				spans.push({
					start: span.start + lead,
					end: span.end + lead,
					path: span.path,
				});
			continue;
		}
		logfmt(offset, line, spans);
	}
	return spans;
}

const isNameUnit = (character: string) => /^[0-9A-Za-z_.-]$/.test(character);
const isSpaceUnit = (character: string) => /^[ \t\n\f\r]$/.test(character);

/** `key=value` pairs; a key is the name run immediately before an `=`. */
function logfmt(offset: number, line: string, spans: KeySpan[]): void {
	let index = 0;
	while (index < line.length) {
		if (line.charAt(index) !== '=') {
			index++;
			continue;
		}
		let keyStart = index;
		while (keyStart > 0 && isNameUnit(line.charAt(keyStart - 1))) keyStart--;
		if (keyStart === index) {
			index++;
			continue;
		}
		let valueStart = index + 1;
		let valueEnd: number;
		if (line.charAt(valueStart) === '"') {
			valueEnd = valueStart + 1;
			while (valueEnd < line.length && line.charAt(valueEnd) !== '"')
				valueEnd++;
			valueStart++;
		} else {
			valueEnd = valueStart;
			while (valueEnd < line.length && !isSpaceUnit(line.charAt(valueEnd)))
				valueEnd++;
		}
		spans.push({
			start: offset + valueStart,
			end: offset + valueEnd,
			path: line.slice(keyStart, index),
		});
		index = Math.max(valueEnd, index + 1);
	}
}
