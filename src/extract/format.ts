import { trim } from './text';

/**
 * Which reader supplies key paths — the crate's `format.rs`. The format never
 * decides whether an address is found, only whether it carries a key.
 */
export const FALLBACK_FORMAT = 'unknown';

const ALIASES: ReadonlyArray<readonly [string, string]> = Object.freeze([
	['json', 'json'],
	['jsonc', 'json'],
	['yaml', 'yaml'],
	['yml', 'yaml'],
	['toml', 'toml'],
	['ini', 'ini'],
	['cfg', 'ini'],
	['conf', 'ini'],
	['properties', 'ini'],
	['env', 'env'],
	['dotenv', 'env'],
	['csv', 'csv'],
	['tsv', 'tsv'],
	['log', 'log'],
	['logs', 'log'],
	['ndjson', 'log'],
	['jsonl', 'log'],
	['txt', FALLBACK_FORMAT],
	['text', FALLBACK_FORMAT],
	['plaintext', FALLBACK_FORMAT],
]);

export const SUPPORTED_FORMATS = Object.freeze([
	'json',
	'yaml',
	'toml',
	'ini',
	'env',
	'csv',
	'tsv',
	'log',
]);

const normalise = (value: string) =>
	trim(value).replace(/^\.+/, '').toLowerCase();

export function canonical(format: string): string {
	return ALIASES.find(([alias]) => alias === format)?.[1] ?? FALLBACK_FORMAT;
}

/** From an explicit format, else a filename — every suffix, right to left — else the fallback. */
export function resolveFormat(
	format: string | undefined,
	filename: string | undefined,
): string {
	if (format !== undefined) {
		const direct = canonical(normalise(format));
		if (direct !== FALLBACK_FORMAT) return direct;
	}
	if (filename === undefined) return FALLBACK_FORMAT;
	const whole = canonical(normalise(filename));
	if (whole !== FALLBACK_FORMAT) return whole;
	for (const part of filename.split('.').slice(1).reverse()) {
		const key = canonical(normalise(part));
		if (key !== FALLBACK_FORMAT) return key;
	}
	return FALLBACK_FORMAT;
}
