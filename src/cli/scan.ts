/**
 * Reading files and shaping the report, as the Rust CLI's `scan.rs` does.
 *
 * One report per text file. A binary file, a NUL in its first 8 KiB, is not a
 * candidate: it produces no report and is counted. A file that could not be
 * read, and a directory the walk could not enter, are reported with the reason.
 */
import { readFileSync } from 'node:fs';
import { sep } from 'node:path';
import {
	FALLBACK_FORMAT,
	type Found,
	find,
	parseError,
	resolveFormat,
	survives,
} from '../extract';
import type { ScanOptions, WalkOptions } from './args';
import { decodeUtf8OrThrow, rustIoMessage, withoutBom } from './ioError';
import { collect } from './walk';

interface Diagnostic {
	readonly severity: 'warning';
	readonly code: 'skipped' | 'unparsed';
	readonly message: string;
}

export interface FileReport {
	readonly schema: 1;
	readonly file: string;
	readonly format: string;
	readonly addresses: readonly Found[];
	readonly diagnostics: readonly Diagnostic[];
	readonly summary: { readonly addresses: number; readonly refused: number };
}

function reportPath(path: string): string {
	return sep === '/' ? path : path.split(sep).join('/');
}

/** The crate's `format_of`: the file name alone decides. */
function formatOf(path: string): string {
	return resolveFormat(
		undefined,
		path.split(sep === '/' ? '/' : /[\\/]/).at(-1),
	);
}

/** Every report under the inputs and how many binary files were skipped. */
export function tree(
	inputs: readonly string[],
	walk: WalkOptions,
	options: ScanOptions,
): { readonly reports: FileReport[]; readonly binary: number } {
	const walked = collect(inputs, walk);
	const reports: FileReport[] = [];
	for (const file of walked.files) {
		const scanned = scanFile(file, options);
		if (scanned) reports.push(scanned);
	}
	const binary = walked.files.length - reports.length;
	for (const entry of walked.unreadable) {
		reports.push(
			skipped(reportPath(entry.path), formatOf(entry.path), entry.reason),
		);
	}
	return { reports, binary };
}

/** A report, or null for a binary file. */
export function scanFile(
	path: string,
	options: ScanOptions,
): FileReport | null {
	const file = reportPath(path);
	const format = options.format ?? formatOf(path);
	let bytes: Buffer;
	try {
		bytes = readFileSync(path);
	} catch (error) {
		return skipped(file, format, rustIoMessage(error));
	}
	if (bytes.subarray(0, 8192).includes(0)) return null;
	let content: string;
	try {
		content = decodeUtf8OrThrow(bytes);
	} catch {
		return skipped(file, format, 'not UTF-8 text');
	}
	return scanContent(withoutBom(content), file, format, options);
}

export function scanContent(
	content: string,
	file: string,
	format: string,
	options: ScanOptions,
): FileReport {
	const addresses = find(content, format).filter((found) =>
		survives(found, options.kinds, options.classes),
	);
	const unparsed = parseError(content, format);
	const refused = addresses.filter((found) => found.refused !== null).length;
	return Object.freeze({
		schema: 1,
		file,
		format,
		addresses,
		diagnostics:
			unparsed === undefined
				? []
				: [
						{
							severity: 'warning' as const,
							code: 'unparsed' as const,
							message: unparsed,
						},
					],
		summary: { addresses: addresses.length - refused, refused },
	});
}

function skipped(file: string, format: string, message: string): FileReport {
	return Object.freeze({
		schema: 1,
		file,
		format,
		addresses: [],
		diagnostics: [
			{ severity: 'warning' as const, code: 'skipped' as const, message },
		],
		summary: { addresses: 0, refused: 0 },
	});
}

export function wasSkipped(report: FileReport): boolean {
	return report.diagnostics.some((diagnostic) => diagnostic.code === 'skipped');
}

/** grep's convention, with a refusal or an unread file failing only `--strict`. */
export function exitCode(
	reports: readonly FileReport[],
	strict: boolean,
): number {
	const unsure = reports.some(
		(report) => wasSkipped(report) || report.summary.refused > 0,
	);
	if (strict && unsure) return 2;
	return reports.some((report) => report.summary.addresses > 0) ? 0 : 1;
}

export function describe(report: FileReport, found: Found): string {
	return `${report.file}:${found.line}:${found.column}  ${found.text}  ${verdict(found)}`;
}

/** Rust's `{:?}` of the reason is its variant name: `AmbiguousVersion`. */
function verdict(found: Found): string {
	if (found.refused !== null) {
		const variant = found.refused.reason
			.split('_')
			.map((word) => `${word.charAt(0).toUpperCase()}${word.slice(1)}`)
			.join('');
		return `refused ${variant} — ${found.refused.detail}`;
	}
	if (found.normalized !== null && found.class !== null) {
		return `${found.normalized}  ${found.class}`;
	}
	return '';
}

export { FALLBACK_FORMAT };
