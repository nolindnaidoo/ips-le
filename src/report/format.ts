import * as vscode from 'vscode';
import { type Found, KINDS } from '../extract';
import {
	type ScanLimits,
	type ScanSummary,
	unreadNotes,
} from '../workspace/scan';

export interface ReportInput {
	readonly file: string;
	readonly format: string;
	readonly rows: readonly Found[];
	/** The JSON parser's message, when the document did not parse. */
	readonly unparsed: string | undefined;
	/** Whether each row leads with its line and column. On unless said otherwise. */
	readonly positions?: boolean;
}

/**
 * The report a person reads, as Markdown: the addresses grouped by kind with
 * their canonical form and class, then every run that could not be read as an
 * address with the reason — never dropped.
 */
export function formatReport({
	file,
	format,
	rows,
	unparsed,
	positions = true,
}: ReportInput): string {
	const refusals = rows.filter((row) => row.refused !== null);
	const addresses = rows.length - refusals.length;
	const lines: string[] = [`# ${vscode.l10n.t('IPs-LE report')}`, ''];
	lines.push(
		`${code(file)} · ${format} · ${vscode.l10n.t('{0} address(es), {1} could not be read', addresses, refusals.length)}`,
		'',
	);
	if (unparsed !== undefined) lines.push(`> ${unparsed}`, '');
	if (rows.length === 0) {
		lines.push(vscode.l10n.t('No addresses found.'), '');
		return lines.join('\n');
	}

	for (const kind of KINDS) {
		const ofKind = rows.filter(
			(row) => row.refused === null && row.kind === kind,
		);
		if (ofKind.length === 0) continue;
		lines.push(`## ${kind} (${ofKind.length})`, '');
		for (const row of ofKind) lines.push(item(row, positions));
		lines.push('');
	}

	if (refusals.length > 0) {
		lines.push(
			`## ${vscode.l10n.t('Could not be read ({0})', refusals.length)}`,
			'',
		);
		for (const row of refusals)
			lines.push(
				item(row, positions),
				'',
				`  ${row.refused?.reason}: ${row.refused?.detail}`,
				'',
			);
	}
	return lines.join('\n');
}

export interface FileRows {
	readonly file: string;
	readonly format: string;
	/** The rows this report lists for the file, which may be fewer than it holds. */
	readonly rows: readonly Found[];
	/** How many addresses the file holds. */
	readonly named: number;
	/** How many runs it holds that could not be. */
	readonly refused: number;
}

export interface WorkspaceReportInput {
	/** The folder that was scanned, or undefined for the whole workspace. */
	readonly where: string | undefined;
	readonly files: readonly FileRows[];
	readonly summary: ScanSummary;
	readonly limits: ScanLimits;
	/** Whether the runs that could not be read are listed, or only counted. */
	readonly refusalsListed: boolean;
	readonly positions?: boolean;
}

/**
 * The report for a folder or a workspace.
 *
 * It opens with a table of every file that holds something, because a project
 * has too many to find by scrolling. Then one section per file, in path
 * order, and last whatever the scan left unread. A file with nothing in it is
 * counted and not listed.
 */
export function formatWorkspaceReport({
	where,
	files,
	summary,
	limits,
	refusalsListed,
	positions = true,
}: WorkspaceReportInput): string {
	const named = files.reduce((sum, entry) => sum + entry.named, 0);
	const refused = files.reduce((sum, entry) => sum + entry.refused, 0);
	const lines: string[] = [
		`# ${vscode.l10n.t('{0} workspace report', 'IPs-LE')}`,
		'',
	];
	const scope = where === undefined ? '' : `${code(where)} · `;
	lines.push(
		`${scope}${vscode.l10n.t('{0} file(s) read', summary.read)} · ${vscode.l10n.t('{0} address(es), {1} could not be read', named, refused)}`,
		'',
	);
	if (files.length === 0) lines.push(vscode.l10n.t('No addresses found.'), '');

	if (files.length > 0) {
		lines.push(
			`| ${vscode.l10n.t('File')} | ${vscode.l10n.t('Addresses')} | ${vscode.l10n.t('Could not be read')} |`,
			'|---|---|---|',
		);
		for (const entry of files)
			lines.push(
				`| ${code(entry.file).replace(/\|/g, '\\|')} | ${entry.named} | ${entry.refused} |`,
			);
		lines.push('');
	}
	if (refused > 0 && !refusalsListed)
		lines.push(
			`> ${vscode.l10n.t('What could not be read is counted per file and not listed. The {0} setting lists each one.', code('ips-le.workspace.scanIncludeRefusals'))}`,
			'',
		);

	for (const entry of files) {
		if (entry.rows.length === 0) continue;
		lines.push(
			`## ${code(entry.file)} · ${entry.format} (${entry.rows.length})`,
			'',
		);
		for (const row of entry.rows) {
			lines.push(item(row, positions, true));
			if (row.refused !== null)
				lines.push('', `  ${row.refused.reason}: ${row.refused.detail}`, '');
		}
		lines.push('');
	}

	const notes = unreadNotes(summary, limits, code('ips-le.workspace.*'));
	if (notes.length > 0) lines.push(...notes.map((note) => `> ${note}`), '');
	return lines.join('\n');
}

/** One row: where, if asked for, then what, its canonical form and class, its key, and a block's span. */
function item(row: Found, positions: boolean, withKind = false): string {
	const parts = positions
		? [`**${row.line}:${row.column}**`, code(row.text)]
		: [code(row.text)];
	if ((withKind || row.refused !== null) && row.kind !== null)
		parts.push(row.kind);
	if (row.normalized !== null && row.normalized !== row.text)
		parts.push(`→ ${code(row.normalized)}`);
	if (row.class !== null) parts.push(row.class);
	if (row.key !== null && row.key !== '')
		parts.push(`${vscode.l10n.t('key')} ${code(row.key)}`);
	if (row.cidr !== null) {
		parts.push(
			`${code(row.cidr.network)}–${code(row.cidr.last)}`,
			vscode.l10n.t('{0} addresses', row.cidr.hosts),
		);
	}
	return `- ${parts.join(' · ')}`;
}

/** Text as a code span. A code span cannot escape a backtick, so one becomes a quote. */
function code(text: string): string {
	return `\`${text.replace(/`/g, "'").replace(/\r?\n/g, ' ')}\``;
}
