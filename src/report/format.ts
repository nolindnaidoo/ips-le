import * as vscode from 'vscode';
import { type Found, KINDS } from '../extract';

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

/** One row: where, if asked for, then what, its canonical form and class, its key, and a block's span. */
function item(row: Found, positions: boolean): string {
	const parts = positions
		? [`**${row.line}:${row.column}**`, code(row.text)]
		: [code(row.text)];
	if (row.refused !== null && row.kind !== null) parts.push(row.kind);
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
