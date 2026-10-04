import * as vscode from 'vscode';
import { readConfig } from '../config/config';
import { find, parseError, resolveFormat, survives } from '../extract';
import { formatReport } from '../report/format';
import type { CommandDependencies } from './index';
import { showReport } from './output';

/**
 * Extract the addresses in the active document, as the editor holds it.
 *
 * The format comes from the language mode first and the file name second; it
 * decides only the key paths, never which addresses are found.
 */
export async function extractFromActiveDocument(
	deps: CommandDependencies,
): Promise<void> {
	deps.telemetry.event('command', { name: 'extract' });
	const editor = vscode.window.activeTextEditor;
	if (!editor) {
		deps.notifier.error(vscode.l10n.t('No active editor'));
		return;
	}
	const document = editor.document;
	const text = document.getText();
	if (text.length === 0) {
		deps.notifier.info(vscode.l10n.t('File is empty'));
		return;
	}
	const config = readConfig();
	if (config.safetyEnabled && !document.isUntitled) {
		try {
			const { size } = await vscode.workspace.fs.stat(document.uri);
			if (size > config.safetyFileSizeWarnBytes) {
				deps.notifier.warn(
					vscode.l10n.t(
						'Large file detected ({0} bytes). Extraction may take longer.',
						size,
					),
				);
			}
		} catch {
			// A document with no file behind it has no size to warn about.
		}
	}

	// The base name, not the path: the rules that read a name never see a directory.
	const base = document.fileName.slice(
		Math.max(
			document.fileName.lastIndexOf('/'),
			document.fileName.lastIndexOf('\\'),
		) + 1,
	);
	const format = resolveFormat(document.languageId, base);
	const rows = find(text, format).filter((one) =>
		survives(one, config.kinds, config.classes),
	);
	const unparsed = parseError(text, format);
	const refused = rows.filter((row) => row.refused !== null).length;
	const file = document.isUntitled
		? document.fileName
		: vscode.workspace.asRelativePath(document.uri, false);
	await showReport(
		formatReport({ file, format, rows, unparsed }),
		config,
		deps,
	);

	deps.telemetry.event('extracted', {
		addresses: String(rows.length - refused),
		refused: String(refused),
	});
	deps.statusBar.flash(vscode.l10n.t('{0} address(es)', rows.length - refused));
	if (unparsed !== undefined)
		deps.notifier.warn(
			vscode.l10n.t('This JSON does not parse, so no key paths are reported'),
		);
	if (refused > 0)
		deps.notifier.warn(
			vscode.l10n.t(
				'{0} run(s) could not be read as an address; the report gives each reason',
				refused,
			),
		);
}
