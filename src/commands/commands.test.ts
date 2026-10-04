import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import {
	_clipboardText,
	_createDocument,
	_createExtensionContext,
	_diagnostics,
	_openedDocuments,
	_registeredCommands,
	_resetMockState,
	_respondToOpenDialog,
	_setActiveEditor,
	_setConfig,
	_setWorkspaceFiles,
	_shownMessages,
	executedBuiltins,
	Uri,
	workspace,
} from '../__mocks__/vscode';
import { registerOpenSettingsCommand } from '../config/settings';
import type { Telemetry } from '../telemetry/telemetry';
import { createNotifier } from '../ui/notifier';
import type { StatusBar } from '../ui/statusBar';
import { generateHelpContent, registerHelpCommand } from './help';
import { registerCommands } from './index';

function makeDeps() {
	const flashes: string[] = [];
	const telemetry: Telemetry = { event: () => {}, dispose: () => {} };
	const statusBar: StatusBar = { flash: (text) => flashes.push(text) };
	return {
		deps: {
			notifier: createNotifier(),
			statusBar,
			telemetry,
			ratingPrompt: { recordSuccess: async () => {} },
		},
		flashes,
	};
}

async function runCommand(id: string, ...args: unknown[]): Promise<void> {
	const handler = _registeredCommands().get(id);
	if (!handler) throw new Error(`command not registered: ${id}`);
	await handler(...args);
}

function report(): string {
	const last = _openedDocuments().at(-1);
	if (!last) throw new Error('no report was opened');
	return last.getText();
}

const DOCUMENT = JSON.stringify(
	{
		upstream: {
			host: '2001:0db8:0000:0000:0000:0000:0000:0001',
			allow: '10.0.0.0/8',
		},
		legacy: '010.1.1.1',
	},
	null,
	2,
);

let flashes: string[] = [];
beforeEach(() => {
	_resetMockState();
	const made = makeDeps();
	flashes = made.flashes;
	registerCommands(_createExtensionContext() as never, made.deps);
});

describe('ips-le.extract', () => {
	it('errors when no editor is active', async () => {
		await runCommand('ips-le.extract');
		expect(_shownMessages()[0]).toMatchObject({
			kind: 'error',
			message: 'No active editor',
		});
	});

	it('says an empty file is empty', async () => {
		_setConfig('ips-le.notificationsLevel', 'all');
		_setActiveEditor(_createDocument({ content: '' }));
		await runCommand('ips-le.extract');
		expect(_shownMessages()[0]).toMatchObject({
			kind: 'info',
			message: 'File is empty',
		});
	});

	it('normalizes each address with its class and key, spans a block, and refuses the leading zero by name', async () => {
		_setActiveEditor(
			_createDocument({
				content: DOCUMENT,
				languageId: 'json',
				fileName: '/w/config.json',
			}),
		);
		await runCommand('ips-le.extract');
		const text = report();
		expect(text).toContain(
			'`/w/config.json` · json · 2 address(es), 1 could not be read',
		);
		expect(text).toContain(
			'- **3:14** · `2001:0db8:0000:0000:0000:0000:0000:0001` · → `2001:db8::1` · documentation · key `upstream.host`',
		);
		expect(text).toContain('`10.0.0.0`–`10.255.255.255` · 16777216 addresses');
		expect(text).toContain('## Could not be read (1)');
		expect(text).toContain('octal_hazard: 010.1.1.1 has a leading zero');
		expect(flashes).toContain('2 address(es)');
	});

	it('reads the format from the file name when the language mode does not say', async () => {
		_setActiveEditor(
			_createDocument({
				content: 'level=info peer=10.0.0.1\n',
				fileName: '/w/access.log.1',
			}),
		);
		await runCommand('ips-le.extract');
		expect(report()).toContain('key `peer`');
	});

	it('narrows to the kinds and classes the settings name, and keeps every refusal', async () => {
		_setConfig('ips-le.kinds', ['cidr']);
		_setActiveEditor(
			_createDocument({ content: DOCUMENT, languageId: 'json' }),
		);
		await runCommand('ips-le.extract');
		expect(report()).not.toContain('## ipv6');
		expect(report()).toContain('## cidr (1)');
		expect(report()).toContain('## Could not be read (1)');
	});

	it('warns that a broken JSON document has no key paths, and still lists its addresses', async () => {
		_setConfig('ips-le.notificationsLevel', 'all');
		_setActiveEditor(
			_createDocument({
				content: '{"a": 1 "b": 2} 10.0.0.5',
				languageId: 'json',
			}),
		);
		await runCommand('ips-le.extract');
		expect(report()).toContain(
			'> could not read this as JSON, so no key paths are reported: Expected comma on line 1 column 8',
		);
		expect(report()).toContain('`10.0.0.5`');
		expect(
			_shownMessages().some(
				(m) =>
					m.message ===
					'This JSON does not parse, so no key paths are reported',
			),
		).toBe(true);
	});

	it('warns about a large file before extracting', async () => {
		_setConfig('ips-le.notificationsLevel', 'all');
		_setConfig('ips-le.safety.fileSizeWarnBytes', 1000);
		_setWorkspaceFiles({ '/w/big.txt': 'x'.repeat(2000) });
		_setActiveEditor(
			_createDocument({ content: 'x'.repeat(2000), fileName: '/w/big.txt' }),
		);
		await runCommand('ips-le.extract');
		expect(
			_shownMessages().some((m) =>
				m.message.startsWith('Large file detected (2000 bytes)'),
			),
		).toBe(true);
	});

	it('copies the report when asked to', async () => {
		_setConfig('ips-le.copyToClipboardEnabled', true);
		_setActiveEditor(
			_createDocument({ content: DOCUMENT, languageId: 'json' }),
		);
		await runCommand('ips-le.extract');
		expect(_clipboardText()).toBe(report());
	});

	it('shows no positions when the setting is off', async () => {
		_setConfig('ips-le.showPositions', false);
		_setActiveEditor(
			_createDocument({ content: DOCUMENT, languageId: 'json' }),
		);
		await runCommand('ips-le.extract');
		expect(report()).not.toMatch(/\*\*(\d+:\d+|—)\*\*/);
		expect(report()).toMatch(/^- `/m);
	});

	it('decides positions for the clipboard separately from the report', async () => {
		_setConfig('ips-le.copyToClipboardEnabled', true);
		_setConfig('ips-le.clipboardIncludesPositions', false);
		_setActiveEditor(
			_createDocument({ content: DOCUMENT, languageId: 'json' }),
		);
		await runCommand('ips-le.extract');
		expect(report()).toMatch(/\*\*\d+:\d+\*\*/);
		expect(_clipboardText()).not.toMatch(/\*\*(\d+:\d+|—)\*\*/);
		expect(_clipboardText()).toMatch(/^- `/m);
	});
});

describe('settings and help', () => {
	it('opens the settings filtered to this extension', async () => {
		const { deps } = makeDeps();
		registerOpenSettingsCommand(
			_createExtensionContext() as never,
			deps.telemetry,
		);
		await runCommand('ips-le.openSettings');
		expect(executedBuiltins.at(-1)).toMatchObject({ args: ['ips-le.'] });
	});

	it('opens the help, which names the normalization and every refusal', async () => {
		const { deps } = makeDeps();
		registerHelpCommand(_createExtensionContext() as never, deps.telemetry);
		await runCommand('ips-le.help');
		for (const word of [
			'RFC 5952',
			'octal_hazard',
			'ambiguous_version',
			'integer_form',
			'prefix_out_of_range',
			'malformed_address',
			'mac_ambiguous',
		]) {
			expect(generateHelpContent()).toContain(word);
		}
	});
});

describe('ips-le.scanWorkspace and ips-le.scanFolder', () => {
	const UUID = '192.0.2.10';
	const BAD = '010.1.1.1';
	const TREE = {
		'/w/api/a.json': JSON.stringify({ id: UUID }),
		'/w/api/b.txt': `first ${UUID}\nthen ${BAD}`,
		'/w/empty.md': 'nothing here',
		'/w/node_modules/dep.json': JSON.stringify({ id: UUID }),
		// No extension to go by, so it is read and found not to be text.
		'/w/blob': new Uint8Array([0x89, 0x50, 0x00, 0x47]),
	};

	function open(): void {
		_setWorkspaceFiles(TREE);
		workspace.workspaceFolders = [{ uri: Uri.file('/w'), name: 'w', index: 0 }];
	}

	it('warns when no workspace is open', async () => {
		_setConfig('ips-le.notificationsLevel', 'all');
		await runCommand('ips-le.scanWorkspace');
		expect(_shownMessages()[0]).toMatchObject({ kind: 'warning' });
		expect(_openedDocuments()).toHaveLength(0);
	});

	it('reports every file that holds an address, one section each, in path order', async () => {
		open();
		await runCommand('ips-le.scanWorkspace');

		const text = report();
		expect(text).toContain('# IPs-LE workspace report');
		expect(text).toContain(
			'3 file(s) read · 2 address(es), 1 could not be read',
		);
		// The table names every file that holds something, with both counts.
		expect(text).toContain('| File | Addresses | Could not be read |');
		expect(text).toContain('| `/w/api/a.json` | 1 | 0 |');
		expect(text).toContain('| `/w/api/b.txt` | 1 | 1 |');
		// What could not be read is counted there and not listed below.
		expect(text.match(/^## .*$/gm)).toEqual([
			'## `/w/api/a.json` · json (1)',
			'## `/w/api/b.txt` · unknown (1)',
		]);
		expect(text).not.toContain(BAD);
		expect(text).toContain('`ips-le.workspace.scanIncludeRefusals`');
		// A named address says its kind here, since nothing groups by it.
		expect(text).toContain(`- **1:8** · \`${UUID}\` · ipv4`);
		// Left out by the built-in excludes, and the report says they were on.
		expect(text).not.toContain('node_modules');
		expect(text).toContain(
			'> Not read: dependency folders, build output, caches and lockfiles; images, fonts, archives and other binary files; 0 file(s) ignored by .gitignore. The `ips-le.workspace.*` settings change this.',
		);
		expect(text).toContain(
			'> 1 file(s) that are not UTF-8 text were not read.',
		);
		expect(flashes).toEqual(['2 address(es) in 2 file(s)']);
	});

	it('lists each run that could not be read when asked to', async () => {
		open();
		_setConfig('ips-le.workspace.scanIncludeRefusals', true);
		await runCommand('ips-le.scanWorkspace');

		expect(report()).toContain('## `/w/api/b.txt` · unknown (2)');
		expect(report()).toContain(BAD);
		expect(report()).not.toContain('scanIncludeRefusals');
	});

	it('leaves the Problems panel alone unless asked', async () => {
		open();
		await runCommand('ips-le.scanWorkspace');
		expect(_diagnostics().size).toBe(0);
	});

	it('puts the runs that could not be read in the Problems panel when asked, and only those', async () => {
		open();
		_setConfig('ips-le.workspace.scanProblemsEnabled', true);
		await runCommand('ips-le.scanWorkspace');

		const problems = _diagnostics();
		expect([...problems.keys()]).toEqual(['/w/api/b.txt']);
		const [problem] = problems.get('/w/api/b.txt') ?? [];
		expect(problem?.severity).toBe(1);
		expect(problem?.source).toBe('ips-le');
		expect(problem?.range.start).toMatchObject({ line: 1, character: 5 });
		expect(problem?.range.end.character).toBe(5 + BAD.length);
	});

	it('scans only the folder it is handed', async () => {
		open();
		_setWorkspaceFiles({ ...TREE, '/w/web/c.txt': UUID });
		await runCommand('ips-le.scanFolder', Uri.file('/w/web'));

		expect(report()).toContain('`/w/web` · 1 file(s) read · 1 address(es)');
		// Paths are relative to the folder that was picked.
		expect(report().match(/^## .*$/gm)).toEqual(['## `c.txt` · unknown (1)']);
	});

	it('asks for a folder from the palette, and does nothing when none is picked', async () => {
		open();
		_respondToOpenDialog(() => undefined);
		await runCommand('ips-le.scanFolder');
		expect(_openedDocuments()).toHaveLength(0);

		_respondToOpenDialog(() => [Uri.file('/w/api')]);
		await runCommand('ips-le.scanFolder');
		expect(report()).toContain('`/w/api` · 2 file(s) read');
	});

	it('stops at the results limit and says the rest was not read', async () => {
		open();
		_setConfig('ips-le.workspace.scanMaxResults', 1);
		await runCommand('ips-le.scanWorkspace');

		const text = report();
		expect(text.match(/^## .*$/gm)).toEqual(['## `/w/api/a.json` · json (1)']);
		expect(text).toContain(
			'> The results limit was reached. The rest of the files were not read.',
		);
	});

	it('says when more files matched than the file limit', async () => {
		open();
		_setConfig('ips-le.workspace.scanMaxFiles', 1);
		await runCommand('ips-le.scanWorkspace');
		expect(report()).toContain(
			'> More files matched than the limit of 1. The rest were not read.',
		);
	});

	it('honours the positions settings as Extract does', async () => {
		open();
		_setConfig('ips-le.showPositions', false);
		await runCommand('ips-le.scanWorkspace');
		expect(report()).not.toMatch(/\*\*\d+:\d+\*\*/);
		expect(report()).toContain(`- \`${UUID}\` · ipv4`);
	});
	it('prints the rows the README shows as its sample', async () => {
		_setWorkspaceFiles({
			'/w/deploy/config.json': JSON.stringify(
				{
					upstream: { host: '2001:0db8:0000:0000:0000:0000:0000:0001' },
					peer: '192.0.2.10',
					legacy: '010.1.1.1',
				},
				null,
				2,
			),
		});
		workspace.workspaceFolders = [{ uri: Uri.file('/w'), name: 'w', index: 0 }];
		await runCommand('ips-le.scanFolder', Uri.file('/w'));

		const rows = report()
			.split('\n')
			.filter((line) => line.startsWith('- '));
		expect(rows).toHaveLength(2);
		const readme = readFileSync(
			join(__dirname, '..', '..', 'README.md'),
			'utf8',
		);
		for (const row of rows) expect(readme).toContain(row);
		expect(readme).toContain('| `deploy/config.json` | 2 | 1 |');
		expect(report()).toContain('| `deploy/config.json` | 2 | 1 |');
	});
});
