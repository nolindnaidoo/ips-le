import { beforeEach, describe, expect, it } from 'vitest';
import {
	_clipboardText,
	_createDocument,
	_createExtensionContext,
	_openedDocuments,
	_registeredCommands,
	_resetMockState,
	_setActiveEditor,
	_setConfig,
	_setWorkspaceFiles,
	_shownMessages,
	executedBuiltins,
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
		deps: { notifier: createNotifier(), statusBar, telemetry },
		flashes,
	};
}

async function runCommand(id: string): Promise<void> {
	const handler = _registeredCommands().get(id);
	if (!handler) throw new Error(`command not registered: ${id}`);
	await handler();
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
