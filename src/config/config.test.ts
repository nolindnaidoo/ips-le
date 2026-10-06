import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { _resetMockState, _setConfig } from '../__mocks__/vscode';
import { CLASSES, KINDS } from '../extract';
import {
	DEFAULT_EXCLUDED_FILES,
	DEFAULT_EXCLUDED_FOLDERS,
	DEFAULT_EXCLUDED_PATHS,
} from '../workspace/defaults';
import {
	CONFIG_DEFAULTS,
	isValidNotificationLevel,
	readConfig,
} from './config';

describe('config defaults parity with package.json', () => {
	const manifest = JSON.parse(
		readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8'),
	) as {
		contributes: {
			configuration: {
				properties: Record<string, { default: unknown; enum?: string[] }>;
			};
		};
	};
	const props = manifest.contributes.configuration.properties;
	const KEY_MAP: Record<string, keyof typeof CONFIG_DEFAULTS> = {
		'ips-le.classes': 'classes',
		'ips-le.clipboardIncludesPositions': 'clipboardIncludesPositions',
		'ips-le.copyToClipboardEnabled': 'copyToClipboardEnabled',
		'ips-le.kinds': 'kinds',
		'ips-le.notificationsLevel': 'notificationsLevel',
		'ips-le.openResultsSideBySide': 'openResultsSideBySide',
		'ips-le.safety.enabled': 'safetyEnabled',
		'ips-le.safety.fileSizeWarnBytes': 'safetyFileSizeWarnBytes',
		'ips-le.showPositions': 'showPositions',
		'ips-le.statusBar.enabled': 'statusBarEnabled',
		'ips-le.telemetryEnabled': 'telemetryEnabled',
		'ips-le.workspace.scanAlwaysInclude': 'workspaceScanAlwaysInclude',
		'ips-le.workspace.scanExcludes': 'workspaceScanExcludes',
		'ips-le.workspace.scanIncludeRefusals': 'workspaceScanIncludeRefusals',
		'ips-le.workspace.scanMaxFiles': 'workspaceScanMaxFiles',
		'ips-le.workspace.scanMaxResults': 'workspaceScanMaxResults',
		'ips-le.workspace.scanPatterns': 'workspaceScanPatterns',
		'ips-le.workspace.scanProblemsEnabled': 'workspaceScanProblemsEnabled',
		'ips-le.workspace.scanRespectGitignore': 'workspaceScanRespectGitignore',
		'ips-le.workspace.scanSkipBinaryFiles': 'workspaceScanSkipBinaryFiles',
		'ips-le.workspace.scanUseDefaultExcludes':
			'workspaceScanUseDefaultExcludes',
	};

	it('covers every declared setting', () => {
		expect(Object.keys(props).sort()).toEqual(Object.keys(KEY_MAP).sort());
	});

	for (const [manifestKey, defaultsKey] of Object.entries(KEY_MAP)) {
		it(`${manifestKey} default matches`, () => {
			expect(CONFIG_DEFAULTS[defaultsKey]).toEqual(props[manifestKey]?.default);
		});
	}

	it('offers exactly the kinds and classes the engine names', () => {
		const items = (key: string) =>
			(props[key] as unknown as { items: { enum: string[] } }).items.enum;
		expect(items('ips-le.kinds')).toEqual([...KINDS]);
		expect(items('ips-le.classes')).toEqual([...CLASSES]);
	});
});

describe('the README states the scan limits the code uses', () => {
	const readme = readFileSync(join(__dirname, '..', '..', 'README.md'), 'utf8');
	const grouped = (n: number) => n.toLocaleString('en-US');

	it('in the settings table', () => {
		expect(readme).toContain(
			`| \`ips-le.workspace.scanMaxFiles\` | \`${CONFIG_DEFAULTS.workspaceScanMaxFiles}\` |`,
		);
		expect(readme).toContain(
			`| \`ips-le.workspace.scanMaxResults\` | \`${CONFIG_DEFAULTS.workspaceScanMaxResults}\` |`,
		);
	});

	it('in the prose', () => {
		expect(readme).toContain(
			`It stops at ${grouped(CONFIG_DEFAULTS.workspaceScanMaxFiles)} files or ${grouped(CONFIG_DEFAULTS.workspaceScanMaxResults)} listed addresses.`,
		);
	});
});

describe('the README lists the folders a scan skips', () => {
	it('exactly as the code has them', () => {
		const readme = readFileSync(
			join(__dirname, '..', '..', 'README.md'),
			'utf8',
		);
		const listed =
			/<!-- built-in-folders -->\n(.*)\n<!-- \/built-in-folders -->/
				.exec(readme)?.[1]
				?.split(', ')
				.map((entry) => entry.replace(/`/g, ''));
		expect(listed).toEqual([...DEFAULT_EXCLUDED_FOLDERS, '*.egg-info']);
	});

	it('and the files, exactly as the code has them', () => {
		const readme = readFileSync(
			join(__dirname, '..', '..', 'README.md'),
			'utf8',
		);
		const listed = /<!-- built-in-files -->\n(.*)\n<!-- \/built-in-files -->/
			.exec(readme)?.[1]
			?.split(', ')
			.map((entry) => entry.replace(/`/g, ''));
		expect(listed).toEqual([
			...DEFAULT_EXCLUDED_FILES,
			...DEFAULT_EXCLUDED_PATHS,
		]);
	});
});

describe('readConfig', () => {
	afterEach(() => _resetMockState());

	it('drops a name the engine does not know, so a typo never hides an address', () => {
		_setConfig('ips-le.kinds', ['ipv5']);
		expect(readConfig().kinds).toEqual([]);
		_setConfig('ips-le.classes', ['private', 'nonsense']);
		expect(readConfig().classes).toEqual(['private']);
		_setConfig('ips-le.kinds', 'ipv4');
		expect(readConfig().kinds).toEqual([]);
	});

	it('falls back to the default for a value of the wrong type, and floors the size', () => {
		_setConfig('ips-le.openResultsSideBySide', 'yes');
		_setConfig('ips-le.safety.fileSizeWarnBytes', 5);
		expect(readConfig().openResultsSideBySide).toBe(true);
		expect(readConfig().safetyFileSizeWarnBytes).toBe(1000);
	});
});

describe('isValidNotificationLevel', () => {
	it('accepts the three declared levels and nothing else', () => {
		for (const level of ['all', 'important', 'silent'])
			expect(isValidNotificationLevel(level)).toBe(true);
		expect(isValidNotificationLevel('verbose')).toBe(false);
	});
});
