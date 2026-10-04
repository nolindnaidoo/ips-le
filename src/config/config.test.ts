import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { _resetMockState, _setConfig } from '../__mocks__/vscode';
import { CLASSES, KINDS } from '../extract';
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
		'ips-le.copyToClipboardEnabled': 'copyToClipboardEnabled',
		'ips-le.kinds': 'kinds',
		'ips-le.notificationsLevel': 'notificationsLevel',
		'ips-le.openResultsSideBySide': 'openResultsSideBySide',
		'ips-le.safety.enabled': 'safetyEnabled',
		'ips-le.safety.fileSizeWarnBytes': 'safetyFileSizeWarnBytes',
		'ips-le.statusBar.enabled': 'statusBarEnabled',
		'ips-le.telemetryEnabled': 'telemetryEnabled',
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
