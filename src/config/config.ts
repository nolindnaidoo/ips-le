import * as vscode from 'vscode';
import { CLASSES, KINDS } from '../extract';
import type { Configuration, NotificationLevel } from '../types';

/**
 * The defaults, exported for the parity gate: `config.test.ts` asserts they
 * match every default declared in package.json, which is what stops the two
 * drifting apart.
 */
export const CONFIG_DEFAULTS = Object.freeze({
	classes: [] as const,
	clipboardIncludesPositions: true,
	copyToClipboardEnabled: false,
	kinds: [] as const,
	notificationsLevel: 'silent' as const,
	openResultsSideBySide: true,
	safetyEnabled: true,
	safetyFileSizeWarnBytes: 1_000_000,
	showPositions: true,
	statusBarEnabled: true,
	telemetryEnabled: false,
});

export function readConfig(): Configuration {
	const config = vscode.workspace.getConfiguration('ips-le');
	return Object.freeze({
		classes: readNames(config, 'classes', CLASSES),
		clipboardIncludesPositions: readBoolean(
			config,
			'clipboardIncludesPositions',
			CONFIG_DEFAULTS.clipboardIncludesPositions,
		),
		copyToClipboardEnabled: readBoolean(
			config,
			'copyToClipboardEnabled',
			CONFIG_DEFAULTS.copyToClipboardEnabled,
		),
		kinds: readNames(config, 'kinds', KINDS),
		notificationsLevel: readNotificationLevel(config),
		openResultsSideBySide: readBoolean(
			config,
			'openResultsSideBySide',
			CONFIG_DEFAULTS.openResultsSideBySide,
		),
		safetyEnabled: readBoolean(
			config,
			'safety.enabled',
			CONFIG_DEFAULTS.safetyEnabled,
		),
		safetyFileSizeWarnBytes: readNumber(
			config,
			'safety.fileSizeWarnBytes',
			CONFIG_DEFAULTS.safetyFileSizeWarnBytes,
			1000,
		),
		showPositions: readBoolean(
			config,
			'showPositions',
			CONFIG_DEFAULTS.showPositions,
		),
		statusBarEnabled: readBoolean(
			config,
			'statusBar.enabled',
			CONFIG_DEFAULTS.statusBarEnabled,
		),
		telemetryEnabled: readBoolean(
			config,
			'telemetryEnabled',
			CONFIG_DEFAULTS.telemetryEnabled,
		),
	});
}

function readBoolean(
	config: vscode.WorkspaceConfiguration,
	key: string,
	defaultValue: boolean,
): boolean {
	const value = config.get(key, defaultValue);
	return typeof value === 'boolean' ? value : defaultValue;
}

function readNumber(
	config: vscode.WorkspaceConfiguration,
	key: string,
	defaultValue: number,
	minValue: number,
): number {
	const value = Number(config.get(key, defaultValue));
	if (!Number.isFinite(value)) return defaultValue;
	return Math.max(minValue, value);
}

/**
 * A filter from the settings. A name the engine does not know is dropped
 * rather than honoured, and a filter left with nothing in it reports
 * everything — a typo must never hide an address.
 */
function readNames<T extends string>(
	config: vscode.WorkspaceConfiguration,
	key: string,
	allowed: readonly T[],
): T[] {
	const raw = config.get<unknown>(key, []);
	if (!Array.isArray(raw)) return [];
	return allowed.filter((name) => raw.includes(name));
}

export function isValidNotificationLevel(v: unknown): v is NotificationLevel {
	return v === 'all' || v === 'important' || v === 'silent';
}

function readNotificationLevel(
	config: vscode.WorkspaceConfiguration,
): NotificationLevel {
	const raw = config.get<string>(
		'notificationsLevel',
		CONFIG_DEFAULTS.notificationsLevel,
	);
	return isValidNotificationLevel(raw)
		? raw
		: CONFIG_DEFAULTS.notificationsLevel;
}
