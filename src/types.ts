import type { Class, Kind } from './extract';

export type NotificationLevel = 'all' | 'important' | 'silent';

/** The extension's settings, read once per command and frozen. */
export interface Configuration {
	readonly classes: readonly Class[];
	readonly copyToClipboardEnabled: boolean;
	readonly kinds: readonly Kind[];
	readonly notificationsLevel: NotificationLevel;
	readonly openResultsSideBySide: boolean;
	readonly safetyEnabled: boolean;
	readonly safetyFileSizeWarnBytes: number;
	readonly statusBarEnabled: boolean;
	readonly telemetryEnabled: boolean;
}
