import type { Class, Kind } from './extract';

export type NotificationLevel = 'all' | 'important' | 'silent';

/** The extension's settings, read once per command and frozen. */
export interface Configuration {
	readonly classes: readonly Class[];
	/** Whether the copy on the clipboard carries positions, whatever the screen shows. */
	readonly clipboardIncludesPositions: boolean;
	readonly copyToClipboardEnabled: boolean;
	readonly kinds: readonly Kind[];
	readonly notificationsLevel: NotificationLevel;
	readonly openResultsSideBySide: boolean;
	readonly safetyEnabled: boolean;
	readonly safetyFileSizeWarnBytes: number;
	/** Whether the output gives the line and column of each address. */
	readonly showPositions: boolean;
	readonly statusBarEnabled: boolean;
	readonly telemetryEnabled: boolean;
	/** Globs read whatever the excludes and `.gitignore` say. */
	readonly workspaceScanAlwaysInclude: readonly string[];
	/** Globs left out on top of the built-in list. */
	readonly workspaceScanExcludes: readonly string[];
	/** List each refusal in a folder scan, not only how many. */
	readonly workspaceScanIncludeRefusals: boolean;
	readonly workspaceScanMaxFiles: number;
	/** The most results one folder scan lists before it stops reading. */
	readonly workspaceScanMaxResults: number;
	readonly workspaceScanPatterns: readonly string[];
	/** Publish a folder scan's refusals to the Problems panel. */
	readonly workspaceScanProblemsEnabled: boolean;
	readonly workspaceScanRespectGitignore: boolean;
	readonly workspaceScanSkipBinaryFiles: boolean;
	readonly workspaceScanUseDefaultExcludes: boolean;
}
