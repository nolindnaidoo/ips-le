import * as vscode from 'vscode';
import type { Telemetry } from '../telemetry/telemetry';

/**
 * Register the help command
 */
export function registerHelpCommand(
	context: vscode.ExtensionContext,
	telemetry: Telemetry,
): void {
	const disposable = vscode.commands.registerCommand(
		'ips-le.help',
		async () => {
			telemetry.event('command', { name: 'help' });
			await showHelp();
		},
	);
	context.subscriptions.push(disposable);
}

async function showHelp(): Promise<void> {
	const doc = await vscode.workspace.openTextDocument({
		content: generateHelpContent(),
		language: 'markdown',
	});
	await vscode.window.showTextDocument(doc, {
		preview: false,
		viewColumn: vscode.ViewColumn.Beside,
	});
}

/** Every claim here is the crate's behaviour, and the corpus pins it. */
export function generateHelpContent(): string {
	return [
		'# IPs-LE Help',
		'',
		'Finds every IPv4 and IPv6 address, CIDR block and MAC address in a document, with its position, its key path, its canonical form and what it is for. Text that cannot be read as an address unambiguously is reported with the reason, never guessed at. Nothing is resolved, looked up or connected to.',
		'',
		'## Commands',
		'',
		'- **Extract Addresses** (`Ctrl+Alt+A`, Mac `Cmd+Alt+A`): the active document, as the editor holds it.',
		'',
		'## What each finding carries',
		'',
		'- **Canonical form.** IPv6 follows RFC 5952, so `2001:0db8::0001` and `2001:db8::1` are one address. A MAC comes back lowercase with colons.',
		'- **Class.** One of `loopback`, `private`, `link-local`, `cgnat`, `multicast`, `broadcast`, `reserved`, `documentation`, `unique-local` or `global`. `::ffff:127.0.0.1` is loopback.',
		"- **A CIDR block's span**: its network, its last address and how many addresses it holds.",
		'',
		'## Refusals',
		'',
		'| Reason | When |',
		'|---|---|',
		'| `octal_hazard` | A leading zero, as in `010.1.1.1`: octal to some resolvers and decimal to others. |',
		'| `ambiguous_version` | Three dotted groups, as in `10.0.1`: a version or an address missing an octet. Under a key naming a version it is silent. |',
		'| `integer_form` | A bare integer under a key naming an address, as in `bind_ip = 2130706433`. |',
		'| `prefix_out_of_range` | A CIDR prefix past 32 for IPv4 or 128 for IPv6. |',
		'| `malformed_address` | The shape of an address that does not parse. |',
		'| `mac_ambiguous` | Twelve hex digits with no separators: a MAC or the front of a hash. |',
		'',
		'## Key paths',
		'',
		'In JSON, YAML, TOML, INI, `.env`, CSV and logs (logfmt and JSON lines) each address also carries the key it sits under. The format decides only how an address is addressed, never whether it is found: an address inside a URL, a comment or a log message is still found. A JSON document that does not parse still has its addresses reported, with a note that the key paths are missing.',
		'',
		'## Agents',
		'',
		"The bundled MCP server offers `extract_ips` to agent mode. It answers exactly as the `ips-le` command-line tool's server does.",
		'',
		'## Troubleshooting',
		'',
		'- **A version string was refused**: put it under a key that names a version (`version`, `ver`, `rev`), or read the reason beside it.',
		'- **Only some addresses appear**: `ips-le.kinds` and `ips-le.classes` narrow the addresses; refusals are always shown.',
		'',
	].join('\n');
}
