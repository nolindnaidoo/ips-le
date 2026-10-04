import * as assert from 'node:assert';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as vscode from 'vscode';

const EXTENSION_ID = 'nolindnaidoo.ips-le';

function file(name: string, content: string): vscode.Uri {
	const path = join(mkdtempSync(join(tmpdir(), 'ips-le-it-')), name);
	writeFileSync(path, content);
	return vscode.Uri.file(path);
}

async function extractFrom(uri: vscode.Uri): Promise<string> {
	await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(uri));
	await vscode.commands.executeCommand('ips-le.extract');
	const report = vscode.workspace.textDocuments
		.filter((doc) => doc.languageId === 'markdown' && doc.getText().includes('IPs-LE report'))
		.find((doc) => doc.getText().includes(vscode.workspace.asRelativePath(uri, false)));
	assert.ok(report, 'no report document found');
	return report.getText();
}

describe('IPs-LE integration', function () {
	this.timeout(30_000);

	it('activates', async () => {
		const extension = vscode.extensions.getExtension(EXTENSION_ID);
		assert.ok(extension, `extension ${EXTENSION_ID} not found`);
		await extension.activate();
		assert.strictEqual(extension.isActive, true);
	});

	it('registers every declared command', async () => {
		const extension = vscode.extensions.getExtension(EXTENSION_ID);
		await extension?.activate();
		const commands = await vscode.commands.getCommands(true);
		for (const id of ['ips-le.extract', 'ips-le.openSettings', 'ips-le.help']) {
			assert.ok(commands.includes(id), `missing command: ${id}`);
		}
	});

	it('normalizes each address with its class and key, and refuses the leading zero by name', async () => {
		const text = await extractFrom(
			file('config.json', JSON.stringify({ upstream: { host: '2001:0db8:0000:0000:0000:0000:0000:0001' }, legacy: '010.1.1.1' }, null, 2)),
		);
		assert.ok(text.includes('→ `2001:db8::1` · documentation · key `upstream.host`'), text);
		assert.ok(text.includes('octal_hazard: 010.1.1.1 has a leading zero'), text);
	});

	it('reads a rotated log as a log, so its logfmt key names the address', async () => {
		const text = await extractFrom(file('access.log.1', 'level=info peer=10.0.0.1\n'));
		assert.ok(text.includes('key `peer`'), text);
	});

	it('offers its MCP server to agent mode', async () => {
		// The registration itself is only observable in a real host, which
		// scripts/e2e-vsix.js covers against the installed VSIX.
		const extension = vscode.extensions.getExtension(EXTENSION_ID);
		await extension?.activate();
		assert.strictEqual(
			typeof vscode.lm.registerMcpServerDefinitionProvider,
			'function',
			'this VS Code build predates the MCP provider API',
		);
		const providers = extension?.packageJSON.contributes.mcpServerDefinitionProviders as {
			id: string;
			label: string;
		}[];
		assert.deepStrictEqual(
			providers.map((p) => p.id),
			['ips-le'],
		);
	});
});
