import * as assert from 'node:assert';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
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
		for (const id of [
			'ips-le.extract',
			'ips-le.scanWorkspace',
			'ips-le.scanFolder',
			'ips-le.openSettings',
			'ips-le.help',
		]) {
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

	it('scans a folder from disk: a section per file, excludes honoured, binaries left unread, refusals in Problems', async () => {
		const root = mkdtempSync(join(tmpdir(), 'ips-le-scan-'));
		mkdirSync(join(root, 'api'));
		mkdirSync(join(root, 'node_modules'));
		const uuid = '192.0.2.10';
		const bad = '010.1.1.1';
		writeFileSync(join(root, 'api', 'a.json'), JSON.stringify({ id: uuid }));
		writeFileSync(join(root, 'api', 'b.txt'), `first ${uuid}\nthen ${bad}\n`);
		writeFileSync(join(root, 'node_modules', 'dep.json'), JSON.stringify({ id: uuid }));
		writeFileSync(join(root, 'logo.bin'), Buffer.from([0x89, 0x50, 0x00, 0x47]));
		writeFileSync(join(root, 'empty.md'), 'nothing here');

		writeFileSync(join(root, '.gitignore'), 'generated/\n');
		mkdirSync(join(root, 'generated'));
		writeFileSync(join(root, 'generated', 'g.json'), JSON.stringify({ id: uuid }));
		const settings = vscode.workspace.getConfiguration('ips-le');
		await settings.update('workspace.scanProblemsEnabled', true, vscode.ConfigurationTarget.Global);

		// As the Explorer calls it: with the folder that was clicked.
		await vscode.commands.executeCommand('ips-le.scanFolder', vscode.Uri.file(root));
		await settings.update('workspace.scanProblemsEnabled', undefined, vscode.ConfigurationTarget.Global);

		// This scan's report, whatever other reports the session has open.
		const report = vscode.workspace.textDocuments.find(
			(doc) => doc.languageId === 'markdown' && doc.getText().includes('ips-le-scan-'),
		);
		assert.ok(report, 'no workspace report was opened');
		const text = report.getText();
		// The .gitignore itself is read, and what it names is not.
		assert.match(text, /4 file\(s\) read · 2 address\(es\), 1 could not be read/);
		assert.ok(!text.includes('generated'), 'a file ignored by .gitignore was read');
		assert.match(text, /\| `api\/b\.txt` \| 1 \| 1 \|/);
		assert.deepStrictEqual(text.match(/^## .*$/gm), ['## `api/a.json` · json (1)', '## `api/b.txt` · unknown (1)']);
		assert.ok(!text.includes('node_modules'), 'an excluded folder was read');
		// `.bin` is on the list of extensions that are not text, so the file is
		// never opened, and the report says which filters were on.
		assert.match(text, /> Not read: dependency folders, build output, caches and lockfiles; images, fonts, archives and other binary files; 1 file\(s\) ignored by \.gitignore\./);

		const problems = vscode.languages
			.getDiagnostics()
			.filter(([, list]) => list.some((d) => d.source === 'ips-le'));
		assert.strictEqual(problems.length, 1, 'expected problems for one file');
		const [uri, list] = problems[0] as [vscode.Uri, vscode.Diagnostic[]];
		assert.ok(uri.path.endsWith('/api/b.txt'));
		assert.strictEqual(list.length, 1);
		assert.strictEqual(list[0]?.severity, vscode.DiagnosticSeverity.Warning);
		assert.strictEqual(list[0]?.range.start.line, 1);
		assert.strictEqual(list[0]?.range.start.character, 5);
	});
});
