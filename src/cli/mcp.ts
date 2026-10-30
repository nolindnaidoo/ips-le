/**
 * `ips-le mcp`: the crate's MCP server (`crate/src/mcp/`), not the
 * extension's. It offers `ips_le_scan` beside the shared `extract_ips`,
 * answers in the crate's words, and writes every reply with its keys sorted,
 * as a `serde_json::Value` without `preserve_order` does.
 */

import { CLASSES, KINDS, resolveFormat } from '../extract';
import { sortedKeys } from '../mcp/envelope';
import { readFilter, TOOLS } from '../mcp/tools';
import { type Frame, frames, type Request } from './frames';
import { tree, wasSkipped } from './scan';

const PROTOCOL_VERSION = '2025-06-18';
const PARSE_ERROR = -32700;
const INVALID_PARAMS = -32602;
const METHOD_NOT_FOUND = -32601;

type Handled =
	| { readonly result: unknown }
	| { readonly error: { readonly code: number; readonly message: string } };

const SHARED = sharedTool('extract_ips');

const SCAN_DEFINITION = {
	name: 'ips_le_scan',
	description:
		'Find every IP address, CIDR block and MAC address in files or directories, with the file it came from, its line and column, and the key it sits under where the format has one. Reads the filesystem; never writes to it, never resolves a name and never opens a socket.',
	inputSchema: {
		type: 'object',
		properties: {
			path: { type: 'string', description: 'a file or directory to read' },
			paths: {
				type: 'array',
				items: { type: 'string' },
				description: 'several files or directories, instead of `path`',
			},
			format: {
				type: 'string',
				description:
					'Force a format for every file instead of inferring one per file name. An unrecognised name still scans; it just reports no key paths.',
			},
			kind: {
				type: 'array',
				items: { type: 'string', enum: [...KINDS] },
				description: 'Report only these kinds. Refusals are always reported.',
			},
			class: {
				type: 'array',
				items: { type: 'string', enum: [...CLASSES] },
				description: 'Report only these classes. Refusals are always reported.',
			},
			hidden: {
				type: 'boolean',
				default: false,
				description: 'Walk hidden files and directories too.',
			},
			ignored: {
				type: 'boolean',
				default: false,
				description: 'Walk files excluded by .gitignore too.',
			},
		},
	},
};

/** The shared tool is the extension's, definition and handler both. */
function sharedTool(name: string) {
	const tool = TOOLS.find((candidate) => candidate.name === name);
	if (!tool) throw new Error(`the extension offers no tool named ${name}`);
	return tool;
}

/**
 * Serves until stdin closes, one request at a time, in order, over the
 * crate's framing in `frames.ts`.
 */
export async function serve(
	input: AsyncIterable<Uint8Array>,
	write: (line: string) => Promise<void> | undefined,
	version: string,
): Promise<number> {
	for await (const frame of frames(input)) {
		const response = await respond(frame, version);
		if (response !== undefined) await write(`${response}\n`);
	}
	return 0;
}

/** A malformed frame is answered in the extension server's words, so a client that sent one learns what happened. */
function respond(frame: Frame, version: string): Promise<string | undefined> {
	if ('refusal' in frame) {
		return Promise.resolve(
			JSON.stringify(
				sortedKeys({
					jsonrpc: '2.0',
					id: null,
					error: { code: PARSE_ERROR, message: frame.refusal },
				}),
			),
		);
	}
	return handle(frame.request, version);
}

function field(value: unknown, name: string): unknown {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		return undefined;
	}
	return Object.hasOwn(value, name)
		? (value as Record<string, unknown>)[name]
		: undefined;
}

async function handle(
	request: Request,
	version: string,
): Promise<string | undefined> {
	const id = field(request, 'id');
	// A notification carries no id, or a null one, and gets no reply.
	if (id === undefined || id === null) return undefined;

	const handled = await dispatch(
		request.method,
		field(request, 'params'),
		version,
	);
	return JSON.stringify(sortedKeys({ jsonrpc: '2.0', id, ...handled }));
}

async function dispatch(
	method: string,
	params: unknown,
	version: string,
): Promise<Handled> {
	if (method === 'initialize') {
		return {
			result: {
				protocolVersion: PROTOCOL_VERSION,
				capabilities: { tools: {} },
				serverInfo: { name: 'ips-le', version },
			},
		};
	}
	if (method === 'tools/list') {
		return {
			result: {
				tools: [
					{
						name: SHARED.name,
						description: SHARED.description,
						inputSchema: SHARED.inputSchema,
					},
					SCAN_DEFINITION,
				],
			},
		};
	}
	if (method === 'tools/call') return callTool(params);
	if (method === 'ping') return { result: {} };
	return {
		error: {
			code: METHOD_NOT_FOUND,
			message: `Unknown method: ${method}`,
		},
	};
}

/**
 * Protocol failures are JSON-RPC errors. A tool that fails on its arguments
 * returns a result carrying `isError`, so a model reads the reason rather than
 * concluding the server is broken.
 */
async function callTool(params: unknown): Promise<Handled> {
	const name = field(params, 'name');
	if (typeof name !== 'string') {
		return {
			error: {
				code: INVALID_PARAMS,
				message: 'tools/call requires a string `name`',
			},
		};
	}
	// serde_json answers `get` on anything but an object with nothing, so
	// arguments that are not an object read as an empty one.
	const raw = field(params, 'arguments');
	const args = isObject(raw) ? raw : {};
	if (name === 'extract_ips') {
		return { result: await outcome(() => SHARED.handler(args)) };
	}
	if (name === 'ips_le_scan') {
		return { result: await outcome(async () => scan(args)) };
	}
	return {
		error: {
			code: INVALID_PARAMS,
			message: `Unknown tool: ${name}`,
		},
	};
}

function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function outcome(tool: () => Promise<unknown>): Promise<unknown> {
	let envelope: unknown;
	try {
		envelope = sortedKeys(await tool());
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return { content: [{ type: 'text', text: message }], isError: true };
	}
	return {
		content: [{ type: 'text', text: JSON.stringify(envelope, null, 2) }],
		structuredContent: envelope,
		isError: false,
	};
}

/** The crate's `scan_tool`: paths, then the filters, then the walk. */
function scan(args: Record<string, unknown>): unknown {
	const inputs = requestedPaths(args);
	const options = {
		format:
			typeof args.format === 'string'
				? resolveFormat(args.format, undefined)
				: null,
		kinds: readFilter(args, 'kind', KINDS),
		classes: readFilter(args, 'class', CLASSES),
	};
	const { reports, binary } = tree(
		inputs,
		{ hidden: args.hidden === true, respectIgnore: args.ignored !== true },
		options,
	);
	const addresses = reports.reduce(
		(total, report) => total + report.summary.addresses,
		0,
	);
	const refused = reports.reduce(
		(total, report) => total + report.summary.refused,
		0,
	);
	const diagnostics = reports.filter(wasSkipped).map((report) => ({
		severity: 'warning',
		code: 'unreadable',
		message: `${report.file} could not be read, so this scan does not cover it`,
	}));
	if (refused > 0) {
		diagnostics.push({
			severity: 'warning',
			code: 'refused',
			message: `${refused} candidates could not be read unambiguously and were refused`,
		});
	}
	return {
		ok: true,
		data: { reports, addresses, refused, binaryFiles: binary },
		diagnostics,
		meta: { tool: 'ips_le_scan', count: reports.length, truncated: false },
	};
}

function requestedPaths(args: Record<string, unknown>): readonly string[] {
	if (typeof args.path === 'string') return [args.path];
	if (Array.isArray(args.paths)) {
		const paths = args.paths.filter(
			(item): item is string => typeof item === 'string',
		);
		if (paths.length === 0) throw new Error('the list of paths was empty');
		return paths;
	}
	throw new Error('no file or directory was supplied to read');
}
