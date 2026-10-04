import {
	CLASSES,
	type Class,
	find,
	KINDS,
	type Kind,
	parseError,
	resolveFormat,
	SUPPORTED_FORMATS,
	survives,
} from '../extract';
import {
	DEFAULT_MAX_RESULTS,
	type Diagnostic,
	MAX_MAX_RESULTS,
	readMaxResults,
} from './envelope';
import type { ToolDefinition } from './transport';

/**
 * The tool this server exposes: `extract_ips`, which the crate's server offers
 * too. One name, one schema, two implementations — the definition below is
 * the crate's, word for word, and `crate/fixtures/mcp-extract-ips.json` pins
 * the answers on both sides.
 *
 * **A refusal survives every filter**, and a JSON document that does not parse
 * still has its addresses reported: the parse only supplies key paths.
 */

const DESCRIPTION =
	'Extract every IP address, CIDR block and MAC address from a document, normalized and classified. IPv6 is canonicalized per RFC 5952, so 2001:0db8::0001 and 2001:db8::1 come back as one address rather than two. Each finding carries its line, column and — for JSON, YAML, TOML, INI, dotenv, CSV and logs — the key it sits under. Text this cannot read unambiguously is returned as a named refusal, never as a guess: a leading zero (octal or decimal, depending on the resolver), a dotted triple that may be a version, a bare integer in an address field. Resolves no names, geolocates nothing, opens no sockets.';

/** An optional array of names; a name nothing recognises is an error, never a pass-through. */
function readFilter<T extends string>(
	args: Record<string, unknown>,
	name: string,
	allowed: readonly T[],
): T[] {
	if (!Object.hasOwn(args, name)) return [];
	const value = args[name];
	if (!Array.isArray(value))
		throw new Error(`${name} must be an array of names`);
	return value.map((item: unknown) => {
		if (typeof item !== 'string')
			throw new Error(`${name} must be an array of names`);
		const found = allowed.find((candidate) => candidate === item.toLowerCase());
		if (found === undefined)
			throw new Error(`${item} is not a ${name}: ${allowed.join(', ')}`);
		return found;
	});
}

function extractIps(args: Record<string, unknown>): Promise<unknown> {
	if (typeof args.content !== 'string')
		throw new Error('content is required and must be a string');
	const content = args.content;
	const maxResults = readMaxResults(args);
	const kinds: Kind[] = readFilter(args, 'kind', KINDS);
	const classes: Class[] = readFilter(args, 'class', CLASSES);
	const format = resolveFormat(
		typeof args.format === 'string' ? args.format : undefined,
		typeof args.filename === 'string' ? args.filename : undefined,
	);

	const unparsed = parseError(content, format);
	const diagnostics: Diagnostic[] =
		unparsed === undefined
			? []
			: [{ severity: 'warning', code: 'unparsed', message: unparsed }];

	const found = find(content, format).filter((one) =>
		survives(one, kinds, classes),
	);
	const truncated = found.length > maxResults;
	const addresses = found.slice(0, maxResults);
	// Counted after the cap, as the crate counts it: the refusals in what is returned.
	const refused = addresses.filter((one) => one.refused !== null).length;

	return Promise.resolve({
		ok: true,
		data: { addresses, refused, format },
		diagnostics,
		meta: { tool: 'extract_ips', count: addresses.length, truncated },
	});
}

export const TOOLS: readonly ToolDefinition[] = Object.freeze([
	Object.freeze({
		name: 'extract_ips',
		description: DESCRIPTION,
		inputSchema: {
			type: 'object',
			properties: {
				content: { type: 'string', description: 'The document text to scan.' },
				format: {
					type: 'string',
					enum: SUPPORTED_FORMATS,
					description:
						'Document format. Optional — it only decides whether findings carry a key path, never whether they are found.',
				},
				filename: {
					type: 'string',
					description:
						'Filename used to infer the format when `format` is absent, e.g. "app.yaml" or "access.log".',
				},
				kind: {
					type: 'array',
					items: { type: 'string', enum: KINDS },
					description: 'Report only these kinds. Refusals are always reported.',
				},
				class: {
					type: 'array',
					items: { type: 'string', enum: CLASSES },
					description:
						'Report only these classes. Refusals are always reported.',
				},
				maxResults: {
					type: 'integer',
					minimum: 1,
					maximum: MAX_MAX_RESULTS,
					default: DEFAULT_MAX_RESULTS,
					description: `Cap on returned findings (default ${DEFAULT_MAX_RESULTS}). meta.truncated reports whether any were dropped.`,
				},
			},
			required: ['content'],
			additionalProperties: false,
		},
		handler: extractIps,
	}),
]);
