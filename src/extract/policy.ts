import {
	formatIpv4,
	formatIpv6,
	mappedV4,
	parseIpv4,
	parseIpv6,
	type V4,
	type V6,
	v4Bits,
	v4FromBits,
	v6Bits,
	v6FromBits,
} from './net';

/**
 * What a candidate is, what it means, and when this tool refuses to say — the
 * crate's `policy.rs`.
 *
 * **Never resolve an ambiguity into an answer**, and **say the decoded form
 * only next to the flag**: `2130706433` in an address field is refused with
 * 127.0.0.1 in its detail, never listed as a loopback address.
 */

export const KINDS = Object.freeze(['ipv4', 'ipv6', 'cidr', 'mac'] as const);
export type Kind = (typeof KINDS)[number];

export const CLASSES = Object.freeze([
	'loopback',
	'private',
	'link-local',
	'cgnat',
	'multicast',
	'broadcast',
	'reserved',
	'documentation',
	'unique-local',
	'global',
] as const);
export type Class = (typeof CLASSES)[number];

export type Reason =
	| 'ambiguous_version'
	| 'malformed_address'
	| 'octal_hazard'
	| 'integer_form'
	| 'prefix_out_of_range'
	| 'mac_ambiguous';

export interface Refusal {
	readonly reason: Reason;
	readonly detail: string;
}

/** `hosts` is decimal text: `::/0` holds 2^128. `broadcast` is null for IPv6. */
export interface Block {
	readonly prefix: number;
	readonly network: string;
	readonly broadcast: string | null;
	readonly last: string;
	readonly hosts: string;
}

export type Reading =
	| {
			readonly reading: 'address';
			readonly kind: Kind;
			readonly normalized: string;
			readonly class: Class;
			readonly block: Block | null;
	  }
	| {
			readonly reading: 'refused';
			readonly kind: Kind | null;
			readonly refusal: Refusal;
	  };

/** The evidence outside the token, from the key it sits under. */
export interface Context {
	readonly version: boolean;
	readonly address: boolean;
}

const ADDRESS_SUFFIXES = Object.freeze([
	'ip',
	'addr',
	'address',
	'host',
	'gateway',
	'cidr',
	'subnet',
]);

export function contextFromKey(key: string | null): Context {
	if (key === null) return { version: false, address: false };
	const last = key.split(/[./]/).at(-1) as string;
	const flat = last.replace(/[^0-9A-Za-z]/g, '').toLowerCase();
	return {
		version: flat.includes('version') || flat === 'ver' || flat === 'rev',
		address: ADDRESS_SUFFIXES.some((suffix) => flat.endsWith(suffix)),
	};
}

const refused = (
	kind: Kind | null,
	reason: Reason,
	detail: string,
): Reading => ({
	reading: 'refused',
	kind,
	refusal: { reason, detail },
});

/** `undefined` is "not an address and not an ambiguity either". */
export function read(token: string, context: Context): Reading | undefined {
	const slash = token.indexOf('/');
	if (slash !== -1)
		return readCidr(token.slice(0, slash), token.slice(slash + 1));
	const octets = macOctets(token);
	if (octets !== undefined) return readMac(octets);
	if (token.includes(':'))
		return looksLikeIpv6(token) ? readIpv6(token) : undefined;
	if (token.includes('.')) return readDotted(token, context);
	return readBare(token, context);
}

/** Seven colons, a `::`, or six colons with a dotted tail. */
export function looksLikeIpv6(token: string): boolean {
	if (token.includes('::')) return true;
	const colons = token.split(':').length - 1;
	if (colons === 7) return true;
	const tail = token.slice(token.lastIndexOf(':') + 1);
	return colons === 6 && tail.split('.').length === 4;
}

// -- IPv4 ------------------------------------------------------------

function readDotted(token: string, context: Context): Reading | undefined {
	const groups = token.split('.');
	if (!groups.every((group) => /^[0-9]+$/.test(group))) return undefined;
	if (groups.length === 4) {
		const hazard = octalHazard(token, groups);
		if (hazard !== undefined) return hazard;
		if (context.version) return undefined;
		return readIpv4(token);
	}
	if (groups.length === 3) {
		if (context.version) return undefined;
		return refused(
			null,
			'ambiguous_version',
			`${token} has three groups: a version string, or an IPv4 address missing an octet. Nothing here says which.`,
		);
	}
	return undefined;
}

function octalHazard(
	token: string,
	groups: readonly string[],
): Reading | undefined {
	if (!groups.some((group) => group.length > 1 && group.startsWith('0')))
		return undefined;
	return refused(
		'ipv4',
		'octal_hazard',
		`${token} has a leading zero. Some resolvers read a leading-zero octet as octal and some as decimal, so this text has two addresses and no way to choose.`,
	);
}

function readIpv4(token: string): Reading {
	const address = parseIpv4(token);
	if (address === undefined)
		return refused(
			'ipv4',
			'malformed_address',
			`${token} has four groups and is not an IPv4 address.`,
		);
	return {
		reading: 'address',
		kind: 'ipv4',
		normalized: formatIpv4(address),
		class: classOfV4(address),
		block: null,
	};
}

// -- IPv6 ------------------------------------------------------------

function readIpv6(token: string): Reading {
	const bare = token.split('%')[0] as string;
	const address = parseIpv6(bare);
	if (address === undefined) {
		return refused(
			'ipv6',
			'malformed_address',
			`${token} has the shape of an IPv6 address and is not one.`,
		);
	}
	return {
		reading: 'address',
		kind: 'ipv6',
		normalized: formatIpv6(address),
		class: classOfV6(address),
		block: null,
	};
}

// -- CIDR ------------------------------------------------------------

function readCidr(base: string, prefix: string): Reading | undefined {
	const shaped = base.includes(':')
		? looksLikeIpv6(base)
		: base.split('.').length === 4;
	if (!shaped) return undefined;
	if (!/^[0-9]+$/.test(prefix)) {
		return refused(
			'cidr',
			'malformed_address',
			`${base}/${prefix} does not carry a prefix length.`,
		);
	}
	// `parse::<u16>().unwrap_or(u16::MAX)`, printed as the number it parsed to.
	const parsed = Number.parseInt(prefix, 10);
	const width = parsed > 0xffff ? 0xffff : parsed;
	return base.includes(':') ? cidrV6(base, width) : cidrV4(base, width);
}

function cidrV4(base: string, prefix: number): Reading {
	const hazard = octalHazard(base, base.split('.'));
	if (hazard !== undefined) return hazard;
	const address = parseIpv4(base);
	if (address === undefined)
		return refused(
			'cidr',
			'malformed_address',
			`${base}/${prefix} does not carry an IPv4 address.`,
		);
	if (prefix > 32) {
		return refused(
			'cidr',
			'prefix_out_of_range',
			`an IPv4 prefix is 0 to 32; ${base}/${prefix} names ${prefix}.`,
		);
	}
	const bits = BigInt(v4Bits(address));
	const mask =
		prefix === 0 ? 0n : (0xffffffffn << BigInt(32 - prefix)) & 0xffffffffn;
	const network = v4FromBits(Number(bits & mask));
	const last = v4FromBits(Number((bits & mask) | (~mask & 0xffffffffn)));
	return {
		reading: 'address',
		kind: 'cidr',
		normalized: `${formatIpv4(address)}/${prefix}`,
		class: classOfV4(network),
		block: {
			prefix,
			network: formatIpv4(network),
			broadcast: formatIpv4(last),
			last: formatIpv4(last),
			hosts: (1n << BigInt(32 - prefix)).toString(),
		},
	};
}

const ALL_V6 = (1n << 128n) - 1n;

function cidrV6(base: string, prefix: number): Reading {
	const address = parseIpv6(base.split('%')[0] as string);
	if (address === undefined)
		return refused(
			'cidr',
			'malformed_address',
			`${base}/${prefix} does not carry an IPv6 address.`,
		);
	if (prefix > 128) {
		return refused(
			'cidr',
			'prefix_out_of_range',
			`an IPv6 prefix is 0 to 128; ${base}/${prefix} names ${prefix}.`,
		);
	}
	const bits = v6Bits(address);
	const mask = prefix === 0 ? 0n : (ALL_V6 << BigInt(128 - prefix)) & ALL_V6;
	const network = v6FromBits(bits & mask);
	const last = v6FromBits((bits & mask) | (~mask & ALL_V6));
	return {
		reading: 'address',
		kind: 'cidr',
		normalized: `${formatIpv6(address)}/${prefix}`,
		class: classOfV6(network),
		block: {
			prefix,
			network: formatIpv6(network),
			broadcast: null,
			last: formatIpv6(last),
			hosts: (1n << BigInt(128 - prefix)).toString(),
		},
	};
}

// -- MAC -------------------------------------------------------------

/** Six two-digit hex groups under one separator, `:` or `-`. */
export function macOctets(token: string): number[] | undefined {
	for (const separator of [':', '-']) {
		const groups = token.split(separator);
		if (groups.length !== 6) continue;
		if (groups.every((group) => /^[0-9A-Fa-f]{2}$/.test(group))) {
			return groups.map((group) => Number.parseInt(group, 16));
		}
	}
	return undefined;
}

function readMac(octets: readonly number[]): Reading {
	let klass: Class = 'global';
	if (octets.every((octet) => octet === 0xff)) klass = 'broadcast';
	else if (((octets[0] as number) & 1) === 1) klass = 'multicast';
	return {
		reading: 'address',
		kind: 'mac',
		normalized: octets
			.map((octet) => octet.toString(16).padStart(2, '0'))
			.join(':'),
		class: klass,
		block: null,
	};
}

// -- Bare tokens -----------------------------------------------------

function readBare(token: string, context: Context): Reading | undefined {
	if (/^[0-9]+$/.test(token)) {
		if (!context.address) return undefined;
		const value = BigInt(token);
		if (value > 0xffffffffn) return undefined;
		return refused(
			'ipv4',
			'integer_form',
			`${token} in an address field is ${formatIpv4(v4FromBits(Number(value)))} read as a 32-bit integer. Some resolvers accept that form; this tool will not decide that they did.`,
		);
	}
	if (
		!(
			token.length === 12 &&
			/^[0-9A-Fa-f]+$/.test(token) &&
			/[A-Fa-f]/.test(token)
		)
	)
		return undefined;
	return refused(
		null,
		'mac_ambiguous',
		`${token} is twelve hex digits with no separators: a MAC address written bare, or the front of a hash. Nothing here says which.`,
	);
}

// -- Classification --------------------------------------------------

function classOfV4([a, b, c, d]: V4): Class {
	if (a === 127) return 'loopback';
	if (a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31))
		return 'private';
	if (a === 169 && b === 254) return 'link-local';
	if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
	if (a === 255 && b === 255 && c === 255 && d === 255) return 'broadcast';
	if (
		(a === 192 && b === 0 && c === 2) ||
		(a === 198 && b === 51 && c === 100) ||
		(a === 203 && b === 0 && c === 113)
	) {
		return 'documentation';
	}
	if (a >= 224 && a <= 239) return 'multicast';
	if (
		a === 0 ||
		a >= 240 ||
		(a === 192 && b === 0 && c === 0) ||
		(a === 198 && (b === 18 || b === 19))
	)
		return 'reserved';
	return 'global';
}

function classOfV6(groups: V6): Class {
	const mapped = mappedV4(groups);
	if (mapped !== undefined) return classOfV4(mapped);
	const bits = v6Bits(groups);
	if (bits === 1n) return 'loopback';
	if (bits === 0n) return 'reserved';
	const [first, second] = groups as [number, number];
	if ((first & 0xff00) === 0xff00) return 'multicast';
	if ((first & 0xffc0) === 0xfe80) return 'link-local';
	if ((first & 0xfe00) === 0xfc00) return 'unique-local';
	if (first === 0x2001 && second === 0x0db8) return 'documentation';
	if (first === 0x2001 && second < 0x0200) return 'reserved';
	if (first === 0x0100 && second === 0 && groups[2] === 0 && groups[3] === 0)
		return 'reserved';
	return 'global';
}
