/**
 * `Ipv4Addr` and `Ipv6Addr` as Rust's standard library parses and prints them —
 * `core::net::parser` and `Ipv6Addr`'s `Display`, transcribed.
 *
 * Not `URL` or `node:net`: what the crate accepts and how it spells the result
 * is std's, and the RFC 5952 form the report promises is std's `Display`. Both
 * are held to the crate by the corpus and the differential.
 */

/** Four octets, or nothing. */
export type V4 = readonly [number, number, number, number];
/** Eight 16-bit groups, or nothing. */
export type V6 = readonly number[];

class Parser {
	position = 0;
	constructor(private readonly text: string) {}

	private atomically<T>(inner: () => T | undefined): T | undefined {
		const start = this.position;
		const result = inner();
		if (result === undefined) this.position = start;
		return result;
	}

	private peek(): string | undefined {
		return this.position < this.text.length
			? this.text.charAt(this.position)
			: undefined;
	}

	private readGiven(character: string): true | undefined {
		return this.atomically(() => {
			if (this.peek() !== character) return undefined;
			this.position++;
			return true;
		});
	}

	private readSeparator<T>(
		separator: string,
		index: number,
		inner: () => T | undefined,
	): T | undefined {
		return this.atomically(() => {
			if (index > 0 && this.readGiven(separator) === undefined)
				return undefined;
			return inner();
		});
	}

	/** `read_number`: greedy digits, a digit cap, overflow and the zero-prefix rule. */
	private readNumber(
		radix: number,
		maxDigits: number,
		allowZeroPrefix: boolean,
		max: number,
	): number | undefined {
		return this.atomically(() => {
			let result = 0;
			let digits = 0;
			const hasLeadingZero = this.peek() === '0';
			for (;;) {
				const character = this.peek();
				const digit =
					character === undefined
						? Number.NaN
						: Number.parseInt(character, radix);
				if (Number.isNaN(digit) || !/^[0-9A-Za-z]$/.test(character as string))
					break;
				this.position++;
				result = result * radix + digit;
				if (result > max) return undefined;
				digits++;
				if (digits > maxDigits) return undefined;
			}
			if (digits === 0) return undefined;
			if (!allowZeroPrefix && hasLeadingZero && digits > 1) return undefined;
			return result;
		});
	}

	readIpv4(): V4 | undefined {
		return this.atomically(() => {
			const octets: number[] = [];
			for (let index = 0; index < 4; index++) {
				const octet = this.readSeparator('.', index, () =>
					this.readNumber(10, 3, false, 0xff),
				);
				if (octet === undefined) return undefined;
				octets.push(octet);
			}
			return octets as unknown as V4;
		});
	}

	/** `read_groups`: an embedded IPv4 is tried first wherever two groups remain. */
	private readGroups(groups: number[], limit: number): [number, boolean] {
		for (let index = 0; index < limit; index++) {
			if (index < limit - 1) {
				const v4 = this.readSeparator(':', index, () => this.readIpv4());
				if (v4 !== undefined) {
					groups[index] = (v4[0] << 8) | v4[1];
					groups[index + 1] = (v4[2] << 8) | v4[3];
					return [index + 2, true];
				}
			}
			const group = this.readSeparator(':', index, () =>
				this.readNumber(16, 4, true, 0xffff),
			);
			if (group === undefined) return [index, false];
			groups[index] = group;
		}
		return [limit, false];
	}

	readIpv6(): V6 | undefined {
		return this.atomically(() => {
			const head = new Array<number>(8).fill(0);
			const [headSize, headIpv4] = this.readGroups(head, 8);
			if (headSize === 8) return head;
			if (headIpv4) return undefined;
			if (
				this.readGiven(':') === undefined ||
				this.readGiven(':') === undefined
			)
				return undefined;
			const tail = new Array<number>(7).fill(0);
			const [tailSize] = this.readGroups(tail, 8 - (headSize + 1));
			for (let index = 0; index < tailSize; index++)
				head[8 - tailSize + index] = tail[index] as number;
			return head;
		});
	}

	get done(): boolean {
		return this.position === this.text.length;
	}
}

function parseWith<T>(
	text: string,
	read: (parser: Parser) => T | undefined,
): T | undefined {
	const parser = new Parser(text);
	const result = read(parser);
	return result !== undefined && parser.done ? result : undefined;
}

export function parseIpv4(text: string): V4 | undefined {
	if (text.length > 15) return undefined;
	return parseWith(text, (parser) => parser.readIpv4());
}

export function parseIpv6(text: string): V6 | undefined {
	return parseWith(text, (parser) => parser.readIpv6());
}

export const formatIpv4 = (octets: V4): string => octets.join('.');

export function v4FromBits(bits: number): V4 {
	return [
		(bits >>> 24) & 0xff,
		(bits >>> 16) & 0xff,
		(bits >>> 8) & 0xff,
		bits & 0xff,
	];
}

export const v4Bits = (octets: V4): number =>
	((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;

/** `to_ipv4_mapped`: `::ffff:a.b.c.d`. */
export function mappedV4(groups: V6): V4 | undefined {
	if (groups.slice(0, 5).some((group) => group !== 0) || groups[5] !== 0xffff)
		return undefined;
	const high = groups[6] as number;
	const low = groups[7] as number;
	return [high >> 8, high & 0xff, low >> 8, low & 0xff];
}

/** `Ipv6Addr`'s `Display`: RFC 5952, the first longest zero run of two or more compressed. */
export function formatIpv6(groups: V6): string {
	const mapped = mappedV4(groups);
	if (mapped !== undefined) return `::ffff:${formatIpv4(mapped)}`;
	let longest = { start: 0, length: 0 };
	let current = { start: 0, length: 0 };
	groups.forEach((group, index) => {
		if (group !== 0) {
			current = { start: 0, length: 0 };
			return;
		}
		if (current.length === 0) current.start = index;
		current.length++;
		if (current.length > longest.length) longest = { ...current };
	});
	const hex = (part: readonly number[]) =>
		part.map((group) => group.toString(16)).join(':');
	if (longest.length > 1) {
		return `${hex(groups.slice(0, longest.start))}::${hex(groups.slice(longest.start + longest.length))}`;
	}
	return hex(groups);
}

export function v6Bits(groups: V6): bigint {
	return groups.reduce((bits, group) => (bits << 16n) | BigInt(group), 0n);
}

export function v6FromBits(bits: bigint): V6 {
	return Array.from({ length: 8 }, (_, index) =>
		Number((bits >> BigInt(16 * (7 - index))) & 0xffffn),
	);
}
