import { looksLikeIpv6, macOctets } from './policy';

/**
 * Which runs of text are worth asking the policy about — the crate's
 * `scanner.rs`. Every format goes through here, over the whole document: an
 * address is almost never a value, it is inside one.
 *
 * Offsets are UTF-16 indices. Every unit this compares is ASCII, so they find
 * the same runs the crate's byte scan does.
 */

export interface Candidate {
	readonly offset: number;
	readonly text: string;
}

const isHex = (unit: number) =>
	(unit >= 0x30 && unit <= 0x39) ||
	(unit >= 0x41 && unit <= 0x46) ||
	(unit >= 0x61 && unit <= 0x66);
const isSeparator = (unit: number) =>
	unit === 0x2e || unit === 0x3a || unit === 0x2d;
const isAddress = (unit: number) => isHex(unit) || isSeparator(unit);
const isIdentifier = (unit: number) =>
	(unit >= 0x30 && unit <= 0x39) ||
	(unit >= 0x41 && unit <= 0x5a) ||
	(unit >= 0x61 && unit <= 0x7a) ||
	unit === 0x5f;

export function candidates(text: string): Candidate[] {
	const out: Candidate[] = [];
	let start = 0;
	while (start < text.length) {
		if (!isAddress(text.charCodeAt(start))) {
			start++;
			continue;
		}
		let end = start;
		while (end < text.length && isAddress(text.charCodeAt(end))) end++;
		const run = bound(text, start, end);
		start = end;
		if (run !== undefined)
			start = Math.max(emit(text, run[0], run[1], out), start);
	}
	return out;
}

/** Narrow a run to the part that is not part of a name, or drop it. */
function bound(
	text: string,
	start: number,
	end: number,
): [number, number] | undefined {
	if (end < text.length && isIdentifier(text.charCodeAt(end))) return undefined;
	if (start === 0 || !isIdentifier(text.charCodeAt(start - 1)))
		return [start, end];
	let leadEnd = start;
	while (leadEnd < end && isSeparator(text.charCodeAt(leadEnd))) leadEnd++;
	if (leadEnd === start) return undefined;
	if (text.slice(start, leadEnd).includes('::')) return undefined;
	return leadEnd < end ? [leadEnd, end] : undefined;
}

/** Trim, split and record one run. Returns the offset consumed to. */
function emit(
	text: string,
	start: number,
	end: number,
	out: Candidate[],
): number {
	const trimmed = trim(start, text.slice(start, end));
	if (trimmed === undefined) return end;
	const [offset, token] = trimmed;

	if (!splits(token)) {
		const suffix = cidrSuffix(text, offset + token.length);
		if (suffix !== undefined) {
			const stop = offset + token.length + suffix;
			out.push({ offset, text: text.slice(offset, stop) });
			return stop;
		}
		out.push({ offset, text: token });
		return end;
	}

	const separator = token.includes('-') ? '-' : ':';
	let cursor = offset;
	for (const part of token.split(separator)) {
		const piece = trim(cursor, part);
		if (piece !== undefined) out.push({ offset: piece[0], text: piece[1] });
		cursor += part.length + 1;
	}
	return end;
}

function splits(token: string): boolean {
	if (macOctets(token) !== undefined) return false;
	if (token.includes('-')) return true;
	return token.includes(':') && !looksLikeIpv6(token);
}

/** Drop the `.`, `-` and trailing `:` a run collected; a leading `:` stays. */
function trim(offset: number, token: string): [number, string] | undefined {
	let trimmed = token.replace(/[.-]+$/, '');
	if (!trimmed.endsWith('::')) trimmed = trimmed.replace(/:+$/, '');
	const lead = trimmed.length - trimmed.replace(/^[.-]+/, '').length;
	trimmed = trimmed.slice(lead);
	return trimmed === '' ? undefined : [offset + lead, trimmed];
}

/** A `/` and one to three digits not followed by a name character. */
function cidrSuffix(text: string, at: number): number | undefined {
	if (text.charAt(at) !== '/') return undefined;
	let end = at + 1;
	while (end < text.length && /[0-9]/.test(text.charAt(end)) && end - at <= 3)
		end++;
	if (end === at + 1) return undefined;
	if (end < text.length && isIdentifier(text.charCodeAt(end))) return undefined;
	return end - at;
}
