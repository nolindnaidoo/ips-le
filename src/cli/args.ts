/**
 * The command line, parsed as the Rust CLI parses it: strictly, in order, and
 * refusing rather than defaulting.
 */
import {
	CLASSES,
	type Class,
	KINDS,
	type Kind,
	resolveFormat,
} from '../extract';
import { FLAGS } from './usage';

export interface WalkOptions {
	readonly hidden: boolean;
	readonly respectIgnore: boolean;
}

export interface ScanOptions {
	/** The forced format, or null to infer one per file name. */
	readonly format: string | null;
	readonly kinds: readonly Kind[];
	readonly classes: readonly Class[];
}

export interface Cli {
	readonly strict: boolean;
	readonly inputs: readonly string[];
	readonly stdin: boolean;
	readonly scan: ScanOptions;
	readonly walk: WalkOptions;
}

export function parse(args: readonly string[]): Cli {
	const inputs: string[] = [];
	const kinds: Kind[] = [];
	const classes: Class[] = [];
	let stdin = false;
	let strict = false;
	let format: string | null = null;
	let walk: WalkOptions = { hidden: false, respectIgnore: true };

	for (let index = 0; index < args.length; index++) {
		const arg = args[index] as string;
		if (arg.startsWith('-') && !FLAGS.includes(arg)) {
			throw new Error(`${arg} is not an option. Try --help.`);
		}
		if (arg === '--format' || arg === '--kind' || arg === '--class') {
			index += 1;
			const value = args[index];
			if (value === undefined) throw new Error(`${arg} needs a value`);
			if (arg === '--format') format = resolveFormat(value, undefined);
			if (arg === '--kind') kinds.push(named(value, KINDS, 'kind'));
			if (arg === '--class') classes.push(named(value, CLASSES, 'class'));
			continue;
		}
		if (arg === '--stdin') stdin = true;
		if (arg === '--strict') strict = true;
		if (arg === '--hidden') walk = { ...walk, hidden: true };
		if (arg === '--no-ignore') walk = { ...walk, respectIgnore: false };
		if (!arg.startsWith('-')) inputs.push(arg);
	}

	if (stdin && inputs.length > 0) {
		throw new Error('reading from stdin takes no file arguments');
	}
	if (!stdin && inputs.length === 0) {
		throw new Error('name a file or a directory to read. Try --help.');
	}
	return Object.freeze({
		strict,
		inputs,
		stdin,
		scan: { format, kinds, classes },
		walk,
	});
}

/** The crate's `Kind::parse` and `Class::parse`, over a lowercased value. */
function named<T extends string>(
	value: string,
	allowed: readonly T[],
	noun: string,
): T {
	const found = allowed.find((candidate) => candidate === value.toLowerCase());
	if (found === undefined) {
		throw new Error(`${value} is not a ${noun}. Try ${allowed.join(', ')}.`);
	}
	return found;
}
