import { isWhitespace } from './text';

/**
 * `jsonc-parser` 0.33.2's `parse_to_ast`, transcribed for the options the
 * crate's `json.rs` passes: comments and trailing commas allowed; loose
 * property names, missing commas, single quotes, hex and unary plus refused.
 *
 * Not `JSON.parse`: a document that does not parse is reported with this
 * parser's own message and position, which the differential holds to the
 * crate's, and a leaf's range is its token — quotes included — which is what a
 * key path covers.
 *
 * Indices are UTF-16 units; an error's column counts characters, as the
 * crate's does without the `error_unicode_width` feature.
 */

export type JsonValue =
	| {
			readonly type: 'object';
			readonly properties: ReadonlyArray<{
				readonly name: string;
				readonly value: JsonValue;
			}>;
	  }
	| { readonly type: 'array'; readonly elements: readonly JsonValue[] }
	| { readonly type: 'leaf'; readonly start: number; readonly end: number };

type Token =
	| { readonly t: '{' | '}' | '[' | ']' | ',' | ':' | 'boolean' | 'null' }
	| { readonly t: 'string'; readonly value: string }
	| { readonly t: 'number' | 'word'; readonly value: string }
	| { readonly t: 'comment' };

export class JsoncError extends Error {
	constructor(kind: string, start: number, text: string) {
		let line = 1;
		let column = 1;
		for (const character of text.slice(0, start)) {
			if (character === '\n') {
				line++;
				column = 1;
			} else {
				column++;
			}
		}
		super(`${kind} on line ${line} column ${column}`);
	}
}

const MAXIMUM_NESTING_DEPTH = 512;
const ALPHANUMERIC = /^[\p{Alphabetic}\p{Nd}\p{Nl}\p{No}]$/u;

class Scanner {
	index = 0;
	tokenStart = 0;
	current: Token | undefined;

	constructor(readonly text: string) {}

	error(kind: string, start: number): JsoncError {
		return new JsoncError(kind, start, this.text);
	}

	private charAt(index: number): string | undefined {
		const code = this.text.codePointAt(index);
		return code === undefined ? undefined : String.fromCodePoint(code);
	}

	scan(): Token | undefined {
		this.skipWhitespace();
		this.tokenStart = this.index;
		const character = this.text.charAt(this.index);
		if (this.index >= this.text.length) {
			this.current = undefined;
			return undefined;
		}
		let token: Token;
		if ('{}[],:'.includes(character)) {
			this.index++;
			token = { t: character as '{' };
		} else if (character === "'") {
			throw this.error(
				'Single-quoted strings are not allowed',
				this.tokenStart,
			);
		} else if (character === '"') {
			token = this.string();
		} else if (character === '/') {
			const next = this.text.charAt(this.index + 1);
			if (next === '/') token = this.commentLine();
			else if (next === '*') token = this.commentBlock();
			else throw this.error('Unexpected token', this.tokenStart);
		} else if (
			character === '-' ||
			character === '+' ||
			(character >= '0' && character <= '9')
		) {
			token = this.number();
		} else if (character === 't' && this.moveWord('true')) {
			token = { t: 'boolean' };
		} else if (character === 'f' && this.moveWord('false')) {
			token = { t: 'boolean' };
		} else if (character === 'n' && this.moveWord('null')) {
			token = { t: 'null' };
		} else {
			token = this.word();
		}
		this.current = token;
		return token;
	}

	private skipWhitespace(): void {
		while (this.index < this.text.length) {
			const unit = this.text.charCodeAt(this.index);
			if (unit <= 0x20) {
				if (
					unit === 0x20 ||
					unit === 0x09 ||
					unit === 0x0a ||
					unit === 0x0d ||
					unit === 0x0b ||
					unit === 0x0c
				) {
					this.index++;
					continue;
				}
				return;
			}
			if (unit >= 0x80) {
				const character = this.charAt(this.index) as string;
				if (isWhitespace(character)) {
					this.index += character.length;
					continue;
				}
			}
			return;
		}
	}

	private string(): Token {
		const start = this.index + 1;
		for (let at = start; at < this.text.length; at++) {
			const character = this.text.charAt(at);
			if (character === '"') {
				this.index = at + 1;
				return { t: 'string', value: this.text.slice(start, at) };
			}
			if (character === '\\') break;
		}
		return this.slowString();
	}

	/** `parse_string_with_char_provider`, from the opening quote. */
	private slowString(): Token {
		const tokenStart = this.index;
		let lastStart = this.index + 1;
		let value = '';
		let lastWasBackslash = false;
		let at = this.index;
		const step = (): string | undefined => {
			const here = this.charAt(at);
			if (here === undefined) return undefined;
			at += here.length;
			return this.charAt(at);
		};
		for (let character = step(); character !== undefined; character = step()) {
			if (lastWasBackslash) {
				const escapeStart = at - 1;
				if (!'"\'\\/bfurnt'.includes(character))
					throw this.error('Invalid escape', escapeStart);
				if (character === "'")
					throw this.error(
						'Invalid escape in double quote string',
						escapeStart,
					);
				value += this.text.slice(lastStart, escapeStart);
				if (character === 'u') {
					const read = (): [number, string] => {
						let digits = '';
						for (let count = 0; count < 4; count++) {
							const digit = step();
							if (digit === undefined || !/^[0-9A-Fa-f]$/.test(digit)) {
								throw this.error('Expected four hex digits', escapeStart);
							}
							digits += digit;
						}
						return [Number.parseInt(digits, 16), digits];
					};
					const invalid = (detail: string) =>
						this.error(
							`Invalid unicode escape sequence. '${detail}' is not a valid UTF8 character`,
							escapeStart,
						);
					const [high, highDigits] = read();
					if (high >= 0xd800 && high <= 0xdbff) {
						if (step() !== '\\' || step() !== 'u')
							throw invalid(`${highDigits} (unpaired high surrogate)`);
						const [low] = read();
						if (low < 0xdc00 || low > 0xdfff)
							throw invalid(
								`${highDigits} (high surrogate not followed by low surrogate)`,
							);
						value += String.fromCodePoint(
							(high - 0xd800) * 0x400 + (low - 0xdc00) + 0x10000,
						);
					} else if (high >= 0xdc00 && high <= 0xdfff) {
						throw invalid(`${highDigits} (unpaired low surrogate)`);
					} else {
						value += String.fromCodePoint(high);
					}
					lastStart = at + (this.charAt(at)?.length ?? 0);
				} else {
					const escapes: Record<string, string> = {
						b: '\b',
						f: '\f',
						t: '\t',
						r: '\r',
						n: '\n',
					};
					value += escapes[character] ?? character;
					lastStart = at + character.length;
				}
				lastWasBackslash = false;
			} else if (character === '"') {
				step();
				this.index = at;
				return {
					t: 'string',
					value: value + this.text.slice(lastStart, at - 1),
				};
			} else {
				lastWasBackslash = character === '\\';
			}
		}
		throw this.error('Unterminated string literal', tokenStart);
	}

	private number(): Token {
		const start = this.index;
		const digit = (index: number) => /^[0-9]$/.test(this.text.charAt(index));
		const character = this.text.charAt(this.index);
		if (character === '+')
			throw this.error('Unary plus on numbers is not allowed', this.tokenStart);
		if (character === '-') this.index++;
		if (this.text.charAt(this.index) === '0') {
			this.index++;
			if (/^[xX]$/.test(this.text.charAt(this.index))) {
				throw this.error(
					'Hexadecimal numbers are not allowed',
					this.tokenStart,
				);
			}
		} else if (/^[1-9]$/.test(this.text.charAt(this.index))) {
			this.index++;
			while (digit(this.index)) this.index++;
		} else {
			throw this.error('Expected digit following negative sign', this.index);
		}
		if (this.text.charAt(this.index) === '.') {
			this.index++;
			if (!digit(this.index)) throw this.error('Expected digit', this.index);
			while (digit(this.index)) this.index++;
		}
		if (/^[eE]$/.test(this.text.charAt(this.index))) {
			this.index++;
			const sign = this.text.charAt(this.index);
			if (sign === '-' || sign === '+') {
				this.index++;
				if (!digit(this.index)) throw this.error('Expected digit', this.index);
			} else if (!digit(this.index)) {
				throw this.error(
					'Expected plus, minus, or digit in number literal',
					this.index,
				);
			}
			while (digit(this.index)) this.index++;
		}
		return { t: 'number', value: this.text.slice(start, this.index) };
	}

	private commentLine(): Token {
		this.index += 2;
		while (this.index < this.text.length) {
			const character = this.text.charAt(this.index);
			if (character === '\n') break;
			if (character === '\r' && this.text.charAt(this.index + 1) === '\n')
				break;
			this.index++;
		}
		return { t: 'comment' };
	}

	private commentBlock(): Token {
		this.index += 2;
		for (;;) {
			if (this.index >= this.text.length)
				throw this.error('Unterminated comment block', this.tokenStart);
			if (
				this.text.charAt(this.index) === '*' &&
				this.text.charAt(this.index + 1) === '/'
			) {
				this.index += 2;
				return { t: 'comment' };
			}
			this.index++;
		}
	}

	private moveWord(word: string): boolean {
		const end = this.index + word.length;
		if (this.text.slice(this.index, end) !== word) return false;
		const next = this.charAt(end);
		if (next !== undefined && ALPHANUMERIC.test(next)) return false;
		this.index = end;
		return true;
	}

	private word(): Token {
		const start = this.index;
		while (this.index < this.text.length) {
			const unit = this.text.charCodeAt(this.index);
			if (unit < 0x80) {
				const character = this.text.charAt(this.index);
				if (/^[ \t\n\f\r]$/.test(character) || character === ':') break;
				if (/^[0-9A-Za-z_-]$/.test(character)) this.index++;
				else throw this.error('Unexpected token', this.tokenStart);
			} else {
				const character = this.charAt(this.index) as string;
				if (isWhitespace(character)) break;
				if (ALPHANUMERIC.test(character)) this.index += character.length;
				else throw this.error('Unexpected token', this.tokenStart);
			}
		}
		if (this.index === start)
			throw this.error('Unexpected token', this.tokenStart);
		return { t: 'word', value: this.text.slice(start, this.index) };
	}
}

class Context {
	readonly scanner: Scanner;
	lastTokenEnd = 0;
	readonly ranges: number[] = [];

	constructor(text: string) {
		this.scanner = new Scanner(text);
	}

	/** The next token past any comments. */
	scan(): Token | undefined {
		let token = this.scanner.scan();
		while (token?.t === 'comment') token = this.scanner.scan();
		this.lastTokenEnd = this.scanner.index;
		return token;
	}

	get token(): Token | undefined {
		return this.scanner.current;
	}

	errorAtToken(kind: string): JsoncError {
		return this.scanner.error(kind, this.scanner.tokenStart);
	}

	/** An error over the innermost open range, which is popped. */
	errorAtRange(kind: string): JsoncError {
		return this.scanner.error(kind, this.ranges.pop() as number);
	}

	leaf(): JsonValue {
		return {
			type: 'leaf',
			start: this.scanner.tokenStart,
			end: this.scanner.index,
		};
	}
}

const isValueStart = (token: Token) =>
	['{', '[', 'string', 'boolean', 'number', 'null'].includes(token.t);

function parseValue(context: Context): JsonValue | undefined {
	if (context.ranges.length > MAXIMUM_NESTING_DEPTH)
		throw context.errorAtRange('Maximum nesting depth exceeded');
	const token = context.token;
	if (token === undefined) return undefined;
	switch (token.t) {
		case '{':
			return parseObject(context);
		case '[':
			return parseArray(context);
		case 'string':
		case 'boolean':
		case 'number':
		case 'null':
			return context.leaf();
		case ']':
			throw context.errorAtToken('Unexpected close bracket');
		case '}':
			throw context.errorAtToken('Unexpected close brace');
		case ',':
			throw context.errorAtToken('Unexpected comma');
		case ':':
			throw context.errorAtToken('Unexpected colon');
		default:
			throw context.errorAtToken('Unexpected word');
	}
}

function parseObject(context: Context): JsonValue {
	const properties: Array<{ name: string; value: JsonValue }> = [];
	context.ranges.push(context.scanner.tokenStart);
	context.scan();
	for (;;) {
		const token = context.token;
		if (token?.t === '}') break;
		if (token === undefined) throw context.errorAtRange('Unterminated object');
		if (token.t === 'string')
			properties.push(parseProperty(context, token.value));
		else if (token.t === 'word' || token.t === 'number')
			throw context.errorAtToken('Expected string for object property');
		else throw context.errorAtToken('Unexpected token in object');

		const afterValueEnd = context.lastTokenEnd;
		const next = context.scan();
		if (next?.t === ',') context.scan();
		else if (
			next?.t === 'string' ||
			next?.t === 'word' ||
			next?.t === 'number'
		) {
			throw context.scanner.error('Expected comma', afterValueEnd);
		}
	}
	context.ranges.pop();
	return { type: 'object', properties };
}

function parseProperty(
	context: Context,
	name: string,
): { name: string; value: JsonValue } {
	context.ranges.push(context.scanner.tokenStart);
	if (context.scan()?.t !== ':')
		throw context.errorAtToken(
			'Expected colon after the string or word in object property',
		);
	context.scan();
	const value = parseValue(context);
	if (value === undefined)
		throw context.errorAtToken('Expected value after colon in object property');
	context.ranges.pop();
	return { name, value };
}

function parseArray(context: Context): JsonValue {
	const elements: JsonValue[] = [];
	context.ranges.push(context.scanner.tokenStart);
	context.scan();
	for (;;) {
		const token = context.token;
		if (token?.t === ']') break;
		if (token === undefined) throw context.errorAtRange('Unterminated array');
		const value = parseValue(context);
		if (value === undefined) throw context.errorAtRange('Unterminated array');
		elements.push(value);

		const afterValueEnd = context.lastTokenEnd;
		const next = context.scan();
		if (next?.t === ',') context.scan();
		else if (next !== undefined && isValueStart(next))
			throw context.scanner.error('Expected comma', afterValueEnd);
	}
	context.ranges.pop();
	return { type: 'array', elements };
}

/** The root value, or nothing for an empty document; throws a `JsoncError`. */
export function parseJsonc(text: string): JsonValue | undefined {
	const context = new Context(text);
	context.scan();
	const value = parseValue(context);
	if (context.scan() !== undefined)
		throw context.errorAtToken('Text cannot contain more than one JSON value');
	return value;
}
