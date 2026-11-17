type JsonScalar = null | boolean | number | string;
export type StrictJsonValue =
  JsonScalar | readonly StrictJsonValue[] | { readonly [key: string]: StrictJsonValue };

const poisonKeys = new Set(['__proto__', 'constructor', 'prototype']);

class StrictJsonParser {
  private offset = 0;

  constructor(
    private readonly source: string,
    private readonly maximumDepth: number,
  ) {}

  parse(): StrictJsonValue {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.offset !== this.source.length) throw new Error('trailing JSON bytes');
    return value;
  }

  private parseValue(depth: number): StrictJsonValue {
    if (depth > this.maximumDepth) throw new Error('JSON nesting limit exceeded');
    const character = this.source[this.offset];
    if (character === '"') return this.parseString();
    if (character === '{') return this.parseObject(depth);
    if (character === '[') return this.parseArray(depth);
    if (character === 't') return this.parseKeyword('true', true);
    if (character === 'f') return this.parseKeyword('false', false);
    if (character === 'n') return this.parseKeyword('null', null);
    return this.parseNumber();
  }

  private parseObject(depth: number): StrictJsonValue {
    this.offset += 1;
    this.skipWhitespace();
    const output = {} as Record<string, StrictJsonValue>;
    const names = new Set<string>();
    if (this.source[this.offset] === '}') {
      this.offset += 1;
      return Object.freeze(output);
    }
    while (true) {
      if (this.source[this.offset] !== '"') throw new Error('invalid JSON object member');
      const name = this.parseString();
      if (poisonKeys.has(name) || names.has(name)) throw new Error('invalid JSON object key');
      names.add(name);
      this.skipWhitespace();
      if (this.source[this.offset] !== ':') throw new Error('invalid JSON object separator');
      this.offset += 1;
      this.skipWhitespace();
      Object.defineProperty(output, name, {
        value: this.parseValue(depth + 1),
        enumerable: true,
        configurable: false,
        writable: false,
      });
      this.skipWhitespace();
      const separator = this.source[this.offset];
      this.offset += 1;
      if (separator === '}') return Object.freeze(output);
      if (separator !== ',') throw new Error('invalid JSON object separator');
      this.skipWhitespace();
    }
  }

  private parseArray(depth: number): StrictJsonValue {
    this.offset += 1;
    this.skipWhitespace();
    const output: StrictJsonValue[] = [];
    if (this.source[this.offset] === ']') {
      this.offset += 1;
      return Object.freeze(output);
    }
    while (true) {
      output.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      const separator = this.source[this.offset];
      this.offset += 1;
      if (separator === ']') return Object.freeze(output);
      if (separator !== ',') throw new Error('invalid JSON array separator');
      this.skipWhitespace();
    }
  }

  private parseString(): string {
    const start = this.offset;
    this.offset += 1;
    while (this.offset < this.source.length) {
      const character = this.source[this.offset];
      if (character === '"') {
        this.offset += 1;
        return JSON.parse(this.source.slice(start, this.offset)) as string;
      }
      if (character === '\\') {
        this.offset += 1;
        const escaped = this.source[this.offset];
        if (escaped === 'u') {
          const hex = this.source.slice(this.offset + 1, this.offset + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('invalid JSON string escape');
          this.offset += 5;
          continue;
        }
        if (!escaped || !'"\\/bfnrt'.includes(escaped))
          throw new Error('invalid JSON string escape');
        this.offset += 1;
        continue;
      }
      if (!character || character.charCodeAt(0) <= 0x1f)
        throw new Error('invalid JSON string character');
      this.offset += 1;
    }
    throw new Error('unterminated JSON string');
  }

  private parseKeyword<T extends JsonScalar>(token: string, value: T): T {
    if (this.source.slice(this.offset, this.offset + token.length) !== token)
      throw new Error('invalid JSON value');
    this.offset += token.length;
    return value;
  }

  private parseNumber(): number {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      this.source.slice(this.offset),
    );
    if (!match) throw new Error('invalid JSON number');
    const token = match[0];
    this.offset += token.length;
    const value = Number(token);
    if (
      !Number.isFinite(value) ||
      Object.is(value, -0) ||
      Math.abs(value) > Number.MAX_SAFE_INTEGER ||
      !sameDecimalValue(token, value)
    )
      throw new Error('unsafe JSON number');
    return value;
  }

  private skipWhitespace() {
    while (/\s/.test(this.source[this.offset] ?? '') && this.offset < this.source.length) {
      const code = this.source.charCodeAt(this.offset);
      if (code !== 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d)
        throw new Error('invalid JSON whitespace');
      this.offset += 1;
    }
  }
}

type DecimalParts = Readonly<{ sign: '' | '-'; digits: string; exponent: number }>;

const decimalParts = (token: string): DecimalParts => {
  const match = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(token);
  if (!match) throw new Error('invalid JSON number');
  const sign = match[1] as '' | '-';
  const integer = match[2] ?? '';
  const fraction = match[3] ?? '';
  const exponentToken = match[4] ?? '0';
  const exponent = Number(exponentToken);
  const sourceDigits = `${integer}${fraction}`.replace(/^0+/, '');
  if (sourceDigits === '') return { sign, digits: '0', exponent: 0 };
  if (!Number.isSafeInteger(exponent)) throw new Error('unsafe JSON number');
  const trailingZeroes = sourceDigits.length - sourceDigits.replace(/0+$/, '').length;
  return {
    sign,
    digits: sourceDigits.slice(0, sourceDigits.length - trailingZeroes),
    exponent: exponent - fraction.length + trailingZeroes,
  };
};

const sameDecimalValue = (token: string, value: number) => {
  const source = decimalParts(token);
  if (source.digits === '0') return value === 0 && source.sign !== '-';
  const retained = decimalParts(value.toString());
  return (
    source.sign === retained.sign &&
    source.digits === retained.digits &&
    source.exponent === retained.exponent
  );
};

export const parseStrictJsonBytes = (
  bytes: Uint8Array,
  options: Readonly<{ maximumDepth: number }>,
): StrictJsonValue => {
  if (!(bytes instanceof Uint8Array)) throw new Error('invalid JSON bytes');
  if (!Number.isSafeInteger(options.maximumDepth) || options.maximumDepth < 1)
    throw new Error('invalid JSON nesting limit');
  const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return new StrictJsonParser(source, options.maximumDepth).parse();
};
