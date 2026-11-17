import { TextDecoder } from 'node:util';

/** Closed PC-CBOR-1 subset shared by schema-owned identity and control codecs. */
export type CborValue =
  bigint | number | string | Buffer | readonly CborValue[] | ReadonlyMap<number, CborValue>;
export const MAX_CBOR_BYTES = 65_536;
export const MAX_UINT64 = (1n << 64n) - 1n;
// CBOR strings carry their own encoding; U+FEFF is content, never a byte-order marker.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function argument(major: number, value: bigint): Buffer {
  if (value < 0n || value > MAX_UINT64) throw new Error('CBOR integer out of range');
  if (value < 24n) return Buffer.from([(major << 5) | Number(value)]);
  const size = value <= 0xffn ? 1 : value <= 0xffffn ? 2 : value <= 0xffff_ffffn ? 4 : 8;
  const result = Buffer.alloc(size + 1);
  result[0] = (major << 5) | ({ 1: 24, 2: 25, 4: 26, 8: 27 } as const)[size];
  if (size === 8) result.writeBigUInt64BE(value, 1);
  else result.writeUIntBE(Number(value), 1, size);
  return result;
}

export function encodeCbor(value: CborValue, maxBytes = MAX_CBOR_BYTES): Buffer {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_CBOR_BYTES + 1024)
    throw new Error('Invalid CBOR budget');
  let byteBudget = maxBytes;
  const charge = (bytes: Buffer): Buffer => {
    byteBudget -= bytes.length;
    if (byteBudget < 0) throw new Error('CBOR exceeds byte limit');
    return bytes;
  };
  function encode(item: CborValue, depth: number): Buffer {
    if (depth > 8) throw new Error('CBOR exceeds nesting limit');
    if (typeof item === 'number' || typeof item === 'bigint') {
      if (typeof item === 'number' && !Number.isSafeInteger(item))
        throw new Error('CBOR requires exact integer');
      const integer = BigInt(item);
      return charge(argument(integer < 0 ? 1 : 0, integer < 0 ? -1n - integer : integer));
    }
    if (typeof item === 'string') {
      if (item.normalize('NFC') !== item) throw new Error('CBOR text is not NFC');
      const bytes = Buffer.from(item, 'utf8');
      if (decoder.decode(bytes) !== item) throw new Error('CBOR text contains invalid Unicode');
      return Buffer.concat([charge(argument(3, BigInt(bytes.length))), charge(bytes)]);
    }
    if (Buffer.isBuffer(item))
      return Buffer.concat([charge(argument(2, BigInt(item.length))), charge(item)]);
    if (Array.isArray(item)) {
      if (item.length > 256) throw new Error('CBOR exceeds collection limit');
      for (let index = 0; index < item.length; index++)
        if (!Object.hasOwn(item, index)) throw new Error('CBOR array contains a hole');
      return Buffer.concat([
        charge(argument(4, BigInt(item.length))),
        ...item.map((entry) => encode(entry, depth + 1)),
      ]);
    }
    if (item instanceof Map) {
      if (item.size > 256) throw new Error('CBOR exceeds collection limit');
      const entries = [...item.entries()].sort(([a], [b]) => a - b);
      const parts = [charge(argument(5, BigInt(entries.length)))];
      for (const [key, entry] of entries) {
        if (!Number.isSafeInteger(key) || key < 0 || key > 0xffff_ffff)
          throw new Error('CBOR map key must be uint32');
        parts.push(charge(argument(0, BigInt(key))), encode(entry, depth + 1));
      }
      return Buffer.concat(parts);
    }
    throw new Error('Unsupported CBOR value');
  }
  return encode(value, 0);
}

/** Rejects alternate encodings before a domain codec interprets the exact map. */
export function decodeCbor(input: Buffer, maxBytes = MAX_CBOR_BYTES): CborValue {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_CBOR_BYTES + 1024)
    throw new Error('Invalid CBOR budget');
  if (!Buffer.isBuffer(input) || input.length === 0 || input.length > maxBytes)
    throw new Error('Invalid CBOR size');
  let offset = 0;
  function read(depth: number): CborValue {
    if (depth > 8) throw new Error('CBOR exceeds nesting limit');
    const initial = input[offset++];
    if (initial === undefined) throw new Error('Truncated CBOR');
    const major = initial >> 5;
    const additional = initial & 31;
    if (major > 5 || additional > 27) throw new Error('Unsupported CBOR item');
    let value: bigint;
    if (additional < 24) value = BigInt(additional);
    else {
      const size = 1 << (additional - 24);
      if (offset + size > input.length) throw new Error('Truncated CBOR argument');
      value = size === 8 ? input.readBigUInt64BE(offset) : BigInt(input.readUIntBE(offset, size));
      offset += size;
      const minimum = [24n, 256n, 65_536n, 4_294_967_296n][additional - 24]!;
      if (value < minimum) throw new Error('Non-shortest CBOR argument');
    }
    if (major === 0) return value;
    if (major === 1) return -1n - value;
    if (value > BigInt(maxBytes)) throw new Error('CBOR item exceeds size limit');
    const length = Number(value);
    if (major === 2 || major === 3) {
      if (offset + length > input.length) throw new Error('Truncated CBOR string');
      const bytes = input.subarray(offset, offset + length);
      offset += length;
      if (major === 2) return Buffer.from(bytes);
      const text = decoder.decode(bytes);
      if (text.normalize('NFC') !== text) throw new Error('CBOR text is not NFC');
      return text;
    }
    if (length > 256) throw new Error('CBOR exceeds collection limit');
    if (major === 4) return Array.from({ length }, () => read(depth + 1));
    const result = new Map<number, CborValue>();
    let previous = -1;
    for (let index = 0; index < length; index++) {
      const key = read(depth + 1);
      if (typeof key !== 'bigint' || key < 0 || key > 0xffff_ffffn || key <= previous)
        throw new Error('CBOR map keys are not strictly ordered uint32');
      previous = Number(key);
      result.set(previous, read(depth + 1));
    }
    return result;
  }
  const result = read(0);
  if (offset !== input.length) throw new Error('Trailing CBOR data');
  return result;
}
