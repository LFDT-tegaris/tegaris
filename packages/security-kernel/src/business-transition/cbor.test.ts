import { describe, expect, it } from 'vitest';

import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from './cbor.js';
import { canonicalDefinitionJson } from './definition.js';

// Independently specified shortest-form vectors, not output from the encoder.
const vectors: readonly [CborValue, string][] = [
  [0n, '00'],
  [23n, '17'],
  [24n, '1818'],
  [255n, '18ff'],
  [256n, '190100'],
  [65_535n, '19ffff'],
  [65_536n, '1a00010000'],
  [4_294_967_296n, '1b0000000100000000'],
  [9_007_199_254_740_993n, '1b0020000000000001'],
  [MAX_UINT64, '1bffffffffffffffff'],
  [-7n, '26'],
  ['é', '62c3a9'],
  ['\uFEFFa', '64efbbbf61'],
  [Buffer.from([0, 1, 255]), '430001ff'],
  [[1n, 2n], '820102'],
  [
    new Map<number, CborValue>([
      [24, 2n],
      [1, 1n],
    ]),
    'a20101181802',
  ],
];
describe('control receipt canonical CBOR primitives', () => {
  it.each(vectors)('encodes and decodes exact canonical vector %s', (semantic, hex) => {
    expect(encodeCbor(semantic).toString('hex')).toBe(hex);
    expect(decodeCbor(Buffer.from(hex, 'hex'))).toEqual(semantic);
  });
  it.each([
    '1817',
    '1900ff',
    '1a0000ffff',
    '1b00000000ffffffff',
    '5f40ff',
    '9fff',
    'bf00ff',
    'd200',
    'f4',
    'f6',
    'fa00000000',
    '00ff',
    'a201000101',
    'a202000101',
    'a1616100',
    '62c0af',
    '63eda080',
    '6365cc81',
    '590001',
    '8100ff',
  ])('rejects noncanonical or undeclared encoding %s', (hex) => {
    expect(() => decodeCbor(Buffer.from(hex, 'hex'))).toThrow();
  });
  it('bounds integer precision, Unicode, byte lengths, nesting and item cardinality', () => {
    expect(() => encodeCbor(Number.MAX_SAFE_INTEGER + 1)).toThrow();
    expect(() => encodeCbor(MAX_UINT64 + 1n)).toThrow();
    expect(() => encodeCbor('\ud800')).toThrow();
    expect(() => encodeCbor('e\u0301')).toThrow();
    expect(() => encodeCbor(Buffer.alloc(65_536))).toThrow();
    expect(() => decodeCbor(Buffer.concat([Buffer.alloc(9, 0x81), Buffer.from([0])]))).toThrow();
    expect(() => decodeCbor(Buffer.from('9affffffff', 'hex'))).toThrow();
    expect(() => encodeCbor(new Array(2))).toThrow();
    expect(() => encodeCbor([0n, ...new Array(2)])).toThrow();
  });
});

describe('canonical product definition bytes', () => {
  it('fixes object order, JSON escaping, array order and NFC Unicode', () => {
    expect(canonicalDefinitionJson({ z: [2, 1], a: 'é\n', b: { y: null, x: true } })).toBe(
      '{"a":"é\\n","b":{"x":true,"y":null},"z":[2,1]}',
    );
  });
  it.each([
    1.5,
    Number.NaN,
    Number.MAX_SAFE_INTEGER + 1,
    -0,
    undefined,
    1n,
    '\ud800',
    'e\u0301',
    new Date(),
    new Array(2),
  ])('rejects ambiguous definition input %s', (input) => {
    expect(() => canonicalDefinitionJson(input)).toThrow();
  });
});
