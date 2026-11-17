import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  evidenceKeyId,
  receiptProtectedHeader,
  receiptSigStructure,
  signReceiptCose,
  verifyReceiptCose,
} from './cose.js';

const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
const pkcs8 = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
const payload = Buffer.from('a10001', 'hex');
const aad = Buffer.from('7063706c616e653a636f73652d7369676e313a763200', 'hex');
const kid = `sha256:${createHash('sha256').update(spki).digest('hex')}`;
// Independent byte-level profile2 header oracle. No production CBOR encoder.
const header = Buffer.concat([
  Buffer.from('a801260284186418651866186703736170706c69636174696f6e2f70632b63626f72045847', 'hex'),
  Buffer.from(kid),
  Buffer.from('1864195dc11865011866190152186702', 'hex'),
]);
function bstr(bytes: Buffer): Buffer {
  if (bytes.length < 24) return Buffer.concat([Buffer.from([0x40 | bytes.length]), bytes]);
  if (bytes.length <= 255) return Buffer.concat([Buffer.from([0x58, bytes.length]), bytes]);
  throw new Error('Reference vector exceeds independent byte-string encoder');
}
function structure(h = header, a = aad, p = payload): Buffer {
  return Buffer.concat([Buffer.from('846a5369676e617475726531', 'hex'), bstr(h), bstr(a), bstr(p)]);
}
function independentlySigned(h = header, a = aad, p = payload, der = false): Buffer {
  const signature = sign('sha256', structure(h, a, p), {
    key: pair.privateKey,
    dsaEncoding: der ? 'der' : 'ieee-p1363',
  });
  return Buffer.concat([
    Buffer.from('d284', 'hex'),
    bstr(h),
    Buffer.from('a0', 'hex'),
    bstr(p),
    bstr(signature),
  ]);
}
describe('control business receipt purpose-separated profile2 signature primitive', () => {
  it('matches independently encoded protected headers and Sig_structure', () => {
    expect(evidenceKeyId(spki)).toBe(kid);
    expect(receiptProtectedHeader(spki)).toEqual(header);
    expect(receiptSigStructure(spki, payload)).toEqual(structure());
    expect(verifyReceiptCose(spki, payload, independentlySigned())).toBe(true);
    const output = signReceiptCose(pkcs8, spki, payload);
    expect(
      verify(
        'sha256',
        structure(),
        { key: pair.publicKey, dsaEncoding: 'ieee-p1363' },
        output.subarray(-64),
      ),
    ).toBe(true);
    expect(verifyReceiptCose(spki, payload, output)).toBe(true);
  });
  it('rejects independently signed algorithm, purpose, schema, profile and KID substitutions', () => {
    for (const [before, after] of [
      ['0126', '0127'],
      ['195dc1', '195dc2'],
      ['186501', '186502'],
      ['190152', '190151'],
      ['186702', '186701'],
    ]) {
      const substituted = Buffer.from(header.toString('hex').replace(before!, after!), 'hex');
      expect(substituted.equals(header)).toBe(false);
      expect(verifyReceiptCose(spki, payload, independentlySigned(substituted))).toBe(false);
    }
    const wrongKid = Buffer.from(header);
    const offset = wrongKid.indexOf(Buffer.from('sha256:')) + 7;
    wrongKid[offset] = wrongKid[offset] === 0x61 ? 0x62 : 0x61;
    expect(verifyReceiptCose(spki, payload, independentlySigned(wrongKid))).toBe(false);
  });
  it('rejects empty or substituted AAD, DER signatures, tags, detached or mismatched payloads, trailing bytes and tampering', () => {
    const valid = independentlySigned();
    for (const invalid of [
      independentlySigned(header, Buffer.alloc(0)),
      independentlySigned(header, Buffer.from('other')),
      independentlySigned(header, aad, payload, true),
      valid.subarray(1),
      Buffer.concat([Buffer.from([0xd2]), valid]),
      Buffer.concat([valid, Buffer.from([0])]),
      independentlySigned(header, aad, Buffer.from('a10002', 'hex')),
    ]) {
      expect(verifyReceiptCose(spki, payload, invalid)).toBe(false);
    }
    const altered = Buffer.from(valid);
    altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
    expect(verifyReceiptCose(spki, payload, altered)).toBe(false);
    const foreign = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
      format: 'der',
      type: 'spki',
    });
    expect(verifyReceiptCose(foreign, payload, valid)).toBe(false);
    expect(() => signReceiptCose(pkcs8, foreign, payload)).toThrow();
  });
});
