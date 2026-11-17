import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  decodeReceiptStructure,
  decodeReceiptStructureV2,
  encodeReceiptStructure,
  encodeReceiptStructureV2,
  type BusinessTransitionReceipt,
} from './payload.js';
import { businessTransitionCoseContextV2 } from './generated-v2.js';
import {
  receiptProtectedHeaderV2,
  signReceiptCoseV2,
  verifyReceiptCose,
  verifyReceiptCoseV2,
} from './cose.js';
const id = '018f0000-0000-7000-8000-000000000001';
const h = Buffer.alloc(32, 1);
// Structural oracle only: this deliberately unadmitted profile grants no business authority.
const receipt: BusinessTransitionReceipt = {
  receiptId: id,
  schemaDefinitionDigest: Buffer.from(
    businessTransitionCoseContextV2.definitionDigest.slice(7),
    'hex',
  ),
  transitionProfileId: 'structural-v2',
  transitionProfileVersion: 1,
  transitionProfileDigest: h,
  environmentId: 'test',
  participantId: id,
  privacyDomainId: id,
  operationId: id,
  actionIntentId: 'ACT-TEST-V1',
  catalogOperationId: 'TEST-OP',
  aggregateType: 'test',
  aggregateId: id,
  actorKeyDigest: h,
  preCommitAuthorityDigest: h,
  actionIntentDigest: h,
  candidateDigest: h,
  idempotencyRecordId: id,
  before: { existence: 1, revision: 1n, stateDigest: h },
  after: { existence: 1, revision: 2n, stateDigest: h },
  authorizationEvidence: [{ kind: 2, evidenceId: 'proof', evidenceDigest: h }],
  outboxEvents: [],
  transitionKind: 1,
  recordedAtNs: 1000n,
  signerId: 'test',
  signerTrustSnapshotDigest: h,
  requestDigest: h,
};
const golden =
  'b81b0050018f00000000700080000000000000010158204e7de36861819909275bdec8103d1df04984c03b34cb593437dfe68f5c2c1d9a026d7374727563747572616c2d7632030104582001010101010101010101010101010101010101010101010101010101010101010564746573740650018f00000000700080000000000000010750018f00000000700080000000000000010850018f0000000070008000000000000001096b4143542d544553542d56310a67544553542d4f500b64746573740c50018f00000000700080000000000000010d582001010101010101010101010101010101010101010101010101010101010101010e582001010101010101010101010101010101010101010101010101010101010101010f5820010101010101010101010101010101010101010101010101010101010101010110582001010101010101010101010101010101010101010101010101010101010101011150018f000000007000800000000000000112a300010101025820010101010101010101010101010101010101010101010101010101010101010113a30001010202582001010101010101010101010101010101010101010101010101010101010101011481a30002016570726f6f66025820010101010101010101010101010101010101010101010101010101010101010115801601171903e818186474657374181958200101010101010101010101010101010101010101010101010101010101010101181a58200101010101010101010101010101010101010101010101010101010101010101';
function bstr(bytes: Buffer): Buffer {
  if (bytes.length < 24) return Buffer.concat([Buffer.from([0x40 | bytes.length]), bytes]);
  if (bytes.length < 256) return Buffer.concat([Buffer.from([0x58, bytes.length]), bytes]);
  const size = Buffer.alloc(3);
  size[0] = 0x59;
  size.writeUInt16BE(bytes.length, 1);
  return Buffer.concat([size, bytes]);
}
describe('explicit receipt version 2 compatibility boundary', () => {
  it('matches independently encoded complete v2 bytes with zero event references', () => {
    expect(encodeReceiptStructureV2(receipt).toString('hex')).toBe(golden);
    expect(decodeReceiptStructureV2(Buffer.from(golden, 'hex'))).toEqual(receipt);
    expect(() => encodeReceiptStructure(receipt)).toThrow();
    expect(() => decodeReceiptStructure(Buffer.from(golden, 'hex'))).toThrow();
  });
  it('rejects definition substitution and still requires authorization evidence', () => {
    expect(() => encodeReceiptStructureV2({ ...receipt, schemaDefinitionDigest: h })).toThrow();
    expect(() => encodeReceiptStructureV2({ ...receipt, authorizationEvidence: [] })).toThrow();
  });
  it('pins independently signed COSE to 24001@2 and rejects version substitution', () => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
    const kid = 'sha256:' + createHash('sha256').update(spki).digest('hex');
    const header = Buffer.concat([
      Buffer.from(
        'a801260284186418651866186703736170706c69636174696f6e2f70632b63626f72045847',
        'hex',
      ),
      Buffer.from(kid),
      Buffer.from('1864195dc11865021866190152186702', 'hex'),
    ]);
    expect(receiptProtectedHeaderV2(spki)).toEqual(header);
    const payload = Buffer.from(golden, 'hex');
    const structure = Buffer.concat([
      Buffer.from('846a5369676e617475726531', 'hex'),
      bstr(header),
      bstr(Buffer.from('pcplane:cose-sign1:v2\0')),
      bstr(payload),
    ]);
    const signature = sign('sha256', structure, {
      key: pair.privateKey,
      dsaEncoding: 'ieee-p1363',
    });
    const cose = Buffer.concat([
      Buffer.from('d284', 'hex'),
      bstr(header),
      Buffer.from('a0', 'hex'),
      bstr(payload),
      bstr(signature),
    ]);
    expect(verifyReceiptCoseV2(spki, payload, cose)).toBe(true);
    expect(verifyReceiptCose(spki, payload, cose)).toBe(false);
    const output = signReceiptCoseV2(
      pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
      spki,
      payload,
    );
    expect(verifyReceiptCoseV2(spki, payload, output)).toBe(true);
    const altered = Buffer.from(cose);
    altered[altered.indexOf(Buffer.from('186502', 'hex')) + 2] = 1;
    expect(verifyReceiptCoseV2(spki, payload, altered)).toBe(false);
  });
});
