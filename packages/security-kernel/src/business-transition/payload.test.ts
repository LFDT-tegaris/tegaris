import { describe, expect, it } from 'vitest';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from './cbor.js';
import { businessTransitionCoseContext } from './generated.js';
import {
  decodeReceiptStructure,
  encodeReceiptStructure,
  type BusinessTransitionReceipt,
} from './payload.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = (n: number) => Buffer.alloc(32, n);
// Structural conformance fixture only. This profile is deliberately unadmitted;
// these tests cannot establish a domain transition or trusted business receipt.
const receipt: BusinessTransitionReceipt = {
  receiptId: id(1),
  schemaDefinitionDigest: Buffer.from(
    businessTransitionCoseContext.definitionDigest.slice(7),
    'hex',
  ),
  transitionProfileId: 'unadmitted-structural-fixture',
  transitionProfileVersion: 1,
  transitionProfileDigest: h(1),
  environmentId: 'local-test',
  participantId: id(2),
  privacyDomainId: id(3),
  operationId: id(4),
  actionIntentId: 'ACT-IDENTITY_DELETE_SESSION-V1',
  catalogOperationId: 'ID-OP-SESSION-REVOKE',
  aggregateType: 'session',
  aggregateId: id(5),
  actorKeyDigest: h(2),
  preCommitAuthorityDigest: h(3),
  actionIntentDigest: h(4),
  candidateDigest: h(5),
  idempotencyRecordId: id(6),
  before: { existence: 1, revision: 9_007_199_254_740_993n, stateDigest: h(6) },
  after: { existence: 1, revision: MAX_UINT64, stateDigest: h(7) },
  authorizationEvidence: [
    { kind: 1, evidenceId: 'authentication-1', evidenceDigest: h(8) },
    { kind: 2, evidenceId: 'authorization-1', evidenceDigest: h(9) },
  ],
  outboxEvents: [
    {
      eventId: id(7),
      eventType: 'io.openpc.control.command.committed.v1',
      dataSchemaUri:
        'https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted',
      source: 'urn:openpc:service:identity',
      subject: `urn:openpc:resource:${id(5)}`,
      aggregateSequence: MAX_UINT64,
      occurredAtNs: 1_789_041_234_567_890_000n,
      correlationId: id(8),
      payloadDigest: h(10),
    },
  ],
  transitionKind: 1,
  recordedAtNs: 1_789_041_234_567_890_000n,
  signerId: 'control-test-evidence',
  signerTrustSnapshotDigest: h(11),
  requestDigest: h(12),
};
function altered(change: (map: Map<number, CborValue>) => void): Buffer {
  const map = decodeCbor(encodeReceiptStructure(receipt)) as Map<number, CborValue>;
  change(map);
  return encodeCbor(map);
}
describe('control receipt exact 27-field structural codec', () => {
  it('matches independently encoded complete 27-field golden bytes', () => {
    // Direct schema-key encoding in an independent Python implementation.
    // The fixture remains structurally valid but has no admitted business profile.
    const golden =
      'b81b0050018f000000007000800000000000000101582041a877ca7e00e74f32c8becf8daee38f26c12ab9d9dcf6ff80ed8e75608b3c1f02781d756e61646d69747465642d7374727563747572616c2d6669787475726503010458200101010101010101010101010101010101010101010101010101010101010101056a6c6f63616c2d746573740650018f00000000700080000000000000020750018f00000000700080000000000000030850018f000000007000800000000000000409781e4143542d4944454e544954595f44454c4554455f53455353494f4e2d56310a7449442d4f502d53455353494f4e2d5245564f4b450b6773657373696f6e0c50018f00000000700080000000000000050d582002020202020202020202020202020202020202020202020202020202020202020e582003030303030303030303030303030303030303030303030303030303030303030f5820040404040404040404040404040404040404040404040404040404040404040410582005050505050505050505050505050505050505050505050505050505050505051150018f000000007000800000000000000612a30001011b0020000000000001025820060606060606060606060606060606060606060606060606060606060606060613a30001011bffffffffffffffff02582007070707070707070707070707070707070707070707070707070707070707071482a30001017061757468656e7469636174696f6e2d310258200808080808080808080808080808080808080808080808080808080808080808a30002016f617574686f72697a6174696f6e2d3102582009090909090909090909090909090909090909090909090909090909090909091581a90050018f0000000070008000000000000007017826696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e763102784f68747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d697474656403781b75726e3a6f70656e70633a736572766963653a6964656e7469747904783875726e3a6f70656e70633a7265736f757263653a30313866303030302d303030302d373030302d383030302d303030303030303030303035051bffffffffffffffff061b18d3f3862af204500750018f00000000700080000000000000080958200a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a1601171b18d3f3862af20450181875636f6e74726f6c2d746573742d65766964656e6365181958200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b181a58200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c';
    expect(encodeReceiptStructure(receipt).toString('hex')).toBe(golden);
    expect(decodeReceiptStructure(Buffer.from(golden, 'hex'))).toEqual(receipt);
  });
  it('preserves uint64 values above JavaScript precision and optional event metadata', () => {
    expect(decodeReceiptStructure(encodeReceiptStructure(receipt))).toEqual(receipt);
    const optional = {
      ...receipt,
      outboxEvents: [
        { ...receipt.outboxEvents[0]!, causationId: id(9), authorityGeneration: h(13) },
      ],
    };
    expect(decodeReceiptStructure(encodeReceiptStructure(optional))).toEqual(optional);
    expect(encodeReceiptStructure(optional)).not.toEqual(encodeReceiptStructure(receipt));
  });
  it.each(Array.from({ length: 27 }, (_, i) => i))(
    'rejects missing required top-level field %i',
    (key) => {
      expect(() =>
        decodeReceiptStructure(
          altered((map) => {
            map.delete(key);
          }),
        ),
      ).toThrow();
    },
  );
  it.each(Array.from({ length: 27 }, (_, i) => i))(
    'rejects wrong wire type for top-level field %i',
    (key) => {
      expect(() =>
        decodeReceiptStructure(
          altered((map) => {
            map.set(key, new Map());
          }),
        ),
      ).toThrow();
    },
  );
  it('rejects unknown fields, wrong UUID version/width, absent revisions and non-microsecond timestamps', () => {
    for (const change of [
      (m: Map<number, CborValue>) => m.set(27, 1n),
      (m: Map<number, CborValue>) => m.set(0, Buffer.alloc(15)),
      (m: Map<number, CborValue>) =>
        m.set(0, Buffer.from('018f0000000040008000000000000001', 'hex')),
      (m: Map<number, CborValue>) => m.set(23, 1n),
      (m: Map<number, CborValue>) => m.set(22, 3n),
      (m: Map<number, CborValue>) => m.set(3, 0n),
      (m: Map<number, CborValue>) => m.set(1, Buffer.alloc(31)),
      (m: Map<number, CborValue>) =>
        m.set(
          18,
          new Map<number, CborValue>([
            [0, 0n],
            [1, 1n],
            [2, h(1)],
          ]),
        ),
    ])
      expect(() => decodeReceiptStructure(altered(change))).toThrow();
    expect(() => encodeReceiptStructure({ ...receipt, extra: 'undeclared' } as never)).toThrow();
  });
  it('rejects empty, duplicate and unordered proof/event references', () => {
    const event = receipt.outboxEvents[0]!;
    for (const value of [
      { ...receipt, authorizationEvidence: [] },
      { ...receipt, outboxEvents: [] },
      {
        ...receipt,
        authorizationEvidence: [
          receipt.authorizationEvidence[0]!,
          receipt.authorizationEvidence[0]!,
        ],
      },
      { ...receipt, authorizationEvidence: [...receipt.authorizationEvidence].reverse() },
      { ...receipt, outboxEvents: [{ ...event, aggregateSequence: 1n }, event] },
      { ...receipt, outboxEvents: [event, { ...event, eventId: id(10) }] },
      { ...receipt, outboxEvents: [event, { ...event, eventId: id(10), aggregateSequence: 1n }] },
    ])
      expect(() => encodeReceiptStructure(value)).toThrow();
  });
});
