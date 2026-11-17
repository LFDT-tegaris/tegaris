import { spawnSync } from 'node:child_process';
import { createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeCbor, encodeCbor, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { factConsumerFailureContext as context } from './failure-generated.js';
import {
  decodeFactConsumerFailure,
  encodeFactConsumerFailure,
  factConsumerFailureDigest,
  factConsumerFailureWorkItem,
  type FactConsumerFailure,
} from './failure.js';
import {
  factConsumerFailureProtectedHeader,
  signFactConsumerFailure,
  verifyFactConsumerFailureSignature,
} from './failure-cose.js';
import { verifyFactConsumerProfileSignature } from './cose.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (byte: string) => `sha256:${byte.repeat(32)}`;
function fixture(consumerId: FactConsumerFailure['consumerId'] = 'LS-FLEET-CONTROL') {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const privateKey = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
  const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
  const receipt: FactConsumerFailure = {
    environmentId: 'owned-local',
    participantId: id(101),
    privacyDomainId: id(201),
    consumerId,
    subscriptionId:
      consumerId === 'LS-FLEET-CONTROL'
        ? 'SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1'
        : 'SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1',
    eventId: id(301),
    candidateId: id(302),
    generationId: id(303),
    factType: 'CONTRACT_STATE_CALL',
    sequence: '9223372036854775807',
    envelopeDigest: digest('11'),
    dataDigest: digest('22'),
    materialDigest: digest('33'),
    initialProfileDigest: digest('44'),
    currentProfileDigest: digest('55'),
    failedAttempts: 3,
    maximumAttempts: 3,
    leaseGeneration: '18446744073709551615',
    workloadCredentialId: id(401),
    workloadCredentialEpoch: '18446744073709551615',
    workloadPrincipalId: id(402),
    workItemId: id(501),
    problem: 'PC-DATA-6005',
    recordedAtMs: 1780000000000,
    signerKeyId: evidenceKeyId(spki),
    receiptId: id(502),
  };
  const payload = encodeFactConsumerFailure(receipt);
  const cose = signFactConsumerFailure(privateKey, spki, payload);
  return { receipt, payload, cose, privateKey, spki };
}
function resigned(
  f: ReturnType<typeof fixture>,
  payload: Buffer,
  changeHeader?: (map: Map<number, CborValue>) => void,
) {
  const header = decodeCbor(factConsumerFailureProtectedHeader(f.spki)) as Map<number, CborValue>;
  changeHeader?.(header);
  const encoded = encodeCbor(header);
  const signature = sign(
    'sha256',
    encodeCbor(['Signature1', encoded, Buffer.from(context.externalAadHex, 'hex'), payload]),
    {
      key: createPrivateKey({ key: f.privateKey, format: 'der', type: 'pkcs8' }),
      dsaEncoding: 'ieee-p1363',
    },
  );
  return Buffer.concat([Buffer.from([0xd2]), encodeCbor([encoded, new Map(), payload, signature])]);
}

describe('source-owned Fact consumer failure receipt', () => {
  it.each(['LS-FLEET-CONTROL', 'LS-CONTROL-WORK'] as const)(
    'round trips %s exact exhausted state without rounding ordinals',
    (consumer) => {
      const f = fixture(consumer);
      expect(decodeFactConsumerFailure(f.payload)).toEqual(f.receipt);
      expect(verifyFactConsumerFailureSignature(f.spki, f.payload, f.cose)).toBe(true);
      expect(factConsumerFailureDigest(f.cose)).toMatch(/^sha256:[0-9a-f]{64}$/);
      const map = decodeCbor(f.payload) as Map<number, CborValue>;
      expect([...map.keys()]).toEqual(Array.from({ length: 27 }, (_, n) => n));
      expect(map.get(10)).toBe(9223372036854775807n);
      expect(map.get(18)).toBe(18446744073709551615n);
    },
  );
  it('projects one safe OPEN work item and no delivery/cursor authority', () => {
    const f = fixture();
    const item = factConsumerFailureWorkItem(f.receipt);
    expect(item).toEqual({
      participantId: id(101),
      privacyDomainId: id(201),
      workItemId: id(501),
      kind: 'FLEET_FAILURE',
      state: 'OPEN',
      rowVersion: '1',
      resourceRef: `urn:openpc:resource:${id(302)}`,
      payloadDigest: digest('33'),
      reason: 'Fact delivery quarantined (PC-DATA-6005).',
      createdByPrincipalId: id(402),
      assigneePrincipalId: null,
      claimedByPrincipalId: null,
      completedByPrincipalId: null,
    });
    expect(Object.isFrozen(item)).toBe(true);
    expect(factConsumerFailureWorkItem(fixture('LS-CONTROL-WORK').receipt).kind).toBe(
      'DELIVERY_FAILURE',
    );
    expect(Object.keys(item)).not.toContain('envelope');
    expect(Object.keys(item)).not.toContain('cursor');
  });
  it('rejects non-exhausted, reset, zero, fractional and overflowing attempts and ordinals', () => {
    const { receipt } = fixture();
    for (const patch of [
      { failedAttempts: 2 },
      { maximumAttempts: 4 },
      { failedAttempts: 0, maximumAttempts: 0 },
      { failedAttempts: 1001, maximumAttempts: 1001 },
      { failedAttempts: 1.5, maximumAttempts: 1.5 },
      { failedAttempts: -0 },
      { leaseGeneration: '2' },
      { leaseGeneration: '18446744073709551616' },
      { sequence: '9223372036854775808' },
      { sequence: '0' },
      { sequence: '01' },
      { workloadCredentialEpoch: '-1' },
      { recordedAtMs: Number.MAX_SAFE_INTEGER + 1 },
      { recordedAtMs: -0 },
    ])
      expect(() => encodeFactConsumerFailure({ ...receipt, ...patch })).toThrow();
  });
  it('rejects crossed subscriptions, unsafe problems, untyped IDs, unknown fields and accessors', () => {
    const { receipt } = fixture();
    for (const patch of [
      { subscriptionId: 'SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1' },
      { consumerId: 'LS-NOTIFICATION' },
      { problem: 'raw source detail' },
      { factType: 'OTHER' },
      { workItemId: receipt.receiptId },
      { eventId: '018f0000-0000-4000-8000-000000000301' },
      { envelopeDigest: 'sha256:aa' },
      { environmentId: 'non-nfc-e\u0301' },
      { unexpected: true },
    ])
      expect(() =>
        encodeFactConsumerFailure({ ...receipt, ...patch } as FactConsumerFailure),
      ).toThrow();
    const accessor = { ...receipt };
    Object.defineProperty(accessor, 'problem', {
      get() {
        throw Error('getter ran');
      },
    });
    expect(() => encodeFactConsumerFailure(accessor)).toThrow('Invalid Fact consumer failure');
    expect(() => encodeFactConsumerFailure(Object.assign(Object.create({}), receipt))).toThrow();
  });
  it('rejects every changed payload field even when a valid signature exists for the original', () => {
    const f = fixture();
    for (let index = 0; index < context.fields.length; index++) {
      const map = decodeCbor(f.payload) as Map<number, CborValue>;
      const value = map.get(index);
      if (Buffer.isBuffer(value)) {
        const next = Buffer.from(value);
        next[next.length - 1] = next[next.length - 1]! ^ 1;
        map.set(index, next);
      } else if (typeof value === 'bigint') map.set(index, value === 0n ? 1n : value - 1n);
      else map.set(index, `${String(value)}x`);
      expect(verifyFactConsumerFailureSignature(f.spki, encodeCbor(map), f.cose)).toBe(false);
    }
  });
  it('rejects signed malformed payloads, missing/extra fields, and definition substitutions', () => {
    const f = fixture();
    for (const mutate of [
      (map: Map<number, CborValue>) => {
        map.delete(6);
      },
      (map: Map<number, CborValue>) => {
        map.set(27, 'unregistered');
      },
      (map: Map<number, CborValue>) => {
        map.set(0, Buffer.alloc(32));
      },
      (map: Map<number, CborValue>) => {
        map.set(16, 2);
      },
      (map: Map<number, CborValue>) => {
        map.set(23, 'raw fault');
      },
      (map: Map<number, CborValue>) => {
        map.set(18, '3');
      },
    ]) {
      const map = decodeCbor(f.payload) as Map<number, CborValue>;
      mutate(map);
      const payload = encodeCbor(map);
      expect(verifyFactConsumerFailureSignature(f.spki, payload, resigned(f, payload))).toBe(false);
    }
  });
  it('rejects installation purpose, altered critical headers, tags, unprotected data and trailing bytes', () => {
    const f = fixture();
    expect(verifyFactConsumerProfileSignature(f.spki, f.payload, f.cose)).toBe(false);
    for (const mutate of [
      (map: Map<number, CborValue>) => {
        map.set(100, 24006);
      },
      (map: Map<number, CborValue>) => {
        map.set(102, 343);
      },
      (map: Map<number, CborValue>) => {
        map.set(103, 1);
      },
      (map: Map<number, CborValue>) => {
        map.set(2, [100, 101, 102]);
      },
      (map: Map<number, CborValue>) => {
        map.set(104, 1);
      },
    ])
      expect(
        verifyFactConsumerFailureSignature(f.spki, f.payload, resigned(f, f.payload, mutate)),
      ).toBe(false);
    const container = decodeCbor(f.cose.subarray(1)) as CborValue[];
    container[1] = new Map([[1, 1]]);
    for (const invalid of [
      f.cose.subarray(1),
      Buffer.concat([f.cose, Buffer.from([0])]),
      Buffer.concat([Buffer.from([0xd2]), encodeCbor(container)]),
    ])
      expect(verifyFactConsumerFailureSignature(f.spki, f.payload, invalid)).toBe(false);
  });
  it('rejects unrelated keys and canonical payloads naming another signer', () => {
    const f = fixture(),
      other = fixture();
    expect(verifyFactConsumerFailureSignature(other.spki, f.payload, f.cose)).toBe(false);
    expect(() => signFactConsumerFailure(other.privateKey, f.spki, f.payload)).toThrow();
    const payload = encodeFactConsumerFailure({
      ...f.receipt,
      signerKeyId: other.receipt.signerKeyId,
    });
    expect(() => signFactConsumerFailure(f.privateKey, f.spki, payload)).toThrow();
    expect(verifyFactConsumerFailureSignature(f.spki, payload, resigned(f, payload))).toBe(false);
  });
});

it
  .skipIf(!process.env.OPENPC_FACT_WORKLOAD_TEST_BINARY)
  .each(['LS-FLEET-CONTROL', 'LS-CONTROL-WORK'] as const)(
  'native failure wire interoperability for %s preserves independently encoded signed bytes',
  (consumer) => {
    const f = fixture(consumer);
    const result = spawnSync(
      process.env.OPENPC_FACT_WORKLOAD_TEST_BINARY!,
      [
        'consumer_profile::failure::tests::typescript_failure_wire_interoperability',
        '--exact',
        '--ignored',
        '--nocapture',
      ],
      {
        encoding: 'utf8',
        timeout: 30000,
        maxBuffer: 1024 * 1024,
        env: {
          ...process.env,
          OPENPC_FACT_FAILURE_WIRE: JSON.stringify({
            receipt: f.receipt,
            spki: [...f.spki],
            payload: [...f.payload],
            cose: [...f.cose],
          }),
        },
      },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain('1 passed;');
    const prefix = 'OPENPC_FACT_FAILURE_WIRE|';
    const lines = result.stdout.split('\n').filter((line) => line.startsWith(prefix));
    expect(lines).toHaveLength(1);
    const native = JSON.parse(lines[0]!.slice(prefix.length));
    const payload = Buffer.from(native.payload),
      cose = Buffer.from(native.cose),
      spki = Buffer.from(native.spki);
    expect(decodeFactConsumerFailure(payload)).toEqual({
      ...f.receipt,
      signerKeyId: evidenceKeyId(spki),
    });
    expect(verifyFactConsumerFailureSignature(spki, payload, cose)).toBe(true);
  },
);
