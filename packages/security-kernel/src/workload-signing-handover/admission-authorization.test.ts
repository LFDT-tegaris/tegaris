import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { expect, it } from 'vitest';
import { decodeCbor, encodeCbor, type CborValue } from '../canonical-cbor.js';
import {
  encodeIdentityAuthContextAssertionPayload,
  signIdentityAuthContextAssertionCoseSign1Ed25519,
  verifyIdentityAuthContextAssertionCoseSign1Ed25519,
} from '../identity-runtime.js';
import { handoverAdmissionAuthorizationFixture } from './authorization.fixture.js';
import {
  decodeHandoverAdmissionAuthorization,
  encodeHandoverAdmissionAuthorization,
  signHandoverAdmissionAuthorization,
  verifyHandoverAdmissionAuthorization,
  type HandoverAdmissionAuthorization,
} from './admission-authorization.js';

const pair = () => {
  const key = generateKeyPairSync('ed25519');
  return {
    privateKey: key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    publicKey: key.publicKey.export({ format: 'der', type: 'spki' }),
  };
};
const payload = () => encodeHandoverAdmissionAuthorization(handoverAdmissionAuthorizationFixture());

it('encodes the exact closed semantic envelope and round-trips all fields', () => {
  const bytes = payload(),
    statement = handoverAdmissionAuthorizationFixture();
  expect(decodeHandoverAdmissionAuthorization(bytes)).toEqual(statement);
  const envelope = decodeCbor(bytes) as Map<number, CborValue>;
  expect([...envelope.keys()]).toEqual([0, 1, 2, 3]);
  expect(envelope.get(0)).toBe(1n);
  expect(envelope.get(1)).toBe(24042n);
  expect(envelope.get(2)).toBe(1n);
  const body = envelope.get(3) as Map<number, CborValue>;
  expect(body.size).toBe(36);
  expect(body.get(1)).toBe(1n);
  expect(body.get(2)).toEqual(Buffer.from(statement.participantId.replaceAll('-', ''), 'hex'));
  expect(body.get(10)).toEqual(Buffer.from(statement.candidateDigest.slice(7), 'hex'));
  expect(body.get(29)).toBe(1793772000000000000n);
  expect(body.get(31)).toEqual(Buffer.from(statement.successorTrustSetDigest.slice(7), 'hex'));
  expect(body.get(32)).toEqual(Buffer.from(statement.selectorTransitionDigest.slice(7), 'hex'));
});

it('produces a purpose-specific Ed25519 signature independently verified over its protected context', () => {
  const key = pair(),
    bytes = payload(),
    signed = signHandoverAdmissionAuthorization(key.privateKey, key.publicKey, bytes);
  expect(verifyHandoverAdmissionAuthorization(key.publicKey, bytes, signed)).toBe(true);
  const [header, unprotected, embedded, signature] = decodeCbor(signed.subarray(1)) as CborValue[];
  const protectedFields = decodeCbor(header as Buffer) as Map<number, CborValue>;
  expect(protectedFields.get(1)).toBe(-8n);
  expect(protectedFields.get(100)).toBe(24042n);
  expect(protectedFields.get(102)).toBe(379n);
  expect(unprotected).toEqual(new Map());
  expect(embedded).toEqual(bytes);
  const structure = encodeCbor([
    'Signature1',
    header!,
    Buffer.from('pcplane:cose-sign1:v2\0'),
    bytes,
  ]);
  expect(
    verify(
      null,
      structure,
      createPublicKey({ key: key.publicKey, type: 'spki', format: 'der' }),
      signature as Buffer,
    ),
  ).toBe(true);
  expect(verifyHandoverAdmissionAuthorization(pair().publicKey, bytes, signed)).toBe(false);
  expect(verifyIdentityAuthContextAssertionCoseSign1Ed25519(key.publicKey, bytes, signed)).toBe(
    false,
  );
  expect(() =>
    signIdentityAuthContextAssertionCoseSign1Ed25519(key.privateKey, key.publicKey, bytes),
  ).toThrow();
});

it.each(Object.keys(handoverAdmissionAuthorizationFixture()))(
  'binds field %s to the signature or rejects its substitution',
  (field) => {
    const key = pair(),
      original = handoverAdmissionAuthorizationFixture(),
      bytes = encodeHandoverAdmissionAuthorization(original);
    const signed = signHandoverAdmissionAuthorization(key.privateKey, key.publicKey, bytes);
    const changed = {
      ...original,
      [field]: field.endsWith('Digest')
        ? 'sha256:' + 'ff'.repeat(32)
        : field.endsWith('Id') &&
            !['workloadId', 'environmentId', 'actionIntentId', 'catalogOperationId'].includes(field)
          ? '01a10000-0000-7000-8000-000000000099'
          : field === 'admittedAtNs'
            ? '1793772000000001000'
            : field === 'authorizationExpiresAtNs'
              ? '1793772059000000000'
              : 'changed',
    };
    let altered: Buffer;
    try {
      altered = encodeHandoverAdmissionAuthorization(changed as HandoverAdmissionAuthorization);
    } catch {
      return;
    }
    expect(verifyHandoverAdmissionAuthorization(key.publicKey, altered, signed)).toBe(false);
  },
);

it.each([
  { extra: 'unknown' },
  { makerPrincipalId: handoverAdmissionAuthorizationFixture().checkerPrincipalId },
  { successorCredentialId: handoverAdmissionAuthorizationFixture().predecessorCredentialId },
  { successorCredentialEpoch: '6' },
  { predecessorCredentialEpoch: '18446744073709551616' },
  { successorCredentialEpoch: '05' },
  { expectedRevision: '2' },
  { environmentId: '*' },
  { admittedAtNs: '1793772000000000001' },
  { admittedAtNs: '-1000' },
  { authorizationExpiresAtNs: '1793772000000000000' },
  { authorizationExpiresAtNs: '1793772060000001000' },
  { participantId: '01a10000-0000-4000-8000-000000000001' },
])('rejects malformed, broadened or unbounded statement %#', (change) => {
  expect(() =>
    encodeHandoverAdmissionAuthorization({
      ...handoverAdmissionAuthorizationFixture(),
      ...change,
    } as HandoverAdmissionAuthorization),
  ).toThrow();
});

it('rejects unknown/omitted fields, accessors, altered envelope and noncanonical/trailing bytes', () => {
  const original = handoverAdmissionAuthorizationFixture();
  const missing = { ...original };
  Reflect.deleteProperty(missing, 'candidateDigest');
  expect(() => encodeHandoverAdmissionAuthorization(missing)).toThrow();
  const getter = Object.defineProperty({ ...original }, 'candidateDigest', {
    get() {
      throw new Error('must not invoke getter');
    },
  });
  expect(() => encodeHandoverAdmissionAuthorization(getter)).toThrow('Invalid handover');
  const bytes = payload();
  for (const altered of [
    Buffer.concat([bytes, Buffer.from([0])]),
    Buffer.concat([Buffer.from([0xd2]), bytes]),
  ])
    expect(() => decodeHandoverAdmissionAuthorization(altered)).toThrow();
  for (const [key, value] of [
    [0, 2],
    [1, 24034],
    [2, 2],
    [4, 1],
  ] as const) {
    const map = decodeCbor(bytes) as Map<number, CborValue>;
    map.set(key, value);
    expect(() => decodeHandoverAdmissionAuthorization(encodeCbor(map))).toThrow();
  }
  const map = decodeCbor(bytes) as Map<number, CborValue>;
  (map.get(3) as Map<number, CborValue>).set(0, Buffer.alloc(32));
  expect(() => decodeHandoverAdmissionAuthorization(encodeCbor(map))).toThrow();
});

it('rejects modified COSE headers, unprotected claims, wrong key pairs and noncanonical public keys', () => {
  const key = pair(),
    bytes = payload(),
    signed = signHandoverAdmissionAuthorization(key.privateKey, key.publicKey, bytes);
  const cose = decodeCbor(signed.subarray(1)) as CborValue[];
  for (const [field, replacement] of [
    [1, -7],
    [100, 3002],
    [101, 2],
    [102, 13],
    [103, 1],
    [104, 1],
  ] as const) {
    const fields = decodeCbor(cose[0] as Buffer) as Map<number, CborValue>;
    fields.set(field, replacement);
    const altered = Buffer.concat([
      Buffer.from([0xd2]),
      encodeCbor([encodeCbor(fields), ...cose.slice(1)]),
    ]);
    expect(verifyHandoverAdmissionAuthorization(key.publicKey, bytes, altered)).toBe(false);
  }
  expect(verifyHandoverAdmissionAuthorization(key.publicKey, bytes, signed.subarray(1))).toBe(
    false,
  );
  const unprotected = Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor([cose[0]!, new Map([[1, 1]]), cose[2]!, cose[3]!]),
  ]);
  expect(verifyHandoverAdmissionAuthorization(key.publicKey, bytes, unprotected)).toBe(false);
  expect(() =>
    signHandoverAdmissionAuthorization(pair().privateKey, key.publicKey, bytes),
  ).toThrow();
  expect(
    verifyHandoverAdmissionAuthorization(
      Buffer.concat([key.publicKey, Buffer.from([0])]),
      bytes,
      signed,
    ),
  ).toBe(false);
});

it('rejects a valid same-root ordinary Identity assertion in the admission verifier', () => {
  const key = pair();
  const ordinary = encodeIdentityAuthContextAssertionPayload({
    assertionId: 'synthetic-ordinary',
    actorKeyDigest: Buffer.alloc(32, 1),
    actorKind: 0,
    participantContextDigest: Buffer.alloc(32, 2),
    audienceDigest: Buffer.alloc(32, 3),
    senderBindingKind: 1,
    assuranceProfileDigest: Buffer.alloc(32, 4),
    authorityVectorDigest: Buffer.alloc(32, 5),
    issuedAtNs: 1n,
    expiresAtNs: 2n,
    authenticationEvidenceDigest: Buffer.alloc(32, 6),
  });
  const signed = signIdentityAuthContextAssertionCoseSign1Ed25519(
    key.privateKey,
    key.publicKey,
    ordinary,
  );
  expect(verifyIdentityAuthContextAssertionCoseSign1Ed25519(key.publicKey, ordinary, signed)).toBe(
    true,
  );
  expect(verifyHandoverAdmissionAuthorization(key.publicKey, ordinary, signed)).toBe(false);
  expect(verifyHandoverAdmissionAuthorization(key.publicKey, payload(), signed)).toBe(false);
});

it('rejects duplicate, unordered, non-shortest and indefinite maps at the admission boundary', () => {
  const bytes = payload(),
    map = decodeCbor(bytes) as Map<number, CborValue>,
    body = map.get(3) as Map<number, CborValue>;
  const encodedBody = encodeCbor(body),
    prefix = bytes.subarray(0, bytes.length - encodedBody.length);
  expect(encodedBody.subarray(0, 2)).toEqual(Buffer.from([0xb8, 0x24]));
  const pairs = [...body].map(([k, v]) => Buffer.concat([encodeCbor(k), encodeCbor(v)]));
  const duplicate = [...pairs];
  duplicate[duplicate.length - 1] = duplicate[0]!;
  const unordered = [...pairs];
  [unordered[0], unordered[1]] = [unordered[1]!, unordered[0]!];
  const malformed = [
    Buffer.concat([prefix, Buffer.from([0xb8, 0x24]), ...duplicate]),
    Buffer.concat([prefix, Buffer.from([0xb8, 0x24]), ...unordered]),
    Buffer.concat([prefix, Buffer.from([0xb9, 0, 0x24]), ...pairs]),
    Buffer.concat([prefix, Buffer.from([0xbf]), ...pairs, Buffer.from([0xff])]),
    Buffer.concat([bytes.subarray(0, 2), Buffer.from([0x18, 1]), bytes.subarray(3)]),
  ];
  for (const altered of malformed)
    expect(() => decodeHandoverAdmissionAuthorization(altered)).toThrow();
});

it('rejects double tags, signature corruption and trailing signature bytes', () => {
  const key = pair(),
    bytes = payload(),
    signed = signHandoverAdmissionAuthorization(key.privateKey, key.publicKey, bytes);
  const corrupt = Buffer.from(signed);
  corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1;
  for (const altered of [
    Buffer.concat([Buffer.from([0xd2]), signed]),
    corrupt,
    Buffer.concat([signed, Buffer.from([0])]),
  ])
    expect(verifyHandoverAdmissionAuthorization(key.publicKey, bytes, altered)).toBe(false);
});
