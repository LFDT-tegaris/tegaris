import { createHash, generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { decodeCbor, encodeCbor, MAX_CBOR_BYTES, type CborValue } from '../canonical-cbor.js';
import { signConsumerCose, verifyConsumerCose } from '../fact-consumer/cose-framing.js';
import { evidenceKmsCoseProfiles } from './generated.js';
import {
  encodeEvidenceKmsClaim,
  decodeEvidenceKmsClaim,
  signEvidenceKmsClaim,
  verifyEvidenceKmsClaim,
  encodeEvidenceKmsResponse,
  decodeEvidenceKmsResponse,
  evidenceKmsAbsentDigest,
  type EvidenceKmsProfileClaims,
  type EvidenceKmsReceiptClaims,
  type EvidenceWrappedKeyClaims,
} from './codec.js';

const hash = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (n: string) => `sha256:${n.repeat(64)}`;
function key() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
    spki: pair.publicKey.export({ type: 'spki', format: 'der' }),
  };
}
const issuer = key(),
  provider = key(),
  recovery = key();
const scope = { environmentId: 'local-kms', participantId: id(1), privacyDomainId: id(2) };
const binding = {
  providerId: 'test-kms',
  reference: 'secret://test-kms/evidence#v1',
  version: 'v1',
  providerKeyId: 'test-key',
  providerKeyVersion: 'v1',
  keyEpoch: '1',
  wrapProfileDigest: digest('1'),
  policyDigest: digest('2'),
  recoveryProfileDigest: digest('3'),
};
const profile: EvidenceKmsProfileClaims = {
  ...scope,
  ...binding,
  profileId: id(3),
  revision: '1',
  producerTrustDigest: digest('4'),
  owner: 'LS-EVIDENCE-EXPORT',
  secretClass: 'SECRET-EVIDENCE-VAULT',
  providerOrigin: 'https://127.0.0.1:4433',
  providerTlsSpkiDigest: digest('5'),
  receiptKeyId: hash(provider.spki),
  recoveryKeyId: hash(recovery.spki),
  permissions: 'ENCRYPT_AND_DECRYPT',
  kekExportPolicy: 'NON_EXPORTABLE',
  recoveryMode: 'THRESHOLD_ESCROW',
  validFromMs: 1800000000000,
  validUntilMs: 1800000300000,
  issuerKeyId: hash(issuer.spki),
};
const record: EvidenceWrappedKeyClaims = {
  ...scope,
  ...binding,
  attemptId: id(4),
  originalRequestDigest: digest('6'),
  objectIntentDigest: digest('7'),
  profileDigest: digest('8'),
  wrappedKey: 'a1'.repeat(60),
  createdAtMs: 1800000001000,
  signerKeyId: hash(provider.spki),
};
const receipt: EvidenceKmsReceiptClaims = {
  ...scope,
  ...binding,
  receiptId: id(5),
  profileDigest: digest('8'),
  operation: 'PREPARE',
  attemptId: id(4),
  exchangeId: id(4),
  requestDigest: digest('6'),
  challenge: 'ab'.repeat(32),
  objectIntentDigest: digest('7'),
  keyId: digest('9'),
  keyUse: 'NONE',
  outcome: 'PROVED',
  keyState: 'CURRENT',
  providerSequence: '2',
  recoveryFloor: '1',
  materialDigest: evidenceKmsAbsentDigest,
  observedAtMs: 1800000001000,
  validUntilMs: 1800000004000,
  signerKeyId: hash(provider.spki),
};

it('round-trips each allocated family through shared canonical CBOR and ES256 COSE', () => {
  const signedProfile = signEvidenceKmsClaim(
    'EvidenceKmsProfileV1',
    issuer.privateKey,
    issuer.spki,
    profile,
  );
  const signedRecord = signEvidenceKmsClaim(
    'EvidenceWrappedKeyRecordV1',
    provider.privateKey,
    provider.spki,
    record,
  );
  const signedReceipt = signEvidenceKmsClaim(
    'EvidenceKmsReceiptV1',
    provider.privateKey,
    provider.spki,
    receipt,
  );
  expect(verifyEvidenceKmsClaim('EvidenceKmsProfileV1', issuer.spki, signedProfile)).toEqual(
    profile,
  );
  expect(verifyEvidenceKmsClaim('EvidenceWrappedKeyRecordV1', provider.spki, signedRecord)).toEqual(
    record,
  );
  expect(verifyEvidenceKmsClaim('EvidenceKmsReceiptV1', provider.spki, signedReceipt)).toEqual(
    receipt,
  );
  expect(() => verifyEvidenceKmsClaim('EvidenceKmsReceiptV1', provider.spki, signedRecord)).toThrow(
    'Evidence KMS wire rejected',
  );
  expect(() =>
    verifyEvidenceKmsClaim('EvidenceWrappedKeyRecordV1', provider.spki, signedReceipt),
  ).toThrow('Evidence KMS wire rejected');
  expect(() =>
    verifyEvidenceKmsClaim('EvidenceKmsProfileV1', provider.spki, signedProfile),
  ).toThrow('Evidence KMS wire rejected');
});

it('rejects tampered payload, signature, critical header, unprotected data and trailing bytes', () => {
  const original = signEvidenceKmsClaim(
    'EvidenceKmsReceiptV1',
    provider.privateKey,
    provider.spki,
    receipt,
  );
  const signature = Buffer.from(original.cose);
  signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
  const payload = Buffer.from(original.payload);
  payload[payload.length - 1] = payload[payload.length - 1]! ^ 1;
  const outer = decodeCbor(original.cose.subarray(1)) as unknown[];
  const unprotected = Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor([outer[0] as Buffer, new Map([[1, 1]]), outer[2] as Buffer, outer[3] as Buffer]),
  ]);
  for (const signed of [
    { ...original, cose: signature },
    { ...original, payload },
    { ...original, cose: unprotected },
    { ...original, cose: Buffer.concat([original.cose, Buffer.from([0])]) },
  ])
    expect(() => verifyEvidenceKmsClaim('EvidenceKmsReceiptV1', provider.spki, signed)).toThrow(
      'Evidence KMS wire rejected',
    );
  const header = decodeCbor(outer[0] as Buffer) as Map<number, unknown>;
  header.set(102, 353);
  const changed = Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor([
      encodeCbor(header as Map<number, never>),
      new Map(),
      outer[2] as Buffer,
      outer[3] as Buffer,
    ]),
  ]);
  expect(() =>
    verifyEvidenceKmsClaim('EvidenceKmsReceiptV1', provider.spki, { ...original, cose: changed }),
  ).toThrow('Evidence KMS wire rejected');
});

it('requires distinct signer roles, exact reference/version, policy and bounded canonical data', () => {
  for (const patch of [
    { receiptKeyId: profile.recoveryKeyId },
    { recoveryKeyId: profile.issuerKeyId },
    { providerOrigin: 'http://127.0.0.1' },
    { providerOrigin: 'https://user:secret@localhost' },
    { reference: 'secret://test-kms/evidence#current', version: 'current' },
    { reference: 'secret://test-kms/../evidence#v1' },
    { version: 'v2' },
    { keyEpoch: '0' },
    { keyEpoch: '18446744073709551616' },
    { validFromMs: -0 },
    { validUntilMs: profile.validFromMs },
    { owner: 'LS-NOTIFICATION' },
    { kekExportPolicy: 'EXPORTABLE' },
    { recoveryMode: 'NONE' },
    { privateKey: 'PRIVATE_CANARY' },
    { admitted: true },
  ])
    expect(() =>
      encodeEvidenceKmsClaim('EvidenceKmsProfileV1', {
        ...profile,
        ...patch,
      } as EvidenceKmsProfileClaims),
    ).toThrow('Evidence KMS wire rejected');
  for (const patch of [
    { wrappedKey: '' },
    { wrappedKey: 'a'.repeat(3) },
    { wrappedKey: 'a1'.repeat(8193) },
    { wrappedKey: 'AA'.repeat(60) },
    { keyId: digest('9') },
    { originalRequestDigest: 'not-a-digest' },
  ])
    expect(() =>
      encodeEvidenceKmsClaim('EvidenceWrappedKeyRecordV1', { ...record, ...patch }),
    ).toThrow('Evidence KMS wire rejected');
});

it('cannot recast revoked, retained, no-effect or historical receipts as successful encryption material', () => {
  const unwrap: EvidenceKmsReceiptClaims = {
    ...receipt,
    operation: 'UNWRAP',
    exchangeId: id(6),
    keyUse: 'ENCRYPT',
    materialDigest: digest('a'),
  };
  expect(() => encodeEvidenceKmsClaim('EvidenceKmsReceiptV1', unwrap)).not.toThrow();
  for (const patch of [
    { keyState: 'REVOKED' },
    { keyState: 'DESTROYED' },
    { keyState: 'RETAINED' },
    { keyUse: 'NONE' },
    { keyId: evidenceKmsAbsentDigest },
    { materialDigest: evidenceKmsAbsentDigest },
    { outcome: 'REJECTED' },
    { recoveryFloor: '3' },
    { observedAtMs: receipt.validUntilMs },
  ])
    expect(() =>
      encodeEvidenceKmsClaim('EvidenceKmsReceiptV1', {
        ...unwrap,
        ...patch,
      } as EvidenceKmsReceiptClaims),
    ).toThrow('Evidence KMS wire rejected');
  expect(() =>
    encodeEvidenceKmsClaim('EvidenceKmsReceiptV1', {
      ...unwrap,
      keyUse: 'DECRYPT',
      keyState: 'RETAINED',
    }),
  ).not.toThrow();
  expect(() =>
    encodeEvidenceKmsClaim('EvidenceKmsReceiptV1', { ...receipt, materialDigest: digest('a') }),
  ).toThrow('Evidence KMS wire rejected');
});

it('rejects accessors, missing fields, extra numeric keys and noncanonical payload bytes', () => {
  let calls = 0;
  const accessor = { ...receipt };
  Object.defineProperty(accessor, 'keyId', {
    enumerable: true,
    get() {
      calls++;
      return receipt.keyId;
    },
  });
  expect(() => encodeEvidenceKmsClaim('EvidenceKmsReceiptV1', accessor)).toThrow(
    'Evidence KMS wire rejected',
  );
  expect(calls).toBe(0);
  const bytes = encodeEvidenceKmsClaim('EvidenceKmsReceiptV1', receipt);
  const unknown = decodeCbor(bytes) as Map<number, never>;
  unknown.set(99, 1 as never);
  for (const candidate of [
    Buffer.alloc(0),
    Buffer.concat([bytes, Buffer.from([0])]),
    encodeCbor(unknown),
  ])
    expect(() => decodeEvidenceKmsClaim('EvidenceKmsReceiptV1', candidate)).toThrow(
      'Evidence KMS wire rejected',
    );
  for (const field of Object.keys(receipt)) {
    const missing = { ...receipt } as Record<string, unknown>;
    delete missing[field];
    expect(() =>
      encodeEvidenceKmsClaim(
        'EvidenceKmsReceiptV1',
        missing as unknown as EvidenceKmsReceiptClaims,
      ),
    ).toThrow('Evidence KMS wire rejected');
  }
});

it('frames only bounded binary signed objects and transient 32-byte material without granting authority', () => {
  const signed = signEvidenceKmsClaim(
    'EvidenceKmsReceiptV1',
    provider.privateKey,
    provider.spki,
    receipt,
  );
  const frame = {
    profile: signEvidenceKmsClaim('EvidenceKmsProfileV1', issuer.privateKey, issuer.spki, profile),
    receipt: signed,
    record: signEvidenceKmsClaim(
      'EvidenceWrappedKeyRecordV1',
      provider.privateKey,
      provider.spki,
      record,
    ),
    recovery: signed,
    material: Buffer.alloc(32, 7),
  };
  const bytes = encodeEvidenceKmsResponse(frame),
    decoded = decodeEvidenceKmsResponse(bytes);
  expect(decoded.material).toEqual(frame.material);
  expect(decoded).not.toHaveProperty('verified');
  decoded.material.fill(0);
  bytes.fill(0);
  frame.material.fill(0);
  for (const size of [1, 31, 33, 65536])
    expect(() => encodeEvidenceKmsResponse({ ...frame, material: Buffer.alloc(size) })).toThrow(
      'Evidence KMS wire rejected',
    );
  expect(() => decodeEvidenceKmsResponse(Buffer.alloc(MAX_CBOR_BYTES + 1025))).toThrow(
    'Evidence KMS wire rejected',
  );
});

it('accepts the exact shared response frame limit and rejects the first byte beyond it', () => {
  // Nine keys and byte-string headers occupy 23 bytes at this payload size.
  // Framing does not authenticate these bytes as claims.
  const limit = MAX_CBOR_BYTES + 1024;
  const empty = { payload: Buffer.alloc(0), cose: Buffer.alloc(0) };
  const response = {
    profile: { ...empty, payload: Buffer.alloc(limit - 23, 1) },
    receipt: empty,
    record: empty,
    recovery: empty,
    material: Buffer.alloc(0),
  };
  const encoded = encodeEvidenceKmsResponse(response);
  expect(encoded.length).toBe(limit);
  expect(decodeEvidenceKmsResponse(encoded)).toEqual(response);
  expect(() =>
    encodeEvidenceKmsResponse({
      ...response,
      profile: { ...empty, payload: Buffer.alloc(limit - 22, 1) },
    }),
  ).toThrow();
  const oversized = Buffer.concat([encoded, Buffer.from([0])]);
  expect(() => decodeEvidenceKmsResponse(oversized)).toThrow('Evidence KMS wire rejected');
});

it('requires exact-key DESTROYED observations for signed destruction success', () => {
  for (const outcome of ['PROVED', 'UNKNOWN', 'REJECTED'] as const) {
    for (const keyState of ['CURRENT', 'RETAINED', 'REVOKED', 'DESTROYED'] as const) {
      const claims: EvidenceKmsReceiptClaims = {
        ...receipt,
        operation: 'DESTROY',
        outcome,
        keyState,
      };
      if (outcome === 'PROVED' && keyState !== 'DESTROYED') {
        expect(() => encodeEvidenceKmsClaim('EvidenceKmsReceiptV1', claims)).toThrow(
          'Evidence KMS wire rejected',
        );
      } else {
        const signed = signEvidenceKmsClaim(
          'EvidenceKmsReceiptV1',
          provider.privateKey,
          provider.spki,
          claims,
        );
        expect(verifyEvidenceKmsClaim('EvidenceKmsReceiptV1', provider.spki, signed)).toEqual(
          claims,
        );
      }
    }
  }
  for (const patch of [
    { keyId: evidenceKmsAbsentDigest },
    { keyUse: 'ENCRYPT' as const },
    { keyUse: 'DECRYPT' as const },
    { materialDigest: digest('a') },
  ]) {
    expect(() =>
      encodeEvidenceKmsClaim('EvidenceKmsReceiptV1', {
        ...receipt,
        operation: 'DESTROY',
        keyState: 'DESTROYED',
        ...patch,
      }),
    ).toThrow('Evidence KMS wire rejected');
  }
});

it('rejects cryptographically valid destruction signatures with false success semantics', () => {
  const context = evidenceKmsCoseProfiles.EvidenceKmsReceiptV1;
  const operation = context.fields.find((field) => field.name === 'operation')!;
  const valid = decodeCbor(
    encodeEvidenceKmsClaim('EvidenceKmsReceiptV1', {
      ...receipt,
      operation: 'DESTROY',
      keyState: 'DESTROYED',
    }),
  ) as Map<number, CborValue>;
  for (const patch of [
    { keyState: 'CURRENT' as const },
    { keyState: 'RETAINED' as const },
    { keyState: 'REVOKED' as const },
    { keyId: evidenceKmsAbsentDigest, keyState: 'DESTROYED' as const },
  ]) {
    const map = decodeCbor(
      encodeEvidenceKmsClaim('EvidenceKmsReceiptV1', {
        ...receipt,
        operation: 'STATUS',
        ...patch,
      }),
    ) as Map<number, CborValue>;
    map.set(operation.key, valid.get(operation.key)!);
    const payload = encodeCbor(map);
    const cose = signConsumerCose(context, provider.privateKey, provider.spki, payload);
    expect(verifyConsumerCose(context, provider.spki, payload, cose)).toBe(true);
    expect(() => decodeEvidenceKmsClaim('EvidenceKmsReceiptV1', payload)).toThrow(
      'Evidence KMS wire rejected',
    );
    expect(() =>
      verifyEvidenceKmsClaim('EvidenceKmsReceiptV1', provider.spki, { payload, cose }),
    ).toThrow('Evidence KMS wire rejected');
  }
});
