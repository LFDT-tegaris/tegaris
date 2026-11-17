import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { signConsumerCose } from '../fact-consumer/cose-framing.js';
import {
  encodeProviderRetryQualification,
  providerRetryQualificationProfiles,
  qualificationCanonicalJson,
  qualificationDigest,
  verifyProviderRetryAuthority,
  type QualificationFamily,
  type QualificationInputClaims,
  type QualificationRoot,
} from './provider-retry-qualification.js';
import { verifyProviderRetryInput } from './provider-retry-input.js';

// External test authority only. These real signatures exercise cryptographic
// input verification, not execution, non-exportability or reviewer independence.
const instant = 1800000000000;
const id = '019fe9a5-2000-7000-8000-000000000001';
const h = (text: string) => qualificationDigest(Buffer.from(text));
const descriptor = {
  format: 'COSE_Sign1',
  algorithm: 'ES256',
  curve: 'P-256',
  hash: 'SHA-256',
  canonicalization: 'PC-CBOR-1',
};
const pair = () => {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: key.publicKey.export({ format: 'der', type: 'spki' }),
  };
};
function fixture(
  options: { state?: string; purpose?: string; revoked?: boolean; authority?: string } = {},
) {
  const rootKey = pair(),
    inputKey = pair();
  const authorityId = options.authority ?? 'provider-input-test';
  const root: QualificationRoot = {
    authorityId,
    rootKeyId: qualificationDigest(rootKey.spki),
    rootSpki: rootKey.spki,
    rootEpoch: '1',
    policySigner: 'OFFLINE_TRUST_ROOT',
    validFromMs: instant - 10000,
    validUntilMs: instant + 100000,
  };
  const sign = <F extends QualificationFamily>(
    family: F,
    claims: Parameters<typeof encodeProviderRetryQualification<F>>[1],
    key = rootKey,
  ) => {
    const payload = encodeProviderRetryQualification(family, claims);
    return {
      payload,
      cose: signConsumerCose(
        providerRetryQualificationProfiles[family],
        key.privateKey,
        key.spki,
        payload,
      ),
    };
  };
  const rd = Buffer.from(
    qualificationCanonicalJson({
      schemaVersion: '1.0',
      authorityId,
      revocations: options.revoked
        ? [
            {
              schemaVersion: '1.0',
              authorityId,
              keyId: qualificationDigest(inputKey.spki),
              keyEpoch: 1,
              state: 'REVOKED',
              receiptEffect: 'INVALIDATE_RECEIPTS_COVERED_BY_REVOKED_KEY_EPOCH',
              evidenceRetention: 'PRESERVE_NEVER_DELETE_OR_RESIGN',
              signatureEnvelope: descriptor,
              effectiveAt: new Date(instant - 1).toISOString(),
            },
          ]
        : [],
    }),
  );
  const revocations = {
    ...sign('revocations', {
      authorityId,
      snapshotId: id,
      sequence: '1',
      revocationDocumentDigest: qualificationDigest(rd),
      rootKeyId: root.rootKeyId,
      rootEpoch: '1',
      issuedAtMs: instant - 5000,
      validUntilMs: instant + 50000,
    }),
    document: rd,
  };
  const kd = Buffer.from(
    qualificationCanonicalJson({
      schemaVersion: '1.0',
      authorityId,
      policySigner: root.policySigner,
      issuedAt: new Date(instant - 5000).toISOString(),
      signatureEnvelope: descriptor,
      keys: [
        {
          keyId: qualificationDigest(inputKey.spki),
          epoch: 1,
          state: options.state ?? 'ACTIVE',
          purpose: options.purpose ?? 'pc.cose.operations-qualification-input.v1',
          nonExportable: true,
          backend: 'HSM',
          publicKeySpkiHex: inputKey.spki.toString('hex'),
          validFromMs: instant - 5000,
          validUntilMs: instant + 50000,
        },
      ],
    }),
  );
  const keyset = {
    ...sign('keyset', {
      authorityId,
      keysetId: id,
      sequence: '1',
      keysetDocumentDigest: qualificationDigest(kd),
      revocationPayloadDigest: qualificationDigest(revocations.payload),
      policySigner: root.policySigner,
      rootKeyId: root.rootKeyId,
      rootEpoch: '1',
      issuedAtMs: instant - 5000,
      validUntilMs: instant + 50000,
    }),
    document: kd,
  };
  const current = verifyProviderRetryAuthority(root, { keyset, revocations }, instant);
  const input: QualificationInputClaims = {
    authorityId,
    environmentId: 'provider-test',
    profile: 'local',
    inputId: id,
    slot: 'QINPUT-LOCAL-PROVIDER-READ-RETRY-V1',
    setting: 'provider.read_retry_limit',
    value: 0,
    method: 'eth_call',
    methodClass: 'RETRY_SAFE_READ',
    methodProfileDigest: h('method'),
    workloadIdentityDigest: h('workload'),
    environmentIdentityDigest: h('environment'),
    subjectArtifactDigest: h('subject'),
    buildDigest: h('build'),
    sourceTreeDigest: h('source'),
    configurationSchemaDigest: h('schema'),
    namedProfileDigest: h('profile'),
    issuerKeyId: qualificationDigest(inputKey.spki),
    issuerEpoch: '1',
    validFromMs: instant - 1000,
    validUntilMs: instant + 10000,
  };
  const signInput = (changes: Partial<QualificationInputClaims> = {}) =>
    sign('input', { ...input, ...changes }, inputKey);
  return { current, input, signInput, inputKey };
}
it.each([0, 1, 2, 3])(
  'authenticates an exact provider input value %i without an executed receipt',
  (value) => {
    const f = fixture(),
      envelope = f.signInput({ value });
    const verified = verifyProviderRetryInput(envelope, f.current, instant);
    expect(verified.input.value).toBe(value);
    expect(verified.inputPayloadDigest).toBe(qualificationDigest(envelope.payload));
    expect(verified.qualificationRef).toBe(
      `qualification://${f.input.authorityId}/${id}@${verified.inputPayloadDigest}`,
    );
    expect(Object.isFrozen(verified)).toBe(true);
    expect(Object.isFrozen(verified.input)).toBe(true);
    expect(Object.keys(verified).sort()).toEqual([
      'input',
      'inputPayloadDigest',
      'qualificationRef',
    ]);
  },
);
it.each(['DRAFT', 'SUSPENDED', 'RETIRED', 'REVOKED'])(
  'denies a new reservation under %s input key state',
  (state) => {
    const f = fixture({ state });
    expect(() => verifyProviderRetryInput(f.signInput(), f.current, instant)).toThrow(
      'OPS_PROVIDER_RETRY_UNQUALIFIED',
    );
  },
);
it.each([
  'pc.cose.operations-qualification-executed-receipt.v1',
  'pc.cose.operations-notification-async-input.v1',
  'pc.cose.operations-notification-async-capacity-receipt.v1',
])('rejects another installed key purpose %s', (purpose) => {
  const f = fixture({ purpose });
  expect(() => verifyProviderRetryInput(f.signInput(), f.current, instant)).toThrow();
});
it('rejects a revoked original, unknown epoch and foreign authority', () => {
  const revoked = fixture({ revoked: true });
  expect(() => verifyProviderRetryInput(revoked.signInput(), revoked.current, instant)).toThrow();
  const f = fixture();
  expect(() =>
    verifyProviderRetryInput(f.signInput({ issuerEpoch: '2' }), f.current, instant),
  ).toThrow();
  expect(() =>
    verifyProviderRetryInput(f.signInput({ authorityId: 'foreign-authority' }), f.current, instant),
  ).toThrow();
});
it.each([Number.NaN, -1, instant - 1001, instant + 10000, instant + 50000])(
  'rejects invalid or stale current time %s',
  (now) => {
    const f = fixture();
    expect(() => verifyProviderRetryInput(f.signInput(), f.current, now)).toThrow();
  },
);
it('rejects input profile/slot disagreement and validity outside the actual key', () => {
  const f = fixture();
  for (const change of [
    { slot: 'QINPUT-TEST-PROVIDER-READ-RETRY-V1' },
    { validFromMs: instant - 6000 },
    { validUntilMs: instant + 60000 },
    { validUntilMs: instant - 1000 },
  ])
    expect(() => verifyProviderRetryInput(f.signInput(change), f.current, instant)).toThrow();
});
it('rejects wrong COSE purpose, signature, payload and malformed input without a receipt', () => {
  const f = fixture(),
    envelope = f.signInput();
  const wrongPurpose = signConsumerCose(
    providerRetryQualificationProfiles.receipt,
    f.inputKey.privateKey,
    f.inputKey.spki,
    envelope.payload,
  );
  const damaged = Buffer.from(envelope.cose);
  damaged[damaged.length - 1]! ^= 1;
  for (const original of [
    { ...envelope, cose: wrongPurpose },
    { ...envelope, cose: damaged },
    { ...envelope, payload: f.signInput({ value: 1 }).payload },
    { ...envelope, payload: Buffer.alloc(0) },
  ])
    expect(() => verifyProviderRetryInput(original, f.current, instant)).toThrow();
});
