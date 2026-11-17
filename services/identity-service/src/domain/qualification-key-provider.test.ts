import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { qualificationDigest } from '../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import {
  qualificationKeyInstallation,
  qualificationKeyDescriptorDigest,
  qualificationKeyRequestDigest,
  qualificationKeyPossessionPreimage,
  validateQualificationKeyRequest,
  validateQualificationKeyObservation,
  qualificationKeyRequestSchema,
  type QualificationKeyInstallation,
  type QualificationKeyDescriptor,
  type QualificationKeyRequest,
} from './qualification-key-provider.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = (s: string) => qualificationDigest(Buffer.from(s));
function sample() {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    spki = key.publicKey.export({ type: 'spki', format: 'der' });
  const trust: QualificationKeyInstallation = {
    schemaVersion: 1,
    installationId: id(1),
    participantId: id(2),
    privacyDomainId: id(3),
    environmentId: 'local-test',
    authorityId: 'qualification-test',
    rootEpoch: '1',
    keyId: qualificationDigest(spki),
    keyEpoch: '1',
    purpose: 'pc.cose.operations-qualification-executed-receipt.v1',
    publicKeySpkiHex: spki.toString('hex'),
    reference: 'secret://test-provider/qualification#v1',
    version: 'v1',
    providerId: 'external-test',
    providerOrigin: 'https://127.0.0.1:9443',
    providerTlsSpkiDigest: h('provider-tls'),
    peer: {
      principalId: id(4),
      credentialId: id(5),
      participantEpoch: '1',
      principalEpoch: '1',
      credentialEpoch: '1',
      workloadId: 'urn:openpc:workload:' + id(6),
      keyDigest: h('client-key'),
      certificateDigest: h('client-cert'),
    },
    validFromMs: 1000,
    validUntilMs: 30000,
  };
  const descriptor: QualificationKeyDescriptor = {
    schemaVersion: 1,
    providerId: trust.providerId,
    participantId: trust.participantId,
    privacyDomainId: trust.privacyDomainId,
    environmentId: trust.environmentId,
    authorityId: trust.authorityId,
    rootEpoch: '1',
    keyId: trust.keyId,
    keyEpoch: '1',
    purpose: trust.purpose,
    reference: trust.reference,
    version: trust.version,
    publicKeySpkiHex: trust.publicKeySpkiHex,
    algorithm: 'ES256',
    state: 'ACTIVE',
    validFromMs: 1000,
    validUntilMs: 30000,
    policyRevision: '1',
    custody: 'EXTERNAL_SOFTWARE_FIXTURE',
    clients: [
      {
        credentialId: trust.peer.credentialId,
        credentialEpoch: '1',
        certificateDigest: trust.peer.certificateDigest,
        methods: ['INSPECT', 'PROVE'],
      },
    ],
  };
  const request: QualificationKeyRequest = {
    schemaVersion: 1,
    installationDigest: qualificationKeyInstallation(trust).digest,
    participantId: trust.participantId,
    privacyDomainId: trust.privacyDomainId,
    environmentId: trust.environmentId,
    authorityId: trust.authorityId,
    rootEpoch: '1',
    keysetDigest: h('keyset'),
    revocationsDigest: h('revocations'),
    keyId: trust.keyId,
    keyEpoch: '1',
    purpose: trust.purpose,
    providerId: trust.providerId,
    reference: trust.reference,
    version: 'v1',
    peer: trust.peer,
    operationId: id(7),
    attemptId: id(8),
    issuedAtMs: 2000,
    deadlineAtMs: 10000,
    method: 'PROVE',
    inspectionAttemptId: id(9),
    challengeHex: 'ab'.repeat(32),
    descriptorDigest: qualificationKeyDescriptorDigest(descriptor),
  };
  const proofHex = sign('sha256', qualificationKeyPossessionPreimage(request, descriptor), {
    key: key.privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('hex');
  const observed = {
    schemaVersion: 1 as const,
    attemptId: request.attemptId,
    requestDigest: qualificationKeyRequestDigest(request),
    observedAtMs: 2500,
    outcome: 'OBSERVED' as const,
    reason: null,
    descriptor,
    proofHex,
  };
  return { trust, request, descriptor, observed, key };
}
it('verifies real fixed-domain ES256 proof and freezes exact originals without granting hardware assurance', () => {
  const s = sample(),
    result = validateQualificationKeyObservation(s.request, s.observed, s.trust);
  expect(result.descriptor?.custody).toBe('EXTERNAL_SOFTWARE_FIXTURE');
  expect(Object.isFrozen(result.descriptor?.clients)).toBe(true);
  expect(Buffer.from(s.observed.proofHex, 'hex')).toHaveLength(64);
  s.observed.descriptor.clients[0]!.methods = ['INSPECT'];
  expect(result.descriptor?.clients[0]?.methods).toContain('PROVE');
});
describe('original request binding', () => {
  it.each([
    'installationDigest',
    'keyId',
    'keyEpoch',
    'purpose',
    'reference',
    'version',
    'participantId',
    'privacyDomainId',
    'environmentId',
    'authorityId',
    'rootEpoch',
    'providerId',
  ] as const)('rejects substituted %s', (field) => {
    const s = sample();
    expect(() =>
      validateQualificationKeyRequest({ ...s.request, [field]: 'substituted' }, s.trust),
    ).toThrow();
  });
  it.each([
    'principalId',
    'credentialId',
    'credentialEpoch',
    'principalEpoch',
    'participantEpoch',
    'workloadId',
    'certificateDigest',
    'keyDigest',
  ] as const)('rejects substituted peer %s', (field) => {
    const s = sample();
    expect(() =>
      validateQualificationKeyRequest(
        { ...s.request, peer: { ...s.request.peer, [field]: 'substituted' } },
        s.trust,
      ),
    ).toThrow();
  });
});
it.each(['SIGN', 'SIGN_RECEIPT', 'SIGN_NOTIFICATION_DELIVERY_STARTED', 'EXPORT', 'LOOKUP'])(
  'rejects %s as a dispatch method',
  (method) => {
    const s = sample();
    expect(() => qualificationKeyRequestSchema.parse({ ...s.request, method })).toThrow();
  },
);
it.each([
  'state',
  'policyRevision',
  'publicKeySpkiHex',
  'purpose',
  'keyEpoch',
  'reference',
] as const)('proof binds actual descriptor %s', (field) => {
  const s = sample();
  expect(() =>
    validateQualificationKeyObservation(
      s.request,
      { ...s.observed, descriptor: { ...s.descriptor, [field]: 'substituted' } },
      s.trust,
    ),
  ).toThrow();
});
it('rejects a real signature in another domain and a changed challenge/inspection lineage', () => {
  const s = sample(),
    wrong = sign('sha256', Buffer.from('different domain'), {
      key: s.key.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex');
  expect(() =>
    validateQualificationKeyObservation(s.request, { ...s.observed, proofHex: wrong }, s.trust),
  ).toThrow();
  for (const change of [{ challengeHex: 'cd'.repeat(32) }, { inspectionAttemptId: id(99) }]) {
    const r = { ...s.request, ...change };
    expect(() =>
      validateQualificationKeyObservation(
        r,
        { ...s.observed, requestDigest: qualificationKeyRequestDigest(r) },
        s.trust,
      ),
    ).toThrow();
  }
});
it('requires actual peer ACL method/key epoch and retains expired originals only by original time', () => {
  const s = sample();
  expect(validateQualificationKeyObservation(s.request, s.observed, s.trust)).toEqual(s.observed);
  const changed = { ...s.descriptor, clients: [] };
  expect(() =>
    validateQualificationKeyObservation(s.request, { ...s.observed, descriptor: changed }, s.trust),
  ).toThrow();
  expect(() =>
    validateQualificationKeyObservation(
      s.request,
      { ...s.observed, observedAtMs: s.request.deadlineAtMs },
      s.trust,
    ),
  ).toThrow();
});
it('INSPECT forbids proof bytes; rejected observations disclose no descriptor or proof', () => {
  const s = sample();
  const { challengeHex, inspectionAttemptId, descriptorDigest, ...rest } = s.request as Extract<
    QualificationKeyRequest,
    { method: 'PROVE' }
  >;
  void challengeHex;
  void inspectionAttemptId;
  void descriptorDigest;
  const r = { ...rest, method: 'INSPECT' as const },
    o = { ...s.observed, requestDigest: qualificationKeyRequestDigest(r), proofHex: null };
  expect(validateQualificationKeyObservation(r, o, s.trust).outcome).toBe('OBSERVED');
  expect(() =>
    validateQualificationKeyObservation(r, { ...o, proofHex: s.observed.proofHex }, s.trust),
  ).toThrow();
  expect(() =>
    validateQualificationKeyObservation(
      r,
      { ...o, outcome: 'REJECTED', reason: 'DENIED' },
      s.trust,
    ),
  ).toThrow();
});
it('preserves an immutable first result and rejects unknown response fields/private material', () => {
  const s = sample();
  expect(() =>
    validateQualificationKeyObservation(
      s.request,
      { ...s.observed, privateKey: 'never-retain' },
      s.trust,
    ),
  ).toThrow();
  expect(() =>
    validateQualificationKeyObservation(
      s.request,
      { ...s.observed, observedAtMs: 2501 },
      s.trust,
      s.observed,
    ),
  ).toThrow();
});
it.each([NaN, Infinity, -0, -1, Number.MAX_SAFE_INTEGER + 1])(
  'rejects malformed time %s before provider I/O',
  (issuedAtMs) => {
    const s = sample();
    expect(() => validateQualificationKeyRequest({ ...s.request, issuedAtMs }, s.trust)).toThrow();
  },
);
it.each([
  'http://127.0.0.1',
  'https://user:secret@127.0.0.1',
  'https://127.0.0.1/path',
  'https://127.0.0.1?query=yes',
])('rejects uninstalled origin %s', (providerOrigin) => {
  const s = sample();
  expect(() => qualificationKeyInstallation({ ...s.trust, providerOrigin })).toThrow();
});

function separatedSample() {
  const s = sample();
  const observer = {
    ...s.trust.peer,
    principalId: id(40),
    credentialId: id(41),
    workloadId: 'urn:openpc:workload:' + id(42),
    keyDigest: h('observer-key'),
    certificateDigest: h('observer-cert'),
  };
  const trust = qualificationKeyInstallation({ ...s.trust, schemaVersion: 2, observer }).pins;
  if (trust.schemaVersion !== 2) throw new Error('Expected independent observer installation');
  const descriptor: QualificationKeyDescriptor = {
    ...s.descriptor,
    schemaVersion: 2,
    observers: [{ observer, subject: trust.peer, methods: ['INSPECT', 'PROVE'] }],
  };
  const request = qualificationKeyRequestSchema.parse({
    ...s.request,
    schemaVersion: 2,
    observer,
    installationDigest: qualificationKeyInstallation(trust).digest,
    descriptorDigest: qualificationKeyDescriptorDigest(descriptor),
  });
  const observed = {
    ...s.observed,
    schemaVersion: 2 as const,
    descriptor,
    requestDigest: qualificationKeyRequestDigest(request),
    proofHex: sign('sha256', qualificationKeyPossessionPreimage(request, descriptor), {
      key: s.key.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex'),
  };
  return { trust, descriptor, request, observed };
}
it('v2 binds independent observer and subject without granting signing or subject possession', () => {
  const s = separatedSample();
  expect(validateQualificationKeyObservation(s.request, s.observed, s.trust)).toEqual(s.observed);
  expect(
    qualificationKeyPossessionPreimage(s.request, s.descriptor).subarray(0, 35).toString(),
  ).toContain('pc.qualification-key-possession.v2');
  expect(() => qualificationKeyRequestSchema.parse({ ...s.request, method: 'SIGN' })).toThrow();
  expect(() =>
    validateQualificationKeyRequest({ ...s.request, schemaVersion: 1 }, s.trust),
  ).toThrow();
  expect(() =>
    validateQualificationKeyObservation(s.request, { ...s.observed, schemaVersion: 1 }, s.trust),
  ).toThrow();
  expect(() =>
    validateQualificationKeyObservation(
      s.request,
      {
        ...s.observed,
        descriptor: {
          ...s.descriptor,
          observers: [{ ...s.descriptor.observers[0], subject: s.trust.observer }],
        },
      },
      s.trust,
    ),
  ).toThrow();
});
it.each(['principalId', 'credentialId', 'workloadId', 'keyDigest', 'certificateDigest'] as const)(
  'v2 rejects shared subject/observer %s and pin substitution',
  (field) => {
    const s = separatedSample();
    expect(() =>
      qualificationKeyInstallation({
        ...s.trust,
        observer: { ...s.trust.observer, [field]: s.trust.peer[field] },
      }),
    ).toThrow();
    expect(() =>
      validateQualificationKeyRequest(
        { ...s.request, observer: { ...s.trust.observer, [field]: s.trust.peer[field] } },
        s.trust,
      ),
    ).toThrow();
  },
);
it('v2 requires both subject ACL and exact authorized observer pair', () => {
  const s = separatedSample();
  for (const descriptor of [
    { ...s.descriptor, observers: [] },
    { ...s.descriptor, observers: [{ ...s.descriptor.observers[0], methods: ['INSPECT'] }] },
    { ...s.descriptor, clients: [{ ...s.descriptor.clients[0], methods: ['INSPECT'] }] },
  ])
    expect(() =>
      validateQualificationKeyObservation(s.request, { ...s.observed, descriptor }, s.trust),
    ).toThrow();
});
