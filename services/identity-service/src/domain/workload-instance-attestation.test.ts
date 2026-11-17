import { createHash, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { expect, it } from 'vitest';
import { workloadRenewalDigest } from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import {
  workloadInstanceAdmissionDefinitionDigest,
  type WorkloadInstanceAdmissionDefinition,
} from '../contracts/workload-instance-admission.js';
import {
  encodeWorkloadInstanceChallenge,
  encodeManagedWorkloadInstanceStatement,
  workloadInstanceChallengeDigest,
  decodeManagedWorkloadInstanceEvidence,
  type WorkloadInstanceChallenge,
  type ManagedWorkloadInstanceStatement,
} from '../contracts/workload-instance-attestation.js';
import {
  managedWorkloadAttestationProfileDigest,
  type ManagedWorkloadAttestationProfile,
} from '../contracts/workload-renewal-attestation.js';
import { workloadRenewalPolicyDefinitionDigest } from '../contracts/workload-renewal-policy.js';
import { verifyManagedWorkloadInstanceAttestation } from './workload-instance-attestation.js';

const id = (n: number) => '018f0000-0000-7000-8000-' + n.toString(16).padStart(12, '0');
const hash = (n: number) => 'sha256:' + n.toString(16).padStart(64, '0');
const startMs = Date.parse('2026-10-04T10:00:00.000Z');
const start = BigInt(startMs) * 1000000n,
  second = 1000000000n;
const iso = (seconds: number) => new Date(startMs + seconds * 1000).toISOString();

function fixture(profilePatch: Partial<ManagedWorkloadAttestationProfile> = {}) {
  const attestor = generateKeyPairSync('ed25519');
  const spki = Buffer.from(attestor.publicKey.export({ type: 'spki', format: 'der' }));
  const profile: ManagedWorkloadAttestationProfile = {
    domain: 'pc.identity.workload-renewal.managed-attestor-profile.v1',
    version: 1,
    environmentId: 'local-managed',
    issuer: 'urn:openpc:attestor:isolated-host',
    audience: 'openpc-initial-workload',
    managedAttestorScopeDigest: hash(30),
    publicKeySpkiDerBase64: spki.toString('base64'),
    maximumEvidenceLifetimeSeconds: 120,
    validFromNs: (start - second).toString(),
    validUntilNs: (start + 3600n * second).toString(),
    ...profilePatch,
  };
  const policy = {
    version: 1 as const,
    participantId: id(1),
    privacyDomainId: id(2),
    policyId: id(5),
    principalId: id(3),
    workloadId: 'urn:openpc:workload:' + id(4),
    issuerProfileDigest: hash(31),
    providerQualificationDigest: hash(32),
    attestationProfileDigest: managedWorkloadAttestationProfileDigest(profile),
    managedAttestorScopeDigest: profile.managedAttestorScopeDigest,
    maximumInstances: 4,
    maximumEnrollmentsPerMinute: 4,
    certificateLifetimeSeconds: 86400,
    recoveryReserveSeconds: 1800,
    maximumOverlapSeconds: 60,
    validFrom: iso(-1),
    validUntil: iso(3600),
  };
  const definition: WorkloadInstanceAdmissionDefinition = {
    version: 1,
    participantId: policy.participantId,
    privacyDomainId: policy.privacyDomainId,
    environmentId: profile.environmentId,
    familyReservationId: id(7),
    familyId: id(8),
    instanceRegistrationId: id(9),
    instanceRegistrationDigest: hash(33),
    instanceId: id(11),
    instanceGeneration: '1',
    deploymentBindingDigest: hash(34),
    principalId: policy.principalId,
    workloadId: policy.workloadId,
    initialCredentialId: id(10),
    initialCredentialEpoch: '2',
    initialCredentialFingerprint: hash(35),
    policyId: policy.policyId,
    policyRevision: '3',
    policyDigest: workloadRenewalPolicyDefinitionDigest(policy),
    issuerProfileDigest: policy.issuerProfileDigest,
    providerQualificationDigest: policy.providerQualificationDigest,
    attestationProfileDigest: policy.attestationProfileDigest,
    managedAttestorScopeDigest: policy.managedAttestorScopeDigest,
    participantSecurityInvalidationEpoch: '5',
    validFrom: policy.validFrom,
    validUntil: policy.validUntil,
  };
  const proposal = {
    requestId: id(24),
    expectedRevision: '0' as const,
    definition,
    reason: 'Enroll independently registered instance',
  };
  const challenge: WorkloadInstanceChallenge = {
    domain: 'pc.identity.workload-instance.challenge.v1',
    version: 1,
    enrollmentPreparationOperationId: id(18),
    enrollmentAttemptId: id(19),
    challengeId: id(20),
    approvalRequestId: id(17),
    candidateDigest: sha256(proposal),
    definitionDigest: workloadInstanceAdmissionDefinitionDigest(definition),
    definition,
    nonce: randomBytes(32).toString('base64url'),
    issuedAtNs: start.toString(),
    validUntilNs: (start + 120n * second).toString(),
  };
  const statement: ManagedWorkloadInstanceStatement = {
    domain: 'pc.identity.workload-instance.managed-attestation.v1',
    version: 1,
    issuer: profile.issuer,
    audience: profile.audience,
    attestorKeyDigest: workloadRenewalDigest(spki),
    attestationProfileDigest: policy.attestationProfileDigest,
    managedAttestorScopeDigest: policy.managedAttestorScopeDigest,
    challenge,
    challengeDigest: workloadInstanceChallengeDigest(challenge),
    nativeObservationDigest: hash(99),
    issuedAtNs: (start + second).toString(),
    validUntilNs: (start + 61n * second).toString(),
  };
  const expected = {
    challenge,
    profile,
    proposal,
    policyDefinition: policy,
    policyRevision: '3',
    nativeObservationDigest: statement.nativeObservationDigest,
    parentValidity: {
      approvalRequestId: challenge.approvalRequestId,
      initialCredentialValidFromNs: (start - second).toString(),
      initialCredentialValidUntilNs: (start + 600n * second).toString(),
      approvalValidFromNs: (start - second).toString(),
      approvalValidUntilNs: (start + 1800n * second).toString(),
    },
    nowNs: start + 2n * second,
  };
  const evidenceFor = (value: unknown = statement, key = attestor.privateKey) =>
    Buffer.from(
      canonicalDefinitionJson({
        statement: value,
        signatureBase64: sign(null, Buffer.from(canonicalDefinitionJson(value)), key).toString(
          'base64',
        ),
      }),
    );
  return {
    attestor,
    spki,
    profile,
    policy,
    definition,
    proposal,
    challenge,
    statement,
    expected,
    evidenceFor,
  };
}

it('authenticates initial historical evidence with independent Ed25519 and exact original candidate/native bindings', () => {
  const f = fixture(),
    evidence = f.evidenceFor();
  const decoded = decodeManagedWorkloadInstanceEvidence(evidence);
  expect(
    verify(
      null,
      encodeManagedWorkloadInstanceStatement(decoded.statement),
      f.attestor.publicKey,
      Buffer.from(decoded.signatureBase64, 'base64'),
    ),
  ).toBe(true);
  const result = verifyManagedWorkloadInstanceAttestation(evidence, f.expected)!;
  expect(result).toBeDefined();
  expect(result.evidenceDigest).toBe(
    'sha256:' + createHash('sha256').update(evidence).digest('hex'),
  );
  expect(result.candidateDigest).toBe(sha256(f.proposal));
  expect(result.candidateDigest).not.toBe(result.definitionDigest);
  expect(result.nativeObservationDigest).toBe(f.expected.nativeObservationDigest);
  expect(result.enrollmentPreparationOperationId).toBe(
    f.challenge.enrollmentPreparationOperationId,
  );
  expect(result.enrollmentAttemptId).toBe(f.challenge.enrollmentAttemptId);
  expect(Object.isFrozen(result)).toBe(true);
  expect(Object.keys(result).sort()).toEqual(
    [
      'attestationProfileDigest',
      'attestorKeyDigest',
      'candidateDigest',
      'challengeDigest',
      'challengeId',
      'definitionDigest',
      'enrollmentAttemptId',
      'enrollmentPreparationOperationId',
      'evidenceDigest',
      'nativeObservationDigest',
      'statementIssuedAtNs',
      'statementValidUntilNs',
    ].sort(),
  );
  expect(verifyManagedWorkloadInstanceAttestation(evidence, f.expected)).toEqual(result);
});

it.each([
  { domain: 'pc.identity.workload-renewal.managed-attestation.v1' },
  { version: 2 },
  { issuer: 'other-managed-source' },
  { audience: 'other-audience' },
  { attestorKeyDigest: hash(80) },
  { attestationProfileDigest: hash(81) },
  { managedAttestorScopeDigest: hash(82) },
  { nativeObservationDigest: hash(83) },
  { challengeDigest: hash(84) },
  { admitted: true },
])('rejects authentic but wrong initial protocol/source/native statement %j', (patch) => {
  const f = fixture();
  expect(
    verifyManagedWorkloadInstanceAttestation(
      f.evidenceFor({ ...f.statement, ...patch }),
      f.expected,
    ),
  ).toBeUndefined();
});

it.each([
  'participantId',
  'privacyDomainId',
  'principalId',
  'familyReservationId',
  'familyId',
  'instanceRegistrationId',
  'instanceId',
  'initialCredentialId',
  'policyId',
] as const)(
  'rejects a validly signed foreign %s even when its definition/challenge hashes are self-consistent',
  (field) => {
    const f = fixture();
    const definition = { ...f.definition, [field]: id(70) };
    const challenge = {
      ...f.challenge,
      definition,
      definitionDigest: workloadInstanceAdmissionDefinitionDigest(definition),
    };
    const statement = {
      ...f.statement,
      challenge,
      challengeDigest: workloadInstanceChallengeDigest(challenge),
    };
    expect(
      verifyManagedWorkloadInstanceAttestation(f.evidenceFor(statement), f.expected),
    ).toBeUndefined();
  },
);

it.each([
  'enrollmentPreparationOperationId',
  'enrollmentAttemptId',
  'challengeId',
  'approvalRequestId',
] as const)(
  'rejects authentic evidence for a different original %s without trying a new business intent',
  (field) => {
    const f = fixture(),
      challenge = { ...f.challenge, [field]: id(71) };
    expect(
      verifyManagedWorkloadInstanceAttestation(
        f.evidenceFor({
          ...f.statement,
          challenge,
          challengeDigest: workloadInstanceChallengeDigest(challenge),
        }),
        f.expected,
      ),
    ).toBeUndefined();
  },
);

it('binds the full original proposal, including reason/request ID, separately from the unchanged definition', () => {
  const f = fixture(),
    evidence = f.evidenceFor();
  for (const proposal of [
    { ...f.proposal, reason: 'A different governed enrollment intent' },
    { ...f.proposal, requestId: id(72) },
  ])
    expect(
      verifyManagedWorkloadInstanceAttestation(evidence, { ...f.expected, proposal }),
    ).toBeUndefined();
});

it.each([
  { issuedAtNs: (start - second).toString() },
  { issuedAtNs: (start + 3n * second).toString() },
  { validUntilNs: (start + 2n * second).toString() },
  { validUntilNs: (start + 121n * second).toString() },
  { validUntilNs: (start + 61n * second + 1000n).toString() },
])('denies authentic future/expired/outside-challenge/over60s proofs %j', (patch) => {
  const f = fixture();
  expect(
    verifyManagedWorkloadInstanceAttestation(
      f.evidenceFor({ ...f.statement, ...patch }),
      f.expected,
    ),
  ).toBeUndefined();
});

it('checks one authoritative now and never extends original proof validity on repeat parsing', () => {
  const f = fixture(),
    evidence = f.evidenceFor();
  expect(
    verifyManagedWorkloadInstanceAttestation(evidence, {
      ...f.expected,
      nowNs: start + 60n * second,
    }),
  ).toBeDefined();
  for (const nowNs of [
    start - 1000n,
    start + 61n * second,
    start + 120n * second,
    -1n,
    18446744073709551616n,
    start + 1n,
  ])
    expect(
      verifyManagedWorkloadInstanceAttestation(evidence, { ...f.expected, nowNs }),
    ).toBeUndefined();
  expect(verifyManagedWorkloadInstanceAttestation(evidence, f.expected)).toBeDefined();
});

it.each(['initialCredentialValidFromNs', 'approvalValidFromNs'] as const)(
  'does not accept challenge issued before actual %s',
  (field) => {
    const f = fixture();
    expect(
      verifyManagedWorkloadInstanceAttestation(f.evidenceFor(), {
        ...f.expected,
        parentValidity: { ...f.expected.parentValidity, [field]: (start + second).toString() },
      }),
    ).toBeUndefined();
  },
);
it.each(['initialCredentialValidUntilNs', 'approvalValidUntilNs'] as const)(
  'does not let challenge outlive actual %s',
  (field) => {
    const f = fixture();
    expect(
      verifyManagedWorkloadInstanceAttestation(f.evidenceFor(), {
        ...f.expected,
        parentValidity: {
          ...f.expected.parentValidity,
          [field]: (start + 119n * second).toString(),
        },
      }),
    ).toBeUndefined();
  },
);

it('denies a different approval, revision or independently trusted native source', () => {
  const f = fixture(),
    evidence = f.evidenceFor();
  for (const patch of [
    { policyRevision: '4' },
    { nativeObservationDigest: hash(73) },
    { parentValidity: { ...f.expected.parentValidity, approvalRequestId: id(74) } },
  ])
    expect(
      verifyManagedWorkloadInstanceAttestation(evidence, { ...f.expected, ...patch }),
    ).toBeUndefined();
});

it('enforces genuine matching profile lifetime and maximum evidence duration independently of digest mismatch', () => {
  for (const patch of [
    { validFromNs: (start + second).toString() },
    { validUntilNs: (start + 119n * second).toString() },
    { maximumEvidenceLifetimeSeconds: 59 },
  ]) {
    const f = fixture(patch);
    expect(f.definition.attestationProfileDigest).toBe(
      managedWorkloadAttestationProfileDigest(f.profile),
    );
    expect(verifyManagedWorkloadInstanceAttestation(f.evidenceFor(), f.expected)).toBeUndefined();
  }
});

it.each([{ validFrom: iso(-2) }, { validUntil: iso(3601) }])(
  'rejects a fully matching signed candidate whose admission tenure exceeds its actual policy %j',
  (patch) => {
    const f = fixture(),
      definition = { ...f.definition, ...patch };
    const proposal = { ...f.proposal, definition };
    const challenge = {
      ...f.challenge,
      definition,
      definitionDigest: workloadInstanceAdmissionDefinitionDigest(definition),
      candidateDigest: sha256(proposal),
    };
    const statement = {
      ...f.statement,
      challenge,
      challengeDigest: workloadInstanceChallengeDigest(challenge),
    };
    expect(
      verifyManagedWorkloadInstanceAttestation(f.evidenceFor(statement), {
        ...f.expected,
        proposal,
        challenge,
      }),
    ).toBeUndefined();
  },
);

it('denies forged signatures and noncanonical or duplicate-key evidence without returning a digest for it', () => {
  const f = fixture(),
    evidence = f.evidenceFor();
  const wrong = generateKeyPairSync('ed25519');
  const text = evidence.toString('utf8');
  for (const bytes of [
    f.evidenceFor(f.statement, wrong.privateKey),
    Buffer.from(' ' + text),
    Buffer.from(text + '\n'),
    Buffer.from(text.replace('"version":1', '"version":1,"version":1')),
    Buffer.from('{"statement":{}}'),
    Buffer.from([0xff]),
    Buffer.alloc(16385),
    Buffer.from(canonicalDefinitionJson({ ...JSON.parse(text), secret: 'forbidden' })),
  ])
    expect(verifyManagedWorkloadInstanceAttestation(bytes, f.expected)).toBeUndefined();
});

it.each([
  'challenge',
  'profile',
  'proposal',
  'policyDefinition',
  'policyRevision',
  'nativeObservationDigest',
  'parentValidity',
  'nowNs',
] as const)('never invokes an outer trusted %s accessor', (field) => {
  const f = fixture(),
    expected = { ...f.expected };
  let reads = 0;
  Object.defineProperty(expected, field, {
    enumerable: true,
    get() {
      reads++;
      return f.expected[field];
    },
  });
  expect(verifyManagedWorkloadInstanceAttestation(f.evidenceFor(), expected)).toBeUndefined();
  expect(reads).toBe(0);
});

it.each(['length', 'copy', 'slice', 'toString', 'constructor'] as const)(
  'never uses the input binary %s override',
  (field) => {
    const f = fixture(),
      evidence = f.evidenceFor();
    let reads = 0;
    Object.defineProperty(evidence, field, {
      enumerable: true,
      get() {
        reads++;
        throw new Error('must not run');
      },
    });
    expect(verifyManagedWorkloadInstanceAttestation(evidence, f.expected)).toBeUndefined();
    expect(reads).toBe(0);
  },
);

it('rejects hidden/symbol/inherited/extra expected state and nested source getters without reading them', () => {
  const f = fixture(),
    evidence = f.evidenceFor();
  const hidden = { ...f.expected };
  Object.defineProperty(hidden, 'nowNs', { enumerable: false, value: f.expected.nowNs });
  const missing = { ...f.expected } as Partial<typeof f.expected>;
  delete missing.parentValidity;
  for (const expected of [
    hidden,
    missing,
    Object.create(f.expected),
    { ...f.expected, [Symbol('ready')]: true },
    { ...f.expected, admitted: true },
  ])
    expect(verifyManagedWorkloadInstanceAttestation(evidence, expected as never)).toBeUndefined();
  let reads = 0;
  const parentValidity = { ...f.expected.parentValidity };
  Object.defineProperty(parentValidity, 'approvalValidUntilNs', {
    enumerable: true,
    get() {
      reads++;
      return f.expected.parentValidity.approvalValidUntilNs;
    },
  });
  expect(
    verifyManagedWorkloadInstanceAttestation(evidence, { ...f.expected, parentValidity }),
  ).toBeUndefined();
  expect(reads).toBe(0);
  expect(
    verifyManagedWorkloadInstanceAttestation(new Uint8Array(evidence) as never, f.expected),
  ).toBeUndefined();
});

it('requires canonical nonce, distinct original IDs, exact known definition and finite microsecond-u64 challenge', () => {
  const f = fixture();
  for (const patch of [
    { nonce: 'A'.repeat(42) },
    { nonce: f.challenge.nonce + '=' },
    { enrollmentAttemptId: f.challenge.enrollmentPreparationOperationId },
    { approvalRequestId: f.challenge.challengeId },
    { definitionDigest: hash(75) },
    { issuedAtNs: (start + 1n).toString() },
    { issuedAtNs: '-1' },
    { validUntilNs: (start + 120n * second + 1000n).toString() },
    { validUntilNs: '18446744073709551616' },
    { validUntilNs: start.toString() },
    { domain: 'pc.identity.workload-renewal.challenge.v1' },
    { ready: true },
  ])
    expect(() => encodeWorkloadInstanceChallenge({ ...f.challenge, ...patch } as never)).toThrow();
});
