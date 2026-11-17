import { generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  encodeWorkloadRenewalRequest,
  signWorkloadRenewalCose,
  workloadRenewalDigest,
} from '@openpc/security-kernel';
import { renewalRequestFixture } from '../../../../packages/security-kernel/src/workload-renewal/fixture.js';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import {
  encodeWorkloadRenewalChallenge,
  managedWorkloadAttestationProfileDigest,
  workloadRenewalChallengeDigest,
  type ManagedWorkloadAttestationProfile,
  type ManagedWorkloadAttestationStatement,
  type WorkloadRenewalChallenge,
} from '../contracts/workload-renewal-attestation.js';
import { workloadRenewalPolicyDefinitionDigest } from '../contracts/workload-renewal-policy.js';
import { verifyManagedWorkloadRenewalAttestation } from './workload-renewal-attestation.js';

const id = (n: number) => `018f0000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const hash = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
const instant = new Date('2026-10-04T10:00:00.000Z');
const start = BigInt(instant.getTime()) * 1000000n;
const second = 1000000000n;

function fixture(
  profilePatch: Partial<ManagedWorkloadAttestationProfile> = {},
  challengePatch: Partial<WorkloadRenewalChallenge> = {},
) {
  const attestor = generateKeyPairSync('ed25519');
  const successor = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = Buffer.from(successor.publicKey.export({ type: 'spki', format: 'der' }));
  const request = renewalRequestFixture(workloadRenewalDigest(spki));
  const profile: ManagedWorkloadAttestationProfile = {
    domain: 'pc.identity.workload-renewal.managed-attestor-profile.v1',
    version: 1,
    environmentId: 'local-qualification',
    issuer: 'urn:openpc:attestor:isolated-host',
    audience: 'openpc-workload-renewal',
    managedAttestorScopeDigest: hash(40),
    publicKeySpkiDerBase64: Buffer.from(
      attestor.publicKey.export({ type: 'spki', format: 'der' }),
    ).toString('base64'),
    maximumEvidenceLifetimeSeconds: 120,
    validFromNs: (start - second).toString(),
    validUntilNs: (start + 3600n * second).toString(),
    ...profilePatch,
  };
  const policy = {
    version: 1 as const,
    participantId: request.participantId,
    privacyDomainId: request.privacyDomainId,
    policyId: request.policyId,
    principalId: request.principalId,
    workloadId: request.workloadId,
    issuerProfileDigest: request.issuerProfileDigest,
    providerQualificationDigest: request.providerQualificationDigest,
    attestationProfileDigest: managedWorkloadAttestationProfileDigest(profile),
    managedAttestorScopeDigest: profile.managedAttestorScopeDigest,
    maximumInstances: 4,
    maximumEnrollmentsPerMinute: 4,
    certificateLifetimeSeconds: 86400,
    recoveryReserveSeconds: 1800,
    maximumOverlapSeconds: 60,
    validFrom: new Date(instant.getTime() - 1000).toISOString(),
    validUntil: new Date(instant.getTime() + 172800000).toISOString(),
  };
  const {
    profileId,
    profileVersion,
    challengeDigest,
    attestationDigest,
    requestValidFromNs,
    requestValidUntilNs,
    ...shared
  } = request;
  void profileId;
  void profileVersion;
  void challengeDigest;
  void attestationDigest;
  void requestValidFromNs;
  void requestValidUntilNs;
  const challenge: WorkloadRenewalChallenge = {
    ...shared,
    domain: 'pc.identity.workload-renewal.challenge.v1',
    version: 1,
    environmentId: profile.environmentId,
    familySecurityEpoch: '2',
    participantSecurityInvalidationEpoch: '0',
    attestationProfileDigest: policy.attestationProfileDigest,
    managedAttestorScopeDigest: policy.managedAttestorScopeDigest,
    policyDigest: workloadRenewalPolicyDefinitionDigest(policy),
    nonce: randomBytes(32).toString('base64url'),
    requestedCertificateNotBeforeNs: start.toString(),
    requestedCertificateNotAfterNs: (start + 86400n * second).toString(),
    issuedAtNs: start.toString(),
    validUntilNs: (start + 120n * second).toString(),
    ...challengePatch,
  };
  const statement: ManagedWorkloadAttestationStatement = {
    domain: 'pc.identity.workload-renewal.managed-attestation.v1',
    version: 1,
    issuer: profile.issuer,
    audience: profile.audience,
    attestorKeyDigest: workloadRenewalDigest(Buffer.from(profile.publicKeySpkiDerBase64, 'base64')),
    attestationProfileDigest: policy.attestationProfileDigest,
    managedAttestorScopeDigest: policy.managedAttestorScopeDigest,
    challenge,
    challengeDigest: workloadRenewalChallengeDigest(challenge),
    issuedAtNs: (start + second).toString(),
    validUntilNs: (start + 61n * second).toString(),
  };
  const evidenceFor = (value: unknown = statement, privateKey = attestor.privateKey) => {
    const signatureBase64 = sign(
      null,
      Buffer.from(canonicalDefinitionJson(value)),
      privateKey,
    ).toString('base64');
    return Buffer.from(canonicalDefinitionJson({ statement: value, signatureBase64 }));
  };
  const inputFor = (
    evidence = evidenceFor(),
    patch: Partial<typeof request> = {},
    key = successor,
  ) => {
    const payload = encodeWorkloadRenewalRequest({
      ...request,
      ...Object.fromEntries(
        Object.keys(request)
          .filter((field) => field in challenge)
          .map((field) => [field, challenge[field as keyof typeof challenge]]),
      ),
      challengeDigest: statement.challengeDigest,
      attestationDigest: workloadRenewalDigest(evidence),
      requestValidFromNs: statement.issuedAtNs,
      requestValidUntilNs: statement.validUntilNs,
      ...patch,
    });
    const successorSpkiDer = Buffer.from(key.publicKey.export({ type: 'spki', format: 'der' }));
    return {
      evidence,
      requestBytes: payload,
      newKeyProof: signWorkloadRenewalCose(
        'REQUEST',
        Buffer.from(key.privateKey.export({ type: 'pkcs8', format: 'der' })),
        successorSpkiDer,
        payload,
      ),
      successorSpkiDer,
    };
  };
  return {
    attestor,
    successor,
    profile,
    policy,
    challenge,
    statement,
    evidenceFor,
    inputFor,
    expected: {
      challenge,
      profile,
      policyDefinition: policy,
      policyRevision: request.policyRevision,
      nowNs: start + 2n * second,
    },
  };
}

it('authenticates exact independent evidence and frozen375 possession without claiming current admission or one-use consumption', () => {
  const f = fixture(),
    input = f.inputFor();
  const result = verifyManagedWorkloadRenewalAttestation(input, f.expected);
  expect(result).toEqual({
    challengeId: f.challenge.challengeId,
    renewalId: f.challenge.renewalId,
    challengeDigest: workloadRenewalChallengeDigest(f.challenge),
    evidenceDigest: workloadRenewalDigest(input.evidence),
    attestationProfileDigest: f.policy.attestationProfileDigest,
    attestorKeyDigest: f.statement.attestorKeyDigest,
    statementIssuedAtNs: f.statement.issuedAtNs,
    statementValidUntilNs: f.statement.validUntilNs,
  });
  expect(Object.isFrozen(result)).toBe(true);
  // Historical verification is repeatable. Durable owner, not this verifier,
  // must reject a consumed challenge or reconcile its identical original.
  expect(verifyManagedWorkloadRenewalAttestation(input, f.expected)).toEqual(result);
});

it.each([
  ['issuer', 'urn:openpc:attestor:other'],
  ['audience', 'other-audience'],
  ['attestorKeyDigest', hash(90)],
  ['attestationProfileDigest', hash(91)],
  ['managedAttestorScopeDigest', hash(92)],
  ['challengeDigest', hash(93)],
  ['domain', 'pc.identity.workload-renewal.managed-attestation.v2'],
  ['version', 2],
] as const)(
  'rejects a correctly signed statement with wrong %s even after updating the375 evidence digest',
  (field, value) => {
    const f = fixture(),
      statement = { ...f.statement, [field]: value };
    const evidence = f.evidenceFor(statement);
    const envelope = JSON.parse(evidence.toString('utf8'));
    expect(
      verify(
        null,
        Buffer.from(canonicalDefinitionJson(statement)),
        f.attestor.publicKey,
        Buffer.from(envelope.signatureBase64, 'base64'),
      ),
    ).toBe(true);
    expect(
      verifyManagedWorkloadRenewalAttestation(f.inputFor(evidence), f.expected),
    ).toBeUndefined();
  },
);

it.each([
  ['environmentId', 'other-environment'],
  ['participantId', id(70)],
  ['privacyDomainId', id(71)],
  ['principalId', id(72)],
  ['workloadId', `urn:openpc:workload:${id(73)}`],
  ['familyId', id(74)],
  ['instanceId', id(75)],
  ['instanceGeneration', '3'],
  ['familySecurityEpoch', '3'],
  ['participantSecurityInvalidationEpoch', '1'],
  ['renewalId', id(76)],
  ['predecessorCredentialId', id(77)],
  ['predecessorGeneration', '13'],
  ['expectedFamilyRevision', '14'],
  ['policyId', id(78)],
  ['policyRevision', '4'],
  ['policyDigest', hash(70)],
  ['attestationProfileDigest', hash(71)],
  ['managedAttestorScopeDigest', hash(72)],
  ['issuerProfileDigest', hash(73)],
  ['providerQualificationDigest', hash(74)],
  ['newKeyDigest', hash(75)],
  ['challengeId', id(79)],
  ['nonce', Buffer.alloc(32, 7).toString('base64url')],
  ['requestedCertificateNotBeforeNs', (start + second).toString()],
  ['requestedCertificateNotAfterNs', (start + 86399n * second).toString()],
] as const)('rejects independently valid signed challenge substitution at %s', (field, value) => {
  const f = fixture();
  const challenge = { ...f.challenge, [field]: value };
  const evidence = f.evidenceFor({
    ...f.statement,
    challenge,
    challengeDigest: workloadRenewalChallengeDigest(challenge),
  });
  expect(verifyManagedWorkloadRenewalAttestation(f.inputFor(evidence), f.expected)).toBeUndefined();
});

it.each([
  ['familyId', id(80)],
  ['instanceId', id(81)],
  ['instanceGeneration', '8'],
  ['predecessorCredentialId', id(82)],
  ['predecessorGeneration', '21'],
  ['expectedFamilyRevision', '22'],
  ['policyRevision', '6'],
  ['challengeId', id(83)],
  ['challengeDigest', hash(81)],
  ['attestationDigest', hash(82)],
  ['requestedCertificateNotAfterNs', (start + 86399n * second).toString()],
] as const)('rejects valid successor375 proof with different %s', (field, value) => {
  const f = fixture();
  expect(
    verifyManagedWorkloadRenewalAttestation(f.inputFor(undefined, { [field]: value }), f.expected),
  ).toBeUndefined();
});

it('denies a stolen live leaf/new key without independent approved attestor signing possession', () => {
  const f = fixture(),
    attacker = generateKeyPairSync('ed25519');
  const evidence = f.evidenceFor(f.statement, attacker.privateKey);
  expect(verifyManagedWorkloadRenewalAttestation(f.inputFor(evidence), f.expected)).toBeUndefined();
  const otherKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const otherDigest = workloadRenewalDigest(
    Buffer.from(otherKey.publicKey.export({ type: 'spki', format: 'der' })),
  );
  expect(
    verifyManagedWorkloadRenewalAttestation(
      f.inputFor(undefined, { newKeyDigest: otherDigest }, otherKey),
      f.expected,
    ),
  ).toBeUndefined();
});

it('rejects future, expired and older-than60s proof while preserving a separate120s challenge cap', () => {
  const f = fixture();
  for (const statement of [
    { ...f.statement, issuedAtNs: (start + 3n * second).toString() },
    { ...f.statement, validUntilNs: (start + 2n * second).toString() },
    { ...f.statement, validUntilNs: (start + 121n * second).toString() },
    { ...f.statement, issuedAtNs: (start - second).toString() },
  ])
    expect(
      verifyManagedWorkloadRenewalAttestation(f.inputFor(f.evidenceFor(statement)), f.expected),
    ).toBeUndefined();
  const statement = { ...f.statement, validUntilNs: (start + 120n * second).toString() };
  const input = f.inputFor(f.evidenceFor(statement), {
    requestValidUntilNs: statement.validUntilNs,
  });
  expect(
    verifyManagedWorkloadRenewalAttestation(input, { ...f.expected, nowNs: start + 61n * second }),
  ).toBeDefined();
  expect(
    verifyManagedWorkloadRenewalAttestation(input, {
      ...f.expected,
      nowNs: start + 61n * second + 1000n,
    }),
  ).toBeUndefined();
  expect(
    verifyManagedWorkloadRenewalAttestation(f.inputFor(), { ...f.expected, nowNs: start - 1000n }),
  ).toBeUndefined();
  expect(
    verifyManagedWorkloadRenewalAttestation(f.inputFor(), {
      ...f.expected,
      nowNs: start + 120n * second,
    }),
  ).toBeUndefined();
});

it('rejects trusted-parent/profile mismatch and shorter policy/certificate/attestor ceilings', () => {
  const f = fixture(),
    input = f.inputFor();
  for (const expected of [
    { ...f.expected, policyRevision: '4' },
    { ...f.expected, policyDefinition: { ...f.policy, maximumInstances: 5 } },
    {
      ...f.expected,
      policyDefinition: {
        ...f.policy,
        validUntil: new Date(instant.getTime() + 60000).toISOString(),
      },
    },
    { ...f.expected, profile: { ...f.profile, environmentId: 'another-environment' } },
    { ...f.expected, profile: { ...f.profile, validUntilNs: (start + 30n * second).toString() } },
  ])
    expect(verifyManagedWorkloadRenewalAttestation(input, expected)).toBeUndefined();
});

it('enforces the genuinely matching approved profile lifetime rather than merely a mismatched digest', () => {
  const short = fixture({ maximumEvidenceLifetimeSeconds: 5 });
  expect(short.challenge.attestationProfileDigest).toBe(
    managedWorkloadAttestationProfileDigest(short.profile),
  );
  expect(verifyManagedWorkloadRenewalAttestation(short.inputFor(), short.expected)).toBeUndefined();
  const proof = { ...short.statement, validUntilNs: (start + 5n * second).toString() };
  const input = short.inputFor(short.evidenceFor(proof), {
    requestValidUntilNs: proof.validUntilNs,
  });
  expect(verifyManagedWorkloadRenewalAttestation(input, short.expected)).toBeDefined();
});

it.each([
  { requestedCertificateNotBeforeNs: (start + 3n * second).toString() },
  {
    requestedCertificateNotBeforeNs: (start - second).toString(),
    requestedCertificateNotAfterNs: (start + second).toString(),
  },
])(
  'denies an unusable certificate interval despite authentic complete expected-tuple proofs',
  (interval) => {
    const f = fixture({}, interval);
    expect(verifyManagedWorkloadRenewalAttestation(f.inputFor(), f.expected)).toBeUndefined();
  },
);

it('rejects malformed and noncanonical envelopes, duplicate members, extra fields and signature encodings', () => {
  const f = fixture(),
    valid = f.evidenceFor(),
    parsed = JSON.parse(valid.toString('utf8'));
  const cases = [
    Buffer.concat([Buffer.from(' '), valid]),
    Buffer.from(JSON.stringify(parsed)),
    Buffer.from(valid.toString('utf8').replace('"statement":', '"statement":{},"statement":')),
    Buffer.from(canonicalDefinitionJson({ ...parsed, admitted: true })),
    Buffer.from(
      canonicalDefinitionJson({
        ...parsed,
        signatureBase64: parsed.signatureBase64.replace(/=+$/u, ''),
      }),
    ),
    Buffer.alloc(16385),
    Buffer.from([0xff]),
  ];
  // Deliberately reverse top-level members because JSON.stringify may already
  // share the canonical order of these two fields.
  cases[1] = Buffer.from(
    `{"statement":${canonicalDefinitionJson(parsed.statement)},"signatureBase64":${JSON.stringify(parsed.signatureBase64)}}`,
  );
  for (const evidence of cases)
    expect(
      verifyManagedWorkloadRenewalAttestation(f.inputFor(evidence), f.expected),
    ).toBeUndefined();
});

it('rejects noncanonical nonce/u64/time/key inputs and never invokes expected-data getters', () => {
  const f = fixture();
  for (const challenge of [
    { ...f.challenge, nonce: f.challenge.nonce + '=' },
    { ...f.challenge, instanceGeneration: '01' },
    { ...f.challenge, familySecurityEpoch: '18446744073709551616' },
    { ...f.challenge, validUntilNs: (start + 120n * second + 1000n).toString() },
    { ...f.challenge, issuedAtNs: (start + 1n).toString() },
  ])
    expect(() => encodeWorkloadRenewalChallenge(challenge)).toThrow();
  const input = f.inputFor();
  const proof = Buffer.from(input.newKeyProof);
  proof[proof.length - 1] = proof[proof.length - 1]! ^ 1;
  expect(
    verifyManagedWorkloadRenewalAttestation({ ...input, newKeyProof: proof }, f.expected),
  ).toBeUndefined();
  expect(
    verifyManagedWorkloadRenewalAttestation(
      { ...input, successorSpkiDer: Buffer.concat([input.successorSpkiDer, Buffer.from([0])]) },
      f.expected,
    ),
  ).toBeUndefined();
  let accessed = false;
  const profile = { ...f.profile };
  Object.defineProperty(profile, 'issuer', {
    enumerable: true,
    get() {
      accessed = true;
      return f.profile.issuer;
    },
  });
  expect(
    verifyManagedWorkloadRenewalAttestation(input, { ...f.expected, profile }),
  ).toBeUndefined();
  expect(accessed).toBe(false);
});

it('rejects good-first/bad-after evidence substitution despite valid375 possession binding the bad evidence', () => {
  const f = fixture();
  const good = f.evidenceFor();
  const bad = f.evidenceFor({ ...f.statement, audience: 'attacker-audience' });
  const input = f.inputFor(bad);
  expect(verifyManagedWorkloadRenewalAttestation(input, f.expected)).toBeUndefined();
  expect(verifyManagedWorkloadRenewalAttestation(f.inputFor(good), f.expected)).toBeDefined();
  let reads = 0;
  Object.defineProperty(input, 'evidence', {
    enumerable: true,
    get() {
      reads++;
      return reads === 1 ? good : bad;
    },
  });
  expect(verifyManagedWorkloadRenewalAttestation(input, f.expected)).toBeUndefined();
  expect(reads).toBe(0);
});

it.each(['evidence', 'requestBytes', 'newKeyProof', 'successorSpkiDer'] as const)(
  'rejects the outer %s accessor before reading any replacement bytes',
  (field) => {
    const f = fixture(),
      input = f.inputFor(),
      first = input[field];
    let reads = 0;
    Object.defineProperty(input, field, {
      enumerable: true,
      get() {
        reads++;
        return reads === 1 ? first : Buffer.alloc(first.length);
      },
    });
    expect(verifyManagedWorkloadRenewalAttestation(input, f.expected)).toBeUndefined();
    expect(reads).toBe(0);
  },
);

it.each(['challenge', 'profile', 'policyDefinition', 'policyRevision', 'nowNs'] as const)(
  'rejects trusted outer %s accessors instead of accepting a changing expectation',
  (field) => {
    const f = fixture(),
      expected = { ...f.expected },
      initial = expected[field];
    let reads = 0;
    Object.defineProperty(expected, field, {
      enumerable: true,
      get() {
        reads++;
        return initial;
      },
    });
    expect(verifyManagedWorkloadRenewalAttestation(f.inputFor(), expected)).toBeUndefined();
    expect(reads).toBe(0);
  },
);

it('denies missing, inherited, hidden or extra outer data and wrong scalar/binary values', () => {
  const f = fixture(),
    original = f.inputFor();
  const missing = { ...original } as Partial<typeof original>;
  delete missing.newKeyProof;
  const hidden = { ...original };
  Object.defineProperty(hidden, 'evidence', { enumerable: false, value: original.evidence });
  const symbol = { ...original, [Symbol('authority')]: true };
  for (const input of [
    missing,
    hidden,
    symbol,
    Object.create(original),
    { ...original, installed: true },
    { ...original, evidence: new Uint8Array(original.evidence) },
    { ...original, successorSpkiDer: Buffer.alloc(92) },
  ])
    expect(verifyManagedWorkloadRenewalAttestation(input as never, f.expected)).toBeUndefined();
  for (const expected of [
    Object.create(f.expected),
    { ...f.expected, installed: true },
    { ...f.expected, nowNs: '1800000000000000000' },
    { ...f.expected, policyRevision: 3 },
  ])
    expect(verifyManagedWorkloadRenewalAttestation(original, expected as never)).toBeUndefined();
});

it.each(['length', 'copy', 'slice', 'toString', 'constructor'] as const)(
  'rejects input-owned %s binary overrides without invoking them',
  (field) => {
    const f = fixture(),
      input = f.inputFor();
    let reads = 0;
    Object.defineProperty(input.evidence, field, {
      enumerable: true,
      get() {
        reads++;
        throw new Error('must never be read');
      },
    });
    expect(verifyManagedWorkloadRenewalAttestation(input, f.expected)).toBeUndefined();
    expect(reads).toBe(0);
  },
);
