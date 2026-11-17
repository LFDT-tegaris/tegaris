import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import { buildIdentityEnvelopeRotationTrust } from './identity-envelope-rotation-trust.js';
import type { IdentityEnvelopeRotationDescriptor } from './identity-envelope-rotation-provider.js';
import type { IdentityEnvelopeRotationIssuer } from '../db/identity-envelope-rotation-issuer.js';
import { identityEnvelopeRecoveryFixture } from './identity-envelope-recovery.test-fixture.js';
import {
  identityEnvelopeRecoveryEnrollment,
  identityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { planIdentityEnvelopeRotationAttempts } from './identity-envelope-rotation-plan.js';
import type { IdentityEnvelopeRotationPlanInput } from './identity-envelope-rotation-plan.js';
const id = (n: number) => `01990000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const oldKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
  type: 'spki',
  format: 'der',
});

function recoveryInput() {
  const f = identityEnvelopeRecoveryFixture();
  const nowNs = BigInt(f.now.getTime()) * 1000000n;
  const historical = {
    ...oldTrust,
    validFromNs: nowNs - 1000000n,
    validUntilNs: nowNs + 7200000000000n,
  };
  const current = {
    ...issuer,
    workloadPrincipalEpoch: '2',
    credentialValidFromNs: (nowNs - 1000000n).toString(),
    credentialValidUntilNs: (nowNs + 7200000000000n).toString(),
  };
  const next = {
    ...descriptor,
    validFromNs: nowNs.toString(),
    validUntilNs: (nowNs + 3600000000000n).toString(),
  };
  const enrollment = identityEnvelopeRecoveryEnrollment.parse({
    ...f.enrollment,
    participantId: oldTrust.participantId,
    privacyDomainId: oldTrust.privacyDomainId,
    issuerPrincipalId: current.workloadPrincipalId,
    issuerCredentialPublicKeyDigest: current.workloadPublicKeyDigest,
    oldTrustDigest: identityEnvelopeSigningTrustDigest(historical),
    request: {
      ...f.enrollment.request,
      environmentId: oldTrust.environmentId,
      workloadCredentialId: oldTrust.workloadCredentialId,
      oldFingerprint: oldTrust.signerId,
      oldReference: oldTrust.secretReference,
      newReference: next.reference,
    },
  });
  const lease = identityEnvelopeRecoveryLease.parse({
    schema: 'pc.identity.identity-envelope-recovery-lease',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: id(20),
    enrollmentId: enrollment.enrollmentId,
    enrollmentDigest: canonicalAuthorizationDigest(enrollment),
    intentDigest: 'sha256:' + '77'.repeat(32),
    rotationId: id(21),
    creationOperationId: id(22),
    activationOperationId: id(23),
    executorPrincipalId: enrollment.recoveryPrincipal.principalId,
    issuer: current,
    oldTrustDigest: enrollment.oldTrustDigest,
    selectionAdmissionVersion: enrollment.selectionAdmissionVersion,
    proofIds: [id(24), id(25), id(26), id(27)],
    proofEvidenceDigest: 'sha256:' + '78'.repeat(32),
    validFrom: f.now.toISOString(),
    validUntil: new Date(f.now.getTime() + 900000).toISOString(),
    postReviewRequired: true,
  });
  return {
    ...input(),
    oldTrust: historical,
    descriptor: next,
    preparedIssuer: current,
    currentIssuer: current,
    observedAtNs: nowNs + 1000000n,
    admission: { kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY' as const, enrollment, lease },
  };
}
describe('exact custody provenance for purpose371 successor trust', () => {
  it('binds the enrolled current credential while preserving immutable predecessor trust', () => {
    const value = recoveryInput();
    const before = identityEnvelopeSigningTrustPreimage(value.oldTrust);
    const successor = id(98);
    for (const issuer of [
      value.preparedIssuer,
      value.currentIssuer,
      value.admission.lease.issuer,
    ]) {
      issuer.workloadCredentialId = successor;
      issuer.workloadCredentialEpoch = '2';
    }
    value.descriptor.workloadCredentialId = successor;
    value.descriptor.workloadCredentialEpoch = '2';
    value.admission.enrollment.request.workloadCredentialId = successor;
    value.admission.enrollment.issuerCredentialEpoch = '2';
    value.admission.lease.enrollmentDigest = canonicalAuthorizationDigest(
      value.admission.enrollment,
    );
    const trust = buildIdentityEnvelopeRotationTrust(value);
    expect(trust.workloadCredentialId).toBe(successor);
    expect(trust.workloadCredentialEpoch).toBe(2n);
    expect(identityEnvelopeSigningTrustPreimage(value.oldTrust)).toEqual(before);
    const plan = planIdentityEnvelopeRotationAttempts(
      {
        request: value.admission.enrollment.request,
        rotationId: value.admission.lease.rotationId,
        operationId: id(50),
        state: 'APPROVED',
        toState: 'PREPARED',
        ...value,
        callerWorkloadCredentialId: successor,
        nowNs: value.observedAtNs,
        authorityValidUntilNs: BigInt(Date.parse(value.admission.lease.validUntil)) * 1000000n,
      },
      () => id(51),
    );
    expect(plan.attempts[0]?.request.workloadCredentialId).toBe(successor);
    value.descriptor.workloadCredentialId = value.oldTrust.workloadCredentialId;
    expect(() => buildIdentityEnvelopeRotationTrust(value)).toThrow();
  });
  it('records recovery provenance and post-fence epochs without inventing an ordinary approval', () => {
    const value = recoveryInput();
    const original = identityEnvelopeSigningTrustPreimage(value.oldTrust);
    const trust = buildIdentityEnvelopeRotationTrust(value);
    expect(trust.admissionReference).toBe(
      `urn:openpc:resource:${value.admission.lease.rotationId}`,
    );
    expect(trust.admissionKind).toBe('GOVERNED');
    expect(trust.workloadParticipantEpoch).toBe(7n);
    expect(trust.workloadPrincipalEpoch).toBe(2n);
    expect(trust.workloadCredentialEpoch).toBe(1n);
    expect(identityEnvelopeSigningTrustPreimage(value.oldTrust)).toEqual(original);
    expect(value.admission).not.toHaveProperty('approvalRequestId');
    const changed = recoveryInput();
    changed.admission.lease.proofEvidenceDigest = 'sha256:' + '79'.repeat(32);
    expect(buildIdentityEnvelopeRotationTrust(changed).admissionDigest).not.toEqual(
      trust.admissionDigest,
    );
  });
  it.each([
    'foreign-enrollment',
    'changed-enrollment',
    'wrong-executor',
    'stale-issuer',
    'wrong-rotation-source',
    'wrong-reference',
    'future-lease',
    'expired-lease',
    'enrollment-expiry',
    'duplicate-custodians',
    'ordinary-approval-alias',
  ])('rejects %s recovery provenance', (failure) => {
    const value = recoveryInput();
    const { enrollment, lease } = value.admission;
    if (failure === 'foreign-enrollment') lease.enrollmentId = id(99);
    if (failure === 'changed-enrollment') enrollment.rootRevision = '2';
    if (failure === 'wrong-executor')
      lease.executorPrincipalId = enrollment.custodians[0].principalId;
    if (failure === 'stale-issuer')
      value.currentIssuer = { ...value.currentIssuer, workloadPrincipalEpoch: '1' };
    if (failure === 'wrong-rotation-source') lease.oldTrustDigest = 'sha256:' + '80'.repeat(32);
    if (failure === 'wrong-reference') value.descriptor.reference = 'secret://local/foreign#2';
    if (failure === 'future-lease')
      value.observedAtNs = BigInt(Date.parse(lease.validFrom)) * 1000000n - 1000n;
    if (failure === 'expired-lease')
      value.observedAtNs = BigInt(Date.parse(lease.validUntil)) * 1000000n;
    if (failure === 'enrollment-expiry') {
      enrollment.validUntil = new Date(Date.parse(lease.validUntil) - 1).toISOString();
      lease.enrollmentDigest = canonicalAuthorizationDigest(enrollment);
    }
    if (failure === 'duplicate-custodians') enrollment.custodians[1] = enrollment.custodians[0];
    if (failure === 'ordinary-approval-alias')
      Object.assign(value.admission, { approvalRequestId: lease.recoveryId });
    expect(() => buildIdentityEnvelopeRotationTrust(value)).toThrow();
  });
});

function planInput(): IdentityEnvelopeRotationPlanInput {
  const f = recoveryInput();
  return {
    request: f.admission.enrollment.request,
    rotationId: f.admission.lease.rotationId,
    operationId: id(50),
    state: 'APPROVED',
    toState: 'PREPARED',
    oldTrust: f.oldTrust,
    preparedIssuer: f.preparedIssuer,
    currentIssuer: f.currentIssuer,
    admission: f.admission,
    callerWorkloadCredentialId: f.currentIssuer.workloadCredentialId,
    nowNs: f.observedAtNs,
    authorityValidUntilNs: BigInt(Date.parse(f.admission.lease.validUntil)) * 1000000n,
  };
}
describe('purpose371 attempts under exact custody admission', () => {
  it('prepares only the enrolled new reference and actual Participant workload transport', () => {
    const f = planInput();
    const planned = planIdentityEnvelopeRotationAttempts(f, () => id(51));
    expect(planned.attempts).toHaveLength(1);
    expect(planned.attempts[0]).toMatchObject({
      slot: 'new',
      request: {
        method: 'PREPARE',
        purposeCode: 371,
        reference: f.request.newReference,
        callerWorkloadCredentialId: f.currentIssuer.workloadCredentialId,
        issuerParticipantEpoch: '7',
        issuerPrincipalEpoch: '2',
        governanceDigest: planned.governanceDigest,
      },
    });
    expect(planned.successor).toBeUndefined();
  });
  it('distributes the exact future trust context and independently bounds old/new possession challenges', () => {
    const f = {
      ...planInput(),
      descriptor: recoveryInput().descriptor,
      state: 'PREPARED' as const,
      toState: 'DISTRIBUTED' as const,
    };
    const distributed = planIdentityEnvelopeRotationAttempts(f, () => id(52));
    expect(distributed.attempts[0]!.request).toMatchObject({
      method: 'DISTRIBUTE',
      trustContextDigest: identityEnvelopeSigningTrustDigest(distributed.successor!),
    });
    let n = 53;
    const proven = planIdentityEnvelopeRotationAttempts(
      { ...f, state: 'DISTRIBUTED', toState: 'VERIFIED' },
      () => id(n++),
    );
    expect(proven.attempts.map((a) => a.slot)).toEqual(['old', 'new']);
    for (const attempt of proven.attempts) {
      expect(attempt.request.method).toBe('PROVE');
      if (attempt.request.method !== 'PROVE') throw Error('invalid proof fixture');
      expect(attempt.request.challengeHex).toBe(
        identityEnvelopeSigningTrustDigest(proven.successor!).slice(7),
      );
      expect(BigInt(attempt.request.challengeExpiresAtNs)).toBe(f.nowNs + 300000000000n);
    }
    const short = planIdentityEnvelopeRotationAttempts(
      {
        ...f,
        state: 'DISTRIBUTED',
        toState: 'VERIFIED',
        authorityValidUntilNs: f.nowNs + 1000000000n,
      },
      () => id(n++),
    );
    for (const attempt of short.attempts)
      if (attempt.request.method === 'PROVE')
        expect(BigInt(attempt.request.challengeExpiresAtNs)).toBe(f.nowNs + 1000000000n);
  });
  it.each([
    'foreign-caller',
    'issuer-drift',
    'changed-enrolled-request',
    'wrong-rotation',
    'expired-lease',
    'extended-authority',
    'wrong-issuer-fence',
    'wrong-executor',
    'receipt-purpose',
    'unsupported-transition',
  ])('rejects %s before allocating an attempt', (failure) => {
    const f = planInput();
    const admission = f.admission;
    if (!('kind' in admission)) throw Error('invalid custody fixture');
    if (failure === 'foreign-caller') Object.assign(f, { callerWorkloadCredentialId: id(99) });
    if (failure === 'issuer-drift')
      Object.assign(f, { currentIssuer: { ...f.currentIssuer, workloadParticipantEpoch: '8' } });
    if (failure === 'changed-enrolled-request')
      Object.assign(f, { request: { ...f.request, reason: 'caller-changed intent' } });
    if (failure === 'wrong-rotation') Object.assign(f, { rotationId: id(99) });
    if (failure === 'expired-lease') Object.assign(f, { nowNs: f.authorityValidUntilNs });
    if (failure === 'extended-authority')
      Object.assign(f, { authorityValidUntilNs: f.authorityValidUntilNs + 1000n });
    if (failure === 'wrong-issuer-fence') {
      admission.enrollment.issuerPrincipalEpoch = '2';
      admission.lease.enrollmentDigest = canonicalAuthorizationDigest(admission.enrollment);
    }
    if (failure === 'wrong-executor')
      admission.lease.executorPrincipalId = admission.enrollment.custodians[0].principalId;
    if (failure === 'receipt-purpose')
      Object.assign(f.request, { purpose: 'pc.cose.business-transition-receipt.v1' });
    if (failure === 'unsupported-transition') Object.assign(f, { toState: 'OLD_REVOKED' });
    let allocated = false;
    expect(() =>
      planIdentityEnvelopeRotationAttempts(f, () => {
        allocated = true;
        return id(51);
      }),
    ).toThrow();
    expect(allocated).toBe(false);
  });
  it('requires the provider descriptor before allocating later effects and rejects duplicate attempt identities', () => {
    const f = planInput();
    expect(() =>
      planIdentityEnvelopeRotationAttempts(
        { ...f, state: 'PREPARED', toState: 'DISTRIBUTED' },
        () => id(51),
      ),
    ).toThrow();
    expect(() =>
      planIdentityEnvelopeRotationAttempts(
        { ...f, descriptor: recoveryInput().descriptor, state: 'DISTRIBUTED', toState: 'VERIFIED' },
        () => id(51),
      ),
    ).toThrow();
  });
});
const newKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
  type: 'spki',
  format: 'der',
});
const oldTrust: IdentityEnvelopeSigningTrust = {
  participantId: id(1),
  privacyDomainId: id(2),
  environmentId: 'disposable-qa',
  signerId: evidenceKeyId(oldKey),
  publicKeySpkiDer: oldKey,
  workloadCredentialId: id(3),
  workloadCredentialEpoch: 1n,
  workloadParticipantEpoch: 1n,
  workloadPrincipalEpoch: 1n,
  keyEpoch: 1n,
  validFromNs: 1000n,
  validUntilNs: 900000n,
  admissionKind: 'BOOTSTRAP',
  admissionReference: 'initial-test-trust',
  admissionDigest: Buffer.alloc(32, 1),
  secretClass: 'SECRET-SIGNING-KEY',
  secretReference: 'secret://local/envelope-issuer#1',
  secretVersion: '1',
  purpose: 'pc.cose.identity-authority-envelope.v1',
  profileId: 'pc.identity.authority-envelope.v1',
  profileVersion: 1,
  profileDigest: identityEnvelopeSigningProfileDigest,
};
const descriptor: IdentityEnvelopeRotationDescriptor = {
  participantId: id(1),
  privacyDomainId: id(2),
  environmentId: 'disposable-qa',
  workloadCredentialId: id(3),
  workloadCredentialEpoch: '1',
  secretClass: 'SECRET-SIGNING-KEY',
  reference: 'secret://local/envelope-issuer#2',
  version: '2',
  purpose: oldTrust.purpose,
  purposeCode: 371,
  schemaId: 24034,
  schemaVersion: 1,
  schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
  profileId: oldTrust.profileId,
  profileVersion: 1,
  profileDigest: identityEnvelopeSigningProfileDigest,
  algorithm: 'ES256',
  publicKeySpkiHex: newKey.toString('hex'),
  fingerprint: evidenceKeyId(newKey),
  validFromNs: '2000',
  validUntilNs: '800000',
  state: 'ACTIVE',
  revokedAtNs: null,
  retiredAtNs: null,
};
const issuer: IdentityEnvelopeRotationIssuer = {
  participantId: id(1),
  privacyDomainId: id(2),
  workloadCredentialId: id(3),
  workloadPrincipalId: id(4),
  workloadParticipantEpoch: '7',
  workloadPrincipalEpoch: '1',
  workloadCredentialEpoch: '1',
  workloadPublicKeyDigest: 'sha256:' + '71'.repeat(32),
  credentialValidFromNs: '1000',
  credentialValidUntilNs: '900000',
};
const admission = {
  rotationId: id(5),
  operationId: id(6),
  candidateDigest: 'sha256:' + '72'.repeat(32),
  approvalRequestId: id(7),
  approvalDecisionDigest: 'sha256:' + '73'.repeat(32),
  makerPrincipalId: id(8),
  checkerPrincipalId: id(9),
  oldTrustDigest: identityEnvelopeSigningTrustDigest(oldTrust),
};
function input() {
  return {
    oldTrust,
    oldLifecycleState: 'ACTIVE' as const,
    descriptor,
    preparedIssuer: issuer,
    currentIssuer: issuer,
    admission,
    observedAtNs: 3000n,
  };
}
describe('immutable governed purpose371 successor trust construction', () => {
  it('binds new trust to current issuer epochs and preserves historical signed bytes', () => {
    const original = identityEnvelopeSigningTrustPreimage(oldTrust);
    const result = buildIdentityEnvelopeRotationTrust(input());
    expect(result.workloadParticipantEpoch).toBe(7n);
    expect(result.keyEpoch).toBe(2n);
    expect(result.admissionKind).toBe('GOVERNED');
    expect(result.signerId).toBe(descriptor.fingerprint);
    expect(identityEnvelopeSigningTrustDigest(result)).not.toBe(admission.oldTrustDigest);
    expect(identityEnvelopeSigningTrustPreimage(oldTrust)).toEqual(original);
    expect(oldTrust.workloadParticipantEpoch).toBe(1n);
  });
  it.each(['REVOKED', 'RETIRED'] as const)('never revives old %s trust', (state) => {
    expect(() =>
      buildIdentityEnvelopeRotationTrust({ ...input(), oldLifecycleState: state }),
    ).toThrow();
  });
  it.each([
    { participantId: id(99) },
    { privacyDomainId: id(99) },
    { environmentId: 'foreign' },
    { workloadCredentialId: id(99) },
    { workloadCredentialEpoch: '2' },
    { reference: oldTrust.secretReference, version: oldTrust.secretVersion },
    { fingerprint: oldTrust.signerId, publicKeySpkiHex: oldKey.toString('hex') },
    { validUntilNs: '901000' },
  ])('rejects incompatible successor metadata: %j', (change) => {
    expect(() =>
      buildIdentityEnvelopeRotationTrust({ ...input(), descriptor: { ...descriptor, ...change } }),
    ).toThrow();
  });
  it('rejects self approval, changed historical provenance and issuer drift after preparation', () => {
    expect(() =>
      buildIdentityEnvelopeRotationTrust({
        ...input(),
        admission: { ...admission, checkerPrincipalId: admission.makerPrincipalId },
      }),
    ).toThrow();
    expect(() =>
      buildIdentityEnvelopeRotationTrust({
        ...input(),
        admission: { ...admission, oldTrustDigest: 'sha256:' + '74'.repeat(32) },
      }),
    ).toThrow();
    expect(() =>
      buildIdentityEnvelopeRotationTrust({
        ...input(),
        currentIssuer: { ...issuer, workloadParticipantEpoch: '8' },
      }),
    ).toThrow();
  });
  it('separates signing keys from workload authentication keys', () => {
    const collision = { ...issuer, workloadPublicKeyDigest: descriptor.fingerprint };
    expect(() =>
      buildIdentityEnvelopeRotationTrust({
        ...input(),
        currentIssuer: collision,
        preparedIssuer: collision,
      }),
    ).toThrow();
  });
  it('binds authenticated approval provenance and rejects stale/overflowing preparation', () => {
    const first = buildIdentityEnvelopeRotationTrust(input());
    const changed = buildIdentityEnvelopeRotationTrust({
      ...input(),
      admission: { ...admission, approvalDecisionDigest: 'sha256:' + '75'.repeat(32) },
    });
    expect(changed.admissionDigest).not.toEqual(first.admissionDigest);
    expect(() =>
      buildIdentityEnvelopeRotationTrust({ ...input(), observedAtNs: 800000n }),
    ).toThrow();
    expect(() =>
      buildIdentityEnvelopeRotationTrust({
        ...input(),
        oldTrust: { ...oldTrust, keyEpoch: 18446744073709551615n },
        admission: {
          ...admission,
          oldTrustDigest: identityEnvelopeSigningTrustDigest({
            ...oldTrust,
            keyEpoch: 18446744073709551615n,
          }),
        },
      }),
    ).toThrow();
  });
});
