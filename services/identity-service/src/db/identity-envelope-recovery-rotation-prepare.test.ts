import { createHash, generateKeyPairSync } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryEnrollment,
  identityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
import {
  identityEnvelopeRotationRequestSchema,
  identityEnvelopeRotationRequestDigest,
  identityEnvelopeRotationDescriptorSchema,
} from '../domain/identity-envelope-rotation-provider.js';
import {
  publishIdentityEnvelopeRecoveryRotationPhase,
  resolveIdentityEnvelopeRecoveryRotationPhase,
} from './identity-envelope-recovery-rotation-prepare.js';
const owner = vi.hoisted(() => ({ source: vi.fn(), creation: vi.fn() }));
vi.mock('./identity-envelope-rotation-candidate.js', () => ({
  captureIdentityEnvelopeRotationSource: owner.source,
}));
vi.mock('./identity-envelope-recovery-rotation.js', () => ({
  authenticateIdentityEnvelopeRecoveryRotationCreation: owner.creation,
}));
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const f = identityEnvelopeRecoveryFixture();
  const at = BigInt(f.now.getTime()) * 1000000n;
  const oldKey = Buffer.from(
    generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
      format: 'der',
      type: 'spki',
    }),
  );
  const newKey = Buffer.from(
    generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
      format: 'der',
      type: 'spki',
    }),
  );
  const oldTrust: IdentityEnvelopeSigningTrust = {
    participantId: f.enrollment.participantId,
    privacyDomainId: f.enrollment.privacyDomainId,
    environmentId: 'local',
    signerId: evidenceKeyId(oldKey),
    publicKeySpkiDer: oldKey,
    workloadCredentialId: f.enrollment.request.workloadCredentialId,
    workloadCredentialEpoch: 1n,
    workloadParticipantEpoch: 1n,
    workloadPrincipalEpoch: 1n,
    keyEpoch: 1n,
    validFromNs: at - 1000000000n,
    validUntilNs: at + 7200000000000n,
    admissionKind: 'BOOTSTRAP',
    admissionReference: 'initial-unit-trust',
    admissionDigest: Buffer.alloc(32, 1),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: f.enrollment.request.oldReference,
    secretVersion: '1',
    purpose: identityEnvelopeContext.purpose,
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
  };
  const enrollment = identityEnvelopeRecoveryEnrollment.parse({
    ...f.enrollment,
    oldTrustDigest: identityEnvelopeSigningTrustDigest(oldTrust),
    request: { ...f.enrollment.request, oldFingerprint: oldTrust.signerId },
  });
  const issuer = {
    participantId: enrollment.participantId,
    privacyDomainId: enrollment.privacyDomainId,
    workloadCredentialId: enrollment.request.workloadCredentialId,
    workloadPrincipalId: enrollment.issuerPrincipalId,
    workloadParticipantEpoch: '7',
    workloadPrincipalEpoch: '2',
    workloadCredentialEpoch: '1',
    workloadPublicKeyDigest: enrollment.issuerCredentialPublicKeyDigest,
    credentialValidFromNs: (at - 1000000000n).toString(),
    credentialValidUntilNs: (at + 7200000000000n).toString(),
  };
  const lease = identityEnvelopeRecoveryLease.parse({
    schema: 'pc.identity.identity-envelope-recovery-lease',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: id(400),
    enrollmentId: enrollment.enrollmentId,
    enrollmentDigest: canonicalAuthorizationDigest(enrollment),
    intentDigest: 'sha256:' + '11'.repeat(32),
    rotationId: id(401),
    creationOperationId: id(402),
    activationOperationId: id(403),
    executorPrincipalId: enrollment.recoveryPrincipal.principalId,
    issuer,
    oldTrustDigest: enrollment.oldTrustDigest,
    selectionAdmissionVersion: '1',
    proofIds: [id(600), id(601), id(602), id(603)],
    proofEvidenceDigest: 'sha256:' + '77'.repeat(32),
    validFrom: f.now.toISOString(),
    validUntil: new Date(f.now.getTime() + 900000).toISOString(),
    postReviewRequired: true,
  });
  const admission = { kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY', enrollment, lease };
  const actor = {
    participantId: enrollment.participantId,
    principalId: lease.executorPrincipalId,
    platform: true,
    sessionToken: 'unit-only',
  };
  const request = identityEnvelopeRotationRequestSchema.parse({
    participantId: enrollment.participantId,
    privacyDomainId: enrollment.privacyDomainId,
    environmentId: 'local',
    workloadCredentialId: issuer.workloadCredentialId,
    workloadCredentialEpoch: '1',
    secretClass: 'SECRET-SIGNING-KEY',
    reference: enrollment.request.newReference,
    version: '2',
    purpose: identityEnvelopeContext.purpose,
    purposeCode: 371,
    schemaId: 24034,
    schemaVersion: 1,
    schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
    callerWorkloadCredentialId: issuer.workloadCredentialId,
    rotationId: lease.rotationId,
    operationId: id(700),
    attemptId: id(701),
    issuerParticipantEpoch: '7',
    issuerPrincipalEpoch: '2',
    governanceDigest: canonicalAuthorizationDigest({
      domain: 'pc.identity.envelope-rotation-governance.v1',
      admission,
    }),
    method: 'PREPARE',
  });
  const descriptor = identityEnvelopeRotationDescriptorSchema.parse({
    participantId: request.participantId,
    privacyDomainId: request.privacyDomainId,
    environmentId: request.environmentId,
    workloadCredentialId: request.workloadCredentialId,
    workloadCredentialEpoch: request.workloadCredentialEpoch,
    secretClass: request.secretClass,
    reference: request.reference,
    version: request.version,
    purpose: request.purpose,
    purposeCode: request.purposeCode,
    schemaId: request.schemaId,
    schemaVersion: request.schemaVersion,
    schemaDefinitionDigest: request.schemaDefinitionDigest,
    profileId: request.profileId,
    profileVersion: request.profileVersion,
    profileDigest: request.profileDigest,
    algorithm: 'ES256',
    publicKeySpkiHex: newKey.toString('hex'),
    fingerprint: evidenceKeyId(newKey),
    validFromNs: at.toString(),
    validUntilNs: (at + 3600000000000n).toString(),
    state: 'ACTIVE',
    revokedAtNs: null,
    retiredAtNs: null,
  });
  const observation = {
    schemaVersion: 1,
    providerId: 'unit-provider',
    attemptId: request.attemptId,
    operationId: request.operationId,
    requestDigest: identityEnvelopeRotationRequestDigest(request),
    method: 'PREPARE',
    recordedAtNs: (at + 1000000n).toString(),
    outcome: 'SUCCEEDED',
    reason: null,
    descriptor,
    resultHex: null,
  };
  const attempt = {
    request,
    requestDigest: Buffer.from(identityEnvelopeRotationRequestDigest(request).slice(7), 'hex'),
    state: 'OBSERVED',
    first: observation,
    firstDigest: canonicalAuthorizationDigestBytes(observation),
    observation,
    digest: canonicalAuthorizationDigestBytes(observation),
    startedAtNs: at.toString(),
  };
  const step: {
    state: string;
    fromRevision: string;
    fromState: string;
    toState: string;
    current: boolean;
    bound: boolean;
    result: unknown | null;
    cbor: Buffer | null;
    digest: Buffer | null;
    cose: Buffer | null;
  } = {
    state: 'STARTED',
    fromRevision: '2',
    fromState: 'APPROVED',
    toState: 'PREPARED',
    current: true,
    bound: true,
    result: null,
    cbor: null,
    digest: null,
    cose: null,
  };
  const events: string[] = [];
  let outbox = true;
  const query = vi.fn(
    async (sql: string, parameters?: unknown[]): Promise<{ rowCount: number; rows: unknown[] }> => {
      if (sql.includes('from control.identity_envelope_rotation_step'))
        return { rowCount: 1, rows: [step] };
      if (sql.includes('from control.identity_envelope_rotation_attempt'))
        return { rowCount: 1, rows: [attempt] };
      if (sql.startsWith('select exists')) return { rowCount: 1, rows: [{ matches: outbox }] };
      if (sql.startsWith('update control.identity_envelope_rotation_step')) {
        events.push('step');
        step.state = 'COMMITTED';
        step.result = parameters![1];
        step.cbor = parameters![2] as Buffer;
        step.digest = parameters![3] as Buffer;
        step.cose = parameters![4] as Buffer;
        return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith('update control.signing_key_rotation')) {
        events.push('rotation');
        return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith('update control.outbox_aggregate_head')) {
        events.push('head');
        return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith('insert into control.outbox_event')) {
        events.push('outbox');
        return { rowCount: 1, rows: [] };
      }
      throw new Error('unexpected SQL');
    },
  );
  const source = { trust: oldTrust, issuer, recordedAtNs: at + 2000000n };
  owner.source.mockResolvedValue(source);
  const signer = {
    signCanonicalAssertion: vi.fn(async (payload: Buffer) => {
      events.push('sign');
      return {
        evidenceCbor: payload,
        evidenceDigest: createHash('sha256').update(payload).digest(),
        coseSign1: Buffer.from('unit-only'),
        signerKeyDigest: Buffer.alloc(32, 1),
      };
    }),
    verifyCanonicalAssertion: vi.fn(async () => ({ signerKeyDigest: Buffer.alloc(32, 1) })),
  };
  const publish = () =>
    publishIdentityEnvelopeRecoveryRotationPhase(
      { query } as never,
      actor,
      enrollment,
      lease,
      request.operationId,
      true,
      signer,
    );
  return {
    actor,
    enrollment,
    lease,
    request,
    descriptor,
    observation,
    attempt,
    step,
    source,
    query,
    signer,
    events,
    publish,
    missingOutbox: () => {
      outbox = false;
    },
  };
}
const mutations = (f: ReturnType<typeof fixture>) =>
  f.query.mock.calls.filter(([sql]) => /^(insert|update|delete)/u.test(sql));

async function distributionFixture() {
  const f = fixture();
  const prepared = await f.publish();
  const originalStep = { ...f.step };
  const originalAttempt = { ...f.attempt };
  const originalQuery = f.query.getMockImplementation()!;
  const request = identityEnvelopeRotationRequestSchema.parse({
    ...f.request,
    method: 'DISTRIBUTE',
    operationId: id(710),
    attemptId: id(711),
    expectedFingerprint: f.descriptor.fingerprint,
    trustContextDigest: prepared!.trustDigest,
  });
  const observation = {
    ...f.observation,
    method: 'DISTRIBUTE',
    operationId: request.operationId,
    attemptId: request.attemptId,
    recordedAtNs: (BigInt(f.observation.recordedAtNs) + 3000000n).toString(),
    requestDigest: identityEnvelopeRotationRequestDigest(request),
  };
  Object.assign(f.attempt, {
    request,
    requestDigest: Buffer.from(identityEnvelopeRotationRequestDigest(request).slice(7), 'hex'),
    first: observation,
    observation,
    firstDigest: canonicalAuthorizationDigestBytes(observation),
    digest: canonicalAuthorizationDigestBytes(observation),
    startedAtNs: (BigInt(f.observation.recordedAtNs) + 2000000n).toString(),
  });
  Object.assign(f.step, {
    state: 'STARTED',
    fromRevision: '3',
    fromState: 'PREPARED',
    toState: 'DISTRIBUTED',
    result: null,
    cbor: null,
    digest: null,
    cose: null,
  });
  f.source.recordedAtNs += 3000000n;
  let present = true;
  f.query.mockImplementation(async (sql, params) => {
    if (sql.startsWith('select s.operation_id::text'))
      return {
        rowCount: present ? 1 : 0,
        rows: present
          ? [
              {
                operationId: f.request.operationId,
                request: originalAttempt.request,
                observation: originalAttempt.observation,
              },
            ]
          : [],
      };
    if (
      sql.includes('from control.identity_envelope_rotation_step') &&
      params?.[0] === f.request.operationId
    )
      return { rowCount: 1, rows: [originalStep] };
    if (
      sql.includes('from control.identity_envelope_rotation_attempt') &&
      params?.[0] === f.request.operationId
    )
      return { rowCount: 1, rows: [originalAttempt] };
    return originalQuery(sql, params);
  });
  f.query.mockClear();
  f.events.length = 0;
  f.signer.signCanonicalAssertion.mockClear();
  owner.source.mockClear();
  return {
    ...f,
    originalStep,
    originalAttempt,
    request,
    observation,
    missingPrepared: () => {
      present = false;
    },
    distribute: () =>
      publishIdentityEnvelopeRecoveryRotationPhase(
        { query: f.query } as never,
        f.actor,
        f.enrollment,
        f.lease,
        request.operationId,
        true,
        f.signer,
      ),
  };
}

it('publishes DISTRIBUTE for exactly the signed PREPARE descriptor and trust digest, with no admission or selection', async () => {
  const f = await distributionFixture();
  expect(await f.distribute()).toMatchObject({
    operationId: f.request.operationId,
    fromRevision: '3',
    revision: '4',
    state: 'DISTRIBUTED',
    trustDigest: (f.originalStep.result as { trustDigest: string }).trustDigest,
  });
  expect(f.events).toEqual(['sign', 'step', 'rotation', 'head', 'outbox']);
  expect(mutations(f)).toHaveLength(4);
  expect(
    mutations(f).every(
      ([sql]) => !/(business_signing_key|signing_selection|signing_grant)/u.test(sql),
    ),
  ).toBe(true);
  const head = mutations(f).find(([sql]) => sql.startsWith('update control.outbox_aggregate_head'));
  expect(head?.[1]?.slice(-2)).toEqual(['3', '2']);
});

it('authenticates completed distribution and predecessor on expired historical replay without signing or current-source capture', async () => {
  const f = await distributionFixture();
  const result = await f.distribute();
  f.step.current = false;
  f.originalStep.current = false;
  f.query.mockClear();
  f.events.length = 0;
  owner.source.mockClear();
  f.signer.signCanonicalAssertion.mockClear();
  expect(await f.distribute()).toEqual(result);
  expect(mutations(f)).toHaveLength(0);
  expect(owner.source).not.toHaveBeenCalled();
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});

it.each([
  'missing-prepare',
  'unsigned-prepare',
  'prepare-result',
  'prepare-observation',
  'descriptor',
  'trust-context',
] as const)('rejects DISTRIBUTE %s before new signing or effects', async (kind) => {
  const f = await distributionFixture();
  if (kind === 'missing-prepare') f.missingPrepared();
  if (kind === 'unsigned-prepare') f.originalStep.cose = null;
  if (kind === 'prepare-result')
    f.originalStep.result = {
      ...(f.originalStep.result as object),
      signerId: 'sha256:' + '99'.repeat(32),
    };
  if (kind === 'prepare-observation') f.originalAttempt.digest = Buffer.alloc(32, 9);
  if (kind === 'descriptor') {
    f.observation.descriptor = {
      ...f.descriptor,
      validUntilNs: (BigInt(f.descriptor.validUntilNs) - 1000n).toString(),
    };
    f.attempt.first = f.observation;
    f.attempt.observation = f.observation;
    f.attempt.firstDigest = canonicalAuthorizationDigestBytes(f.observation);
    f.attempt.digest = canonicalAuthorizationDigestBytes(f.observation);
  }
  if (kind === 'trust-context') {
    const request = { ...f.request, trustContextDigest: 'sha256:' + '99'.repeat(32) };
    f.attempt.request = request;
    f.attempt.requestDigest = Buffer.from(
      identityEnvelopeRotationRequestDigest(request).slice(7),
      'hex',
    );
  }
  await expect(f.distribute()).rejects.toThrow();
  expect(mutations(f)).toHaveLength(0);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it('signs and commits the original prepared metadata, shared state and outbox without admitting trust or changing selection', async () => {
  const f = fixture();
  expect(await f.publish()).toMatchObject({
    operationId: f.request.operationId,
    rotationId: f.lease.rotationId,
    revision: '3',
    state: 'PREPARED',
    signerId: f.descriptor.fingerprint,
  });
  expect(f.events).toEqual(['sign', 'step', 'rotation', 'head', 'outbox']);
  expect(mutations(f)).toHaveLength(4);
  expect(
    mutations(f).every(
      ([sql]) =>
        !/(business_signing_key|signing_selection|signing_grant|authority_envelope)/u.test(sql),
    ),
  ).toBe(true);
});
it('authenticates the original signed result and event on expired replay without current-source capture or new effects', async () => {
  const f = fixture();
  const result = await f.publish();
  f.query.mockClear();
  f.events.length = 0;
  f.step.current = false;
  owner.source.mockClear();
  f.signer.signCanonicalAssertion.mockClear();
  expect(await f.publish()).toEqual(result);
  expect(mutations(f)).toEqual([]);
  expect(owner.source).not.toHaveBeenCalled();
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each(['pending', 'stale-lease', 'ambiguous'] as const)(
  'retains %s without claiming preparation or signing',
  async (kind) => {
    const f = fixture();
    if (kind === 'pending') f.attempt.state = 'STARTED';
    if (kind === 'stale-lease') f.step.current = false;
    if (kind === 'ambiguous') f.step.state = 'WRITE_AMBIGUITY';
    expect(await f.publish()).toBeUndefined();
    expect(mutations(f)).toEqual([]);
    expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  },
);
it.each([
  'wrong-phase',
  'unbound',
  'wrong-request-digest',
  'changed-first',
  'changed-observation-digest',
  'before-start',
  'future-result',
  'issuer-drift',
  'creation-proof',
] as const)('rejects %s before signing or durable publication', async (kind) => {
  const f = fixture();
  if (kind === 'wrong-phase') f.step.toState = 'VERIFIED';
  if (kind === 'unbound') f.step.bound = false;
  if (kind === 'wrong-request-digest') f.attempt.requestDigest = Buffer.alloc(32, 9);
  if (kind === 'changed-first')
    f.attempt.first = { ...f.observation, providerId: 'changed-provider' };
  if (kind === 'changed-observation-digest') f.attempt.digest = Buffer.alloc(32, 9);
  if (kind === 'before-start')
    f.attempt.startedAtNs = (BigInt(f.observation.recordedAtNs) + 1000n).toString();
  if (kind === 'future-result') f.source.recordedAtNs = BigInt(f.observation.recordedAtNs) - 1000n;
  if (kind === 'issuer-drift')
    f.source.issuer = { ...f.source.issuer, workloadPrincipalEpoch: '3' };
  if (kind === 'creation-proof') owner.creation.mockRejectedValue(new Error('bad creation proof'));
  await expect(f.publish()).rejects.toThrow();
  expect(mutations(f)).toEqual([]);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each(['result', 'digest', 'signature', 'outbox'] as const)(
  'rejects corrupted historical %s without replaying effects',
  async (kind) => {
    const f = fixture();
    await f.publish();
    f.query.mockClear();
    f.signer.signCanonicalAssertion.mockClear();
    if (kind === 'result')
      f.step.result = { ...(f.step.result as object), signerId: 'sha256:' + '99'.repeat(32) };
    if (kind === 'digest') f.step.digest = Buffer.alloc(32, 9);
    if (kind === 'signature') f.signer.verifyCanonicalAssertion.mockResolvedValue(false as never);
    if (kind === 'outbox') f.missingOutbox();
    await expect(f.publish()).rejects.toThrow();
    expect(mutations(f)).toEqual([]);
    expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  },
);
it('publication CAS failure propagates for transaction rollback instead of returning success', async () => {
  const f = fixture();
  const original = f.query.getMockImplementation()!;
  f.query.mockImplementation(async (sql, params) =>
    sql.startsWith('update control.signing_key_rotation')
      ? { rowCount: 0, rows: [] }
      : original(sql, params),
  );
  await expect(f.publish()).rejects.toThrow();
  expect(f.events).toEqual(['sign', 'step']);
});

it('historical-only resolution authenticates committed preparation without an authenticated-session surrogate', async () => {
  const f = fixture();
  const original = await f.publish();
  f.query.mockClear();
  owner.source.mockClear();
  owner.creation.mockClear();
  f.signer.signCanonicalAssertion.mockClear();
  f.step.current = false;
  const result = await resolveIdentityEnvelopeRecoveryRotationPhase(
    { query: f.query } as never,
    {
      kind: 'HISTORICAL',
      subject: {
        participantId: f.enrollment.participantId,
        principalId: f.lease.executorPrincipalId,
      },
    },
    f.enrollment,
    f.lease,
    f.request.operationId,
    false,
    f.signer,
  );
  expect(result).toEqual(original);
  expect(mutations(f)).toHaveLength(0);
  expect(owner.source).not.toHaveBeenCalled();
  expect(owner.creation).not.toHaveBeenCalled();
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  expect(f.signer.verifyCanonicalAssertion).toHaveBeenCalled();
});
