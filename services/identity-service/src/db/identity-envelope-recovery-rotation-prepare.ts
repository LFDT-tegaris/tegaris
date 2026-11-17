import {
  assertHistoricalRecoveryRotationStep,
  recoveryRotationSubject,
  requireCurrentRecoveryRotationActor,
  type RecoveryRotationContext,
} from './identity-envelope-recovery-rotation-context.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { identityEnvelopeSigningTrustDigest } from '@openpc/security-kernel';
import type {
  IdentityEnvelopeRecoveryEnrollment,
  IdentityEnvelopeRecoveryLease,
  IdentityEnvelopeRecoveryRotationPrepareResult,
  IdentityEnvelopeRecoveryRotationDistributionResult,
  IdentityEnvelopeRecoveryRotationVerificationResult,
  IdentityEnvelopeRecoveryRotationCutoverResult,
  IdentityEnvelopeRecoveryRotationObservationResult,
} from '../contracts/identity-envelope-recovery.js';
import {
  identityEnvelopeRecoveryRotationPrepareResult,
  identityEnvelopeRecoveryRotationDistributionResult,
} from '../contracts/identity-envelope-recovery.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationJson,
} from '../contracts/authorization.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import {
  identityEnvelopeRecoveryEvidencePayload,
  signIdentityEnvelopeRecoveryEvidence,
} from '../domain/identity-envelope-recovery-evidence.js';
import {
  identityEnvelopeRotationRequestSchema,
  identityEnvelopeRotationRequestDigest,
  validateIdentityEnvelopeRotationObservation,
  identityEnvelopeRotationDescriptorSchema,
  type IdentityEnvelopeRotationDescriptor,
} from '../domain/identity-envelope-rotation-provider.js';
import { buildIdentityEnvelopeRotationTrust } from '../domain/identity-envelope-rotation-trust.js';
import { captureIdentityEnvelopeRotationSource } from './identity-envelope-rotation-candidate.js';
import { authenticateIdentityEnvelopeRecoveryRotationCreation } from './identity-envelope-recovery-rotation.js';
import {
  resolveIdentityEnvelopeRecoveryRetirement,
  type IdentityEnvelopeRecoveryRotationTerminalResult,
} from './identity-envelope-recovery-rotation-retirement.js';
import { resolveIdentityEnvelopeRecoveryObservation } from './identity-envelope-recovery-rotation-observation.js';
import { resolveIdentityEnvelopeRecoveryCutover } from './identity-envelope-recovery-rotation-cutover.js';
import { resolveIdentityEnvelopeRecoveryVerification } from './identity-envelope-recovery-rotation-verification.js';

/** Dispatch only to the authenticated original phase owner. Raw provider
 * observations never establish completion or ordinary permission effects. */
export async function publishIdentityEnvelopeRecoveryRotationPhase(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<
  | IdentityEnvelopeRecoveryRotationPrepareResult
  | IdentityEnvelopeRecoveryRotationDistributionResult
  | IdentityEnvelopeRecoveryRotationVerificationResult
  | IdentityEnvelopeRecoveryRotationCutoverResult
  | IdentityEnvelopeRecoveryRotationObservationResult
  | IdentityEnvelopeRecoveryRotationTerminalResult
  | undefined
> {
  return resolveIdentityEnvelopeRecoveryRotationPhase(
    client,
    { kind: 'CURRENT', actor },
    enrollment,
    lease,
    operationId,
    localQaEnabled,
    signer,
  );
}

export async function resolveIdentityEnvelopeRecoveryRotationPhase(
  client: PoolClient,
  context: RecoveryRotationContext,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<
  | IdentityEnvelopeRecoveryRotationPrepareResult
  | IdentityEnvelopeRecoveryRotationDistributionResult
  | IdentityEnvelopeRecoveryRotationVerificationResult
  | IdentityEnvelopeRecoveryRotationCutoverResult
  | IdentityEnvelopeRecoveryRotationObservationResult
  | IdentityEnvelopeRecoveryRotationTerminalResult
  | undefined
> {
  const actor = recoveryRotationSubject(context, enrollment, lease);
  const selected = await client.query<{
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
  }>(
    `select s.state,s.from_revision::text as "fromRevision",s.from_state as "fromState",s.to_state as "toState",
      case when s.state='COMMITTED' then false else openpc.identity_envelope_rotation_step_current(s) end as current,openpc.identity_envelope_rotation_step_bound(s) as bound,
      s.result,s.evidence_cbor as cbor,s.evidence_digest as digest,s.cose_sign1 as cose
      from control.identity_envelope_rotation_step s where s.operation_id=$1 and s.participant_id=$2 and s.privacy_domain_id=$3
      and s.rotation_id=$4 and s.recovery_id=$5 and s.principal_id=$6 for update of s`,
    [
      operationId,
      actor.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      lease.recoveryId,
      actor.principalId,
    ],
  );
  const step = selected.rows[0];
  assertHistoricalRecoveryRotationStep(context, step);
  if (
    selected.rowCount === 1 &&
    step?.bound &&
    step.fromRevision === '4' &&
    step.fromState === 'DISTRIBUTED' &&
    step.toState === 'VERIFIED' &&
    actor.principalId === lease.executorPrincipalId
  )
    return resolveIdentityEnvelopeRecoveryVerification(
      client,
      context,
      enrollment,
      lease,
      operationId,
      localQaEnabled,
      signer,
    );
  if (
    selected.rowCount === 1 &&
    step?.bound &&
    step.fromRevision === '5' &&
    step.fromState === 'VERIFIED' &&
    step.toState === 'CUTOVER_FENCED' &&
    actor.principalId === lease.executorPrincipalId
  )
    return resolveIdentityEnvelopeRecoveryCutover(
      client,
      context,
      enrollment,
      lease,
      operationId,
      localQaEnabled,
      signer,
    );
  if (
    selected.rowCount === 1 &&
    step?.bound &&
    step.fromRevision === '6' &&
    step.fromState === 'CUTOVER_FENCED' &&
    step.toState === 'OBSERVING' &&
    actor.principalId === lease.executorPrincipalId
  )
    return resolveIdentityEnvelopeRecoveryObservation(
      client,
      context,
      enrollment,
      lease,
      operationId,
      localQaEnabled,
      signer,
    );
  if (
    selected.rowCount === 1 &&
    step?.bound &&
    ['7', '8', '9'].includes(step.fromRevision) &&
    actor.principalId === lease.executorPrincipalId
  )
    return resolveIdentityEnvelopeRecoveryRetirement(
      client,
      context,
      enrollment,
      lease,
      operationId,
      localQaEnabled,
      signer,
    );
  const distribute =
    step?.fromRevision === '3' && step.fromState === 'PREPARED' && step.toState === 'DISTRIBUTED';
  const prepare =
    step?.fromRevision === '2' && step.fromState === 'APPROVED' && step.toState === 'PREPARED';
  if (
    selected.rowCount !== 1 ||
    !step ||
    !step.bound ||
    (!prepare && !distribute) ||
    actor.principalId !== lease.executorPrincipalId
  )
    throw new PlatformRecoveryError();
  const attempts = await client.query<{
    request: unknown;
    requestDigest: Buffer;
    state: string;
    first: unknown | null;
    firstDigest: Buffer | null;
    observation: unknown | null;
    digest: Buffer | null;
    startedAtNs: string | null;
  }>(
    `select request,request_digest as "requestDigest",state,
      first_observation as first,first_observation_digest as "firstDigest",observation,observation_digest as digest,
      (floor(extract(epoch from started_at)*1000000)*1000)::text as "startedAtNs"
      from control.identity_envelope_rotation_attempt where operation_id=$1 and participant_id=$2 and privacy_domain_id=$3
      and rotation_id=$4 and slot='new' for share`,
    [operationId, actor.participantId, enrollment.privacyDomainId, lease.rotationId],
  );
  const attempt = attempts.rows[0];
  if (attempts.rowCount !== 1 || !attempt) throw new PlatformRecoveryError();
  if (attempt.state !== 'OBSERVED') return undefined;
  const request = identityEnvelopeRotationRequestSchema.parse(attempt.request);
  const prepared = distribute
    ? await resolveIdentityEnvelopeRecoveryPreparedDescriptor(
        client,
        context,
        enrollment,
        lease,
        localQaEnabled,
        signer,
      )
    : undefined;
  const admission = { kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY' as const, enrollment, lease };
  if (
    request.method !== (distribute ? 'DISTRIBUTE' : 'PREPARE') ||
    request.participantId !== actor.participantId ||
    request.privacyDomainId !== enrollment.privacyDomainId ||
    request.environmentId !== enrollment.request.environmentId ||
    request.rotationId !== lease.rotationId ||
    request.operationId !== operationId ||
    request.reference !== enrollment.request.newReference ||
    request.expectedFingerprint !==
      (prepared?.descriptor.fingerprint ?? enrollment.request.newFingerprint) ||
    (distribute &&
      (request.method !== 'DISTRIBUTE' ||
        request.trustContextDigest !== prepared?.result.trustDigest)) ||
    request.workloadCredentialId !== lease.issuer.workloadCredentialId ||
    request.callerWorkloadCredentialId !== lease.issuer.workloadCredentialId ||
    request.workloadCredentialEpoch !== lease.issuer.workloadCredentialEpoch ||
    request.issuerParticipantEpoch !== lease.issuer.workloadParticipantEpoch ||
    request.issuerPrincipalEpoch !== lease.issuer.workloadPrincipalEpoch ||
    request.governanceDigest !==
      canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-rotation-governance.v1',
        admission,
      }) ||
    identityEnvelopeRotationRequestDigest(request) !==
      `sha256:${attempt.requestDigest.toString('hex')}` ||
    attempt.first === null ||
    attempt.observation === null ||
    !attempt.firstDigest ||
    !attempt.digest ||
    canonicalAuthorizationJson(attempt.first) !== canonicalAuthorizationJson(attempt.observation) ||
    !attempt.firstDigest.equals(attempt.digest) ||
    `sha256:${attempt.digest.toString('hex')}` !== canonicalAuthorizationDigest(attempt.observation)
  )
    throw new PlatformRecoveryError();
  const observation = validateIdentityEnvelopeRotationObservation(request, attempt.observation);
  if (
    observation.outcome !== 'SUCCEEDED' ||
    !observation.descriptor ||
    !attempt.startedAtNs ||
    BigInt(observation.recordedAtNs) < BigInt(attempt.startedAtNs) ||
    (prepared &&
      canonicalAuthorizationJson(prepared.descriptor) !==
        canonicalAuthorizationJson(observation.descriptor))
  )
    throw new PlatformRecoveryError();
  const observationsDigest = canonicalAuthorizationDigest([{ request, observation }]);
  if (step.state === 'COMMITTED') {
    const result = (
      distribute
        ? identityEnvelopeRecoveryRotationDistributionResult
        : identityEnvelopeRecoveryRotationPrepareResult
    ).parse(step.result);
    if (
      result.operationId !== operationId ||
      result.rotationId !== lease.rotationId ||
      result.recoveryId !== lease.recoveryId ||
      result.signerId !== observation.descriptor.fingerprint ||
      result.observationsDigest !== observationsDigest ||
      (prepared && result.trustDigest !== prepared.result.trustDigest) ||
      !step.cbor ||
      !step.digest ||
      !step.cose ||
      !step.digest.equals(createHash('sha256').update(step.cbor).digest())
    )
      throw new PlatformRecoveryError();
    const expected = identityEnvelopeRecoveryEvidencePayload({
      enrollment,
      operationId,
      actorPrincipalId: actor.principalId,
      purpose: 'rotation-phase',
      value: result,
      authenticationDigest: lease.proofEvidenceDigest,
      issuedAt: result.completedAt,
      expiresAt: lease.validUntil,
    });
    if (
      !step.cbor.equals(expected) ||
      !(await signer.verifyCanonicalAssertion(expected, step.cose))
    )
      throw new PlatformRecoveryError();
    const event = await client.query<{ matches: boolean }>(
      `select exists(select 1 from control.outbox_event where participant_id=$1
      and privacy_domain_id=$2 and aggregate_type='signing-key-rotation' and aggregate_id=$3 and event_id=$4
      and event_type='openpc.identity.envelope-rotation.phase.v1' and payload_cbor=$5 and payload_digest=$6 and cose_sign1=$7) as matches`,
      [
        actor.participantId,
        enrollment.privacyDomainId,
        lease.rotationId,
        operationId,
        step.cbor,
        step.digest,
        step.cose,
      ],
    );
    if (event.rowCount !== 1 || event.rows[0]?.matches !== true) throw new PlatformRecoveryError();
    return result;
  }
  if (step.state !== 'STARTED' || step.current !== true) return undefined;
  requireCurrentRecoveryRotationActor(context);
  await authenticateIdentityEnvelopeRecoveryRotationCreation(
    client,
    context,
    enrollment,
    lease,
    lease.creationOperationId,
    signer,
  );
  const source = await captureIdentityEnvelopeRotationSource(
    client,
    enrollment,
    enrollment.request,
    signer,
  );
  if (BigInt(observation.recordedAtNs) > source.recordedAtNs) throw new PlatformRecoveryError();
  const trust = buildIdentityEnvelopeRotationTrust({
    oldTrust: source.trust,
    oldLifecycleState: 'ACTIVE',
    descriptor: observation.descriptor,
    preparedIssuer: lease.issuer,
    currentIssuer: source.issuer,
    admission,
    observedAtNs: source.recordedAtNs,
  });
  const trustDigest = identityEnvelopeSigningTrustDigest(trust);
  if (prepared && trustDigest !== prepared.result.trustDigest) throw new PlatformRecoveryError();
  const result = (
    distribute
      ? identityEnvelopeRecoveryRotationDistributionResult
      : identityEnvelopeRecoveryRotationPrepareResult
  ).parse({
    schema: 'pc.identity.identity-envelope-recovery-rotation-phase',
    schemaVersion: 1,
    operationId,
    rotationId: lease.rotationId,
    recoveryId: lease.recoveryId,
    fromRevision: step.fromRevision,
    revision: (BigInt(step.fromRevision) + 1n).toString(),
    state: step.toState,
    signerId: trust.signerId,
    trustDigest,
    observationsDigest,
    completedAt: new Date(Number(source.recordedAtNs / 1000000n)).toISOString(),
  });
  requireCurrentRecoveryRotationActor(context);
  const signed = await signIdentityEnvelopeRecoveryEvidence(
    identityEnvelopeRecoveryEvidencePayload({
      enrollment,
      operationId,
      actorPrincipalId: actor.principalId,
      purpose: 'rotation-phase',
      value: result,
      authenticationDigest: lease.proofEvidenceDigest,
      issuedAt: result.completedAt,
      expiresAt: lease.validUntil,
    }),
    signer,
  );
  await commitIdentityEnvelopeRecoveryRotationPhase(client, {
    actor: requireCurrentRecoveryRotationActor(context),
    enrollment,
    lease,
    result,
    signed,
    fromState: step.fromState,
  });
  return result;
}

/** Read only the immutable descriptor whose PREPARE result and same-operation
 * event authenticate under the original lease. Current epochs are never recaptured. */
export async function readIdentityEnvelopeRecoveryPreparedDescriptor(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<{
  result: IdentityEnvelopeRecoveryRotationPrepareResult;
  descriptor: IdentityEnvelopeRotationDescriptor;
}> {
  return resolveIdentityEnvelopeRecoveryPreparedDescriptor(
    client,
    { kind: 'CURRENT', actor },
    enrollment,
    lease,
    localQaEnabled,
    signer,
  );
}

export async function resolveIdentityEnvelopeRecoveryPreparedDescriptor(
  client: PoolClient,
  context: RecoveryRotationContext,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<{
  result: IdentityEnvelopeRecoveryRotationPrepareResult;
  descriptor: IdentityEnvelopeRotationDescriptor;
}> {
  const actor = recoveryRotationSubject(context, enrollment, lease);
  const rows = await client.query<{ operationId: string; request: unknown; observation: unknown }>(
    `select s.operation_id::text as "operationId",a.request,a.observation
    from control.identity_envelope_rotation_step s join control.identity_envelope_rotation_attempt a
      using(participant_id,privacy_domain_id,rotation_id,operation_id)
    where s.participant_id=$1 and s.privacy_domain_id=$2 and s.rotation_id=$3 and s.recovery_id=$4
      and s.principal_id=$5 and s.from_revision=2 and s.from_state='APPROVED' and s.to_state='PREPARED'
      and s.state='COMMITTED' and a.slot='new' and a.state='OBSERVED'`,
    [
      actor.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      lease.recoveryId,
      actor.principalId,
    ],
  );
  const row = rows.rows[0];
  if (rows.rowCount !== 1 || !row) throw new PlatformRecoveryError();
  const result = await resolveIdentityEnvelopeRecoveryRotationPhase(
    client,
    context,
    enrollment,
    lease,
    row.operationId,
    localQaEnabled,
    signer,
  );
  const request = identityEnvelopeRotationRequestSchema.parse(row.request);
  const observation = validateIdentityEnvelopeRotationObservation(request, row.observation);
  const descriptor = identityEnvelopeRotationDescriptorSchema.parse(observation.descriptor);
  if (
    !result ||
    result.state !== 'PREPARED' ||
    result.signerId !== descriptor.fingerprint ||
    result.observationsDigest !== canonicalAuthorizationDigest([{ request, observation }])
  )
    throw new PlatformRecoveryError();
  return { result, descriptor };
}

/** Read only the immutable descriptor whose DISTRIBUTE result and same-operation
 * event authenticate under the original lease. Current epochs are never recaptured. */
export async function readIdentityEnvelopeRecoveryDistributedDescriptor(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<{
  result: IdentityEnvelopeRecoveryRotationDistributionResult;
  descriptor: IdentityEnvelopeRotationDescriptor;
}> {
  return resolveIdentityEnvelopeRecoveryDistributedDescriptor(
    client,
    { kind: 'CURRENT', actor },
    enrollment,
    lease,
    localQaEnabled,
    signer,
  );
}

export async function resolveIdentityEnvelopeRecoveryDistributedDescriptor(
  client: PoolClient,
  context: RecoveryRotationContext,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<{
  result: IdentityEnvelopeRecoveryRotationDistributionResult;
  descriptor: IdentityEnvelopeRotationDescriptor;
}> {
  const actor = recoveryRotationSubject(context, enrollment, lease);
  const rows = await client.query<{ operationId: string; request: unknown; observation: unknown }>(
    `select s.operation_id::text as "operationId",a.request,a.observation
    from control.identity_envelope_rotation_step s join control.identity_envelope_rotation_attempt a
      using(participant_id,privacy_domain_id,rotation_id,operation_id)
    where s.participant_id=$1 and s.privacy_domain_id=$2 and s.rotation_id=$3 and s.recovery_id=$4
      and s.principal_id=$5 and s.from_revision=3 and s.from_state='PREPARED' and s.to_state='DISTRIBUTED'
      and s.state='COMMITTED' and a.slot='new' and a.state='OBSERVED'`,
    [
      actor.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      lease.recoveryId,
      actor.principalId,
    ],
  );
  const row = rows.rows[0];
  if (rows.rowCount !== 1 || !row) throw new PlatformRecoveryError();
  const result = await resolveIdentityEnvelopeRecoveryRotationPhase(
    client,
    context,
    enrollment,
    lease,
    row.operationId,
    localQaEnabled,
    signer,
  );
  const request = identityEnvelopeRotationRequestSchema.parse(row.request);
  const observation = validateIdentityEnvelopeRotationObservation(request, row.observation);
  const descriptor = identityEnvelopeRotationDescriptorSchema.parse(observation.descriptor);
  if (
    !result ||
    result.state !== 'DISTRIBUTED' ||
    result.signerId !== descriptor.fingerprint ||
    result.observationsDigest !== canonicalAuthorizationDigest([{ request, observation }])
  )
    throw new PlatformRecoveryError();
  return { result, descriptor };
}

/** Same original scoped transaction for signed result, shared state, any exact
 * public trust effect and outbox. Any failure propagates to the public owner's rollback. */
export async function commitIdentityEnvelopeRecoveryRotationPhase(
  client: PoolClient,
  input: {
    actor: AuthenticatedIdentityActor;
    enrollment: IdentityEnvelopeRecoveryEnrollment;
    lease: IdentityEnvelopeRecoveryLease;
    result:
      | IdentityEnvelopeRecoveryRotationPrepareResult
      | IdentityEnvelopeRecoveryRotationDistributionResult
      | IdentityEnvelopeRecoveryRotationVerificationResult
      | IdentityEnvelopeRecoveryRotationCutoverResult
      | IdentityEnvelopeRecoveryRotationObservationResult
      | IdentityEnvelopeRecoveryRotationTerminalResult;
    signed: Awaited<ReturnType<typeof signIdentityEnvelopeRecoveryEvidence>>;
    fromState: string;
  },
  admit?: () => Promise<unknown>,
) {
  const { actor, enrollment, lease, result, signed, fromState } = input;
  const operationId = result.operationId;
  const completed = await client.query(
    `update control.identity_envelope_rotation_step set state='COMMITTED',result=$2,evidence_cbor=$3,
    evidence_digest=$4,cose_sign1=$5,completed_at=$6 where operation_id=$1 and state='STARTED'`,
    [
      operationId,
      result,
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      result.completedAt,
    ],
  );
  if (completed.rowCount !== 1) throw new PlatformRecoveryError();
  const updated = await client.query(
    `update control.signing_key_rotation set state=$6,revision=$7,new_signer_id=$4,updated_at=clock_timestamp(),
    cutover_at_ns=case when $6='CUTOVER_FENCED' then floor(extract(epoch from $10::timestamptz)*1000000)*1000 else cutover_at_ns end
    where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 and recovery_case_id=$5 and state=$8 and revision=$9`,
    [
      actor.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      result.signerId,
      lease.recoveryId,
      result.state,
      result.revision,
      fromState,
      result.fromRevision,
      result.completedAt,
    ],
  );
  if (updated.rowCount !== 1) throw new PlatformRecoveryError();
  if (admit) await admit();
  const head = await client.query(
    `update control.outbox_aggregate_head set last_sequence=$3,updated_at=clock_timestamp()
    where participant_id=$1 and aggregate_type='signing-key-rotation' and aggregate_id=$2 and last_sequence=$4`,
    [
      actor.participantId,
      lease.rotationId,
      (BigInt(result.revision) - 1n).toString(),
      (BigInt(result.fromRevision) - 1n).toString(),
    ],
  );
  if (head.rowCount !== 1) throw new PlatformRecoveryError();
  await client.query(
    `insert into control.outbox_event(participant_id,privacy_domain_id,aggregate_type,aggregate_id,aggregate_sequence,
    event_id,event_type,payload_cbor,payload_digest,cose_sign1,occurred_at)
    values($1,$2,'signing-key-rotation',$3,$9,$4,'openpc.identity.envelope-rotation.phase.v1',$5,$6,$7,$8)`,
    [
      actor.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      operationId,
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      result.completedAt,
      (BigInt(result.revision) - 1n).toString(),
    ],
  );
}
