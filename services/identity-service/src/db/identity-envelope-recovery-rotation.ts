import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import type {
  IdentityEnvelopeRecoveryEnrollment,
  IdentityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
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
import { readIdentityEnvelopeRecoveryReceipt } from './identity-envelope-recovery-readback.js';
import { readRecoveryEnrollmentPurpose } from './recovery-enrollment-purpose.js';
import {
  recoveryRotationSubject,
  type RecoveryRotationContext,
} from './identity-envelope-recovery-rotation-context.js';

/** Resolve the original server reservation under authenticated custody. The
 * caller ends this read transaction before opening the actual operation. */
export async function resolveIdentityEnvelopeRecoveryRotationOperation(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
) {
  if (
    (await readRecoveryEnrollmentPurpose(client, actor.participantId, enrollmentId)) !==
    'pc.identity.identity-envelope-recovery-enrollment'
  )
    throw new PlatformRecoveryError();
  const read = await readIdentityEnvelopeRecoveryReceipt(
    client,
    actor,
    enrollmentId,
    recoveryId,
    localQaEnabled,
    signer,
    'CUSTODY_ONLY',
  );
  if (!read.receipt.lease || actor.principalId !== read.receipt.lease.executorPrincipalId)
    throw new PlatformRecoveryError();
  return read.receipt.lease.creationOperationId;
}

/** Verifies only the original signed creation. Callers own custody and any
 * current-authority checks needed for new work. Missing history never creates a
 * rotation, signs evidence or supplies current authority. */
export async function authenticateIdentityEnvelopeRecoveryRotationCreation(
  client: PoolClient,
  context: RecoveryRotationContext,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  signer: IdentityRuntimeEvidenceSigner,
) {
  const actor = recoveryRotationSubject(context, enrollment, lease);
  if (
    operationId !== lease.creationOperationId ||
    lease.enrollmentDigest !== canonicalAuthorizationDigest(enrollment) ||
    lease.oldTrustDigest !== enrollment.oldTrustDigest ||
    lease.executorPrincipalId !== enrollment.recoveryPrincipal.principalId
  )
    throw new PlatformRecoveryError();
  const prior = await client.query<{
    request: unknown;
    recoveryId: string;
    candidateDigest: Buffer;
    maker: string;
    approvalId: string | null;
    approvedOperationId: string;
    createdAt: Date;
  }>(
    `select r.request,r.recovery_case_id::text as "recoveryId",r.candidate_digest as "candidateDigest",
      r.maker_principal_id::text as maker,r.approval_request_id::text as "approvalId",
      r.approved_operation_id::text as "approvedOperationId",r.created_at as "createdAt"
     from control.signing_key_rotation r join control.platform_recovery_case c
      on c.participant_id=r.participant_id and c.privacy_domain_id=r.privacy_domain_id
      and c.recovery_id=r.recovery_case_id
     where r.participant_id=$1 and r.privacy_domain_id=$2 and r.rotation_id=$3
      and c.recovery_id=$4 and c.signer_repair_enrollment_id=$5
      and c.enrollment_digest=$6 and c.lease_bindings=$7::jsonb`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      lease.recoveryId,
      enrollment.enrollmentId,
      canonicalAuthorizationDigestBytes(enrollment),
      lease,
    ],
  );
  const row = prior.rows[0];
  const candidateDigest = canonicalAuthorizationDigest({ request: enrollment.request, lease });
  if (
    prior.rowCount !== 1 ||
    !row ||
    row.recoveryId !== lease.recoveryId ||
    row.maker !== actor.principalId ||
    row.approvalId !== null ||
    row.approvedOperationId !== lease.activationOperationId ||
    canonicalAuthorizationJson(row.request) !== canonicalAuthorizationJson(enrollment.request) ||
    `sha256:${row.candidateDigest.toString('hex')}` !== candidateDigest
  )
    throw new PlatformRecoveryError();
  const createdMs = new Date(row.createdAt).getTime();
  if (
    !Number.isFinite(createdMs) ||
    createdMs < Date.parse(lease.validFrom) ||
    createdMs >= Date.parse(lease.validUntil)
  )
    throw new PlatformRecoveryError();
  const result = {
    schema: 'pc.identity.identity-envelope-recovery-rotation-creation',
    schemaVersion: 1,
    operationId,
    recoveryId: lease.recoveryId,
    enrollmentId: enrollment.enrollmentId,
    rotationId: lease.rotationId,
    candidateDigest,
    revision: '2',
    state: 'APPROVED',
    createdAt: new Date(createdMs).toISOString(),
  } as const;
  const payload = identityEnvelopeRecoveryEvidencePayload({
    enrollment,
    operationId,
    actorPrincipalId: actor.principalId,
    purpose: 'rotation-creation',
    value: result,
    authenticationDigest: lease.proofEvidenceDigest,
    issuedAt: result.createdAt,
    expiresAt: lease.validUntil,
  });
  const event = await client.query<{ cbor: Buffer; digest: Buffer; cose: Buffer }>(
    `select payload_cbor as cbor,payload_digest as digest,cose_sign1 as cose from control.outbox_event
     where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='signing-key-rotation'
      and aggregate_id=$3 and aggregate_sequence=1 and event_id=$4
      and event_type='openpc.identity.envelope-rotation.created.v1'`,
    [enrollment.participantId, enrollment.privacyDomainId, lease.rotationId, operationId],
  );
  const saved = event.rows[0];
  if (
    event.rowCount !== 1 ||
    !saved ||
    !saved.cbor.equals(payload) ||
    !saved.digest.equals(createHash('sha256').update(payload).digest()) ||
    !(await signer.verifyCanonicalAssertion(payload, saved.cose))
  )
    throw new PlatformRecoveryError();
  return result;
}

/** Creation consumes no ordinary approval/grant and performs no provider I/O.
 * The one lease reservation, rotation and signed event commit together. */
export async function createIdentityEnvelopeRecoveryRotation(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
) {
  await client.query('select * from openpc.lock_identity_envelope_recovery_enrollment($1)', [
    enrollmentId,
  ]);
  const read = await readIdentityEnvelopeRecoveryReceipt(
    client,
    actor,
    enrollmentId,
    recoveryId,
    localQaEnabled,
    signer,
  );
  const lease = read.receipt.lease;
  const e = read.enrollment;
  if (
    !lease ||
    actor.principalId !== lease.executorPrincipalId ||
    operationId !== lease.creationOperationId
  )
    throw new PlatformRecoveryError();
  const candidateDigest = canonicalAuthorizationDigest({ request: e.request, lease });
  const prior = await client.query<{
    request: unknown;
    recoveryId: string;
    candidateDigest: Buffer;
    maker: string;
    approvalId: string | null;
    approvedOperationId: string;
    createdAt: Date;
    state: string;
    revision: string;
  }>(
    `select request,recovery_case_id::text as "recoveryId",candidate_digest as "candidateDigest",
    maker_principal_id::text as maker,approval_request_id::text as "approvalId",approved_operation_id::text as "approvedOperationId",
    created_at as "createdAt",state,revision::text as revision from control.signing_key_rotation
    where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 for update`,
    [e.participantId, e.privacyDomainId, lease.rotationId],
  );
  const row = prior.rows[0];
  if (
    (prior.rowCount ?? 0) > 1 ||
    (row &&
      (row.recoveryId !== recoveryId ||
        row.maker !== actor.principalId ||
        row.approvalId !== null ||
        row.approvedOperationId !== lease.activationOperationId ||
        canonicalAuthorizationJson(row.request) !== canonicalAuthorizationJson(e.request) ||
        `sha256:${row.candidateDigest.toString('hex')}` !== candidateDigest))
  )
    throw new PlatformRecoveryError();
  const clock = await client.query<{ now: Date; current: boolean }>(
    'select clock_timestamp() as now,openpc.identity_envelope_recovery_lease_current($1) as current',
    [recoveryId],
  );
  const now = clock.rows[0]?.now;
  if (clock.rowCount !== 1 || !now || !Number.isFinite(new Date(now).getTime()))
    throw new PlatformRecoveryError();
  const createdAt = new Date(row?.createdAt ?? now).toISOString();
  const result = {
    schema: 'pc.identity.identity-envelope-recovery-rotation-creation',
    schemaVersion: 1,
    operationId,
    recoveryId,
    enrollmentId,
    rotationId: lease.rotationId,
    candidateDigest,
    revision: '2',
    state: 'APPROVED',
    createdAt,
  } as const;
  const payload = identityEnvelopeRecoveryEvidencePayload({
    enrollment: e,
    operationId,
    actorPrincipalId: actor.principalId,
    purpose: 'rotation-creation',
    value: result,
    authenticationDigest: lease.proofEvidenceDigest,
    issuedAt: createdAt,
    expiresAt: lease.validUntil,
  });
  if (row) {
    const event = await client.query<{ cbor: Buffer; digest: Buffer; cose: Buffer }>(
      `select payload_cbor as cbor,payload_digest as digest,cose_sign1 as cose from control.outbox_event
       where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='signing-key-rotation'
        and aggregate_id=$3 and aggregate_sequence=1 and event_id=$4
        and event_type='openpc.identity.envelope-rotation.created.v1'`,
      [e.participantId, e.privacyDomainId, lease.rotationId, operationId],
    );
    const saved = event.rows[0];
    if (
      event.rowCount !== 1 ||
      !saved ||
      !saved.cbor.equals(payload) ||
      !saved.digest.equals(createHash('sha256').update(payload).digest()) ||
      !(await signer.verifyCanonicalAssertion(payload, saved.cose))
    )
      throw new PlatformRecoveryError();
    return {
      ...result,
      replay: true,
      currentState: row.state,
      currentRevision: row.revision,
      authority: read.receipt.authority,
      evidenceDigest: `sha256:${saved.digest.toString('hex')}`,
    };
  }
  if (
    read.receipt.authority !== 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY' ||
    clock.rows[0]!.current !== true ||
    Date.parse(createdAt) < Date.parse(lease.validFrom) ||
    Date.parse(createdAt) >= Date.parse(lease.validUntil)
  )
    throw new PlatformRecoveryError();
  const action = await client.query<{ digest: Buffer }>(
    `select semantic_digest as digest from control.action_intent
    where action_intent_id=$1 and resource_type='signing-key-rotation' and operation_class='CREATE' and maker_checker_required`,
    [e.request.actionIntentId],
  );
  if (
    action.rowCount !== 1 ||
    `sha256:${action.rows[0]!.digest.toString('hex')}` !== e.request.actionIntentDigest
  )
    throw new PlatformRecoveryError();
  const signed = await signIdentityEnvelopeRecoveryEvidence(payload, signer);
  const inserted = await client.query(
    `insert into control.signing_key_rotation
    (participant_id,privacy_domain_id,rotation_id,request,candidate_digest,maker_principal_id,recovery_case_id,
     environment_id,workload_credential_id,old_signer_id,old_trust_digest,state,revision,created_at,updated_at)
     values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'REQUESTED',1,$12,$12)`,
    [
      e.participantId,
      e.privacyDomainId,
      lease.rotationId,
      e.request,
      canonicalAuthorizationDigestBytes({ request: e.request, lease }),
      actor.principalId,
      recoveryId,
      e.request.environmentId,
      e.request.workloadCredentialId,
      e.request.oldFingerprint,
      Buffer.from(lease.oldTrustDigest.slice(7), 'hex'),
      createdAt,
    ],
  );
  if (inserted.rowCount !== 1) throw new PlatformRecoveryError();
  const approved = await client.query(
    `update control.signing_key_rotation set state='APPROVED',revision=2,
    approved_operation_id=$4,updated_at=clock_timestamp() where participant_id=$1 and privacy_domain_id=$2
    and rotation_id=$3 and state='REQUESTED' and revision=1`,
    [e.participantId, e.privacyDomainId, lease.rotationId, lease.activationOperationId],
  );
  if (approved.rowCount !== 1) throw new PlatformRecoveryError();
  await client.query(
    `insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence)
    values($1,'signing-key-rotation',$2,1)`,
    [e.participantId, lease.rotationId],
  );
  await client.query(
    `insert into control.outbox_event(participant_id,privacy_domain_id,aggregate_type,aggregate_id,
    aggregate_sequence,event_id,event_type,payload_cbor,payload_digest,cose_sign1,occurred_at)
    values($1,$2,'signing-key-rotation',$3,1,$4,'openpc.identity.envelope-rotation.created.v1',$5,$6,$7,$8)`,
    [
      e.participantId,
      e.privacyDomainId,
      lease.rotationId,
      operationId,
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      createdAt,
    ],
  );
  return {
    ...result,
    replay: false,
    currentState: 'APPROVED',
    currentRevision: '2',
    authority: read.receipt.authority,
    evidenceDigest: `sha256:${signed.evidenceDigest.toString('hex')}`,
  };
}
