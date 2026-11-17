import type { PoolClient } from 'pg';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
  canonicalAuthorizationJson,
} from '../contracts/authorization.js';
import type {
  IdentityEnvelopeRecoveryEnrollment,
  IdentityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { planIdentityEnvelopeRotationAttempts } from '../domain/identity-envelope-rotation-plan.js';
import {
  identityEnvelopeRotationRequestDigest,
  identityEnvelopeRotationRequestSchema,
  validateIdentityEnvelopeRotationObservation,
} from '../domain/identity-envelope-rotation-provider.js';
import { localOperationId } from '../domain/local-operation-id.js';
import type { PlatformRecoveryCommand } from './platform-recovery-command.js';
import { readIdentityEnvelopeRecoveryReceipt } from './identity-envelope-recovery-readback.js';
import {
  resolveIdentityEnvelopeRecoveryRotationOperation,
  authenticateIdentityEnvelopeRecoveryRotationCreation,
} from './identity-envelope-recovery-rotation.js';
import { captureIdentityEnvelopeRotationSource } from './identity-envelope-rotation-candidate.js';
import {
  publishIdentityEnvelopeRecoveryRotationPhase,
  readIdentityEnvelopeRecoveryPreparedDescriptor,
  readIdentityEnvelopeRecoveryDistributedDescriptor,
} from './identity-envelope-recovery-rotation-prepare.js';
import { captureIdentityEnvelopeRotationSuccessorSource } from './identity-envelope-rotation-successor-source.js';
import { readIdentityEnvelopeRotationConsumer } from '../../../participant-service/src/identity-envelope-rotation-consumer.js';
import type { IdentityEnvelopeRotationDescriptor } from '../domain/identity-envelope-rotation-provider.js';

type Advance = Extract<PlatformRecoveryCommand, { kind: 'ROTATION_ADVANCE' }>;
interface Step {
  operationId: string;
  rotationId: string;
  recoveryId: string;
  principalId: string;
  fromRevision: string;
  fromState: string;
  toState: string;
  state: string;
  consumerActivationOperationId?: string | null;
  consumerObservationOperationId?: string | null;
  authorityBinding: unknown;
  authorityDigest: Buffer;
}
async function existing(client: PoolClient, actor: AuthenticatedIdentityActor, command: Advance) {
  const selected = await client.query<Step>(
    `select operation_id::text as "operationId",rotation_id::text as "rotationId",recovery_id::text as "recoveryId",
    principal_id::text as "principalId",from_revision::text as "fromRevision",from_state as "fromState",to_state as "toState",state,
    consumer_activation_operation_id::text as "consumerActivationOperationId",consumer_observation_operation_id::text as "consumerObservationOperationId",authority_binding as "authorityBinding",authority_digest as "authorityDigest" from control.identity_envelope_rotation_step
    where participant_id=$1 and openpc.matches_privacy(privacy_domain_id) and principal_id=$2 and idempotency_key=$3`,
    [actor.participantId, actor.principalId, command.idempotencyKey],
  );
  if ((selected.rowCount ?? 0) > 1) throw new PlatformRecoveryError();
  const step = selected.rows[0];
  if (
    step &&
    (step.recoveryId !== command.recoveryId ||
      step.fromRevision !== command.expectedRevision ||
      step.principalId !== actor.principalId)
  )
    throw new PlatformRecoveryError();
  return step;
}
/** A supported exact replay selects the original operation. Allocation supplies
 * no authority; the write transaction must recheck every source before READY. */
export async function resolveIdentityEnvelopeRecoveryRotationStep(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  command: Advance,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
) {
  await resolveIdentityEnvelopeRecoveryRotationOperation(
    client,
    actor,
    enrollmentId,
    command.recoveryId,
    localQaEnabled,
    signer,
  );
  const step = await existing(client, actor, command);
  return step?.operationId ?? localOperationId();
}
async function readAttempts(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  step: Step,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  prepared?: { descriptor: IdentityEnvelopeRotationDescriptor; result: { trustDigest: string } },
) {
  const selected = await client.query<{
    slot: string;
    request: unknown;
    digest: Buffer;
    state: string;
    first: unknown | null;
    observation: unknown | null;
    ambiguityKind: string | null;
  }>(
    `select slot,request,request_digest as digest,state,first_observation as first,observation,ambiguity_kind as "ambiguityKind"
      from control.identity_envelope_rotation_attempt where participant_id=$1 and rotation_id=$2 and operation_id=$3
      and openpc.matches_privacy(privacy_domain_id) order by slot`,
    [actor.participantId, step.rotationId, step.operationId],
  );
  if (
    (step.fromRevision === '5' &&
      step.fromState === 'VERIFIED' &&
      step.toState === 'CUTOVER_FENCED') ||
    (step.fromRevision === '9' &&
      step.fromState === 'OLD_RETIRED' &&
      step.toState === 'COMPLETE' &&
      !!step.consumerObservationOperationId)
  ) {
    if (selected.rowCount !== 0) throw new PlatformRecoveryError();
    return [];
  }
  const distribute =
    step.fromRevision === '3' && step.fromState === 'PREPARED' && step.toState === 'DISTRIBUTED';
  const prepare =
    step.fromRevision === '2' && step.fromState === 'APPROVED' && step.toState === 'PREPARED';
  const verify =
    step.fromRevision === '4' && step.fromState === 'DISTRIBUTED' && step.toState === 'VERIFIED';
  const observe =
    step.fromRevision === '6' &&
    step.fromState === 'CUTOVER_FENCED' &&
    step.toState === 'OBSERVING';
  const revoke =
    step.fromRevision === '7' && step.fromState === 'OBSERVING' && step.toState === 'OLD_REVOKED';
  const retire =
    step.fromRevision === '8' && step.fromState === 'OLD_REVOKED' && step.toState === 'OLD_RETIRED';
  if (
    selected.rowCount !== (verify ? 2 : 1) ||
    (!prepare && !distribute && !verify && !observe && !revoke && !retire) ||
    ((distribute || verify || observe || revoke || retire) && !prepared) ||
    (verify &&
      (new Set(selected.rows.map((r) => r.slot)).size !== 2 ||
        selected.rows.some((r) => !['old', 'new'].includes(r.slot)))) ||
    (!verify &&
      selected.rows[0]?.slot !== (observe ? 'effective' : revoke || retire ? 'old' : 'new')) ||
    (observe && !step.consumerActivationOperationId) ||
    ((revoke || retire) && !step.consumerObservationOperationId)
  )
    throw new PlatformRecoveryError();
  return selected.rows.map((row) => {
    const request = identityEnvelopeRotationRequestSchema.parse(row.request);
    if (
      request.rotationId !== step.rotationId ||
      request.operationId !== step.operationId ||
      request.method !==
        (verify || observe
          ? 'PROVE'
          : revoke
            ? 'REVOKE'
            : retire
              ? 'RETIRE'
              : distribute
                ? 'DISTRIBUTE'
                : 'PREPARE') ||
      request.participantId !== actor.participantId ||
      request.privacyDomainId !== enrollment.privacyDomainId ||
      request.environmentId !== enrollment.request.environmentId ||
      request.workloadCredentialId !== lease.issuer.workloadCredentialId ||
      request.callerWorkloadCredentialId !== lease.issuer.workloadCredentialId ||
      request.workloadCredentialEpoch !== lease.issuer.workloadCredentialEpoch ||
      request.issuerParticipantEpoch !== lease.issuer.workloadParticipantEpoch ||
      request.issuerPrincipalEpoch !== lease.issuer.workloadPrincipalEpoch ||
      request.reference !==
        (row.slot === 'old' ? enrollment.request.oldReference : enrollment.request.newReference) ||
      request.expectedFingerprint !==
        (row.slot === 'old'
          ? enrollment.request.oldFingerprint
          : (prepared?.descriptor.fingerprint ?? enrollment.request.newFingerprint)) ||
      (distribute &&
        (request.method !== 'DISTRIBUTE' ||
          request.trustContextDigest !== prepared?.result.trustDigest)) ||
      ((verify || observe) &&
        (request.method !== 'PROVE' ||
          request.challengeHex !== prepared?.result.trustDigest.slice(7))) ||
      request.governanceDigest !==
        canonicalAuthorizationDigest({
          domain: 'pc.identity.envelope-rotation-governance.v1',
          admission: step.authorityBinding,
        }) ||
      identityEnvelopeRotationRequestDigest(request) !== `sha256:${row.digest.toString('hex')}`
    )
      throw new PlatformRecoveryError();
    const first =
      row.first === null
        ? undefined
        : validateIdentityEnvelopeRotationObservation(request, row.first);
    if (
      row.observation !== null &&
      (first === undefined ||
        canonicalAuthorizationJson(first) !==
          canonicalAuthorizationJson(
            validateIdentityEnvelopeRotationObservation(request, row.observation),
          ))
    )
      throw new PlatformRecoveryError();
    return {
      attemptId: request.attemptId,
      method: request.method,
      state: row.state,
      ambiguityKind: row.ambiguityKind,
    };
  });
}
/** Commit an immutable exact request before Participant alone acquires STARTED
 * and touches provider transport. No provider bytes, approval seed or effect is
 * supplied by the browser, and a queue receipt never claims business completion. */
export async function queueIdentityEnvelopeRecoveryRotation(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  command: Advance,
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
    command.recoveryId,
    localQaEnabled,
    signer,
  );
  const lease = read.receipt.lease;
  if (!lease || actor.principalId !== lease.executorPrincipalId) throw new PlatformRecoveryError();
  const binding = {
    kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY' as const,
    enrollment: read.enrollment,
    lease,
  };
  const step = await existing(client, actor, command);
  if (step) {
    if (
      step.operationId !== operationId ||
      step.rotationId !== lease.rotationId ||
      canonicalAuthorizationJson(step.authorityBinding) !== canonicalAuthorizationJson(binding) ||
      !step.authorityDigest.equals(canonicalAuthorizationDigestBytes(binding))
    )
      throw new PlatformRecoveryError();
    const prepared = [
      'PREPARED',
      'DISTRIBUTED',
      'CUTOVER_FENCED',
      'OBSERVING',
      'OLD_REVOKED',
      'OLD_RETIRED',
    ].includes(step.fromState)
      ? await (
          step.fromState !== 'PREPARED'
            ? readIdentityEnvelopeRecoveryDistributedDescriptor
            : readIdentityEnvelopeRecoveryPreparedDescriptor
        )(client, actor, read.enrollment, lease, localQaEnabled, signer)
      : undefined;
    const attempts = await readAttempts(client, actor, step, read.enrollment, lease, prepared);
    const result = await publishIdentityEnvelopeRecoveryRotationPhase(
      client,
      actor,
      read.enrollment,
      lease,
      operationId,
      localQaEnabled,
      signer,
    );
    let state = result === undefined ? step.state : 'COMMITTED';
    if (state === 'WRITE_AMBIGUITY') {
      // This exact public replay requests historical lookup only. Preserve the
      // original attempt, STARTED timestamp, first response and first failure;
      // never reset an attempt to READY or create a replacement request.
      if (
        !attempts.some((a) => a.state === 'WRITE_AMBIGUITY') ||
        attempts.some((a) => a.state === 'WRITE_AMBIGUITY' && a.ambiguityKind === null)
      )
        throw new PlatformRecoveryError();
      const resumed = await client.query(
        `update control.identity_envelope_rotation_step set state='STARTED'
        where operation_id=$1 and participant_id=$2 and privacy_domain_id=$3 and rotation_id=$4
          and recovery_id=$5 and principal_id=$6 and state='WRITE_AMBIGUITY'`,
        [
          operationId,
          actor.participantId,
          read.enrollment.privacyDomainId,
          lease.rotationId,
          lease.recoveryId,
          actor.principalId,
        ],
      );
      if (resumed.rowCount !== 1) throw new PlatformRecoveryError();
      state = 'STARTED';
    }
    return {
      operationId,
      rotationId: lease.rotationId,
      recoveryId: lease.recoveryId,
      fromRevision: step.fromRevision,
      fromState: step.fromState,
      toState: step.toState,
      state,
      replay: true,
      authority: read.receipt.authority,
      permissionEffect: 'NONE',
      attempts,
      ...(result === undefined ? {} : { result }),
    };
  }
  if (read.receipt.authority !== 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY')
    throw new PlatformRecoveryError();
  // Authenticate the creation's original signed readback before staging an
  // independent phase; this call is historical-only because creation must exist.
  const rotation = await client.query<{ state: string; revision: string; recoveryId: string }>(
    `select state,revision::text as revision,recovery_case_id::text as "recoveryId"
    from control.signing_key_rotation where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 for update`,
    [actor.participantId, read.enrollment.privacyDomainId, lease.rotationId],
  );
  const row = rotation.rows[0];
  if (
    rotation.rowCount !== 1 ||
    !row ||
    row.recoveryId !== lease.recoveryId ||
    ![
      'APPROVED',
      'PREPARED',
      'DISTRIBUTED',
      'VERIFIED',
      'CUTOVER_FENCED',
      'OBSERVING',
      'OLD_REVOKED',
      'OLD_RETIRED',
    ].includes(row.state) ||
    row.revision !==
      (
        {
          APPROVED: '2',
          PREPARED: '3',
          DISTRIBUTED: '4',
          VERIFIED: '5',
          CUTOVER_FENCED: '6',
          OBSERVING: '7',
          OLD_REVOKED: '8',
          OLD_RETIRED: '9',
        } as Record<string, string>
      )[row.state] ||
    row.revision !== command.expectedRevision
  )
    throw new PlatformRecoveryError();
  await authenticateIdentityEnvelopeRecoveryRotationCreation(
    client,
    { kind: 'CURRENT', actor },
    read.enrollment,
    lease,
    lease.creationOperationId,
    signer,
  );
  const source = ['CUTOVER_FENCED', 'OBSERVING', 'OLD_REVOKED', 'OLD_RETIRED'].includes(row.state)
    ? await captureIdentityEnvelopeRotationSuccessorSource(client, read.enrollment, lease)
    : await captureIdentityEnvelopeRotationSource(
        client,
        read.enrollment,
        read.enrollment.request,
        signer,
      );
  let consumer;
  if ('selectedTrust' in source && row.state === 'CUTOVER_FENCED') {
    const prior = await client.query<{ operationId: string }>(
      `select operation_id::text as "operationId" from control.identity_envelope_rotation_step where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 and recovery_id=$4 and from_revision=5 and to_state='CUTOVER_FENCED' and state='COMMITTED'`,
      [actor.participantId, read.enrollment.privacyDomainId, lease.rotationId, lease.recoveryId],
    );
    if (prior.rowCount !== 1 || !prior.rows[0]) throw new PlatformRecoveryError();
    const cutover = await publishIdentityEnvelopeRecoveryRotationPhase(
      client,
      actor,
      read.enrollment,
      lease,
      prior.rows[0].operationId,
      localQaEnabled,
      signer,
    );
    if (
      !cutover ||
      cutover.state !== 'CUTOVER_FENCED' ||
      cutover.signerId !== source.selectedTrust.signerId
    )
      throw new PlatformRecoveryError();
    consumer = await readIdentityEnvelopeRotationConsumer(
      client,
      {
        trust: source.selectedTrust,
        cutoverAtNs: source.cutoverAtNs,
        observedAtNs: source.recordedAtNs,
      },
      signer,
    );
    if (!consumer) throw new PlatformRecoveryError();
  }
  let consumerObservationOperationId: string | undefined;
  if (['OBSERVING', 'OLD_REVOKED', 'OLD_RETIRED'].includes(row.state)) {
    const prior = await client.query<{ operationId: string }>(
      `select operation_id::text as "operationId" from control.identity_envelope_rotation_step where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 and recovery_id=$4 and from_revision=6 and to_state='OBSERVING' and state='COMMITTED'`,
      [actor.participantId, read.enrollment.privacyDomainId, lease.rotationId, lease.recoveryId],
    );
    if (prior.rowCount !== 1 || !prior.rows[0]) throw new PlatformRecoveryError();
    const observed = await publishIdentityEnvelopeRecoveryRotationPhase(
      client,
      actor,
      read.enrollment,
      lease,
      prior.rows[0].operationId,
      localQaEnabled,
      signer,
    );
    if (
      !observed ||
      observed.state !== 'OBSERVING' ||
      observed.operationId !== prior.rows[0].operationId ||
      !('selectedTrust' in source) ||
      observed.signerId !== source.selectedTrust.signerId
    )
      throw new PlatformRecoveryError();
    consumerObservationOperationId = observed.operationId;
  }
  const prepared = [
    'PREPARED',
    'DISTRIBUTED',
    'CUTOVER_FENCED',
    'OBSERVING',
    'OLD_REVOKED',
    'OLD_RETIRED',
  ].includes(row.state)
    ? await (
        row.state !== 'PREPARED'
          ? readIdentityEnvelopeRecoveryDistributedDescriptor
          : readIdentityEnvelopeRecoveryPreparedDescriptor
      )(client, actor, read.enrollment, lease, localQaEnabled, signer)
    : undefined;
  const fromState = row.state as
    | 'APPROVED'
    | 'PREPARED'
    | 'DISTRIBUTED'
    | 'VERIFIED'
    | 'CUTOVER_FENCED'
    | 'OBSERVING'
    | 'OLD_REVOKED'
    | 'OLD_RETIRED';
  const toState = (
    {
      APPROVED: 'PREPARED',
      PREPARED: 'DISTRIBUTED',
      DISTRIBUTED: 'VERIFIED',
      VERIFIED: 'CUTOVER_FENCED',
      CUTOVER_FENCED: 'OBSERVING',
      OBSERVING: 'OLD_REVOKED',
      OLD_REVOKED: 'OLD_RETIRED',
      OLD_RETIRED: 'COMPLETE',
    } as const
  )[fromState];
  const plan = planIdentityEnvelopeRotationAttempts(
    {
      request: read.enrollment.request,
      rotationId: lease.rotationId,
      operationId,
      state: fromState,
      toState,
      ...(prepared ? { descriptor: prepared.descriptor } : {}),
      oldTrust: source.trust,
      preparedIssuer: lease.issuer,
      currentIssuer: source.issuer,
      admission: binding,
      callerWorkloadCredentialId: lease.issuer.workloadCredentialId,
      nowNs: source.recordedAtNs,
      authorityValidUntilNs: BigInt(Date.parse(lease.validUntil)) * 1000000n,
    },
    localOperationId,
  );
  const inserted = await client.query(
    `insert into control.identity_envelope_rotation_step(operation_id,participant_id,privacy_domain_id,
    rotation_id,recovery_id,principal_id,idempotency_key,from_revision,from_state,to_state,authority_binding,authority_digest,consumer_activation_operation_id,consumer_observation_operation_id)
    values($1,$2,$3,$4,$5,$6,$7,$8,$11,$12,$9,$10,$13,$14)`,
    [
      operationId,
      actor.participantId,
      read.enrollment.privacyDomainId,
      lease.rotationId,
      lease.recoveryId,
      actor.principalId,
      command.idempotencyKey,
      command.expectedRevision,
      binding,
      canonicalAuthorizationDigestBytes(binding),
      fromState,
      toState,
      consumer?.operationId ?? null,
      consumerObservationOperationId ?? null,
    ],
  );
  if (inserted.rowCount !== 1) throw new PlatformRecoveryError();
  for (const attempt of plan.attempts) {
    const stored = await client.query(
      `insert into control.identity_envelope_rotation_attempt(attempt_id,operation_id,participant_id,privacy_domain_id,
      rotation_id,slot,request,request_digest) values($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        attempt.request.attemptId,
        operationId,
        actor.participantId,
        read.enrollment.privacyDomainId,
        lease.rotationId,
        attempt.slot,
        attempt.request,
        Buffer.from(identityEnvelopeRotationRequestDigest(attempt.request).slice(7), 'hex'),
      ],
    );
    if (stored.rowCount !== 1) throw new PlatformRecoveryError();
  }
  let result;
  if (toState === 'CUTOVER_FENCED' || toState === 'COMPLETE') {
    if (plan.attempts.length !== 0) throw new PlatformRecoveryError();
    const started = await client.query(
      "update control.identity_envelope_rotation_step set state='STARTED',started_at=clock_timestamp() where operation_id=$1 and state='READY'",
      [operationId],
    );
    if (started.rowCount !== 1) throw new PlatformRecoveryError();
    result = await publishIdentityEnvelopeRecoveryRotationPhase(
      client,
      actor,
      read.enrollment,
      lease,
      operationId,
      localQaEnabled,
      signer,
    );
    if (!result || result.state !== toState) throw new PlatformRecoveryError();
  }
  return {
    operationId,
    rotationId: lease.rotationId,
    recoveryId: lease.recoveryId,
    fromRevision: command.expectedRevision,
    fromState,
    toState,
    state: result ? 'COMMITTED' : 'READY',
    replay: false,
    ...(result ? { result } : {}),
    authority: read.receipt.authority,
    permissionEffect: 'NONE',
    attempts: plan.attempts.map((a) => ({
      attemptId: a.request.attemptId,
      method: a.request.method,
      state: 'READY',
      ambiguityKind: null,
    })),
  };
}
