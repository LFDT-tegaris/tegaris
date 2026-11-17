import {
  defaultRecoveryLifetimes,
  recoveryLifetimeSettings,
  type RecoveryLifetimeSettings,
} from '../domain/platform-recovery-lifetimes.js';
import type { PoolClient } from 'pg';
import {
  platformAdministrationRecoveryEnrollment,
  platformRecoveryIntent,
  type PlatformRecoveryIntent,
} from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  assertPlatformRecoveryIntent,
  assertPlatformRecoverySource,
  PlatformRecoveryError,
} from '../domain/platform-recovery-policy.js';
import { localOperationId } from '../domain/local-operation-id.js';
import {
  readExpiredPlatformAdministration,
  assertPlatformRecoverySigners,
  readRootExpiryPlatformAdministration,
} from './platform-recovery-enrollment.js';
import {
  readPlatformRecoverySession,
  type PlatformRecoveryCeremonyContext,
} from './platform-recovery-proof.js';
import {
  readPendingPlatformRecoveryContinuation,
  readPendingPlatformRecoveryExpiry,
  readPendingPlatformRecoveryExpirySuccessor,
  readUneffectedPlatformRecoveryPredecessor,
} from './platform-recovery-continuation.js';
import { readPlatformRecoveryApprovalContinuation } from './platform-recovery-approval-continuation.js';
import { readExpiredRecoverySupersession } from './platform-recovery-supersession.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeAssertionVerifier,
} from '../domain/identity-kernel.js';
import type { PlatformRecoveryProof } from '../domain/platform-recovery-ceremony.js';
import { assertPlatformRecoveryRoles } from './platform-recovery-role.js';

const deny = () => new PlatformRecoveryError();
const bytes = (value: string) => Buffer.from(value.slice(7), 'hex');

/** The installation-owner document remains the only initial recovery trust source. */
export async function readPlatformRecoverySource(
  client: PoolClient,
  enrollmentId: string,
  localQaEnabled: boolean,
  verifier?: IdentityRuntimeAssertionVerifier,
) {
  const selected = await client.query<{
    document: unknown;
    document_digest: Buffer;
    row_version: string;
    state: string;
  }>(
    `select document,document_digest,row_version::text,state from openpc.lock_platform_recovery_enrollment($1)`,
    [enrollmentId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw deny();
  const enrollment = platformAdministrationRecoveryEnrollment.parse(row.document);
  if (
    enrollment.enrollmentId !== enrollmentId ||
    canonicalAuthorizationDigest(enrollment) !== `sha256:${row.document_digest.toString('hex')}`
  )
    throw deny();
  if (enrollment.schemaVersion !== 1 && !localQaEnabled) throw deny();
  const recovered =
    enrollment.schemaVersion !== 1
      ? await readRootExpiryPlatformAdministration(client, enrollment, verifier)
      : undefined;
  const current = recovered ?? (await readExpiredPlatformAdministration(client, enrollment));
  const continuation =
    enrollment.schemaVersion === 3
      ? await readPendingPlatformRecoveryContinuation(client, enrollment, verifier)
      : undefined;
  const expiry =
    enrollment.schemaVersion === 4
      ? await readPendingPlatformRecoveryExpiry(client, enrollment, verifier)
      : undefined;
  const approval =
    enrollment.schemaVersion === 4
      ? await readPlatformRecoveryApprovalContinuation(client, enrollment, verifier)
      : undefined;
  const uneffected =
    enrollment.schemaVersion === 2 && enrollment.uneffectedPredecessor
      ? await readUneffectedPlatformRecoveryPredecessor(
          client,
          enrollment,
          verifier,
          recovered?.rootExpiryPendingBridge,
        )
      : undefined;
  const source = {
    ...current,
    ...continuation,
    ...expiry,
    ...approval,
    ...uneffected,
    ...(uneffected ? { preparation: uneffected.uneffectedPreparation } : {}),
    enrollment,
    enrollmentRevision: row.row_version,
    enrollmentState: row.state,
    expiredReplacementId: enrollment.schemaVersion !== 1 ? null : enrollment.expiredReplacementId,
    plannedRecordIds:
      approval?.plannedRecordIds ?? continuation?.plannedRecordIds ?? ([] as string[]),
    localQaEnabled,
  };
  assertPlatformRecoverySource(source);
  await assertPlatformRecoverySigners(client, enrollment, localQaEnabled);
  await assertPlatformRecoveryRoles(
    client,
    enrollment.participantId,
    current.preparation,
    current.preparation.successorScope.administration.actionIntentIds,
  );
  return source;
}

/** Persist a proposal only. New record names are generated here and never turn caller resource names into authority. */
export async function createPlatformRecoveryCase(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  input: PlatformRecoveryIntent['preparation'],
  localQaEnabled: boolean,
  configuredLifetimes: RecoveryLifetimeSettings = defaultRecoveryLifetimes,
  verifier?: IdentityRuntimeAssertionVerifier,
) {
  const source = await readPlatformRecoverySource(client, enrollmentId, localQaEnabled, verifier);
  const lifetimes = recoveryLifetimeSettings.parse(configuredLifetimes);
  const supersession =
    source.recoveryContinuation || source.pendingExpiry
      ? undefined
      : await readExpiredRecoverySupersession(client, actor, source, verifier);
  if (
    lifetimes.profile !== 'C17' &&
    (!localQaEnabled || source.enrollment.assurance !== 'LOCAL_QA_VIRTUAL_AUTHENTICATOR')
  )
    throw deny();
  if (
    actor.principalId !== source.enrollment.recoveryPrincipal.principalId ||
    (source.pendingReplacementId !== null &&
      !supersession &&
      !source.recoveryContinuation &&
      !source.pendingExpiry)
  )
    throw deny();
  await readPlatformRecoverySession(client, actor, source.enrollment);
  // An expired proposal can close but cannot be modified, resurrected or silently replayed as a new case.
  const existing = await client.query(
    `select 1 from control.platform_recovery_case where enrollment_id=$1 and state in ('DRAFT','REQUESTED','ACTIVE')`,
    [enrollmentId],
  );
  if (existing.rowCount !== 0) throw deny();
  const preparation = structuredClone(input);
  const suppliedNames = [
    preparation.replacementId,
    ...preparation.administrators.flatMap((v) => [v.envelopeId, v.assignmentId]),
  ];
  if (
    suppliedNames.length !== 5 ||
    new Set(suppliedNames).size !== 5 ||
    suppliedNames.some((v) => source.root.grantable.administration.resourceIds.includes(v))
  )
    throw deny();
  if (
    (source.recoveryContinuation || source.approvalContinuation) &&
    canonicalAuthorizationDigest(input) !== canonicalAuthorizationDigest(source.preparation)
  )
    throw deny();
  const preservePreparation = Boolean(source.recoveryContinuation || source.approvalContinuation);
  const plannedRecordIds = preservePreparation
    ? [...source.plannedRecordIds]
    : Array.from({ length: 5 }, () => localOperationId());
  const substitute = (value: string) => {
    const index = suppliedNames.indexOf(value);
    return index < 0 ? value : plannedRecordIds[index]!;
  };
  if (!preservePreparation) {
    preparation.replacementId = plannedRecordIds[0]!;
    preparation.successorScope.administration.resourceIds =
      preparation.successorScope.administration.resourceIds
        .map(substitute)
        .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    for (const [index, administrator] of preparation.administrators.entries()) {
      administrator.envelopeId = plannedRecordIds[index * 2 + 1]!;
      administrator.assignmentId = plannedRecordIds[index * 2 + 2]!;
      administrator.usable.administration.resourceIds =
        administrator.usable.administration.resourceIds
          .map(substitute)
          .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
      administrator.grantable.administration.resourceIds =
        administrator.grantable.administration.resourceIds
          .map(substitute)
          .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    }
  }
  if (
    source.recoveryContinuation &&
    canonicalAuthorizationDigest(preparation) !== source.recoveryContinuation.preparationDigest
  )
    throw deny();
  const collision = source.recoveryContinuation
    ? { rowCount: 0 }
    : await client.query(
        `select 1 from control.authority_envelope where authority_envelope_id=any($1::uuid[])
    union all select 1 from control.assignment where assignment_id=any($1::uuid[])
    union all select 1 from control.platform_scope_replacement where replacement_id=any($1::uuid[])`,
        [plannedRecordIds],
      );
  if (collision.rowCount !== 0) throw deny();
  const intent = platformRecoveryIntent.parse({
    schema: 'pc.identity.platform-recovery-intent',
    schemaVersion: 1,
    recoveryId: localOperationId(),
    enrollmentId,
    enrollmentRevision: source.enrollmentRevision,
    enrollmentDigest: canonicalAuthorizationDigest(source.enrollment),
    validFrom: source.now.toISOString(),
    validUntil: new Date(
      Math.min(
        source.now.getTime() + lifetimes.leaseMs,
        Date.parse(source.enrollment.validUntil),
        Number(BigInt(source.root.grantable.validUntilNs) / 1000000n),
        // SOURCE and CREATE read different clocks. A new case must fit the
        // already prepared scopes, even when both configured lifetimes match.
        Number(BigInt(preparation.successorScope.validUntilNs) / 1000000n),
        ...preparation.administrators.flatMap((a) => [
          Number(BigInt(a.usable.validUntilNs) / 1000000n),
          Number(BigInt(a.grantable.validUntilNs) / 1000000n),
        ]),
      ),
    ).toISOString(),
    administratorEpochs: source.administratorEpochs,
    lifetimes,
    ...(supersession ? { supersession } : {}),
    ...(source.recoveryContinuation ? { continuation: source.recoveryContinuation } : {}),
    ...(source.enrollment.schemaVersion === 3 && source.enrollment.source.activatedHandoff
      ? {
          completionSourceDigest: canonicalAuthorizationDigest(
            source.enrollment.source.activatedHandoff,
          ),
        }
      : {}),
    ...(source.pendingExpiry ? { pendingExpiry: source.pendingExpiry } : {}),
    ...(source.approvalContinuation ? { approvalContinuation: source.approvalContinuation } : {}),
    ...(source.enrollment.schemaVersion === 4 && source.enrollment.source.closedApproval
      ? {
          closedApprovalSourceDigest: canonicalAuthorizationDigest(
            source.enrollment.source.closedApproval,
          ),
        }
      : {}),
    preparation,
  });
  assertPlatformRecoveryIntent(intent, {
    ...source,
    plannedRecordIds,
    recoverySupersession: supersession,
  });
  await assertPlatformRecoveryRoles(
    client,
    source.enrollment.participantId,
    intent.preparation,
    intent.preparation.successorScope.administration.actionIntentIds,
  );
  const intentDigest = canonicalAuthorizationDigest(intent);
  await client.query(
    `insert into control.platform_recovery_case(recovery_id,participant_id,privacy_domain_id,enrollment_id,
    enrollment_revision,enrollment_digest,intent,intent_digest,planned_record_ids,valid_from,valid_until)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      intent.recoveryId,
      source.enrollment.participantId,
      source.enrollment.privacyDomainId,
      enrollmentId,
      intent.enrollmentRevision,
      bytes(intent.enrollmentDigest),
      intent,
      bytes(intentDigest),
      JSON.stringify(plannedRecordIds),
      intent.validFrom,
      intent.validUntil,
    ],
  );
  return {
    intent,
    intentDigest,
    state: 'DRAFT' as const,
    authority: 'NONE' as const,
    assurance: source.enrollment.assurance,
  };
}

/** Each command revalidates current source, all fixed credentials and the immutable intent before case effects. */
export async function readPlatformRecoveryCeremony(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
  localQaEnabled: boolean,
  verifier?: IdentityRuntimeAssertionVerifier,
): Promise<PlatformRecoveryCeremonyContext> {
  const source = await readPlatformRecoverySource(client, enrollmentId, localQaEnabled, verifier);
  const enrollment = source.enrollment;
  if (
    ![
      enrollment.recoveryPrincipal.principalId,
      ...enrollment.custodians.map((v) => v.principalId),
      ...enrollment.administratorPrincipalIds,
    ].includes(actor.principalId)
  )
    throw deny();
  await readPlatformRecoverySession(client, actor, enrollment);
  const selected = await client.query<{
    intent: unknown;
    intent_digest: Buffer;
    planned_record_ids: string[];
    state: string;
  }>(
    `select intent,intent_digest,planned_record_ids,state from control.platform_recovery_case
    where participant_id=$1 and privacy_domain_id=$2 and enrollment_id=$3 and recovery_id=$4 for update`,
    [enrollment.participantId, enrollment.privacyDomainId, enrollmentId, recoveryId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw deny();
  const intent = platformRecoveryIntent.parse(row.intent);
  if (
    intent.recoveryId !== recoveryId ||
    canonicalAuthorizationDigest(intent) !== `sha256:${row.intent_digest.toString('hex')}`
  )
    throw deny();
  const supersession = intent.supersession
    ? await readExpiredRecoverySupersession(client, actor, source, verifier, intent)
    : undefined;
  const expiryPendingSuccessor =
    enrollment.schemaVersion === 4 &&
    source.pendingReplacementId !== enrollment.source.pendingExpiry.preparation.replacementId
      ? await readPendingPlatformRecoveryExpirySuccessor(
          client,
          enrollment,
          intent,
          row.planned_record_ids,
          source.pendingReplacementId,
        )
      : undefined;
  assertPlatformRecoveryIntent(intent, {
    ...source,
    plannedRecordIds: row.planned_record_ids,
    recoverySupersession: supersession,
    expiryPendingSuccessor,
  });
  await assertPlatformRecoveryRoles(
    client,
    enrollment.participantId,
    intent.preparation,
    intent.preparation.successorScope.administration.actionIntentIds,
  );
  const proofs = await readRecoveryCeremonyProofs(client, enrollment, recoveryId);
  return { enrollment, intent, state: row.state, proofs, now: source.now };
}

/** Session currentness is shared by both independent custody purposes. */
export async function readRecoveryCeremonyProofs(
  client: PoolClient,
  enrollment: { participantId: string; privacyDomainId: string },
  recoveryId: string,
): Promise<readonly PlatformRecoveryProof[]> {
  const proofs = await client.query<PlatformRecoveryProof & { liveSession: boolean }>(
    `select proof.proof_id::text as "proofId",proof.principal_id::text as "principalId",proof.principal_epoch::text as "principalEpoch",
      proof.credential_id::text as "credentialId",proof.credential_epoch::text as "credentialEpoch",proof.session_id::text as "sessionId",
      proof.session_epoch::text as "sessionEpoch",proof.phase,'sha256:'||encode(proof.intent_digest,'hex') as "intentDigest",proof.verified_at as "verifiedAt",
      challenge.verified_proof_max_age_ms::integer as "verifiedProofMaxAgeMs",
      exists(select 1 from control.session s where s.participant_id=proof.participant_id and s.principal_id=proof.principal_id
       and s.session_id=proof.session_id and s.session_epoch=proof.session_epoch and s.authority_epoch=proof.principal_epoch
       and s.context_mode='PLATFORM' and s.privacy_domain_id is null and s.state='ACTIVE'
       and s.idle_expires_at>clock_timestamp() and s.absolute_expires_at>clock_timestamp()
       and (challenge.verified_proof_max_age_ms=300000 or
         (challenge.verified_proof_max_age_ms=3000000 and challenge.duration_profile='LOCAL_QA_10X'
           and s.duration_profile='LOCAL_QA_10X' and challenge.expires_at>clock_timestamp()))) as "liveSession"
     from control.platform_recovery_proof proof join control.platform_recovery_challenge challenge
       on challenge.participant_id=proof.participant_id and challenge.privacy_domain_id=proof.privacy_domain_id
        and challenge.recovery_id=proof.recovery_id and challenge.challenge_id=proof.challenge_id and challenge.proof_id=proof.proof_id
     where proof.participant_id=$1 and proof.privacy_domain_id=$2 and proof.recovery_id=$3 order by proof.verified_at,proof.proof_id`,
    [enrollment.participantId, enrollment.privacyDomainId, recoveryId],
  );
  if (
    proofs.rows.some(
      (proof) =>
        !proof.liveSession || ![300000, 3000000].includes(proof.verifiedProofMaxAgeMs ?? 0),
    )
  )
    throw deny();
  return proofs.rows;
}
