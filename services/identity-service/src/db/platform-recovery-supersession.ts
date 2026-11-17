import type { PoolClient } from 'pg';
import {
  platformRecoverySupersession,
  type PlatformRecoveryIntent,
} from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  PlatformRecoveryError,
  type PlatformRecoverySource,
} from '../domain/platform-recovery-policy.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeAssertionVerifier,
} from '../domain/identity-kernel.js';
import { readPlatformRecoveryReceipt } from './platform-recovery-readback.js';
import { readUneffectedPlatformRecoveryPredecessor } from './platform-recovery-continuation.js';

/** The caller retains the common Participant write and enrollment/Root fences.
 * Read the immutable original without requesting UPDATE on the replacement owner aggregate. */
export async function readExpiredRecoverySupersession(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  source: PlatformRecoverySource,
  verifier?: IdentityRuntimeAssertionVerifier,
  intent?: PlatformRecoveryIntent,
) {
  const retained = intent?.supersession;
  if (source.pendingReplacementId === null && !retained) return undefined;
  if (!verifier) throw new PlatformRecoveryError();
  const previous =
    source.enrollment.schemaVersion === 2 ? source.enrollment.uneffectedPredecessor : undefined;
  const authenticated =
    source.enrollment.schemaVersion === 2 && previous
      ? await readUneffectedPlatformRecoveryPredecessor(
          client,
          source.enrollment,
          verifier,
          source.rootExpiryPendingBridge,
        )
      : undefined;
  const originalEnrollmentId = previous?.enrollmentId ?? source.enrollment.enrollmentId;
  const selected = await client.query<{
    link: unknown;
    state: string;
    revision: string;
    supersededBy: string | null;
    candidate: unknown;
    consumed: boolean;
    hasEffects: boolean;
  }>(
    `select jsonb_build_object('recoveryId',c.recovery_id::text,'intentDigest','sha256:'||encode(c.intent_digest,'hex'),
      'replacementId',r.replacement_id::text,'preparationDigest','sha256:'||encode(r.candidate_digest,'hex'),
      'preparationOperationId',r.prepare_operation_id::text,'preparationApprovalId',r.prepare_approval_id::text,
      'expectedRevision','1','successorDigest','sha256:'||encode(r.successor_digest,'hex')) as link,
      r.state,r.row_version::text as revision,r.superseded_by::text as "supersededBy",r.candidate,
      exists(select 1 from control.mutation_candidate m join control.approval_request a
       on a.participant_id=m.participant_id and a.privacy_domain_id=m.privacy_domain_id
        and a.subject_id=m.mutation_candidate_id and a.subject_digest=m.candidate_digest
       where m.participant_id=r.participant_id and m.privacy_domain_id=r.privacy_domain_id
        and m.mutation_candidate_id=r.prepare_candidate_id and m.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE'
        and m.state='CONSUMED' and m.consumed_operation_id=r.prepare_operation_id
        and m.candidate_digest=r.candidate_digest and a.approval_request_id=r.prepare_approval_id and a.state='APPROVED') as consumed,
      exists(select 1 from jsonb_array_elements(r.candidate->'administrators') admin
        where exists(select 1 from control.authority_envelope e where e.participant_id=r.participant_id
          and e.authority_envelope_id::text=admin->>'envelopeId')
         or exists(select 1 from control.assignment a where a.participant_id=r.participant_id and a.assignment_id::text=admin->>'assignmentId')
         or exists(select 1 from control.identity_envelope_proposal p where p.participant_id=r.participant_id and p.envelope_id::text=admin->>'envelopeId')) as "hasEffects"
     from control.platform_scope_replacement r join control.platform_recovery_case c
      on c.participant_id=r.participant_id and c.privacy_domain_id=r.privacy_domain_id
       and c.intent->'preparation'=r.candidate and c.enrollment_id=$2
     where r.participant_id=$1 and r.privacy_domain_id=$3 and r.replacement_id=$4
      and r.platform_context_id=$5 and ((r.predecessor_epoch=$6 and r.expected_root_revision=$7
      and r.predecessor_digest=$8) or ($9::boolean and openpc.platform_scope_pending_root_bridge_current(r,$6,$7,$8)))
      and c.state='EXPIRED' and c.activation_operation_id is not null
      and c.valid_until<=clock_timestamp()`,
    [
      source.enrollment.participantId,
      originalEnrollmentId,
      source.enrollment.privacyDomainId,
      retained?.replacementId ?? source.pendingReplacementId,
      source.enrollment.platformContextId,
      source.enrollment.rootEpoch,
      source.enrollment.rootRevision,
      Buffer.from(source.enrollment.rootDigest.slice(7), 'hex'),
      authenticated !== undefined && source.rootExpiryPendingBridge !== undefined,
    ],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    !row.consumed ||
    row.hasEffects ||
    !(
      (row.state === 'WITHDRAWING' &&
        row.revision === '1' &&
        row.supersededBy === null &&
        source.pendingReplacementId === (retained?.replacementId ?? source.pendingReplacementId)) ||
      (row.state === 'SUPERSEDED' &&
        row.revision === '2' &&
        intent &&
        row.supersededBy === intent.preparation.replacementId &&
        source.pendingReplacementId === row.supersededBy)
    )
  )
    throw new PlatformRecoveryError();
  const link = platformRecoverySupersession.parse(row.link);
  if (
    authenticated &&
    (link.recoveryId !== previous!.recoveryId ||
      canonicalAuthorizationDigest(row.candidate) !==
        canonicalAuthorizationDigest(authenticated.uneffectedPreparation))
  )
    throw new PlatformRecoveryError();
  if (retained && canonicalAuthorizationDigest(retained) !== canonicalAuthorizationDigest(link))
    throw new PlatformRecoveryError();
  const read = await readPlatformRecoveryReceipt(
    client,
    actor,
    originalEnrollmentId,
    link.recoveryId,
    verifier,
  );
  if (
    read.receipt.state !== 'EXPIRED' ||
    read.receipt.authority !== 'NONE' ||
    !read.receipt.activation ||
    read.receipt.intentDigest !== link.intentDigest ||
    canonicalAuthorizationDigest(read.receipt.intent.preparation) !== link.preparationDigest ||
    canonicalAuthorizationDigest(row.candidate) !== link.preparationDigest ||
    read.receipt.intent.preparation.administrators.some((a) =>
      [a.usable, a.grantable].some(
        (scope) => BigInt(scope.validUntilNs) > BigInt(source.now.getTime()) * 1000000n,
      ),
    )
  )
    throw new PlatformRecoveryError();
  return link;
}
