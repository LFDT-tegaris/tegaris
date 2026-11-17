import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { IdentityKernelError } from '../domain/identity-errors.js';
import { authenticateHistoricalIdentityEnvelopeRecoveryCustody } from '../domain/identity-envelope-recovery-custody.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { identityEnvelopeRecoveryIntent } from '../contracts/identity-envelope-recovery.js';
import { identityEnvelopeRecoveryReviewView } from '../contracts/identity-envelope-recovery-review.js';

/** Ordinary scoped governance read, never an enrolled human's recovery lease.
 * The caller must authorize the actual recovery resource before entering. */
export async function readIdentityEnvelopeRecoveryReview(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  recoveryId: string,
) {
  const found = await client.query<{
    document: unknown;
    pin: unknown;
    signature: Buffer;
    documentDigest: Buffer;
    intent: unknown;
    intentDigest: Buffer;
    state: string;
    revision: string;
    activatedOperationId: string | null;
    reviewedAt: Date | null;
    reviewerId: string | null;
    reviewOperationId: string | null;
    noteDigest: Buffer | null;
    now: Date;
    collision: boolean;
  }>(
    `select e.document,t.document as pin,e.signature,e.document_digest as "documentDigest",c.intent,c.intent_digest as "intentDigest",
    c.state,c.row_version::text as revision,c.activation_operation_id::text as "activatedOperationId",c.reviewed_at as "reviewedAt",c.reviewed_by_principal_id::text as "reviewerId",c.review_operation_id::text as "reviewOperationId",c.review_note_digest as "noteDigest",clock_timestamp() as now,
    exists(select 1 from control.recovery_challenge old where old.participant_id=c.participant_id and old.privacy_domain_id=c.privacy_domain_id and old.recovery_challenge_id=c.recovery_id) as collision
    from control.platform_recovery_case c join control.identity_envelope_recovery_enrollment e on e.enrollment_id=c.signer_repair_enrollment_id and e.participant_id=c.participant_id and e.privacy_domain_id=c.privacy_domain_id and e.document_digest=c.enrollment_digest
    join control.identity_envelope_recovery_custody_trust t on t.custody_trust_id=e.custody_trust_id and t.participant_id=e.participant_id and t.privacy_domain_id=e.privacy_domain_id and t.document_digest=e.custody_trust_digest
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.recovery_id=$3 and openpc.matches_privacy(c.privacy_domain_id)`,
    [participantId, privacyDomainId, recoveryId],
  );
  if (found.rowCount === 0) return undefined;
  const row = found.rows[0];
  if (found.rowCount !== 1 || !row || row.collision)
    throw new IdentityKernelError('PC-IDENTITY-1008');
  const enrollment = authenticateHistoricalIdentityEnvelopeRecoveryCustody(row.pin, {
    document: row.document,
    signature: row.signature.toString('base64url'),
  });
  const intent = identityEnvelopeRecoveryIntent.parse(row.intent);
  if (
    enrollment.participantId !== participantId ||
    enrollment.privacyDomainId !== privacyDomainId ||
    intent.recoveryId !== recoveryId ||
    intent.enrollmentId !== enrollment.enrollmentId ||
    intent.enrollmentDigest !== canonicalAuthorizationDigest(enrollment) ||
    canonicalAuthorizationDigest(enrollment) !== `sha256:${row.documentDigest.toString('hex')}` ||
    canonicalAuthorizationDigest(intent) !== `sha256:${row.intentDigest.toString('hex')}` ||
    (row.reviewedAt !== null) !== (row.reviewOperationId !== null) ||
    !Number.isFinite(new Date(row.now).getTime())
  )
    throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    effect: identityEnvelopeRecoveryReviewView.parse({
      purpose: intent.purpose,
      recoveryId,
      participantId,
      privacyDomainId,
      enrollmentId: enrollment.enrollmentId,
      issuerPrincipalId: enrollment.issuerPrincipalId,
      executorPrincipalId: enrollment.recoveryPrincipal.principalId,
      custodianPrincipalIds: enrollment.custodians.map((c) => c.principalId),
      rotationId: intent.rotationId,
      creationOperationId: intent.creationOperationId,
      activationOperationId: row.activatedOperationId,
      intentDigest: canonicalAuthorizationDigest(intent),
      state: row.state,
      revision: row.revision,
      issuedAt: intent.validFrom,
      expiresAt: intent.validUntil,
      leaseExpired: new Date(row.now).getTime() >= Date.parse(intent.validUntil),
      authority: 'NONE',
      postReviewRequired: true,
      postReviewStatus: row.reviewedAt ? 'REVIEWED' : 'REQUIRED',
      reviewedAt: row.reviewedAt?.toISOString() ?? null,
      reviewedByPrincipalId: row.reviewerId,
      reviewNoteDigest: row.noteDigest ? `sha256:${row.noteDigest.toString('hex')}` : null,
    }),
    operationId: row.reviewOperationId,
  };
}

/** Exact POST_REVIEW aggregate only. Keep its original row lock and fail on
 * cross-owner identity collision; other account recovery operations stay separate. */
export async function lockIdentityEnvelopeRecoveryReviewVersion(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  recoveryId: string,
) {
  const found = await client.query<{ revision: string; collision: boolean }>(
    `select c.row_version::text as revision,
    exists(select 1 from control.recovery_challenge old where old.participant_id=c.participant_id and old.privacy_domain_id=c.privacy_domain_id and old.recovery_challenge_id=c.recovery_id) as collision
    from control.platform_recovery_case c where c.participant_id=$1 and c.privacy_domain_id=$2 and c.recovery_id=$3 and c.signer_repair_enrollment_id is not null and openpc.matches_privacy(c.privacy_domain_id) for update of c`,
    [participantId, privacyDomainId, recoveryId],
  );
  if (found.rowCount === 0) return undefined;
  if (found.rowCount !== 1 || found.rows[0]?.collision)
    throw new IdentityKernelError('PC-IDENTITY-1008');
  return found.rows[0]!.revision;
}

/** Called inside the existing maker/checker/step-up mutation owner. Review is a
 * new independently governed effect, never inferred from activation or ACK. */
export async function postReviewIdentityEnvelopeRecovery(
  client: PoolClient,
  input: {
    participantId: string;
    privacyDomainId: string;
    recoveryId: string;
    principalId: string;
    checkerPrincipalId: string;
    operationId: string;
    note: string;
  },
) {
  const found = await client.query<{ enrollment: unknown }>(
    `select e.document as enrollment
    from control.platform_recovery_case c join control.identity_envelope_recovery_enrollment e
     on e.participant_id=c.participant_id and e.enrollment_id=c.signer_repair_enrollment_id
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.recovery_id=$3 for update of c`,
    [input.participantId, input.privacyDomainId, input.recoveryId],
  );
  if (found.rowCount === 0) return undefined;
  if (found.rowCount !== 1 || input.principalId === input.checkerPrincipalId)
    throw new IdentityKernelError('PC-IDENTITY-1007');
  const updated = await client.query<{ reviewedAt: Date }>(
    `update control.platform_recovery_case c set reviewed_at=clock_timestamp(),
    reviewed_by_principal_id=$4,review_operation_id=$5,review_note_digest=$6,row_version=row_version+1,updated_at=clock_timestamp()
    from control.identity_envelope_recovery_enrollment e where c.participant_id=$1 and c.privacy_domain_id=$2 and c.recovery_id=$3
     and e.enrollment_id=c.signer_repair_enrollment_id and e.participant_id=c.participant_id and c.activated_at is not null
     and c.state in ('COMPLETED','REVOKED','EXPIRED') and c.reviewed_at is null
     and $4::text not in (e.document->>'issuerPrincipalId',e.document#>>'{recoveryPrincipal,principalId}')
     and $7::text not in (e.document->>'issuerPrincipalId',e.document#>>'{recoveryPrincipal,principalId}') returning c.reviewed_at as "reviewedAt"`,
    [
      input.participantId,
      input.privacyDomainId,
      input.recoveryId,
      input.principalId,
      input.operationId,
      createHash('sha256').update(input.note).digest(),
      input.checkerPrincipalId,
    ],
  );
  if (updated.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1007');
  return {
    recoveryId: input.recoveryId,
    postReviewStatus: 'REVIEWED' as const,
    reviewedAt: updated.rows[0]!.reviewedAt.toISOString(),
  };
}
