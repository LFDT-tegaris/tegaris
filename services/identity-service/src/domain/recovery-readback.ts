import type { PoolClient } from 'pg';

import { IdentityKernelError } from './identity-errors.js';
import { readIdentityEnvelopeRecoveryReview } from '../db/identity-envelope-recovery-post-review.js';

/** Exact scoped read; challenge bytes, credentials and other memberships are never projected. */
export async function readRecovery(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  recoveryId: string,
) {
  const signer = await readIdentityEnvelopeRecoveryReview(
    client,
    participantId,
    privacyDomainId,
    recoveryId,
  );
  if (signer) return signer;
  const result = await client.query<{
    recovery_challenge_id: string;
    principal_id: string;
    recovery_principal_id: string;
    custodian_one_principal_id: string;
    custodian_two_principal_id: string;
    custodian_one_approved_at: Date | null;
    custodian_two_approved_at: Date | null;
    purpose_digest: Buffer;
    current_epoch: string;
    outcome: string;
    row_version: string;
    issued_at: Date;
    expires_at: Date;
    consumed_at: Date | null;
    reviewed_at: Date | null;
    reviewed_by_principal_id: string | null;
    review_note: string | null;
    replacement_required: boolean;
    replacement_enrolled_at: Date | null;
    expired: boolean;
    operation_id: string | null;
  }>(
    `select recovery.recovery_challenge_id,recovery.principal_id,recovery.recovery_principal_id,
       recovery.custodian_one_principal_id,recovery.custodian_two_principal_id,
       recovery.custodian_one_approved_at,recovery.custodian_two_approved_at,
       recovery.purpose_digest,recovery.current_epoch::text,recovery.outcome,recovery.row_version::text,
       recovery.issued_at,recovery.expires_at,recovery.consumed_at,recovery.reviewed_at,recovery.reviewed_by_principal_id,recovery.review_note,
       recovery.replacement_required,recovery.replacement_enrolled_at,
       recovery.expires_at<=clock_timestamp() expired,candidate.consumed_operation_id::text operation_id
     from control.recovery_challenge recovery
     left join lateral (select consumed_operation_id from control.mutation_candidate
       where participant_id=recovery.participant_id and privacy_domain_id=recovery.privacy_domain_id
         and resource_id=recovery.recovery_challenge_id and state='CONSUMED'
         and catalog_operation_id in ('ID-OP-RECOVERY-BEGIN','ID-OP-RECOVERY-APPROVE','ID-OP-RECOVERY-COMPLETE','ID-OP-RECOVERY-POST-REVIEW')
         and expected_revision<recovery.row_version
       order by expected_revision desc,created_at desc limit 1) candidate on true
     where recovery.participant_id=$1 and recovery.privacy_domain_id=$2 and recovery.recovery_challenge_id=$3`,
    [participantId, privacyDomainId, recoveryId],
  );
  const row = result.rows[0];
  if (!row) throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    effect: {
      recoveryId: row.recovery_challenge_id,
      participantId,
      privacyDomainId,
      subjectId: row.principal_id,
      recoveryPrincipalId: row.recovery_principal_id,
      custodians: [
        {
          principalId: row.custodian_one_principal_id,
          approvedAt: row.custodian_one_approved_at?.toISOString() ?? null,
        },
        {
          principalId: row.custodian_two_principal_id,
          approvedAt: row.custodian_two_approved_at?.toISOString() ?? null,
        },
      ],
      purposeDigest: `sha256:${row.purpose_digest.toString('hex')}`,
      subjectEpoch: row.current_epoch,
      state: row.outcome,
      revision: row.row_version,
      issuedAt: row.issued_at.toISOString(),
      expiresAt: row.expires_at.toISOString(),
      completedAt: row.consumed_at?.toISOString() ?? null,
      leaseExpired: row.expired,
      replacementState: row.replacement_required
        ? row.replacement_enrolled_at
          ? 'ENROLLED'
          : 'AWAITING_ENROLLMENT'
        : 'NOT_REQUIRED',
      replacementEnrolledAt: row.replacement_enrolled_at?.toISOString() ?? null,
      postReviewRequired: true,
      postReviewStatus: row.reviewed_at === null ? 'REQUIRED' : 'REVIEWED',
      reviewedAt: row.reviewed_at?.toISOString() ?? null,
      reviewedByPrincipalId: row.reviewed_by_principal_id,
      reviewNote: row.review_note,
    },
    operationId: row.operation_id,
  };
}
