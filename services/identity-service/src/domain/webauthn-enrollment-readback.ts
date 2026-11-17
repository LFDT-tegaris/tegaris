import type { PoolClient } from 'pg';
import { IdentityKernelError } from './identity-errors.js';

/** Self-service ceremony readback. The current session must have the original
 * subject epoch; rotating context does not erase the durable enrollment result. */
export async function readWebAuthnEnrollment(
  client: PoolClient,
  participantId: string,
  principalId: string,
  principalEpoch: string,
  enrollmentId: string,
) {
  const result = await client.query<{
    enrollment_id: string;
    expires_at: Date;
    consumed_at: Date | null;
    expired: boolean;
    credential_id: string | null;
    credential_epoch: string | null;
    credential_active: boolean;
  }>(
    `select enrollment.enrollment_id,enrollment.expires_at,enrollment.consumed_at,
       enrollment.expires_at<=clock_timestamp() expired,
       credential.credential_id,credential.credential_epoch::text,
       coalesce(credential.state='ACTIVE' and credential.valid_from<=clock_timestamp()
         and (credential.valid_until is null or credential.valid_until>clock_timestamp()),false) credential_active
     from control.webauthn_enrollment enrollment
     join control.session original on original.participant_id=enrollment.participant_id
       and original.principal_id=enrollment.principal_id and original.session_id=enrollment.session_id
       and original.authority_epoch=$3::numeric
     left join control.credential credential on credential.participant_id=enrollment.participant_id
       and credential.principal_id=enrollment.principal_id and credential.credential_id=enrollment.credential_id
       and credential.kind='WEBAUTHN'
     where enrollment.participant_id=$1 and enrollment.principal_id=$2 and enrollment.enrollment_id=$4`,
    [participantId, principalId, principalEpoch, enrollmentId],
  );
  const row = result.rows[0];
  if (!row || result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    enrollmentId: row.enrollment_id,
    principalId,
    participantId,
    principalEpoch,
    state: row.consumed_at
      ? ('COMPLETED' as const)
      : row.expired
        ? ('EXPIRED' as const)
        : ('PENDING' as const),
    expiresAt: row.expires_at.toISOString(),
    completedAt: row.consumed_at?.toISOString() ?? null,
    credential:
      row.credential_id && row.credential_epoch
        ? {
            credentialId: row.credential_id,
            credentialEpoch: row.credential_epoch,
            active: row.credential_active,
          }
        : null,
  };
}
