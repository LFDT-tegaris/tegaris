import type { PoolClient } from 'pg';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';

/** The stored source chooses the owner; caller fields never choose a purpose.
 * An identifier collision or foreign context is a denial, never a fallback. */
export async function readRecoveryEnrollmentPurpose(
  client: PoolClient,
  participantId: string,
  enrollmentId: string,
) {
  const result = await client.query<{ schema: string }>(
    `select document->>'schema' as schema from control.platform_recovery_enrollment
    where participant_id=$1 and enrollment_id=$2 and openpc.matches_privacy(privacy_domain_id)
    union all select document->>'schema' as schema from control.identity_envelope_recovery_enrollment
    where participant_id=$1 and enrollment_id=$2 and openpc.matches_privacy(privacy_domain_id)
    union all select document->>'schema' as schema from control.root_expiry_recovery_enrollment
    where participant_id=$1 and enrollment_id=$2 and openpc.matches_privacy(privacy_domain_id)`,
    [participantId, enrollmentId],
  );
  const value = result.rows[0]?.schema;
  if (
    result.rowCount !== 1 ||
    (value !== 'pc.identity.local-root-expiry-recovery-enrollment' &&
      value !== 'pc.identity.platform-recovery-enrollment' &&
      value !== 'pc.identity.discovery-certificate-recovery-enrollment' &&
      value !== 'pc.identity.identity-envelope-recovery-enrollment')
  )
    throw new PlatformRecoveryError();
  return value;
}
