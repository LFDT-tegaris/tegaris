import type { PoolClient } from 'pg';
import { lockAuthorityFence } from '../db/authority-fence.js';
import { IdentityKernelError } from './identity-errors.js';

/** A recovered account must prove a new IdP authentication, not just obtain a new token. */
export async function assertRecoveryOidcFreshness(
  client: PoolClient,
  participantId: string,
  principalId: string,
  authenticatedAt: Date | undefined,
  now: Date,
) {
  const result = await client.query<{ consumed_at: Date }>(
    `select consumed_at from control.recovery_challenge where participant_id=$1 and principal_id=$2 and outcome='COMPLETED' and consumed_at is not null order by consumed_at desc limit 1`,
    [participantId, principalId],
  );
  const recovery = result.rows[0];
  if (!recovery) return;
  // OIDC auth_time has whole-second precision. Round the recovery boundary up so
  // an authentication from just before the recovery cannot become fresh by rounding.
  if (
    !authenticatedAt ||
    !Number.isFinite(authenticatedAt.getTime()) ||
    authenticatedAt.getTime() < Math.ceil(recovery.consumed_at.getTime() / 1000) * 1000 ||
    authenticatedAt > now
  )
    throw new IdentityKernelError('PC-AUTH-0002');
}

/** Serialize initial and recovery enrollment against subject invalidation and each other. */
export async function fenceInitialEnrollment(
  client: PoolClient,
  participantId: string,
  principalId: string,
  sessionId: string,
  principalEpoch: string,
  governedPrivacyDomainId?: string,
) {
  const credentials = await client.query<{ credential_id: string }>(
    `select credential_id from control.credential where participant_id=$1 and principal_id=$2`,
    [participantId, principalId],
  );
  const recoveryScopes = await client.query<{ privacy_domain_id: string }>(
    `select privacy_domain_id from control.recovery_challenge where participant_id=$1 and principal_id=$2 and current_epoch=$3::numeric-1 and outcome='COMPLETED' and replacement_required and replacement_credential_id is null and privacy_domain_id is not null`,
    [participantId, principalId, principalEpoch],
  );
  await lockAuthorityFence(client, participantId, {
    privacy_domain: [
      ...new Set([
        ...recoveryScopes.rows.map((row) => row.privacy_domain_id),
        ...(governedPrivacyDomainId ? [governedPrivacyDomainId] : []),
      ]),
    ].map((id) => ({ id })),
    participant: [{ id: participantId }],
    principal: [{ id: principalId, write: true }],
    session: [{ id: sessionId, write: true }],
    credential: credentials.rows.map((row) => ({ id: row.credential_id })),
  });
}

/** No live authenticator may be replaced by this path. Only a completed recovery
 * at this exact subject epoch can admit one new authenticator after historical ones. */
export async function initialEnrollmentRecovery(
  client: PoolClient,
  participantId: string,
  principalId: string,
  principalEpoch: string,
): Promise<{ recoveryId: string; privacyDomainId: string } | undefined> {
  const credentials = await client.query<{ state: string }>(
    `select state from control.credential where participant_id=$1 and principal_id=$2 and kind='WEBAUTHN'`,
    [participantId, principalId],
  );
  if (credentials.rows.some((row) => row.state !== 'REVOKED'))
    throw new IdentityKernelError('PC-AUTH-0006');
  const recovery = await client.query<{ recovery_challenge_id: string; privacy_domain_id: string }>(
    `select recovery_challenge_id,privacy_domain_id from control.recovery_challenge where participant_id=$1 and principal_id=$2 and current_epoch=$3::numeric-1
    and outcome='COMPLETED' and consumed_at is not null and privacy_domain_id is not null and replacement_required=true and replacement_credential_id is null`,
    [participantId, principalId, principalEpoch],
  );
  if (recovery.rowCount !== 1 && credentials.rowCount !== 0)
    throw new IdentityKernelError('PC-AUTH-0006');
  if ((recovery.rowCount ?? 0) > 1) throw new IdentityKernelError('PC-AUTH-0006');
  const row = recovery.rows[0];
  return row
    ? { recoveryId: row.recovery_challenge_id, privacyDomainId: row.privacy_domain_id }
    : undefined;
}

export async function completeRecoveryEnrollment(
  client: PoolClient,
  participantId: string,
  principalId: string,
  recoveryId: string,
  privacyDomainId: string,
  credentialId: string,
  principalEpoch: string,
) {
  const result = await client.query(
    `update control.recovery_challenge set replacement_credential_id=$4,replacement_enrolled_at=clock_timestamp(),row_version=row_version+1
    where participant_id=$1 and principal_id=$2 and recovery_challenge_id=$3 and current_epoch=$5::numeric-1 and outcome='COMPLETED'
      and replacement_required=true and replacement_credential_id is null and privacy_domain_id=$6`,
    [participantId, principalId, recoveryId, credentialId, principalEpoch, privacyDomainId],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-AUTH-0006');
}
