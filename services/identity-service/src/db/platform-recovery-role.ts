import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { PlatformRecoveryIntent } from '../contracts/platform-recovery.js';
import { platformRecoveryLeaseActions } from '../domain/platform-recovery-lease.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';

/** Reject an unusable handoff before starting its short-lived ceremony. Activation rechecks these mutable owners. */
export async function assertPlatformRecoveryRoles(
  client: PoolClient,
  participantId: string,
  preparation: PlatformRecoveryIntent['preparation'],
  rootActions: readonly string[],
) {
  const actions = platformRecoveryLeaseActions.filter((action) => rootActions.includes(action));
  for (const required of [
    'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
    'ACT-PARTICIPANT_CREATE_MEMBER-V1',
    'ACT-POLICY_APPROVE_REQUEST-V1',
    'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    'ACT-IDENTITY_UPDATE_STEP_UP-V1',
    'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
  ]) {
    if (!(actions as readonly string[]).includes(required)) throw new PlatformRecoveryError();
  }
  // The action catalogue is immutable; runtime identities only have SELECT access.
  const registered = await client.query<{ action_intent_id: string; risk_class: string }>(
    `select action_intent_id,risk_class from control.action_intent
      where action_intent_id=any($1::text[])`,
    [actions],
  );
  if (
    registered.rowCount !== actions.length ||
    new Set(registered.rows.map((row) => row.action_intent_id)).size !== actions.length ||
    registered.rows.some((row) => !(actions as readonly string[]).includes(row.action_intent_id))
  )
    throw new PlatformRecoveryError();
  for (const administrator of preparation.administrators) {
    // Activation checks the registered action risk against both grants. Catch
    // an incompatible declaration before recovery revokes the old sessions.
    if (
      [administrator.usable, administrator.grantable].some((scope) =>
        registered.rows.some(
          (row) => !scope.administration.riskClasses.some((risk) => risk === row.risk_class),
        ),
      )
    )
      throw new PlatformRecoveryError();
    const selected = await client.query<{
      role: { roleId: string; version: string; actions: string[] };
    }>(
      `select jsonb_build_object('roleId',r.role_id,'version',r.row_version::text,'actions',r.action_intent_ids,
        'origin',r.origin,'createdByPrincipalId',r.created_by_principal_id::text,'creatorParticipantId',r.creator_participant_id::text,
        'bootstrapMandateId',r.bootstrap_mandate_id::text,'bootstrapPlatformParticipantId',r.bootstrap_platform_participant_id::text) as role
       from control.authority_role r where r.participant_id=$1 and r.authority_role_id=$2 and r.state='ACTIVE' for share`,
      [participantId, administrator.roleId],
    );
    const role = selected.rows[0]?.role;
    if (
      selected.rowCount !== 1 ||
      !role ||
      role.version !== administrator.expectedRoleRevision ||
      canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-role-binding.v1',
        participantId,
        role,
      }) !== administrator.roleDigest ||
      actions.some((action) => !role.actions.includes(action))
    )
      throw new PlatformRecoveryError();
  }
}
