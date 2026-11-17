import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigest } from '../../../identity-service/src/contracts/authorization.js';
import { ParticipantKernelError } from './participant-errors.js';

export interface RoleBindingPreview {
  participantId: string;
  roleId: string;
  roleRef: string;
  revision: string;
  roleDigest: string;
  actionIntentIds: string[];
}

/** Read-only signing input. The caller holds the same exact role read fence as
 * ordinary role readback. A preview never grants or reserves administration. */
export async function readRoleBindingPreview(
  client: PoolClient,
  participantId: string,
  roleId: string,
): Promise<RoleBindingPreview> {
  const selected = await client.query<{
    role: {
      roleId: string;
      version: string;
      actions: string[];
      origin: string;
      createdByPrincipalId: string;
      creatorParticipantId: string;
      bootstrapMandateId: string | null;
      bootstrapPlatformParticipantId: string | null;
    };
  }>(
    `select jsonb_build_object('roleId',role.role_id,'version',role.row_version::text,
      'actions',role.action_intent_ids,'origin',role.origin,
      'createdByPrincipalId',role.created_by_principal_id::text,
      'creatorParticipantId',role.creator_participant_id::text,
      'bootstrapMandateId',role.bootstrap_mandate_id::text,
      'bootstrapPlatformParticipantId',role.bootstrap_platform_participant_id::text) as role
     from control.authority_role role where role.participant_id=$1
       and role.authority_role_id=$2 and role.state='ACTIVE' for share of role`,
    [participantId, roleId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw new ParticipantKernelError('PC-IDENTITY-1008');
  return {
    participantId,
    roleId,
    roleRef: row.role.roleId,
    revision: row.role.version,
    roleDigest: canonicalAuthorizationDigest({
      domain: 'pc.identity.envelope-role-binding.v1',
      participantId,
      role: row.role,
    }),
    actionIntentIds: row.role.actions,
  };
}
