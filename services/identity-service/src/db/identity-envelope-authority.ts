import type { PoolClient } from 'pg';
import type { EnvelopeAuthorityBinding } from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  AuthorityFenceError,
  captureDurableAuthorities,
  type BoundAuthority,
  type DurableAuthority,
} from './authority-fence.js';

/** Capture after the existing full session/role/grant fence, before any Platform
 * root lock or target-context switch. This is an immutable record of the exact
 * selected authority, never a replacement authorization path. Recheck the
 * durable grant for later business use without reviving an issuing session. */
export async function captureFencedEnvelopeAuthority(
  client: PoolClient,
  participantId: string,
  authority: BoundAuthority,
): Promise<{ binding: EnvelopeAuthorityBinding; durable: DurableAuthority }> {
  const durable = (await captureDurableAuthorities(client, participantId, [authority]))[0];
  if (!durable) throw new AuthorityFenceError();
  const selected = await client.query<{
    roleId: string;
    version: string;
    actions: string[];
    origin: string;
    createdByPrincipalId: string;
    creatorParticipantId: string;
    bootstrapMandateId: string | null;
    bootstrapPlatformParticipantId: string | null;
  }>(
    `select role.role_id as "roleId",role.row_version::text as version,
      role.action_intent_ids as actions,role.origin,
      role.created_by_principal_id::text as "createdByPrincipalId",
      role.creator_participant_id::text as "creatorParticipantId",
      role.bootstrap_mandate_id::text as "bootstrapMandateId",
      role.bootstrap_platform_participant_id::text as "bootstrapPlatformParticipantId"
    from control.assignment assignment join control.authority_role role
      on role.participant_id=assignment.participant_id and role.role_id=assignment.role_id
    where assignment.participant_id=$1 and assignment.assignment_id=$2
      and assignment.row_version=$3 and assignment.authority_envelope_id=$4
      and assignment.state='ACTIVE' and role.state='ACTIVE'`,
    [
      participantId,
      authority.assignmentId,
      authority.assignmentRowVersion,
      authority.authorityEnvelopeId,
    ],
  );
  const role = selected.rows[0];
  if (selected.rowCount !== 1 || !role) throw new AuthorityFenceError();
  const binding: Omit<EnvelopeAuthorityBinding, 'authorityDigest'> = {
    participantId,
    participantEpoch: authority.participantEpoch,
    principalId: authority.principalId,
    principalEpoch: authority.principalEpoch,
    sessionId: authority.sessionId,
    sessionEpoch: authority.sessionEpoch,
    assignmentId: authority.assignmentId,
    assignmentVersion: authority.assignmentRowVersion,
    authorityEnvelopeId: authority.authorityEnvelopeId,
    authorityEpoch: authority.authorityEpoch,
    delegationEpoch: authority.delegationEpoch,
    roleId: role.roleId,
    roleVersion: role.version,
    roleDigest: canonicalAuthorizationDigest({
      domain: 'pc.identity.envelope-role-binding.v1',
      participantId,
      role,
    }),
  };
  return {
    binding: {
      ...binding,
      authorityDigest: canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-authority-binding.v1',
        binding,
        authority: {
          ...durable.grant,
          sessionId: authority.sessionId,
          sessionEpoch: authority.sessionEpoch,
        },
        durable,
      }),
    },
    durable,
  };
}
