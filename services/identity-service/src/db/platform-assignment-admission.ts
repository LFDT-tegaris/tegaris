import type { PoolClient } from 'pg';
import { isDeepStrictEqual } from 'node:util';
import type { Assignment } from '../../../participant-service/src/domain/authority-kernel.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { AuthorityFenceError } from './authority-fence.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';
import { pendingPlatformAdministrator } from './pending-platform-administrator.js';

/** Exact, runtime-free handoff only. The ordinary governed assignment owner
 * still validates the actor, envelope, role, principal and overlap. A future
 * grant cannot be selected by any current-authority resolver. */
export async function platformAssignmentAdmission(client: PoolClient, incoming: Assignment) {
  const selected = await client.query<{
    platform_context_id: string | null;
    platform_authority_epoch: string | null;
  }>(
    `select platform_context_id,platform_authority_epoch::text
     from control.authority_envelope where participant_id=$1 and authority_envelope_id=$2`,
    [incoming.participantId, incoming.authorityEnvelopeId],
  );
  if (selected.rowCount !== 1) throw new AuthorityFenceError();
  const envelope = selected.rows[0]!;
  if (envelope.platform_context_id === null) return undefined;
  const root = await readCurrentPlatformScope(client, envelope.platform_context_id);
  if (envelope.platform_authority_epoch === root.platformAuthorityEpoch) return undefined;
  if (incoming.privacyDomainIds.length !== 1 || incoming.groupId !== undefined)
    throw new AuthorityFenceError();
  const pending = await pendingPlatformAdministrator(
    client,
    {
      participantId: incoming.participantId,
      privacyDomainId: incoming.privacyDomainIds[0]!,
    },
    root,
    incoming.authorityEnvelopeId,
  );
  const admin = pending.administrator,
    scope = admin.usable;
  if (
    envelope.platform_authority_epoch !== pending.root.platformAuthorityEpoch ||
    incoming.id !== admin.assignmentId ||
    incoming.principalId !== admin.principalId ||
    incoming.roleId !== `urn:openpc:role:${admin.roleId}` ||
    incoming.state !== 'ACTIVE' ||
    !incoming.makerCheckerRequired ||
    !incoming.stepUpRequired ||
    incoming.onwardDelegationDepth !== 0 ||
    (incoming.capabilityIds?.length ?? 0) !== 0 ||
    incoming.validUntil === null ||
    BigInt(incoming.validFrom.getTime()) * 1000000n !== BigInt(scope.validFromNs) ||
    BigInt(incoming.validUntil.getTime()) * 1000000n !== BigInt(scope.validUntilNs) ||
    !isDeepStrictEqual(incoming.privacyDomainIds, scope.administration.privacyDomainIds) ||
    !isDeepStrictEqual(incoming.actionIntentIds, scope.administration.actionIntentIds) ||
    !isDeepStrictEqual(incoming.resourceIds, scope.administration.resourceIds) ||
    !isDeepStrictEqual(incoming.riskClasses, scope.administration.riskClasses)
  )
    throw new AuthorityFenceError();
  const role = await client.query<{ role: { version: string } }>(
    `select jsonb_build_object(
    'roleId',r.role_id,'version',r.row_version::text,'actions',r.action_intent_ids,'origin',r.origin,
    'createdByPrincipalId',r.created_by_principal_id::text,'creatorParticipantId',r.creator_participant_id::text,
    'bootstrapMandateId',r.bootstrap_mandate_id::text,'bootstrapPlatformParticipantId',r.bootstrap_platform_participant_id::text) role
    from control.authority_role r where r.participant_id=$1 and r.authority_role_id=$2 and r.state='ACTIVE' for share`,
    [incoming.participantId, admin.roleId],
  );
  if (
    role.rowCount !== 1 ||
    role.rows[0]!.role.version !== admin.expectedRoleRevision ||
    canonicalAuthorizationDigest({
      domain: 'pc.identity.envelope-role-binding.v1',
      participantId: incoming.participantId,
      role: role.rows[0]!.role,
    }) !== admin.roleDigest
  )
    throw new AuthorityFenceError();
  return {
    platformContextId: root.platformContextId,
    platformAuthorityEpoch: pending.root.platformAuthorityEpoch,
  };
}
