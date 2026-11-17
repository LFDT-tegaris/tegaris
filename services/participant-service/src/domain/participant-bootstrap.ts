import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigest } from '../../../identity-service/src/contracts/authorization.js';
import type { BootstrapIssuanceAuthority } from '../../../identity-service/src/domain/bootstrap-authority.js';
import {
  firstAdministratorProposal,
  type FirstAdministratorProposal,
} from '../contracts/first-administrator.js';
import { ParticipantKernelError } from './participant-errors.js';

const bytes = (value: string) => Buffer.from(value.slice(7), 'hex');

/** Part of the existing governed Participant creation transaction, before it publishes its receipt. */
export async function createParticipantBootstrap(
  client: PoolClient,
  participantId: string,
  candidate: FirstAdministratorProposal,
  authority: BootstrapIssuanceAuthority,
) {
  const parsed = firstAdministratorProposal.parse(candidate);
  if (authority.participantId === participantId)
    throw new ParticipantKernelError('PC-IDENTITY-1005');
  const maker = authority.signers[0]!;
  const checker = authority.signers[1]!;
  const ttlMs = parsed.configuration['participant.first_admin_invite_ttl'];
  const deadline = (
    await client.query<{ created_at: Date; expires_at: Date }>(
      `select statement_timestamp() created_at,statement_timestamp()+$1::integer*interval '1 millisecond' expires_at`,
      [ttlMs],
    )
  ).rows[0]!;
  const registered = await client.query<{ action_intent_id: string }>(
    `select action_intent_id from control.action_intent where action_intent_id=any($1::text[])`,
    [parsed.actionIntentIds],
  );
  if (registered.rowCount !== parsed.actionIntentIds.length)
    throw new ParticipantKernelError('PC-IDENTITY-1005');
  await client.query(
    `insert into control.participant_bootstrap_custody
    (mandate_id,participant_id,participant_epoch,platform_participant_id,maker_principal_id,checker_principal_id,invitation_id,
     first_admin_invite_ttl_ms,configuration_digest,candidate,candidate_digest,issuance_authority,created_operation_id,created_at,expires_at)
    values($1,$2,0,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      parsed.mandateId,
      participantId,
      authority.participantId,
      maker.principalId,
      checker.principalId,
      parsed.invitationId,
      ttlMs,
      bytes(canonicalAuthorizationDigest(parsed.configuration)),
      parsed,
      bytes(canonicalAuthorizationDigest(parsed)),
      authority,
      authority.operationId,
      deadline.created_at,
      deadline.expires_at,
    ],
  );
  await client.query(
    `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
    values($1,$2,'Root','PARTICIPANT_LOCAL','PARTICIPANT_LOCAL','PROVISIONING')`,
    [parsed.privacyDomainId, participantId],
  );
  await client.query(
    `update control.participant set root_privacy_domain_id=$2 where participant_id=$1 and state='PROVISIONING' and root_privacy_domain_id is null`,
    [participantId, parsed.privacyDomainId],
  );
  await client.query(
    `insert into control.authority_role(authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id,bootstrap_mandate_id,bootstrap_platform_participant_id)
    values($1,$2,$3,'Participant administrator',$4,'BOOTSTRAP',$5,$6,$7)`,
    [
      parsed.roleId,
      participantId,
      `urn:openpc:role:${parsed.roleId}`,
      parsed.actionIntentIds,
      maker.principalId,
      parsed.mandateId,
      authority.participantId,
    ],
  );
  await client.query(
    `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',true),openpc.assert_request_context(true)`,
    [participantId, parsed.privacyDomainId, authority.operationId],
  );
  await client.query(
    `insert into control.participant_invitation
    (invitation_id,participant_id,privacy_domain_id,display_name,recipient_issuer,recipient_subject,recipient_audience,intended_role_id,
     created_by_principal_id,bootstrap_mandate_id,bootstrap_platform_participant_id,expires_at,last_mutation_operation_id,created_at)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      parsed.invitationId,
      participantId,
      parsed.privacyDomainId,
      parsed.displayName,
      parsed.recipientIssuer,
      parsed.recipientSubject,
      parsed.recipientAudience,
      parsed.roleId,
      maker.principalId,
      parsed.mandateId,
      authority.participantId,
      deadline.expires_at,
      authority.operationId,
      deadline.created_at,
    ],
  );
  // Cross-Participant provenance is retained by the custody owner; ordinary tokens continue requiring their own issuance authority.
  await client.query(
    `insert into control.participant_invitation_token
    (participant_id,privacy_domain_id,invitation_id,token_version,token_digest,ttl_seconds,expires_at,operation_id,created_at)
    values($1,$2,$3,1,$4,$5,$6,$7,$8)`,
    [
      participantId,
      parsed.privacyDomainId,
      parsed.invitationId,
      bytes(parsed.tokenDigest),
      Math.ceil(ttlMs / 1000),
      deadline.expires_at,
      authority.operationId,
      deadline.created_at,
    ],
  );
  // Resolve the target's deferred token invariant before the shared mutation owner
  // returns to the Platform scope to publish its approval/evidence receipt.
  await client.query('set constraints control.invitation_current_token immediate');
  return {
    mandateId: parsed.mandateId,
    invitationId: parsed.invitationId,
    privacyDomainId: parsed.privacyDomainId,
    state: 'ACTIVE' as const,
    expiresAt: deadline.expires_at.toISOString(),
    configuration: parsed.configuration,
    issuanceAuthorityDigest: canonicalAuthorizationDigest(authority),
  };
}
