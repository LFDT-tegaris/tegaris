import type { PoolClient } from 'pg';
import {
  firstAdministratorProposal,
  type ParticipantBootstrapChange,
  type ParticipantBootstrapReadback,
} from '../contracts/first-administrator.js';
import { fenceBootstrapInvitation } from '../../../identity-service/src/domain/bootstrap-invitation.js';
import type { AuthenticatedActor } from './participant-kernel.js';
import { ParticipantKernelError } from './participant-errors.js';

const denied = () => new ParticipantKernelError('PC-IDENTITY-1005');
/** Resolve target custody through the source's consumed public creation candidate. */
export async function bootstrapSourceProposal(client: PoolClient, source: string, target: string) {
  const rows = await client.query<{ proposal: unknown }>(
    `select candidate_document->'firstAdministrator' proposal from control.mutation_candidate
     where participant_id=$1 and resource_id=$2 and catalog_operation_id='ID-OP-PARTICIPANT-CREATE' and state='CONSUMED'
       and candidate_document->>'participantId'=$2::text`,
    [source, target],
  );
  if (rows.rowCount !== 1) throw denied();
  return firstAdministratorProposal.parse(rows.rows[0]!.proposal);
}
async function context(client: PoolClient, participantId: string, privacyDomainId: string) {
  await client.query(
    `select openpc.set_request_context('PARTICIPANT',$1,$2,current_setting('openpc.operation_id')::uuid,current_setting('openpc.action_intent_id'),true)`,
    [participantId, privacyDomainId],
  );
}
export async function readBootstrapLifecycle(
  client: PoolClient,
  participantId: string,
): Promise<ParticipantBootstrapReadback> {
  const row = (
    await client.query<{
      participant_id: string;
      mandate_id: string;
      invitation_id: string;
      custody_generation: string;
      token_version: string;
      revision: string;
      privacy_domain_id: string;
      maker_principal_id: string;
      checker_principal_id: string;
      state: ParticipantBootstrapReadback['state'];
      expires_at: Date;
      operation_id: string;
    }>(
      `select custody.participant_id,custody.mandate_id,custody.invitation_id,custody.custody_generation::text,
     invitation.token_version::text,participant.row_version::text revision,invitation.privacy_domain_id,custody.maker_principal_id,custody.checker_principal_id,
     case when custody.state in ('ACTIVE','CLAIM_PENDING') and custody.expires_at<=clock_timestamp() then 'EXPIRED' else custody.state end state,
     custody.expires_at,invitation.last_mutation_operation_id operation_id
     from control.participant_bootstrap_custody custody join control.participant participant on participant.participant_id=custody.participant_id
       join control.participant_invitation invitation on invitation.participant_id=custody.participant_id and invitation.invitation_id=custody.invitation_id
     where custody.participant_id=$1`,
      [participantId],
    )
  ).rows;
  if (row.length !== 1) throw denied();
  const value = row[0]!;
  return {
    participantId: value.participant_id,
    mandateId: value.mandate_id,
    invitationId: value.invitation_id,
    custodyGeneration: value.custody_generation,
    tokenVersion: value.token_version,
    revision: value.revision,
    privacyDomainId: value.privacy_domain_id,
    makerPrincipalId: value.maker_principal_id,
    checkerPrincipalId: value.checker_principal_id,
    state: value.state,
    expiresAt: value.expires_at.toISOString(),
    operationId: value.operation_id,
  };
}
export async function sourceBootstrapReadback(
  client: PoolClient,
  actor: AuthenticatedActor,
  target: string,
  sourcePrivacy: string,
) {
  const proposal = await bootstrapSourceProposal(client, actor.participantId, target);
  await context(client, target, proposal.privacyDomainId);
  const result = await readBootstrapLifecycle(client, target);
  if (result.mandateId !== proposal.mandateId || result.invitationId !== proposal.invitationId)
    throw denied();
  await context(client, actor.participantId, sourcePrivacy);
  return result;
}
/** Called only by the existing candidate/approval/WebAuthn/idempotency transaction. */
export async function changeBootstrapCustody(
  client: PoolClient,
  actor: AuthenticatedActor,
  candidate: ParticipantBootstrapChange,
  operationId: string,
) {
  const proof = actor.mutationAuthorization;
  if (!proof || !actor.platform) throw denied();
  await context(client, actor.participantId, proof.privacyDomainId);
  const proposal = await bootstrapSourceProposal(
    client,
    actor.participantId,
    candidate.participantId,
  );
  if (
    proposal.mandateId !== candidate.mandateId ||
    proposal.invitationId !== candidate.invitationId
  )
    throw denied();
  await context(client, candidate.participantId, proposal.privacyDomainId);
  const custody = await fenceBootstrapInvitation(
    client,
    candidate.participantId,
    proposal.privacyDomainId,
    candidate.invitationId,
  );
  if (
    !custody ||
    custody.maker_principal_id !== actor.principalId ||
    custody.checker_principal_id !== proof.checkerPrincipalId ||
    custody.platform_participant_id !== actor.participantId ||
    custody.custody_generation !== candidate.custodyGeneration
  )
    throw denied();
  const current = await readBootstrapLifecycle(client, candidate.participantId);
  if (
    current.tokenVersion !== candidate.tokenVersion ||
    current.revision !== candidate.expectedRevision ||
    !['ACTIVE', 'CLAIM_PENDING'].includes(current.state)
  )
    throw denied();
  const rotating = candidate.change.mutation === 'ROTATE';
  if (candidate.change.mutation === 'ROTATE') {
    const digest = Buffer.from(candidate.change.tokenDigest.slice(7), 'hex');
    if (
      (
        await client.query(
          'select 1 from control.participant_invitation_token where participant_id=$1 and token_digest=$2',
          [candidate.participantId, digest],
        )
      ).rowCount
    )
      throw denied();
  }
  if (custody.candidate_session_id) {
    await client.query(
      `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason=$3,row_version=row_version+1
      where participant_id=$1 and session_id=$2 and state='ACTIVE'`,
      [
        candidate.participantId,
        custody.candidate_session_id,
        rotating ? 'first-administrator-custody-rotated' : 'first-administrator-custody-revoked',
      ],
    );
  }
  await client.query(
    `update control.participant_bootstrap_custody set state=$3,
    custody_generation=custody_generation+case when $4 then 1 else 0 end,
    candidate_membership_id=case when $4 then null else candidate_membership_id end,
    candidate_session_id=case when $4 then null else candidate_session_id end,
    closed_at=case when $4 then null else clock_timestamp() end,row_version=row_version+1
    where participant_id=$1 and mandate_id=$2`,
    [candidate.participantId, candidate.mandateId, rotating ? 'ACTIVE' : 'CANCELLED', rotating],
  );
  await client.query(
    `update control.participant_invitation set state=$3,token_version=token_version+case when $4 then 1 else 0 end,
    row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$5
    where participant_id=$1 and invitation_id=$2`,
    [
      candidate.participantId,
      candidate.invitationId,
      rotating ? 'PENDING' : 'REVOKED',
      rotating,
      operationId,
    ],
  );
  if (candidate.change.mutation === 'ROTATE')
    await client.query(
      `insert into control.participant_invitation_token
    (participant_id,privacy_domain_id,invitation_id,token_version,token_digest,ttl_seconds,expires_at,operation_id,issuance_authority)
    values($1,$2,$3,$4,$5,$6,$7,$8,null)`,
      [
        candidate.participantId,
        proposal.privacyDomainId,
        candidate.invitationId,
        String(BigInt(candidate.tokenVersion) + 1n),
        Buffer.from(candidate.change.tokenDigest.slice(7), 'hex'),
        proposal.configuration['participant.first_admin_invite_ttl'] / 1000,
        custody.expires_at,
        operationId,
      ],
    );
  await client.query(
    'update control.participant set row_version=row_version+1 where participant_id=$1',
    [candidate.participantId],
  );
  await client.query('set constraints control.invitation_current_token immediate');
  return { operationId, result: await readBootstrapLifecycle(client, candidate.participantId) };
}
