import type { PoolClient } from 'pg';
import type { InvitationCandidate } from '../contracts/invitation-operations.js';
import { IdentityKernelError } from './identity-errors.js';
import type { InvitationAuthority } from './invitation-authority.js';

interface InvitationRow {
  invitation_id: string;
  participant_id: string;
  privacy_domain_id: string;
  display_name: string;
  recipient_issuer: string;
  recipient_subject: string;
  recipient_audience: string;
  intended_role_id: string;
  created_by_principal_id: string;
  state: 'PENDING' | 'REVOKED' | 'ACCEPTED';
  token_version: string;
  expires_at: Date;
  row_version: string;
  last_mutation_operation_id: string;
  created_at: Date;
  updated_at: Date;
  observed_at: Date;
  accepted_membership_id: string | null;
  accepted_at: Date | null;
}

function readback(row: InvitationRow | undefined) {
  if (!row) throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    invitationId: row.invitation_id,
    participantId: row.participant_id,
    privacyDomainId: row.privacy_domain_id,
    displayName: row.display_name,
    recipient: {
      issuer: row.recipient_issuer,
      subject: row.recipient_subject,
      audience: row.recipient_audience,
    },
    roleIntent: { roleId: row.intended_role_id, authorityGranted: false as const },
    createdByPrincipalId: row.created_by_principal_id,
    state:
      row.state === 'PENDING' && row.expires_at <= row.observed_at
        ? ('EXPIRED' as const)
        : row.state,
    tokenVersion: String(row.token_version),
    expiresAt: row.expires_at.toISOString(),
    revision: String(row.row_version),
    operationId: row.last_mutation_operation_id,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
    ...(row.state === 'ACCEPTED' && row.accepted_membership_id && row.accepted_at
      ? {
          acceptance: {
            membershipId: row.accepted_membership_id,
            acceptedAt: row.accepted_at.toISOString(),
          },
        }
      : {}),
  };
}
export type ParticipantInvitation = ReturnType<typeof readback>;

export async function readParticipantInvitation(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  invitationId: string,
) {
  return readback(
    (
      await client.query<InvitationRow>(
        `select invitation.*,acceptance.membership_id accepted_membership_id,acceptance.accepted_at,clock_timestamp() observed_at
         from control.participant_invitation invitation left join control.participant_invitation_acceptance acceptance
          on acceptance.participant_id=invitation.participant_id and acceptance.privacy_domain_id=invitation.privacy_domain_id and acceptance.invitation_id=invitation.invitation_id and acceptance.token_version=invitation.token_version
     where invitation.participant_id=$1 and invitation.privacy_domain_id=$2 and invitation.invitation_id=$3 for share of invitation`,
        [participantId, privacyDomainId, invitationId],
      )
    ).rows[0],
  );
}

/** Runs only within the existing current-authority, approval, step-up and idempotency transaction. */
export async function mutateParticipantInvitation(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  principalId: string,
  candidate: InvitationCandidate,
  operationId: string,
  issuanceAuthority?: InvitationAuthority,
) {
  const change = candidate.change;
  const current =
    change.mutation === 'CREATE'
      ? undefined
      : await readParticipantInvitation(
          client,
          participantId,
          privacyDomainId,
          change.invitationId,
        );
  if (
    current &&
    (current.state === 'REVOKED' ||
      current.state === 'ACCEPTED' ||
      current.recipient.issuer !== candidate.issuer ||
      current.recipient.audience !== candidate.audience)
  )
    throw new IdentityKernelError('PC-IDENTITY-1002');
  if (change.mutation !== 'REVOKE') {
    const role = change.mutation === 'CREATE' ? change.intendedRoleId : current!.roleIntent.roleId;
    const eligible = await client.query(
      `select authority_role_id from control.authority_role where participant_id=$1 and authority_role_id=$2 and state='ACTIVE' for share`,
      [participantId, role],
    );
    if (eligible.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1002');
  }
  if (change.mutation === 'REVOKE') {
    await client.query(
      `update control.participant_invitation set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$4
      where participant_id=$1 and privacy_domain_id=$2 and invitation_id=$3`,
      [participantId, privacyDomainId, change.invitationId, operationId],
    );
  } else {
    if (!issuanceAuthority) throw new IdentityKernelError('PC-IDENTITY-1005');
    const reused = await client.query(
      `select 1 from control.participant_invitation_token
      where participant_id=$1 and privacy_domain_id=$2 and token_digest=$3 limit 1`,
      [participantId, privacyDomainId, Buffer.from(change.tokenDigest.slice(7), 'hex')],
    );
    if (reused.rowCount) throw new IdentityKernelError('PC-IDENTITY-1009');
    const deadline = (
      await client.query<{ expires_at: Date }>(
        `select clock_timestamp()+$1::integer*interval '1 second' expires_at`,
        [change.ttlSeconds],
      )
    ).rows[0]!.expires_at;
    const version = current ? String(BigInt(current.tokenVersion) + 1n) : '1';
    if (change.mutation === 'CREATE') {
      await client.query(
        `insert into control.participant_invitation
        (invitation_id,participant_id,privacy_domain_id,display_name,recipient_issuer,recipient_subject,recipient_audience,intended_role_id,created_by_principal_id,expires_at,last_mutation_operation_id)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          change.invitationId,
          participantId,
          privacyDomainId,
          change.displayName,
          candidate.issuer,
          change.recipientSubject,
          candidate.audience,
          change.intendedRoleId,
          principalId,
          deadline,
          operationId,
        ],
      );
    } else {
      await client.query(
        `update control.participant_invitation set token_version=$4,expires_at=$5,row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$6
        where participant_id=$1 and privacy_domain_id=$2 and invitation_id=$3`,
        [participantId, privacyDomainId, change.invitationId, version, deadline, operationId],
      );
    }
    await client.query(
      `insert into control.participant_invitation_token
      (participant_id,privacy_domain_id,invitation_id,token_version,token_digest,ttl_seconds,expires_at,operation_id,issuance_authority)
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        participantId,
        privacyDomainId,
        change.invitationId,
        version,
        Buffer.from(change.tokenDigest.slice(7), 'hex'),
        change.ttlSeconds,
        deadline,
        operationId,
        issuanceAuthority,
      ],
    );
  }
  return readParticipantInvitation(client, participantId, privacyDomainId, change.invitationId);
}
