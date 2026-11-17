import { createHash, randomBytes } from 'node:crypto';
import type { PoolClient } from 'pg';
import { lockAuthorityFence } from '../db/authority-fence.js';
import { fenceBootstrapAuthority, type BootstrapIssuanceAuthority } from './bootstrap-authority.js';
import { IdentityKernelError } from './identity-errors.js';
import { localOperationId } from './local-operation-id.js';
import type { FirstAdministratorProposal } from '../../../participant-service/src/contracts/first-administrator.js';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';

export interface BootstrapCustodyRow {
  mandate_id: string;
  participant_id: string;
  participant_epoch: string;
  custody_generation: string;
  platform_participant_id: string;
  maker_principal_id: string;
  checker_principal_id: string;
  invitation_id: string;
  state: string;
  candidate: FirstAdministratorProposal;
  candidate_digest: Buffer;
  issuance_authority: BootstrapIssuanceAuthority;
  expires_at: Date;
  candidate_membership_id: string | null;
  candidate_session_id: string | null;
  accepted_intent_digest: Buffer | null;
  acceptance_result: unknown;
}
const denied = () => new IdentityKernelError('PC-AUTH-0002');
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();

export async function readBootstrapCustody(
  client: PoolClient,
  participantId: string,
  invitationId: string,
) {
  const result = await client.query<BootstrapCustodyRow>(
    `select *,participant_epoch::text,custody_generation::text from control.participant_bootstrap_custody where participant_id=$1 and invitation_id=$2`,
    [participantId, invitationId],
  );
  return result.rows[0];
}

/** Lock the issuing authority before the target root, consistently with Platform mutations. */
export async function fenceBootstrapInvitation(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  invitationId: string,
): Promise<BootstrapCustodyRow | undefined> {
  const observed = await readBootstrapCustody(client, participantId, invitationId);
  if (!observed) return undefined;
  if (
    !['ACTIVE', 'CLAIM_PENDING'].includes(observed.state) ||
    observed.candidate.privacyDomainId !== privacyDomainId
  )
    throw denied();
  const authority = observed.issuance_authority;
  if (
    observed.platform_participant_id !== authority.participantId ||
    observed.maker_principal_id !== authority.signers[0]?.principalId ||
    observed.checker_principal_id !== authority.signers[1]?.principalId ||
    !observed.candidate_digest.equals(canonicalAuthorizationDigestBytes(observed.candidate))
  )
    throw denied();
  const context = (
    await client.query<{ operation_id: string; action_intent_id: string }>(
      `select current_setting('openpc.operation_id') operation_id,current_setting('openpc.action_intent_id') action_intent_id`,
    )
  ).rows[0]!;
  const candidateIdentity =
    observed.candidate_membership_id === null
      ? undefined
      : (
          await client.query<{ identity_subject_id: string }>(
            `select identity_subject_id from control.participant_membership where participant_id=$1 and membership_id=$2`,
            [participantId, observed.candidate_membership_id],
          )
        ).rows[0]?.identity_subject_id;
  await client.query(
    `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
    [
      authority.participantId,
      authority.privacyDomainId,
      context.operation_id,
      context.action_intent_id,
    ],
  );
  await fenceBootstrapAuthority(client, authority, participantId, observed.candidate);
  // Compare authoritative global identity membership as well as the exact initial IdP credential.
  const self = await client.query(
    `select 1 from control.credential where participant_id=$1 and principal_id=any($2::uuid[])
    and kind='OIDC_SUBJECT' and issuer=$3 and subject=$4 and audience=$5 limit 1`,
    [
      authority.participantId,
      authority.signers.map((value) => value.principalId),
      observed.candidate.recipientIssuer,
      observed.candidate.recipientSubject,
      observed.candidate.recipientAudience,
    ],
  );
  if (self.rowCount) throw denied();
  if (candidateIdentity) {
    const sameIdentity = await client.query(
      `select 1 from control.participant_membership where participant_id=$1 and membership_id=any($2::uuid[]) and identity_subject_id=$3 limit 1`,
      [
        authority.participantId,
        authority.signers.map((value) => value.principalId),
        candidateIdentity,
      ],
    );
    if (sameIdentity.rowCount) throw denied();
  }
  await client.query(
    `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
    [participantId, privacyDomainId, context.operation_id, context.action_intent_id],
  );
  await lockAuthorityFence(client, participantId, {
    participant: [{ id: participantId, write: true }],
  });
  const selected = await client.query<BootstrapCustodyRow>(
    `select custody.*,custody.participant_epoch::text,custody.custody_generation::text
    from control.participant_bootstrap_custody custody join control.participant participant on participant.participant_id=custody.participant_id
      and participant.state='PROVISIONING' and participant.authority_epoch=custody.participant_epoch and participant.root_privacy_domain_id=$3
    where custody.participant_id=$1 and custody.invitation_id=$2 and custody.state in ('ACTIVE','CLAIM_PENDING') and custody.expires_at>clock_timestamp()
      and not exists(select 1 from control.principal where participant_id=$1 and state='ACTIVE')
      and not exists(select 1 from control.assignment where participant_id=$1 and state='ACTIVE') for update of custody`,
    [participantId, invitationId, privacyDomainId],
  );
  if (selected.rowCount !== 1 || selected.rows[0]!.mandate_id !== observed.mandate_id)
    throw denied();
  return selected.rows[0]!;
}

/** A receipt-bound ceremony session is rejected by the normal active-session owner until handoff. */
export async function startBootstrapAcceptanceSession(
  client: PoolClient,
  custody: BootstrapCustodyRow,
  membershipId: string,
  principalEpoch: string,
) {
  if (custody.state !== 'ACTIVE' || custody.candidate_membership_id !== null) throw denied();
  const sessionId = localOperationId();
  const token = `${custody.participant_id}.${sessionId}`;
  await client.query(
    `insert into control.session(session_id,participant_id,principal_id,opaque_token_digest,state,authority_epoch,participant_epoch,
    delegation_epoch,session_epoch,refresh_family_id,refresh_token_digest,refresh_used,csrf_secret,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,client_fingerprint_digest)
    values($1,$2,$3,$4,'ACTIVE',$5,$6,0,1,$7,$8,false,$9,statement_timestamp(),statement_timestamp(),statement_timestamp()+interval '30 minutes',statement_timestamp()+interval '12 hours',$10)`,
    [
      sessionId,
      custody.participant_id,
      membershipId,
      hash(token),
      principalEpoch,
      custody.participant_epoch,
      localOperationId(),
      hash(randomBytes(32)),
      randomBytes(32),
      hash('first-administrator-ceremony'),
    ],
  );
  await client.query(
    `update control.participant_bootstrap_custody set state='CLAIM_PENDING',candidate_membership_id=$3,candidate_session_id=$4,row_version=row_version+1 where participant_id=$1 and mandate_id=$2 and state='ACTIVE'`,
    [custody.participant_id, custody.mandate_id, membershipId, sessionId],
  );
  return { mandateId: custody.mandate_id, sessionToken: token, state: 'CLAIM_PENDING' as const };
}
