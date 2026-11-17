import type { PoolClient } from 'pg';
import { IdentityKernelError } from './identity-errors.js';
import { readPrincipal, type PrincipalRecord } from './principal-lifecycle.js';

/** Called only inside the governed principal-provision transaction, after its local principal insert. */
export async function createInitialHumanMembership(client: PoolClient, principal: PrincipalRecord) {
  if (principal.kind !== 'USER' && principal.kind !== 'PLATFORM_OPERATOR') return;
  await client.query(`insert into control.identity_subject(identity_subject_id) values ($1)`, [
    principal.principalId,
  ]);
  await client.query(
    `insert into control.participant_membership(membership_id,participant_id,identity_subject_id)
    values ($1,$2,$1)`,
    [principal.principalId, principal.participantId],
  );
}

/** Internal resolution only. Disclosure still requires real authority on this Participant's membership. */
export async function resolveSubjectMembership(
  client: PoolClient,
  participantId: string,
  subjectId: string,
) {
  const rows = await client.query<{ membership_id: string }>(
    `select membership_id from control.participant_membership
    where participant_id=$1 and identity_subject_id=$2`,
    [participantId, subjectId],
  );
  if (rows.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  return rows.rows[0]!.membership_id;
}

/** Only the selected membership is projected; a global subject reference never exposes other Participants. */
export async function readIdentitySubject(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  membershipId: string,
  subjectId: string,
) {
  const rows = await client.query<{ identity_subject_id: string; created_at: Date }>(
    `
    select subject.identity_subject_id,subject.created_at from control.identity_subject subject
    join control.participant_membership membership using(identity_subject_id)
    where membership.participant_id=$1 and membership.membership_id=$2 and subject.identity_subject_id=$3`,
    [participantId, membershipId, subjectId],
  );
  if (rows.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  const subject = rows.rows[0]!;
  const membership = await readPrincipal(client, participantId, privacyDomainId, membershipId);
  return {
    effect: {
      identitySubjectId: subject.identity_subject_id,
      createdAt: subject.created_at.toISOString(),
    },
    membership: membership.effect,
    membershipOperationId: membership.operationId,
  };
}
