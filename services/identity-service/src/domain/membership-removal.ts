import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { lockAuthorityFence, type AuthorityFence } from '../db/authority-fence.js';
import { principalInvalidationFence } from '../db/principal-invalidation-fence.js';
import { IdentityKernelError } from './identity-errors.js';
import { readPrincipal } from './principal-lifecycle.js';

interface RemovalDependencies {
  envelopes: string[];
  assignments: string[];
  delegations: string[];
}

/** The Participant write fence serializes discovery with grant admission and invalidation. */
async function dependencies(client: PoolClient, participantId: string, principalId: string) {
  const rows = await client.query<{ kind: keyof RemovalDependencies; id: string }>(
    `with recursive envelopes as (
       select authority_envelope_id from control.authority_envelope where participant_id=$1 and principal_id=$2
     ), assignments as (
       select assignment_id from control.assignment where participant_id=$1
         and (principal_id=$2 or authority_envelope_id in (select authority_envelope_id from envelopes))
     ), descendants as (
       select delegation_id from control.delegation where participant_id=$1
         and (grantor_principal_id=$2 or delegate_principal_id=$2
           or parent_assignment_id in (select assignment_id from assignments))
       union select child.delegation_id from control.delegation child join descendants parent
         on child.parent_delegation_id=parent.delegation_id where child.participant_id=$1
     )
     select 'envelopes' kind,authority_envelope_id::text id from envelopes
     union all select 'assignments',assignment_id::text from assignments
     union all select 'delegations',delegation_id::text from descendants limit 16385`,
    [participantId, principalId],
  );
  if (rows.rows.length > 16_384) throw new IdentityKernelError('PC-IDENTITY-1004');
  const result: RemovalDependencies = { envelopes: [], assignments: [], delegations: [] };
  for (const row of rows.rows) result[row.kind].push(row.id);
  return result;
}

export async function membershipRemovalFence(
  client: PoolClient,
  participantId: string,
  principalId: string,
): Promise<AuthorityFence> {
  await lockAuthorityFence(client, participantId, {
    participant: [{ id: participantId, write: true }],
  });
  const grants = await dependencies(client, participantId, principalId);
  return {
    ...(await principalInvalidationFence(client, participantId, principalId, true)),
    participant: [{ id: participantId, write: true }],
    authority_envelope: grants.envelopes.map((id) => ({ id, write: true })),
    assignment: grants.assignments.map((id) => ({ id, write: true })),
    delegation: grants.delegations.map((id) => ({ id, write: true })),
  };
}

/** Governed local offboarding retains the global subject and every immutable membership binding. */
export async function removeMembership(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  principalId: string,
  makerId: string,
  operationId: string,
) {
  if (principalId === makerId) throw new IdentityKernelError('PC-IDENTITY-1005');
  const changed = await client.query(
    `update control.principal principal set state='OFFBOARDED',authority_epoch=authority_epoch+1,
       row_version=row_version+1,updated_at=clock_timestamp()
     where participant_id=$1 and principal_id=$2 and state in ('PROVISIONED','ACTIVE','SUSPENDED')
       and exists (select 1 from control.participant_membership membership
         where membership.participant_id=principal.participant_id and membership.membership_id=principal.principal_id)
     returning principal_id`,
    [participantId, principalId],
  );
  if (changed.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1002');
  const grants = await dependencies(client, participantId, principalId);
  await client.query(
    `update control.session set state='REVOKED',session_epoch=session_epoch+1,
       row_version=row_version+1,updated_at=clock_timestamp(),revoked_at=clock_timestamp(),
       revoked_reason='membership-removed'
     where participant_id=$1 and principal_id=$2 and state in ('AUTHENTICATING','ACTIVE','STEP_UP_REQUIRED')`,
    [participantId, principalId],
  );
  const credentials = await client.query<{ id: string }>(
    `update control.credential set state='REVOKED',credential_epoch=credential_epoch+1,
       row_version=row_version+1,updated_at=clock_timestamp()
     where participant_id=$1 and principal_id=$2 and state not in ('REVOKED','EXPIRED')
     returning credential_id::text id`,
    [participantId, principalId],
  );
  await client.query(
    `with revoked as (update control.authority_group_member set state='REVOKED',revoked_at=clock_timestamp()
     where participant_id=$1 and principal_id=$2 and state not in ('REVOKED','EXPIRED','RETIRED') returning authority_group_id)
     update control.authority_group set row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$3
     where participant_id=$1 and authority_group_id in (select authority_group_id from revoked) and state='ACTIVE'`,
    [participantId, principalId, operationId],
  );
  const revoked: { kind: string; id: string }[] = [
    { kind: 'principal', id: principalId },
    ...credentials.rows.map(({ id }) => ({ kind: 'credential', id })),
  ];
  for (const [table, ids] of [
    ['authority_envelope', grants.envelopes],
    ['assignment', grants.assignments],
    ['delegation', grants.delegations],
  ] as const) {
    const result = await client.query<{ id: string }>(
      `update control.${table} set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp()
         ,last_mutation_operation_id=$3
       where participant_id=$1 and ${table}_id=any($2::uuid[]) and state not in ('REVOKED','EXPIRED')
       returning ${table}_id::text id`,
      [participantId, ids, operationId],
    );
    revoked.push(...result.rows.map(({ id }) => ({ kind: table, id })));
  }
  const epoch = await client.query<{ authority_epoch: string }>(
    `update control.participant set authority_epoch=authority_epoch+1,row_version=row_version+1,
       updated_at=clock_timestamp() where participant_id=$1 returning authority_epoch::text`,
    [participantId],
  );
  for (const target of revoked) {
    await client.query(
      `insert into control.revocation
       (participant_id,target_type,target_id,effective_at,reason_code,authority_epoch,receipt_digest,created_by_principal_id)
       values ($1,$2,$3,clock_timestamp(),'MEMBERSHIP_REMOVED',$4,$5,$6)`,
      [
        participantId,
        target.kind,
        target.id,
        epoch.rows[0]!.authority_epoch,
        createHash('sha256').update(`${operationId}:${target.kind}:${target.id}`).digest(),
        makerId,
      ],
    );
  }
  return (await readPrincipal(client, participantId, privacyDomainId, principalId)).effect;
}
