import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  groupMutationCandidateSchema,
  groupOperationIds,
  type GroupChange,
} from '../contracts/group-operations.js';
import { ParticipantKernelError } from './participant-errors.js';
import { z } from 'zod';
import {
  directoryGroupCandidateSchema,
  directoryGroupOperationIds,
  directoryGroupOperation,
} from '../contracts/directory-group-operations.js';
const proposalCandidate = z.union([groupMutationCandidateSchema, directoryGroupCandidateSchema]);
const proposalOperations = [
  ...Object.values(groupOperationIds),
  ...Object.values(directoryGroupOperationIds),
];
export interface GroupRecord {
  readonly groupId: string;
  readonly participantId: string;
  readonly groupName: string;
  readonly state: string;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly operationId: string | null;
}
interface GroupRow {
  authority_group_id: string;
  participant_id: string;
  group_name: string;
  state: string;
  row_version: string;
  created_at: Date;
  updated_at: Date;
  last_mutation_operation_id: string | null;
}
function record(row: GroupRow | undefined): GroupRecord {
  if (!row) throw new ParticipantKernelError('PC-IDENTITY-1008');
  return {
    groupId: row.authority_group_id,
    participantId: row.participant_id,
    groupName: row.group_name,
    state: row.state,
    revision: String(row.row_version),
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
    operationId: row.last_mutation_operation_id,
  };
}
export async function readGroup(
  client: PoolClient,
  participantId: string,
  groupId: string,
  cursor?: string,
) {
  const group = await client.query<GroupRow>(
    'select * from control.authority_group where participant_id=$1 and authority_group_id=$2 for share',
    [participantId, groupId],
  );
  const effect = record(group.rows[0]);
  const members = await client.query<{
    authority_group_member_id: string;
    principal_id: string;
    display_label: string;
    state: string;
    valid_from: Date;
    valid_until: Date | null;
    revoked_at: Date | null;
    current: boolean;
  }>(
    `select m.authority_group_member_id,m.principal_id,p.display_label,m.state,lower(m.valid_during) valid_from,
       upper(m.valid_during) valid_until,m.revoked_at,
       ($4='ACTIVE' and m.state='ACTIVE' and m.valid_during @> clock_timestamp() and p.state='ACTIVE' and openpc.directory_group_permits(m.participant_id,m.authority_group_id)
        and exists(select 1 from control.participant_membership binding where binding.participant_id=m.participant_id and binding.membership_id=m.principal_id)) as current
      from control.authority_group_member m join control.principal p on p.participant_id=m.participant_id and p.principal_id=m.principal_id
      where m.participant_id=$1 and m.authority_group_id=$2 and ($3::uuid is null or m.authority_group_member_id>$3)
      order by m.authority_group_member_id limit 51`,
    [participantId, groupId, cursor ?? null, effect.state],
  );
  const page = members.rows.slice(0, 50);
  return {
    effect,
    members: page.map((row) => ({
      memberId: row.authority_group_member_id,
      principalId: row.principal_id,
      displayName: row.display_label,
      state: row.state,
      current: row.current,
      joinedAt: row.valid_from.toISOString(),
      validUntil: row.valid_until?.toISOString() ?? null,
      revokedAt: row.revoked_at?.toISOString() ?? null,
    })),
    nextCursor: members.rows.length > 50 ? page.at(-1)!.authority_group_member_id : null,
  };
}
export type GroupReadback = Awaited<ReturnType<typeof readGroup>>;
export type GroupProposalBinding =
  | { readonly approvalRequestId: string }
  | { readonly expectedRevision: string; readonly makerPrincipalId: string };
function bindingSql(binding: GroupProposalBinding) {
  return 'approvalRequestId' in binding
    ? { sql: 'a.approval_request_id=$4', values: [binding.approvalRequestId] }
    : {
        sql: 'm.expected_revision=$4 and m.maker_principal_id=$5',
        values: [binding.expectedRevision, binding.makerPrincipalId],
      };
}
export async function resolveGroupProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  candidateDigest: string,
  binding: GroupProposalBinding,
) {
  const bound = bindingSql(binding);
  const result = await client.query<{ resource_id: string }>(
    `select distinct m.resource_id from control.mutation_candidate m
    left join control.approval_request a on a.participant_id=m.participant_id and a.privacy_domain_id=m.privacy_domain_id and a.subject_id=m.mutation_candidate_id
    where m.participant_id=$1 and m.privacy_domain_id=$2 and m.candidate_digest=$3 and ${bound.sql}
    and m.catalog_operation_id=any($${4 + bound.values.length}::text[]) limit 2`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(candidateDigest.slice(7), 'hex'),
      ...bound.values,
      proposalOperations,
    ],
  );
  if (result.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
  return result.rows[0]!.resource_id;
}
export async function readGroupProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  resourceId: string,
  candidateDigest: string,
  binding: GroupProposalBinding,
) {
  const bound = bindingSql(binding);
  const result = await client.query<{
    resource_id: string;
    maker_principal_id: string;
    expected_revision: string;
    state: string;
    expires_at: Date;
    candidate_document: unknown;
    catalog_operation_id: string;
    consumed_operation_id: string | null;
    approval_request_id: string | null;
    reason: string | null;
  }>(
    `select m.resource_id,m.maker_principal_id,m.expected_revision::text,m.state,m.expires_at,m.candidate_document,
      m.catalog_operation_id,m.consumed_operation_id,a.approval_request_id,a.reason
     from control.mutation_candidate m left join control.approval_request a on a.participant_id=m.participant_id and a.privacy_domain_id=m.privacy_domain_id and a.subject_id=m.mutation_candidate_id
     where m.participant_id=$1 and m.privacy_domain_id=$2 and m.candidate_digest=$3 and ${bound.sql}
      and m.resource_id=$${4 + bound.values.length} and m.catalog_operation_id=any($${5 + bound.values.length}::text[]) for share of m`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(candidateDigest.slice(7), 'hex'),
      ...bound.values,
      resourceId,
      proposalOperations,
    ],
  );
  const row = result.rows[0],
    candidate = proposalCandidate.safeParse(row?.candidate_document);
  if (
    result.rowCount !== 1 ||
    !row ||
    !candidate.success ||
    candidate.data.expectedRevision !== row.expected_revision ||
    candidate.data.groupId !== resourceId ||
    ('observation' in candidate.data
      ? directoryGroupOperation(candidate.data)
      : groupOperationIds[candidate.data.mutation]) !== row.catalog_operation_id
  )
    throw new ParticipantKernelError('PC-IDENTITY-1008');
  return {
    candidateDigest,
    resourceId,
    makerPrincipalId: row.maker_principal_id,
    expectedRevision: row.expected_revision,
    state: row.state,
    expiresAt: row.expires_at.toISOString(),
    candidate: candidate.data,
    catalogOperationId: row.catalog_operation_id,
    operationId: row.consumed_operation_id,
    ...(row.approval_request_id
      ? { approval: { approvalRequestId: row.approval_request_id, reason: row.reason } }
      : {}),
  };
}
export type GroupProposal = Awaited<ReturnType<typeof readGroupProposal>>;
/** Caller holds the Participant write fence; group data never adds permissions. */
export async function revokeLinkedAssignments(
  client: PoolClient,
  participantId: string,
  groupId: string,
  makerId: string,
  operationId: string,
  principalId?: string | readonly string[],
) {
  const assignments = await client.query<{ assignment_id: string }>(
    `update control.assignment set state='REVOKED',row_version=row_version+1,
    updated_at=clock_timestamp(),last_mutation_operation_id=$4 where participant_id=$1 and authority_group_id=$2
    and ($3::uuid[] is null or principal_id=any($3::uuid[])) and state in ('ACTIVE','SUSPENDED') returning assignment_id`,
    [
      participantId,
      groupId,
      principalId === undefined
        ? null
        : typeof principalId === 'string'
          ? [principalId]
          : principalId,
      operationId,
    ],
  );
  if (!assignments.rows.length) return 0;
  await client.query(
    `with recursive descendants as (
    select delegation_id from control.delegation where participant_id=$1 and parent_assignment_id=any($2::uuid[])
    union select child.delegation_id from control.delegation child join descendants parent on child.parent_delegation_id=parent.delegation_id where child.participant_id=$1
  ) update control.delegation set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$3
    where participant_id=$1 and delegation_id in (select delegation_id from descendants) and state in ('ACTIVE','SUSPENDED')`,
    [participantId, assignments.rows.map((row) => row.assignment_id), operationId],
  );
  const epoch = await client.query<{ authority_epoch: string }>(
    `update control.participant set authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 returning authority_epoch::text`,
    [participantId],
  );
  for (const assignment of assignments.rows)
    await client.query(
      `insert into control.revocation
    (participant_id,target_type,target_id,effective_at,reason_code,authority_epoch,receipt_digest,created_by_principal_id)
    values ($1,'assignment',$2,clock_timestamp(),'GROUP_MEMBERSHIP_REMOVED',$3,$4,$5)`,
      [
        participantId,
        assignment.assignment_id,
        epoch.rows[0]!.authority_epoch,
        createHash('sha256')
          .update(
            `group:${groupId}:assignment:${assignment.assignment_id}:operation:${operationId}`,
          )
          .digest(),
        makerId,
      ],
    );
  return assignments.rows.length;
}
export async function mutateGroup(
  client: PoolClient,
  participantId: string,
  makerId: string,
  change: GroupChange,
  operationId: string,
) {
  if (change.mutation === 'CREATE') {
    const created = await client.query<GroupRow>(
      `insert into control.authority_group(authority_group_id,participant_id,group_name,state,last_mutation_operation_id)
      values ($1,$2,$3,'ACTIVE',$4) returning *`,
      [change.groupId, participantId, change.groupName, operationId],
    );
    return { effect: record(created.rows[0]), revokedAssignments: 0 };
  }
  const group = await client.query<GroupRow>(
    `select * from control.authority_group where participant_id=$1 and authority_group_id=$2 and state='ACTIVE' for update`,
    [participantId, change.groupId],
  );
  const current = record(group.rows[0]);
  let revokedAssignments = 0;
  if (change.mutation === 'ADD_MEMBER') {
    const directory = await client.query(
      'select 1 from control.directory_group_mapping where participant_id=$1 and authority_group_id=$2',
      [participantId, change.groupId],
    );
    if (directory.rowCount) throw new ParticipantKernelError('PC-IDENTITY-1002');
    const principal = await client.query(
      `select 1 from control.principal p join control.participant_membership m on m.participant_id=p.participant_id and m.membership_id=p.principal_id
      where p.participant_id=$1 and p.principal_id=$2 and p.state='ACTIVE' and p.kind in ('USER','PLATFORM_OPERATOR') for share of p,m`,
      [participantId, change.principalId],
    );
    if (principal.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1002');
    await client.query(
      `update control.authority_group_member set state='EXPIRED',revoked_at=clock_timestamp()
      where participant_id=$1 and authority_group_id=$2 and principal_id=$3 and state='ACTIVE' and upper(valid_during)<=clock_timestamp()`,
      [participantId, change.groupId, change.principalId],
    );
    await client.query(
      `insert into control.authority_group_member(participant_id,authority_group_id,principal_id,valid_during,state)
      values ($1,$2,$3,tstzrange(clock_timestamp(),null,'[)'),'ACTIVE')`,
      [participantId, change.groupId, change.principalId],
    );
  } else if (change.mutation === 'REMOVE_MEMBER') {
    const removed = await client.query(
      `update control.authority_group_member set state='REVOKED',revoked_at=clock_timestamp()
      where participant_id=$1 and authority_group_id=$2 and principal_id=$3 and state in ('ACTIVE','SUSPENDED') returning authority_group_member_id`,
      [participantId, change.groupId, change.principalId],
    );
    if (removed.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1002');
    revokedAssignments = await revokeLinkedAssignments(
      client,
      participantId,
      change.groupId,
      makerId,
      operationId,
      change.principalId,
    );
  } else if (change.mutation === 'RETIRE') {
    await client.query(
      `update control.authority_group_member set state='REVOKED',revoked_at=clock_timestamp()
      where participant_id=$1 and authority_group_id=$2 and state not in ('REVOKED','EXPIRED','RETIRED')`,
      [participantId, change.groupId],
    );
    revokedAssignments = await revokeLinkedAssignments(
      client,
      participantId,
      change.groupId,
      makerId,
      operationId,
    );
  }
  const updated = await client.query<GroupRow>(
    `update control.authority_group set group_name=$3,state=$4,row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$5
    where participant_id=$1 and authority_group_id=$2 and state='ACTIVE' returning *`,
    [
      participantId,
      change.groupId,
      change.mutation === 'RENAME' ? change.groupName : current.groupName,
      change.mutation === 'RETIRE' ? 'RETIRED' : 'ACTIVE',
      operationId,
    ],
  );
  return { effect: record(updated.rows[0]), revokedAssignments };
}
export type GroupMutationResult = Awaited<ReturnType<typeof mutateGroup>>;
