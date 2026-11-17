import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { Assignment, Delegation } from './authority-kernel.js';
import {
  assignmentFromRow,
  delegationFromRow,
  type AssignmentRow,
  type DelegationRow,
} from './authority-records.js';
import { ParticipantKernelError } from './participant-errors.js';

export const grantOperations = [
  'ID-OP-ASSIGNMENT-CREATE',
  'ID-OP-ASSIGNMENT-REVOKE',
  'ID-OP-DELEGATION-ISSUE',
  'ID-OP-DELEGATION-REVOKE',
] as const;
export type GrantKind = 'assignment' | 'delegation';
export interface GrantReadback<T extends Assignment | Delegation = Assignment | Delegation> {
  readonly effect: T;
  readonly revision: string;
  readonly operationId: string | null;
}
export interface GrantProposal {
  readonly candidateDigest: string;
  readonly resourceId: string;
  readonly kind: GrantKind;
  readonly mutation: 'CREATE' | 'REVOKE';
  readonly expectedRevision: string;
  readonly state: string;
  readonly expiresAt: string;
  readonly proposedGrant: Assignment | Delegation;
}

/** The caller fences actual READ_RESOURCE authority until this transaction commits. */
export async function readGrant(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  grantId: string,
  kind: GrantKind,
  completeScope = false,
): Promise<GrantReadback> {
  const found = await client.query<
    (AssignmentRow | DelegationRow) & { row_version: string; operation_id: string | null }
  >(
    `select g.*,lower(g.valid_during) valid_from,upper(g.valid_during) valid_until,
       candidate.consumed_operation_id::text operation_id
     from control.${kind} g left join lateral (
       select consumed_operation_id from control.mutation_candidate c
        where c.participant_id=g.participant_id and c.privacy_domain_id=$3 and c.state='CONSUMED'
          and ((g.last_mutation_operation_id is not null and c.consumed_operation_id=g.last_mutation_operation_id)
            or (g.last_mutation_operation_id is null and c.resource_id=g.${kind}_id
              and c.catalog_operation_id=any($4::text[]) and c.expected_revision=g.row_version-1))
        order by c.expected_revision desc limit 1
     ) candidate on true where g.participant_id=$1 and g.${kind}_id=$2
       and $3::text=any(g.privacy_domain_ids) and (not $5 or g.privacy_domain_ids=ARRAY[$3::text])`,
    [
      participantId,
      grantId,
      privacyDomainId,
      kind === 'assignment' ? grantOperations.slice(0, 2) : grantOperations.slice(2),
      completeScope,
    ],
  );
  if (found.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
  const row = found.rows[0]!;
  return {
    effect: {
      ...(kind === 'assignment'
        ? assignmentFromRow(row as AssignmentRow)
        : delegationFromRow(row as DelegationRow)),
      privacyDomainIds: [privacyDomainId],
    },
    revision: String(row.row_version),
    operationId: row.operation_id,
  };
}

export async function readGrantProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  candidateDigest: string,
  resourceId: string,
): Promise<GrantProposal> {
  const result = await client.query<{
    catalog_operation_id: (typeof grantOperations)[number];
    expected_revision: string;
    state: string;
    expires_at: Date;
    candidate_document: Assignment | Delegation;
  }>(
    `select catalog_operation_id,expected_revision::text,state,expires_at,candidate_document
      from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2
       and candidate_digest=$3 and resource_id=$4 and catalog_operation_id=any($5::text[]) for share`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(candidateDigest.slice(7), 'hex'),
      resourceId,
      grantOperations,
    ],
  );
  if (result.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
  const row = result.rows[0]!;
  const kind = row.catalog_operation_id.includes('ASSIGNMENT') ? 'assignment' : 'delegation';
  const mutation = row.catalog_operation_id.endsWith('REVOKE') ? 'REVOKE' : 'CREATE';
  const value =
    mutation === 'CREATE'
      ? row.candidate_document
      : (await readGrant(client, participantId, privacyDomainId, resourceId, kind, true)).effect;
  // A review must expose the entire scope it asks a checker to approve. A
  // single-context read cannot provide a complete review of a multi-context grant.
  if (value.privacyDomainIds.length !== 1 || value.privacyDomainIds[0] !== privacyDomainId)
    throw new ParticipantKernelError('PC-IDENTITY-1008');
  const permission = {
    id: resourceId,
    participantId,
    privacyDomainIds: [privacyDomainId],
    actionIntentIds: value.actionIntentIds,
    capabilityIds: value.capabilityIds ?? [],
    resourceIds: value.resourceIds,
    riskClasses: value.riskClasses,
    validFrom: new Date(value.validFrom),
    validUntil: value.validUntil === null ? null : new Date(value.validUntil),
    makerCheckerRequired: value.makerCheckerRequired,
    stepUpRequired: value.stepUpRequired,
    onwardDelegationDepth: value.onwardDelegationDepth,
    delegationEpoch: value.delegationEpoch,
    scopeDigest: value.scopeDigest,
    state: mutation === 'CREATE' ? ('ACTIVE' as const) : ('REVOKED' as const),
  };
  const proposedGrant =
    'principalId' in value
      ? {
          ...permission,
          principalId: value.principalId,
          authorityEnvelopeId: value.authorityEnvelopeId,
          ...(value.roleId === undefined ? {} : { roleId: value.roleId }),
          ...(value.groupId === undefined ? {} : { groupId: value.groupId }),
        }
      : {
          ...permission,
          parentId: value.parentId,
          grantorId: value.grantorId,
          granteeId: value.granteeId,
        };
  return {
    candidateDigest,
    resourceId,
    kind,
    mutation,
    expectedRevision: row.expected_revision,
    state: row.state,
    expiresAt: row.expires_at.toISOString(),
    proposedGrant,
  };
}

export async function grantDescendants(
  client: PoolClient,
  participantId: string,
  kind: GrantKind,
  targetId: string,
): Promise<string[]> {
  const result = await client.query<{ id: string }>(
    `with recursive descendants as (
      select delegation_id from control.delegation where participant_id=$1
        and (($3='assignment' and parent_assignment_id=$2) or ($3='delegation' and parent_delegation_id=$2))
      union select child.delegation_id from control.delegation child join descendants parent
        on child.parent_delegation_id=parent.delegation_id where child.participant_id=$1
    ) select delegation_id::text id from descendants limit 16385`,
    [participantId, targetId, kind],
  );
  if (result.rows.length > 16_384) throw new ParticipantKernelError('PC-IDENTITY-1004');
  return result.rows.map((row) => row.id);
}

export async function revokeGrant(
  client: PoolClient,
  participantId: string,
  principalId: string,
  kind: GrantKind,
  targetId: string,
  operationId: string,
): Promise<{ newEpoch: string }> {
  const descendants = await grantDescendants(client, participantId, kind, targetId);
  const target = await client.query(
    `update control.${kind} set state='REVOKED',row_version=row_version+1,
    updated_at=clock_timestamp(),last_mutation_operation_id=$3 where participant_id=$1 and ${kind}_id=$2
    and state in ('ACTIVE','SUSPENDED') returning ${kind}_id`,
    [participantId, targetId, operationId],
  );
  if (target.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1002');
  const revoked = await client.query<{ delegation_id: string }>(
    `update control.delegation
    set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$3
    where participant_id=$1 and delegation_id=any($2::uuid[]) and state in ('ACTIVE','SUSPENDED')
    returning delegation_id`,
    [participantId, descendants, operationId],
  );
  const epoch = await client.query<{ authority_epoch: string }>(
    `update control.participant
    set authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp()
    where participant_id=$1 returning authority_epoch::text`,
    [participantId],
  );
  const newEpoch = epoch.rows[0]!.authority_epoch;
  for (const target of [
    { kind, id: targetId },
    ...revoked.rows.map((row) => ({ kind: 'delegation', id: row.delegation_id })),
  ]) {
    await client.query(
      `insert into control.revocation
      (participant_id,target_type,target_id,effective_at,reason_code,authority_epoch,receipt_digest,created_by_principal_id)
      values ($1,$2,$3,clock_timestamp(),$4,$5,$6,$7)`,
      [
        participantId,
        target.kind,
        target.id,
        target.id === targetId ? 'EXPLICIT_REVOKE' : 'ANCESTOR_REVOKED',
        newEpoch,
        createHash('sha256').update(`${target.kind}:${target.id}:${newEpoch}`).digest(),
        principalId,
      ],
    );
  }
  return { newEpoch };
}
