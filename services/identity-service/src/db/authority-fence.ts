import { currentPlatformEnvelopeSql } from './current-platform-envelope.js';
import type { PoolClient } from 'pg';
import { isDeepStrictEqual } from 'node:util';
import { assertRecoveryPrincipalAction } from '../domain/recovery-principal.js';

/** Participant, privacy, authority roots, then children (C04 transaction order). */
const authorityTables = [
  ['participant', 'participant_id', 0],
  ['privacy_domain', 'privacy_domain_id', 1],
  ['principal', 'principal_id', 2],
  ['authority_envelope', 'authority_envelope_id', 2],
  ['authority_role', 'authority_role_id', 2],
  ['assignment', 'assignment_id', 2],
  ['session', 'session_id', 3],
  ['delegation', 'delegation_id', 3],
  ['credential', 'credential_id', 3],
] as const;

type AuthorityTable = (typeof authorityTables)[number][0];

export interface AuthorityRowLock {
  readonly id: string;
  /** Declare writes before taking any locks to avoid a later shared-lock upgrade. */
  readonly write?: boolean;
}

export type AuthorityFence = Partial<Readonly<Record<AuthorityTable, readonly AuthorityRowLock[]>>>;

export interface GrantAuthority {
  readonly catalogOperationId?: string;
  readonly principalId: string;
  readonly participantEpoch: string;
  readonly principalEpoch: string;
  readonly assignmentId: string;
  readonly assignmentRowVersion: string;
  readonly authorityEnvelopeId: string;
  readonly authorityEpoch: string;
  readonly delegationEpoch: string;
  readonly privacyDomainId: string;
  readonly actionIntentId: string;
  readonly resourceId: string;
}

export interface BoundAuthority extends GrantAuthority {
  readonly sessionId: string;
  readonly sessionEpoch: string;
}

/** Exact dependencies already verified and locked by the ordinary mutation owner. */
export interface MutationAuthorityContext {
  readonly makerAuthority: BoundAuthority;
  readonly approvalAuthorities: readonly BoundAuthority[];
  readonly makerSignerCredentialId: string | undefined;
  readonly checkerSignerCredentialId: string | undefined;
}

/** A committed business grant outlives its issuing browser session, not its authority path. */
export interface DurableAuthority {
  readonly grant: GrantAuthority;
  readonly dependencies: unknown;
}

interface AuthorityPath {
  readonly delegationIds: string[];
  readonly principalIds: string[];
  readonly roleId: string | null;
}

export class AuthorityFenceError extends Error {
  constructor() {
    super('authority dependency is unavailable');
  }
}

/**
 * Lock exact authority dependencies inside an existing scoped transaction, before
 * revalidating their state/epochs and before locking business aggregates. Locks
 * live until commit/rollback. This function grants no authority and writes no state.
 * Callers must include every dependency of the authority path they subsequently use.
 */
export async function lockAuthorityFence(
  client: PoolClient,
  participantId: string,
  fence: AuthorityFence,
): Promise<void> {
  const ordered: {
    table: AuthorityTable;
    column: string;
    rank: number;
    id: string;
    write: boolean;
  }[] = [];
  for (const [table, column, rank] of authorityTables) {
    const requested = fence[table] ?? [];
    const rows = new Map<string, boolean>();
    for (const row of requested) {
      rows.set(row.id, rows.get(row.id) === true || row.write === true);
    }
    for (const [id, write] of rows) ordered.push({ table, column, rank, id, write });
  }
  // UUID byte order, then the stable table name when two tables share an ID.
  ordered.sort(
    (left, right) =>
      left.rank - right.rank ||
      Buffer.compare(
        Buffer.from(left.id.replaceAll('-', ''), 'hex'),
        Buffer.from(right.id.replaceAll('-', ''), 'hex'),
      ) ||
      (left.table < right.table ? -1 : left.table > right.table ? 1 : 0),
  );
  for (const { table, column, id, write } of ordered) {
    const selected = await client.query(
      `select ${column} from control.${table}
        where participant_id=$1 and ${column}=$2 for ${write ? 'update' : 'share'}`,
      [participantId, id],
    );
    if (selected.rowCount !== 1) throw new AuthorityFenceError();
  }
}

async function authorityPath(
  client: PoolClient,
  participantId: string,
  authority: GrantAuthority | BoundAuthority,
): Promise<AuthorityPath> {
  const selected = await client.query<AuthorityPath>(
    `with recursive path as (
       select a.principal_id terminal_principal_id,a.delegation_epoch,
              a.onward_delegation_depth remaining_depth,null::uuid delegation_id,
              array[]::uuid[] delegation_ids,array[a.principal_id] principal_ids
         from control.assignment a
        where a.participant_id=$1 and a.assignment_id=$2 and a.state='ACTIVE'
          and a.row_version=$3 and a.authority_envelope_id=$4
          and a.valid_during @> clock_timestamp()
          and $5=any(a.action_intent_ids) and $6=any(a.privacy_domain_ids)
          and openpc.assignment_role_permits(a.participant_id,a.role_id,$5)
          and openpc.assignment_group_permits(a.participant_id,a.authority_group_id,a.principal_id,a.valid_during)
          and openpc.administration_resource_permits(a.resource_ids,$7,$5,$1,$10,${
            'sessionId' in authority ? '$13::uuid' : 'null::uuid'
          },$4)
       union all
       select d.delegate_principal_id,d.delegation_epoch,d.onward_delegation_depth,
              d.delegation_id,p.delegation_ids||d.delegation_id,
              p.principal_ids||d.delegate_principal_id
         from path p join control.delegation d on d.participant_id=$1
          and ((p.delegation_id is null and d.parent_assignment_id=$2)
               or d.parent_delegation_id=p.delegation_id)
          and d.grantor_principal_id=p.terminal_principal_id and d.state='ACTIVE'
          and d.valid_during @> clock_timestamp()
          and $5=any(d.action_intent_ids) and $6=any(d.privacy_domain_ids)
          and ($7=any(d.resource_ids) or '*'=any(d.resource_ids))
          and d.onward_delegation_depth<p.remaining_depth
        where p.remaining_depth>0 and cardinality(p.delegation_ids)<32
          and not d.delegation_id=any(p.delegation_ids)
     )
     select path.delegation_ids as "delegationIds",path.principal_ids as "principalIds",
       (select role.authority_role_id::text from control.assignment assignment
         join control.authority_role role on role.participant_id=assignment.participant_id
          and role.role_id=assignment.role_id
         where assignment.participant_id=$1 and assignment.assignment_id=$2) as "roleId"
       from path
       join control.authority_envelope e on e.participant_id=$1
        and e.authority_envelope_id=$4 and e.authority_epoch=$8 and e.state='ACTIVE'
        and ${currentPlatformEnvelopeSql('e', false, true)}
        and e.valid_from<=clock_timestamp()
        and (e.valid_until is null or e.valid_until>clock_timestamp())
        and $5=any(e.action_intent_ids) and $6=any(e.privacy_domain_ids)
        and openpc.administration_resource_permits(e.resource_ids,$7,$5,$1,$10,${
          'sessionId' in authority ? '$13::uuid' : 'null::uuid'
        },$4)
       join control.participant participant on participant.participant_id=$1
        and participant.state='ACTIVE' and participant.authority_epoch=$9
       join control.privacy_domain privacy on privacy.participant_id=$1
        and privacy.privacy_domain_id=$6::uuid and privacy.state='ACTIVE'
       join control.principal principal on principal.participant_id=$1
        and principal.principal_id=$10 and principal.state='ACTIVE'
        and principal.authority_epoch=$11
       ${
         'sessionId' in authority
           ? `join control.session session on session.participant_id=$1
        and session.session_id=$13 and session.principal_id=$10
        and session.state='ACTIVE' and session.session_epoch=$14
        and session.participant_epoch=$9 and session.authority_epoch=$11
        and session.delegation_epoch=$12
        and session.idle_expires_at>clock_timestamp()
        and session.absolute_expires_at>clock_timestamp()`
           : ''
       }
      where path.terminal_principal_id=$10 and path.delegation_epoch=$12
        and not exists (
          select 1 from unnest(path.principal_ids) dependency(id)
           where not exists (select 1 from control.principal p
             where p.participant_id=$1 and p.principal_id=dependency.id and p.state='ACTIVE')
        )`,
    [
      participantId,
      authority.assignmentId,
      authority.assignmentRowVersion,
      authority.authorityEnvelopeId,
      authority.actionIntentId,
      authority.privacyDomainId,
      authority.resourceId,
      authority.authorityEpoch,
      authority.participantEpoch,
      authority.principalId,
      authority.principalEpoch,
      authority.delegationEpoch,
      ...('sessionId' in authority ? [authority.sessionId, authority.sessionEpoch] : []),
    ],
  );
  if (selected.rowCount !== 1 || selected.rows[0] === undefined) throw new AuthorityFenceError();
  return selected.rows[0];
}

/** Resolve, lock, then revalidate the exact bound paths; a newly inserted path cannot substitute. */
export async function fenceBoundAuthorities(
  client: PoolClient,
  participantId: string,
  authorities: readonly BoundAuthority[],
  additional: AuthorityFence = {},
): Promise<AuthorityFence> {
  return fenceAuthorities(client, participantId, authorities, additional);
}

async function fenceAuthorities(
  client: PoolClient,
  participantId: string,
  authorities: readonly (GrantAuthority | BoundAuthority)[],
  additional: AuthorityFence,
): Promise<AuthorityFence> {
  const paths: AuthorityPath[] = [];
  const fence: Partial<Record<AuthorityTable, AuthorityRowLock[]>> = {};
  for (const [table] of authorityTables) fence[table] = [...(additional[table] ?? [])];
  fence.participant!.push({ id: participantId });
  for (const authority of authorities) {
    const qualification = await client.query<{ credential_id: string; principal_id?: string }>(
      `select credential_id,principal_id from control.recovery_principal where participant_id=$1 and principal_id=$2
       union all select (signer->>'credentialId')::uuid,(signer->>'principalId')::uuid
       from control.authority_envelope envelope join control.platform_recovery_case recovery
        on recovery.recovery_id=envelope.recovery_case_id and recovery.participant_id=envelope.participant_id
       join control.platform_recovery_enrollment source on source.enrollment_id=recovery.enrollment_id
        and source.participant_id=recovery.participant_id and source.privacy_domain_id=recovery.privacy_domain_id
       cross join lateral jsonb_array_elements(jsonb_build_array(source.document->'recoveryPrincipal')||(source.document->'custodians')) signer
       where envelope.participant_id=$1 and envelope.authority_envelope_id=$3 and envelope.representation='RECOVERY_V1'`,
      [participantId, authority.principalId, authority.authorityEnvelopeId],
    );
    fence.credential!.push(...qualification.rows.map((row) => ({ id: row.credential_id })));
    fence.principal!.push(
      ...qualification.rows.flatMap((row) => (row.principal_id ? [{ id: row.principal_id }] : [])),
    );
    const path = await authorityPath(client, participantId, authority);
    paths.push(path);
    fence.principal!.push(...path.principalIds.map((id) => ({ id })));
    fence.privacy_domain!.push({ id: authority.privacyDomainId });
    if ('sessionId' in authority) fence.session!.push({ id: authority.sessionId });
    fence.authority_envelope!.push({ id: authority.authorityEnvelopeId });
    fence.assignment!.push({ id: authority.assignmentId });
    if (path.roleId !== null) fence.authority_role!.push({ id: path.roleId });
    fence.delegation!.push(...path.delegationIds.map((id) => ({ id })));
  }
  await lockAuthorityFence(client, participantId, fence);
  for (const [index, authority] of authorities.entries()) {
    try {
      await assertRecoveryPrincipalAction(client, { ...authority, participantId });
    } catch {
      throw new AuthorityFenceError();
    }
    const current = await authorityPath(client, participantId, authority);
    const previous = paths[index]!;
    if (
      JSON.stringify(current.delegationIds) !== JSON.stringify(previous.delegationIds) ||
      current.roleId !== previous.roleId ||
      JSON.stringify(current.principalIds) !== JSON.stringify(previous.principalIds)
    ) {
      throw new AuthorityFenceError();
    }
  }
  return fence;
}

/** Recheck time-sensitive authority under the original held fence. No lock is
 * taken after business rows: a newly discovered dependency fails closed. */
export async function revalidateBoundAuthorities(
  client: PoolClient,
  participantId: string,
  authorities: readonly BoundAuthority[],
  held: AuthorityFence,
): Promise<void> {
  if (authorities.length === 0) throw new AuthorityFenceError();
  for (const authority of authorities) {
    try {
      await assertRecoveryPrincipalAction(client, { ...authority, participantId });
    } catch {
      throw new AuthorityFenceError();
    }
    const current = await authorityPath(client, participantId, authority);
    const required: AuthorityFence = {
      participant: [{ id: participantId }],
      privacy_domain: [{ id: authority.privacyDomainId }],
      principal: current.principalIds.map((id) => ({ id })),
      authority_envelope: [{ id: authority.authorityEnvelopeId }],
      assignment: [{ id: authority.assignmentId }],
      session: [{ id: authority.sessionId }],
      authority_role: current.roleId === null ? [] : [{ id: current.roleId }],
      delegation: current.delegationIds.map((id) => ({ id })),
    };
    for (const table of Object.keys(required) as (keyof AuthorityFence)[]) {
      const heldIds = new Set((held[table] ?? []).map((row) => row.id));
      if (required[table]!.some((row) => !heldIds.has(row.id))) throw new AuthorityFenceError();
    }
  }
}

async function durableDependencies(
  client: PoolClient,
  participantId: string,
  grant: GrantAuthority,
) {
  const path = await authorityPath(client, participantId, grant);
  const result = await client.query<{ dependencies: unknown }>(
    `select jsonb_build_object(
      'path',$2::jsonb,
      'principals',(select jsonb_agg(jsonb_build_array(principal_id,authority_epoch::text) order by principal_id)
        from control.principal where participant_id=$1 and principal_id=any($3::uuid[])),
      'privacy',(select row_version::text from control.privacy_domain where participant_id=$1 and privacy_domain_id=$4),
      'role',(select row_version::text from control.authority_role where participant_id=$1 and authority_role_id=$5),
      'delegations',(select jsonb_agg(jsonb_build_array(delegation_id,delegation_epoch::text,row_version::text) order by delegation_id)
        from control.delegation where participant_id=$1 and delegation_id=any($6::uuid[]))
    ) dependencies`,
    [
      participantId,
      JSON.stringify(path),
      path.principalIds,
      grant.privacyDomainId,
      path.roleId,
      path.delegationIds,
    ],
  );
  return result.rows[0]!.dependencies;
}

/** Called inside the issuance mutation after the full session-bound authority fence. */
export async function captureDurableAuthorities(
  client: PoolClient,
  participantId: string,
  authorities: readonly BoundAuthority[],
): Promise<readonly DurableAuthority[]> {
  const result: DurableAuthority[] = [];
  for (const authority of authorities) {
    await authorityPath(client, participantId, authority);
    const grant: GrantAuthority = {
      principalId: authority.principalId,
      participantEpoch: authority.participantEpoch,
      principalEpoch: authority.principalEpoch,
      assignmentId: authority.assignmentId,
      assignmentRowVersion: authority.assignmentRowVersion,
      authorityEnvelopeId: authority.authorityEnvelopeId,
      authorityEpoch: authority.authorityEpoch,
      delegationEpoch: authority.delegationEpoch,
      privacyDomainId: authority.privacyDomainId,
      actionIntentId: authority.actionIntentId,
      resourceId: authority.resourceId,
      ...(authority.catalogOperationId === undefined
        ? {}
        : { catalogOperationId: authority.catalogOperationId }),
    };
    result.push({ grant, dependencies: await durableDependencies(client, participantId, grant) });
  }
  return result;
}

/** Only for immutable, previously captured business grants; never authorizes a new user mutation. */
export async function revalidateDurableAuthorities(
  client: PoolClient,
  participantId: string,
  authorities: readonly DurableAuthority[],
): Promise<void> {
  if (authorities.length === 0) throw new AuthorityFenceError();
  for (const { grant, dependencies } of authorities) {
    try {
      await assertRecoveryPrincipalAction(client, { ...grant, participantId });
    } catch {
      throw new AuthorityFenceError();
    }
    // Read-only: a changed path/epoch is rejected, never locked as a new parent
    // after business rows. Session lifetime is absent from durable grants.
    if (!isDeepStrictEqual(dependencies, await durableDependencies(client, participantId, grant)))
      throw new AuthorityFenceError();
  }
}

/** Acquire the whole ordinary fence before any business locks, then validate. */
export async function fenceDurableAuthorities(
  client: PoolClient,
  participantId: string,
  authorities: readonly DurableAuthority[],
  additional: AuthorityFence = {},
  current: readonly BoundAuthority[] = [],
): Promise<void> {
  if (authorities.length === 0) throw new AuthorityFenceError();
  await fenceAuthorities(
    client,
    participantId,
    [...authorities.map((entry) => entry.grant), ...current],
    additional,
  );
  for (const { grant, dependencies } of authorities) {
    if (!isDeepStrictEqual(dependencies, await durableDependencies(client, participantId, grant)))
      throw new AuthorityFenceError();
  }
}
