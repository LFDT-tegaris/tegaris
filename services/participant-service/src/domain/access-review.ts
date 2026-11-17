import type { PoolClient } from 'pg';
import type { Assignment, Delegation, PermissionSet } from './authority-kernel.js';
import { validateDelegation } from './authority-kernel.js';
import { intersectGrantPermissions } from './grant-admission.js';
import { readGrant, type GrantKind, type GrantReadback } from './grant-lifecycle.js';
import { envelopeFromRow, type EnvelopeRow } from './authority-records.js';
import { ParticipantKernelError } from './participant-errors.js';

export interface AccessReviewQuery {
  readonly after?: string;
  readonly limit: number;
}
export interface AdministrativeAccessPath {
  readonly grant: GrantReadback;
  readonly assignmentId: string;
  readonly envelopeId: string;
  readonly envelopeEpoch: string;
  readonly ancestry: readonly { id: string; kind: GrantKind; revision: string; state: string }[];
  readonly constraints: PermissionSet;
  readonly current: boolean;
  readonly reasons: readonly string[];
  readonly remediation: { kind: GrantKind; id: string; revision: string } | null;
}
export interface AccessReviewPage {
  readonly authoritative: false;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly subject: { id: string; kind: string; state: string; authorityEpoch: string };
  readonly participantEpoch: string;
  readonly observedAt: string;
  readonly items: readonly AdministrativeAccessPath[];
  readonly nextCursor: string | null;
  readonly completeness: 'COMPLETE' | 'MORE';
  readonly authorizedEmpty: boolean;
  readonly decisionBoundary: 'CURRENT_GRANT_INTERSECTION_REQUIRES_LIVE_REQUEST_AUTHORIZATION';
}

/** The repository holds the Participant read fence for the whole operation.
 * Every disclosed dependency also needs live EFFECTIVE_ACCESS authority. The
 * review never manufactures a subject session or a platform policy decision. */
export async function readAdministrativeAccess(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  subjectId: string,
  query: AccessReviewQuery,
  authorizeResource: (id: string) => Promise<void>,
): Promise<AccessReviewPage> {
  const subjectResult = await client.query<{
    id: string;
    kind: string;
    state: string;
    authorityEpoch: string;
    participant_epoch: string;
  }>(
    `select p.principal_id::text id,p.kind,p.state,p.authority_epoch::text "authorityEpoch",
       owner.authority_epoch::text participant_epoch
     from control.principal p join control.participant owner using(participant_id)
     where p.participant_id=$1 and p.principal_id=$2 and owner.state='ACTIVE'`,
    [participantId, subjectId],
  );
  if (subjectResult.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
  const subject = subjectResult.rows[0]!;
  const [afterKind, afterId] = query.after?.split(':') ?? [];
  const leaves = await client.query<{ id: string; kind: GrantKind }>(
    `with grants as (
       select assignment_id id,'assignment'::text kind from control.assignment
        where participant_id=$1 and principal_id=$2 and $3=any(privacy_domain_ids)
       union all
       select delegation_id id,'delegation'::text kind from control.delegation
        where participant_id=$1 and delegate_principal_id=$2 and $3=any(privacy_domain_ids)
     ) select id::text,kind from grants
       where $4::uuid is null or (id,kind)>($4::uuid,$5::text)
       order by id,kind limit $6`,
    [
      participantId,
      subjectId,
      privacyDomainId,
      afterId ?? null,
      afterKind ?? null,
      query.limit + 1,
    ],
  );
  const fenced = new Set([subjectId]);
  const authorize = async (id: string) => {
    if (!fenced.has(id)) {
      if (fenced.size >= 256) throw new ParticipantKernelError('PC-IDENTITY-1004');
      await authorizeResource(id);
      fenced.add(id);
    }
  };
  const items: AdministrativeAccessPath[] = [];
  for (const leaf of leaves.rows.slice(0, query.limit)) {
    const ancestry: GrantReadback[] = [];
    let id = leaf.id,
      kind = leaf.kind;
    const seen = new Set<string>();
    for (;;) {
      if (seen.has(id) || seen.size > 32) throw new ParticipantKernelError('PC-IDENTITY-1003');
      seen.add(id);
      await authorize(id);
      const record = await readGrant(client, participantId, privacyDomainId, id, kind);
      ancestry.unshift(record);
      if ('principalId' in record.effect) break;
      const parent = await client.query<{ id: string; kind: GrantKind }>(
        `select parent_assignment_id::text id,'assignment'::text kind from control.delegation
          where participant_id=$1 and delegation_id=$2 and parent_assignment_id is not null
         union all
         select parent_delegation_id::text id,'delegation'::text kind from control.delegation
          where participant_id=$1 and delegation_id=$2 and parent_delegation_id is not null`,
        [participantId, id],
      );
      if (parent.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1003');
      ({ id, kind } = parent.rows[0]!);
    }
    const assignment = ancestry[0]!.effect as Assignment;
    await authorize(assignment.authorityEnvelopeId);
    const envelopeRows = await client.query<EnvelopeRow>(
      `select * from control.authority_envelope where participant_id=$1 and authority_envelope_id=$2
        and $3=any(privacy_domain_ids)`,
      [participantId, assignment.authorityEnvelopeId, privacyDomainId],
    );
    if (envelopeRows.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
    const envelope = envelopeFromRow(envelopeRows.rows[0]!);
    const reasons = new Set<string>();
    let constraints = intersectGrantPermissions(assignment, envelope);
    if (envelope.state !== 'ACTIVE') reasons.add('ENVELOPE_NOT_ACTIVE');
    let parent = assignment as Assignment | Delegation;
    for (const { effect } of ancestry) {
      if (effect.state !== 'ACTIVE') reasons.add('GRANT_NOT_ACTIVE');
      if ('parentId' in effect) {
        if (
          effect.parentId !== parent.id ||
          effect.delegationEpoch !== parent.delegationEpoch ||
          validateDelegation(effect, parent) !== undefined
        )
          reasons.add('DELEGATION_NOT_CURRENT');
        constraints = intersectGrantPermissions(constraints, effect);
      }
      parent = effect;
    }
    if (assignment.roleId) {
      const roles = await client.query<{ id: string; state: string; action_intent_ids: string[] }>(
        `select authority_role_id::text id,state,action_intent_ids from control.authority_role
          where participant_id=$1 and role_id=$2`,
        [participantId, assignment.roleId],
      );
      if (roles.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
      const role = roles.rows[0]!;
      await authorize(role.id);
      if (role.state !== 'ACTIVE') reasons.add('ROLE_NOT_ACTIVE');
      constraints = {
        ...constraints,
        actionIntentIds: constraints.actionIntentIds.filter((action) =>
          role.action_intent_ids.includes(action),
        ),
      };
    }
    if (assignment.groupId) await authorize(assignment.groupId);
    const currentRows = await client.query<{
      group_permits: boolean;
      now: Date;
      principals_active: boolean;
    }>(
      `select clock_timestamp() now,
        openpc.assignment_group_permits(a.participant_id,a.authority_group_id,a.principal_id,a.valid_during) group_permits,
        not exists(select id from unnest($3::uuid[]) id where not exists(
          select 1 from control.principal p where p.participant_id=$1 and p.principal_id=id and p.state='ACTIVE')) principals_active
       from control.assignment a where a.participant_id=$1 and a.assignment_id=$2`,
      [
        participantId,
        assignment.id,
        ancestry.map(({ effect }) =>
          'principalId' in effect ? effect.principalId : effect.granteeId,
        ),
      ],
    );
    if (currentRows.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
    const current = currentRows.rows[0]!;
    if (!current.group_permits) reasons.add('GROUP_MEMBERSHIP_OR_DIRECTORY_NOT_CURRENT');
    if (!current.principals_active) reasons.add('PRINCIPAL_NOT_ACTIVE');
    if (constraints.validFrom > current.now) reasons.add('NOT_YET_VALID');
    if (constraints.validUntil !== null && constraints.validUntil <= current.now)
      reasons.add('VALIDITY_ENDED');
    if (
      constraints.actionIntentIds.length === 0 ||
      constraints.resourceIds.length === 0 ||
      constraints.riskClasses.length === 0 ||
      !constraints.privacyDomainIds.includes(privacyDomainId)
    )
      reasons.add('EMPTY_ADMINISTRATIVE_INTERSECTION');
    const grant = ancestry.at(-1)!;
    items.push({
      grant,
      assignmentId: assignment.id,
      envelopeId: envelope.id,
      envelopeEpoch: envelope.authorityEpoch,
      ancestry: ancestry.map(({ effect, revision }) => ({
        id: effect.id,
        kind: 'principalId' in effect ? 'assignment' : 'delegation',
        revision,
        state: effect.state,
      })),
      constraints: { ...constraints, privacyDomainIds: [privacyDomainId] },
      current: reasons.size === 0,
      reasons: [...reasons],
      remediation: ['ACTIVE', 'SUSPENDED'].includes(grant.effect.state)
        ? { kind: leaf.kind, id: leaf.id, revision: grant.revision }
        : null,
    });
  }
  // The extra row is cursor control only; disclose its existence only after the
  // same live resource check, never infer authorized completeness from a filter.
  if (leaves.rows.length > query.limit) await authorize(leaves.rows[query.limit]!.id);
  const last = leaves.rows.slice(0, query.limit).at(-1);
  const more = leaves.rows.length > query.limit;
  return {
    authoritative: false,
    participantId,
    privacyDomainId,
    subject: {
      id: subject.id,
      kind: subject.kind,
      state: subject.state,
      authorityEpoch: subject.authorityEpoch,
    },
    participantEpoch: subject.participant_epoch,
    observedAt: new Date().toISOString(),
    items,
    nextCursor: more && last ? `${last.kind}:${last.id}` : null,
    completeness: more ? 'MORE' : 'COMPLETE',
    authorizedEmpty: leaves.rows.length === 0,
    decisionBoundary: 'CURRENT_GRANT_INTERSECTION_REQUIRES_LIVE_REQUEST_AUTHORIZATION',
  };
}
