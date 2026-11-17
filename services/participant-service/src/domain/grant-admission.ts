import { currentPlatformEnvelopeSql } from '../../../identity-service/src/db/current-platform-envelope.js';
import type { PoolClient } from 'pg';

import {
  type Assignment,
  type Delegation,
  type PermissionSet,
  validateDelegation,
} from './authority-kernel.js';
import {
  assignmentFromRow,
  delegationFromRow,
  envelopeFromRow,
  type AssignmentRow,
  type DelegationRow,
  type EnvelopeRow,
} from './authority-records.js';
import { ParticipantKernelError } from './participant-errors.js';

const limit = 16_384;
const intersection = <T extends string>(a: readonly T[], b: readonly T[]): T[] => [
  ...new Set(a.filter((value) => b.includes(value))),
];
const resources = (a: readonly string[], b: readonly string[]) =>
  a.includes('*') ? b : b.includes('*') ? a : intersection(a, b);

export function intersectGrantPermissions(a: PermissionSet, b: PermissionSet): PermissionSet {
  return {
    participantId: a.participantId,
    privacyDomainIds: intersection(a.privacyDomainIds, b.privacyDomainIds),
    actionIntentIds: intersection(a.actionIntentIds, b.actionIntentIds),
    capabilityIds: intersection(a.capabilityIds ?? [], b.capabilityIds ?? []),
    resourceIds: resources(a.resourceIds, b.resourceIds),
    riskClasses: intersection(a.riskClasses, b.riskClasses),
    validFrom: new Date(Math.max(a.validFrom.getTime(), b.validFrom.getTime())),
    validUntil:
      a.validUntil === null
        ? b.validUntil
        : b.validUntil === null
          ? a.validUntil
          : new Date(Math.min(a.validUntil.getTime(), b.validUntil.getTime())),
    makerCheckerRequired: a.makerCheckerRequired || b.makerCheckerRequired,
    stepUpRequired: a.stepUpRequired || b.stepUpRequired,
    onwardDelegationDepth: Math.min(a.onwardDelegationDepth, b.onwardDelegationDepth),
  };
}

/** Identity's administrative resolver selects paths by action, privacy, resource
 * and time. Risk is not an input to that resolver, so a different risk label
 * cannot make two administrative paths unambiguous. Runtime capabilities have
 * their own risk-scoped permission intersection. */
export function grantsOverlap(a: PermissionSet, b: PermissionSet, now: Date): boolean {
  if (a.participantId !== b.participantId) return false;
  const common = intersectGrantPermissions(a, b);
  const start = Math.max(now.getTime(), common.validFrom.getTime());
  return (
    (common.validUntil === null || start < common.validUntil.getTime()) &&
    common.privacyDomainIds.length > 0 &&
    common.resourceIds.length > 0 &&
    (common.actionIntentIds.length > 0 ||
      ((common.capabilityIds?.length ?? 0) > 0 && common.riskClasses.length > 0))
  );
}

/** Called inside the governed mutation, after its Participant UPDATE fence.
 * That common root serializes assignment and delegation admission, including
 * missing rows; locking only existing grants cannot prevent insertion races.
 * No authority identifiers or conflicting scope are returned to the caller. */
export async function assertGrantAdmission(
  client: PoolClient,
  incoming: Assignment | Delegation,
  futureRoot?: { platformContextId: string; platformAuthorityEpoch: string },
): Promise<void> {
  const pid = incoming.participantId;
  const assignments = await client.query<AssignmentRow>(
    `select a.*,lower(a.valid_during) valid_from,upper(a.valid_during) valid_until
       from control.assignment a
       left join control.authority_role r on r.participant_id=a.participant_id and r.role_id=a.role_id
      where a.participant_id=$1 and a.state='ACTIVE'
        and (a.role_id is null or r.state='ACTIVE')
      order by a.assignment_id limit 16385`,
    [pid],
  );
  const delegations = await client.query<DelegationRow>(
    `select *,lower(valid_during) valid_from,upper(valid_during) valid_until
       from control.delegation where participant_id=$1 and state='ACTIVE'
      order by delegation_id limit 16385`,
    [pid],
  );
  const envelopes = await client.query<EnvelopeRow>(
    `select e.* from control.authority_envelope e where participant_id=$1 and state='ACTIVE'
       and ((${currentPlatformEnvelopeSql('e')}
          and ($2::uuid is null or e.platform_context_id is distinct from $2))
         or (e.platform_context_id=$2 and e.platform_authority_epoch=$3))
      order by authority_envelope_id limit 16385`,
    [pid, futureRoot?.platformContextId ?? null, futureRoot?.platformAuthorityEpoch ?? null],
  );
  const principals = await client.query<{ principal_id: string }>(
    `select principal_id from control.principal where participant_id=$1 and state='ACTIVE'
      order by principal_id limit 16385`,
    [pid],
  );
  const roles = await client.query<{ role_id: string; action_intent_ids: string[] }>(
    `select role_id,action_intent_ids from control.authority_role
      where participant_id=$1 and state='ACTIVE' order by role_id limit 16385`,
    [pid],
  );
  const time = await client.query<{ now: Date }>('select clock_timestamp() as now');
  if (
    [assignments, delegations, envelopes, principals, roles].some(
      (result) => result.rows.length > limit,
    )
  )
    throw new ParticipantKernelError('PC-IDENTITY-1004');
  const now = time.rows[0]!.now;
  const activePrincipals = new Set(principals.rows.map((row) => row.principal_id));
  const envelopeById = new Map(
    envelopes.rows.map((row) => [row.authority_envelope_id, envelopeFromRow(row)]),
  );
  const roleById = new Map(roles.rows.map((row) => [row.role_id, row.action_intent_ids]));
  const grants = [
    ...assignments.rows.map(assignmentFromRow),
    ...delegations.rows.map(delegationFromRow),
  ];
  const byId = new Map(grants.map((grant) => [grant.id, grant]));
  if (byId.size !== grants.length) throw new ParticipantKernelError('PC-IDENTITY-1004');
  if (byId.has(incoming.id)) throw new ParticipantKernelError('PC-IDENTITY-1002');
  const effective = new Map<string, PermissionSet | undefined>();
  function path(
    grant: Assignment | Delegation,
    seen = new Set<string>(),
  ): PermissionSet | undefined {
    if (effective.has(grant.id)) return effective.get(grant.id);
    if (seen.has(grant.id) || seen.size > 32) throw new ParticipantKernelError('PC-IDENTITY-1003');
    seen.add(grant.id);
    const subject = 'principalId' in grant ? grant.principalId : grant.granteeId;
    if (!activePrincipals.has(subject)) return undefined;
    let scope: PermissionSet | undefined;
    if ('parentId' in grant) {
      const parent = byId.get(grant.parentId);
      if (
        parent !== undefined &&
        grant.delegationEpoch === parent.delegationEpoch &&
        validateDelegation(grant, parent) === undefined
      ) {
        const parentScope = path(parent, seen);
        if (parentScope !== undefined) scope = intersectGrantPermissions(grant, parentScope);
      }
    } else {
      const envelope = envelopeById.get(grant.authorityEnvelopeId);
      if (envelope !== undefined) {
        scope = intersectGrantPermissions(grant, envelope);
        if (grant.roleId !== undefined)
          scope = {
            ...scope,
            actionIntentIds: intersection(scope.actionIntentIds, roleById.get(grant.roleId) ?? []),
          };
      }
    }
    effective.set(grant.id, scope);
    return scope;
  }
  const subject = 'principalId' in incoming ? incoming.principalId : incoming.granteeId;
  if ('parentId' in incoming) {
    const parent = byId.get(incoming.parentId);
    const parentScope = parent === undefined ? undefined : path(parent);
    // Validate against the complete live ancestry, not merely the immediate row.
    if (
      parent === undefined ||
      parentScope === undefined ||
      validateDelegation(incoming, { ...parent, ...parentScope }) !== undefined ||
      (incoming.validUntil !== null && incoming.validUntil <= now)
    )
      throw new ParticipantKernelError('PC-IDENTITY-1003');
  }
  for (const grant of grants) {
    if (('principalId' in grant ? grant.principalId : grant.granteeId) !== subject) continue;
    const scope = path(grant);
    if (scope !== undefined && grantsOverlap(incoming, scope, now))
      throw new ParticipantKernelError('PC-IDENTITY-1002');
  }
}
