import { createHash } from 'node:crypto';

import {
  transitionStatePreimage,
  type CborValue,
  type TransitionStateContext,
} from '@openpc/security-kernel/business-transition/state';
import type { PoolClient } from 'pg';
import { z } from 'zod';

import { sha256 } from '../../digest.js';
import { digestSchema, openPcUrnSchema, uuidSchema } from '../../resource-contracts.js';
import { ConfigurationRepositoryError, type MutationBusinessState } from '../types.js';

const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18_446_744_073_709_551_615n);
const kind = z.enum([
  'APPROVAL',
  'REMEDIATION',
  'DELIVERY_FAILURE',
  'FLEET_FAILURE',
  'EVIDENCE_BACKLOG',
]);
const scopeSchema = z.strictObject({
  participantId: uuidSchema,
  privacyDomainId: uuidSchema,
  aggregateId: uuidSchema,
});
const stateSchema = z
  .strictObject({
    workItemId: uuidSchema,
    participantId: uuidSchema,
    privacyDomainId: uuidSchema,
    kind,
    state: z.enum(['OPEN', 'CLAIMED', 'COMPLETED', 'CANCELLED']),
    assigneePrincipalId: uuidSchema.nullable(),
    resourceRef: openPcUrnSchema,
    payloadDigest: digestSchema,
    reasonDigest: digestSchema,
    createdByPrincipalId: uuidSchema,
    claimedByPrincipalId: uuidSchema.nullable(),
    completedByPrincipalId: uuidSchema.nullable(),
    revision,
  })
  .refine((value) => {
    switch (value.state) {
      case 'OPEN':
        return value.claimedByPrincipalId === null && value.completedByPrincipalId === null;
      case 'CLAIMED':
        return (
          value.claimedByPrincipalId !== null &&
          value.assigneePrincipalId === value.claimedByPrincipalId &&
          value.completedByPrincipalId === null
        );
      case 'COMPLETED':
        return (
          value.claimedByPrincipalId !== null &&
          value.assigneePrincipalId === value.claimedByPrincipalId &&
          value.completedByPrincipalId === value.claimedByPrincipalId
        );
      case 'CANCELLED':
        // Retain historical actors. No new cancellation command is introduced here.
        return true;
    }
  });

const actor = { actorPrincipalId: uuidSchema };
const commandSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('CREATE'),
    ...actor,
    expectedRevision: z.literal('0'),
    workItemKind: kind,
    assigneePrincipalId: uuidSchema.nullable(),
    resourceRef: openPcUrnSchema,
    payloadDigest: digestSchema,
    reasonDigest: digestSchema,
  }),
  z.strictObject({
    kind: z.literal('UPDATE'),
    ...actor,
    expectedRevision: revision,
    replacementDigest: digestSchema,
    reasonDigest: digestSchema,
  }),
  z.strictObject({ kind: z.literal('CLAIM'), ...actor, expectedRevision: revision }),
  z.strictObject({ kind: z.literal('COMPLETE'), ...actor, expectedRevision: revision }),
]);

export type WorkItemBusinessState = z.infer<typeof stateSchema>;
export type WorkItemStateScope = z.infer<typeof scopeSchema>;
export type WorkItemStateCommand = z.infer<typeof commandSchema>;

function invalid(): never {
  throw new ConfigurationRepositoryError('PC-DATA-6007');
}

function scopedState(
  scope: WorkItemStateScope,
  state: WorkItemBusinessState | undefined,
): WorkItemBusinessState | undefined {
  if (!scopeSchema.safeParse(scope).success) invalid();
  if (state === undefined) return undefined;
  const parsed = stateSchema.safeParse(state);
  if (!parsed.success) invalid();
  const actual = parsed.data;
  if (
    actual.workItemId !== scope.aggregateId ||
    actual.participantId !== scope.participantId ||
    actual.privacyDomainId !== scope.privacyDomainId
  )
    invalid();
  return actual;
}

/** Read both snapshots inside the existing serializable mutation, after authority fences. */
export async function readWorkItemBusinessState(
  client: PoolClient,
  scope: WorkItemStateScope,
): Promise<WorkItemBusinessState | undefined> {
  if (!scopeSchema.safeParse(scope).success) invalid();
  const selected = await client.query<
    Omit<WorkItemBusinessState, 'reasonDigest'> & { reason: string }
  >(
    `select work_item_id::text as "workItemId",participant_id::text as "participantId",
            privacy_domain_id::text as "privacyDomainId",kind,state,
            assignee_principal_id::text as "assigneePrincipalId",resource_ref as "resourceRef",
            'sha256:'||encode(payload_digest,'hex') as "payloadDigest",reason,
            created_by_principal_id::text as "createdByPrincipalId",
            claimed_by_principal_id::text as "claimedByPrincipalId",
            completed_by_principal_id::text as "completedByPrincipalId",row_version::text as revision
       from control.work_item
      where participant_id=$1 and privacy_domain_id=$2 and work_item_id=$3 for update`,
    [scope.participantId, scope.privacyDomainId, scope.aggregateId],
  );
  if (selected.rowCount === 0) return undefined;
  if (selected.rowCount !== 1) invalid();
  const { reason, ...row } = selected.rows[0]!;
  if (typeof reason !== 'string' || reason.length === 0 || [...reason].length > 1024) invalid();
  return Object.freeze(
    scopedState(scope, { ...row, reasonDigest: sha256(Buffer.from(reason, 'utf8')) })!,
  );
}

/** P0 must register this exact projection; this encoder grants no signing authority. */
export function bindWorkItemBusinessState(
  context: TransitionStateContext,
  state: WorkItemBusinessState | undefined,
): MutationBusinessState['before'] {
  if (context.aggregateType !== 'work-item') invalid();
  const actual = scopedState(
    {
      participantId: context.participantId,
      privacyDomainId: context.privacyDomainId,
      aggregateId: context.aggregateId,
    },
    state,
  );
  const uuid = (value: string): Buffer => Buffer.from(value.replaceAll('-', ''), 'hex');
  // Scope, aggregate identity and revision are in the enclosing canonical preimage.
  // Audit timestamps are excluded; reason bytes are committed without disclosing them.
  const projection =
    actual === undefined
      ? new Map<number, CborValue>()
      : new Map<number, CborValue>([
          [0, actual.kind],
          [1, actual.state],
          [2, actual.resourceRef],
          [3, Buffer.from(actual.payloadDigest.slice(7), 'hex')],
          [4, Buffer.from(actual.reasonDigest.slice(7), 'hex')],
          [5, uuid(actual.createdByPrincipalId)],
        ]);
  if (actual !== undefined) {
    for (const [key, principalId] of [
      [6, actual.assigneePrincipalId],
      [8, actual.claimedByPrincipalId],
      [10, actual.completedByPrincipalId],
    ] as const) {
      projection.set(key, principalId === null ? 0n : 1n);
      if (principalId !== null) projection.set(key + 1, uuid(principalId));
    }
  }
  const existence = actual === undefined ? 0 : 1;
  const version = actual === undefined ? 0n : BigInt(actual.revision);
  const preimage = transitionStatePreimage(context, existence, version, projection);
  return {
    preimage,
    reference: {
      existence,
      revision: version,
      stateDigest: createHash('sha256').update(preimage).digest(),
    },
  };
}

/** Compare actual durable rows with the exact command, never a public response projection. */
export function assertWorkItemBusinessTransition(
  scope: WorkItemStateScope,
  command: WorkItemStateCommand,
  before: WorkItemBusinessState | undefined,
  after: WorkItemBusinessState | undefined,
): void {
  const parsed = commandSchema.safeParse(command);
  if (!parsed.success) invalid();
  const input = parsed.data;
  const prior = scopedState(scope, before);
  const next = scopedState(scope, after);
  if (next === undefined) invalid();
  if (input.kind === 'CREATE') {
    if (
      prior !== undefined ||
      next.revision !== '1' ||
      next.state !== 'OPEN' ||
      next.kind !== input.workItemKind ||
      next.assigneePrincipalId !== input.assigneePrincipalId ||
      next.resourceRef !== input.resourceRef ||
      next.payloadDigest !== input.payloadDigest ||
      next.reasonDigest !== input.reasonDigest ||
      next.createdByPrincipalId !== input.actorPrincipalId
    )
      invalid();
    return;
  }
  if (
    prior === undefined ||
    prior.revision !== input.expectedRevision ||
    BigInt(next.revision) !== BigInt(prior.revision) + 1n ||
    next.kind !== prior.kind ||
    next.resourceRef !== prior.resourceRef ||
    next.createdByPrincipalId !== prior.createdByPrincipalId
  )
    invalid();
  if (input.kind === 'UPDATE') {
    if (
      prior.state !== 'OPEN' ||
      next.state !== 'OPEN' ||
      next.assigneePrincipalId !== prior.assigneePrincipalId ||
      next.payloadDigest !== input.replacementDigest ||
      next.payloadDigest === prior.payloadDigest ||
      next.reasonDigest !== input.reasonDigest
    )
      invalid();
    return;
  }
  if (next.payloadDigest !== prior.payloadDigest || next.reasonDigest !== prior.reasonDigest)
    invalid();
  if (input.kind === 'CLAIM') {
    if (
      prior.state !== 'OPEN' ||
      next.state !== 'CLAIMED' ||
      (prior.assigneePrincipalId !== null &&
        prior.assigneePrincipalId !== input.actorPrincipalId) ||
      next.assigneePrincipalId !== input.actorPrincipalId ||
      next.claimedByPrincipalId !== input.actorPrincipalId
    )
      invalid();
    return;
  }
  if (
    prior.state !== 'CLAIMED' ||
    next.state !== 'COMPLETED' ||
    prior.assigneePrincipalId !== input.actorPrincipalId ||
    prior.claimedByPrincipalId !== input.actorPrincipalId ||
    next.assigneePrincipalId !== prior.assigneePrincipalId ||
    next.claimedByPrincipalId !== prior.claimedByPrincipalId ||
    next.completedByPrincipalId !== input.actorPrincipalId
  )
    invalid();
}
