import { createHash } from 'node:crypto';
import { businessTransitionProfileForOperation } from '@openpc/security-kernel';
import {
  transitionStatePreimage,
  type CborValue,
} from '@openpc/security-kernel/business-transition/state';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import { createEvidenceHold } from './hold-contracts.js';
import { digest, sequence } from './segment.js';

const stateSchema = z.strictObject({
  holdKind: createEvidenceHold.shape.holdKind,
  selectorDigest: digest,
  state: z.enum(['ACTIVE', 'RELEASED']),
  revision: z.enum(['1', '2']),
  approvalRequestId: z.uuidv7(),
  creationOperationId: z.uuidv7(),
  releaseApprovalRequestId: z.uuidv7().nullable(),
  releaseOperationId: z.uuidv7().nullable(),
  effectiveAtNs: sequence,
  updatedAtNs: sequence,
});
type HoldState = z.infer<typeof stateSchema>;

export async function readHoldBusinessState(client: PoolClient, context: MutationContext) {
  const result = await client.query(
    `select hold_kind as "holdKind",selector_digest as "selectorDigest",state,revision::text,
     approval_request_id::text as "approvalRequestId",creation_operation_id::text as "creationOperationId",
     release_approval_request_id::text as "releaseApprovalRequestId",release_operation_id::text as "releaseOperationId",
     (floor(extract(epoch from effective_at)*1000000)*1000)::text as "effectiveAtNs",
     (floor(extract(epoch from updated_at)*1000000)*1000)::text as "updatedAtNs"
     from control.retention_hold where participant_id=$1 and privacy_domain_id=$2 and retention_hold_id=$3 for update`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.resourceId,
    ],
  );
  if (!result.rowCount) return undefined;
  if (result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
  return stateSchema.parse(result.rows[0]);
}

const uuidBytes = (value: string | null) => Buffer.from(value?.replaceAll('-', '') ?? '', 'hex');
/** Both projections come from the owning rows inside the fenced mutation transaction. */
export function bindHoldTransition(
  context: MutationContext,
  operationId: string,
  before: HoldState | undefined,
  after: HoldState | undefined,
) {
  const profile = businessTransitionProfileForOperation(context.catalogOperationId);
  const create = [
    'CFG-OP-CREATE-EVIDENCE-HOLD',
    'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD',
  ].includes(context.catalogOperationId);
  if (
    !profile ||
    profile.aggregateType !== 'evidence-hold' ||
    !after ||
    (create
      ? before !== undefined ||
        after.state !== 'ACTIVE' ||
        after.revision !== '1' ||
        after.creationOperationId !== operationId ||
        after.approvalRequestId !== context.authorization.approvalRequestId ||
        after.releaseApprovalRequestId !== null ||
        after.releaseOperationId !== null
      : !before ||
        before.state !== 'ACTIVE' ||
        before.revision !== '1' ||
        after.state !== 'RELEASED' ||
        after.revision !== '2' ||
        after.releaseOperationId !== operationId ||
        after.releaseApprovalRequestId !== context.authorization.approvalRequestId ||
        before.holdKind !== after.holdKind ||
        before.selectorDigest !== after.selectorDigest ||
        before.approvalRequestId !== after.approvalRequestId ||
        before.creationOperationId !== after.creationOperationId ||
        before.effectiveAtNs !== after.effectiveAtNs ||
        BigInt(before.updatedAtNs) > BigInt(after.updatedAtNs))
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const binding = {
    profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    participantId: context.authorization.participantId,
    privacyDomainId: context.authorization.privacyDomainId,
    aggregateType: profile.aggregateType,
    aggregateId: context.resourceId,
  };
  const bind = (state: HoldState | undefined) => {
    const projection = state
      ? new Map<number, CborValue>([
          [0, state.holdKind],
          [1, Buffer.from(state.selectorDigest.slice(7), 'hex')],
          [2, state.state],
          [3, uuidBytes(state.approvalRequestId)],
          [4, uuidBytes(state.creationOperationId)],
          [5, uuidBytes(state.releaseApprovalRequestId)],
          [6, uuidBytes(state.releaseOperationId)],
          [7, BigInt(state.effectiveAtNs)],
          [8, BigInt(state.updatedAtNs)],
        ])
      : new Map<number, CborValue>();
    const existence = state ? (1 as const) : (0 as const);
    const revision = BigInt(state?.revision ?? '0');
    const preimage = transitionStatePreimage(binding, existence, revision, projection);
    return {
      preimage,
      reference: {
        existence,
        revision,
        stateDigest: createHash('sha256').update(preimage).digest(),
      },
    };
  };
  return { before: bind(before), after: bind(after) };
}
