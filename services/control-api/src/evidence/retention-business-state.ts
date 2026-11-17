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
import { digest, sequence } from './segment.js';

const stateSchema = z.strictObject({
  policyDigest: digest,
  predecessorPolicyId: z.uuidv7().nullable(),
  revision: z.enum(['1', '2']),
  approvalRequestId: z.uuidv7(),
  activationOperationId: z.uuidv7(),
  retirementApprovalRequestId: z.uuidv7().nullable(),
  retirementOperationId: z.uuidv7().nullable(),
  activeFromNs: sequence,
  activeUntilNs: sequence.nullable(),
});
type PolicyState = z.infer<typeof stateSchema>;
export async function readRetentionBusinessState(client: PoolClient, context: MutationContext) {
  const result = await client.query(
    `select policy_digest as "policyDigest",predecessor_policy_id::text as "predecessorPolicyId",revision::text,
    approval_request_id::text as "approvalRequestId",activation_operation_id::text as "activationOperationId",
    retirement_approval_request_id::text as "retirementApprovalRequestId",retirement_operation_id::text as "retirementOperationId",
    (floor(extract(epoch from active_from)*1000000)*1000)::text as "activeFromNs",
    (floor(extract(epoch from active_until)*1000000)*1000)::text as "activeUntilNs"
    from control.retention_policy where participant_id=$1 and privacy_domain_id=$2 and retention_policy_id=$3 for update`,
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
export function bindRetentionTransition(
  context: MutationContext,
  operationId: string,
  before: PolicyState | undefined,
  after: PolicyState | undefined,
) {
  const profile = businessTransitionProfileForOperation(context.catalogOperationId);
  const activation = context.catalogOperationId === 'CFG-OP-ACTIVATE-RETENTION-POLICY';
  if (
    !profile ||
    profile.aggregateType !== 'retention-policy' ||
    !after ||
    (activation
      ? before !== undefined ||
        after.revision !== '1' ||
        after.activeUntilNs !== null ||
        after.activationOperationId !== operationId ||
        after.approvalRequestId !== context.authorization.approvalRequestId ||
        after.retirementOperationId !== null ||
        after.retirementApprovalRequestId !== null
      : !before ||
        before.revision !== '1' ||
        before.activeUntilNs !== null ||
        after.revision !== '2' ||
        after.activeUntilNs === null ||
        after.retirementOperationId !== operationId ||
        after.retirementApprovalRequestId !== context.authorization.approvalRequestId ||
        after.policyDigest !== before.policyDigest ||
        after.predecessorPolicyId !== before.predecessorPolicyId ||
        after.approvalRequestId !== before.approvalRequestId ||
        after.activationOperationId !== before.activationOperationId ||
        after.activeFromNs !== before.activeFromNs ||
        BigInt(after.activeUntilNs) <= BigInt(before.activeFromNs))
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const binding = {
    profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    participantId: context.authorization.participantId,
    privacyDomainId: context.authorization.privacyDomainId,
    aggregateType: profile.aggregateType,
    aggregateId: context.resourceId,
  };
  const bind = (state: PolicyState | undefined) => {
    const projection = state
      ? new Map<number, CborValue>([
          [0, Buffer.from(state.policyDigest.slice(7), 'hex')],
          [1, uuidBytes(state.predecessorPolicyId)],
          [2, uuidBytes(state.approvalRequestId)],
          [3, uuidBytes(state.activationOperationId)],
          [4, uuidBytes(state.retirementApprovalRequestId)],
          [5, uuidBytes(state.retirementOperationId)],
          [6, BigInt(state.activeFromNs)],
          [7, state.activeUntilNs === null ? Buffer.alloc(0) : BigInt(state.activeUntilNs)],
        ])
      : new Map<number, CborValue>();
    const existence = state ? (1 as const) : (0 as const),
      revision = BigInt(state?.revision ?? '0');
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
