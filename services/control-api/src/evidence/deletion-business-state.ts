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
import { RUNTIME_ARTIFACT_MAX_BYTES } from './runtime-artifact-archive-contract.js';

const deletionState = z.strictObject({
  retentionPolicyId: z.uuidv7(),
  targetSelectorDigest: digest,
  eligibilityDigest: digest,
  beforeDigest: digest,
  afterDigest: digest,
  attemptId: z.uuidv7(),
  operationId: z.uuidv7(),
  approvalRequestId: z.uuidv7(),
  revision: z.literal('1'),
  state: z.literal('SUCCEEDED'),
  deletedCount: z.literal('1'),
  deletedBytes: sequence,
  retainedAliasCount: z.literal('0'),
  beforeUsedBytes: sequence,
  afterUsedBytes: sequence,
  startedAtNs: sequence,
  completedAtNs: sequence,
});
type DeletionState = z.infer<typeof deletionState>;
export async function readDeletionBusinessState(client: PoolClient, context: MutationContext) {
  const rows = await client.query(
    `select retention_policy_id::text as "retentionPolicyId",target_selector_digest as "targetSelectorDigest",
     eligibility_digest as "eligibilityDigest",before_digest as "beforeDigest",after_digest as "afterDigest",
     attempt_id::text as "attemptId",operation_id::text as "operationId",approval_request_id::text as "approvalRequestId",
     revision::text,state,deleted_count::text as "deletedCount",deleted_bytes::text as "deletedBytes",
     retained_alias_count::text as "retainedAliasCount",
     before_used_bytes::text as "beforeUsedBytes",after_used_bytes::text as "afterUsedBytes",
     (floor(extract(epoch from started_at)*1000000)*1000)::text as "startedAtNs",
     (floor(extract(epoch from completed_at)*1000000)*1000)::text as "completedAtNs"
     from control.deletion_job where participant_id=$1 and privacy_domain_id=$2 and deletion_job_id=$3 for update`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.resourceId,
    ],
  );
  if (!rows.rowCount) return undefined;
  if (rows.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
  return deletionState.parse(rows.rows[0]);
}
export function bindDeletionTransition(
  context: MutationContext,
  operationId: string,
  before: DeletionState | undefined,
  after: DeletionState | undefined,
  profileVersion = 1,
) {
  const profile = businessTransitionProfileForOperation(context.catalogOperationId, profileVersion);
  if (
    !profile ||
    profile.aggregateType !== 'evidence-deletion' ||
    before ||
    !after ||
    after.operationId !== operationId ||
    after.approvalRequestId !== context.authorization.approvalRequestId ||
    BigInt(after.deletedBytes) < 1n ||
    BigInt(after.deletedBytes) >
      BigInt(
        context.catalogOperationId === 'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH'
          ? RUNTIME_ARTIFACT_MAX_BYTES
          : 2097152,
      ) ||
    BigInt(after.beforeUsedBytes) - BigInt(after.deletedBytes) !== BigInt(after.afterUsedBytes) ||
    BigInt(after.completedAtNs) < BigInt(after.startedAtNs)
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const binding = {
    profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    participantId: context.authorization.participantId,
    privacyDomainId: context.authorization.privacyDomainId,
    aggregateType: profile.aggregateType,
    aggregateId: context.resourceId,
  };
  const bind = (state: DeletionState | undefined) => {
    const uuid = (value: string) => Buffer.from(value.replaceAll('-', ''), 'hex');
    const hash = (value: string) => Buffer.from(value.slice(7), 'hex');
    const projection = state
      ? new Map<number, CborValue>([
          [0, uuid(state.retentionPolicyId)],
          [1, hash(state.targetSelectorDigest)],
          [2, hash(state.eligibilityDigest)],
          [3, hash(state.beforeDigest)],
          [4, hash(state.afterDigest)],
          [5, uuid(state.attemptId)],
          [6, uuid(state.operationId)],
          [7, uuid(state.approvalRequestId)],
          [8, BigInt(state.deletedCount)],
          [9, BigInt(state.deletedBytes)],
          [10, BigInt(state.retainedAliasCount)],
          [11, BigInt(state.startedAtNs)],
          [12, BigInt(state.completedAtNs)],
          [13, BigInt(state.beforeUsedBytes)],
          [14, BigInt(state.afterUsedBytes)],
        ])
      : new Map<number, CborValue>();
    const existence = state ? (1 as const) : (0 as const),
      revision = state ? 1n : 0n;
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
