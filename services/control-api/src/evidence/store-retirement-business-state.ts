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

const hash = z.string().regex(/^[0-9a-f]{64}$/u);
const ordinal = z.string().regex(/^[1-9][0-9]*$/u);
const admissionState = z.strictObject({
  attemptId: z.uuidv7(),
  retirementId: z.uuidv7(),
  previousAttemptId: z.uuidv7().nullable(),
  hostDigest: hash,
  attemptDigest: hash,
  selectionDigest: hash,
  sourceBindingDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  retentionPolicyId: z.uuidv7(),
  approvalRequestId: z.uuidv7(),
  operationId: z.uuidv7(),
  lifecycleRevision: ordinal,
  dispatchNotAfterMs: ordinal,
  revision: z.literal('1'),
  admittedAtNs: ordinal,
});
type AdmissionState = z.infer<typeof admissionState>;

export async function readStoreRetirementAdmissionState(
  client: PoolClient,
  context: MutationContext,
) {
  const selected = await client.query(
    `select attempt_id::text as "attemptId",retirement_id::text as "retirementId",
    previous_attempt_id::text as "previousAttemptId",host_digest as "hostDigest",attempt_digest as "attemptDigest",
    selection_digest as "selectionDigest",source_binding_digest as "sourceBindingDigest",
    retention_policy_id::text as "retentionPolicyId",approval_request_id::text as "approvalRequestId",
    operation_id::text as "operationId",lifecycle_revision::text as "lifecycleRevision",dispatch_not_after_ms::text as "dispatchNotAfterMs",revision::text,
    (floor(extract(epoch from admitted_at)*1000000)*1000)::text as "admittedAtNs"
    from control.store_retirement_admission where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.resourceId,
    ],
  );
  if (selected.rowCount === 0) return undefined;
  if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
  return admissionState.parse(selected.rows[0]);
}

/** Admission signs only committed intent. It must never use the existing local
 * deletion SUCCEEDED profile or count a target effect before authenticated readback. */
export function bindStoreRetirementAdmission(
  context: MutationContext,
  operationId: string,
  before: AdmissionState | undefined,
  after: AdmissionState | undefined,
) {
  const profile = businessTransitionProfileForOperation(context.catalogOperationId);
  if (
    !profile ||
    profile.profileId !== 'pc.control.store-retirement.admit' ||
    before ||
    !after ||
    after.attemptId !== context.resourceId ||
    after.operationId !== operationId ||
    after.approvalRequestId !== context.authorization.approvalRequestId ||
    BigInt(after.lifecycleRevision) > 9223372036854775807n
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const binding = {
    profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    participantId: context.authorization.participantId,
    privacyDomainId: context.authorization.privacyDomainId,
    aggregateType: profile.aggregateType,
    aggregateId: context.resourceId,
  };
  const bind = (state: AdmissionState | undefined) => {
    const uuid = (value: string) => Buffer.from(value.replaceAll('-', ''), 'hex');
    const projection = state
      ? new Map<number, CborValue>([
          [0, Buffer.from(state.hostDigest, 'hex')],
          [1, Buffer.from(state.attemptDigest, 'hex')],
          [2, Buffer.from(state.selectionDigest, 'hex')],
          [3, Buffer.from(state.sourceBindingDigest.slice(7), 'hex')],
          [4, uuid(state.retentionPolicyId)],
          [5, uuid(state.approvalRequestId)],
          [6, uuid(state.operationId)],
          [7, uuid(state.retirementId)],
          [8, state.previousAttemptId ? uuid(state.previousAttemptId) : Buffer.alloc(0)],
          [9, BigInt(state.lifecycleRevision)],
          [10, BigInt(state.admittedAtNs)],
          [11, BigInt(state.dispatchNotAfterMs)],
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
