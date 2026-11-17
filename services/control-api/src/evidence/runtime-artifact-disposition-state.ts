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
const state = z.strictObject({
  dispositionId: z.uuidv7(),
  sourceOwnerId: z.uuidv7(),
  inputId: z.uuidv7(),
  configurationDigest: hash,
  selectionDigest: hash,
  approvalRequestId: z.uuidv7(),
  operationId: z.uuidv7(),
  admittedAtNs: z.string().regex(/^[1-9][0-9]*$/u),
  revision: z.literal('1'),
});
type State = z.infer<typeof state>;

export async function readRuntimeArtifactDispositionState(
  client: PoolClient,
  context: MutationContext,
) {
  const selected = await client.query(
    `select disposition_id::text as "dispositionId",source_owner_id::text as "sourceOwnerId",
     runtime_configuration_input_id::text as "inputId",encode(configuration_digest,'hex') as "configurationDigest",
     encode(selection_digest,'hex') as "selectionDigest",approval_request_id::text as "approvalRequestId",
     operation_id::text as "operationId",revision::text,
     (floor(extract(epoch from admitted_at)*1000000)*1000)::text as "admittedAtNs"
     from control.runtime_artifact_source_disposition where participant_id=$1 and privacy_domain_id=$2 and disposition_id=$3`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.resourceId,
    ],
  );
  if (selected.rowCount === 0) return undefined;
  if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
  return state.parse(selected.rows[0]);
}

export function bindRuntimeArtifactDisposition(
  context: MutationContext,
  operationId: string,
  before: State | undefined,
  after: State | undefined,
) {
  const profile = businessTransitionProfileForOperation(context.catalogOperationId);
  if (
    !profile ||
    profile.profileId !== 'pc.control.runtime-artifact.disposition' ||
    before ||
    !after ||
    after.dispositionId !== context.resourceId ||
    after.operationId !== operationId ||
    after.approvalRequestId !== context.authorization.approvalRequestId
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  after = state.parse(after);
  const binding = {
    profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    participantId: context.authorization.participantId,
    privacyDomainId: context.authorization.privacyDomainId,
    aggregateType: profile.aggregateType,
    aggregateId: context.resourceId,
  };
  const bind = (value: State | undefined) => {
    const uuid = (id: string) => Buffer.from(id.replaceAll('-', ''), 'hex');
    const projection = value
      ? new Map<number, CborValue>([
          [0, uuid(value.sourceOwnerId)],
          [1, uuid(value.inputId)],
          [2, Buffer.from(value.configurationDigest, 'hex')],
          [3, Buffer.from(value.selectionDigest, 'hex')],
          [4, uuid(value.approvalRequestId)],
          [5, uuid(value.operationId)],
          [6, BigInt(value.admittedAtNs)],
        ])
      : new Map<number, CborValue>();
    const existence = value ? (1 as const) : (0 as const),
      revision = value ? 1n : 0n;
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
