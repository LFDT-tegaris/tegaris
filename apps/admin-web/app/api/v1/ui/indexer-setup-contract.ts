import { createHash } from 'node:crypto';
import { z } from 'zod';
import { configurationMutationOperation } from '../../../../../../packages/security-kernel/src/configuration-operations';
import {
  createIndexerProfileSchema,
  createProjectionPlanSchema,
  projectionRecoverySchema,
  updateRuntimeTargetSchema,
} from '../../../../../../services/control-api/src/configuration/resource-contracts';

export const indexerSetupKind = z.enum([
  'indexers',
  'projections',
  'projection-validation',
  'runtime-activation',
]);
export type IndexerSetupKind = z.infer<typeof indexerSetupKind>;
const definitions = {
  'runtime-activation': {
    operation: 'CFG-OP-UPDATE-RUNTIME-TARGET',
    evidence: 'UPDATE_RUNTIME_TARGETS',
    collection: 'runtime-targets',
    schema: updateRuntimeTargetSchema,
  },
  'indexers': {
    operation: 'CFG-OP-CREATE-INDEXER-PROFILE',
    evidence: 'CREATE_INDEXER_PROFILES',
    collection: 'indexer-profiles',
    schema: createIndexerProfileSchema,
  },
  'projections': {
    operation: 'CFG-OP-CREATE-PROJECTION-PLAN',
    evidence: 'CREATE_PROJECTION_PLANS',
    collection: 'projection-plans',
    schema: createProjectionPlanSchema,
  },
  'projection-validation': {
    operation: 'CFG-OP-RECOVER-PROJECTION-PLAN',
    evidence: 'RECOVER_PROJECTION_PLAN',
    collection: 'projection-plans',
    schema: projectionRecoverySchema,
  },
} as const;
export function indexerSetupAction(kind: IndexerSetupKind) {
  const definition = definitions[kind];
  const binding = configurationMutationOperation(definition.operation);
  // Existing ordinary actions only. Admission retains its independent checker flow.
  if (binding.makerCheckerRequired || binding.stepUpRequired)
    throw new Error('Governed admission cannot use ordinary setup');
  const digest =
    'sha256:' +
    createHash('sha256')
      .update(
        [
          binding.actionIntentId,
          binding.resourceType,
          binding.operationClass,
          'STANDARD',
          'false',
          'false',
          'true',
          'AUTHORIZED_ONLY',
          'REDACTED',
          definition.evidence,
        ].join('\0'),
      )
      .digest('hex');
  return { ...definition, id: binding.actionIntentId, digest };
}
export const indexerSetupPreview = z.strictObject({
  command: z.literal('PREVIEW_INDEXER'),
  kind: indexerSetupKind,
  requestKey: z.uuid(),
  fields: z.record(z.string(), z.unknown()),
  reason: z.string().trim().min(1).max(1024),
});
export function indexerSetupBody(
  kind: IndexerSetupKind,
  fields: Record<string, unknown>,
  reason: string,
  participantId: string,
) {
  if (
    ['participantId', 'actionIntentId', 'actionIntentDigest', 'reason', 'readiness'].some(
      (key) => key in fields,
    )
  )
    throw new Error('Setup metadata is server-owned');
  const action = indexerSetupAction(kind);
  return action.schema.parse({
    ...fields,
    actionIntentId: action.id,
    actionIntentDigest: action.digest,
    reason,
    ...(kind === 'indexers' ? { participantId: `urn:openpc:participant:${participantId}` } : {}),
    ...(kind === 'projections' ? { readiness: 'UNKNOWN' } : {}),
  });
}
