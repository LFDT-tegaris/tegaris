import { z } from 'zod';
import type { EvidenceProvenance } from '../../../services/control-api/src/evidence/provenance-contracts';
import { operationResponseSchema } from '../../../services/control-api/src/configuration/resource-contracts';

// REQ-SR01-PROVENANCE-SR01-PQ-000273 / 000289 / 000376.
// A reference is navigation input, never permission to read its target.
export const evidenceOperationEndpoint = '/api/v1/ui/evidence-operation-correlation';
const id = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const resource = z
  .string()
  .regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u)
  .refine((value) => id.safeParse(value.slice('urn:openpc:resource:'.length)).success);
export const evidenceOperationQuery = z.strictObject({ evidenceId: resource, actorKey: digest });
export const correlatedOperation = operationResponseSchema
  .pick({
    operationId: true,
    resourceRef: true,
    actionIntentId: true,
    state: true,
    truthState: true,
    revision: true,
    createdAt: true,
    updatedAt: true,
  })
  .extend({ resourceRef: resource })
  .strict();
export const evidenceOperationView = evidenceOperationQuery
  .extend({
    receiptId: id,
    recordDigest: digest,
    recordedAt: operationResponseSchema.shape.createdAt,
    historicalRevision: operationResponseSchema.shape.revision,
    operation: correlatedOperation,
  })
  .strict();
export type EvidenceOperationView = z.infer<typeof evidenceOperationView>;

/** Provenance must already pass its server-only schema and authorized owner.
 * Both responses must come from independently authorized public owners. No
 * authority or effect conclusion is derived from this identity-only join. */
export function projectEvidenceOperation(
  query: z.infer<typeof evidenceOperationQuery>,
  provenance: EvidenceProvenance,
  operationInput: unknown,
): EvidenceOperationView {
  const operation = operationResponseSchema.parse(operationInput);
  const business = provenance.business;
  if (
    provenance.evidenceId !== query.evidenceId ||
    provenance.status !== 'VERIFIED_BUSINESS_TRANSITION' ||
    !business ||
    business.operationId !== `urn:openpc:operation:${operation.operationId}` ||
    business.actionIntentId !== operation.actionIntentId ||
    operation.resourceRef !== `urn:openpc:resource:${business.aggregateId}`
  ) {
    throw new Error('Evidence operation binding unavailable');
  }
  const {
    operationId,
    resourceRef,
    actionIntentId,
    state,
    truthState,
    revision,
    createdAt,
    updatedAt,
  } = operation;
  return evidenceOperationView.parse({
    ...query,
    receiptId: business.receiptId,
    recordDigest: provenance.recordDigest,
    recordedAt: business.recordedAt,
    historicalRevision: business.after.revision,
    operation: {
      operationId,
      resourceRef,
      actionIntentId,
      state,
      truthState,
      revision,
      createdAt,
      updatedAt,
    },
  });
}
