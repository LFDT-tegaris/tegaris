import { z } from 'zod';

const document = z.record(z.string(), z.unknown());
const result = z.strictObject({
  resultDigest: z.string().regex(/^[0-9a-f]{64}$/u),
  sequence: z.string().regex(/^[1-9][0-9]*$/u),
  observedAt: z.string(),
  status: z.strictObject({
    operationId: z.string(),
    signedTransactionHash: z.string(),
    attemptId: z.string(),
    evidenceDigest: z.string(),
    state: z.string(),
    truthState: z.string(),
  }),
  outcome: z.strictObject({
    attempt: document.nullable(),
    occurrence: document.nullable(),
    invalidation: document.nullable(),
  }),
  association: document.nullable(),
});
export const deploymentProjectionReadbackSchema = result.extend({
  identity: z.literal('PC-DEPLOYMENT-JOURNAL-PROJECTION-1'),
  authority: z.literal('OBSERVATION_ONLY'),
});
export const deploymentRejectionReadbackSchema = result.extend({
  identity: z.literal('PC-DEPLOYMENT-RESERVATION-REJECTION-1'),
  authority: z.literal('NONE'),
});
