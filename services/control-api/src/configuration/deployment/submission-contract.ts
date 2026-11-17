import { z } from 'zod';
import { digestSchema, resourceUrnSchema } from '../resource-contracts.js';

/** A fresh governed command over exact signed bytes. Preparation approval is
 * not reused as execution approval, and callers cannot provide custody claims. */
export const createDeploymentSubmissionSchema = z.strictObject({
  actionIntentId: z.literal('ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
  deploymentIntentId: resourceUrnSchema.refine((v) => v.startsWith('urn:openpc:resource:')),
  predecessorOperationId: resourceUrnSchema
    .refine((v) => v.startsWith('urn:openpc:operation:'))
    .optional(),
  signedTransaction: z
    .string()
    .regex(/^0x(?:[0-9a-f]{2})+$/u)
    .max(262_146),
});

export type CreateDeploymentSubmission = z.infer<typeof createDeploymentSubmissionSchema>;

const evidenceDocument = z.record(z.string(), z.unknown()).nullable();
/** Documents are validated by the shared signed projection owner before this
 * filtered management representation can be released. No raw trace or key. */
export const deploymentSubmissionResponseSchema = z.strictObject({
  deploymentSubmissionId: resourceUrnSchema,
  operationId: z.string().startsWith('urn:openpc:operation:'),
  state: z.enum(['ACCEPTED', 'WRITE_AMBIGUITY', 'SUCCEEDED', 'FAILED', 'REORG']),
  truthState: z.enum(['UNKNOWN', 'WRITE_AMBIGUITY', 'SUCCESS', 'FAILED', 'REORG', 'UNAVAILABLE']),
  revision: z.string().regex(/^(0|[1-9][0-9]*)$/u),
  runtimePermission: z.literal('NONE'),
  attempt: evidenceDocument,
  occurrence: evidenceDocument,
  invalidation: evidenceDocument,
  association: evidenceDocument,
  associationCurrent: z.boolean(),
});
