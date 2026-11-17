import { z } from 'zod';
import { digestSchema, resourceUrnSchema } from '../resource-contracts.js';

const resource = resourceUrnSchema.refine((v) => v.startsWith('urn:openpc:resource:'));
const bytes = z.string().regex(/^0x(?:[0-9a-f]{2})+$/u);
const hash = z.string().regex(/^0x[0-9a-f]{64}$/u);
const address = z.string().regex(/^0x[0-9a-f]{40}$/u);
const decimal = z.string().regex(/^(0|[1-9][0-9]*)$/u);

/** Dedicated deployment preparation. Caller fields contain identity references
 * and the exact signing payload, never authority, approval or readiness claims. */
export const createDeploymentIntentSchema = z.strictObject({
  actionIntentId: z.literal('ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1'),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
  deploymentPolicyId: resource,
  runtimeTargetId: resource,
  walletBindingId: resource,
  nativeValueAuthorizationId: resource.optional(),
  // The authenticated human remains the maker. This selects an actual workload
  // that must independently authenticate and authorize any later submission.
  executionWorkloadId: z
    .string()
    .regex(
      /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    )
    .optional(),
  signingPayload: bytes.max(262_146),
});
export type CreateDeploymentIntent = z.infer<typeof createDeploymentIntentSchema>;

export const deploymentIntentResponseSchema = z.strictObject({
  deploymentIntentId: resource,
  deploymentPolicyId: resource,
  runtimeTargetId: resource,
  walletBindingId: resource,
  state: z.enum(['DRAFT', 'EXPIRED']),
  authority: z.literal('NONE'),
  revision: z.literal('1'),
  signingPayload: bytes.max(262_146),
  signingHash: hash,
  sender: address,
  chainId: decimal,
  nonce: decimal,
  gasLimit: decimal,
  transactionType: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  expectedContractAddress: address.nullable(),
  intentDigest: digestSchema,
  preparationDigest: digestSchema,
  // Opaque canonical UTF-8 JSON preserves the full integer range.
  // This is a non-authorizing intent artifact, not a signed execution grant.
  intentDocument: bytes.max(524_290),
  createdAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
});
