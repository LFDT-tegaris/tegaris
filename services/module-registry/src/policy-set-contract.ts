import { z } from 'zod';
import {
  digestSchema,
  resourceUrnSchema,
} from '../../control-api/src/configuration/resource-contracts.js';

// A create command may describe a draft, never claim an active version. The
// nullable canonical field remains explicit; the activation owner owns changes.
export const createPolicySetSchema = z.strictObject({
  participantId: z
    .string()
    .regex(/^urn:openpc:participant:/u)
    .pipe(resourceUrnSchema),
  name: z
    .string()
    .min(1)
    .max(160)
    .refine((name) => name.trim().length > 0),
  activeVersionDigest: digestSchema.nullable(),
  actionIntentId: z.literal('ACT-POLICY_SETS_CREATE_RESOURCE-V1'),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
});

export const policySetResponseSchema = z.strictObject({
  policySetId: resourceUrnSchema,
  participantId: resourceUrnSchema,
  name: z.string().min(1).max(160),
  state: z.enum(['DRAFT', 'ACTIVE', 'RETIRED']),
  activeVersionDigest: digestSchema.nullable(),
  revision: z.string().regex(/^[1-9][0-9]*$/u),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

export type PolicySetView = z.infer<typeof policySetResponseSchema>;
