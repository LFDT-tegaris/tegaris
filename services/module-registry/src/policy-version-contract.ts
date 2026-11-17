import { z } from 'zod';
import {
  digestSchema,
  semanticVersionSchema,
} from '../../control-api/src/configuration/resource-contracts.js';

export const policyVersionRefSchema = z
  .string()
  .regex(
    /^urn:openpc:policy-version:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
export const policySetRefSchema = z
  .string()
  .regex(
    /^urn:openpc:policy-set:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
export const policyVersionResponseSchema = z.strictObject({
  policyVersionId: policyVersionRefSchema,
  policySetId: policySetRefSchema,
  semanticVersion: semanticVersionSchema,
  normalizedPolicyDigest: digestSchema,
  dependencyClosureDigest: digestSchema,
  state: z.enum(['DRAFT', 'VALIDATED', 'APPROVED', 'PUBLISHED', 'ACTIVE', 'SUPERSEDED', 'RETIRED']),
  revision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  createdAt: z.iso.datetime({ precision: 6 }),
  updatedAt: z.iso.datetime({ precision: 6 }),
});
export type PolicyVersionView = z.infer<typeof policyVersionResponseSchema>;
