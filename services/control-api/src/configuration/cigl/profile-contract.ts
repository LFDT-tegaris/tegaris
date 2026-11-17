import { z } from 'zod';
import { digestSchema, resourceUrnSchema } from '../resource-contracts.js';

const rawDigest = z.string().regex(/^[0-9a-f]{64}$/u);
export const ciglDependencyPathSchema = z.strictObject({
  ordinal: z.number().int().min(1).max(2048),
  actionDigest: rawDigest,
  contractMethodPolicyId: z.uuidv7(),
  runtimeBindingId: z.uuidv7(),
  selector: z.array(z.number().int().min(0).max(255)).length(4),
  relationshipPath: z.array(z.number().int().min(1).max(2048)).min(1).max(128),
  closureDigest: rawDigest,
});

export const verifiedCiglProfileSchema = z.strictObject({
  identity: z.literal('PC-CIGL-PROFILE-COMPILATION-1'),
  runtimePermission: z.literal('NONE'),
  profileDigest: digestSchema,
  artifactDigest: digestSchema,
  receiptDigest: digestSchema,
  methodCount: z.number().int().min(1).max(2049),
  grantCount: z.number().int().min(0).max(4096),
  dependencyPaths: z.array(ciglDependencyPathSchema).max(2048).nullable(),
});
export const ciglPublicationSourcesSchema = z.strictObject({
  targetRuntimeId: resourceUrnSchema,
  targetRevision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  installedCapsuleDigest: digestSchema,
  participantEpoch: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  grantSourcesDigest: digestSchema,
});
export const ciglProfileReadbackSchema = z.strictObject({
  profileId: resourceUrnSchema,
  revision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  state: z.enum(['PENDING', 'RUNNING', 'COMPILED', 'FAILED']),
  runtimePermission: z.literal('NONE'),
  compiledAt: z.iso.datetime().nullable(),
  result: verifiedCiglProfileSchema.nullable(),
  // A pin for an exact approval request, not activation or readiness evidence.
  currentSources: ciglPublicationSourcesSchema.nullable(),
});
