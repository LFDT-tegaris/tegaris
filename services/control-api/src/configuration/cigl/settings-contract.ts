import { z } from 'zod';
import { digestSchema, resourceUrnSchema } from '../resource-contracts.js';

/** Public shape; the shared Rust owner validates the configuration semantics
 * and returns the canonical definition/digest used by publication and runtime. */
export const ciglSettingsDefinitionSchema = z.strictObject({
  schemaVersion: z.literal('1.0'),
  scope: z.discriminatedUnion('kind', [
    z.strictObject({ kind: z.literal('ALL_CHAINS') }),
    z.strictObject({
      kind: z.literal('CHAIN'),
      chainId: z.string().max(20),
      networkId: z.string().min(1).max(192),
      genesisDigest: digestSchema,
    }),
  ]),
  mode: z.enum(['HYBRID_STRICT', 'OFF']),
  enforcement: z.strictObject({
    ethCall: z.boolean(),
    ethEstimateGas: z.boolean(),
    prepareWrite: z.boolean(),
    rawSubmission: z.boolean(),
    deploymentConstructors: z.boolean(),
    runtimeTraceForWrites: z.boolean(),
    reviewedSchemaSubset: z.boolean(),
    failClosed: z.boolean(),
    rejectExternalStateOverrides: z.boolean(),
  }),
  traceLimits: z.strictObject({
    maxDepth: z.number().int().min(1).max(128),
    maxFrames: z.number().int().min(1).max(2048),
    maxResponseBytes: z.number().int().min(100_000).max(20_000_000),
    timeoutMs: z.number().int().min(500).max(30_000),
  }),
  traceProvider: z.enum(['DEBUG_TRACE_CALL', 'TRACE_CALL']),
  readinessScope: z.enum(['METHOD', 'CONTRACT']),
  schemaFallbackEnabled: z.boolean(),
  precompileAllowlist: z.array(z.string().regex(/^0x[0-9a-f]{40}$/u)).max(256),
  systemContractAllowlist: z.array(z.string().regex(/^0x[0-9a-f]{40}$/u)).max(256),
  postMine: z.strictObject({ enabled: z.boolean(), freezeOnDivergence: z.boolean() }),
});
export type CiglSettingsDefinition = z.infer<typeof ciglSettingsDefinitionSchema>;

export const createCiglSettingsSchema = z.strictObject({
  actionIntentId: z.literal('ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1'),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
  definition: ciglSettingsDefinitionSchema,
});

export const ciglSettingsArtifactFields = {
  configurationArtifactCbor: z
    .string()
    .regex(/^0x(?:[0-9a-f]{2})+$/u)
    .max(131_074),
  configurationArtifactDigest: digestSchema,
};
export const ciglSettingsResponseSchema = z.strictObject({
  ...ciglSettingsArtifactFields,
  ciglSettingsId: resourceUrnSchema,
  definition: ciglSettingsDefinitionSchema,
  definitionDigest: digestSchema,
  publicationOperationId: z.uuid(),
  publicationAuthorityDigest: digestSchema,
  revision: z.literal('1'),
  state: z.literal('STAGED'),
  runtimePermission: z.literal('NONE'),
  createdAt: z.iso.datetime(),
});
