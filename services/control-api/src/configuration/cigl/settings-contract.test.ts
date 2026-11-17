import { expect, it } from 'vitest';
import { createCiglSettingsSchema } from './settings-contract.js';

const command = {
  actionIntentId: 'ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1',
  actionIntentDigest: `sha256:${'ab'.repeat(32)}`,
  reason: 'Review global interaction settings.',
  definition: {
    schemaVersion: '1.0',
    scope: { kind: 'ALL_CHAINS' },
    mode: 'HYBRID_STRICT',
    enforcement: {
      ethCall: true,
      ethEstimateGas: true,
      prepareWrite: true,
      rawSubmission: true,
      deploymentConstructors: true,
      runtimeTraceForWrites: true,
      reviewedSchemaSubset: true,
      failClosed: true,
      rejectExternalStateOverrides: true,
    },
    traceLimits: {
      maxDepth: 128,
      maxFrames: 2048,
      maxResponseBytes: 20_000_000,
      timeoutMs: 30_000,
    },
    traceProvider: 'DEBUG_TRACE_CALL',
    readinessScope: 'METHOD',
    schemaFallbackEnabled: false,
    precompileAllowlist: [],
    systemContractAllowlist: [],
    postMine: { enabled: false, freezeOnDivergence: false },
  },
};
it('keeps public settings closed and prevents callers supplying readiness or actor claims', () => {
  expect(createCiglSettingsSchema.safeParse(command).success).toBe(true);
  for (const field of ['participantId', 'actorPrincipalId', 'active', 'ready', 'analysisDigest']) {
    expect(createCiglSettingsSchema.safeParse({ ...command, [field]: true }).success).toBe(false);
    expect(
      createCiglSettingsSchema.safeParse({
        ...command,
        definition: { ...command.definition, [field]: true },
      }).success,
    ).toBe(false);
  }
  for (const mode of ['SCHEMA_ONLY', 'TRACE_REQUIRED', 'TRACE_PREFERRED_SCHEMA_FALLBACK']) {
    expect(
      createCiglSettingsSchema.safeParse({
        ...command,
        definition: { ...command.definition, mode },
      }).success,
    ).toBe(false);
  }
  expect(
    createCiglSettingsSchema.safeParse({
      ...command,
      definition: {
        ...command.definition,
        traceLimits: { ...command.definition.traceLimits, maxFrames: 2049 },
      },
    }).success,
  ).toBe(false);
  expect(
    createCiglSettingsSchema.safeParse({
      ...command,
      definition: { ...command.definition, precompileAllowlist: ['0x01'] },
    }).success,
  ).toBe(false);
});
