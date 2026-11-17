import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import {
  deploymentDefinitionDigests,
  deploymentPolicyDefinitionSchema,
  type DeploymentPolicyDefinition,
} from './policy-contract.js';
import { registerConfigurationRoutes } from '../http.js';
import { ConfigurationRepositoryError } from '../persistence/types.js';

const zero = `0x${'00'.repeat(32)}`;
const digest = `sha256:${'11'.repeat(32)}`;
const resourceId = '018f0000-0000-7000-8000-000000000301';

it('requires the exact named CREATE3 helper and its complete evidence profile', () => {
  const candidate = definition();
  candidate.route = {
    mechanism: 'CREATE3',
    runtimeBindingId: `urn:openpc:resource:${resourceId}`,
    canonicalSignature: 'deployCreate3(bytes32,bytes)',
    codeHash: `0x${'22'.repeat(32)}`,
    adapterDigest: digest,
    arguments: 'SALT_INIT_CODE',
    saltNamespaceDigest: digest,
    saltTransform: 'IDENTITY',
    helperProfile: 'SOLADY_CREATE3_V0_1_26',
  };
  expect(deploymentPolicyDefinitionSchema.safeParse(candidate).success).toBe(false);
  candidate.creationEvidence = 'COMPLETE_SOLADY_CREATE3_CALL_AND_OPCODE_V1';
  expect(deploymentPolicyDefinitionSchema.safeParse(candidate).success).toBe(true);
  expect(
    deploymentPolicyDefinitionSchema.safeParse({
      ...candidate,
      route: { ...candidate.route, helperProfile: 'caller-provided-helper' },
    }).success,
  ).toBe(false);
});

function definition(): DeploymentPolicyDefinition {
  return {
    schemaVersion: '1.0.0',
    profileId: 'reference:test',
    profileVersion: '1.0.0',
    assuranceLevel: 'A0',
    creationEvidence: 'COMPLETE_SINGLE_CREATION_CALL_AND_OPCODE_V1',
    chainId: '1',
    networkId: 'ethereum',
    genesisDigest: digest,
    abiArtifactId: `urn:openpc:resource:${resourceId}`,
    artifact: {
      mode: 'EXACT_INIT_CODE',
      initCode: '0x6001600c60003960016000f300',
      runtimeCodeHash: `0x${'22'.repeat(32)}`,
    },
    route: { mechanism: 'TRANSACTION_CREATE' },
    allowedSenders: [`0x${'33'.repeat(20)}`],
    requiredRoles: ['role:deployer'],
    approvalRequirement: 'MAKER_CHECKER',
    webauthnRequired: true,
    expiresAt: '2030-01-01T00:00:00.000Z',
    transactionPolicy: {
      version: 1,
      allowedTransactionTypes: [0, 1, 2],
      maximumValue: zero,
      maximumGasLimit: '1000000',
      maximumFeePerGas: `0x${'00'.repeat(31)}ff`,
      maximumPriorityFeePerGas: zero,
      maximumRawTransactionBytes: 131072,
      maximumCalldataBytes: 32768,
      maximumAccessListAddresses: 128,
      maximumAccessListStorageKeys: 1024,
    },
  };
}

describe('deployment publication input boundary', () => {
  it('binds the exact artifact and governance definition without asserting activation', () => {
    const original = definition();
    const result = deploymentDefinitionDigests(original);
    expect(result.initCodeHash).toMatch(/^0x[0-9a-f]{64}$/u);
    const changed = structuredClone(original);
    changed.allowedSenders = [`0x${'44'.repeat(20)}`];
    expect(deploymentDefinitionDigests(changed).definitionDigest).not.toBe(result.definitionDigest);
    expect(deploymentDefinitionDigests(changed).artifactDigest).toBe(result.artifactDigest);
    changed.artifact.initCode += '00';
    expect(deploymentDefinitionDigests(changed).artifactDigest).not.toBe(result.artifactDigest);
    expect(deploymentPolicyDefinitionSchema.safeParse({ ...original, ready: true }).success).toBe(
      false,
    );
    expect(
      deploymentPolicyDefinitionSchema.safeParse({ ...original, state: 'ACTIVE' }).success,
    ).toBe(false);
  });

  it('rejects incompatible assurance, source aliases, sets and chain quantities', () => {
    const original = definition();
    for (const patch of [
      { assuranceLevel: 'A2' },
      { chainId: '01' },
      { chainId: '0x1' },
      { chainId: '18446744073709551616' },
      { allowedSenders: [...original.allowedSenders, ...original.allowedSenders] },
      { requiredRoles: ['role:z', 'role:a'] },
      { abiArtifactId: `urn:openpc:participant:${resourceId}` },
      { artifact: { ...original.artifact, initCode: '0x' } },
      {
        artifact: {
          ...original.artifact,
          runtimeCodeHash: '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
        },
      },
    ])
      expect(deploymentPolicyDefinitionSchema.safeParse({ ...original, ...patch }).success).toBe(
        false,
      );
  });

  it('accepts a direct deployment ceiling without granting Native Value authority', () => {
    const original = definition();
    expect(
      deploymentPolicyDefinitionSchema.safeParse({
        ...original,
        transactionPolicy: { ...original.transactionPolicy, maximumValue: `0x${'01'.repeat(32)}` },
      }).success,
    ).toBe(true);
  });

  it('binds factory ABI shape and includes its encoding overhead in the budget', () => {
    const original = definition();
    const factory = {
      runtimeBindingId: `urn:openpc:resource:${resourceId}`,
      codeHash: `0x${'44'.repeat(32)}`,
      adapterDigest: digest,
    };
    const create = {
      ...original,
      route: { mechanism: 'CREATE', ...factory, canonicalSignature: 'deploy(bytes)' },
    };
    expect(deploymentPolicyDefinitionSchema.safeParse(create).success).toBe(true);
    for (const [argumentsKind, signature] of [
      ['INIT_CODE_SALT', 'deploy(bytes,bytes32)'],
      ['SALT_INIT_CODE', 'deploy(bytes32,bytes)'],
    ]) {
      const create2 = {
        ...original,
        route: {
          mechanism: 'CREATE2',
          ...factory,
          arguments: argumentsKind,
          canonicalSignature: signature,
          saltNamespaceDigest: digest,
          saltTransform: 'IDENTITY',
        },
      };
      expect(deploymentPolicyDefinitionSchema.safeParse(create2).success).toBe(true);
      expect(
        deploymentPolicyDefinitionSchema.safeParse({
          ...create2,
          transactionPolicy: { ...original.transactionPolicy, maximumCalldataBytes: 100 },
        }).success,
      ).toBe(false);
      expect(
        deploymentPolicyDefinitionSchema.safeParse({
          ...create2,
          route: { ...create2.route, canonicalSignature: 'deploy(bytes)' },
        }).success,
      ).toBe(false);
    }
  });

  it('selects the real maker/checker and step-up owner and rejects untrusted readiness before it', async () => {
    const app = Fastify();
    const authorize = vi.fn(async () => {
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    });
    registerConfigurationRoutes(app, { pool: {} as never, authorizer: { authorize } });
    const headers = {
      'cookie': '__Host-openpc_session=session',
      'x-request-id': resourceId,
      'x-correlation-id': resourceId,
      'openpc-api-version': '1',
      'openpc-participant-id': `urn:openpc:participant:${resourceId}`,
      'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${resourceId}`,
      'idempotency-key': 'deployment-policy-header-test',
      'x-csrf-token': 'a'.repeat(32),
      'origin': 'https://openpc.local',
      'openpc-action-intent-digest': digest,
    };
    const payload = {
      actionIntentId: 'ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1',
      actionIntentDigest: digest,
      reason: 'Publish exact deployment restrictions.',
      definition: definition(),
    };
    try {
      expect(
        (await app.inject({ method: 'POST', url: '/api/v1/deployment-policies', headers, payload }))
          .statusCode,
      ).toBe(403);
      expect(authorize).toHaveBeenCalledWith(
        expect.objectContaining({ makerCheckerRequired: true, stepUpRequired: true }),
      );
      authorize.mockClear();
      expect(
        (
          await app.inject({
            method: 'POST',
            url: '/api/v1/deployment-policies',
            headers,
            payload: { ...payload, definition: { ...payload.definition, approved: true } },
          })
        ).statusCode,
      ).toBe(400);
      expect(authorize).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  });
});
