import Fastify from 'fastify';
import { expect, it, vi } from 'vitest';
import { registerConfigurationRoutes } from './http.js';
import { ContractAssetRepository } from './repositories/contract-assets.js';
import { ConfigurationRepositoryError } from './persistence/types.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const paths = [
  ['abi-artifacts', 'abi-artifact', 'ACT-ABI_ARTIFACTS_READ_RESOURCE-V1', 'listAbiArtifacts'],
  [
    'logical-contract-assets',
    'logical-contract-asset',
    'ACT-LOGICAL_CONTRACT_ASSETS_READ_RESOURCE-V1',
    'listLogicalContracts',
  ],
  [
    'contract-runtime-bindings',
    'contract-runtime-binding',
    'ACT-CONTRACT_RUNTIME_BINDINGS_READ_RESOURCE-V1',
    'listRuntimeBindings',
  ],
  [
    'contract-method-policies',
    'contract-method-policy',
    'ACT-CONTRACT_METHOD_POLICIES_READ_RESOURCE-V1',
    'listContractMethodPolicies',
  ],
] as const;
const headers = {
  'cookie': '__Host-openpc_session=opaque-session',
  'x-request-id': participantId,
  'x-correlation-id': participantId,
  'openpc-api-version': '1',
  'openpc-participant-id': `urn:openpc:participant:${participantId}`,
  'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
};

it.each(paths)(
  'requires native complete-resource authority for %s',
  async (path, resourceType, action, method) => {
    const app = Fastify();
    const authorize = vi.fn().mockResolvedValue({ participantId, privacyDomainId });
    const read = vi
      .spyOn(ContractAssetRepository.prototype, method)
      .mockResolvedValue({ items: [], total: '0', snapshotRevision: '1' } as never);
    registerConfigurationRoutes(app, { pool: {} as never, authorizer: { authorize } });
    try {
      const response = await app.inject({
        method: 'GET',
        url: `/api/v1/${path}?limit=25`,
        headers,
      });
      expect(response.statusCode).toBe(200);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.json()).toMatchObject({
        items: [],
        total: '0',
        completeness: 'COMPLETE',
        authorizedEmpty: true,
      });
      expect(authorize).toHaveBeenCalledWith(
        expect.objectContaining({
          resourceId: '*',
          actionIntentId: action,
          participantId,
          privacyDomainId,
          makerCheckerRequired: false,
          stepUpRequired: false,
        }),
      );
      expect(read).toHaveBeenCalledWith(
        expect.objectContaining({ resourceId: '*', resourceType, actionIntentId: action }),
        expect.objectContaining({ limit: 25 }),
      );
      expect(read.mock.calls[0]![1]).not.toHaveProperty('visibility');
    } finally {
      read.mockRestore();
      await app.close();
    }
  },
);
it.each(['anonymous', 'denied', 'foreign-participant', 'foreign-domain', 'bad-query'] as const)(
  'prevents catalogue persistence reads for %s',
  async (scenario) => {
    const app = Fastify();
    const authorize = vi.fn(async () => {
      if (scenario === 'denied') throw new ConfigurationRepositoryError('PC-AUTH-0005');
      return {
        participantId: scenario === 'foreign-participant' ? privacyDomainId : participantId,
        privacyDomainId: scenario === 'foreign-domain' ? participantId : privacyDomainId,
      } as never;
    });
    const read = vi.spyOn(ContractAssetRepository.prototype, 'listLogicalContracts');
    registerConfigurationRoutes(app, { pool: {} as never, authorizer: { authorize } });
    try {
      const response = await app.inject({
        method: 'GET',
        url:
          '/api/v1/logical-contract-assets' +
          (scenario === 'bad-query' ? '?filter=secret:eq:x' : ''),
        headers: scenario === 'anonymous' ? { ...headers, cookie: '' } : headers,
      });
      expect(response.statusCode).toBe(
        scenario === 'anonymous' ? 401 : scenario === 'bad-query' ? 400 : 403,
      );
      expect(read).not.toHaveBeenCalled();
    } finally {
      read.mockRestore();
      await app.close();
    }
  },
);
it.each(paths)(
  'guards finite read proofs at repository entry for %s',
  (_path, resourceType, action, method) => {
    const pool = { connect: vi.fn() };
    const repository = new ContractAssetRepository(pool as never);
    expect(() =>
      repository[method](
        {
          resourceId: participantId,
          resourceType,
          actionIntentId: action,
          authorization: {} as never,
        },
        {} as never,
      ),
    ).toThrow('PC-AUTH-0005');
    expect(pool.connect).not.toHaveBeenCalled();
  },
);
