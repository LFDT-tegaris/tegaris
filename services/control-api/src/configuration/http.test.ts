import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { registerConfigurationRoutes } from './http.js';
import { ConfigurationRepositoryError } from './persistence/types.js';
import { resourceRead } from './resource-http.js';
import { registerEvidenceRoutes } from '../evidence/http.js';
import { RuntimeArtifactDispositionRepository } from '../evidence/runtime-artifact-disposition-repository.js';
import * as mutationCandidates from './persistence/mutation-candidate.js';
import { IndexingRepository } from './repositories/indexing.js';
import { ContractAssetRepository } from './repositories/contract-assets.js';
import { sha256 } from './digest.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const resourceId = '018f0000-0000-7000-8000-000000000301';
const digest = `sha256:${'1'.repeat(64)}`;

describe('typed configuration HTTP boundary', () => {
  it.each(['valid', 'unknown-field', 'wrong-action', 'foreign', 'denied', 'anonymous'] as const)(
    'typed argument proposal preserves review without executing the rule: %s',
    async (scenario) => {
      const app = Fastify();
      const propose = vi.fn(async () => {
        if (scenario === 'denied') throw new ConfigurationRepositoryError('PC-AUTH-0005');
        return {
          participantId:
            scenario === 'foreign' ? '018f0000-0000-7000-8000-000000000999' : participantId,
          privacyDomainId,
        } as never;
      });
      // Even a ready execution authorizer must never be reached by proposal-only ingress.
      const authorize = vi.fn(async () => ({ participantId, privacyDomainId }) as never);
      const stage = vi
        .spyOn(mutationCandidates, 'stageMutationCandidate')
        .mockResolvedValue(resourceId);
      const execute = vi.spyOn(ContractAssetRepository.prototype, 'createArgumentRuleVersion');
      const candidate = {
        actionIntentId:
          scenario === 'wrong-action'
            ? 'ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1'
            : 'ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1',
        actionIntentDigest: digest,
        runtimeBindingId: `urn:openpc:resource:${resourceId}`,
        abiArtifactId: `urn:openpc:resource:${participantId}`,
        abiDigest: digest,
        canonicalSignature: 'balanceOf(address)',
        version: '1.0.0',
        namedSetVersions: [],
        rules: [
          {
            parameterPath: 'inputs[0]',
            operandType: 'ADDRESS',
            operator: 'EQ',
            values: ['0x' + '11'.repeat(20)],
          },
        ],
        reason: 'Review the exact allowed account.',
        ...(scenario === 'unknown-field' ? { privateKey: 'must-not-be-disclosed' } : {}),
      };
      registerConfigurationRoutes(app, { pool: {} as never, authorizer: { propose, authorize } });
      try {
        const response = await app.inject({
          method: 'POST',
          url: '/api/v1/typed-argument-rule-versions/proposals',
          headers: {
            ...(scenario === 'anonymous' ? {} : { cookie: '__Host-openpc_session=session' }),
            'x-request-id': resourceId,
            'x-correlation-id': resourceId,
            'openpc-api-version': '1',
            'openpc-participant-id': `urn:openpc:participant:${participantId}`,
            'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
            'x-openpc-action-intent-digest': digest,
            'idempotency-key': 'typed-argument-proposal-0001',
            'x-csrf-token': 'a'.repeat(32),
            'origin': 'https://openpc.local',
          },
          payload: candidate,
        });
        expect(response.statusCode).toBe(
          {
            'valid': 200,
            'unknown-field': 400,
            'wrong-action': 400,
            'foreign': 403,
            'denied': 403,
            'anonymous': 401,
          }[scenario],
        );
        if (scenario === 'valid') {
          expect(response.json()).toMatchObject({
            resourceRef: `urn:openpc:resource:${resourceId}`,
            candidateDigest: sha256(candidate),
            actionIntentId: candidate.actionIntentId,
            runtimePermission: 'NONE',
          });
          expect(stage).toHaveBeenCalledTimes(1);
          expect(stage.mock.calls[0]?.[1]).toMatchObject({
            participantId,
            privacyDomainId,
            catalogOperationId: 'CFG-OP-CREATE-ARGUMENT-RULES',
            candidate,
          });
        } else expect(stage).not.toHaveBeenCalled();
        expect(authorize).not.toHaveBeenCalled();
        expect(execute).not.toHaveBeenCalled();
      } finally {
        await app.close();
        vi.restoreAllMocks();
      }
    },
  );

  it.each(['proposal', 'foreign', 'denied', 'revision', 'target', 'anonymous'] as const)(
    'indexer admission proposal preserves approval and execution separation: %s',
    async (scenario) => {
      const app = Fastify();
      const propose = vi.fn(async () => {
        if (scenario === 'denied') throw new ConfigurationRepositoryError('PC-AUTH-0005');
        return {
          participantId:
            scenario === 'foreign' ? '018f0000-0000-7000-8000-000000000999' : participantId,
          privacyDomainId,
        } as never;
      });
      const authorize = vi.fn();
      const stage = vi
        .spyOn(mutationCandidates, 'stageMutationCandidate')
        .mockResolvedValue(resourceId);
      const admit = vi.spyOn(IndexingRepository.prototype, 'admitIndexer');
      registerConfigurationRoutes(app, { pool: {} as never, authorizer: { propose, authorize } });
      try {
        const response = await app.inject({
          method: 'POST',
          url: `/api/v1/indexer-profiles/urn:openpc:resource:${resourceId}/admit/proposals`,
          headers: {
            ...(scenario === 'anonymous' ? {} : { cookie: '__Host-openpc_session=session' }),
            'x-request-id': resourceId,
            'x-correlation-id': resourceId,
            'openpc-api-version': '1',
            'openpc-participant-id': `urn:openpc:participant:${participantId}`,
            'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
            'x-openpc-action-intent-digest': digest,
            'idempotency-key': 'indexer-admission-proposal-0001',
            'x-csrf-token': 'a'.repeat(32),
            'origin': 'https://openpc.local',
            ...(scenario === 'revision'
              ? {}
              : { 'if-match': `"${sha256({ resourceId, revision: '1' })}"` }),
          },
          payload: {
            actionIntentId: 'ACT-INDEXER_APPROVE_PROFILE-V1',
            actionIntentDigest: digest,
            targetRef: `urn:openpc:resource:${scenario === 'target' ? participantId : resourceId}`,
            expectedRevision: '1',
            inputDigest: digest,
            reason: 'Review the reader before native admission.',
          },
        });
        expect(response.statusCode).toBe(
          { proposal: 200, foreign: 403, denied: 403, revision: 428, target: 400, anonymous: 401 }[
            scenario
          ],
        );
        expect(authorize).not.toHaveBeenCalled();
        expect(admit).not.toHaveBeenCalled();
        if (scenario === 'proposal') {
          expect(response.headers['cache-control']).toBe('no-store');
          expect(response.json()).toMatchObject({
            resourceRef: `urn:openpc:resource:${resourceId}`,
            actionIntentId: 'ACT-INDEXER_APPROVE_PROFILE-V1',
            expectedRevision: '1',
            runtimePermission: 'NONE',
          });
          expect(propose).toHaveBeenCalledWith(
            expect.objectContaining({
              resourceId,
              participantId,
              privacyDomainId,
              catalogOperationId: 'CFG-OP-ADMIT-INDEXER-PROFILE',
              makerCheckerRequired: true,
              stepUpRequired: true,
            }),
          );
          expect(stage).toHaveBeenCalledOnce();
        } else expect(stage).not.toHaveBeenCalled();
      } finally {
        stage.mockRestore();
        admit.mockRestore();
        await app.close();
      }
    },
  );
  it.each(['plan', 'query', 'denied'] as const)(
    'preserves scalar source plan and its scoped authority: %s',
    async (scenario) => {
      const app = Fastify();
      const authorize = vi.fn(async () => {
        if (scenario === 'denied') throw new ConfigurationRepositoryError('PC-AUTH-0005');
        return { participantId, privacyDomainId } as never;
      });
      const plan = {
        selection: null,
        blockers: ['SELECTED_INPUT'],
        nativeCustody: 'REQUIRED_AFTER_COMMITTED_ADMISSION',
        authority: 'NONE',
      } as const;
      const fetch = vi
        .spyOn(RuntimeArtifactDispositionRepository.prototype, 'plan')
        .mockResolvedValue(plan as never);
      registerEvidenceRoutes(app, { pool: {} as never, authorizer: { authorize } });
      try {
        const response = await app.inject({
          method: 'POST',
          url:
            '/api/v1/evidence-deletions/runtime-sources/plan' +
            (scenario === 'query' ? '?limit=1' : ''),
          headers: {
            'cookie': '__Host-openpc_session=session',
            'x-request-id': resourceId,
            'x-correlation-id': resourceId,
            'openpc-api-version': '1',
            'openpc-participant-id': `urn:openpc:participant:${participantId}`,
            'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
          },
          payload: {
            runtimeConfigurationInputId: `urn:openpc:resource:${resourceId}`,
            retentionPolicyId: `urn:openpc:resource:${resourceId}`,
          },
        });
        expect(response.statusCode).toBe({ plan: 200, query: 400, denied: 403 }[scenario]);
        expect(response.headers['cache-control']).toBe('no-store');
        if (scenario === 'plan') {
          expect(response.json()).toEqual(plan);
          expect(authorize).toHaveBeenCalledWith(
            expect.objectContaining({
              resourceId: '*',
              actionIntentId: 'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1',
              privacyDomainId,
            }),
          );
          expect(fetch).toHaveBeenCalledOnce();
        } else expect(fetch).not.toHaveBeenCalled();
      } finally {
        fetch.mockRestore();
        await app.close();
      }
    },
  );
  it.each(['success', 'anonymous', 'malformed', 'denied', 'unavailable'] as const)(
    'prevents caching of an authority-bound resource read: %s',
    async (scenario) => {
      const app = Fastify();
      const authorize = vi.fn(async () => {
        if (scenario === 'denied') throw new ConfigurationRepositoryError('PC-AUTH-0005');
        return { participantId, privacyDomainId } as never;
      });
      app.get(
        '/read/:id',
        resourceRead(
          { pool: {} as never, authorizer: { authorize } },
          'evidence-deletions',
          'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
          async () => {
            if (scenario === 'unavailable')
              throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
            return { revision: '1' };
          },
          z.strictObject({ revision: z.string() }),
        ),
      );
      try {
        const response = await app.inject({
          method: 'GET',
          url: `/read/urn:openpc:resource:${resourceId}`,
          headers: {
            ...(scenario === 'anonymous' ? {} : { cookie: '__Host-openpc_session=session' }),
            'x-request-id': resourceId,
            'x-correlation-id': resourceId,
            'openpc-api-version': '1',
            'openpc-participant-id':
              scenario === 'malformed' ? 'bad' : `urn:openpc:participant:${participantId}`,
            'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
          },
        });
        expect(response.statusCode).toBe(
          { success: 200, anonymous: 401, malformed: 400, denied: 403, unavailable: 503 }[scenario],
        );
        expect(response.headers['cache-control']).toBe('no-store');
        if (scenario !== 'success') expect(response.json()).not.toHaveProperty('revision');
      } finally {
        await app.close();
      }
    },
  );
  it.each(['canonical', 'legacy', 'conflicting'])(
    'binds the %s action digest header before authority lookup',
    async (mode) => {
      const app = Fastify();
      const authorize = vi.fn(async () => {
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      });
      registerConfigurationRoutes(app, { pool: {} as never, authorizer: { authorize } });
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/provider-profiles',
        headers: {
          'cookie': '__Host-openpc_session=session',
          'x-request-id': resourceId,
          'x-correlation-id': resourceId,
          'openpc-api-version': '1',
          'openpc-participant-id': `urn:openpc:participant:${participantId}`,
          'idempotency-key': 'provider-header-binding-0001',
          'x-csrf-token': 'a'.repeat(32),
          'origin': 'https://openpc.local',
          ...(mode === 'legacy'
            ? { 'openpc-action-intent-digest': digest }
            : { 'x-openpc-action-intent-digest': digest }),
          ...(mode === 'conflicting'
            ? { 'openpc-action-intent-digest': `sha256:${'2'.repeat(64)}` }
            : {}),
        },
        payload: {
          actionIntentId: 'ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1',
          actionIntentDigest: digest,
          participantId: `urn:openpc:participant:${participantId}`,
          chainId: '1',
          endpointSecretRef: `urn:openpc:resource:${resourceId}`,
          behaviorFingerprint: digest,
          reason: 'Exercise action digest transport binding.',
        },
      });
      expect(response.statusCode).toBe(mode === 'conflicting' ? 400 : 403);
      expect(authorize).toHaveBeenCalledTimes(mode === 'conflicting' ? 0 : 1);
      await app.close();
    },
  );
  it.each(['operations', 'provider-profiles', 'notification-endpoints'])(
    'binds %s reads to the requested privacy context before persistence',
    async (resource) => {
      const app = Fastify();
      const requestedPrivacy = '018f0000-0000-7000-8000-000000000202';
      const authorize = vi.fn(async () => ({ participantId, privacyDomainId }) as never);
      registerConfigurationRoutes(app, { pool: {} as never, authorizer: { authorize } });
      const response = await app.inject({
        method: 'GET',
        url: resource === 'operations' ? `/api/v1/operations/${resourceId}` : `/api/v1/${resource}`,
        headers: {
          'cookie': '__Host-openpc_session=session',
          'x-request-id': resourceId,
          'x-correlation-id': resourceId,
          'openpc-api-version': '1',
          'openpc-participant-id': `urn:openpc:participant:${participantId}`,
          'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${requestedPrivacy}`,
        },
      });
      expect(authorize).toHaveBeenCalledWith(
        expect.objectContaining({ privacyDomainId: requestedPrivacy }),
      );
      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({ code: 'PC-AUTH-0005' });
      await app.close();
    },
  );

  it.each([
    ['GET', '/api/v1/notification-endpoints'],
    ['GET', `/api/v1/notification-endpoints/urn:openpc:resource:${resourceId}`],
    ['POST', '/api/v1/notification-endpoints'],
    ['PATCH', `/api/v1/notification-endpoints/urn:openpc:resource:${resourceId}`],
    ['POST', `/api/v1/notification-endpoints/urn:openpc:resource:${resourceId}/verify`],
  ] as const)(
    'requires an authenticated session for %s %s before persistence',
    async (method, url) => {
      const authorize = vi.fn();
      const app = Fastify();
      registerConfigurationRoutes(app, { pool: {} as never, authorizer: { authorize } });
      try {
        const result = await app.inject({ method, url });
        expect(result.statusCode).toBe(401);
        expect(result.json()).toMatchObject({ code: 'PC-AUTH-0003' });
        expect(authorize).not.toHaveBeenCalled();
      } finally {
        await app.close();
      }
    },
  );

  it.each(['urn:openpc:privacy-domain:extra:' + privacyDomainId, privacyDomainId, ''])(
    'rejects a malformed privacy context %s before authority lookup',
    async (privacy) => {
      const app = Fastify();
      const authorize = vi.fn(async () => {
        throw new Error('not reached');
      });
      registerConfigurationRoutes(app, { pool: {} as never, authorizer: { authorize } });
      const response = await app.inject({
        method: 'GET',
        url: `/api/v1/operations/${resourceId}`,
        headers: {
          'cookie': '__Host-openpc_session=session',
          'x-request-id': resourceId,
          'x-correlation-id': resourceId,
          'openpc-api-version': '1',
          'openpc-participant-id': `urn:openpc:participant:${participantId}`,
          'openpc-privacy-domain-id': privacy,
        },
      });
      expect(response.statusCode).toBe(400);
      expect(authorize).not.toHaveBeenCalled();
      await app.close();
    },
  );

  it('does not expose the former generic configuration-resource route', async () => {
    const app = Fastify();
    registerConfigurationRoutes(app, {
      pool: {} as never,
      authorizer: {
        authorize: async () => {
          throw new Error('not reached');
        },
      },
    });
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/configuration-resources/anything',
    });
    expect(response.statusCode).toBe(404);
  });

  it('rejects malformed canonical ABI import before authorization or persistence', async () => {
    const app = Fastify();
    registerConfigurationRoutes(app, {
      pool: {} as never,
      authorizer: {
        authorize: async () => {
          throw new Error('not reached');
        },
      },
    });
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/abi-artifacts',
      headers: {
        'cookie': '__Host-openpc_session=session',
        'x-request-id': resourceId,
        'x-correlation-id': resourceId,
        'openpc-api-version': '1',
        'openpc-participant-id': `urn:openpc:participant:${participantId}`,
        'openpc-action-intent-digest': digest,
        'idempotency-key': 'abi-artifact-import-0001',
        'x-csrf-token': 'a'.repeat(32),
        'origin': 'https://openpc.local',
      },
      payload: { unexpected: true },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ code: 'PC-DATA-6004', truthState: 'FAILED' });
  });

  it('registers every typed configuration route and no generic mutation surface', async () => {
    const app = Fastify();
    registerConfigurationRoutes(app, {
      pool: {} as never,
      authorizer: { authorize: async () => Promise.reject(new Error('not reached')) },
    });
    for (const [method, url] of [
      ['GET', '/api/v1/operations/:id'],
      ['GET', '/api/v1/work-items'],
      ['GET', '/api/v1/work-items/:id'],
      ['POST', '/api/v1/work-items'],
      ['PATCH', '/api/v1/work-items/:id'],
      ['POST', '/api/v1/work-items/:id/claim'],
      ['POST', '/api/v1/work-items/:id/complete'],
      ['GET', '/api/v1/abi-artifacts/:id'],
      ['GET', '/api/v1/abi-artifacts'],
      ['POST', '/api/v1/abi-artifacts'],
      ['GET', '/api/v1/logical-contract-assets/:id'],
      ['GET', '/api/v1/logical-contract-assets'],
      ['POST', '/api/v1/logical-contract-assets'],
      ['GET', '/api/v1/contract-runtime-bindings/:id'],
      ['GET', '/api/v1/contract-runtime-bindings'],
      ['POST', '/api/v1/contract-runtime-bindings'],
      ['GET', '/api/v1/typed-argument-rule-versions/:id'],
      ['POST', '/api/v1/typed-argument-rule-versions'],
      ['GET', '/api/v1/contract-method-policies/:id'],
      ['GET', '/api/v1/contract-method-policies'],
      ['POST', '/api/v1/contract-method-policies'],
      ['GET', '/api/v1/provider-profiles'],
      ['POST', '/api/v1/provider-profiles'],
      ['POST', '/api/v1/provider-profiles/:id/qualify'],
      ['POST', '/api/v1/indexer-profiles/:id/admit'],
      ['POST', '/api/v1/indexer-profiles/:id/admit/proposals'],
      ['POST', '/api/v1/projection-plans/:id/recover'],
      ['PATCH', '/api/v1/runtime-targets/:id'],
    ] as const) {
      expect(app.hasRoute({ method, url })).toBe(true);
    }
    const routes = app.printRoutes({ commonPrefix: false });
    expect(routes).not.toContain('/api/v1/configuration-resources/:id');
    expect(routes).not.toContain('/api/v1/runtime-configuration-generations');
  });

  it('rejects an authorization proof from a different participant before persistence', async () => {
    const app = Fastify();
    registerConfigurationRoutes(app, {
      pool: {} as never,
      authorizer: {
        authorize: async () => ({
          sessionId: resourceId,
          participantId: '018f0000-0000-7000-8000-000000000999',
          privacyDomainId,
          principalId: resourceId,
          principalEpoch: '1',
          evidenceKind: 'USER_WEBAUTHN',
          signerCredentialId: resourceId,
          participantEpoch: '1',
          authorityEnvelopeId: resourceId,
          authorityEpoch: '1',
          delegationEpoch: '1',
          assignmentId: resourceId,
          assignmentEpoch: '1',
          evidenceCbor: Buffer.alloc(0),
          evidenceDigest: Buffer.alloc(0),
          coseSign1: Buffer.alloc(0),
        }),
      },
    });
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/indexer-profiles',
      headers: {
        'cookie': '__Host-openpc_session=session',
        'x-request-id': resourceId,
        'x-correlation-id': resourceId,
        'openpc-api-version': '1',
        'openpc-participant-id': `urn:openpc:participant:${participantId}`,
        'openpc-action-intent-digest': digest,
        'idempotency-key': 'indexer-create-0001',
        'x-csrf-token': 'a'.repeat(32),
        'origin': 'https://openpc.local',
      },
      payload: {
        participantId: `urn:openpc:participant:${participantId}`,
        actionIntentId: 'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1',
        actionIntentDigest: digest,
        reason: 'local test',
        engine: 'CLIENT_INDEXER',
        engineVersion: '1.0.0',
        methodProfileDigest: digest,
      },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({
      code: 'PC-AUTH-0005',
      traceId: resourceId,
    });
  });

  it('rejects bearer authorization on the same-origin BFF surface', async () => {
    const app = Fastify();
    registerConfigurationRoutes(app, {
      pool: {} as never,
      authorizer: { authorize: async () => Promise.reject(new Error('not reached')) },
    });
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/provider-profiles',
      headers: {
        'authorization': 'Bearer session',
        'x-request-id': resourceId,
        'x-correlation-id': resourceId,
        'openpc-api-version': '1',
        'openpc-participant-id': `urn:openpc:participant:${participantId}`,
      },
    });
    expect(response.statusCode).toBe(401);
  });

  it('uses the canonical singular resource type for ABI authorization and scoped readback', async () => {
    let admittedResourceType: unknown;
    const client = {
      query: async (sql: string, values?: readonly unknown[]) => {
        if (sql.startsWith('with recursive authority_chain')) {
          return {
            rowCount: 1,
            rows: [
              {
                participantEpoch: '1',
                principalEpoch: '1',
                assignmentId: resourceId,
                assignmentRowVersion: '1',
                authorityEnvelopeId: resourceId,
                authorityEpoch: '1',
                delegationEpoch: '1',
                sessionEpoch: '1',
              },
            ],
          };
        }
        if (sql.includes('from control.action_intent ai')) {
          admittedResourceType = values?.[7];
          return { rowCount: 1, rows: [{}] };
        }
        if (sql.includes('from control.abi_artifact')) {
          return {
            rowCount: 1,
            rows: [
              {
                abiArtifactId: resourceId,
                abiDigest: digest,
                provenanceSource: 'LOCAL_FIXTURE',
                provenanceLocator: 'fixture://transfer',
                provenanceRetrievedAt: '2026-09-10T00:00:00.000Z',
                provenanceSourceDigest: digest,
                canonicalAbi: [],
                policyGenerationDigest: digest,
                revision: '1',
                createdAt: '2026-09-10T00:00:00.000Z',
              },
            ],
          };
        }
        return { rowCount: 0, rows: [] };
      },
      release: () => undefined,
    };
    const app = Fastify();
    registerConfigurationRoutes(app, {
      pool: { connect: async () => client } as never,
      authorizer: {
        authorize: async () => ({
          sessionId: resourceId,
          participantId,
          privacyDomainId,
          principalId: resourceId,
          principalEpoch: '1',
          evidenceKind: 'USER_WEBAUTHN',
          signerCredentialId: resourceId,
          participantEpoch: '1',
          authorityEnvelopeId: resourceId,
          authorityEpoch: '1',
          delegationEpoch: '1',
          assignmentId: resourceId,
          assignmentEpoch: '1',
          evidenceCbor: Buffer.alloc(0),
          evidenceDigest: Buffer.alloc(0),
          coseSign1: Buffer.alloc(0),
        }),
      },
    });
    const response = await app.inject({
      method: 'GET',
      url: `/api/v1/abi-artifacts/urn:openpc:resource:${resourceId}`,
      headers: {
        'cookie': '__Host-openpc_session=session',
        'x-request-id': resourceId,
        'x-correlation-id': resourceId,
        'openpc-api-version': '1',
        'openpc-participant-id': `urn:openpc:participant:${participantId}`,
      },
    });
    expect(response.statusCode).toBe(200);
    expect(admittedResourceType).toBe('abi-artifact');
  });

  it('rejects collection-only query controls on an item read with an exact Problem', async () => {
    const app = Fastify();
    registerConfigurationRoutes(app, {
      pool: {} as never,
      authorizer: { authorize: async () => Promise.reject(new Error('not reached')) },
    });
    const response = await app.inject({
      method: 'GET',
      url: `/api/v1/provider-profiles/urn:openpc:resource:${resourceId}?limit=50`,
      headers: {
        'cookie': '__Host-openpc_session=session',
        'x-request-id': resourceId,
        'x-correlation-id': resourceId,
        'openpc-api-version': '1',
        'openpc-participant-id': `urn:openpc:participant:${participantId}`,
      },
    });
    expect(response.statusCode).toBe(400);
    expect(response.headers['content-type']).toContain('application/problem+json');
    expect(response.json()).toEqual({
      type: 'https://errors.openpc.local/invalid-request',
      title: 'Request validation failed',
      truthState: 'FAILED',
      retryable: false,
      status: 400,
      code: 'PC-DATA-6004',
      traceId: resourceId,
    });
  });

  it('returns 428 when a revision-bound mutation omits If-Match', async () => {
    const app = Fastify();
    registerConfigurationRoutes(app, {
      pool: {} as never,
      authorizer: { authorize: async () => Promise.reject(new Error('not reached')) },
    });
    const target = `urn:openpc:resource:${resourceId}`;
    const response = await app.inject({
      method: 'POST',
      url: `/api/v1/provider-profiles/${target}/quarantine`,
      headers: {
        'cookie': '__Host-openpc_session=session',
        'x-request-id': resourceId,
        'x-correlation-id': resourceId,
        'openpc-api-version': '1',
        'openpc-participant-id': `urn:openpc:participant:${participantId}`,
        'openpc-action-intent-digest': digest,
        'idempotency-key': 'provider-quarantine-0001',
        'x-csrf-token': 'a'.repeat(32),
        'origin': 'https://openpc.local',
      },
      payload: {
        targetRef: target,
        expectedRevision: '1',
        inputDigest: digest,
        actionIntentId: 'ACT-PROVIDER_UPDATE_QUARANTINE-V1',
        actionIntentDigest: digest,
        reason: 'local test',
      },
    });
    expect(response.statusCode).toBe(428);
    expect(response.json()).toMatchObject({
      code: 'PC-DATA-6007',
      status: 428,
      truthState: 'STALE',
      retryable: false,
    });
  });
});
