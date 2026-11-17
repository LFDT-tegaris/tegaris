import Fastify from 'fastify';
import { expect, it, vi } from 'vitest';

import { sha256 } from './digest.js';
import { registerConfigurationRoutes } from './http.js';
import * as candidates from './persistence/mutation-candidate.js';
import { ConfigurationRepositoryError } from './persistence/types.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const resourceId = '018f0000-0000-7000-8000-000000000301';
const body = {
  actionIntentId: 'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1',
  actionIntentDigest: `sha256:${'1'.repeat(64)}`,
  expectedRevision: '8',
  replacementDigest: `sha256:${'2'.repeat(64)}`,
  reason: 'Renew the retained provider observation.',
};

it.each(['proposal', 'anonymous', 'missing-revision', 'mismatched-revision', 'denied'] as const)(
  'governs a provider update proposal without executing it: %s',
  async (scenario) => {
    const app = Fastify();
    const stage = vi.spyOn(candidates, 'stageMutationCandidate').mockResolvedValue(resourceId);
    const propose = vi.fn(async () => {
      if (scenario === 'denied') throw new ConfigurationRepositoryError('PC-AUTH-0005');
      return { participantId, privacyDomainId } as never;
    });
    const authorize = vi.fn();
    registerConfigurationRoutes(app, { pool: {} as never, authorizer: { propose, authorize } });
    try {
      const response = await app.inject({
        method: 'POST',
        url: `/api/v1/provider-profiles/urn:openpc:resource:${resourceId}/proposals`,
        headers: {
          ...(scenario === 'anonymous' ? {} : { cookie: '__Host-openpc_session=session' }),
          'x-request-id': resourceId,
          'x-correlation-id': resourceId,
          'openpc-api-version': '1',
          'openpc-participant-id': `urn:openpc:participant:${participantId}`,
          'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
          'idempotency-key': 'provider-renewal-proposal-0001',
          'x-csrf-token': 'a'.repeat(32),
          'origin': 'https://openpc.local',
          'x-openpc-action-intent-digest': body.actionIntentDigest,
          ...(scenario === 'missing-revision'
            ? {}
            : {
                'if-match': `"${sha256({ resourceId, revision: scenario === 'mismatched-revision' ? '7' : '8' })}"`,
              }),
        },
        payload: body,
      });
      expect(response.statusCode).toBe(
        {
          'proposal': 200,
          'anonymous': 401,
          'missing-revision': 428,
          'mismatched-revision': 412,
          'denied': 403,
        }[scenario],
      );
      expect(authorize).not.toHaveBeenCalled();
      if (scenario === 'proposal') {
        expect(response.headers['cache-control']).toBe('no-store');
        expect(response.json()).toEqual({
          resourceRef: `urn:openpc:resource:${resourceId}`,
          actionIntentId: body.actionIntentId,
          candidateDigest: sha256(body),
          expectedRevision: '8',
          runtimePermission: 'NONE',
        });
        expect(propose).toHaveBeenCalledWith(
          expect.objectContaining({
            catalogOperationId: 'CFG-OP-UPDATE-PROVIDER-PROFILE',
            resourceId,
            expectedRevision: '8',
            makerCheckerRequired: true,
            stepUpRequired: true,
          }),
        );
        expect(stage).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ resourceId, expectedRevision: '8', candidate: body }),
        );
      } else {
        expect(stage).not.toHaveBeenCalled();
        if (scenario !== 'denied') expect(propose).not.toHaveBeenCalled();
      }
    } finally {
      stage.mockRestore();
      await app.close();
    }
  },
);
