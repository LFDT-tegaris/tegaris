import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { registerConfigurationRoutes } from '../http.js';
import * as mutationCandidates from '../persistence/mutation-candidate.js';
import { RuntimeTargetProfileBindingRepository } from './repository.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const targetId = '018f0000-0000-7000-8000-000000000902';
const bindingId = '018f0000-0000-7000-8000-000000000903';
const digest = `sha256:${'1'.repeat(64)}`;

describe('runtime profile proposal HTTP boundary', () => {
  it.each(['proposal', 'anonymous', 'foreign', 'wrong-action', 'grant-injection'] as const)(
    'keeps configuration review separate from new access: %s',
    async (scenario) => {
      const app = Fastify();
      const propose = vi.fn(
        async () =>
          ({
            participantId: scenario === 'foreign' ? targetId : participantId,
            privacyDomainId,
          }) as never,
      );
      const authorize = vi.fn();
      const stage = vi
        .spyOn(mutationCandidates, 'stageMutationCandidate')
        .mockResolvedValue(bindingId);
      const create = vi.spyOn(RuntimeTargetProfileBindingRepository.prototype, 'create');
      registerConfigurationRoutes(app, { pool: {} as never, authorizer: { propose, authorize } });
      try {
        const response = await app.inject({
          method: 'POST',
          url: '/api/v1/runtime-target-profile-bindings/proposals',
          headers: {
            ...(scenario === 'anonymous' ? {} : { cookie: '__Host-openpc_session=session' }),
            'x-request-id': bindingId,
            'x-correlation-id': bindingId,
            'openpc-api-version': '1',
            'openpc-participant-id': `urn:openpc:participant:${participantId}`,
            'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
            'x-openpc-action-intent-digest': digest,
            'idempotency-key': 'runtime-profile-binding-proposal-0001',
            'x-csrf-token': 'a'.repeat(32),
            'origin': 'https://openpc.local',
          },
          payload: {
            actionIntentId:
              scenario === 'wrong-action'
                ? 'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1'
                : 'ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1',
            actionIntentDigest: digest,
            reason: 'Review the exact registered target and profile name.',
            runtimeTargetRef: `urn:openpc:resource:${targetId}`,
            targetRevision: '1',
            targetProfileId: 'devnet-rpc-v1',
            ...(scenario === 'grant-injection'
              ? { capabilityIds: ['CALL_RESULT_DISCLOSURE'] }
              : {}),
          },
        });
        expect(response.statusCode).toBe(
          {
            'proposal': 200,
            'anonymous': 401,
            'foreign': 403,
            'wrong-action': 400,
            'grant-injection': 400,
          }[scenario],
        );
        expect(authorize).not.toHaveBeenCalled();
        expect(create).not.toHaveBeenCalled();
        if (scenario === 'proposal') {
          expect(stage).toHaveBeenCalledOnce();
          expect(propose).toHaveBeenCalledWith(
            expect.objectContaining({
              participantId,
              privacyDomainId,
              catalogOperationId: 'CFG-OP-CREATE-RUNTIME-TARGET-PROFILE',
              makerCheckerRequired: true,
              stepUpRequired: true,
            }),
          );
        } else {
          expect(stage).not.toHaveBeenCalled();
        }
      } finally {
        vi.restoreAllMocks();
        await app.close();
      }
    },
  );
});
