import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { registerConfigurationRoutes } from '../http.js';
import { ConfigurationRepositoryError } from '../persistence/types.js';
import { createDeploymentIntentSchema } from './intent-contract.js';
import { createDeploymentSubmissionSchema } from './submission-contract.js';

const uuid = '018f0000-0000-7000-8000-000000000301';
const digest = `sha256:${'11'.repeat(32)}`;
const input = {
  actionIntentId: 'ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1',
  actionIntentDigest: digest,
  reason: 'Prepare an exact non-authorizing deployment intent.',
  deploymentPolicyId: `urn:openpc:resource:${uuid}`,
  runtimeTargetId: `urn:openpc:resource:${uuid}`,
  walletBindingId: `urn:openpc:resource:${uuid}`,
  signingPayload: '0x02db827a69090102830186a080808d6001600c60003960016000f300c0',
};

describe('dedicated deployment intent input boundary', () => {
  it('admits only exact identity references and canonical payload bytes', () => {
    expect(createDeploymentIntentSchema.parse(input)).toEqual(input);
    const selected = { ...input, executionWorkloadId: `urn:openpc:workload:${uuid}` };
    expect(createDeploymentIntentSchema.parse(selected)).toEqual(selected);
    const endowed = { ...selected, nativeValueAuthorizationId: `urn:openpc:resource:${uuid}` };
    expect(createDeploymentIntentSchema.parse(endowed)).toEqual(endowed);
    for (const patch of [
      { authority: 'APPROVED' },
      { state: 'FINAL_FENCED' },
      { ready: true },
      { participantEpoch: 1 },
      { sender: `0x${'11'.repeat(20)}` },
      { executionWorkloadId: `urn:openpc:resource:${uuid}` },
      { executionPrincipalId: uuid },
      { approvalSetDigest: digest },
      { nativeValueAuthorizationBytes: '0x7b7d' },
      { nativeValueAuthorizationDigest: digest },
      { nativeValueAuthorizationId: `urn:openpc:participant:${uuid}` },
      { signingPayload: '0x' },
      { signingPayload: '0xABC' },
      { signingPayload: `0x${'00'.repeat(131073)}` },
      { runtimeTargetId: `urn:openpc:participant:${uuid}` },
      { actionIntentId: 'ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1' },
    ]) {
      expect(createDeploymentIntentSchema.safeParse({ ...input, ...patch }).success).toBe(false);
    }
  });

  it.each([
    ['/api/v1/deployment-intents', input],
    [
      '/api/v1/deployment-submissions',
      {
        actionIntentId: 'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',
        actionIntentDigest: digest,
        reason: 'Execute an exact signed intent.',
        deploymentIntentId: `urn:openpc:resource:${uuid}`,
        signedTransaction: '0x02abcd',
      },
    ],
  ])(
    'requires the protected mutation owner for %s and rejects authority injection before it',
    async (url, payload) => {
      const app = Fastify();
      const authorize = vi.fn(async () => {
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      });
      registerConfigurationRoutes(app, { pool: {} as never, authorizer: { authorize } });
      const headers = {
        'cookie': '__Host-openpc_session=session',
        'x-request-id': uuid,
        'x-correlation-id': uuid,
        'openpc-api-version': '1',
        'openpc-participant-id': `urn:openpc:participant:${uuid}`,
        'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${uuid}`,
        'idempotency-key': 'deployment-intent-header-test',
        'x-csrf-token': 'a'.repeat(32),
        'origin': 'https://openpc.local',
        'openpc-action-intent-digest': digest,
      };
      try {
        expect(
          (
            await app.inject({
              method: 'POST',
              url,
              headers,
              payload,
            })
          ).statusCode,
        ).toBe(403);
        expect(authorize).toHaveBeenCalledWith(
          expect.objectContaining({ makerCheckerRequired: true, stepUpRequired: true }),
        );
        authorize.mockClear();
        expect(
          (
            await app.inject({
              method: 'POST',
              url,
              headers,
              payload: { ...payload, authority: 'APPROVED' },
            })
          ).statusCode,
        ).toBe(400);
        expect(authorize).not.toHaveBeenCalled();
      } finally {
        await app.close();
      }
    },
  );
  it('rejects caller custody, approval and attempt identity in signed submission input', () => {
    const command = {
      actionIntentId: 'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',
      actionIntentDigest: digest,
      reason: 'Exact signed deployment',
      deploymentIntentId: `urn:openpc:resource:${uuid}`,
      signedTransaction: '0x02abcd',
    };
    expect(createDeploymentSubmissionSchema.parse(command)).toEqual(command);
    const replacement = { ...command, predecessorOperationId: `urn:openpc:operation:${uuid}` };
    expect(createDeploymentSubmissionSchema.parse(replacement)).toEqual(replacement);
    for (const patch of [
      { predecessorOperationId: `urn:openpc:resource:${uuid}` },
      { predecessorOperationId: 'unscoped-command' },
      { predecessorOperationId: null },
      { reservation: {} },
      { commandId: uuid },
      { attemptId: uuid },
      { approvalSetDigest: digest },
      { signedTransaction: '0xABC' },
    ])
      expect(createDeploymentSubmissionSchema.safeParse({ ...command, ...patch }).success).toBe(
        false,
      );
  });
});
