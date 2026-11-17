import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';

import { platformBootstrapPolicyScope } from './platform-bootstrap-policy.js';
import type { PolicyAuthorizationRequest } from './policy-authorization.js';

vi.mock('./platform-envelope-policy.js', () => ({
  platformEnvelopePolicyScope: vi.fn().mockResolvedValue(undefined),
}));

const participantId = '018f0000-0000-7000-8000-000000000101';
const principalId = '018f0000-0000-7000-8000-000000000111';
const sessionId = '018f0000-0000-7000-8000-000000000701';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';

function request(actionIntentId: string, resourceId = participantId): PolicyAuthorizationRequest {
  return {
    sessionToken: 'local-session-token',
    privacyDomainId,
    actionIntentId,
    resourceId,
    stepUpRequired: false,
  };
}

it('admits only the Participant catalogue reads needed by a Platform operator', async () => {
  const client = {
    query: vi.fn().mockResolvedValue({ rowCount: 0, rows: [] }),
  } as unknown as PoolClient;

  await expect(
    platformBootstrapPolicyScope(
      client,
      participantId,
      principalId,
      sessionId,
      request('ACT-PARTICIPANTS_READ_COLLECTION-V1'),
    ),
  ).resolves.toBe(true);
  await expect(
    platformBootstrapPolicyScope(
      client,
      participantId,
      principalId,
      sessionId,
      request('ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1'),
    ),
  ).resolves.toBe(true);
  await expect(
    platformBootstrapPolicyScope(
      client,
      participantId,
      principalId,
      sessionId,
      request('ACT-PARTICIPANTS_READ_RESOURCE-V1'),
    ),
  ).resolves.toBe(true);
  await expect(
    platformBootstrapPolicyScope(
      client,
      participantId,
      principalId,
      sessionId,
      request('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'),
    ),
  ).resolves.toBe(false);
});

it.each(['ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'])(
  'admits exact historical Root approval scope only when its owning query finds the actor: %s',
  async (action) => {
    const resource = '018f0000-0000-7000-8000-000000000901';
    for (const related of [true, false]) {
      const query = vi
        .fn()
        .mockResolvedValue({ rowCount: related ? 1 : 0, rows: related ? [{}] : [] });
      await expect(
        platformBootstrapPolicyScope(
          { query } as unknown as PoolClient,
          participantId,
          principalId,
          sessionId,
          request(action, resource),
        ),
      ).resolves.toBe(related);
      const [sql, params] = query.mock.calls[0]!;
      expect(params.slice(0, 5)).toEqual([
        participantId,
        privacyDomainId,
        resource,
        principalId,
        action,
      ]);
      expect(sql).toContain('approval.approval_request_id::text=$3');
      expect(sql).toContain('$4=candidate.maker_principal_id::text');
      expect(sql).toContain('$4=approval.checker_principal_id::text');
      expect(sql).toContain('candidate.consumed_operation_id is null');
      expect(sql).not.toContain("$5='ACT-POLICY_APPROVE_REQUEST-V1'");
    }
  },
);
