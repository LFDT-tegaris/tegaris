import { afterEach, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import type { Pool } from 'pg';
import { HttpPolicyIdentityGateway, buildPolicyService } from './policy-http.js';
import { registerPublicApprovalRoutes } from './public-approval-http.js';
import { ContractError, PolicyIdentityUnavailable } from './domain/errors.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const input = {
  sessionToken: 'private-unit-session',
  privacyDomainId: id(2),
  actionIntentId: 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
  resourceId: id(3),
  stepUpRequired: false,
};
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
it.each(['network', 'timeout', 'server'])(
  'reports %s as unavailable without fabricating denial or retry',
  async (failure) => {
    const fetch = vi.fn();
    if (failure === 'server') fetch.mockResolvedValue(new Response(null, { status: 503 }));
    else if (failure === 'timeout') {
      const controller = new AbortController();
      controller.abort(new DOMException('unit timeout', 'TimeoutError'));
      vi.spyOn(AbortSignal, 'timeout').mockReturnValue(controller.signal);
      fetch.mockRejectedValue(controller.signal.reason);
    } else
      fetch.mockRejectedValue(new TypeError('fetch failed', { cause: { code: 'ECONNRESET' } }));
    vi.stubGlobal('fetch', fetch);
    const timeout = vi.spyOn(AbortSignal, 'timeout');
    await expect(
      new HttpPolicyIdentityGateway('http://identity.invalid', 'private-unit-token').authorize(
        input,
      ),
    ).rejects.toBeInstanceOf(PolicyIdentityUnavailable);
    expect(fetch).toHaveBeenCalledOnce();
    expect(timeout).toHaveBeenCalledWith(45_000);
  },
);
it.each(['denied', 'malformed'])('keeps %s authorization fail closed', async (failure) => {
  vi.stubGlobal(
    'fetch',
    vi
      .fn()
      .mockResolvedValue(
        failure === 'denied'
          ? new Response(null, { status: 403 })
          : Response.json({ principalId: id(1) }),
      ),
  );
  await expect(
    new HttpPolicyIdentityGateway('http://identity.invalid', 'private-unit-token').authorize(input),
  ).rejects.toBeInstanceOf(ContractError);
});
it.each(['internal', 'public'])(
  'maps only typed transport failure to unavailable at the %s boundary before database access',
  async (boundary) => {
    const connect = vi.fn(),
      pool = { connect } as unknown as Pool;
    const authorize = vi.fn().mockRejectedValue(new PolicyIdentityUnavailable());
    const app =
      boundary === 'internal'
        ? buildPolicyService({
            pool,
            identityGateway: { authorize },
            trustedArtifactSigners: [],
            internalToken: 'unit-internal',
          })
        : Fastify();
    if (boundary === 'public') registerPublicApprovalRoutes(app, { pool, authorize });
    const response = await app.inject(
      boundary === 'internal'
        ? {
            method: 'POST',
            url: '/internal/v1/policy-approvals',
            headers: {
              'authorization': 'Bearer unit-internal',
              'openpc-participant-id': `urn:openpc:participant:${id(1)}`,
              'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${id(2)}`,
            },
            payload: {
              sessionToken: 'unit-session',
              policyVersionId: id(3),
              candidateDigest: 'sha256:' + 'a'.repeat(64),
            },
          }
        : {
            method: 'GET',
            url: `/api/v1/approval-requests/${encodeURIComponent(`urn:openpc:resource:${id(3)}`)}`,
            headers: {
              'x-request-id': id(4),
              'x-correlation-id': id(5),
              'openpc-participant-id': `urn:openpc:participant:${id(1)}`,
              'openpc-api-version': '1',
            },
          },
    );
    try {
      expect(response.statusCode).toBe(503);
      expect(response.json()).toMatchObject({
        code: 'PC-INTEGRATION-5001',
        truthState: 'UNAVAILABLE',
      });
      expect(connect).not.toHaveBeenCalled();
      expect(authorize).toHaveBeenCalledOnce();
    } finally {
      await app.close();
    }
  },
);

it.each(['unknown', 'foreign timeout', 'bad setup', 'JSON syntax'])(
  'does not misclassify %s as owned transport',
  async (failure) => {
    const original =
      failure === 'foreign timeout'
        ? new DOMException('foreign', 'TimeoutError')
        : failure === 'bad setup'
          ? new TypeError('bad URL')
          : failure === 'JSON syntax'
            ? new SyntaxError('bad JSON')
            : new Error('unknown');
    const fetch = vi.fn();
    if (failure === 'JSON syntax')
      fetch.mockResolvedValue({ ok: true, status: 200, json: () => Promise.reject(original) });
    else fetch.mockRejectedValue(original);
    vi.stubGlobal('fetch', fetch);
    await expect(
      new HttpPolicyIdentityGateway('http://identity.invalid', 'unit-token').authorize(input),
    ).rejects.toBe(original);
    expect(fetch).toHaveBeenCalledOnce();
  },
);
it('classifies a closed post-header socket failure as unavailable without retry', async () => {
  const fetch = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: () => Promise.reject(new TypeError('terminated', { cause: { code: 'UND_ERR_SOCKET' } })),
  });
  vi.stubGlobal('fetch', fetch);
  await expect(
    new HttpPolicyIdentityGateway('http://identity.invalid', 'unit-token').authorize(input),
  ).rejects.toBeInstanceOf(PolicyIdentityUnavailable);
  expect(fetch).toHaveBeenCalledOnce();
});
