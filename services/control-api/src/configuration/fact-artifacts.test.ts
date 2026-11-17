import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FactArtifactsClient, registerFactArtifactRoutes } from './fact-artifacts.js';
import type { ConfigurationAuthorizer } from './authorization.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const resourceId = '018f0000-0000-7000-8000-000000000501';
const action = 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1';
const digest = 'sha256:1e0f1ff216ab9a4d35b7467f767710e05e827dc8e40943aa35d6719298c5ac2a';
const authority = {
  participantId,
  privacyDomainId,
  principalId: '018f0000-0000-7000-8000-000000000111',
};
const headers = {
  'cookie': '__Host-openpc_session=session-fixture',
  'openpc-api-version': '1',
  'openpc-participant-id': `urn:openpc:participant:${participantId}`,
  'x-request-id': '018f0000-0000-7000-8000-000000000901',
  'x-correlation-id': '018f0000-0000-7000-8000-000000000902',
};
const command = {
  actionIntentId: action,
  actionIntentDigest: digest,
  expectedRevision: '1',
  replacementDigest: `sha256:${'ab'.repeat(32)}`,
  reason: 'Admit the exact candidate.',
};
const operation = {
  operationId: '018f0000-0000-7000-8000-000000000901',
  resourceRef: `urn:openpc:resource:${resourceId}`,
  actionIntentId: action,
  intentDigest: digest,
  idempotencyKey: 'fact-artifact-contract-0001',
  state: 'SUCCEEDED',
  truthState: 'SUCCESS',
  revision: '1',
  createdAt: '2026-09-19T00:00:00.000000Z',
  updatedAt: '2026-09-19T00:00:00.000000Z',
};
function fixture() {
  const propose = vi.fn().mockResolvedValue(authority);
  const authorize = vi.fn().mockResolvedValue(authority);
  const app = Fastify();
  registerFactArtifactRoutes(app, {
    authorizer: { propose, authorize } as ConfigurationAuthorizer,
    client: new FactArtifactsClient('http://fact.invalid', 'private-owner-token', {
      participantId,
      privacyDomainId,
    }),
  });
  const patch = (body: Readonly<Record<string, unknown>> = command) =>
    app.inject({
      method: 'PATCH',
      url: `/api/v1/fact-artifacts/urn:openpc:resource:${resourceId}`,
      headers: {
        ...headers,
        'origin': 'https://control.example',
        'host': 'control.example',
        'x-csrf-token': 'c'.repeat(64),
        'openpc-action-intent-digest': digest,
        'idempotency-key': operation.idempotencyKey,
        'if-match': `"sha256:${'ab'.repeat(32)}"`,
      },
      payload: body,
    });
  return { app, propose, authorize, patch };
}
afterEach(() => vi.unstubAllGlobals());
describe('Fact artifact public boundary contracts', () => {
  it('forwards exact CSRF and scoped identity and preserves the durable operation', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json(operation, { status: 202 }));
    vi.stubGlobal('fetch', fetch);
    const f = fixture();
    try {
      const response = await f.patch();
      expect(response.statusCode).toBe(202);
      expect(response.json()).toEqual(operation);
      expect(f.propose).toHaveBeenCalledWith(
        expect.objectContaining({
          sessionToken: 'session-fixture',
          actionIntentId: action,
          resourceId,
          csrfToken: 'c'.repeat(64),
          origin: 'https://control.example',
          host: 'control.example',
          makerCheckerRequired: false,
          stepUpRequired: false,
        }),
      );
      const forwarded = fetch.mock.calls[0]![1].headers as Headers;
      expect(forwarded.get('x-openpc-principal-id')).toBe(authority.principalId);
      expect(forwarded.get('openpc-privacy-domain-id')).toBe(
        `urn:openpc:privacy-domain:${privacyDomainId}`,
      );
      expect(forwarded.get('authorization')).toBe('Bearer private-owner-token');
      expect(forwarded.get('cookie')).toBeNull();
    } finally {
      await f.app.close();
    }
  });
  it('rejects fabricated authority fields before contacting any owner', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const f = fixture();
    try {
      expect((await f.patch({ ...command, ready: true })).statusCode).toBe(400);
      expect(f.propose).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      await f.app.close();
    }
  });
  it.each([
    ['upstream text', () => new Response('postgresql://secret@database', { status: 503 })],
    [
      'wrong operation',
      () =>
        Response.json({
          ...operation,
          resourceRef: `urn:openpc:resource:${authority.principalId}`,
        }),
    ],
    ['invalid result', () => Response.json({ ...operation, truthState: 'UNAVAILABLE' })],
  ])('fails closed without exposing %s', async (_name, response) => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(response));
    const f = fixture();
    try {
      const result = await f.patch();
      expect(result.statusCode).toBe(503);
      expect(result.json()).toMatchObject({
        code: 'PC-INTEGRATION-5001',
        truthState: 'UNAVAILABLE',
      });
      expect(result.body).not.toContain('secret@database');
    } finally {
      await f.app.close();
    }
  });
  it('denies a different authorized scope before forwarding', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const f = fixture();
    f.propose.mockResolvedValue({ ...authority, participantId: resourceId });
    try {
      expect((await f.patch()).statusCode).toBe(404);
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      await f.app.close();
    }
  });
  it('hides an authorized scope that the single-scope Fact owner does not serve', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const f = fixture();
    f.authorize.mockResolvedValue({
      ...authority,
      privacyDomainId: resourceId,
    });
    try {
      const response = await f.app.inject({
        method: 'GET',
        url: `/api/v1/fact-artifacts/urn:openpc:resource:${resourceId}`,
        headers: {
          ...headers,
          'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${resourceId}`,
        },
      });
      expect(response.statusCode).toBe(404);
      expect(response.json()).toMatchObject({ code: 'PC-AUTH-0005', truthState: 'DENIED' });
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      await f.app.close();
    }
  });
});
