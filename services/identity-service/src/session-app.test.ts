import { describe, expect, it, vi } from 'vitest';

import { buildIdentityService, type IdentityAuthorizationAdapter } from './app.js';
import { canonicalAuthorizationDigest } from './contracts/authorization.js';
import { IdentityKernel, IdentityKernelError } from './domain/identity-kernel.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const principalId = '018f0000-0000-7000-8000-000000000111';
const sessionId = '018f0000-0000-7000-8000-000000000117';
const nextSessionId = '018f0000-0000-7000-8000-000000000118';
const sessionToken = `${participantId}.${sessionId}`;
const nextSessionToken = `${participantId}.${nextSessionId}`;
const actionIntentId = 'ACT-IDENTITY_CREATE_SESSION-V1';
const actionIntentDigest = `sha256:${'a'.repeat(64)}`;
const reason = 'Rotate the active browser session.';
const candidate = { sessionId, operation: 'REFRESH', reason };
const operation = {
  operationId: '018f0000-0000-7000-8000-000000000601',
  resourceRef: `urn:openpc:resource:${sessionId}`,
  actionIntentId,
  intentDigest: actionIntentDigest,
  idempotencyKey: 'session-refresh-test-key',
  state: 'SUCCEEDED' as const,
  truthState: 'SUCCESS' as const,
  createdAt: '2026-09-11T02:00:00.000000Z',
  updatedAt: '2026-09-11T02:00:00.000000Z',
  revision: '2',
};

function fixture() {
  const sessionSnapshot = vi.fn(async () => ({
    sessionId,
    sessionToken,
    principalId,
    participantId,
    participantEpoch: '5',
    authorityEpoch: '7',
    sessionEpoch: '1',
    refreshFamilyId: '018f0000-0000-7000-8000-000000000119',
    state: 'ACTIVE' as const,
    issuedAt: new Date('2026-09-11T01:00:00Z'),
    lastSeenAt: new Date('2026-09-11T02:00:00Z'),
    idleExpiresAt: new Date('2026-09-11T02:30:00Z'),
    absoluteExpiresAt: new Date('2026-09-11T12:00:00Z'),
  }));
  const verifyCsrf = vi.fn(async () => undefined);
  const actionIntentSemanticDigest = vi.fn(async () => actionIntentDigest);
  const refreshBrowserSession = vi.fn(async () => ({
    result: {
      ...(await sessionSnapshot()),
      sessionId: nextSessionId,
      sessionToken: nextSessionToken,
    },
    operation,
  }));
  const replayCommittedSessionMutation = vi.fn(async () => ({
    nextSessionToken,
    operation,
  }));
  const kernel = {
    sessionSnapshot,
    verifyCsrf,
    actionIntentSemanticDigest,
    refreshBrowserSession,
    replayCommittedSessionMutation,
  } as unknown as IdentityKernel;
  const authorize = vi.fn(async () => ({
    allowed: true,
    evidenceKind: 'IDENTITY_RUNTIME' as const,
    signerKeyDigest: Buffer.alloc(32, 1),
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    evidenceCbor: Buffer.from('evidence'),
    evidenceDigest: Buffer.alloc(32, 2),
    coseSign1: Buffer.from('signature'),
  }));
  return {
    kernel,
    authorize,
    refreshBrowserSession,
    replayCommittedSessionMutation,
    sessionSnapshot,
  };
}

function request(payload = candidate) {
  const command = {
    targetRef: `urn:openpc:resource:${sessionId}`,
    actionIntentId,
    actionIntentDigest,
    inputDigest: canonicalAuthorizationDigest(payload),
    expectedRevision: '1',
    reason,
  };
  return {
    method: 'POST' as const,
    url: '/api/v1/session/refresh',
    headers: {
      'cookie': `__Host-openpc_session=${sessionToken}`,
      'origin': 'https://control.openpc.example',
      'host': 'control.openpc.example',
      'x-csrf-token': 'c'.repeat(43),
      'x-request-id': '018f0000-0000-7000-8000-000000000501',
      'x-correlation-id': '018f0000-0000-7000-8000-000000000502',
      'openpc-api-version': '1',
      'openpc-participant-id': `urn:openpc:participant:${participantId}`,
      'openpc-privacy-domain-id': 'urn:openpc:privacy-domain:018f0000-0000-7000-8000-000000000201',
      'openpc-action-intent-digest': actionIntentDigest,
      'if-match': `"${canonicalAuthorizationDigest({
        resourceType: 'session',
        revision: '1',
        sessionId,
      })}"`,
      'idempotency-key': operation.idempotencyKey,
    },
    payload: command,
  };
}

describe('canonical session mutation routes', () => {
  it('rotates through authorization and returns the durable Operation without exposing tokens', async () => {
    const { kernel, authorize, refreshBrowserSession } = fixture();
    const app = buildIdentityService(kernel, undefined, undefined, {
      authorize,
    } satisfies IdentityAuthorizationAdapter);
    const response = await app.inject(request());
    expect(response.statusCode, response.body).toBe(202);
    expect(response.json()).toEqual(operation);
    expect(response.body).not.toContain(nextSessionToken);
    expect(response.headers['set-cookie']).toContain(nextSessionToken);
    expect(response.headers.etag).toBe(`"${canonicalAuthorizationDigest(operation)}"`);
    expect(response.headers['ratelimit-limit']).toBe('100');
    expect(response.headers['ratelimit-remaining']).toBe('99');
    expect(response.headers['ratelimit-reset']).toBe('60');
    expect(authorize).toHaveBeenCalledWith(
      expect.objectContaining({
        actionIntentId,
        catalogOperationId: 'ID-OP-SESSION-REFRESH',
        candidateDigest: canonicalAuthorizationDigest(candidate),
      }),
    );
    expect(refreshBrowserSession).toHaveBeenCalledWith(
      expect.objectContaining({ mutationAuthorization: expect.any(Object) }),
      reason,
    );
    await app.close();
  });

  it('rejects a tampered command digest before authorization or mutation', async () => {
    const { kernel, authorize, refreshBrowserSession } = fixture();
    const app = buildIdentityService(kernel, undefined, undefined, {
      authorize,
    } satisfies IdentityAuthorizationAdapter);
    const invalid = request();
    invalid.payload.inputDigest = `sha256:${'f'.repeat(64)}`;
    const response = await app.inject(invalid);
    expect(response.statusCode).toBe(409);
    expect(authorize).not.toHaveBeenCalled();
    expect(refreshBrowserSession).not.toHaveBeenCalled();
    await app.close();
  });

  it('returns the exact committed rotation when the predecessor session is already revoked', async () => {
    const {
      kernel,
      authorize,
      refreshBrowserSession,
      replayCommittedSessionMutation,
      sessionSnapshot,
    } = fixture();
    sessionSnapshot.mockRejectedValueOnce(new IdentityKernelError('PC-AUTH-0003'));
    const app = buildIdentityService(kernel, undefined, undefined, {
      authorize,
    } satisfies IdentityAuthorizationAdapter);
    const response = await app.inject(request());
    expect(response.statusCode, response.body).toBe(202);
    expect(response.json()).toEqual(operation);
    expect(response.headers['set-cookie']).toContain(nextSessionToken);
    expect(replayCommittedSessionMutation).toHaveBeenCalledWith(
      expect.objectContaining({
        sessionToken,
        actionIntentId,
        catalogOperationId: 'ID-OP-SESSION-REFRESH',
        idempotencyKey: operation.idempotencyKey,
        candidateDigest: canonicalAuthorizationDigest(candidate),
        expectedRevision: '1',
      }),
    );
    expect(authorize).not.toHaveBeenCalled();
    expect(refreshBrowserSession).not.toHaveBeenCalled();
    await app.close();
  });
});
