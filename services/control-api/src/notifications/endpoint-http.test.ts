import { Socket } from 'node:net';
import { TLSSocket } from 'node:tls';
import Fastify, { type FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { afterEach, expect, it, vi } from 'vitest';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import type { ConfigurationApiOptions } from '../configuration/http.js';
import { sha256 } from '../configuration/digest.js';
import {
  ConfigurationRepositoryError,
  type MutationAuthorization,
  type OperationRecord,
} from '../configuration/persistence/types.js';
import { registerNotificationEndpointRoutes } from './endpoint-http.js';
import { NotificationEndpointVerificationWorkflow } from './endpoint-verification-workflow.js';

// Routing/binding tests only. The workflow method and authorizer are explicit
// doubles; real authorization, TLS and SQL acceptance belongs to the PG journey.
const apps: FastifyInstance[] = [];
const peers: TLSSocket[] = [];
afterEach(async () => {
  for (const app of apps.splice(0)) await app.close();
  for (const peer of peers.splice(0)) peer.destroy();
  vi.restoreAllMocks();
});
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = `sha256:${'1'.repeat(64)}`;

function fixture(composed = true) {
  const pool = () =>
    ({
      options: {
        max: 2,
        connectionTimeoutMillis: 1000,
        statement_timeout: 5000,
        idle_in_transaction_session_timeout: 30000,
      },
      connect: vi.fn(),
    }) as unknown as Pool;
  const peer = new TLSSocket(new Socket());
  peers.push(peer);
  const authorization = {
    participantId: id(1),
    privacyDomainId: id(2),
    principalId: id(4),
    sessionId: id(5),
    sessionEpoch: '1',
    evidenceKind: 'IDENTITY_RUNTIME',
  } as MutationAuthorization;
  const authorize = vi.fn().mockResolvedValue(authorization);
  const options: ConfigurationApiOptions = {
    pool: pool(),
    authorizer: { authorize },
    identityRuntimeVerifier: {
      verifyCanonicalAssertion: vi.fn(),
    } as unknown as IdentityRuntimeVerifier,
    businessEvidence: { environmentId: 'local', signer: { sign: vi.fn() } },
  };
  const workflow = new NotificationEndpointVerificationWorkflow({
    pool: options.pool,
    recipientPool: pool(),
    workloadPeer: peer,
    kernel: { authenticateWorkload: vi.fn() } as unknown as IdentityKernel,
    identityRuntimeVerifier: options.identityRuntimeVerifier!,
    businessEvidence: options.businessEvidence!,
    credentialProvider: { withExactVersion: vi.fn() },
    timeoutMs: 1000,
  });
  const body = {
    actionIntentId: 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
    actionIntentDigest: hash,
    targetRef: `urn:openpc:resource:${id(3)}`,
    expectedRevision: '2',
    inputDigest: hash,
    reason: 'Exercise the public verification route.',
  };
  const headers: Record<string, string> = {
    'cookie': '__Host-openpc_session=session',
    'openpc-api-version': '1',
    'openpc-participant-id': `urn:openpc:participant:${id(1)}`,
    'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${id(2)}`,
    'x-request-id': id(6),
    'x-correlation-id': id(7),
    'idempotency-key': 'public-verification-key',
    'openpc-action-intent-digest': hash,
    'x-csrf-token': 'c'.repeat(32),
    'origin': 'https://openpc.local',
    'host': 'openpc.local',
    'if-match': `"${sha256({ resourceId: id(3), revision: '2' })}"`,
  };
  const operation: OperationRecord = {
    operationId: id(8),
    resourceRef: body.targetRef,
    actionIntentId: body.actionIntentId,
    intentDigest: hash,
    idempotencyKey: headers['idempotency-key']!,
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    createdAt: '2026-09-24T00:00:00.000000Z',
    updatedAt: '2026-09-24T00:00:00.000000Z',
    revision: '3',
  };
  const verify = vi.spyOn(workflow, 'verify').mockResolvedValue(operation);
  const app = Fastify({ logger: false });
  apps.push(app);
  registerNotificationEndpointRoutes(app, options, composed ? workflow : undefined);
  const request = (payload: Record<string, unknown> = body, requestHeaders = headers) =>
    app.inject({
      method: 'POST',
      url: `/api/v1/notification-endpoints/${body.targetRef}/verify`,
      headers: requestHeaders,
      payload,
    });
  return {
    app,
    workflow,
    options,
    authorize,
    authorization,
    verify,
    operation,
    body,
    headers,
    request,
  };
}

it.each([
  ['missing session', 'cookie', '', 401],
  ['missing CSRF', 'x-csrf-token', '', 400],
  ['malformed scope', 'openpc-participant-id', 'bad', 400],
  ['short idempotency key', 'idempotency-key', 'short', 400],
  ['conflicting digest', 'x-openpc-action-intent-digest', `sha256:${'2'.repeat(64)}`, 400],
  ['stale ETag', 'if-match', `"sha256:${'2'.repeat(64)}"`, 412],
] as const)('rejects %s before authorization or workflow', async (_name, field, value, status) => {
  const h = fixture();
  expect((await h.request(h.body, { ...h.headers, [field]: value })).statusCode).toBe(status);
  expect(h.authorize).not.toHaveBeenCalled();
  expect(h.verify).not.toHaveBeenCalled();
});

it('requires If-Match and rejects unknown fields and copied target bindings before workflow', async () => {
  const h = fixture();
  const headers = { ...h.headers };
  delete headers['if-match'];
  expect((await h.request(h.body, headers)).statusCode).toBe(428);
  for (const payload of [
    { ...h.body, credential: 'caller-supplied' },
    { ...h.body, targetRef: `urn:openpc:resource:${id(99)}` },
  ])
    expect((await h.request(payload)).statusCode).toBe(400);
  expect(h.authorize).not.toHaveBeenCalled();
  expect(h.verify).not.toHaveBeenCalled();
});

it.each(['denial', 'read-context', 'scope'] as const)(
  'retains real boundary responsibility on authorizer %s',
  async (failure) => {
    const h = fixture();
    if (failure === 'denial')
      h.authorize.mockRejectedValueOnce(new ConfigurationRepositoryError('PC-AUTH-0005'));
    else
      h.authorize.mockResolvedValueOnce({
        ...h.authorization,
        ...(failure === 'scope' ? { privacyDomainId: id(99) } : { evidenceKind: 'READ_CONTEXT' }),
      });
    expect((await h.request()).statusCode).toBe(403);
    expect(h.verify).not.toHaveBeenCalled();
  },
);

it('fails closed for missing workflow after request authorization', async () => {
  const h = fixture(false);
  const result = await h.request();
  expect(result.statusCode).toBe(503);
  expect(result.json()).toMatchObject({ code: 'PC-INTEGRATION-5001', truthState: 'UNAVAILABLE' });
  expect(h.authorize).toHaveBeenCalledTimes(1);
  expect(h.verify).not.toHaveBeenCalled();
});

it('binds the existing command and returns only the canonical Operation response', async () => {
  const h = fixture();
  const result = await h.request();
  expect(result.statusCode).toBe(202);
  expect(result.json()).toEqual(h.operation);
  expect(result.headers).toMatchObject({
    'cache-control': 'no-store',
    'openpc-api-version': '1',
    'x-request-id': id(6),
    'x-correlation-id': id(7),
  });
  expect(h.authorize).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({
      sessionToken: 'session',
      resourceId: id(3),
      participantId: id(1),
      privacyDomainId: id(2),
      actionIntentId: h.body.actionIntentId,
      actionIntentDigest: hash,
      candidateDigest: sha256(h.body),
      catalogOperationId: 'CFG-OP-VERIFY-NOTIFICATION-ENDPOINT',
      expectedRevision: '2',
      idempotencyKey: h.operation.idempotencyKey,
      makerCheckerRequired: false,
      stepUpRequired: false,
    }),
  );
  expect(h.verify).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({
      authorization: h.authorization,
      candidate: h.body,
      resourceId: id(3),
      expectedRevision: '2',
      expectedEtag: h.headers['if-match'],
      catalogOperationId: 'CFG-OP-VERIFY-NOTIFICATION-ENDPOINT',
      idempotencyKey: h.operation.idempotencyKey,
      resourceType: 'notification-endpoint',
      operationClass: 'UPDATE',
    }),
    h.body,
  );
});

it.each([
  ['PC-FACT-4001', 409, 'UNKNOWN', false],
  ['PC-INTEGRATION-5001', 503, 'UNAVAILABLE', true],
  ['PC-DATA-6007', 412, 'STALE', false],
] as const)(
  'preserves %s truth without leaking private source or credential diagnostics',
  async (code, status, truthState, retryable) => {
    const h = fixture();
    h.verify.mockRejectedValueOnce(
      new ConfigurationRepositoryError(
        code,
        undefined,
        'PRIVATE source secret://local/reference#1',
      ),
    );
    const result = await h.request();
    expect(result.statusCode).toBe(status);
    const problem = result.json();
    expect(problem).toMatchObject({ code, truthState, retryable, traceId: id(6) });
    expect(Object.keys(problem).sort()).toEqual(
      ['code', 'retryable', 'status', 'title', 'traceId', 'truthState', 'type'].sort(),
    );
    expect(result.body).not.toContain('PRIVATE');
    expect(result.body).not.toContain('secret://');
    expect(h.verify).toHaveBeenCalledTimes(1);
  },
);
