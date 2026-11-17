import { NotificationWorkloadTransport } from '../../../identity-service/src/domain/notification-workload-transport.js';
import { Socket } from 'node:net';
import { TLSSocket } from 'node:tls';
import type { Pool, PoolClient } from 'pg';
import { afterEach, expect, it, vi } from 'vitest';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import type { NotificationCredentialLease } from '../../../identity-service/src/domain/notification-secret-recipient.js';
import { canonicalJson } from '../configuration/digest.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
  type OperationRecord,
} from '../configuration/persistence/types.js';
import { notificationVerificationIntentDigest } from './endpoint-verification-state.js';
import {
  NotificationEndpointVerificationWorkflow,
  type NotificationEndpointVerificationWorkflowOptions,
} from './endpoint-verification-workflow.js';

// Control-flow/fault doubles only. These tests cannot establish real Identity,
// PostgreSQL, TLS, provider authority or public journey acceptance.
const owners = vi.hoisted(() => ({
  prepare: vi.fn(),
  readOriginal: vi.fn(),
  dispatch: vi.fn(),
  verify: vi.fn(),
  authorize: vi.fn(),
  persistence: vi.fn(),
  scoped: vi.fn(),
  recipient: vi.fn(),
}));
vi.mock('./endpoint-verification-state.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./endpoint-verification-state.js')>()),
  NotificationEndpointVerificationState: vi.fn(function () {
    return {
      prepare: owners.prepare,
      readOriginal: owners.readOriginal,
      dispatch: owners.dispatch,
    };
  }),
}));
vi.mock('./endpoint-repository.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./endpoint-repository.js')>()),
  requireCanonicalEndpointPersistence: owners.persistence,
  NotificationEndpointRepository: vi.fn(function () {
    return { verify: owners.verify };
  }),
}));
vi.mock('./endpoint-admission.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./endpoint-admission.js')>()),
  authorizeNotificationPreparation: owners.authorize,
}));
vi.mock('../../../identity-service/src/db/scoped-transaction.js', () => ({
  runScopedTransaction: owners.scoped,
}));
vi.mock(
  '../../../identity-service/src/domain/notification-secret-recipient.js',
  async (importOriginal) => ({
    ...(await importOriginal<
      typeof import('../../../identity-service/src/domain/notification-secret-recipient.js')
    >()),
    withNotificationSecretRecipient: owners.recipient,
  }),
);
const peers: TLSSocket[] = [];
afterEach(() => {
  for (const peer of peers.splice(0)) peer.destroy();
  vi.useRealTimers();
  vi.restoreAllMocks();
  for (const owner of Object.values(owners)) owner.mockReset();
});
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = `sha256:${'1'.repeat(64)}`;
type AttemptState = 'PREPARED' | 'DISPATCHED' | 'UNKNOWN' | 'PROVED' | 'REJECTED' | 'ATTACHED';
type RecipientUse = (lease: NotificationCredentialLease) => Promise<unknown>;

function fixture() {
  const order: string[] = [];
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
  peer.authorized = true;
  vi.spyOn(peer, 'getProtocol').mockReturnValue('TLSv1.3');
  const closeListeners = peer.listenerCount('close');
  const options: NotificationEndpointVerificationWorkflowOptions = {
    pool: pool(),
    recipientPool: pool(),
    workloadPeer: peer,
    kernel: { authenticateWorkload: vi.fn() } as unknown as IdentityKernel,
    identityRuntimeVerifier: {
      verifyCanonicalAssertion: vi.fn(),
    } as unknown as IdentityRuntimeVerifier,
    businessEvidence: { environmentId: 'local', signer: { sign: vi.fn() } },
    credentialProvider: { withExactVersion: vi.fn() },
    timeoutMs: 1000,
  };
  const body = {
    actionIntentId: 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
    actionIntentDigest: hash,
    targetRef: `urn:openpc:resource:${id(3)}`,
    expectedRevision: '2',
    inputDigest: hash,
    reason: 'Exercise verification workflow ordering.',
  };
  const context = {
    authorization: {
      participantId: id(1),
      privacyDomainId: id(2),
      principalId: id(4),
      sessionId: id(5),
      sessionEpoch: '1',
      evidenceKind: 'IDENTITY_RUNTIME',
    },
    candidate: body,
    resourceId: id(3),
    expectedRevision: '2',
    idempotencyKey: 'original-verification-key',
    actionIntentId: body.actionIntentId,
    actionIntentDigest: hash,
    catalogOperationId: 'CFG-OP-VERIFY-NOTIFICATION-ENDPOINT',
    aggregateType: 'notification-endpoint',
    resourceType: 'notification-endpoint',
    operationClass: 'UPDATE',
  } as unknown as MutationContext;
  const now = Date.now();
  const challenge = {
    version: 'NotificationVerificationChallengeV1',
    challengeId: id(6),
    nonce: 'aa'.repeat(32),
    environmentId: 'local',
    predecessor: {
      participantId: id(1),
      privacyDomainId: id(2),
      endpointId: id(3),
      revision: '2',
      channel: 'WEBHOOK',
      destinationRef: `urn:openpc:resource:${id(7)}`,
      channelProfileDigest: hash,
      credentialRef: `urn:openpc:resource:${id(8)}`,
    },
    resultRevision: '3',
    credential: {
      participantId: id(1),
      privacyDomainId: id(2),
      credentialRef: `urn:openpc:resource:${id(8)}`,
      channel: 'WEBHOOK',
      destinationRef: `urn:openpc:resource:${id(7)}`,
      secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
      owner: 'LS-NOTIFICATION',
      reference: 'secret://local/notification-mtls#1',
      version: '1',
      fingerprint: hash,
      epoch: '1',
      validFromMs: now - 1000,
      validUntilMs: now + 60000,
      state: 'ACTIVE',
    },
    signedVerificationProfileDigest: hash,
    principalId: id(4),
    inputDigest: hash,
    businessIdempotencyDigest: notificationVerificationIntentDigest(context),
    issuedAtMs: now - 100,
    expiresAtMs: now + 5000,
  };
  const original = {
    attemptId: id(6),
    state: 'PREPARED' as AttemptState,
    operationId: null,
    challengeBytes: Buffer.from(canonicalJson({ challenge })),
    responseBytes: null,
  };
  const operation: OperationRecord = {
    operationId: id(9),
    resourceRef: body.targetRef,
    actionIntentId: body.actionIntentId,
    intentDigest: hash,
    idempotencyKey: context.idempotencyKey,
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    createdAt: '2026-09-24T00:00:00.000000Z',
    updatedAt: '2026-09-24T00:00:00.000000Z',
    revision: '3',
  };
  // Opaque sentinel travels only between mocked owners; never a production lease.
  const lease = {} as NotificationCredentialLease;
  owners.scoped.mockImplementation(
    async (
      _pool: unknown,
      _scope: unknown,
      _id: unknown,
      use: (client: PoolClient) => Promise<unknown>,
    ) => use({} as PoolClient),
  );
  owners.authorize.mockImplementation(async () => {
    order.push('authorize');
  });
  owners.persistence.mockImplementation(async () => {
    order.push('persistence');
  });
  owners.prepare.mockImplementation(async () => {
    order.push('prepare');
    return { attemptId: id(6), state: 'PREPARED' };
  });
  owners.readOriginal.mockImplementation(async () => {
    order.push('read');
    return original;
  });
  owners.dispatch.mockImplementation(async () => {
    order.push('dispatch');
    return 'PROVED';
  });
  owners.recipient.mockImplementation(
    async (
      _pool: unknown,
      _kernel: unknown,
      _peer: unknown,
      _request: unknown,
      _provider: unknown,
      use: RecipientUse,
    ) => {
      order.push('recipient-enter');
      try {
        return await use(lease);
      } finally {
        order.push('recipient-exit');
      }
    },
  );
  owners.verify.mockImplementation(async () => {
    order.push('attach');
    return operation;
  });
  const workflow = new NotificationEndpointVerificationWorkflow(options);
  return {
    options,
    peer,
    closeListeners,
    body,
    context,
    challenge,
    original,
    operation,
    lease,
    workflow,
    order,
    rewrite: () => {
      original.challengeBytes = Buffer.from(canonicalJson({ challenge }));
    },
  };
}

it('requires bounded distinct pools and concrete composition rather than a caller authority callback', () => {
  const h = fixture();
  const changes = [
    { recipientPool: h.options.pool },
    { recipientPool: { options: {}, connect: vi.fn() } as unknown as Pool },
    { workloadPeer: { authorized: true, getProtocol: () => 'TLSv1.3' } as unknown as TLSSocket },
    { timeoutMs: 0 },
    { timeoutMs: 30001 },
    { credentialProvider: undefined },
    { identityRuntimeVerifier: undefined },
    { businessEvidence: undefined },
  ];
  for (const change of changes)
    expect(
      () =>
        new NotificationEndpointVerificationWorkflow({
          ...h.options,
          ...change,
        } as NotificationEndpointVerificationWorkflowOptions),
    ).toThrow('PC-INTEGRATION-5001');
  expect(owners.prepare).not.toHaveBeenCalled();
  expect(owners.recipient).not.toHaveBeenCalled();
});

it('rejects changed request input before source admission or egress', async () => {
  const h = fixture();
  await expect(
    h.workflow.verify(h.context, { ...h.body, inputDigest: `sha256:${'2'.repeat(64)}` }),
  ).rejects.toThrow('PC-DATA-6007');
  expect(owners.scoped).not.toHaveBeenCalled();
  expect(owners.prepare).not.toHaveBeenCalled();
  expect(owners.recipient).not.toHaveBeenCalled();
});

it.each(['authorize', 'persistence', 'prepare'] as const)(
  'retains %s denial before any lease or final mutation',
  async (owner) => {
    const h = fixture();
    const error = new ConfigurationRepositoryError(
      owner === 'persistence' ? 'PC-INTEGRATION-5001' : 'PC-AUTH-0005',
    );
    owners[owner].mockRejectedValueOnce(error);
    await expect(h.workflow.verify(h.context, h.body)).rejects.toBe(error);
    if (owner !== 'prepare') expect(owners.prepare).not.toHaveBeenCalled();
    expect(owners.readOriginal).not.toHaveBeenCalled();
    expect(owners.recipient).not.toHaveBeenCalled();
    expect(owners.verify).not.toHaveBeenCalled();
  },
);

it.each(['PROVED', 'ATTACHED'] as const)(
  'uses the atomic owner for retained %s without another lease or network request',
  async (state) => {
    const h = fixture();
    owners.prepare.mockResolvedValueOnce({ attemptId: id(6), state });
    expect(await h.workflow.verify(h.context, h.body)).toBe(h.operation);
    expect(owners.readOriginal).not.toHaveBeenCalled();
    expect(owners.recipient).not.toHaveBeenCalled();
    expect(owners.dispatch).not.toHaveBeenCalled();
    expect(owners.verify).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ idempotencyKey: h.context.idempotencyKey, candidate: h.body }),
      h.body,
    );
  },
);

it.each(['DISPATCHED', 'UNKNOWN'] as const)(
  'keeps retained %s unresolved without a fabricated operation or resend',
  async (state) => {
    const h = fixture();
    owners.prepare.mockResolvedValueOnce({ attemptId: id(6), state });
    await expect(h.workflow.verify(h.context, h.body)).rejects.toMatchObject({
      code: 'PC-FACT-4001',
      statusOverride: 409,
    });
    expect(owners.recipient).not.toHaveBeenCalled();
    expect(owners.dispatch).not.toHaveBeenCalled();
    expect(owners.verify).not.toHaveBeenCalled();
  },
);

it.each(['PROVED', 'ATTACHED', 'UNKNOWN', 'REJECTED'] as const)(
  'honors the owner readback race to %s before acquiring a lease',
  async (state) => {
    const h = fixture();
    h.original.state = state;
    if (state === 'PROVED' || state === 'ATTACHED')
      expect(await h.workflow.verify(h.context, h.body)).toBe(h.operation);
    else
      await expect(h.workflow.verify(h.context, h.body)).rejects.toMatchObject({
        code: state === 'UNKNOWN' ? 'PC-FACT-4001' : 'PC-DATA-6007',
      });
    expect(owners.recipient).not.toHaveBeenCalled();
    expect(owners.dispatch).not.toHaveBeenCalled();
  },
);

it('derives the exact recipient request from retained bytes and exits the recipient before atomic attachment', async () => {
  const h = fixture();
  expect(await h.workflow.verify(h.context, h.body)).toBe(h.operation);
  expect(h.order).toEqual([
    'authorize',
    'persistence',
    'prepare',
    'read',
    'recipient-enter',
    'dispatch',
    'recipient-exit',
    'attach',
  ]);
  expect(owners.recipient).toHaveBeenCalledExactlyOnceWith(
    h.options.recipientPool,
    h.options.kernel,
    h.peer,
    {
      participantId: id(1),
      privacyDomainId: id(2),
      credentialRef: `urn:openpc:resource:${id(8)}`,
      reference: 'secret://local/notification-mtls#1',
      version: '1',
      epoch: '1',
    },
    h.options.credentialProvider,
    expect.any(Function),
  );
  expect(owners.dispatch).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({ candidate: h.body }),
    id(6),
    h.lease,
    expect.objectContaining({ timeoutMs: 1000, signal: expect.any(AbortSignal) }),
  );
  expect(h.peer.listenerCount('close')).toBe(h.closeListeners);
});

it.each([
  'attempt',
  'participant',
  'privacy',
  'endpoint',
  'revision',
  'principal',
  'input',
  'intent',
] as const)('rejects copied %s bindings before physical material access', async (field) => {
  const h = fixture();
  if (field === 'attempt') h.original.attemptId = id(99);
  if (field === 'participant') h.challenge.credential.participantId = id(99);
  if (field === 'privacy') h.challenge.credential.privacyDomainId = id(99);
  if (field === 'endpoint') h.challenge.predecessor.endpointId = id(99);
  if (field === 'revision') {
    h.challenge.predecessor.revision = '3';
    h.challenge.resultRevision = '4';
  }
  if (field === 'principal') h.challenge.principalId = id(99);
  if (field === 'input') h.challenge.inputDigest = `sha256:${'2'.repeat(64)}`;
  if (field === 'intent') h.challenge.businessIdempotencyDigest = `sha256:${'2'.repeat(64)}`;
  h.rewrite();
  await expect(h.workflow.verify(h.context, h.body)).rejects.toThrow('PC-DATA-6007');
  expect(owners.recipient).not.toHaveBeenCalled();
  expect(owners.verify).not.toHaveBeenCalled();
});

it('does not renew an expired original challenge', async () => {
  const h = fixture();
  h.challenge.expiresAtMs = Date.now() - 1;
  h.rewrite();
  await expect(h.workflow.verify(h.context, h.body)).rejects.toThrow('PC-DATA-6007');
  expect(owners.prepare).toHaveBeenCalledTimes(1);
  expect(owners.recipient).not.toHaveBeenCalled();
});

it('requires a currently authorized workload transport before borrowing material', async () => {
  const h = fixture();
  h.peer.authorized = false;
  await expect(h.workflow.verify(h.context, h.body)).rejects.toThrow('PC-INTEGRATION-5001');
  expect(owners.recipient).not.toHaveBeenCalled();
  expect(owners.dispatch).not.toHaveBeenCalled();
});

it('does not accept a provider/recipient return value in place of an executed source dispatch', async () => {
  const h = fixture();
  owners.recipient.mockResolvedValueOnce('PROVED');
  await expect(h.workflow.verify(h.context, h.body)).rejects.toThrow('PC-INTEGRATION-5001');
  expect(owners.dispatch).not.toHaveBeenCalled();
  expect(owners.verify).not.toHaveBeenCalled();
});

it('redacts a physical-provider failure before the dispatch callback', async () => {
  const h = fixture();
  owners.recipient.mockRejectedValueOnce(new Error('PRIVATE-KEY synthetic-provider-diagnostic'));
  const [result] = await Promise.allSettled([h.workflow.verify(h.context, h.body)]);
  expect(result?.status).toBe('rejected');
  if (result?.status !== 'rejected') throw new Error('Unexpected workflow success');
  expect(result.reason).toMatchObject({
    code: 'PC-INTEGRATION-5001',
    message: 'PC-INTEGRATION-5001',
  });
  expect(result.reason.cause).toBeUndefined();
  expect(owners.verify).not.toHaveBeenCalled();
});

it.each(['dispatch', 'recipient-exit'] as const)(
  'preserves uncertainty after %s failure without final mutation or automatic retry',
  async (failure) => {
    const h = fixture();
    if (failure === 'dispatch')
      owners.dispatch.mockRejectedValueOnce(new Error('commit outcome unknown'));
    else
      owners.recipient.mockImplementationOnce(
        async (
          _p: unknown,
          _k: unknown,
          _s: unknown,
          _r: unknown,
          _provider: unknown,
          use: RecipientUse,
        ) => {
          await use(h.lease);
          throw new Error('recipient currentness lost');
        },
      );
    await expect(h.workflow.verify(h.context, h.body)).rejects.toMatchObject({
      code: 'PC-FACT-4001',
    });
    expect(owners.dispatch).toHaveBeenCalledTimes(1);
    expect(owners.verify).not.toHaveBeenCalled();
  },
);

it('a repeated recipient callback cannot dispatch twice even if the provider swallows its rejection', async () => {
  const h = fixture();
  owners.recipient.mockImplementationOnce(
    async (
      _p: unknown,
      _k: unknown,
      _s: unknown,
      _r: unknown,
      _provider: unknown,
      use: RecipientUse,
    ) => {
      await use(h.lease);
      await use(h.lease).catch(() => undefined);
    },
  );
  await expect(h.workflow.verify(h.context, h.body)).rejects.toThrow('PC-FACT-4001');
  expect(owners.dispatch).toHaveBeenCalledTimes(1);
  expect(owners.verify).not.toHaveBeenCalled();
});

it('a timed-out physical acquisition cannot enter dispatch later', async () => {
  vi.useFakeTimers();
  const h = fixture();
  let use!: RecipientUse, finish!: () => void;
  owners.recipient.mockImplementationOnce(
    (
      _p: unknown,
      _k: unknown,
      _s: unknown,
      _r: unknown,
      _provider: unknown,
      callback: RecipientUse,
    ) => {
      use = callback;
      return new Promise<void>((resolve) => {
        finish = resolve;
      });
    },
  );
  const result = Promise.allSettled([h.workflow.verify(h.context, h.body)]);
  await vi.advanceTimersByTimeAsync(1001);
  expect(await result).toMatchObject([
    { status: 'rejected', reason: { code: 'PC-INTEGRATION-5001' } },
  ]);
  await expect(use(h.lease)).rejects.toThrow('no longer usable');
  finish();
  await Promise.resolve();
  expect(owners.dispatch).not.toHaveBeenCalled();
  expect(owners.verify).not.toHaveBeenCalled();
});

it('timeout exits the recipient callback and leaves late dispatch settlement unresolved', async () => {
  vi.useFakeTimers();
  const h = fixture();
  let finish!: (state: string) => void;
  owners.dispatch.mockImplementationOnce(
    () =>
      new Promise<string>((resolve) => {
        finish = resolve;
      }),
  );
  const result = Promise.allSettled([h.workflow.verify(h.context, h.body)]);
  await vi.advanceTimersByTimeAsync(1001);
  expect(await result).toMatchObject([{ status: 'rejected', reason: { code: 'PC-FACT-4001' } }]);
  expect(h.order).toContain('recipient-exit');
  finish('PROVED');
  await Promise.resolve();
  expect(owners.dispatch).toHaveBeenCalledTimes(1);
  expect(owners.verify).not.toHaveBeenCalled();
});

it('atomic attachment failure is preserved and an original PROVED retry never redispatches', async () => {
  const h = fixture();
  const denial = Object.freeze(new ConfigurationRepositoryError('PC-AUTH-0005'));
  owners.verify.mockRejectedValueOnce(denial);
  await expect(h.workflow.verify(h.context, h.body)).rejects.toBe(denial);
  owners.prepare.mockResolvedValueOnce({ attemptId: id(6), state: 'PROVED' });
  expect(await h.workflow.verify(h.context, h.body)).toBe(h.operation);
  expect(owners.recipient).toHaveBeenCalledTimes(1);
  expect(owners.dispatch).toHaveBeenCalledTimes(1);
});

it('a concurrent caller observes DISPATCHED and the later exact replay returns the original operation', async () => {
  const h = fixture();
  let state: AttemptState = 'PREPARED',
    entered!: () => void,
    finish!: () => void;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const completed = new Promise<void>((resolve) => {
    finish = resolve;
  });
  owners.prepare.mockImplementation(async () => ({ attemptId: id(6), state }));
  owners.dispatch.mockImplementationOnce(async () => {
    state = 'DISPATCHED';
    entered();
    await completed;
    state = 'PROVED';
    return state;
  });
  const first = h.workflow.verify(h.context, h.body);
  await started;
  try {
    await expect(h.workflow.verify(h.context, h.body)).rejects.toThrow('PC-FACT-4001');
  } finally {
    finish();
  }
  expect(await first).toBe(h.operation);
  state = 'ATTACHED';
  expect(await h.workflow.verify(h.context, h.body)).toBe(h.operation);
  expect(owners.dispatch).toHaveBeenCalledTimes(1);
});

it('uses the concrete transport owner before the unchanged real-recipient boundary', async () => {
  const h = fixture();
  // Control-flow mock only; real accepted sockets are covered by transport/PG tests.
  const transport = Object.create(
    NotificationWorkloadTransport.prototype,
  ) as NotificationWorkloadTransport;
  const borrow = vi.fn(async (_credential: unknown, use: (peer: TLSSocket) => Promise<unknown>) =>
    use(h.peer),
  );
  Object.defineProperty(transport, 'withPeer', { value: borrow });
  const workflow = new NotificationEndpointVerificationWorkflow({
    ...h.options,
    workloadPeer: transport,
  });
  expect(await workflow.verify(h.context, h.body)).toEqual(h.operation);
  expect(borrow).toHaveBeenCalledWith(h.challenge.credential, expect.any(Function));
  expect(owners.recipient).toHaveBeenCalledTimes(1);
});
it('keeps missing transport unavailable without dispatch and never consults it for an original UNKNOWN', async () => {
  const h = fixture(),
    transport = Object.create(
      NotificationWorkloadTransport.prototype,
    ) as NotificationWorkloadTransport;
  const borrow = vi.fn().mockRejectedValue(new Error('no live peer'));
  Object.defineProperty(transport, 'withPeer', { value: borrow });
  const workflow = new NotificationEndpointVerificationWorkflow({
    ...h.options,
    workloadPeer: transport,
  });
  await expect(workflow.verify(h.context, h.body)).rejects.toMatchObject({
    code: 'PC-INTEGRATION-5001',
  });
  expect(owners.recipient).not.toHaveBeenCalled();
  expect(owners.dispatch).not.toHaveBeenCalled();
  borrow.mockClear();
  owners.prepare.mockResolvedValue({ attemptId: h.challenge.challengeId, state: 'UNKNOWN' });
  await expect(workflow.verify(h.context, h.body)).rejects.toMatchObject({ code: 'PC-FACT-4001' });
  expect(borrow).not.toHaveBeenCalled();
});
it('preserves ambiguity if transport closes after borrowing instead of returning a false no-effect failure', async () => {
  const h = fixture(),
    transport = Object.create(
      NotificationWorkloadTransport.prototype,
    ) as NotificationWorkloadTransport;
  Object.defineProperty(transport, 'withPeer', {
    value: vi.fn(async (_credential: unknown, use: (peer: TLSSocket) => Promise<unknown>) => {
      await use(h.peer);
      throw new Error('peer closed');
    }),
  });
  const workflow = new NotificationEndpointVerificationWorkflow({
    ...h.options,
    workloadPeer: transport,
  });
  await expect(workflow.verify(h.context, h.body)).rejects.toMatchObject({ code: 'PC-FACT-4001' });
  expect(owners.dispatch).toHaveBeenCalledTimes(1);
  expect(owners.verify).not.toHaveBeenCalled();
});
