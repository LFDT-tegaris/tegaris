import type { Pool } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import type { AuthorityContext } from '../../../services/identity-service/src/contracts/authorization.js';
import {
  FullyScopedPendingDeliveryIdentity,
  type PendingDeliveryReceipt,
  SafePendingScope,
} from '../../../services/identity-service/src/contracts/pending-delivery.js';
import {
  type IdentityAuthorityEvaluationExecutor,
  type PendingDeliveryDiagnosticSink,
  PendingDeliveryKernel,
  type PendingDeliveryRepository,
} from '../../../services/identity-service/src/domain/pending-delivery-kernel.js';
import {
  runScopedTransaction,
  ScopedTransactionSecurityError,
} from '../../../services/identity-service/src/db/scoped-transaction.js';

const uuidA = '018f6d4a-1234-7abc-8def-0123456789ab';
const uuidB = '018f6d4a-1234-7abc-9def-0123456789ac';
const uuidC = '018f6d4a-1234-7abc-adef-0123456789ad';
const digest = `sha256:${'a'.repeat(64)}` as const;
const timestamp = '2026-09-05T00:00:00.000000Z';

const scope = SafePendingScope.create({
  participantId: `urn:openpc:participant:${uuidA}`,
  privacyDomainId: `urn:openpc:privacy-domain:${uuidB}`,
  chainId: '1',
  profileId: `urn:openpc:profile:${uuidC}`,
  profileVersion: '1.0.0',
  deliverySurface: 'HTTP',
});
const authorityContext: AuthorityContext = {
  principalId: `urn:openpc:principal:${uuidA}`,
  participantId: scope.value.participantId,
  privacyDomainId: scope.value.privacyDomainId,
  sessionId: `urn:openpc:session:${uuidA}`,
  authorityEnvelopeId: `urn:openpc:authority-envelope:${uuidA}`,
  authorityEpoch: '1',
  delegationEpoch: '1',
  actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
  policyGenerationDigest: digest,
  factGenerationDigest: digest,
};
const receipt: PendingDeliveryReceipt = {
  pendingDeliveryId: uuidC,
  state: 'PENDING',
  replay: false,
};

function identity() {
  return FullyScopedPendingDeliveryIdentity.create({
    ...scope.value,
    correlatedLogIdentityHmac: Buffer.alloc(32, 1),
    entityHmac: Buffer.alloc(32, 2),
    entityScopeDigest: Buffer.alloc(32, 3),
    protectedDeliveryReferenceDigest: Buffer.alloc(32, 4),
  });
}

function repository(overrides: Partial<PendingDeliveryRepository> = {}): PendingDeliveryRepository {
  return {
    enqueue: vi.fn(async () => receipt),
    transition: vi.fn(async () => receipt),
    summarize: vi.fn(async () => ({
      pendingCount: '1',
      oldestPendingAgeMilliseconds: '5',
      asOf: timestamp,
    })),
    ...overrides,
  };
}

function allow(): IdentityAuthorityEvaluationExecutor {
  return {
    async evaluate(request) {
      return {
        decision: 'ALLOW',
        authorized: true,
        terminal: false,
        existenceVisible: true,
        payloadVisible: true,
        authorityContext: request.authorityContext,
        inputsDigest: request.inputsDigest,
        evaluatedAt: timestamp,
        explanationCodes: ['AUTHORITY_ALLOW'],
        traceSetId: 'TS-ID-AUTHORIZATION',
      };
    },
  };
}

function diagnosticCollector() {
  const diagnostics: Parameters<PendingDeliveryDiagnosticSink['record']>[0][] = [];
  return {
    diagnostics,
    sink: {
      record: (diagnostic) => diagnostics.push(diagnostic),
    } satisfies PendingDeliveryDiagnosticSink,
  };
}

interface ScopedGuard {
  action_intent_id: string | null;
  bypass: boolean;
  context_mode: string | null;
  context_scope: string | null;
  operation_id: string | null;
  participant_id: string | null;
  privacy_domain_id: string | null;
  row_security: string;
  superuser: boolean;
}

const exactScopedGuard: ScopedGuard = {
  action_intent_id: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
  bypass: false,
  context_mode: 'PARTICIPANT',
  context_scope: 'TRANSACTION_LOCAL',
  operation_id: uuidC,
  participant_id: uuidA,
  privacy_domain_id: uuidB,
  row_security: 'on',
  superuser: false,
} as const;

function fakeScopedPool(clean: boolean, guardOverrides: Partial<ScopedGuard> = {}) {
  const release = vi.fn();
  const query = vi.fn(async (sql: string) => {
    if (sql.includes(' as clean')) return { rows: [{ clean }] };
    if (sql.includes('from pg_roles')) {
      return {
        rows: [{ ...exactScopedGuard, ...guardOverrides }],
      };
    }
    return { rows: [] };
  });
  const pool = {
    connect: async () => ({ query, release }),
  } as unknown as Pool;
  return { pool, query, release };
}

describe('P00 pending-delivery kernel', () => {
  it('delegates enqueue and every exact lifecycle transition', async () => {
    const store = repository();
    const kernel = new PendingDeliveryKernel(store, allow());
    await expect(kernel.enqueue(identity())).resolves.toEqual(receipt);
    await kernel.lease(identity());
    await kernel.deliver(identity());
    await kernel.retry(identity());
    await kernel.quarantine(identity(), 'PENDING_STATE_CONFLICT');
    expect(store.transition).toHaveBeenNthCalledWith(1, expect.anything(), { kind: 'LEASE' });
    expect(store.transition).toHaveBeenNthCalledWith(2, expect.anything(), { kind: 'DELIVER' });
    expect(store.transition).toHaveBeenNthCalledWith(3, expect.anything(), {
      kind: 'RETRY_WAIT',
    });
    expect(store.transition).toHaveBeenNthCalledWith(4, expect.anything(), {
      kind: 'QUARANTINE',
      reason: 'PENDING_STATE_CONFLICT',
    });
  });

  it('authorizes the complete scope before reading and returns only the safe aggregate', async () => {
    const store = repository();
    const evaluate = vi.fn(allow().evaluate);
    await expect(
      new PendingDeliveryKernel(store, { evaluate }).summary(scope, authorityContext),
    ).resolves.toEqual({
      pendingCount: '1',
      oldestPendingAgeMilliseconds: '5',
      asOf: timestamp,
    });
    expect(evaluate).toHaveBeenCalledOnce();
    expect(store.summarize).toHaveBeenCalledOnce();
    expect(
      Object.keys(
        await new PendingDeliveryKernel(store, { evaluate }).summary(scope, authorityContext),
      ),
    ).toEqual(['pendingCount', 'oldestPendingAgeMilliseconds', 'asOf']);
  });

  it.each(['DENY', 'UNKNOWN', 'UNAVAILABLE'] as const)(
    'makes %s terminal, non-disclosing, and pre-store',
    async (decision) => {
      const store = repository();
      const authority: IdentityAuthorityEvaluationExecutor = {
        async evaluate(request) {
          return {
            decision,
            authorized: false,
            terminal: true,
            existenceVisible: false,
            payloadVisible: false,
            authorityContext: request.authorityContext,
            inputsDigest: request.inputsDigest,
            evaluatedAt: timestamp,
            explanationCodes: ['AUTHORITY_DENY'],
            traceSetId: 'TS-ID-AUTHORIZATION',
          };
        },
      };
      const { diagnostics, sink } = diagnosticCollector();
      await expect(
        new PendingDeliveryKernel(store, authority, sink).summary(scope, authorityContext),
      ).rejects.toMatchObject({ code: 'PC-RUNTIME-3001' });
      expect(diagnostics).toEqual([{ code: 'PC-RUNTIME-3001', reason: 'PENDING_SCOPE_INVALID' }]);
      expect(store.summarize).not.toHaveBeenCalled();
    },
  );

  it('rejects cross-scope, digest, action, and ALLOW-invariant drift before store access', async () => {
    const mutations = [
      {
        authorityContext: { ...authorityContext, participantId: `urn:openpc:participant:${uuidC}` },
      },
      { inputsDigest: `sha256:${'b'.repeat(64)}` },
      {
        authorityContext: { ...authorityContext, actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' },
      },
      { terminal: true },
    ];
    for (const mutation of mutations) {
      const store = repository();
      const authority: IdentityAuthorityEvaluationExecutor = {
        async evaluate(request) {
          return {
            decision: 'ALLOW',
            authorized: true,
            terminal: false,
            existenceVisible: true,
            payloadVisible: true,
            authorityContext: request.authorityContext,
            inputsDigest: request.inputsDigest,
            evaluatedAt: timestamp,
            explanationCodes: ['AUTHORITY_ALLOW'],
            traceSetId: 'TS-ID-AUTHORIZATION',
            ...mutation,
          };
        },
      };
      const { diagnostics, sink } = diagnosticCollector();
      await expect(
        new PendingDeliveryKernel(store, authority, sink).summary(scope, authorityContext),
      ).rejects.toMatchObject({ code: 'PC-RUNTIME-3001' });
      expect(diagnostics).toEqual([{ code: 'PC-RUNTIME-3001', reason: 'PENDING_SCOPE_INVALID' }]);
      expect(store.summarize).not.toHaveBeenCalled();
    }
  });

  it('collapses raw store failures while sending reasons only to the internal sink', async () => {
    const broken = repository({
      enqueue: async () => {
        throw new Error('postgresql secret detail');
      },
      transition: async () => {
        throw new Error('row and SQL text');
      },
      summarize: async () => {
        throw new Error('database host');
      },
    });
    const { diagnostics, sink } = diagnosticCollector();
    const kernel = new PendingDeliveryKernel(broken, allow(), sink);
    await expect(kernel.enqueue(identity())).rejects.toMatchObject({
      code: 'PC-INTEGRATION-5001',
    });
    await expect(kernel.lease(identity())).rejects.toMatchObject({
      code: 'PC-INTEGRATION-5001',
    });
    await expect(kernel.summary(scope, authorityContext)).rejects.toMatchObject({
      code: 'PC-RUNTIME-3001',
    });
    expect(diagnostics).toEqual([
      { code: 'PC-INTEGRATION-5001', reason: 'PENDING_STORE_UNAVAILABLE' },
      { code: 'PC-INTEGRATION-5001', reason: 'PENDING_STATE_CONFLICT' },
      { code: 'PC-RUNTIME-3001', reason: 'PENDING_STORE_UNAVAILABLE' },
    ]);
    try {
      await kernel.enqueue(identity());
    } catch (error) {
      expect((error as Error).stack).toBeUndefined();
      expect(error).not.toHaveProperty('cause');
      expect(error).not.toHaveProperty('reason');
      expect(Object.keys(error as object)).toEqual([]);
      expect(JSON.stringify(error)).toBe('{}');
    }
  });

  it('rejects dirty checkout and exact-context drift before executing a scoped operation', async () => {
    const operation = vi.fn(async () => 'unreachable');
    const dirty = fakeScopedPool(false);
    await expect(
      runScopedTransaction(
        dirty.pool,
        {
          participantId: uuidA,
          privacyDomainId: uuidB,
          actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        },
        () => uuidC,
        operation,
      ),
    ).rejects.toBeInstanceOf(ScopedTransactionSecurityError);
    expect(operation).not.toHaveBeenCalled();
    expect(dirty.release).toHaveBeenCalledOnce();

    const drifts = [
      { participant_id: '018f6d4a-1234-7abc-bdef-0123456789ae' },
      { privacy_domain_id: '018f6d4a-1234-7abc-bdef-0123456789ae' },
      { operation_id: '018f6d4a-1234-7abc-bdef-0123456789ae' },
      { action_intent_id: 'ACT-IDENTITY_UPDATE_PENDING_DELIVERY-V1' },
      { context_mode: 'PLATFORM' },
      { context_scope: 'SESSION' },
      { row_security: 'off' },
    ];
    for (const drift of drifts) {
      const mismatched = fakeScopedPool(true, drift);
      await expect(
        runScopedTransaction(
          mismatched.pool,
          {
            participantId: uuidA,
            privacyDomainId: uuidB,
            actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
          },
          () => uuidC,
          operation,
        ),
      ).rejects.toBeInstanceOf(ScopedTransactionSecurityError);
      expect(mismatched.query.mock.calls.map(([sql]) => sql)).toContain(
        'set local row_security=on',
      );
    }
    expect(operation).not.toHaveBeenCalled();
  });
});
