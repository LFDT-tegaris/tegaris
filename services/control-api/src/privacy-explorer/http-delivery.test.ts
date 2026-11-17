import { readFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { Writable } from 'node:stream';

import { describe, expect, it } from 'vitest';

import {
  buildB5Harness,
  projectionFor,
} from '../../../../tests/privacy/i07-gate2-b5-test-support.js';
import type { ExplorerProjectionRequestV1 } from '../contracts/privacy-explorer-adapter.js';
import { sha256CanonicalJson } from './canonical.js';
import {
  appendPrivacyExplorerRouteAudit,
  type PrivacyExplorerRouteAuditFact,
} from './evidence-sink.js';
import {
  createPrivacyExplorerHttpApplication,
  createPrivacyExplorerHttpDelivery,
  createPrivacyExplorerCompletionIdentity,
} from './http-delivery.js';
import { createPrivacyExplorerService, type PrivacyExplorerReadResult } from './service.js';

const accepted = (value: unknown) => ({
  outcome: 'ACCEPTED',
  occurrenceId: (value as PrivacyExplorerReadResult).evidence.occurrenceId,
  scopeDigest: (value as PrivacyExplorerReadResult).evidence.scopeDigest,
  resultDigest: (value as PrivacyExplorerReadResult).evidence.resultDigest,
  recordDigest: sha256CanonicalJson((value as PrivacyExplorerReadResult).evidence),
});

const resultFixture = async () => {
  let candidate: ExplorerProjectionRequestV1 | undefined;
  const harness = buildB5Harness({
    implementation: {
      readGovernedProjection: (request, context) => {
        candidate = request;
        return Promise.resolve(projectionFor(request, context));
      },
    },
  });
  const result = await createPrivacyExplorerService(harness.port).read(harness.input);
  if (result.disposition !== 'RELEASED' || !candidate)
    throw new Error('missing released result fixture');
  return Object.freeze({ harness, result, candidate });
};

const sinks = (
  result: PrivacyExplorerReadResult,
  options: { conflict?: boolean; reject?: boolean; malformed?: boolean } = {},
) => {
  let evidenceCalls = 0;
  let auditCalls = 0;
  const events: unknown[] = [];
  return Object.freeze({
    evidenceSink: {
      append: async (evidence: PrivacyExplorerReadResult['evidence']) => {
        evidenceCalls += 1;
        if (options.reject) throw new Error('canary-evidence-failure');
        if (options.malformed) return { outcome: 'ACCEPTED' };
        const receipt = accepted({ evidence } as PrivacyExplorerReadResult);
        return options.conflict ? { ...receipt, outcome: 'CONFLICT' } : receipt;
      },
    },
    auditSink: {
      append: async (fact: unknown) => {
        auditCalls += 1;
        return {
          outcome: 'ACCEPTED',
          attemptId: (fact as { attemptId: string }).attemptId,
          auditDigest: sha256CanonicalJson(fact),
        };
      },
    },
    eventSink: {
      emit: async (event: unknown) => {
        events.push(event);
      },
    },
    evidenceCalls: () => evidenceCalls,
    auditCalls: () => auditCalls,
    events: () => structuredClone(events),
  });
};

const waitFor = async (predicate: () => boolean, message: string) => {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(message);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
};

describe('Privacy Explorer route-audit receipt matrix', () => {
  const facts: readonly PrivacyExplorerRouteAuditFact[] = [
    { phase: 'ADMISSION_REJECTED', attemptId: 'attempt-a' },
    { phase: 'ADMISSION_SUPPRESSED', attemptId: 'attempt-b' },
    {
      phase: 'EXECUTION_REJECTED',
      attemptId: 'attempt-c',
      occurrenceId: 'occurrence-c',
      correlationId: 'correlation-c',
    },
  ];
  const adversaries = [
    ['outcome', (value: Record<string, unknown>) => ({ ...value, outcome: 'CONFLICT' })],
    ['cross-attempt', (value: Record<string, unknown>) => ({ ...value, attemptId: 'other' })],
    ['digest', (value: Record<string, unknown>) => ({ ...value, auditDigest: 'other' })],
    ['missing', (value: Record<string, unknown>) => ({ outcome: value.outcome })],
    ['extra', (value: Record<string, unknown>) => ({ ...value, raw: 'forbidden' })],
    [
      'accessor',
      (value: Record<string, unknown>) =>
        Object.defineProperty({ ...value }, 'auditDigest', {
          enumerable: true,
          get: () => value.auditDigest,
        }),
    ],
    ['proxy', (value: Record<string, unknown>) => new Proxy(value, {})],
    [
      'prototype',
      (value: Record<string, unknown>) => Object.assign(Object.create({ inherited: true }), value),
    ],
  ] as const;

  for (const fact of facts) {
    it(`accepts the exact ${fact.phase} receipt`, async () => {
      await expect(
        appendPrivacyExplorerRouteAudit(
          {
            append: async () => ({
              outcome: 'ACCEPTED',
              attemptId: fact.attemptId,
              auditDigest: sha256CanonicalJson(fact),
            }),
          },
          fact,
        ),
      ).resolves.toBeUndefined();
    });
    for (const [name, mutate] of adversaries) {
      it(`rejects ${name} for ${fact.phase}`, async () => {
        const receipt = {
          outcome: 'ACCEPTED',
          attemptId: fact.attemptId,
          auditDigest: sha256CanonicalJson(fact),
        };
        await expect(
          appendPrivacyExplorerRouteAudit({ append: async () => mutate(receipt) }, fact),
        ).rejects.toThrow();
      });
    }
  }
});

describe('Privacy Explorer evidence-before-delivery owner', () => {
  it('does not release until the exact evidence receipt is accepted', async () => {
    const { harness, result } = await resultFixture();
    let resolveReceipt!: (value: unknown) => void;
    const receipt = new Promise<unknown>((resolve) => {
      resolveReceipt = resolve;
    });
    const auditSink = {
      append: async (fact: unknown) => ({
        outcome: 'ACCEPTED',
        auditDigest: sha256CanonicalJson(fact),
      }),
    };
    const delivery = createPrivacyExplorerHttpDelivery({
      evidenceSink: { append: async () => receipt },
      eventSink: { emit: async () => undefined },
      maximumSinkWaitMilliseconds: 1_000,
      auditSink,
    });
    const pending = delivery.complete(
      createPrivacyExplorerCompletionIdentity(harness.input),
      result,
    );
    let settled = false;
    void pending.then(() => {
      settled = true;
    });
    await Promise.resolve();
    expect(settled).toBe(false);
    resolveReceipt(accepted(result));
    await expect(pending).resolves.toMatchObject({ kind: 'RELEASE', response: result.response });
  });

  it.each([
    ['rejects', { reject: true }, 'EVIDENCE_FAILURE'],
    ['returns a malformed receipt', { malformed: true }, 'EVIDENCE_FAILURE'],
    ['conflicts', { conflict: true }, 'CONFLICT'],
  ] as const)('does not release when the sink %s', async (_name, options, expected) => {
    const { harness, result } = await resultFixture();
    const port = sinks(result, options);
    const delivery = createPrivacyExplorerHttpDelivery({
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 1_000,
    });
    await expect(
      delivery.complete(createPrivacyExplorerCompletionIdentity(harness.input), result),
    ).resolves.toEqual({
      kind: expected,
    });
    expect(port.evidenceCalls()).toBe(1);
  });

  it.each(['outcome', 'occurrenceId', 'scopeDigest', 'resultDigest', 'recordDigest'] as const)(
    'rejects a field-isolated %s receipt mutation',
    async (field) => {
      const { harness, result } = await resultFixture();
      let calls = 0;
      const baseline = accepted(result);
      const delivery = createPrivacyExplorerHttpDelivery({
        evidenceSink: {
          append: async () => {
            calls += 1;
            return { ...baseline, [field]: `MUTATED_${field}` };
          },
        },
        auditSink: sinks(result).auditSink,
        eventSink: sinks(result).eventSink,
        maximumSinkWaitMilliseconds: 1_000,
      });
      await expect(
        delivery.complete(createPrivacyExplorerCompletionIdentity(harness.input), result),
      ).resolves.toEqual({ kind: 'EVIDENCE_FAILURE' });
      expect(calls).toBe(1);
    },
  );

  it('rejects copied, proxied, and field-mutated completion envelopes before the sink append', async () => {
    const { harness, result } = await resultFixture();
    const port = sinks(result);
    const delivery = createPrivacyExplorerHttpDelivery({
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 1_000,
    });
    const copied = Object.freeze({ ...result });
    const substituted = Object.freeze({
      ...result,
      evidence: Object.freeze({ ...result.evidence, requestDigest: `sha256:${'f'.repeat(64)}` }),
    });
    const proxy = new Proxy(result, {});
    for (const candidate of [copied, substituted, proxy]) {
      await expect(
        delivery.complete(
          createPrivacyExplorerCompletionIdentity(harness.input),
          candidate as PrivacyExplorerReadResult,
        ),
      ).resolves.toEqual({ kind: 'EVIDENCE_FAILURE' });
    }
    expect(port.evidenceCalls()).toBe(0);
  });

  it('persists cancellation evidence and suppresses its public delivery', async () => {
    const harness = buildB5Harness({
      implementation: { readGovernedProjection: async () => undefined },
    });
    const controller = new AbortController();
    controller.abort();
    const result = await createPrivacyExplorerService(harness.port).read({
      ...harness.input,
      signal: controller.signal,
    });
    expect(result.disposition).toBe('SUPPRESSED');
    const port = sinks(result);
    const delivery = createPrivacyExplorerHttpDelivery({
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 1_000,
    });
    await expect(
      delivery.complete(createPrivacyExplorerCompletionIdentity(harness.input), result),
    ).resolves.toEqual({
      kind: 'SUPPRESS',
    });
    expect(port.evidenceCalls()).toBe(1);
  });

  it.each([
    ['rejection', { reject: true }],
    ['malformed receipt', { malformed: true }],
    ['conflicting receipt', { conflict: true }],
  ] as const)('keeps a SUPPRESSED result closed after sink %s', async (_name, options) => {
    const harness = buildB5Harness({
      implementation: { readGovernedProjection: async () => undefined },
    });
    const cancelled = new AbortController();
    cancelled.abort();
    const result = await createPrivacyExplorerService(harness.port).read({
      ...harness.input,
      signal: cancelled.signal,
    });
    const port = sinks(result, options);
    const delivery = createPrivacyExplorerHttpDelivery({
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 20,
    });
    await expect(
      delivery.complete(createPrivacyExplorerCompletionIdentity(harness.input), result),
    ).resolves.toEqual({ kind: 'SUPPRESS' });
    expect(port.evidenceCalls()).toBe(1);
  });

  it('keeps a SUPPRESSED result closed when its sink never settles', async () => {
    const harness = buildB5Harness({
      implementation: { readGovernedProjection: async () => undefined },
    });
    const cancelled = new AbortController();
    cancelled.abort();
    const result = await createPrivacyExplorerService(harness.port).read({
      ...harness.input,
      signal: cancelled.signal,
    });
    const port = sinks(result);
    const delivery = createPrivacyExplorerHttpDelivery({
      evidenceSink: { append: async () => new Promise(() => {}) },
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 5,
    });
    await expect(
      delivery.complete(createPrivacyExplorerCompletionIdentity(harness.input), result),
    ).resolves.toEqual({ kind: 'SUPPRESS' });
  });
});

describe('Privacy Explorer public delivery route', () => {
  it.each([true, false])(
    'buffers the prepared result until final authority is %s',
    async (allowed) => {
      const { harness, candidate, result } = await resultFixture();
      const port = sinks(result);
      let beginRelease!: () => void;
      const releasing = new Promise<void>((resolve) => {
        beginRelease = resolve;
      });
      let decide!: () => void;
      const decision = new Promise<void>((resolve) => {
        decide = resolve;
      });
      let sent = false;
      let hookCalls = 0;
      const app = createPrivacyExplorerHttpApplication({
        admission: {
          resolveSession: () => true,
          resolveRequest: async () => ({
            context: harness.input.context,
            profile: harness.input.profile,
            serverMaximumDeadlineAt: '9999-12-31T23:59:59.000Z',
          }),
          clock: () => new Date(Date.parse(harness.input.seed.now) + 1),
          maximumRequestBytes: 65_536,
          maximumJsonDepth: 16,
        },
        prepare: async () => ({
          service: createPrivacyExplorerService(harness.port),
          evidenceSink: port.evidenceSink,
          async release(_result, enqueue) {
            beginRelease();
            await decision;
            if (!allowed) throw new Error('AUTHORITY_REVOKED_SECRET');
            enqueue();
          },
        }),
        auditSink: port.auditSink,
        eventSink: port.eventSink,
        maximumSinkWaitMilliseconds: 1_000,
      });
      app.addHook('onSend', async (_request, _reply, payload) => {
        hookCalls += 1;
        return payload;
      });
      try {
        const pending = app
          .inject({
            method: 'POST',
            url: '/v1/privacy-explorer/projections:read',
            headers: {
              'content-type': 'application/json',
              'cookie': '__Host-openpc_session=session-a',
            },
            payload: JSON.stringify(candidate),
          })
          .then((response) => {
            sent = true;
            return response;
          });
        await releasing;
        expect(sent).toBe(false);
        expect(port.evidenceCalls()).toBe(1);
        decide();
        const response = await pending;
        expect(response.statusCode).toBe(allowed ? 200 : 503);
        expect(response.headers['cache-control']).toBe('no-store');
        if (allowed) {
          expect(response.json()).toMatchObject({ records: [{ id: 'record-a' }] });
          expect(hookCalls).toBe(0);
        } else {
          expect(response.body).not.toContain('record-a');
          expect(response.body).not.toContain('AUTHORITY_REVOKED_SECRET');
        }
      } finally {
        decide();
        await app.close();
      }
    },
  );
  it.each([
    ['reject', async () => Promise.reject(new Error('audit-secret'))],
    ['malformed', async () => ({ outcome: 'ACCEPTED' })],
    ['never settle', async () => new Promise(() => {})],
  ] as const)('closes an admission when its audit sink %s', async (_name, append) => {
    const { harness, result } = await resultFixture();
    const port = sinks(result);
    const app = createPrivacyExplorerHttpApplication({
      admission: {
        resolveSession: () => harness.input.context,
        terminalAuthorizationVerifier: { verify: () => harness.input.context },
        profile: harness.input.profile,
        clock: () => new Date(Date.parse(harness.input.seed.now) + 1),
        maximumRequestBytes: 65_536,
        maximumJsonDepth: 16,
        serverMaximumDeadlineAt: '9999-12-31T23:59:59.000Z',
      },
      service: createPrivacyExplorerService(harness.port),
      evidenceSink: port.evidenceSink,
      auditSink: { append },
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 5,
    });
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/privacy-explorer/projections:read',
        headers: { 'content-type': 'application/json' },
        payload: '{}',
      });
      expect(response.statusCode).toBe(503);
      expect(response.headers['content-type']).toContain('application/problem+json');
      expect(response.json()).toMatchObject({ code: 'PC-RUNTIME-3010' });
      expect(port.evidenceCalls()).toBe(0);
      await waitFor(() => port.events().length === 1, 'audit failure event was not emitted');
      expect(port.events()[0]).toMatchObject({
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'AUDIT_FAILURE',
        errorClass: 'AUDIT_FAILURE',
      });
    } finally {
      await app.close();
    }
  });
  it('audits a pre-session disconnect and leaves no late public effect', async () => {
    const { harness, candidate, result } = await resultFixture();
    const port = sinks(result);
    let resolverStarted = false;
    let serviceCalls = 0;
    const app = createPrivacyExplorerHttpApplication({
      admission: {
        resolveSession: () => {
          resolverStarted = true;
          return new Promise(() => {});
        },
        terminalAuthorizationVerifier: { verify: () => harness.input.context },
        profile: harness.input.profile,
        clock: () => new Date(Date.parse(harness.input.seed.now) + 1),
        maximumRequestBytes: 65_536,
        maximumJsonDepth: 16,
        serverMaximumDeadlineAt: '9999-12-31T23:59:59.000Z',
      },
      service: {
        read: async () => {
          serviceCalls += 1;
          return result;
        },
      },
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 1_000,
    });
    await app.listen({ host: '127.0.0.1', port: 0 });
    try {
      const address = app.server.address();
      if (!address || typeof address === 'string') throw new Error('missing loopback address');
      await new Promise<void>((resolve) => {
        const client = httpRequest({
          host: '127.0.0.1',
          port: address.port,
          path: '/v1/privacy-explorer/projections:read',
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'cookie': '__Host-openpc_session=session-a',
            'content-length': Buffer.byteLength(JSON.stringify(candidate)),
          },
        });
        client.once('error', () => resolve());
        client.once('close', () => resolve());
        client.once('finish', () => client.destroy());
        client.end(JSON.stringify(candidate));
      });
      await waitFor(() => resolverStarted, 'session resolver did not start');
      await waitFor(() => port.auditCalls() === 1, 'suppressed admission audit was not accepted');
      await waitFor(() => port.events().length === 1, 'suppressed admission event was not emitted');
      expect(serviceCalls).toBe(0);
      expect(port.evidenceCalls()).toBe(0);
      expect(port.events()).toEqual([
        {
          profileState: 'NOT_ADMITTED',
          outcomeClass: 'SUPPRESSED',
          durationMilliseconds: expect.any(Number),
          errorClass: 'NONE',
        },
      ]);
    } finally {
      await app.close();
    }
  });
  it('audits and emits the exact service-failure terminal relation', async () => {
    const { harness, candidate, result } = await resultFixture();
    const port = sinks(result);
    const app = createPrivacyExplorerHttpApplication({
      admission: {
        resolveSession: () => harness.input.context,
        terminalAuthorizationVerifier: { verify: () => harness.input.context },
        profile: harness.input.profile,
        clock: () => new Date(Date.parse(harness.input.seed.now) + 1),
        maximumRequestBytes: 65_536,
        maximumJsonDepth: 16,
        serverMaximumDeadlineAt: '9999-12-31T23:59:59.000Z',
      },
      service: { read: async () => Promise.reject(new Error('SERVICE_SECRET_CANARY')) },
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 1_000,
    });
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/privacy-explorer/projections:read',
        headers: {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
        },
        payload: JSON.stringify(candidate),
      });
      expect(response.statusCode).toBe(503);
      expect(response.body).not.toContain('SERVICE_SECRET_CANARY');
      expect(port.evidenceCalls()).toBe(0);
      expect(port.auditCalls()).toBe(1);
      await waitFor(() => port.events().length === 1, 'service failure event was not emitted');
      expect(port.events()).toEqual([
        {
          correlationId: harness.input.seed.auditCorrelationId,
          profileState: 'ADMITTED',
          outcomeClass: 'SAFE_PROBLEM',
          durationMilliseconds: expect.any(Number),
          errorClass: 'SERVICE_FAILURE',
        },
      ]);
    } finally {
      await app.close();
    }
  });
  it('keeps unknown Explorer URLs out of logger-enabled application output', async () => {
    const { harness, result } = await resultFixture();
    const port = sinks(result);
    let logs = '';
    const app = createPrivacyExplorerHttpApplication(
      {
        admission: {
          resolveSession: () => harness.input.context,
          terminalAuthorizationVerifier: { verify: () => harness.input.context },
          profile: harness.input.profile,
          clock: () => new Date(Date.parse(harness.input.seed.now) + 1),
          maximumRequestBytes: 65_536,
          maximumJsonDepth: 16,
          serverMaximumDeadlineAt: '9999-12-31T23:59:59.000Z',
        },
        service: createPrivacyExplorerService(harness.port),
        evidenceSink: port.evidenceSink,
        auditSink: port.auditSink,
        eventSink: port.eventSink,
        maximumSinkWaitMilliseconds: 1_000,
      },
      {
        logger: {
          level: 'info',
          stream: new Writable({
            write(chunk, _encoding, callback) {
              logs += chunk.toString();
              callback();
            },
          }),
        },
      },
    );
    try {
      const response = await app.inject({
        method: 'GET',
        url: '/v1/privacy-explorer/SECRET_URL_CANARY?token=SECRET_QUERY_CANARY',
      });
      expect(response.statusCode).toBe(404);
      expect(response.headers['content-type']).toContain('application/problem+json');
      expect(response.json()).toMatchObject({ code: 'PC-DATA-6003' });
      expect(logs).not.toContain('SECRET_URL_CANARY');
      expect(logs).not.toContain('SECRET_QUERY_CANARY');
    } finally {
      await app.close();
    }
  });
  it.each([
    [
      'synchronous throw',
      () => {
        throw new Error('event-canary');
      },
    ],
    ['asynchronous rejection', async () => Promise.reject(new Error('event-canary'))],
  ] as const)('does not let an event-sink %s alter an accepted result', async (_name, emit) => {
    const { harness, candidate, result } = await resultFixture();
    const port = sinks(result);
    const app = createPrivacyExplorerHttpApplication({
      admission: {
        resolveSession: () => harness.input.context,
        terminalAuthorizationVerifier: { verify: () => harness.input.context },
        profile: harness.input.profile,
        clock: () => new Date(Date.parse(harness.input.seed.now) + 1),
        maximumRequestBytes: 65_536,
        maximumJsonDepth: 16,
        serverMaximumDeadlineAt: '9999-12-31T23:59:59.000Z',
      },
      service: createPrivacyExplorerService(harness.port),
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: { emit },
      maximumSinkWaitMilliseconds: 1_000,
    });
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/privacy-explorer/projections:read',
        headers: {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
        },
        payload: JSON.stringify(candidate),
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual(result.response);
      expect(port.evidenceCalls()).toBe(1);
    } finally {
      await app.close();
    }
  });
  it('registers only the read route and maps accepted results after evidence acceptance', async () => {
    const { harness, result, candidate } = await resultFixture();
    const port = sinks(result);
    const app = createPrivacyExplorerHttpApplication({
      admission: {
        resolveSession: (value) => (value === 'session-a' ? harness.input.context : undefined),
        terminalAuthorizationVerifier: { verify: () => harness.input.context },
        profile: harness.input.profile,
        clock: () => new Date(Date.parse(harness.input.seed.now) + 1),
        maximumRequestBytes: 65_536,
        maximumJsonDepth: 16,
        serverMaximumDeadlineAt: '9999-12-31T23:59:59.000Z',
      },
      service: createPrivacyExplorerService(harness.port),
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 1_000,
    });
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/privacy-explorer/projections:read',
        headers: {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
        },
        payload: JSON.stringify(candidate),
      });
      expect(response.statusCode).toBe(200);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.json()).toEqual(result.response);
      expect(port.evidenceCalls()).toBe(1);
      expect(port.auditCalls()).toBe(0);
      const unauthenticated = await app
        .inject({
          method: 'POST',
          url: '/v1/privacy-explorer/projections:read',
          headers: { 'content-type': 'application/json' },
          payload: '{not-json',
        })
        .catch((error: unknown) => {
          throw new Error('unauthenticated route did not finalize', { cause: error });
        });
      expect(unauthenticated.statusCode).toBe(401);
      expect(port.auditCalls()).toBe(1);
      const unknown = await app
        .inject({
          method: 'GET',
          url: '/v1/privacy-explorer/evidence:verify',
        })
        .catch((error: unknown) => {
          throw new Error('unknown route did not finalize', { cause: error });
        });
      expect(unknown.statusCode).toBe(404);
      expect(port.evidenceCalls()).toBe(1);
    } finally {
      await app.close();
    }
  });

  it('turns a conflicting sink receipt into the closed replay problem', async () => {
    const { harness, result, candidate } = await resultFixture();
    const port = sinks(result, { conflict: true });
    const app = createPrivacyExplorerHttpApplication({
      admission: {
        resolveSession: () => harness.input.context,
        terminalAuthorizationVerifier: { verify: () => harness.input.context },
        profile: harness.input.profile,
        clock: () => new Date(Date.parse(harness.input.seed.now) + 1),
        maximumRequestBytes: 65_536,
        maximumJsonDepth: 16,
        serverMaximumDeadlineAt: '9999-12-31T23:59:59.000Z',
      },
      service: createPrivacyExplorerService(harness.port),
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 1_000,
    });
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/privacy-explorer/projections:read',
        headers: {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
        },
        payload: JSON.stringify(candidate),
      });
      expect(response.statusCode).toBe(409);
      expect(response.headers['content-type']).toContain('application/problem+json');
      expect(response.json()).toMatchObject({ code: 'PC-RUNTIME-3007' });
      expect(port.evidenceCalls()).toBe(1);
    } finally {
      await app.close();
    }
  });

  it('persists cancellation evidence without a late socket payload', async () => {
    const { harness, candidate } = await resultFixture();
    const cancelled = new AbortController();
    cancelled.abort();
    const suppressed = await createPrivacyExplorerService(harness.port).read({
      ...harness.input,
      signal: cancelled.signal,
    });
    expect(suppressed.disposition).toBe('SUPPRESSED');
    const port = sinks(suppressed);
    let serviceStarted = false;
    const app = createPrivacyExplorerHttpApplication({
      admission: {
        resolveSession: () => harness.input.context,
        terminalAuthorizationVerifier: { verify: () => harness.input.context },
        profile: harness.input.profile,
        clock: () => new Date(Date.parse(harness.input.seed.now) + 1),
        maximumRequestBytes: 65_536,
        maximumJsonDepth: 16,
        serverMaximumDeadlineAt: '9999-12-31T23:59:59.000Z',
      },
      service: {
        read: async (input) => {
          serviceStarted = true;
          await new Promise<void>((resolve) =>
            input.signal?.addEventListener('abort', () => resolve(), { once: true }),
          );
          return createPrivacyExplorerService(harness.port).read(input);
        },
      },
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 1_000,
    });
    await app.listen({ host: '127.0.0.1', port: 0 });
    try {
      const address = app.server.address();
      if (!address || typeof address === 'string') throw new Error('missing loopback address');
      await new Promise<void>((resolve, reject) => {
        const client = httpRequest(
          {
            host: '127.0.0.1',
            port: address.port,
            path: '/v1/privacy-explorer/projections:read',
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'cookie': '__Host-openpc_session=session-a',
              'content-length': Buffer.byteLength(JSON.stringify(candidate)),
            },
          },
          (response) => {
            response.resume();
            response.once('end', resolve);
          },
        );
        client.once('error', (error: NodeJS.ErrnoException) => {
          if (error.code === 'ECONNRESET' || error.code === 'EPIPE') resolve();
          else reject(error);
        });
        client.once('finish', () => client.destroy());
        client.end(JSON.stringify(candidate));
      });
      await waitFor(() => serviceStarted, 'service did not start before disconnect');
      await waitFor(() => port.evidenceCalls() === 1, 'cancellation evidence was not accepted');
      expect(port.auditCalls()).toBe(0);
    } finally {
      await app.close();
    }
  });

  it('removes the exact abort listener when transport closes after delivery is claimed', async () => {
    const { harness, candidate, result } = await resultFixture();
    const port = sinks(result);
    const app = createPrivacyExplorerHttpApplication({
      admission: {
        resolveSession: () => harness.input.context,
        terminalAuthorizationVerifier: { verify: () => harness.input.context },
        profile: harness.input.profile,
        clock: () => new Date(Date.parse(harness.input.seed.now) + 1),
        maximumRequestBytes: 65_536,
        maximumJsonDepth: 16,
        serverMaximumDeadlineAt: '9999-12-31T23:59:59.000Z',
      },
      service: createPrivacyExplorerService(harness.port),
      evidenceSink: port.evidenceSink,
      auditSink: port.auditSink,
      eventSink: port.eventSink,
      maximumSinkWaitMilliseconds: 1_000,
    });
    let capturedRequest: import('node:http').IncomingMessage | undefined;
    let endEntered = false;
    app.server.prependListener('request', (request, response) => {
      if (request.url !== '/v1/privacy-explorer/projections:read') return;
      capturedRequest = request;
      response.end = ((..._arguments: unknown[]) => {
        endEntered = true;
        return response;
      }) as typeof response.end;
    });
    await app.listen({ host: '127.0.0.1', port: 0 });
    try {
      const address = app.server.address();
      if (!address || typeof address === 'string') throw new Error('missing loopback address');
      const client = httpRequest({
        host: '127.0.0.1',
        port: address.port,
        path: '/v1/privacy-explorer/projections:read',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
          'content-length': Buffer.byteLength(JSON.stringify(candidate)),
        },
      });
      client.on('error', () => {});
      client.end(JSON.stringify(candidate));
      await waitFor(() => port.evidenceCalls() === 1 && endEntered, 'transport was not claimed');
      if (!capturedRequest) throw new Error('request was not captured');
      const installed = capturedRequest
        .rawListeners('aborted')
        .find(
          (listener) =>
            ((listener as EventListener & { listener?: EventListener }).listener ?? listener)
              .name === 'abortIncompleteRequest',
        );
      expect(installed).toBeTypeOf('function');
      client.destroy();
      await waitFor(
        () => !capturedRequest?.rawListeners('aborted').includes(installed!),
        'exact abort listener remained after premature transport close',
      );
      expect(capturedRequest.rawListeners('aborted')).not.toContain(installed);
      expect(client.destroyed).toBe(true);
      expect(port.evidenceCalls()).toBe(1);
    } finally {
      await app.close();
    }
  });

  it('has no dependency edge to the sealed pending-delivery owner', async () => {
    const source = await Promise.all([
      readFile(new URL('./http-delivery.ts', import.meta.url), 'utf8'),
      readFile(new URL('./evidence-sink.ts', import.meta.url), 'utf8'),
    ]);
    expect(source.join('\n')).not.toMatch(
      /pending[-_ ]delivery|oldest[-_ ]age|pending[-_ ]count/iu,
    );
  });
});
