import Fastify, { type FastifyInstance } from 'fastify';
import { request as httpRequest } from 'node:http';
import { describe, expect, it } from 'vitest';

import {
  buildB5Harness,
  projectionFor,
} from '../../../../tests/privacy/i07-gate2-b5-test-support.js';
import type { ExplorerProjectionRequestV1 } from '../contracts/privacy-explorer-adapter.js';
import { canonicalJson } from './canonical.js';
import type { TerminalAuthorizationFacts } from './context.js';
import {
  createPrivacyExplorerHttpAdmission,
  disposePrivacyExplorerHttpReadAdmission,
  requirePrivacyExplorerHttpReadAdmission,
} from './http-admission.js';
import { createPrivacyExplorerService } from './service.js';

const otherDigest = `sha256:${'f'.repeat(64)}`;
const otherUuid = '123e4567-e89b-42d3-a456-426614174199';
const candidatelessBody = Symbol('candidate body');
type MutableTerminalAuthorizationFacts = {
  -readonly [Key in keyof TerminalAuthorizationFacts]: TerminalAuthorizationFacts[Key];
};

const capturedRequest = async (): Promise<ExplorerProjectionRequestV1> => {
  let request: ExplorerProjectionRequestV1 | undefined;
  const harness = buildB5Harness({
    implementation: {
      readGovernedProjection(candidate, context) {
        request = candidate;
        return Promise.resolve(projectionFor(candidate, context));
      },
    },
  });
  await createPrivacyExplorerService(harness.port).read(harness.input);
  if (!request) throw new Error('missing projection request');
  return request;
};

const testApplication = async (
  candidate: ExplorerProjectionRequestV1,
  options: Readonly<{
    maximumBytes?: number;
    clock?: () => Date;
    serverDeadlineAt?: string;
    terminal?: MutableTerminalAuthorizationFacts;
    resolveSession?: (session: string) => unknown | Promise<unknown>;
    afterAdmission?: (
      input: ReturnType<typeof requirePrivacyExplorerHttpReadAdmission>,
    ) => void | Promise<void>;
  }> = {},
) => {
  const harness = buildB5Harness({
    implementation: { readGovernedProjection: async () => undefined },
  });
  const terminal =
    options.terminal ??
    (structuredClone(harness.input.context) as MutableTerminalAuthorizationFacts);
  const admission = createPrivacyExplorerHttpAdmission({
    resolveSession:
      options.resolveSession ?? ((session) => (session === 'session-a' ? terminal : undefined)),
    terminalAuthorizationVerifier: {
      verify: (value) => (value === terminal ? terminal : undefined),
    },
    profile: harness.input.profile,
    clock: options.clock ?? (() => new Date(Date.parse(candidate.issuedAt) + 1)),
    maximumRequestBytes: options.maximumBytes ?? 65_536,
    maximumJsonDepth: 16,
    serverMaximumDeadlineAt: options.serverDeadlineAt ?? '9999-12-31T23:59:59.000Z',
  });
  const app = Fastify();
  let parserCalls = 0;
  let admittedCalls = 0;
  let capturedAdmission: ReturnType<typeof requirePrivacyExplorerHttpReadAdmission> | undefined;
  app.addContentTypeParser('application/json', (request, payload, done) => {
    parserCalls += 1;
    admission.parseBody(request, payload).then(
      () => done(null, undefined),
      () => done(null, undefined),
    );
  });
  app.post(
    '/_privacy-explorer-admission-test',
    {
      onRequest: async (request, reply) => {
        const controller = new AbortController();
        request.raw.once('aborted', () => controller.abort());
        reply.raw.once('close', () => {
          if (!reply.raw.writableEnded) controller.abort();
        });
        const outcome = await admission.onRequest(
          request,
          reply,
          controller.signal,
          async (problem) => {
            reply.code(problem.httpStatus).type('application/problem+json').send(problem);
          },
        );
        if (outcome === 'REJECTED') return reply;
      },
    },
    async (request, reply) => {
      const outcome = admission.consume(request);
      if (outcome.kind === 'REJECTED')
        return reply
          .code(outcome.problem.httpStatus)
          .type('application/problem+json')
          .send(outcome.problem);
      admittedCalls += 1;
      capturedAdmission = requirePrivacyExplorerHttpReadAdmission(outcome.admission);
      await options.afterAdmission?.(capturedAdmission);
      disposePrivacyExplorerHttpReadAdmission(outcome.admission);
      return reply.code(204).send();
    },
  );
  await app.ready();
  return Object.freeze({
    app,
    admission,
    terminal,
    parserCalls: () => parserCalls,
    admittedCalls: () => admittedCalls,
    capturedAdmission: () => capturedAdmission,
  });
};

const inject = (app: FastifyInstance, body: unknown, headers: Record<string, string | string[]>) =>
  app.inject({
    method: 'POST',
    url: '/_privacy-explorer-admission-test',
    headers,
    payload: typeof body === 'string' ? body : canonicalJson(body),
  });

const loopbackPost = (
  address: string,
  body: string,
  onRequest?: (request: ReturnType<typeof httpRequest>) => void,
) =>
  new Promise<number>((resolve, reject) => {
    const url = new URL(address);
    const request = httpRequest(
      {
        hostname: url.hostname,
        port: url.port,
        method: 'POST',
        path: '/_privacy-explorer-admission-test',
        headers: {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
          'content-length': Buffer.byteLength(body),
        },
      },
      (response) => {
        response.resume();
        response.once('end', () => resolve(response.statusCode ?? 0));
      },
    );
    request.once('error', reject);
    onRequest?.(request);
    request.end(body);
  });

describe('Privacy Explorer HTTP admission', () => {
  it('authenticates before body parsing and reconstructs exactly one opaque admission', async () => {
    const candidate = await capturedRequest();
    const fixture = await testApplication(candidate);
    try {
      const unauthenticated = await inject(fixture.app, '{bad', {
        'content-type': 'application/json',
      });
      expect(unauthenticated.statusCode).toBe(401);
      expect(unauthenticated.headers['content-type']).toContain('application/problem+json');
      expect(unauthenticated.json()).toEqual({
        code: 'PC-AUTH-0001',
        httpStatus: 401,
        jsonRpcCode: -32041,
        grpcStatus: 'UNAUTHENTICATED',
        truthState: 'DENIED',
        retryable: false,
        disclosure: 'NON_LEAKING_INVARIANT',
        publicTitle: 'Resource is unavailable',
      });
      expect(fixture.parserCalls()).toBe(0);
      expect(fixture.admittedCalls()).toBe(0);

      const accepted = await inject(fixture.app, candidate, {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
      });
      expect(accepted.statusCode).toBe(204);
      expect(fixture.parserCalls()).toBe(1);
      expect(fixture.admittedCalls()).toBe(1);
      expect(fixture.capturedAdmission()).toMatchObject({
        context: { resource: candidate.resource },
        seed: { now: candidate.issuedAt, occurrenceId: candidate.occurrence.requestId },
      });
    } finally {
      await fixture.app.close();
    }
  });

  it.each([
    ['empty session', '__Host-openpc_session='],
    ['duplicate session', '__Host-openpc_session=session-a; __Host-openpc_session=session-b'],
    ['malformed session cookie', '__Host-openpc_session=session a'],
    ['invalid session', '__Host-openpc_session=unknown'],
  ])('returns the same 401 for %s before the parser', async (_name, cookie) => {
    const candidate = await capturedRequest();
    const fixture = await testApplication(candidate);
    try {
      const response = await inject(fixture.app, '{not-json', {
        'content-type': 'application/json',
        cookie,
      });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ code: 'PC-AUTH-0001' });
      expect(fixture.parserCalls()).toBe(0);
      expect(fixture.admittedCalls()).toBe(0);
    } finally {
      await fixture.app.close();
    }
  });

  it('rejects representable duplicate Cookie headers before parsing', async () => {
    const candidate = await capturedRequest();
    const fixture = await testApplication(candidate);
    try {
      const response = await inject(fixture.app, '{not-json', {
        'content-type': 'application/json',
        'cookie': ['__Host-openpc_session=session-a', '__Host-openpc_session=session-b'],
      });
      expect(response.statusCode).toBe(401);
      expect(fixture.parserCalls()).toBe(0);
      expect(fixture.admittedCalls()).toBe(0);
    } finally {
      await fixture.app.close();
    }
  });

  it('maps session resolver and verifier failures to the same 401 before parsing', async () => {
    const candidate = await capturedRequest();
    const fixture = await testApplication(candidate, {
      resolveSession: () => {
        throw new Error('session secret must not escape');
      },
    });
    try {
      const response = await inject(fixture.app, '{not-json', {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
      });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ code: 'PC-AUTH-0001' });
      expect(fixture.parserCalls()).toBe(0);
    } finally {
      await fixture.app.close();
    }
  });

  it.each([
    ['missing content type', undefined, candidatelessBody],
    ['wrong content type', 'text/plain', candidatelessBody],
    ['malformed JSON', 'application/json', '{'],
    ['trailing JSON', 'application/json', '{} {}'],
    ['duplicate nested member', 'application/json', '{"a":{"x":1,"x":2}}'],
    ['poisonous member', 'application/json', '{"__proto__":{}}'],
    ['unknown schema member', 'application/json', '{"unknown":true}'],
    ['fractional scalar', 'application/json', '{"filters":[{"value":0.5}]}'],
  ])(
    'maps authenticated %s to a non-leaking 400 with zero admission',
    async (_name, contentType, body) => {
      const candidate = await capturedRequest();
      const fixture = await testApplication(candidate);
      try {
        const headers: Record<string, string> = { cookie: '__Host-openpc_session=session-a' };
        if (contentType) headers['content-type'] = contentType;
        const response = await inject(
          fixture.app,
          body === candidatelessBody ? candidate : body,
          headers,
        );
        expect(response.statusCode).toBe(400);
        expect(response.headers['content-type']).toContain('application/problem+json');
        expect(response.json()).toMatchObject({ httpStatus: 400 });
        expect(fixture.admittedCalls()).toBe(0);
      } finally {
        await fixture.app.close();
      }
    },
  );

  it('rejects an oversized authenticated body before an admission can be consumed', async () => {
    const candidate = await capturedRequest();
    const fixture = await testApplication(candidate, { maximumBytes: 2 });
    try {
      const response = await inject(fixture.app, candidate, {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
      });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({ httpStatus: 400 });
      expect(fixture.admittedCalls()).toBe(0);
    } finally {
      await fixture.app.close();
    }
  });

  it('lets a schema-invalid fractional filter reach generated validation after strict parsing', async () => {
    const candidate = await capturedRequest();
    const fixture = await testApplication(candidate);
    try {
      const response = await inject(
        fixture.app,
        JSON.stringify({ ...candidate, filters: [{ ...candidate.filters[0]!, value: 0.5 }] }),
        {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
        },
      );
      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({ code: 'PC-DATA-6002' });
      expect(fixture.parserCalls()).toBe(1);
      expect(fixture.admittedCalls()).toBe(0);
    } finally {
      await fixture.app.close();
    }
  });

  it.each([
    [
      'subject',
      (request: ExplorerProjectionRequestV1) => ({ ...request, subject: 'other-subject' }),
    ],
    [
      'resource',
      (request: ExplorerProjectionRequestV1) => ({ ...request, resource: 'other-resource' }),
    ],
    [
      'scope participant',
      (request: ExplorerProjectionRequestV1) => ({
        ...request,
        scope: { ...request.scope, participantId: 'other-participant' },
      }),
    ],
    [
      'profile digest',
      (request: ExplorerProjectionRequestV1) => ({
        ...request,
        exportProfile: { ...request.exportProfile, digest: otherDigest },
      }),
    ],
    [
      'query digest',
      (request: ExplorerProjectionRequestV1) => ({ ...request, queryDigest: otherDigest }),
    ],
    [
      'request occurrence',
      (request: ExplorerProjectionRequestV1) => ({
        ...request,
        occurrence: { ...request.occurrence, requestId: otherUuid },
      }),
    ],
    [
      'correlation occurrence',
      (request: ExplorerProjectionRequestV1) => ({
        ...request,
        occurrence: { ...request.occurrence, correlationId: otherUuid },
      }),
    ],
  ])(
    'treats body %s as an assertion and performs no admission on mismatch',
    async (_name, mutate) => {
      const candidate = await capturedRequest();
      const fixture = await testApplication(candidate);
      try {
        const response = await inject(fixture.app, mutate(candidate), {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
        });
        expect(response.statusCode).toBe(400);
        expect(fixture.admittedCalls()).toBe(0);
      } finally {
        await fixture.app.close();
      }
    },
  );

  it('captures the trusted clock once and rejects future, stale, and expired inputs', async () => {
    const candidate = await capturedRequest();
    let calls = 0;
    const future = await testApplication(candidate, {
      clock: () => {
        calls += 1;
        return new Date(Date.parse(candidate.issuedAt) - 1);
      },
    });
    try {
      const response = await inject(future.app, candidate, {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
      });
      expect(response.statusCode).toBe(400);
      expect(calls).toBe(1);
      expect(future.admittedCalls()).toBe(0);
    } finally {
      await future.app.close();
    }

    const stale = await testApplication(candidate, {
      clock: () =>
        new Date(
          Date.parse(candidate.issuedAt) +
            candidate.exportProfile.maximumFreshnessAgeMilliseconds +
            1,
        ),
    });
    try {
      const response = await inject(stale.app, candidate, {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
      });
      expect(response.statusCode).toBe(400);
      expect(stale.admittedCalls()).toBe(0);
    } finally {
      await stale.app.close();
    }

    const expired = await testApplication(candidate, { serverDeadlineAt: candidate.issuedAt });
    try {
      const response = await inject(expired.app, candidate, {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
      });
      expect(response.statusCode).toBe(400);
      expect(expired.admittedCalls()).toBe(0);
    } finally {
      await expired.app.close();
    }
  });

  it('does not retain mutable resolver or body candidates after admission', async () => {
    const candidate = await capturedRequest();
    const fixture = await testApplication(candidate);
    try {
      const response = await inject(fixture.app, candidate, {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
      });
      expect(response.statusCode).toBe(204);
      fixture.terminal.resource = 'mutated-after-admission';
      expect(fixture.capturedAdmission()).toMatchObject({
        context: { resource: candidate.resource },
      });
    } finally {
      await fixture.app.close();
    }
  });

  it('keeps the admitted signal live through a normal loopback request completion', async () => {
    const candidate = await capturedRequest();
    let signal: AbortSignal | undefined;
    const fixture = await testApplication(candidate, {
      afterAdmission: async (input) => {
        if (!input.signal) throw new Error('missing admitted signal');
        signal = input.signal;
        await new Promise((resolve) => setTimeout(resolve, 15));
        expect(input.signal.aborted).toBe(false);
      },
    });
    const address = await fixture.app.listen({ host: '127.0.0.1', port: 0 });
    try {
      await expect(loopbackPost(address, canonicalJson(candidate))).resolves.toBe(204);
      expect(signal?.aborted).toBe(false);
    } finally {
      await fixture.app.close();
    }
  });

  it('aborts the admitted signal exactly once when a loopback client disconnects before reply', async () => {
    const candidate = await capturedRequest();
    let handlerStarted!: () => void;
    const handlerStartedPromise = new Promise<void>((resolve) => {
      handlerStarted = resolve;
    });
    let releaseHandler!: () => void;
    const releaseHandlerPromise = new Promise<void>((resolve) => {
      releaseHandler = resolve;
    });
    let aborts = 0;
    let aborted!: () => void;
    const abortedPromise = new Promise<void>((resolve) => {
      aborted = resolve;
    });
    const fixture = await testApplication(candidate, {
      afterAdmission: async (input) => {
        if (!input.signal) throw new Error('missing admitted signal');
        input.signal.addEventListener('abort', () => {
          aborts += 1;
          aborted();
        });
        handlerStarted();
        await releaseHandlerPromise;
      },
    });
    const address = await fixture.app.listen({ host: '127.0.0.1', port: 0 });
    const body = canonicalJson(candidate);
    const url = new URL(address);
    const client = httpRequest({
      hostname: url.hostname,
      port: url.port,
      method: 'POST',
      path: '/_privacy-explorer-admission-test',
      headers: {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
        'content-length': Buffer.byteLength(body),
      },
    });
    client.once('error', () => undefined);
    client.end(body);
    try {
      await handlerStartedPromise;
      client.destroy();
      await abortedPromise;
      expect(aborts).toBe(1);
    } finally {
      releaseHandler();
      await fixture.app.close();
    }
  });
});
