import { describe, expect, it, vi } from 'vitest';

import {
  buildB5Harness,
  projectionFor,
} from '../../../../tests/privacy/i07-gate2-b5-test-support.js';
import type {
  AdapterCallContextV1,
  EvidenceReferenceV1,
  ExplorerProjectionRequestV1,
} from '../contracts/privacy-explorer-adapter.js';
import { assertExplorerProjectionRequest } from '../contracts/privacy-explorer-adapter.js';
import { canonicalJson, sha256CanonicalJson } from './canonical.js';
import { createHttpGovernedProjectionConsumer } from './http-consumer.js';
import { safeProblemForCondition } from './problems.js';
import { copyExactUint8Array, requireExactOwnData } from './server-input.js';
import { parseStrictJsonBytes } from './strict-json.js';
import {
  createPrivacyExplorerTransportProfile,
  type PrivacyExplorerTransportProfile,
} from './transport-profile.js';
import {
  createTestTlsClientBinding,
  createTlsClientBinding,
  type TlsDispatchResponse,
} from './tls-client-binding.js';

type CapturedCall = Readonly<{
  request: ExplorerProjectionRequestV1;
  context: AdapterCallContextV1;
}>;

const capturedCall = async (): Promise<CapturedCall> => {
  let captured: CapturedCall | undefined;
  const harness = buildB5Harness({
    implementation: {
      readGovernedProjection(request, context) {
        captured = Object.freeze({ request, context });
        return Promise.resolve(projectionFor(request, context));
      },
    },
  });
  const { createPrivacyExplorerService } = await import('./service.js');
  await createPrivacyExplorerService(harness.port).read(harness.input);
  if (!captured) throw new Error('missing captured adapter call');
  return captured;
};

const body = (
  value: string | Uint8Array | readonly (string | Uint8Array)[],
  disposed?: () => void,
): TlsDispatchResponse => {
  const chunks = typeof value === 'string' || value instanceof Uint8Array ? [value] : value;
  return Object.freeze({
    statusCode: 200,
    contentType: 'application/json',
    locationPresent: false,
    body: (async function* () {
      for (const chunk of chunks)
        yield chunk instanceof Uint8Array ? Buffer.from(chunk) : Buffer.from(chunk, 'utf8');
    })(),
    dispose: disposed ?? (() => {}),
  });
};

const profile = (
  captured: CapturedCall,
  dispatch: Parameters<typeof createTestTlsClientBinding>[1],
  limits: Readonly<{ request?: number; response?: number; depth?: number }> = {},
): PrivacyExplorerTransportProfile =>
  createPrivacyExplorerTransportProfile({
    transportClass: 'LOCAL_DEVELOPMENT',
    origin: 'https://127.0.0.1:50123',
    exportProfileDigest: captured.request.exportProfile.digest,
    transportProfileId: 'openpc-test-transport@v1',
    egressPolicyId: 'openpc-test-egress@v1',
    requestByteLimit: limits.request ?? 65_536,
    responseByteLimit: limits.response ?? 65_536,
    maximumJsonDepth: limits.depth ?? 12,
    tlsClientBinding: createTestTlsClientBinding('LOCAL_DEVELOPMENT', dispatch),
  });

const evidenceReference = (captured: CapturedCall): EvidenceReferenceV1 => {
  const preimage = {
    schemaVersion: '1.0' as const,
    evidenceDigest: `sha256:${'e'.repeat(64)}`,
    occurrenceId: captured.context.occurrenceId,
    profileDigest: captured.context.profileDigest,
  };
  return { ...preimage, referenceDigest: sha256CanonicalJson(preimage) };
};

describe('Privacy Explorer outbound HTTP consumer', () => {
  it('pins the two fixed paths, emits the minimal envelope, and makes one attempt per call', async () => {
    const captured = await capturedCall();
    const attempts: { path: string; envelope: unknown }[] = [];
    const consumer = createHttpGovernedProjectionConsumer(
      profile(captured, async (request) => {
        attempts.push({
          path: request.path,
          envelope: parseStrictJsonBytes(request.body, { maximumDepth: 12 }),
        });
        if (request.path === '/v1/privacy-explorer/evidence:verify') {
          const reference = evidenceReference(captured);
          const preimage = {
            schemaVersion: '1.0' as const,
            referenceDigest: reference.referenceDigest,
            evidenceDigest: reference.evidenceDigest,
            verified: true,
          };
          return body(
            JSON.stringify({ ...preimage, verificationDigest: sha256CanonicalJson(preimage) }),
          );
        }
        return body(JSON.stringify(projectionFor(captured.request, captured.context)));
      }),
    );
    await expect(
      consumer.readGovernedProjection(captured.request, captured.context),
    ).resolves.toMatchObject({ requestDigest: sha256CanonicalJson(captured.request) });
    await expect(
      consumer.verifyEvidenceReference(evidenceReference(captured), captured.context),
    ).resolves.toMatchObject({ verified: true });
    expect(attempts).toHaveLength(2);
    expect(attempts.map((attempt) => attempt.path)).toEqual([
      '/v1/privacy-explorer/projection:read',
      '/v1/privacy-explorer/evidence:verify',
    ]);
    expect(attempts[0]?.envelope).toEqual({ context: captured.context, request: captured.request });
    expect((attempts[1]?.envelope as { request: unknown }).request).toEqual(
      evidenceReference(captured),
    );
  });

  it('keeps successful JSON untrusted for the Gate 2 semantic validator', async () => {
    const captured = await capturedCall();
    const consumer = createHttpGovernedProjectionConsumer(
      profile(captured, async () => body('{"unknown":0.5}')),
    );
    await expect(
      consumer.readGovernedProjection(captured.request, captured.context),
    ).resolves.toEqual({
      unknown: 0.5,
    });
  });

  it('emits frozen ordinary objects compatible with the generated request validator', async () => {
    const captured = await capturedCall();
    const parsed = parseStrictJsonBytes(Buffer.from(canonicalJson(captured.request)), {
      maximumDepth: 16,
    });
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.getPrototypeOf((parsed as unknown as ExplorerProjectionRequestV1).scope)).toBe(
      Object.prototype,
    );
    expect(Object.getOwnPropertyDescriptor(parsed, 'scope')).toMatchObject({
      enumerable: true,
      configurable: false,
      writable: false,
    });
    expect(assertExplorerProjectionRequest(parsed)).toEqual(captured.request);
  });

  it.each([
    ['invalid UTF-8', Buffer.from([0xff])],
    ['trailing bytes', Buffer.from('{} {}')],
    ['nested duplicate', Buffer.from('{"a":{"x":1,"x":2}}')],
    ['__proto__ key', Buffer.from('{"__proto__":1}')],
    ['constructor key', Buffer.from('{"constructor":1}')],
    ['prototype key', Buffer.from('{"prototype":1}')],
    ['unsafe numeric scalar', Buffer.from('{"n":9007199254740992}')],
    ['rounded decimal alias', Buffer.from('{"n":1.0000000000000001}')],
    ['rounded decimal integer alias', Buffer.from('{"n":7.0000000000000001}')],
    ['underflow decimal alias', Buffer.from('{"n":1e-9999}')],
    ['safe-boundary decimal alias', Buffer.from('{"n":9007199254740991.1}')],
  ])('maps strict JSON %s to the canonical parse problem', async (_name, response) => {
    const captured = await capturedCall();
    const consumer = createHttpGovernedProjectionConsumer(
      profile(captured, async () => body(response)),
    );
    await expect(
      consumer.readGovernedProjection(captured.request, captured.context),
    ).resolves.toEqual(safeProblemForCondition('EXP-PARSE'));
  });

  it('fails closed for redirect, content type, status tuple, and success-plus-problem ambiguity', async () => {
    const captured = await capturedCall();
    const variants: readonly ((response: TlsDispatchResponse) => TlsDispatchResponse)[] = [
      (response) => Object.freeze({ ...response, locationPresent: true }),
      (response) => Object.freeze({ ...response, contentType: 'application/json; charset=utf-8' }),
      (response) => Object.freeze({ ...response, statusCode: 302 }),
      () =>
        Object.freeze({
          ...body(JSON.stringify(safeProblemForCondition('EXP-COND-004'))),
          statusCode: 200,
        }),
    ];
    for (const variant of variants) {
      const consumer = createHttpGovernedProjectionConsumer(
        profile(captured, async () => variant(body('{}'))),
      );
      await expect(
        consumer.readGovernedProjection(captured.request, captured.context),
      ).resolves.toEqual(safeProblemForCondition('EXP-COND-004'));
    }
  });

  it('admits only an exact registered problem with its matching HTTP status', async () => {
    const captured = await capturedCall();
    const expected = safeProblemForCondition('EXP-COND-004');
    const consumer = createHttpGovernedProjectionConsumer(
      profile(captured, async () =>
        Object.freeze({ ...body(JSON.stringify(expected)), statusCode: expected.httpStatus }),
      ),
    );
    await expect(
      consumer.readGovernedProjection(captured.request, captured.context),
    ).resolves.toEqual(expected);
  });

  it('enforces response limits across chunks and disposes the response', async () => {
    const captured = await capturedCall();
    let disposed = 0;
    const consumer = createHttpGovernedProjectionConsumer(
      profile(
        captured,
        async () =>
          body(['{"x":"', '12345"}'], () => {
            disposed += 1;
          }),
        { response: 10 },
      ),
    );
    await expect(
      consumer.readGovernedProjection(captured.request, captured.context),
    ).resolves.toEqual(safeProblemForCondition('EXP-COND-004'));
    expect(disposed).toBe(1);
  });

  it('accepts an exact response cap and rejects an oversized request before dispatch', async () => {
    const captured = await capturedCall();
    let calls = 0;
    const exactCapConsumer = createHttpGovernedProjectionConsumer(
      profile(captured, async () => body('{}'), { response: 2 }),
    );
    await expect(
      exactCapConsumer.readGovernedProjection(captured.request, captured.context),
    ).resolves.toEqual({});
    const cappedRequestConsumer = createHttpGovernedProjectionConsumer(
      profile(
        captured,
        async () => {
          calls += 1;
          return body('{}');
        },
        { request: 1 },
      ),
    );
    await expect(
      cappedRequestConsumer.readGovernedProjection(captured.request, captured.context),
    ).resolves.toEqual(safeProblemForCondition('EXP-ENVELOPE'));
    expect(calls).toBe(0);
  });

  it('enforces the configured JSON nesting limit independently of result semantics', () => {
    expect(() => parseStrictJsonBytes(Buffer.from('{"a":{"b":{}}}'), { maximumDepth: 1 })).toThrow(
      'JSON nesting limit exceeded',
    );
  });

  it('retains only lossless numeric lexemes while preserving exact safe and fractional values', () => {
    expect(parseStrictJsonBytes(Buffer.from('9007199254740991'), { maximumDepth: 1 })).toBe(
      Number.MAX_SAFE_INTEGER,
    );
    expect(parseStrictJsonBytes(Buffer.from('1e0'), { maximumDepth: 1 })).toBe(1);
    expect(parseStrictJsonBytes(Buffer.from('0.5'), { maximumDepth: 1 })).toBe(0.5);
    for (const alias of [
      '1.0000000000000001',
      '7.0000000000000001',
      '1e-9999',
      '9007199254740991.1',
    ])
      expect(() => parseStrictJsonBytes(Buffer.from(alias), { maximumDepth: 1 })).toThrow(
        'unsafe JSON number',
      );
  });

  it('derives deadline from context, aborts the dispatch, and disposes a late response', async () => {
    const captured = await capturedCall();
    let resolveLate: ((response: TlsDispatchResponse) => void) | undefined;
    let observedAbort = false;
    const consumer = createHttpGovernedProjectionConsumer(
      profile(captured, (request) => {
        request.signal.addEventListener('abort', () => {
          observedAbort = true;
        });
        return new Promise((resolve) => {
          resolveLate = resolve;
        });
      }),
    );
    const expiredSoon = {
      ...captured.context,
      deadlineAt: new Date(Date.now() + 20).toISOString(),
    };
    await expect(consumer.readGovernedProjection(captured.request, expiredSoon)).resolves.toEqual(
      safeProblemForCondition('EXP-DEADLINE'),
    );
    let disposed = 0;
    resolveLate?.(
      body('{}', () => {
        disposed += 1;
      }),
    );
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(observedAbort).toBe(true);
    expect(disposed).toBe(1);
  });

  it.each(['READ_PROJECTION', 'VERIFY_EVIDENCE'] as const)(
    'propagates %s caller cancellation while awaiting headers and disposes a late response',
    async (operation) => {
      const captured = await capturedCall();
      const caller = new AbortController();
      const add = vi.spyOn(caller.signal, 'addEventListener');
      const remove = vi.spyOn(caller.signal, 'removeEventListener');
      const clear = vi.spyOn(globalThis, 'clearTimeout');
      let dispatchSignal: AbortSignal | undefined;
      let resolveLate!: (response: TlsDispatchResponse) => void;
      let disposed = 0;
      const consumer = createHttpGovernedProjectionConsumer(
        profile(captured, (request) => {
          dispatchSignal = request.signal;
          return new Promise((resolve) => {
            resolveLate = resolve;
          });
        }),
      );
      const pending =
        operation === 'READ_PROJECTION'
          ? consumer.readGovernedProjection(captured.request, captured.context, {
              signal: caller.signal,
            })
          : consumer.verifyEvidenceReference(evidenceReference(captured), captured.context, {
              signal: caller.signal,
            });
      expect(dispatchSignal).toBeDefined();
      expect(dispatchSignal).not.toBe(caller.signal);
      caller.abort();
      await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
      expect(dispatchSignal?.aborted).toBe(true);
      const admittedListener = add.mock.calls.find(([event]) => event === 'abort')?.[1];
      expect(admittedListener).toEqual(expect.any(Function));
      expect(remove).toHaveBeenCalledWith('abort', admittedListener);
      expect(clear).toHaveBeenCalled();
      resolveLate(
        body('{}', () => {
          disposed += 1;
        }),
      );
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(disposed).toBe(1);
      add.mockRestore();
      remove.mockRestore();
      clear.mockRestore();
    },
  );

  it.each(['READ_PROJECTION', 'VERIFY_EVIDENCE'] as const)(
    'propagates %s caller cancellation during body streaming and completes iterator cleanup',
    async (operation) => {
      const captured = await capturedCall();
      const caller = new AbortController();
      let dispatchSignal: AbortSignal | undefined;
      let settleChunk!: (result: IteratorResult<Uint8Array>) => void;
      let returned = 0;
      let disposed = 0;
      const streamingBody: AsyncIterable<Uint8Array> = {
        [Symbol.asyncIterator]() {
          return {
            next: () =>
              new Promise<IteratorResult<Uint8Array>>((resolve) => {
                settleChunk = resolve;
              }),
            return: async () => {
              returned += 1;
              return { done: true, value: undefined };
            },
          };
        },
      };
      const consumer = createHttpGovernedProjectionConsumer(
        profile(captured, async (request) => {
          dispatchSignal = request.signal;
          return Object.freeze({
            statusCode: 200,
            contentType: 'application/json',
            locationPresent: false,
            body: streamingBody,
            dispose() {
              disposed += 1;
            },
          });
        }),
      );
      const pending =
        operation === 'READ_PROJECTION'
          ? consumer.readGovernedProjection(captured.request, captured.context, {
              signal: caller.signal,
            })
          : consumer.verifyEvidenceReference(evidenceReference(captured), captured.context, {
              signal: caller.signal,
            });
      while (!settleChunk) await Promise.resolve();
      caller.abort();
      await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
      expect(dispatchSignal?.aborted).toBe(true);
      expect(returned).toBe(1);
      expect(disposed).toBe(1);
      settleChunk({ done: false, value: Buffer.from('{}') });
      await Promise.resolve();
      expect(returned).toBe(1);
      expect(disposed).toBe(1);
    },
  );

  it('rejects caller-selected origin, class mismatch, and production test identities at construction', async () => {
    const captured = await capturedCall();
    const binding = createTestTlsClientBinding('LOCAL_DEVELOPMENT', async () => body('{}'));
    const base = {
      transportClass: 'LOCAL_DEVELOPMENT',
      origin: 'https://127.0.0.1:50123',
      exportProfileDigest: captured.request.exportProfile.digest,
      transportProfileId: 'openpc-test-transport@v1',
      egressPolicyId: 'openpc-test-egress@v1',
      requestByteLimit: 64,
      responseByteLimit: 64,
      maximumJsonDepth: 4,
      tlsClientBinding: binding,
    };
    expect(() =>
      createPrivacyExplorerTransportProfile({ ...base, origin: 'http://127.0.0.1:50123' }),
    ).toThrow();
    expect(() =>
      createPrivacyExplorerTransportProfile({ ...base, origin: 'https://example.test:50123' }),
    ).toThrow();
    expect(() =>
      createPrivacyExplorerTransportProfile({ ...base, transportClass: 'PRODUCTION' }),
    ).toThrow();
    expect(() => createPrivacyExplorerTransportProfile({ ...base, redirect: 'FOLLOW' })).toThrow();
  });

  it('fails closed for every unqualified production TLS/profile construction', async () => {
    const captured = await capturedCall();
    expect(() =>
      createTlsClientBinding({
        transportClass: 'PRODUCTION',
        trustAnchorId: 'prod-ca@v1',
        clientIdentityId: 'prod-client@v1',
        trustAnchorPem: new Uint8Array([1]),
        clientCertificatePem: new Uint8Array([2]),
        clientPrivateKeyPem: new Uint8Array([3]),
      }),
    ).toThrow('production TLS qualification unavailable');
    expect(() =>
      createPrivacyExplorerTransportProfile({
        transportClass: 'PRODUCTION',
        origin: 'https://example.test:50123',
        exportProfileDigest: captured.request.exportProfile.digest,
        transportProfileId: 'prod-transport@v1',
        egressPolicyId: 'prod-egress@v1',
        requestByteLimit: 64,
        responseByteLimit: 64,
        maximumJsonDepth: 4,
        tlsClientBinding: createTestTlsClientBinding('PRODUCTION', async () => body('{}')),
      }),
    ).toThrow('production transport qualification unavailable');
  });

  it('rejects proxy, accessor, symbol, extra, and subclass server inputs without caller traps', () => {
    let proxyTraps = 0;
    const proxy = new Proxy(
      {},
      {
        getPrototypeOf() {
          proxyTraps += 1;
          return Object.prototype;
        },
        ownKeys() {
          proxyTraps += 1;
          return [];
        },
        getOwnPropertyDescriptor() {
          proxyTraps += 1;
          return undefined;
        },
      },
    );
    expect(() => requireExactOwnData(proxy, ['value'], 'test input')).toThrow('invalid test input');
    expect(() => createPrivacyExplorerTransportProfile(proxy)).toThrow('invalid transport profile');
    expect(() => createTlsClientBinding(proxy)).toThrow('invalid TLS input');
    expect(proxyTraps).toBe(0);

    let byteProxyTraps = 0;
    const byteProxy = new Proxy(new Uint8Array([1]), {
      getPrototypeOf() {
        byteProxyTraps += 1;
        return Uint8Array.prototype;
      },
      get() {
        byteProxyTraps += 1;
        return undefined;
      },
    });
    expect(() => copyExactUint8Array(byteProxy, 'test bytes')).toThrow('invalid test bytes');
    expect(() =>
      createTlsClientBinding({
        transportClass: 'LOCAL_DEVELOPMENT',
        trustAnchorId: 'local-ca@v1',
        clientIdentityId: 'local-client@v1',
        trustAnchorPem: byteProxy,
        clientCertificatePem: new Uint8Array([2]),
        clientPrivateKeyPem: new Uint8Array([3]),
      }),
    ).toThrow('invalid TLS material');
    expect(byteProxyTraps).toBe(0);

    let getterCalls = 0;
    const accessor = Object.defineProperty({}, 'value', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 1;
      },
    });
    expect(() => requireExactOwnData(accessor, ['value'], 'test input')).toThrow(
      'invalid test input',
    );
    expect(getterCalls).toBe(0);
    expect(() => requireExactOwnData({ value: 1, extra: 2 }, ['value'], 'test input')).toThrow();
    expect(() =>
      requireExactOwnData({ value: 1, [Symbol('extra')]: 2 }, ['value'], 'test input'),
    ).toThrow();
    class Bytes extends Uint8Array {}
    expect(() => copyExactUint8Array(new Bytes([1]), 'test bytes')).toThrow('invalid test bytes');
    const source = new Uint8Array([1, 2]);
    const copied = copyExactUint8Array(source, 'test bytes');
    source[0] = 9;
    expect(copied).toEqual(Buffer.from([1, 2]));
  });
});
