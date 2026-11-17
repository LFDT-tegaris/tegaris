import { afterEach, expect, it, vi } from 'vitest';

import { BffProblem, invokeAction, performWebAuthnStepUp, readSnapshot } from './bff-client';
import { processSnapshotSchema } from './contracts';
import { localFactAction } from './local-runtime-contract';

it('uses the explicit functional-test adapter without invoking browser MFA', async () => {
  const calls: string[] = [];
  const credentialPrompt = vi.fn();
  vi.stubGlobal('navigator', { credentials: { get: credentialPrompt } });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string) => {
      calls.push(path);
      return Response.json(
        path.endsWith('/challenge')
          ? {
              functionalTest: true,
              publicKey: {
                challenge: 'a'.repeat(43),
                rpId: 'localhost',
                allowCredentials: [{ id: 'b'.repeat(43), type: 'public-key' }],
                timeout: 60_000,
                userVerification: 'required',
              },
              expiresAt: new Date(Date.now() + 60_000)
                .toISOString()
                .replace(/(\.\d{3})Z$/u, '$1000Z'),
            }
          : {
              status: 'verified',
              stepUpVerifiedAt: new Date().toISOString().replace(/(\.\d{3})Z$/u, '$1000Z'),
            },
      );
    }),
  );
  await performWebAuthnStepUp({ ...localFactAction, stepUp: 'FRESH_WEBAUTHN_MAX_5M' });
  expect(calls).toEqual([
    '/api/v1/ui/webauthn/assertion/challenge',
    '/api/v1/ui/webauthn/assertion/functional',
  ]);
  expect(credentialPrompt).not.toHaveBeenCalled();
});

const snapshot = {
  snapshotId: '018f1e57-3f50-7b42-8f00-123456789abc',
  routeId: 'ROUTE-LOGIN-CONTEXT-SESSION',
  processDomainId: 'LOGIN_CONTEXT_SESSION',
  contextDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  authorityGeneration: '1',
  policyGeneration: '1',
  truthState: 'SUCCESS',
  scope: { plane: 'PLATFORM', participantId: null, privacyDomainId: null },
  observedAt: '2026-09-06T00:00:00.000000Z',
  freshness: { observedAt: '2026-09-06T00:00:00.000000Z', state: 'CURRENT' },
  completeness: 'COMPLETE',
  items: [],
  authorizedActions: [],
  evidenceRefs: [],
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

it('uses only same-origin UI BFF paths and validates snapshots', async () => {
  const fetch = vi.fn().mockImplementation((_path: string, init: RequestInit) => {
    const request = new Headers(init.headers);
    return Promise.resolve(
      new Response(JSON.stringify(snapshot), {
        headers: {
          'content-type': 'application/json',
          'etag': `"sha256:${'a'.repeat(64)}"`,
          'openpc-api-version': '1',
          'ratelimit-limit': '100',
          'ratelimit-remaining': '99',
          'ratelimit-reset': '60',
          'x-request-id': request.get('x-request-id')!,
          'x-correlation-id': request.get('x-correlation-id')!,
        },
      }),
    );
  });
  vi.stubGlobal('fetch', fetch);

  await expect(readSnapshot('login-context-session')).resolves.toMatchObject({
    truthState: 'SUCCESS',
  });
  expect(fetch).toHaveBeenCalledWith(
    '/api/v1/ui/process-domains/login-context-session',
    expect.objectContaining({ credentials: 'same-origin' }),
  );
});

it('rejects an action path outside its registered process domain before network I/O', async () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  await expect(
    invokeAction(
      'login-context-session',
      {
        actionIntentId: 'ACT-UI_LOGIN_CONTEXT_SESSION_VIEW-V1',
        actionIntentDigest:
          'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        operationId: 'getSession',
        method: 'POST',
        path: '/api/v1/ui/process-domains/other/actions/view',
        riskClass: 'LOW',
        stepUp: 'NONE',
        idempotency: 'KEY_UNTIL_TERMINAL',
        etagRequired: true,
      },
      { csrfToken: 'csrf', idempotencyKey: 'key', etag: 'tag' },
    ),
  ).rejects.toThrow('outside this process domain');
  expect(fetch).not.toHaveBeenCalled();
});

it('turns unsafe BFF failures into a stable safe problem', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockImplementation((_path: string, init: RequestInit) => {
      const request = new Headers(init.headers);
      return Promise.resolve(
        new Response(
          JSON.stringify({
            type: 'https://errors.openpc.local/unavailable',
            code: 'PC-INTEGRATION-5001',
            status: 503,
            title: 'Unavailable',
            traceId: request.get('x-request-id'),
            truthState: 'UNAVAILABLE',
            retryable: true,
          }),
          {
            status: 503,
            headers: {
              'content-type': 'application/problem+json',
              'x-request-id': request.get('x-request-id')!,
              'x-correlation-id': request.get('x-correlation-id')!,
            },
          },
        ),
      );
    }),
  );
  await expect(readSnapshot('login-context-session')).rejects.toBeInstanceOf(BffProblem);
});

it('rejects a safe problem whose trace ownership differs from its response request ID', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockImplementation((_path: string, init: RequestInit) => {
      const request = new Headers(init.headers);
      return Promise.resolve(
        new Response(
          JSON.stringify({
            type: 'https://errors.openpc.local/unavailable',
            code: 'PC-INTEGRATION-5001',
            status: 503,
            title: 'Unavailable',
            traceId: '018f0000-0000-7000-8000-000000000599',
            truthState: 'UNAVAILABLE',
            retryable: true,
          }),
          {
            status: 503,
            headers: {
              'content-type': 'application/problem+json',
              'x-request-id': request.get('x-request-id')!,
              'x-correlation-id': request.get('x-correlation-id')!,
            },
          },
        ),
      );
    }),
  );
  await expect(readSnapshot('login-context-session')).rejects.toMatchObject({
    status: 503,
    problem: { code: 'PC-INTEGRATION-5001', truthState: 'UNAVAILABLE' },
  });
});

it.each([
  ['code', { code: 'PC-DATA-6004' }, 503],
  ['status', { status: 400 }, 400],
  ['truth state', { truthState: 'FAILED' }, 503],
  ['retryability', { retryable: false }, 503],
] as const)('rejects a problem with a mismatched registry %s', async (_name, mutation, status) => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockImplementation((_path: string, init: RequestInit) => {
      const request = new Headers(init.headers);
      return Promise.resolve(
        new Response(
          JSON.stringify({
            type: 'https://errors.openpc.local/unavailable',
            code: 'PC-INTEGRATION-5001',
            status: 503,
            title: 'Unavailable',
            traceId: request.get('x-request-id'),
            truthState: 'UNAVAILABLE',
            retryable: true,
            ...mutation,
          }),
          {
            status,
            headers: {
              'content-type': 'application/problem+json',
              'x-request-id': request.get('x-request-id')!,
              'x-correlation-id': request.get('x-correlation-id')!,
            },
          },
        ),
      );
    }),
  );
  await expect(readSnapshot('login-context-session')).rejects.toMatchObject({
    status: 503,
    problem: {
      code: 'PC-INTEGRATION-5001',
      status: 503,
      truthState: 'UNAVAILABLE',
      retryable: true,
    },
  });
});

it('rejects presentation fields that are not in the generated UI BFF snapshot contract', () => {
  expect(() =>
    processSnapshotSchema.parse({ ...snapshot, summary: 'client-invented presentation field' }),
  ).toThrow();
  expect(() =>
    processSnapshotSchema.parse({ ...snapshot, snapshotId: crypto.randomUUID() }),
  ).toThrow();
  expect(() =>
    processSnapshotSchema.parse({
      ...snapshot,
      observedAt: '2026-09-06T00:00:00.000Z',
    }),
  ).toThrow();
  expect(() =>
    processSnapshotSchema.parse({
      ...snapshot,
      scope: {
        plane: 'PARTICIPANT',
        participantId: '018f0000-0000-7000-8000-000000000101',
        privacyDomainId: null,
      },
    }),
  ).toThrow();
  expect(() =>
    processSnapshotSchema.parse({
      ...snapshot,
      evidenceRefs: [
        'urn:openpc:evidence:018f0000-0000-7000-8000-000000000601',
        'urn:openpc:evidence:018f0000-0000-7000-8000-000000000601',
      ],
    }),
  ).toThrow();
});

it('performs a browser WebAuthn assertion only through same-origin BFF endpoints', async () => {
  const bytes = (value: string) => new TextEncoder().encode(value).buffer;
  class Credential {
    rawId = bytes('018f0000-0000-7000-8000-000000000711');
    response = {
      authenticatorData: bytes('authenticator'),
      clientDataJSON: bytes('client-data'),
      signature: bytes('signature'),
    };
  }
  const get = vi.fn().mockResolvedValue(new Credential());
  vi.stubGlobal('PublicKeyCredential', Credential);
  vi.stubGlobal('navigator', { credentials: { get } });
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(
      Response.json({
        publicKey: {
          challenge: 'Y2hhbGxlbmdlLWJpbmFyeS12YWx1ZS0wMDAwMDAwMDAwMDA',
          rpId: '127.0.0.1',
          allowCredentials: [
            {
              id: 'MDE4ZjAwMDAtMDAwMC03MDAwLTgwMDAtMDAwMDAwMDAwNzEx',
              type: 'public-key',
            },
          ],
          timeout: 300_000,
          userVerification: 'required',
        },
        expiresAt: new Date(Date.now() + 300000).toISOString().replace('Z', '000Z'),
      }),
    )
    .mockResolvedValueOnce(
      Response.json({
        status: 'verified',
        stepUpVerifiedAt: '2026-09-11T00:00:01.000000Z',
      }),
    );
  vi.stubGlobal('fetch', fetch);

  await performWebAuthnStepUp({
    ...localFactAction,
    method: 'POST',
    path: '/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit',
    idempotency: 'KEY_UNTIL_TERMINAL',
    etagRequired: true,
  });

  expect(get).toHaveBeenCalledWith({
    signal: expect.any(AbortSignal),
    publicKey: expect.objectContaining({
      rpId: '127.0.0.1',
      userVerification: 'required',
    }),
  });
  expect(fetch).toHaveBeenNthCalledWith(
    1,
    '/api/v1/ui/webauthn/assertion/challenge',
    expect.objectContaining({ credentials: 'same-origin' }),
  );
  const verification = JSON.parse(String(fetch.mock.calls[1]?.[1]?.body));
  expect(verification).toMatchObject({
    actionIntentId: localFactAction.actionIntentId,
    challenge: 'Y2hhbGxlbmdlLWJpbmFyeS12YWx1ZS0wMDAwMDAwMDAwMDA',
    assertion: {
      credentialId: 'MDE4ZjAwMDAtMDAwMC03MDAwLTgwMDAtMDAwMDAwMDAwNzEx',
      authenticatorData: 'YXV0aGVudGljYXRvcg',
      clientDataJson: 'Y2xpZW50LWRhdGE',
      signature: 'c2lnbmF0dXJl',
    },
  });
});

it.each(['context changed', 'signal aborted'] as const)(
  'stops internal assertion verification after %s during held navigator.get',
  async (mode) => {
    const bytes = (s: string) => new TextEncoder().encode(s).buffer;
    class Credential {
      rawId = bytes('credential');
      response = {
        authenticatorData: bytes('authenticator'),
        clientDataJSON: bytes('client'),
        signature: bytes('signature'),
      };
    }
    let release!: (credential: Credential) => void,
      current = true;
    const controller = new AbortController();
    const get = vi.fn(
      () =>
        new Promise<Credential>((resolve) => {
          release = resolve;
        }),
    );
    vi.stubGlobal('PublicKeyCredential', Credential);
    vi.stubGlobal('navigator', { credentials: { get } });
    const challenge = {
      publicKey: {
        challenge: 'Y2hhbGxlbmdlLWJpbmFyeS12YWx1ZS0wMDAwMDAwMDAwMDA',
        rpId: '127.0.0.1',
        allowCredentials: [
          { id: 'MDE4ZjAwMDAtMDAwMC03MDAwLTgwMDAtMDAwMDAwMDAwNzEx', type: 'public-key' },
        ],
        timeout: 300000,
        userVerification: 'required',
      },
      expiresAt: new Date(Date.now() + 300000).toISOString().replace('Z', '000Z'),
    };
    const fetch = vi.fn().mockResolvedValue(Response.json(challenge));
    vi.stubGlobal('fetch', fetch);
    const binding = {
      resourceId: '018f0000-0000-7000-8000-000000000711',
      resourceDigest: 'sha256:' + 'a'.repeat(64),
    };
    const operation = performWebAuthnStepUp(localFactAction, binding, {
      signal: controller.signal,
      isCurrent: () => current,
    });
    const rejection = expect(operation).rejects.toMatchObject({ name: 'AbortError' });
    await vi.waitFor(() => expect(get).toHaveBeenCalledOnce());
    expect(get).toHaveBeenCalledWith(expect.objectContaining({ signal: expect.any(AbortSignal) }));
    if (mode === 'context changed') current = false;
    else controller.abort();
    release(new Credential());
    await rejection;
    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0]![0]).toBe('/api/v1/ui/webauthn/assertion/challenge');
    expect(JSON.parse(String(fetch.mock.calls[0]![1].body))).toEqual({
      ...binding,
      actionIntentId: localFactAction.actionIntentId,
      actionIntentDigest: localFactAction.actionIntentDigest,
    });
  },
);

it.each(['expired', 'over-ceiling', 'invalid-date', 'expires-during-authenticator'] as const)(
  'rejects %s challenge before verification dispatch',
  async (mode) => {
    const issuedAt = Date.now();
    let now = issuedAt;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const bytes = (value: string) => new TextEncoder().encode(value).buffer;
    class Credential {
      rawId = bytes('credential');
      response = {
        authenticatorData: bytes('auth'),
        clientDataJSON: bytes('client'),
        signature: bytes('signature'),
      };
    }
    const get = vi.fn().mockImplementation(async () => {
      now = issuedAt + 10_000;
      return new Credential();
    });
    vi.stubGlobal('PublicKeyCredential', Credential);
    vi.stubGlobal('navigator', { credentials: { get } });
    const deadline =
      mode === 'expired'
        ? issuedAt
        : mode === 'over-ceiling'
          ? issuedAt + 300001
          : issuedAt + 10000;
    const fetch = vi.fn().mockResolvedValue(
      Response.json({
        publicKey: {
          challenge: 'Y2hhbGxlbmdlLWJpbmFyeS12YWx1ZS0wMDAwMDAwMDAwMDA',
          rpId: '127.0.0.1',
          allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
          timeout: 300000,
          userVerification: 'required',
        },
        expiresAt:
          mode === 'invalid-date'
            ? '2026-99-11T00:05:00.000000Z'
            : new Date(deadline).toISOString().replace('Z', '000Z'),
      }),
    );
    vi.stubGlobal('fetch', fetch);
    await expect(performWebAuthnStepUp(localFactAction)).rejects.toThrow();
    expect(fetch).toHaveBeenCalledOnce();
    if (mode === 'expires-during-authenticator') {
      expect(get).toHaveBeenCalledOnce();
      expect(get.mock.calls[0]![0].publicKey.timeout).toBe(10000);
    } else expect(get).not.toHaveBeenCalled();
  },
);

it.each([
  ['challenge deadline', 2000, 10000],
  ['browser timeout', 10000, 2000],
  ['caller cancellation', 10000, 10000],
] as const)(
  'settles an unresponsive authenticator at %s without dispatching verification',
  async (mode, lifetime, timeout) => {
    vi.useFakeTimers();
    try {
      class Credential {
        rawId = new TextEncoder().encode('credential').buffer;
        response = {
          authenticatorData: new TextEncoder().encode('auth').buffer,
          clientDataJSON: new TextEncoder().encode('client').buffer,
          signature: new TextEncoder().encode('signature').buffer,
        };
      }
      let release!: (value: Credential) => void;
      const get = vi
        .fn<(options: CredentialRequestOptions) => Promise<Credential>>()
        .mockImplementation(
          () =>
            new Promise<Credential>((resolve) => {
              release = resolve;
            }),
        );
      vi.stubGlobal('PublicKeyCredential', Credential);
      vi.stubGlobal('navigator', { credentials: { get } });
      const fetch = vi.fn().mockResolvedValue(
        Response.json({
          publicKey: {
            challenge: 'Y2hhbGxlbmdlLWJpbmFyeS12YWx1ZS0wMDAwMDAwMDAwMDA',
            rpId: 'localhost',
            allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
            timeout,
            userVerification: 'required',
          },
          expiresAt: new Date(Date.now() + lifetime).toISOString().replace('Z', '000Z'),
        }),
      );
      vi.stubGlobal('fetch', fetch);
      const controller = new AbortController();
      let outcome: unknown;
      const operation = performWebAuthnStepUp(localFactAction, undefined, {
        signal: controller.signal,
      });
      const settled = operation.then(
        () => {
          outcome = 'unexpected success';
        },
        (error: unknown) => {
          outcome = error;
        },
      );
      await vi.waitFor(() => expect(get).toHaveBeenCalledOnce());
      const nativeRequest = get.mock.calls[0]![0];
      if (mode === 'caller cancellation') {
        controller.abort();
        await vi.advanceTimersByTimeAsync(0);
      } else await vi.runAllTimersAsync();
      await Promise.resolve();
      if (mode === 'caller cancellation') expect(outcome).toBeInstanceOf(DOMException);
      else expect(outcome).toBeInstanceOf(Error);
      if (mode === 'caller cancellation') expect(outcome).toMatchObject({ name: 'AbortError' });
      else expect(outcome).toMatchObject({ message: expect.stringContaining('timed out') });
      expect(nativeRequest.signal!.aborted).toBe(true);
      await settled;
      // A browser may resolve late even after cancellation. It must never submit that assertion.
      release(new Credential());
      await Promise.resolve();
      expect(fetch).toHaveBeenCalledOnce();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  },
);
