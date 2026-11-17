import {
  localFactAction,
  localOperationSchema,
  localSessionBootstrapSchema,
  localSnapshotHeadersSchema,
} from './local-runtime-contract';
import {
  rfc3339MicrosUtcPattern,
  uuidV7Pattern,
  processSnapshotSchema,
  safeProblemSchema,
  type AuthorizedAction,
  type ProcessSnapshot,
  type SafeProblem,
} from './contracts';
import { z } from 'zod';

export class BffProblem extends Error {
  public constructor(
    readonly problem: SafeProblem,
    readonly status: number,
  ) {
    super(problem.title);
    this.name = 'BffProblem';
  }
}

export interface UiSessionBootstrap {
  readonly csrfToken: string;
  readonly etag: string;
  readonly idempotencyKey: string;
  readonly locale: string;
  readonly timeZone: string;
  readonly density: string;
  readonly theme: string;
}

const webAuthnChallengeSchema = z
  .object({
    publicKey: z
      .object({
        challenge: z.string().regex(/^[A-Za-z0-9_-]+$/),
        rpId: z.string().min(1).max(253),
        allowCredentials: z
          .array(
            z
              .object({
                id: z.string().regex(/^[A-Za-z0-9_-]+$/),
                type: z.literal('public-key'),
              })
              .strict(),
          )
          .min(1)
          .max(20),
        timeout: z.number().int().positive().max(3_000_000),
        userVerification: z.literal('required'),
      })
      .strict(),
    expiresAt: z.string().regex(rfc3339MicrosUtcPattern),
    durationProfile: z.literal('LOCAL_QA_10X').optional(),
    functionalTest: z.literal(true).optional(),
  })
  .strict()
  .refine((value) => value.publicKey.timeout <= (value.durationProfile ? 3_000_000 : 300_000));
const webAuthnVerifiedSchema = z
  .object({
    status: z.literal('verified'),
    stepUpVerifiedAt: z.string().regex(rfc3339MicrosUtcPattern),
  })
  .strict();

function assertSameOriginPath(path: string): void {
  if (!path.startsWith('/api/v1/ui/') || path.includes('://') || path.includes('\\')) {
    throw new Error('The browser may call only a registered same-origin UI BFF path.');
  }
}

function requestHeaders(headers: HeadersInit | undefined): Headers {
  const result = new Headers(headers);
  result.set('Accept', 'application/json');
  return result;
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) throw new Error('Invalid WebAuthn binary value.');
  return bytes;
}

function encodeBase64Url(value: ArrayBuffer | Uint8Array<ArrayBuffer>): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function isArrayBuffer(value: unknown): value is ArrayBuffer {
  return Object.prototype.toString.call(value) === '[object ArrayBuffer]';
}

async function parseResponse(
  response: Response,
  expected: 'application/json' | 'application/problem+json',
): Promise<unknown> {
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.split(';', 1)[0]?.trim().toLowerCase() !== expected) {
    throw new Error('The UI BFF returned an unexpected response representation.');
  }
  return response.json();
}

async function throwSafeProblem(
  response: Response,
  requestId?: string,
  correlationId?: string,
): Promise<never> {
  if (
    requestId &&
    correlationId &&
    (response.headers.get('x-request-id') !== requestId ||
      response.headers.get('x-correlation-id') !== correlationId)
  ) {
    throw new Error('The UI BFF returned invalid problem ownership headers.');
  }
  const body = await parseResponse(response, 'application/problem+json');
  const parsed = safeProblemSchema.safeParse(body);
  if (
    parsed.success &&
    parsed.data.status === response.status &&
    (!requestId || parsed.data.traceId === requestId)
  ) {
    throw new BffProblem(parsed.data, response.status);
  }
  throw new BffProblem(
    {
      type: 'https://errors.openpc.local/unavailable',
      code: 'PC-INTEGRATION-5001',
      status: 503,
      title: 'The requested process is unavailable.',
      traceId: uuidV7(),
      truthState: 'UNAVAILABLE',
      retryable: true,
    },
    503,
  );
}

function uuidV7(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let timestamp = Date.now();
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = timestamp & 0xff;
    timestamp = Math.floor(timestamp / 256);
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
  const value = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  if (!uuidV7Pattern.test(value)) throw new Error('UUIDv7 generation failed.');
  return value;
}

function exactResponseHeaders(response: Response, requestId: string, correlationId: string): void {
  const integerHeader = (name: string): number => {
    const value = response.headers.get(name);
    return value && /^(0|[1-9][0-9]*)$/u.test(value) ? Number(value) : Number.NaN;
  };
  const parsed = localSnapshotHeadersSchema.safeParse({
    etag: response.headers.get('etag'),
    apiVersion: response.headers.get('openpc-api-version'),
    rateLimit: integerHeader('ratelimit-limit'),
    rateRemaining: integerHeader('ratelimit-remaining'),
    rateReset: integerHeader('ratelimit-reset'),
    requestId: response.headers.get('x-request-id'),
    correlationId: response.headers.get('x-correlation-id'),
  });
  if (
    !parsed.success ||
    parsed.data.requestId !== requestId ||
    parsed.data.correlationId !== correlationId
  ) {
    throw new Error('The UI BFF returned invalid response ownership headers.');
  }
}

export async function readSnapshot(domain: string, signal?: AbortSignal): Promise<ProcessSnapshot> {
  const path = `/api/v1/ui/process-domains/${encodeURIComponent(domain)}`;
  assertSameOriginPath(path);
  const requestId = uuidV7();
  const correlationId = uuidV7();
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: requestHeaders({
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': localFactAction.participantRef,
      'X-Request-ID': requestId,
      'X-Correlation-ID': correlationId,
    }),
    signal,
  });
  if (!response.ok) {
    return throwSafeProblem(response, requestId, correlationId);
  }
  exactResponseHeaders(response, requestId, correlationId);
  return processSnapshotSchema.parse(await parseResponse(response, 'application/json'));
}

export async function readSessionBootstrap(signal?: AbortSignal): Promise<UiSessionBootstrap> {
  const path = '/api/v1/ui/session-bootstrap';
  assertSameOriginPath(path);
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: requestHeaders(undefined),
    signal,
  });
  if (!response.ok) return throwSafeProblem(response);
  return localSessionBootstrapSchema.parse(await parseResponse(response, 'application/json'));
}

export async function invokeAction(
  domain: string,
  action: AuthorizedAction,
  headers: { csrfToken: string; idempotencyKey: string; etag: string },
): Promise<unknown> {
  if (
    !action.path.startsWith(`/api/v1/ui/process-domains/${encodeURIComponent(domain)}/actions/`)
  ) {
    throw new Error('The server-declared action is outside this process domain.');
  }
  const path = action.path;
  assertSameOriginPath(path);
  const requestId = uuidV7();
  const correlationId = uuidV7();
  const response = await fetch(path, {
    method: action.method,
    credentials: 'same-origin',
    headers: requestHeaders({
      'Content-Type': 'application/json',
      'X-CSRF-Token': headers.csrfToken,
      'Idempotency-Key': headers.idempotencyKey,
      'If-Match': headers.etag,
      'OpenPC-Action-Intent-Digest': action.actionIntentDigest,
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': localFactAction.participantRef,
      'X-Request-ID': requestId,
      'X-Correlation-ID': correlationId,
    }),
    body: JSON.stringify({
      actionIntentId: action.actionIntentId,
      actionIntentDigest: action.actionIntentDigest,
      expectedRevision: '1',
      inputDigest: localFactAction.inputDigest,
      reason: 'Authorized local qualification and admission.',
      targetRef: localFactAction.targetRef,
    }),
  });
  if (!response.ok) {
    return throwSafeProblem(response, requestId, correlationId);
  }
  exactResponseHeaders(response, requestId, correlationId);
  return localOperationSchema.parse(await parseResponse(response, 'application/json'));
}

export async function performWebAuthnStepUp(
  action: Pick<AuthorizedAction, 'actionIntentId' | 'actionIntentDigest' | 'stepUp'> &
    Partial<AuthorizedAction>,
  binding?: { readonly resourceId: string; readonly resourceDigest: string },
  lifecycle?: { readonly signal?: AbortSignal; readonly isCurrent?: () => boolean },
): Promise<void> {
  const assertCurrent = () => {
    if (lifecycle?.signal?.aborted || lifecycle?.isCurrent?.() === false)
      throw new DOMException('The operation was cancelled.', 'AbortError');
  };
  assertCurrent();
  if (action.stepUp !== 'FRESH_WEBAUTHN_MAX_5M') {
    throw new Error('WebAuthn step-up is unavailable.');
  }
  const actionBinding = {
    actionIntentId: action.actionIntentId,
    actionIntentDigest: action.actionIntentDigest,
    ...binding,
  };
  const challengeResponse = await fetch('/api/v1/ui/webauthn/assertion/challenge', {
    method: 'POST',
    ...(lifecycle?.signal ? { signal: lifecycle.signal } : {}),
    credentials: 'same-origin',
    headers: requestHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(actionBinding),
  });
  assertCurrent();
  if (!challengeResponse.ok) return throwSafeProblem(challengeResponse);
  const challenge = webAuthnChallengeSchema.parse(
    await parseResponse(challengeResponse, 'application/json'),
  );
  assertCurrent();
  const deadline = Date.parse(challenge.expiresAt);
  const assertChallengeLive = () => {
    const remaining = deadline - Date.now();
    if (
      !Number.isFinite(deadline) ||
      remaining <= 0 ||
      remaining > (challenge.durationProfile ? 3_000_000 : 300_000)
    )
      throw new Error('The WebAuthn challenge expired or has an invalid deadline.');
    return remaining;
  };
  const remaining = assertChallengeLive();
  if (challenge.functionalTest) {
    const response = await fetch('/api/v1/ui/webauthn/assertion/functional', {
      method: 'POST',
      ...(lifecycle?.signal ? { signal: lifecycle.signal } : {}),
      credentials: 'same-origin',
      headers: requestHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ ...actionBinding, challenge: challenge.publicKey.challenge }),
    });
    assertCurrent();
    if (!response.ok) return throwSafeProblem(response);
    webAuthnVerifiedSchema.parse(await parseResponse(response, 'application/json'));
    return;
  }
  if (typeof PublicKeyCredential === 'undefined' || !navigator.credentials)
    throw new Error('WebAuthn step-up is unavailable.');
  const credential = await (async () => {
    const controller = new AbortController();
    const timeout = Math.min(challenge.publicKey.timeout, remaining);
    let cancel = () => {};
    let timer: ReturnType<typeof setTimeout> | undefined;
    const interrupted = new Promise<never>((_resolve, reject) => {
      cancel = () => {
        const error = new DOMException('The operation was cancelled.', 'AbortError');
        reject(error);
        controller.abort(error);
      };
      timer = setTimeout(() => {
        const error = new Error(
          'Authenticator verification timed out. Try again and approve your browser’s prompt.',
        );
        reject(error);
        controller.abort(error);
      }, timeout);
      lifecycle?.signal?.addEventListener('abort', cancel, { once: true });
      if (lifecycle?.signal?.aborted) cancel();
    });
    try {
      // Some browsers leave the credential promise pending after its timeout or cancellation.
      return await Promise.race([
        interrupted,
        navigator.credentials.get({
          signal: controller.signal,
          publicKey: {
            challenge: decodeBase64Url(challenge.publicKey.challenge),
            rpId: challenge.publicKey.rpId,
            allowCredentials: challenge.publicKey.allowCredentials.map((allowed) => ({
              id: decodeBase64Url(allowed.id),
              type: allowed.type,
            })),
            timeout,
            userVerification: challenge.publicKey.userVerification,
          },
        }),
      ]);
    } finally {
      clearTimeout(timer);
      lifecycle?.signal?.removeEventListener('abort', cancel);
    }
  })();
  assertCurrent();
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error('The authenticator did not return a public-key credential.');
  }
  const assertion = credential.response as AuthenticatorAssertionResponse;
  if (
    !('authenticatorData' in assertion) ||
    !isArrayBuffer(assertion.authenticatorData) ||
    !isArrayBuffer(assertion.clientDataJSON) ||
    !isArrayBuffer(assertion.signature)
  ) {
    throw new Error('The authenticator returned an invalid assertion.');
  }
  assertCurrent();
  assertChallengeLive();
  const verificationResponse = await fetch('/api/v1/ui/webauthn/assertion/verify', {
    method: 'POST',
    ...(lifecycle?.signal ? { signal: lifecycle.signal } : {}),
    credentials: 'same-origin',
    headers: requestHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      ...actionBinding,
      challenge: challenge.publicKey.challenge,
      assertion: {
        credentialId: encodeBase64Url(credential.rawId),
        authenticatorData: encodeBase64Url(assertion.authenticatorData),
        clientDataJson: encodeBase64Url(assertion.clientDataJSON),
        signature: encodeBase64Url(assertion.signature),
      },
    }),
  });
  assertCurrent();
  if (!verificationResponse.ok) return throwSafeProblem(verificationResponse);
  webAuthnVerifiedSchema.parse(await parseResponse(verificationResponse, 'application/json'));
  assertCurrent();
}
