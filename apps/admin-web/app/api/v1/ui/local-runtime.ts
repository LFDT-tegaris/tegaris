import { localQaExecutionTimeoutMs } from '../../../../../../packages/security-kernel/src/local-qa-duration-profile';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';

import { NextResponse, type NextRequest } from 'next/server';
import { validOidcAuthorizationEndpoint } from '../../../../lib/oidc-provider-response';
import {
  IdentitySessionUnavailable,
  readIdentitySessionResponse,
} from '../../../../lib/identity-session-read';
import { z } from 'zod';
import {
  functionalActor,
  functionalActorCookie,
  functionalContext,
  functionalContextCookie,
  readFunctionalTestProfile,
  type FunctionalTestProfile,
} from './functional-test-profile';

import {
  localFactAction,
  localFactCommandSchema,
  localOwnerReadSchema,
  localOwnerResultSchema,
  localOperationSchema,
  localReplacementDocument,
  processSnapshotSchema,
  routes,
  safeProblemRelations,
  type ProcessSnapshot,
  type SafeProblem,
} from '@openpc/ui-shell';

// Finite installed owner transaction budget, separate from proof/authentication freshness.
export function localOwnerFetch(input: RequestInfo | URL, init: RequestInit = {}) {
  const budgetMs = localQaExecutionTimeoutMs(120_000);
  const timeout = AbortSignal.timeout(budgetMs);
  const supplied = { ...init };
  const callerSignal =
    supplied.signal === undefined && input instanceof Request ? input.signal : supplied.signal;
  const signal = callerSignal ? AbortSignal.any([callerSignal, timeout]) : timeout;
  const started = performance.now();
  // Request objects carry their own method. An omitted override must never
  // turn a mutation into a retryable read.
  const method =
    supplied.method ??
    (typeof input === 'string' || input instanceof URL
      ? 'GET'
      : input instanceof Request
        ? input.method
        : undefined);
  const retryableRead =
    method?.toUpperCase() === 'GET' &&
    (typeof input === 'string' || input instanceof URL || input instanceof Request);
  const requestInput = retryableRead
    ? input instanceof URL
      ? input.href
      : input instanceof Request
        ? new Request(input)
        : input
    : input;
  const options = {
    ...supplied,
    ...(retryableRead && supplied.headers ? { headers: new Headers(supplied.headers) } : {}),
    signal,
  };
  const data = (value: unknown, key: string): unknown => {
    if ((typeof value !== 'object' && typeof value !== 'function') || value === null)
      return undefined;
    try {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor && 'value' in descriptor ? descriptor.value : undefined;
    } catch {
      return undefined;
    }
  };
  async function read() {
    try {
      return await fetch(requestInput, options);
    } catch (error: unknown) {
      const code = data(data(error, 'cause'), 'code') ?? data(error, 'code');
      if (
        !retryableRead ||
        signal.aborted ||
        !['EAI_AGAIN', 'ECONNREFUSED'].includes(typeof code === 'string' ? code : '')
      )
        throw error;
      try {
        process.stderr.write(
          `${JSON.stringify({ boundary: 'local_owner_read_retry', failure: code })}\n`,
        );
      } catch {
        // The diagnostic sink cannot decide whether a read proceeds.
      }
      // One connection-establishment retry shares the original deadline.
      // Mutations, received HTTP failures and lost responses are never retried.
      await delay(250, undefined, { signal }).catch((cause: unknown) => {
        throw signal.aborted ? signal.reason : cause;
      });
      return fetch(requestInput, options);
    }
  }
  return read().catch((error: unknown) => {
    // Only fixed transport categories are logged. Never inspect messages,
    // URLs, headers or accessor properties from an error or its cause.
    const code = data(data(error, 'cause'), 'code') ?? data(error, 'code');
    const known = [
      'UND_ERR_HEADERS_TIMEOUT',
      'UND_ERR_BODY_TIMEOUT',
      'UND_ERR_CONNECT_TIMEOUT',
      'UND_ERR_SOCKET',
      'ECONNREFUSED',
      'ECONNRESET',
      'ENOTFOUND',
      'EAI_AGAIN',
    ];
    const failure = signal.aborted
      ? timeout.aborted && callerSignal?.aborted
        ? 'CALLER_AND_DEADLINE_ABORTED'
        : timeout.aborted
          ? 'REQUEST_DEADLINE'
          : 'CALLER_ABORT'
      : typeof code === 'string' && known.includes(code)
        ? code
        : 'UNCLASSIFIED_TRANSPORT';
    try {
      process.stderr.write(
        `${JSON.stringify({
          boundary: 'local_owner_fetch',
          failure,
          elapsedMs: Math.round(performance.now() - started),
          budgetMs,
        })}\n`,
      );
    } catch {
      // Diagnostic failure must never replace the original transport rejection.
    }
    throw error;
  });
}

const sessionCookie = 'openpc_local_runtime_session';
const domain = 'fact-source-projection-bridge';
const { actionIntentId, actionIntentDigest, idempotencyKey } = localFactAction;
const stepUpMaximumAgeMs = 5 * 60 * 1000;
const noStoreHeaders = { 'Cache-Control': 'no-store' } as const;
const actionPath = `/api/v1/ui/process-domains/${domain}/actions/qualify-admit`;
const uuidV7Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const sealedSessionVersion = 1;
const sealedSessionIvLength = 12;
const sealedSessionTagLength = 16;
const digestPattern = /^sha256:[0-9a-f]{64}$/u;
const sessionCommandContextSchema = z
  .object({
    revision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
    actionIntentDigest: z.string().regex(digestPattern),
    participantId: z.uuid(),
    privacyDomainId: z.uuid(),
    role: z.enum(['operator', 'viewer']),
    replay: z.boolean(),
    replayCsrfToken: z.string().min(32).max(256).optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.replay !== (value.replayCsrfToken !== undefined)) {
      context.addIssue({ code: 'custom', message: 'replay CSRF state is inconsistent' });
    }
  });
const identityOperationSchema = z
  .object({
    operationId: z.string().regex(uuidV7Pattern),
    resourceRef: z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u),
    actionIntentId: z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u),
    intentDigest: z.string().regex(digestPattern),
    idempotencyKey: z.string().min(16).max(128),
    state: z.literal('SUCCEEDED'),
    truthState: z.literal('SUCCESS'),
    createdAt: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u),
    updatedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u),
    revision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  })
  .strict();
const sealedPayloadAad = {
  'session': Buffer.from('openpc:bff-session:v1', 'utf8'),
  'oidc-custody': Buffer.from('openpc:bff-oidc-custody:v1', 'utf8'),
  'webauthn-custody': Buffer.from('openpc:bff-webauthn-custody:v1', 'utf8'),
  'grant-review': Buffer.from('openpc:bff-grant-review:v1', 'utf8'),
  'role-review': Buffer.from('openpc:bff-role-review:v1', 'utf8'),
  'principal-review': Buffer.from('openpc:bff-principal-review:v1', 'utf8'),
  'group-review': Buffer.from('openpc:bff-group-review:v1', 'utf8'),
  'directory-review': Buffer.from('openpc:bff-directory-review:v1', 'utf8'),
  'invitation-review': Buffer.from('openpc:bff-invitation-review:v1', 'utf8'),
  'participant-bootstrap-review': Buffer.from('openpc:bff-participant-bootstrap-review:v1', 'utf8'),
  'invitation-custody': Buffer.from('openpc:bff-invitation-custody:v1', 'utf8'),
  'invitation-result': Buffer.from('openpc:bff-invitation-result:v1', 'utf8'),
  'workload-review': Buffer.from('openpc:bff-workload-review:v1', 'utf8'),
  'credential-review': Buffer.from('openpc:bff-credential-review:v1', 'utf8'),
  'recovery-review': Buffer.from('openpc:bff-recovery-review:v1', 'utf8'),
  'participant-review': Buffer.from('openpc:bff-participant-review:v1', 'utf8'),
  'policy-release-review': Buffer.from('openpc:bff-policy-release-review:v1', 'utf8'),
  'runtime-setup-review': Buffer.from('openpc:bff-runtime-setup-review:v1', 'utf8'),
  'indexer-setup-review': Buffer.from('openpc:bff-indexer-setup-review:v1', 'utf8'),
  'transaction-review': Buffer.from('openpc:bff-transaction-review:v1', 'utf8'),
  'rpc-access-review': Buffer.from('openpc:bff-rpc-access-review:v1', 'utf8'),
  'platform-ceiling-review': Buffer.from('openpc:bff-platform-ceiling-review:v1', 'utf8'),
  'policy-activation-stage-review': Buffer.from(
    'openpc:bff-policy-activation-stage-review:v1',
    'utf8',
  ),
} as const;
export type SealedPayloadPurpose = keyof typeof sealedPayloadAad;

export interface LocalConfig {
  readonly functionalTest?: FunctionalTestProfile;
  readonly publicApiUrl: string;
  readonly identityUrl: string;
  readonly factUrl: string;
  readonly policyUrl: string;
  readonly oidcAuthorizationUrl: string;
  readonly oidcParticipantId?: string;
  readonly identityToken: string;
  readonly factToken: string;
  readonly policyToken: string;
  readonly cookieKey: Buffer;
}

export interface IdentitySession {
  readonly sessionToken: string;
  readonly role: 'operator' | 'viewer';
  readonly sessionId: string;
  readonly principalId: string;
  readonly participantId: string;
  readonly contextMode: 'PLATFORM' | 'PARTICIPANT';
  readonly platformBootstrapEligible?: boolean;
  readonly availableContexts?: readonly { participantId: string; privacyDomainId: string }[];
  readonly privacyDomainId?: string;
  readonly contextEpoch: string;
  readonly sessionEpoch?: string;
  readonly participantEpoch?: string;
  readonly principalEpoch?: string;
  readonly assignmentId?: string;
  readonly assignmentRowVersion?: string;
  readonly authorityEnvelopeId?: string;
  readonly authorityEpoch?: string;
  readonly delegationEpoch?: string;
  readonly stepUpVerifiedAt: string | null;
}

async function fileSecret(path: string | undefined): Promise<string> {
  if (!path) throw new Error('local runtime secret path unavailable');
  const value = (await readFile(path, 'utf8')).trim();
  if (value.length < 32 || value.length > 256 || !/^\S+$/u.test(value)) {
    throw new Error('local runtime secret invalid');
  }
  return value;
}

export async function readLocalRuntimeConfig(
  environment: NodeJS.ProcessEnv,
): Promise<LocalConfig | undefined> {
  if (environment.OPENPC_LOCAL_RUNTIME !== '1') return undefined;
  const allowed = new Set([
    'OPENPC_PUBLIC_API_INTERNAL_URL',
    'OPENPC_IDENTITY_INTERNAL_URL',
    'OPENPC_FACT_INTERNAL_URL',
    'OPENPC_POLICY_INTERNAL_URL',
    'OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL',
    'OPENPC_OIDC_PARTICIPANT_ID',
    'OPENPC_IDENTITY_INTERNAL_TOKEN_FILE',
    'OPENPC_FACT_INTERNAL_TOKEN_FILE',
    'OPENPC_POLICY_INTERNAL_TOKEN_FILE',
    'OPENPC_BFF_COOKIE_KEY_FILE',
  ]);
  for (const key of Object.keys(environment)) {
    if (/^OPENPC_(?:IDENTITY|FACT|POLICY|OIDC|BFF|PUBLIC_API)_/u.test(key) && !allowed.has(key)) {
      throw new Error(`unknown local BFF variable: ${key}`);
    }
  }
  const identityUrl = environment.OPENPC_IDENTITY_INTERNAL_URL;
  const factUrl = environment.OPENPC_FACT_INTERNAL_URL;
  const policyUrl = environment.OPENPC_POLICY_INTERNAL_URL;
  const publicApiUrl = environment.OPENPC_PUBLIC_API_INTERNAL_URL;
  const oidcAuthorizationUrl = environment.OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL;
  const oidcParticipantId = environment.OPENPC_OIDC_PARTICIPANT_ID;
  if (oidcParticipantId !== undefined && !z.uuid().safeParse(oidcParticipantId).success) {
    throw new Error('OIDC organization configuration invalid');
  }
  const validOwnerUrl = (value: string | undefined) => {
    try {
      const parsed = new URL(value ?? '');
      return (
        parsed.protocol === 'http:' &&
        !parsed.username &&
        !parsed.password &&
        parsed.pathname === '/'
      );
    } catch {
      return false;
    }
  };
  if (
    !validOwnerUrl(publicApiUrl) ||
    !validOwnerUrl(identityUrl) ||
    !validOwnerUrl(factUrl) ||
    !validOwnerUrl(policyUrl) ||
    !validOidcAuthorizationEndpoint(oidcAuthorizationUrl)
  ) {
    throw new Error('local runtime owner URL invalid');
  }
  return {
    functionalTest: await readFunctionalTestProfile(environment),
    publicApiUrl: publicApiUrl!,
    identityUrl: identityUrl!,
    factUrl: factUrl!,
    policyUrl: policyUrl!,
    oidcAuthorizationUrl: oidcAuthorizationUrl!,
    ...(oidcParticipantId === undefined ? {} : { oidcParticipantId }),
    identityToken: await fileSecret(environment.OPENPC_IDENTITY_INTERNAL_TOKEN_FILE),
    factToken: await fileSecret(environment.OPENPC_FACT_INTERNAL_TOKEN_FILE),
    policyToken: await fileSecret(environment.OPENPC_POLICY_INTERNAL_TOKEN_FILE),
    cookieKey: Buffer.from(await fileSecret(environment.OPENPC_BFF_COOKIE_KEY_FILE)),
  };
}

export async function localRuntimeConfig(): Promise<LocalConfig | undefined> {
  return readLocalRuntimeConfig(process.env);
}

function uuidV7(): string {
  const bytes = randomBytes(16);
  let timestamp = Date.now();
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = timestamp & 0xff;
    timestamp = Math.floor(timestamp / 256);
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function responseIds(request?: NextRequest) {
  const requestId = request?.headers.get('x-request-id');
  const correlationId = request?.headers.get('x-correlation-id');
  return {
    requestId: requestId && uuidV7Pattern.test(requestId) ? requestId : uuidV7(),
    correlationId: correlationId && uuidV7Pattern.test(correlationId) ? correlationId : uuidV7(),
  };
}

export function safeProblem(
  code: keyof typeof safeProblemRelations,
  request?: NextRequest,
): NextResponse<SafeProblem> {
  const ids = responseIds(request);
  const relation = safeProblemRelations[code];
  return NextResponse.json(
    {
      type: relation.problemType,
      code,
      status: relation.status,
      title: 'The requested process is unavailable.',
      traceId: ids.requestId,
      truthState: relation.truthState,
      retryable: relation.retryable,
    },
    {
      status: relation.status,
      headers: {
        ...noStoreHeaders,
        'Content-Type': 'application/problem+json',
        'X-Request-ID': ids.requestId,
        'X-Correlation-ID': ids.correlationId,
      },
    },
  );
}

function sessionMutationFailure(
  stage: string,
  code: keyof typeof safeProblemRelations,
  request: NextRequest,
  upstreamStatus?: number,
): NextResponse<SafeProblem> {
  process.stderr.write(
    `OPENPC_LOCAL_SESSION_MUTATION_FAILURE|stage=${stage}|upstream_status=${upstreamStatus ?? 'none'}\n`,
  );
  return safeProblem(code, request);
}

function signature(value: string, key: Buffer): Buffer {
  return createHmac('sha256', key).update(value).digest();
}

export function framedDigest(domainSeparator: string, values: readonly string[]): string {
  const hash = createHash('sha256');
  for (const value of [domainSeparator, ...values]) {
    const bytes = Buffer.from(value, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return `sha256:${hash.digest('hex')}`;
}

function targetEtag(): string {
  return `"${framedDigest('openpc:local-fact-target-etag:v1', [
    localFactAction.resourceRef,
    '1',
    '1',
    '1',
  ])}"`;
}

function projectionEtag(projection: {
  readonly factCount: number;
  readonly latestCandidateId: string | null;
  readonly latestState: string | null;
  readonly observedAtMs: number | null;
}): string {
  return `"${framedDigest('openpc:ui-snapshot-etag:v1', [
    String(projection.factCount),
    projection.latestCandidateId ?? '',
    projection.latestState ?? '',
    String(projection.observedAtMs ?? 0),
  ])}"`;
}

export function csrfToken(
  sessionToken: string,
  key: Buffer,
  path: string = actionPath,
  intentDigest: string = actionIntentDigest,
): string {
  const expiresAt = Date.now() + stepUpMaximumAgeMs;
  const expiry = Buffer.alloc(8);
  expiry.writeBigUInt64BE(BigInt(expiresAt));
  const mac = signature(
    ['openpc:csrf:v1', sessionToken, 'POST', path, intentDigest, String(expiresAt)]
      .map((value) => `${Buffer.byteLength(value, 'utf8')}:${value}`)
      .join(''),
    key,
  );
  return Buffer.concat([expiry, mac]).toString('base64url');
}

export function validCsrf(
  token: string | null,
  sessionToken: string,
  key: Buffer,
  path: string = actionPath,
  intentDigest: string = actionIntentDigest,
): boolean {
  if (!token || !/^[A-Za-z0-9_-]+$/u.test(token)) return false;
  const bytes = Buffer.from(token, 'base64url');
  if (bytes.length !== 40 || bytes.toString('base64url') !== token) return false;
  const expiresAt = Number(bytes.readBigUInt64BE(0));
  const now = Date.now();
  if (
    !Number.isSafeInteger(expiresAt) ||
    expiresAt <= now ||
    expiresAt > now + stepUpMaximumAgeMs
  ) {
    return false;
  }
  const expected = csrfTokenForExpiry(sessionToken, key, expiresAt, path, intentDigest);
  return timingSafeEqual(bytes, expected);
}

function csrfTokenForExpiry(
  sessionToken: string,
  key: Buffer,
  expiresAt: number,
  path: string = actionPath,
  intentDigest: string = actionIntentDigest,
): Buffer {
  const expiry = Buffer.alloc(8);
  expiry.writeBigUInt64BE(BigInt(expiresAt));
  const mac = signature(
    ['openpc:csrf:v1', sessionToken, 'POST', path, intentDigest, String(expiresAt)]
      .map((value) => `${Buffer.byteLength(value, 'utf8')}:${value}`)
      .join(''),
    key,
  );
  return Buffer.concat([expiry, mac]);
}

export function rfc3339Micros(milliseconds = Date.now()): string {
  return new Date(milliseconds).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
}

/** Bound memory while consuming the stream, including requests without a
 * trustworthy Content-Length. Small commands allocate only a small buffer. */
export async function readPublicCommand(request: Request, maximumBytes = 4096) {
  const reader = request.body?.getReader();
  if (!reader) return undefined;
  let buffer = Buffer.allocUnsafe(Math.min(4096, maximumBytes));
  let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value.byteLength > maximumBytes - length) {
        await reader.cancel();
        return undefined;
      }
      const needed = length + value.byteLength;
      if (needed > buffer.byteLength) {
        const grown = Buffer.allocUnsafe(
          Math.min(maximumBytes, Math.max(needed, buffer.byteLength * 2)),
        );
        buffer.copy(grown, 0, 0, length);
        buffer = grown;
      }
      buffer.set(value, length);
      length = needed;
    }
    return parsePublicCommand(
      new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length)),
      maximumBytes,
    );
  } catch {
    return undefined;
  } finally {
    reader.releaseLock();
  }
}

export function parsePublicCommand(raw: string, maximumBytes = 4096) {
  if (Buffer.byteLength(raw, 'utf8') > maximumBytes) return undefined;
  const keys = new Set<string>();
  let depth = 0;
  let index = 0;
  while (index < raw.length) {
    const character = raw[index];
    if (character === '{' || character === '[') {
      depth += 1;
      index += 1;
      continue;
    }
    if (character === '}' || character === ']') {
      depth -= 1;
      index += 1;
      continue;
    }
    if (character !== '"') {
      index += 1;
      continue;
    }
    const start = index;
    index += 1;
    let escaped = false;
    while (index < raw.length) {
      const byte = raw[index]!;
      if (!escaped && byte === '"') break;
      escaped = !escaped && byte === '\\';
      if (byte !== '\\') escaped = false;
      index += 1;
    }
    if (index >= raw.length) return undefined;
    const encoded = raw.slice(start, index + 1);
    index += 1;
    let lookahead = index;
    while (/\s/u.test(raw[lookahead] ?? '')) lookahead += 1;
    if (depth === 1 && raw[lookahead] === ':') {
      let key: unknown;
      try {
        key = JSON.parse(encoded);
      } catch {
        return undefined;
      }
      if (typeof key !== 'string' || keys.has(key)) return undefined;
      keys.add(key);
    }
  }
  if (depth !== 0) return undefined;
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}

export function sealBffPayload(
  payload: unknown,
  key: Buffer,
  purpose: SealedPayloadPurpose = 'session',
): string {
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const iv = randomBytes(sealedSessionIvLength);
  const cipher = createCipheriv('aes-256-gcm', createHash('sha256').update(key).digest(), iv);
  cipher.setAAD(sealedPayloadAad[purpose]);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([
    Buffer.from([sealedSessionVersion]),
    iv,
    cipher.getAuthTag(),
    ciphertext,
  ]).toString('base64url');
}

export function openBffPayload(
  value: string | undefined,
  key: Buffer,
  purpose: SealedPayloadPurpose = 'session',
): unknown {
  if (!value || !/^[A-Za-z0-9_-]+$/u.test(value)) return undefined;
  try {
    const sealed = Buffer.from(value, 'base64url');
    if (
      sealed.toString('base64url') !== value ||
      sealed.length <= 1 + sealedSessionIvLength + sealedSessionTagLength ||
      sealed[0] !== sealedSessionVersion
    ) {
      return undefined;
    }
    const ivEnd = 1 + sealedSessionIvLength;
    const tagEnd = ivEnd + sealedSessionTagLength;
    const decipher = createDecipheriv(
      'aes-256-gcm',
      createHash('sha256').update(key).digest(),
      sealed.subarray(1, ivEnd),
    );
    decipher.setAAD(sealedPayloadAad[purpose]);
    decipher.setAuthTag(sealed.subarray(ivEnd, tagEnd));
    const plaintext = Buffer.concat([decipher.update(sealed.subarray(tagEnd)), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
}

export function encodeBffSession(session: IdentitySession, key: Buffer): string {
  return sealBffPayload({ sessionToken: session.sessionToken, role: session.role }, key);
}

export function decodeBffSession(value: string | undefined, key: Buffer) {
  const decoded = openBffPayload(value, key);
  if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) return undefined;
  const input = decoded as Record<string, unknown>;
  if (
    Object.keys(input).length !== 2 ||
    typeof input.sessionToken !== 'string' ||
    (input.role !== 'operator' && input.role !== 'viewer')
  ) {
    return undefined;
  }
  return { sessionToken: input.sessionToken, role: input.role };
}

async function identityCall<T>(
  runtime: LocalConfig,
  path: string,
  body: unknown,
): Promise<T | undefined> {
  try {
    const response = await localOwnerFetch(`${runtime.identityUrl}${path}`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Authorization': `Bearer ${runtime.identityToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    return response.ok ? ((await response.json()) as T) : undefined;
  } catch {
    return undefined;
  }
}

export function identityOwnerHeaders(
  runtime: LocalConfig,
  session: IdentitySession,
  browserOrigin?: string,
) {
  return {
    'Cookie': `__Host-openpc_session=${session.sessionToken}`,
    'Content-Type': 'application/json',
    'Origin': new URL(runtime.identityUrl).origin,
    ...(browserOrigin === undefined
      ? {}
      : {
          'Authorization': `Bearer ${runtime.identityToken}`,
          'X-OpenPC-Browser-Origin': browserOrigin,
        }),
  };
}

export async function identityCsrf(
  runtime: LocalConfig,
  session: IdentitySession,
  actionIntentId: string,
): Promise<string | undefined> {
  const response = await localOwnerFetch(`${runtime.identityUrl}/api/v1/session/csrf`, {
    method: 'POST',
    cache: 'no-store',
    headers: identityOwnerHeaders(runtime, session),
    body: JSON.stringify({ actionIntentId }),
  }).catch(() => undefined);
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type'))) {
    const problem =
      response === undefined
        ? undefined
        : z
            .object({
              error: z.object({ code: z.string().regex(/^PC-[A-Z]+-[0-9]+$/u) }).passthrough(),
            })
            .passthrough()
            .safeParse(
              await response
                .clone()
                .json()
                .catch(() => undefined),
            );
    process.stderr.write(
      `OPENPC_LOCAL_CSRF_FAILURE|status=${response?.status ?? 0}|code=${problem?.success ? problem.data.error.code : 'unclassified'}\n`,
    );
    return undefined;
  }
  const parsed = z
    .object({ csrfToken: z.string().min(32).max(256) })
    .strict()
    .safeParse(await response.json());
  return parsed.success ? parsed.data.csrfToken : undefined;
}

function readIdentitySessionToken(runtime: LocalConfig, sessionToken: string) {
  return readIdentitySessionResponse(
    localOwnerFetch(`${runtime.identityUrl}/internal/v1/local/session/validate`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Authorization': `Bearer ${runtime.identityToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ sessionToken }),
    }),
  );
}

export async function validateIdentitySessionToken(
  runtime: LocalConfig,
  sessionToken: string,
): Promise<Omit<IdentitySession, 'sessionToken'> | undefined> {
  const result = await readIdentitySessionToken(runtime, sessionToken);
  return result.state === 'AUTHENTICATED' ? result.session : undefined;
}

async function requiredIdentitySessionToken(runtime: LocalConfig, sessionToken: string) {
  const result = await readIdentitySessionToken(runtime, sessionToken);
  if (result.state === 'UNAVAILABLE') throw new IdentitySessionUnavailable();
  return result.state === 'AUTHENTICATED' ? result.session : undefined;
}

export async function authenticated(
  request: NextRequest,
  runtime: LocalConfig,
  readSession = validateIdentitySessionToken,
) {
  if (runtime.functionalTest)
    return functionalIdentitySession(
      runtime,
      request.cookies.get(functionalActorCookie)?.value,
      request.cookies.get(functionalContextCookie)?.value,
      readSession,
    );
  const local = decodeBffSession(request.cookies.get(sessionCookie)?.value, runtime.cookieKey);
  if (!local) return undefined;
  const session = await readSession(runtime, local.sessionToken);
  return session && session.role === local.role
    ? { ...session, sessionToken: local.sessionToken }
    : undefined;
}

export async function functionalIdentitySession(
  runtime: LocalConfig,
  selected?: string,
  selectedContext?: string,
  readSession = validateIdentitySessionToken,
) {
  const role = functionalActor(selected);
  const context = functionalContext(selectedContext);
  const actor = role && runtime.functionalTest?.actors[role];
  const sessionToken =
    context === 'PARTICIPANT'
      ? actor?.sessionToken
      : context === 'PLATFORM'
        ? actor?.platformSessionToken
        : undefined;
  if (!actor || !sessionToken) return undefined;
  const session = await readSession(runtime, sessionToken);
  return session &&
    session.role === role &&
    session.principalId === actor.principalId &&
    session.participantId === actor.participantId &&
    session.contextMode === context &&
    (context === 'PARTICIPANT'
      ? session.privacyDomainId === actor.privacyDomainId
      : session.privacyDomainId === undefined && session.platformBootstrapEligible === true)
    ? { ...session, sessionToken }
    : undefined;
}

export function sameOrigin(request: NextRequest): boolean {
  const origin = request.headers.get('origin');
  const host = request.headers.get('host');
  if (!origin || !host) return false;
  try {
    const source = new URL(origin);
    return (
      source.origin === origin &&
      source.protocol === request.nextUrl.protocol &&
      source.host === host
    );
  } catch {
    return false;
  }
}

export function hasJsonContentType(value: string | null): boolean {
  return value?.split(';', 1)[0]?.trim().toLowerCase() === 'application/json';
}

export async function localRuntimeStatus(request: NextRequest) {
  let runtime: LocalConfig | undefined;
  try {
    runtime = await localRuntimeConfig();
  } catch {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
  if (!runtime) return NextResponse.json({ enabled: false }, { headers: noStoreHeaders });
  let session: IdentitySession | undefined;
  try {
    session = await authenticated(request, runtime, requiredIdentitySessionToken);
  } catch (error) {
    if (error instanceof IdentitySessionUnavailable)
      return safeProblem('PC-INTEGRATION-5001', request);
    throw error;
  }
  return NextResponse.json(
    session
      ? {
          enabled: true,
          authenticated: true,
          role: session.role,
          sessionId: session.sessionId,
          principalId: session.principalId,
          participantId: session.participantId,
          contextMode: session.contextMode,
          ...(session.privacyDomainId === undefined
            ? {}
            : { privacyDomainId: session.privacyDomainId }),
          contextEpoch: session.contextEpoch,
          stepUpVerifiedAt: session.stepUpVerifiedAt,
          availableContexts: session.availableContexts ?? [],
          ...(runtime.functionalTest
            ? {
                functionalTest: true,
                ...(runtime.functionalTest.actors[session.role].platformSessionToken
                  ? { functionalPlatformConfigured: true }
                  : {}),
              }
            : {}),
        }
      : { enabled: true, authenticated: false },
    { headers: noStoreHeaders },
  );
}

export async function localLogin(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005');
  if (!sameOrigin(request)) return safeProblem('PC-AUTH-0002', request);
  const body = (await request.json().catch(() => undefined)) as unknown;
  if (!body || typeof body !== 'object' || Array.isArray(body))
    return safeProblem('PC-DATA-6004', request);
  const input = body as Record<string, unknown>;
  if (
    Object.keys(input).length !== 2 ||
    (input.role !== 'operator' && input.role !== 'viewer') ||
    typeof input.credential !== 'string'
  ) {
    return safeProblem('PC-DATA-6004', request);
  }
  const session = await identityCall<IdentitySession>(
    runtime,
    '/internal/v1/local/session/login',
    input,
  );
  if (!session) return safeProblem('PC-AUTH-0005', request);
  const response = NextResponse.json(
    { status: 'authenticated', role: session.role },
    { status: 201 },
  );
  response.cookies.set(sessionCookie, encodeBffSession(session, runtime.cookieKey), {
    httpOnly: true,
    secure: request.nextUrl.protocol === 'https:',
    sameSite: 'strict',
    path: '/',
    maxAge: 12 * 60 * 60,
  });
  return response;
}

function canonicalFlatDigest(value: Readonly<Record<string, string>>): string {
  const canonical = `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${JSON.stringify(value[key])}`)
    .join(',')}}`;
  return `sha256:${createHash('sha256').update(canonical).digest('hex')}`;
}

export function identitySessionToken(response: Response): string | undefined {
  const cookie = response.headers.get('set-cookie');
  const token = cookie?.split(';', 1)[0]?.split('=', 2).at(1);
  return token && /^[0-9a-f-]{36}\.[0-9a-f-]{36}$/u.test(token) ? token : undefined;
}

async function localSessionMutation(
  request: NextRequest,
  input: {
    readonly actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' | 'ACT-IDENTITY_DELETE_SESSION-V1';
    readonly path: '/api/v1/session/refresh' | '/api/v1/session/logout';
    readonly reason: string;
  },
) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request)) return safeProblem('PC-AUTH-0002', request);
  const local = decodeBffSession(request.cookies.get(sessionCookie)?.value, runtime.cookieKey);
  const [participantId, sessionId, extraTokenPart] = local?.sessionToken.split('.') ?? [];
  if (
    !local ||
    participantId === undefined ||
    sessionId === undefined ||
    extraTokenPart !== undefined ||
    !uuidV7Pattern.test(participantId) ||
    !uuidV7Pattern.test(sessionId)
  ) {
    return safeProblem('PC-AUTH-0005', request);
  }
  const mutationCandidate: Readonly<Record<string, string>> =
    input.path === '/api/v1/session/refresh'
      ? { sessionId, operation: 'REFRESH', reason: input.reason }
      : { sessionId, reason: input.reason };
  const candidateDigest = canonicalFlatDigest(mutationCandidate);
  const idempotencyKey = `session-${input.actionIntentId === 'ACT-IDENTITY_DELETE_SESSION-V1' ? 'logout' : 'refresh'}-${createHash(
    'sha256',
  )
    .update(local.sessionToken)
    .digest('hex')}`;
  const catalogOperationId =
    input.path === '/api/v1/session/refresh' ? 'ID-OP-SESSION-REFRESH' : 'ID-OP-SESSION-REVOKE';
  const ownerUrl = new URL(runtime.identityUrl);
  const ownerOrigin = ownerUrl.origin;
  const contextResponse = await localOwnerFetch(
    `${runtime.identityUrl}/internal/v1/local/session/command-context`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Authorization': `Bearer ${runtime.identityToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sessionToken: local.sessionToken,
        actionIntentId: input.actionIntentId,
        catalogOperationId,
        idempotencyKey,
        candidateDigest,
        origin: ownerOrigin,
        host: ownerUrl.host,
      }),
    },
  ).catch(() => undefined);
  if (!contextResponse?.ok || !hasJsonContentType(contextResponse.headers.get('content-type'))) {
    return sessionMutationFailure(
      'command-context-response',
      contextResponse ? 'PC-AUTH-0005' : 'PC-INTEGRATION-5001',
      request,
      contextResponse?.status,
    );
  }
  const context = sessionCommandContextSchema.safeParse(await contextResponse.json());
  if (!context.success) {
    return sessionMutationFailure(
      'command-context-schema',
      'PC-INTEGRATION-5001',
      request,
      contextResponse.status,
    );
  }
  if (context.data.participantId !== participantId || context.data.role !== local.role) {
    return safeProblem('PC-AUTH-0005', request);
  }
  let csrfToken = context.data.replayCsrfToken;
  if (!context.data.replay) {
    const csrfResponse = await localOwnerFetch(`${runtime.identityUrl}/api/v1/session/csrf`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': `__Host-openpc_session=${local.sessionToken}`,
        'Origin': ownerOrigin,
      },
      body: JSON.stringify({ actionIntentId: input.actionIntentId }),
    }).catch(() => undefined);
    if (!csrfResponse?.ok || !hasJsonContentType(csrfResponse.headers.get('content-type'))) {
      return sessionMutationFailure(
        'csrf-response',
        csrfResponse ? 'PC-AUTH-0005' : 'PC-INTEGRATION-5001',
        request,
        csrfResponse?.status,
      );
    }
    const csrf = z
      .object({ csrfToken: z.string().min(32).max(256) })
      .strict()
      .safeParse(await csrfResponse.json());
    if (!csrf.success) {
      return sessionMutationFailure(
        'csrf-schema',
        'PC-INTEGRATION-5001',
        request,
        csrfResponse.status,
      );
    }
    csrfToken = csrf.data.csrfToken;
  }
  if (csrfToken === undefined) {
    return sessionMutationFailure('csrf-replay-context', 'PC-INTEGRATION-5001', request);
  }
  const command = {
    targetRef: `urn:openpc:resource:${sessionId}`,
    actionIntentId: input.actionIntentId,
    actionIntentDigest: context.data.actionIntentDigest,
    inputDigest: candidateDigest,
    expectedRevision: context.data.revision,
    reason: input.reason,
  };
  const ids = responseIds(request);
  const etag = `"${canonicalFlatDigest({
    resourceType: 'session',
    revision: context.data.revision,
    sessionId,
  })}"`;
  const ownerResponse = await localOwnerFetch(`${runtime.identityUrl}${input.path}`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': `__Host-openpc_session=${local.sessionToken}`,
      'Origin': ownerOrigin,
      'X-CSRF-Token': csrfToken,
      'X-Request-ID': ids.requestId,
      'X-Correlation-ID': ids.correlationId,
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': `urn:openpc:participant:${context.data.participantId}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${context.data.privacyDomainId}`,
      'OpenPC-Action-Intent-Digest': context.data.actionIntentDigest,
      'If-Match': etag,
      'Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify(command),
  }).catch(() => undefined);
  if (!ownerResponse?.ok || !hasJsonContentType(ownerResponse.headers.get('content-type'))) {
    return sessionMutationFailure(
      'owner-response',
      ownerResponse ? 'PC-AUTH-0005' : 'PC-INTEGRATION-5001',
      request,
      ownerResponse?.status,
    );
  }
  const operation = identityOperationSchema.safeParse(await ownerResponse.json());
  if (
    !operation.success ||
    operation.data.actionIntentId !== input.actionIntentId ||
    operation.data.intentDigest !== context.data.actionIntentDigest ||
    operation.data.idempotencyKey !== idempotencyKey ||
    operation.data.resourceRef !== command.targetRef
  ) {
    return sessionMutationFailure(
      'owner-operation-schema',
      'PC-INTEGRATION-5001',
      request,
      ownerResponse.status,
    );
  }
  const response = NextResponse.json(operation.data, {
    status: 202,
    headers: {
      ...noStoreHeaders,
      'ETag': ownerResponse.headers.get('etag') ?? etag,
      'OpenPC-API-Version': '1',
      'X-Request-ID': ids.requestId,
      'X-Correlation-ID': ids.correlationId,
    },
  });
  if (input.path === '/api/v1/session/logout') {
    response.cookies.set(sessionCookie, '', {
      httpOnly: true,
      secure: request.nextUrl.protocol === 'https:',
      sameSite: 'strict',
      path: '/',
      maxAge: 0,
    });
  } else {
    const nextToken = identitySessionToken(ownerResponse);
    if (!nextToken) {
      return sessionMutationFailure(
        'replacement-token',
        'PC-INTEGRATION-5001',
        request,
        ownerResponse.status,
      );
    }
    const next = await identityCall<Omit<IdentitySession, 'sessionToken'>>(
      runtime,
      '/internal/v1/local/session/validate',
      { sessionToken: nextToken },
    );
    if (!next || next.role !== local.role) {
      return sessionMutationFailure('replacement-readback', 'PC-INTEGRATION-5001', request);
    }
    response.cookies.set(
      sessionCookie,
      encodeBffSession({ ...next, sessionToken: nextToken }, runtime.cookieKey),
      {
        httpOnly: true,
        secure: request.nextUrl.protocol === 'https:',
        sameSite: 'strict',
        path: '/',
        maxAge: 12 * 60 * 60,
      },
    );
  }
  return response;
}

export function localLogout(request: NextRequest) {
  return localSessionMutation(request, {
    actionIntentId: 'ACT-IDENTITY_DELETE_SESSION-V1',
    path: '/api/v1/session/logout',
    reason: 'User requested local session logout.',
  });
}

export function localRefreshSession(request: NextRequest) {
  return localSessionMutation(request, {
    actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
    path: '/api/v1/session/refresh',
    reason: 'User requested local session rotation.',
  });
}

export async function localBootstrap(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return undefined;
  const session = await authenticated(request, runtime);
  if (!session) return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json(
    {
      csrfToken: csrfToken(session.sessionToken, runtime.cookieKey),
      etag: targetEtag(),
      idempotencyKey,
      locale: 'en-US',
      timeZone: 'UTC',
      density: 'comfortable',
      theme: 'light',
    },
    { headers: noStoreHeaders },
  );
}

export async function localSnapshot(request: NextRequest, requestedDomain: string) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return undefined;
  if (requestedDomain !== domain) return undefined;
  const session = await authenticated(request, runtime);
  if (!session || session.role !== 'operator') return safeProblem('PC-AUTH-0005', request);
  const ids = responseIds(request);
  const queryKeys = [...request.nextUrl.searchParams.keys()];
  const limits = request.nextUrl.searchParams.getAll('limit');
  const limit = limits.length === 0 ? 50 : Number(limits[0]);
  if (
    !uuidV7Pattern.test(request.headers.get('x-request-id') ?? '') ||
    !uuidV7Pattern.test(request.headers.get('x-correlation-id') ?? '') ||
    request.headers.get('openpc-api-version') !== '1' ||
    session.participantId !== localFactAction.participantRef.split(':').at(-1) ||
    request.headers.get('openpc-participant-id') !== localFactAction.participantRef ||
    queryKeys.some((key) => key !== 'limit') ||
    limits.length > 1 ||
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > 200
  ) {
    return safeProblem('PC-DATA-6004', request);
  }
  try {
    const response = await localOwnerFetch(
      `${runtime.factUrl}/internal/v1/fact-source-projection-bridge`,
      {
        cache: 'no-store',
        headers: {
          'Authorization': `Bearer ${runtime.factToken}`,
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': localFactAction.participantRef,
          'OpenPC-Privacy-Domain-ID': localFactAction.privacyDomainRef,
          'X-OpenPC-Action-Intent': 'ACT-FACT_ARTIFACTS_READ_COLLECTION-V1',
          'OpenPC-Action-Intent-Digest':
            'sha256:a671fa20f95424230312b71c2c6e9198f9add32f0c7f874d216f2ad1b7c7c452',
          'X-Request-ID': ids.requestId,
          'X-Correlation-ID': ids.correlationId,
        },
      },
    );
    if (!response.ok || !hasJsonContentType(response.headers.get('content-type'))) {
      return safeProblem('PC-INTEGRATION-5001', request);
    }
    const projectionResult = localOwnerReadSchema.safeParse(await response.json());
    if (!projectionResult.success) return safeProblem('PC-INTEGRATION-5001', request);
    const projection = projectionResult.data;
    if (projection.requestId !== ids.requestId || projection.correlationId !== ids.correlationId) {
      return safeProblem('PC-INTEGRATION-5001', request);
    }
    if (projection.etag !== projectionEtag(projection)) {
      return safeProblem('PC-INTEGRATION-5001', request);
    }
    const route = routes.find((candidate) => candidate.domain === domain);
    if (!route) return safeProblem('PC-INTEGRATION-5001', request);
    const now = rfc3339Micros();
    const sourceObservedAt =
      projection.observedAtMs === null ? now : rfc3339Micros(projection.observedAtMs);
    const freshnessState =
      projection.observedAtMs === null || Math.abs(Date.now() - projection.observedAtMs) <= 60_000
        ? 'CURRENT'
        : 'STALE';
    const contextDigest = framedDigest('openpc:ui-authority-context:v1', [
      route.id,
      route.processDomainId,
      localFactAction.participantRef,
      localFactAction.privacyDomainRef,
      '1',
      '1',
    ]);
    const scopeDigest = framedDigest('openpc:ui-authorized-scope:v1', [
      'PARTICIPANT',
      localFactAction.participantRef,
      localFactAction.privacyDomainRef,
    ]);
    const snapshot: ProcessSnapshot = processSnapshotSchema.parse({
      snapshotId: uuidV7(),
      routeId: route.id,
      processDomainId: route.processDomainId,
      contextDigest,
      authorityGeneration: '1',
      policyGeneration: '1',
      truthState: projection.factCount > 0 ? 'SUCCESS' : 'AUTHORIZED_EMPTY',
      scope: {
        plane: 'PARTICIPANT',
        participantId: localFactAction.participantRef,
        privacyDomainId: localFactAction.privacyDomainRef,
      },
      freshness: { observedAt: sourceObservedAt, state: freshnessState },
      completeness: 'COMPLETE',
      items:
        projection.factCount > 0
          ? [
              {
                resourceRef: projection.resourceRef,
                truthState: 'SUCCESS',
                scopeDigest,
                observedAt: sourceObservedAt,
              },
            ]
          : [],
      authorizedActions: [
        {
          actionIntentId,
          actionIntentDigest,
          operationId: localFactAction.operationId,
          method: 'POST',
          path: actionPath,
          riskClass: localFactAction.riskClass,
          stepUp: localFactAction.stepUp,
          idempotency: 'KEY_UNTIL_TERMINAL',
          etagRequired: true,
        },
      ],
      evidenceRefs: [],
      observedAt: now,
    });
    return NextResponse.json(snapshot, {
      headers: {
        ...noStoreHeaders,
        'ETag': projection.etag,
        'OpenPC-API-Version': '1',
        'RateLimit-Limit': '100',
        'RateLimit-Remaining': '99',
        'RateLimit-Reset': '60',
        'X-Request-ID': ids.requestId,
        'X-Correlation-ID': ids.correlationId,
      },
    });
  } catch {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
}

export async function localAction(request: NextRequest, requestedDomain: string, intent: string) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime || requestedDomain !== domain) return undefined;
  const session = await authenticated(request, runtime);
  if (!session || session.role !== 'operator') return safeProblem('PC-AUTH-0005', request);
  const stepUpAt = session.stepUpVerifiedAt ? Date.parse(session.stepUpVerifiedAt) : Number.NaN;
  if (
    !Number.isFinite(stepUpAt) ||
    stepUpAt > Date.now() ||
    Date.now() - stepUpAt > stepUpMaximumAgeMs
  ) {
    return safeProblem('PC-AUTH-0003', request);
  }
  if (!sameOrigin(request)) return safeProblem('PC-AUTH-0002', request);
  const rawBody = parsePublicCommand(await request.text());
  const candidate =
    rawBody && typeof rawBody === 'object' && !Array.isArray(rawBody)
      ? (rawBody as Record<string, unknown>)
      : undefined;
  if (
    intent !== 'qualify-admit' ||
    request.headers.get('openpc-action-intent-digest') !== actionIntentDigest ||
    (candidate &&
      (candidate.actionIntentId !== actionIntentId ||
        candidate.actionIntentDigest !== actionIntentDigest))
  ) {
    return safeProblem('PC-AUTH-0006', request);
  }
  if (!validCsrf(request.headers.get('x-csrf-token'), session.sessionToken, runtime.cookieKey)) {
    return safeProblem('PC-AUTH-0002', request);
  }
  const body = localFactCommandSchema.safeParse(rawBody);
  const requestId = request.headers.get('x-request-id') ?? '';
  const correlationId = request.headers.get('x-correlation-id') ?? '';
  if (
    request.method !== 'POST' ||
    request.nextUrl.pathname !== actionPath ||
    !hasJsonContentType(request.headers.get('content-type')) ||
    request.headers.get('idempotency-key') !== idempotencyKey ||
    !/^"sha256:[0-9a-f]{64}"$/u.test(request.headers.get('if-match') ?? '') ||
    request.headers.get('openpc-api-version') !== '1' ||
    session.participantId !== localFactAction.participantRef.split(':').at(-1) ||
    request.headers.get('openpc-participant-id') !==
      `urn:openpc:participant:${session.participantId}` ||
    !uuidV7Pattern.test(requestId) ||
    !uuidV7Pattern.test(correlationId) ||
    !body.success
  ) {
    return safeProblem('PC-DATA-6004', request);
  }
  try {
    const response = await localOwnerFetch(
      `${runtime.factUrl}/internal/v1/fact-source-projection-bridge/actions/qualify-admit`,
      {
        method: 'POST',
        cache: 'no-store',
        headers: {
          'Authorization': `Bearer ${runtime.factToken}`,
          'X-OpenPC-Action-Intent': localFactAction.downstreamActionIntentId,
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': localFactAction.participantRef,
          'OpenPC-Privacy-Domain-ID': localFactAction.privacyDomainRef,
          'OpenPC-Action-Intent-Digest': localFactAction.downstreamActionIntentDigest,
          'Idempotency-Key': idempotencyKey,
          'If-Match': request.headers.get('if-match')!,
          'X-Request-ID': requestId,
          'X-Correlation-ID': correlationId,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          schemaVersion: '1.0',
          uiActionIntentId: body.data.actionIntentId,
          uiActionIntentDigest: body.data.actionIntentDigest,
          downstreamActionIntentId: localFactAction.downstreamActionIntentId,
          downstreamActionIntentDigest: localFactAction.downstreamActionIntentDigest,
          expectedRevision: body.data.expectedRevision,
          replacementDigest: body.data.inputDigest,
          replacementDocument: localReplacementDocument,
          reason: body.data.reason,
          targetRef: body.data.targetRef,
          resourceRef: localFactAction.resourceRef,
          participantId: localFactAction.participantRef,
          privacyDomainId: localFactAction.privacyDomainRef,
          idempotencyKey,
          etag: request.headers.get('if-match')!,
          requestId,
          correlationId,
        }),
      },
    );
    if (response.status === 412) return safeProblem('PC-DATA-6007', request);
    if (response.status === 409) return safeProblem('PC-RUNTIME-3007', request);
    if (!response.ok || !hasJsonContentType(response.headers.get('content-type'))) {
      return safeProblem('PC-INTEGRATION-5001', request);
    }
    const ownerResult = localOwnerResultSchema.safeParse(await response.json());
    if (
      !ownerResult.success ||
      ownerResult.data.requestId !== requestId ||
      ownerResult.data.correlationId !== correlationId ||
      ownerResult.data.etag !== targetEtag()
    ) {
      return safeProblem('PC-INTEGRATION-5001', request);
    }
    const operation = localOperationSchema.parse(ownerResult.data.operation);
    return NextResponse.json(operation, {
      status: 202,
      headers: {
        ...noStoreHeaders,
        'ETag': ownerResult.data.etag,
        'OpenPC-API-Version': '1',
        'RateLimit-Limit': '100',
        'RateLimit-Remaining': '99',
        'RateLimit-Reset': '60',
        'X-Request-ID': requestId,
        'X-Correlation-ID': correlationId,
      },
    });
  } catch {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
}
