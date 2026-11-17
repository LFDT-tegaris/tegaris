import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

import type { NextRequest } from 'next/server';

import type { LocalUiFixture } from '@openpc/ui-shell';

const cookieName = 'openpc_ui_fixture_session';
const maxLifetimeMilliseconds = 10 * 60 * 1000;

interface SessionPayload {
  readonly persona: string;
  readonly state: string;
  readonly intent: string;
  readonly contextEpoch: string;
  readonly expiresAt: number;
  readonly locale?: string;
  readonly timeZone?: string;
  readonly density?: string;
  readonly theme?: string;
}

function signingKey(): Buffer | undefined {
  const value = process.env.OPENPC_UI_FIXTURE_SIGNING_KEY;
  return value ? Buffer.from(value, 'base64url') : undefined;
}

function signature(payload: string, key: Buffer): Buffer {
  return createHmac('sha256', key).update(payload).digest();
}

function parsePayload(encoded: string): SessionPayload | undefined {
  try {
    const value = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as unknown;
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
    const input = value as Record<string, unknown>;
    const known = new Set([
      'persona',
      'state',
      'intent',
      'contextEpoch',
      'expiresAt',
      'locale',
      'timeZone',
      'density',
      'theme',
    ]);
    if (Object.keys(input).some((key) => !known.has(key))) return undefined;
    if (
      typeof input.persona !== 'string' ||
      typeof input.state !== 'string' ||
      typeof input.intent !== 'string' ||
      typeof input.contextEpoch !== 'string' ||
      typeof input.expiresAt !== 'number' ||
      !Number.isSafeInteger(input.expiresAt)
    ) {
      return undefined;
    }
    for (const key of ['locale', 'timeZone', 'density', 'theme'] as const) {
      if (input[key] !== undefined && typeof input[key] !== 'string') return undefined;
    }
    return input as unknown as SessionPayload;
  } catch {
    return undefined;
  }
}

/** Browser headers and unsigned cookies deliberately have no fixture authority. */
export function fixtureFor(request: NextRequest): LocalUiFixture {
  if (process.env.OPENPC_UI_TEST_OVERLAY !== '1') return { enabled: false };
  const key = signingKey();
  const value = request.cookies.get(cookieName)?.value;
  if (!key || !value) return { enabled: false };
  const [encoded, encodedSignature, extra] = value.split('.');
  if (!encoded || !encodedSignature || extra !== undefined) return { enabled: false };
  const received = Buffer.from(encodedSignature, 'base64url');
  const expected = signature(encoded, key);
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
    return { enabled: false };
  }
  const payload = parsePayload(encoded);
  if (
    !payload ||
    payload.expiresAt < Date.now() ||
    payload.expiresAt > Date.now() + maxLifetimeMilliseconds
  ) {
    return { enabled: false };
  }
  return {
    enabled: true,
    persona: payload.persona,
    state: payload.state,
    intent: payload.intent,
    contextEpoch: payload.contextEpoch,
    locale: payload.locale,
    timeZone: payload.timeZone,
    density: payload.density,
    theme: payload.theme,
  };
}

export function bootstrapFor(fixture: LocalUiFixture) {
  if (!fixture.enabled) return undefined;
  return {
    csrfToken: 'local-fixture-csrf',
    etag: '"local-fixture-etag"',
    idempotencyKey: randomUUID(),
    locale: fixture.locale ?? 'en-US',
    timeZone: fixture.timeZone ?? 'UTC',
    density: fixture.density ?? 'comfortable',
    theme: fixture.theme ?? 'light',
  };
}

export const noStoreHeaders = { 'Cache-Control': 'no-store' } as const;
