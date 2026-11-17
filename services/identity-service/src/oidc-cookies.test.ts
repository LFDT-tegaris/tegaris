import { afterEach, expect, it, vi } from 'vitest';
import { oidcCustodyCookie } from './oidc-cookies.js';
afterEach(() => vi.restoreAllMocks());
it('uses the pinned expiry for a new QA cookie and retains the legacy five-minute default', () => {
  const now = Date.parse('2026-10-05T16:00:00Z');
  vi.spyOn(Date, 'now').mockReturnValue(now);
  const custody = { browserSession: 'browser-session', codeVerifier: 'code-verifier' };
  expect(oidcCustodyCookie('transaction', custody)).toContain('Max-Age=300');
  expect(
    oidcCustodyCookie('transaction', custody, 'SESSION', new Date(now + 3_000_000).toISOString()),
  ).toContain('Max-Age=3000');
  for (const expiry of [now, now + 3_001_000, NaN]) {
    const value = Number.isFinite(expiry) ? new Date(expiry).toISOString() : 'invalid';
    expect(() => oidcCustodyCookie('transaction', custody, 'SESSION', value)).toThrow();
  }
});
