import { afterEach, expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import { persistOidcAuthorization } from './oidc-authorization.js';
afterEach(() => vi.unstubAllEnvs());
it('pins new OIDC expiry and preserves the earlier transaction when QA is enabled', async () => {
  vi.stubEnv('OPENPC_LOCAL_QA_DURATION_PROFILE', undefined);
  const now = new Date('2026-10-05T16:00:00Z');
  const configuration = {
    issuer: 'http://issuer.test',
    clientId: 'local-qa',
    redirectUri: 'http://localhost/callback',
  };
  const query = vi.fn(async () => ({ rowCount: 1, rows: [] }));
  const client = { query } as unknown as PoolClient;
  const legacy = await persistOidcAuthorization(client, configuration, now, 'SESSION');
  const oldExpiry = (query.mock.calls[0] as unknown as [string, unknown[]])[1].find(
    (v) => v instanceof Date,
  ) as Date;
  expect(oldExpiry.getTime()).toBe(now.getTime() + 300_000);
  expect(legacy.authorization).not.toHaveProperty('durationProfile');
  vi.stubEnv('OPENPC_LOCAL_RUNTIME', '1');
  vi.stubEnv('OPENPC_LOCAL_RUNTIME_QA_FIXTURE', '1');
  vi.stubEnv('OPENPC_LOCAL_QA_DURATION_PROFILE', 'LOCAL_QA_10X');
  const fresh = await persistOidcAuthorization(client, configuration, now, 'SESSION');
  expect(fresh.authorization).toMatchObject({
    durationProfile: 'LOCAL_QA_10X',
    expiresAt: new Date(now.getTime() + 3_000_000).toISOString(),
  });
  expect(oldExpiry.getTime()).toBe(now.getTime() + 300_000);
  expect(fresh.authorization.transactionId).not.toBe(legacy.authorization.transactionId);
});
