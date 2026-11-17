import { expect, it, vi } from 'vitest';
import { buildIdentityService } from './app.js';
import { localWebAuthnAllowedOrigin } from './local-runtime.js';
import type { IdentityKernel } from './domain/identity-kernel.js';

it('authenticates the BFF origin separately from recipient custody and rejects confused credentials', async () => {
  const bootstrapAcceptance = vi.fn(async () => ({ state: 'CLAIM_PENDING' }));
  const app = buildIdentityService(
    { bootstrapAcceptance } as unknown as IdentityKernel,
    undefined,
    undefined,
    undefined,
    localWebAuthnAllowedOrigin(
      'internal-test-secret',
      'http://localhost:8080/api/v1/ui/oidc-session/callback',
    ),
  );
  const cookie = '__Host-openpc_first_admin_custody=recipient-custody';
  const base = { origin: 'http://identity:3001', host: 'identity:3001' };
  const proxy = {
    ...base,
    'authorization': 'Bearer internal-test-secret',
    'x-openpc-browser-origin': 'http://localhost:8080',
    cookie,
  };
  const send = (headers: Record<string, string>) =>
    app.inject({
      method: 'POST',
      url: '/v1/identity/invitations/018f0000-0000-7000-8000-000000000701/first-administrator',
      headers,
      payload: {
        participantId: '018f0000-0000-7000-8000-000000000101',
        privacyDomainId: '018f0000-0000-7000-8000-000000000201',
        request: { command: 'READ' },
      },
    });
  try {
    expect((await send(proxy)).statusCode).toBe(200);
    expect(bootstrapAcceptance).toHaveBeenLastCalledWith(
      expect.objectContaining({ sessionToken: 'recipient-custody' }),
      { command: 'READ' },
      'http://localhost:8080',
      expect.anything(),
    );
    for (const headers of [
      { ...proxy, authorization: 'Bearer recipient-custody' },
      { ...proxy, 'x-openpc-browser-origin': 'http://foreign.example' },
      { ...proxy, cookie: '__Host-openpc_session=recipient-custody' },
      { ...proxy, cookie: `${cookie}; ${cookie}` },
      { ...proxy, origin: 'http://foreign.example' },
      { ...base, cookie },
    ])
      expect((await send(headers)).statusCode).toBeGreaterThanOrEqual(400);
    expect(bootstrapAcceptance).toHaveBeenCalledTimes(1);
    expect(
      (
        await send({
          origin: 'http://localhost:8080',
          host: 'localhost:8080',
          authorization: 'Bearer direct-custody',
        })
      ).statusCode,
    ).toBe(200);
    expect(bootstrapAcceptance).toHaveBeenLastCalledWith(
      expect.objectContaining({ sessionToken: 'direct-custody' }),
      { command: 'READ' },
      'http://localhost:8080',
      expect.anything(),
    );
  } finally {
    await app.close();
  }
});
