import type { Pool, PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import { readPublicActivationPreview } from './public-activation-store.js';
import type { PublicApprovalScope } from './public-approval-store.js';

const query = vi.fn();
vi.mock('./public-approval-store.js', async (original) => ({
  ...(await original<typeof import('./public-approval-store.js')>()),
  assertActionIntent: vi.fn(),
  inScope: (
    _pool: Pool,
    _scope: PublicApprovalScope,
    body: (client: PoolClient) => Promise<unknown>,
  ) => body({ query } as unknown as PoolClient),
}));
it.each([false, null])(
  'conceals incomplete target read authority (%s) before reading readiness or counts',
  async (allowed) => {
    query.mockReset().mockResolvedValue({ rowCount: 1, rows: [{ allowed }] });
    const scope = {
      participantId: 'participant',
      privacyDomainId: 'privacy',
      principalId: 'maker',
      authority: { sessionId: 'session' },
    } as unknown as PublicApprovalScope;
    await expect(readPublicActivationPreview({} as Pool, scope, 'release')).rejects.toMatchObject({
      code: 'PC-POLICY-2001',
    });
    expect(query).toHaveBeenCalledTimes(1);
    expect(query.mock.calls[0]?.[1]).toEqual(['participant', 'privacy', true, 'maker', 'session']);
  },
);
