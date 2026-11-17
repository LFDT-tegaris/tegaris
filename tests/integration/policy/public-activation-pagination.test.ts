import { describe, expect, it } from 'vitest';

import {
  publicActivationListRequest,
  publicActivationNextCursor,
} from '../../../services/module-registry/src/public-activation-pagination.js';

describe('public activation occurrence pagination', () => {
  const token = 'activation-pagination-session-token';
  const participantId = '018f0000-0000-7000-8000-000000000901';

  it('round-trips an authenticated snapshot cursor and state filter', () => {
    const first = publicActivationListRequest(
      { filter: 'state:eq:ACTIVE_MATCHED', limit: 1, sort: '-updatedAt' },
      token,
      participantId,
    );
    const cursor = publicActivationNextCursor(
      first,
      {
        updatedAt: '2026-09-11T00:00:00.000000Z',
        id: '018f0000-0000-7000-8000-000000000902',
      },
      'state:eq:ACTIVE_MATCHED',
      token,
      participantId,
    );
    expect(cursor).not.toBeNull();
    const second = publicActivationListRequest(
      {
        cursor: cursor as string,
        filter: 'state:eq:ACTIVE_MATCHED',
        limit: 1,
        sort: '-updatedAt',
      },
      token,
      participantId,
    );
    expect(second).toMatchObject({
      state: 'ACTIVE_MATCHED',
      snapshotAt: first.snapshotAt,
      snapshotRevision: first.snapshotRevision,
      after: { id: '018f0000-0000-7000-8000-000000000902' },
    });
  });

  it('rejects cursor tampering, tenant substitution and unsupported filters', () => {
    const first = publicActivationListRequest({ limit: 1 }, token, participantId);
    const cursor = publicActivationNextCursor(
      first,
      {
        updatedAt: '2026-09-11T00:00:00.000000Z',
        id: '018f0000-0000-7000-8000-000000000902',
      },
      undefined,
      token,
      participantId,
    ) as string;
    expect(() =>
      publicActivationListRequest({ cursor: `${cursor}x`, limit: 1 }, token, participantId),
    ).toThrow();
    expect(() =>
      publicActivationListRequest(
        { cursor, limit: 1 },
        token,
        '018f0000-0000-7000-8000-000000000999',
      ),
    ).toThrow();
    expect(() =>
      publicActivationListRequest(
        { filter: 'matchedTargetCount:eq:1', limit: 1 },
        token,
        participantId,
      ),
    ).toThrow();
  });
});
