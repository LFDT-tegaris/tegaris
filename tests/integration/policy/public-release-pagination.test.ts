import { describe, expect, it } from 'vitest';

import {
  publicReleaseListRequest,
  publicReleaseNextCursor,
} from '../../../services/module-registry/src/public-release-pagination.js';

describe('public release pagination', () => {
  const token = 'release-pagination-session-token';
  const participantId = '018f0000-0000-7000-8000-000000000901';

  it('round-trips an authenticated snapshot cursor and filter', () => {
    const first = publicReleaseListRequest(
      { filter: 'state:eq:PUBLISHED', limit: 1, sort: '-updatedAt' },
      token,
      participantId,
    );
    const cursor = publicReleaseNextCursor(
      first,
      {
        updatedAt: '2026-09-11T00:00:00.000000Z',
        id: '018f0000-0000-7000-8000-000000000902',
      },
      'state:eq:PUBLISHED',
      token,
      participantId,
    );
    expect(cursor).not.toBeNull();
    const second = publicReleaseListRequest(
      { cursor: cursor as string, filter: 'state:eq:PUBLISHED', limit: 1, sort: '-updatedAt' },
      token,
      participantId,
    );
    expect(second).toMatchObject({
      state: 'PUBLISHED',
      snapshotAt: first.snapshotAt,
      snapshotRevision: first.snapshotRevision,
      after: { id: '018f0000-0000-7000-8000-000000000902' },
    });
  });

  it('rejects cursor tampering, tenant substitution and unsupported filters', () => {
    const first = publicReleaseListRequest({ limit: 1 }, token, participantId);
    const cursor = publicReleaseNextCursor(
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
      publicReleaseListRequest({ cursor: `${cursor}x`, limit: 1 }, token, participantId),
    ).toThrow();
    expect(() =>
      publicReleaseListRequest({ cursor, limit: 1 }, token, '018f0000-0000-7000-8000-000000000999'),
    ).toThrow();
    expect(() =>
      publicReleaseListRequest(
        { filter: 'manifestDigest:eq:nope', limit: 1 },
        token,
        participantId,
      ),
    ).toThrow();
  });
});
