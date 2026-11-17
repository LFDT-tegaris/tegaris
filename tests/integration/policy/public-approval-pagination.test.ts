import { describe, expect, it } from 'vitest';

import {
  publicApprovalListRequest,
  publicApprovalNextCursor,
} from '../../../services/module-registry/src/public-approval-pagination.js';

const participantId = '018f0000-0000-7000-8000-000000000101';

describe('public approval pagination', () => {
  it('binds the continuation to session, participant, filter and sort', () => {
    const first = publicApprovalListRequest(
      { filter: 'state:eq:REQUESTED', limit: 1, sort: '-updatedAt' },
      'session-one',
      participantId,
    );
    const cursor = publicApprovalNextCursor(
      first,
      {
        updatedAt: '2026-01-01T00:00:00.000000Z',
        id: '018f0000-0000-7000-8000-000000000201',
      },
      'session-one',
      participantId,
    );
    expect(cursor).not.toBeNull();
    expect(
      publicApprovalListRequest(
        { cursor: cursor!, filter: 'state:eq:REQUESTED', limit: 1, sort: '-updatedAt' },
        'session-one',
        participantId,
      ),
    ).toMatchObject({
      after: {
        updatedAt: '2026-01-01T00:00:00.000000Z',
        id: '018f0000-0000-7000-8000-000000000201',
      },
      snapshotAt: first.snapshotAt,
      snapshotRevision: first.snapshotRevision,
    });
    expect(() =>
      publicApprovalListRequest(
        { cursor: cursor!, filter: 'state:eq:REQUESTED', limit: 1, sort: '-updatedAt' },
        'session-two',
        participantId,
      ),
    ).toThrow('PC-POLICY-2000');
    expect(() =>
      publicApprovalListRequest(
        { cursor: cursor!, filter: 'state:eq:APPROVED', limit: 1, sort: '-updatedAt' },
        'session-one',
        participantId,
      ),
    ).toThrow('PC-POLICY-2000');
  });

  it('rejects unknown filter and sort fields', () => {
    expect(() =>
      publicApprovalListRequest({ filter: 'secret:eq:value', limit: 50 }, 'session', participantId),
    ).toThrow('PC-POLICY-2000');
    expect(() =>
      publicApprovalListRequest({ limit: 50, sort: 'createdAt' }, 'session', participantId),
    ).toThrow('PC-POLICY-2000');
  });
});
