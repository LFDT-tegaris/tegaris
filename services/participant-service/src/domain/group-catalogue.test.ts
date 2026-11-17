import { expect, it, vi } from 'vitest';

import { authorityReadPaths } from '../../../identity-service/src/db/authority-read-paths.js';
import { groupCatalogueCandidates } from './group-catalogue.js';

vi.mock('../../../identity-service/src/db/authority-read-paths.js', () => ({
  authorityReadPaths: vi.fn(),
}));

const ids = [
  '018f0000-0000-7000-8000-000000000801',
  '018f0000-0000-7000-8000-000000000802',
] as const;

it('binds group discovery to the Participant filters and returns only resources with one live read path', async () => {
  const query = vi.fn().mockResolvedValue({
    rows: ids.map((id) => ({ id, observed_at: new Date('2026-09-29T12:00:00.000Z') })),
  });
  vi.mocked(authorityReadPaths).mockResolvedValue({
    rows: [{ resource_id: ids[1], assignment_id: 'assignment', delegation_path: [] }],
  } as never);
  const result = await groupCatalogueCandidates(
    { query } as never,
    '018f0000-0000-7000-8000-000000000101',
    '018f0000-0000-7000-8000-000000000111',
    '018f0000-0000-7000-8000-000000000201',
    { search: 'settlement', state: 'ACTIVE', after: ids[0] },
  );
  expect(query).toHaveBeenCalledWith(expect.stringContaining('where participant_id=$1'), [
    '018f0000-0000-7000-8000-000000000101',
    'ACTIVE',
    'settlement',
    ids[0],
  ]);
  expect(query.mock.calls[0]?.[0]).toContain('state::text=$2');
  expect(authorityReadPaths).toHaveBeenCalledWith(
    expect.anything(),
    '018f0000-0000-7000-8000-000000000101',
    '018f0000-0000-7000-8000-000000000111',
    '018f0000-0000-7000-8000-000000000201',
    'ACT-PARTICIPANTS_READ_RESOURCE-V1',
    ids,
    'LOW',
  );
  expect(result).toEqual({ ids: [ids[1]], observedAt: '2026-09-29T12:00:00.000Z' });
});

it('fails closed when one resource has multiple authority paths', async () => {
  const query = vi.fn().mockResolvedValue({
    rows: [{ id: ids[0], observed_at: new Date('2026-09-29T12:00:00.000Z') }],
  });
  vi.mocked(authorityReadPaths).mockResolvedValue({
    rows: [
      { resource_id: ids[0], assignment_id: 'one', delegation_path: [] },
      { resource_id: ids[0], assignment_id: 'two', delegation_path: [] },
    ],
  } as never);
  await expect(
    groupCatalogueCandidates(
      { query } as never,
      '018f0000-0000-7000-8000-000000000101',
      '018f0000-0000-7000-8000-000000000111',
      '018f0000-0000-7000-8000-000000000201',
      { search: '', state: 'ALL' },
    ),
  ).rejects.toMatchObject({ code: 'PC-IDENTITY-1002' });
});
