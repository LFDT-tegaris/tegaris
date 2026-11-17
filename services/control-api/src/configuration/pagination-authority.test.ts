import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { selectPage, type ListRequest } from './pagination.js';

const visibility = {
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  principalId: '018f0000-0000-7000-8000-000000000111',
  sessionId: '018f0000-0000-7000-8000-000000000701',
  actionIntentId: 'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',
};
const request: ListRequest = {
  limit: 2,
  sort: '-updatedAt',
  snapshotAt: '2026-10-01T15:00:00.000Z',
  snapshotRevision: '1',
  filterText: 'state:eq:QUALIFIED',
  filter: { field: 'state', operator: 'eq', value: 'QUALIFIED' },
  visibility,
  after: { updatedAt: '2026-10-01T14:00:00.000Z', id: '018f0000-0000-7000-8000-000000000301' },
};
const specification = {
  table: 'control.provider_profile',
  idColumn: 'provider_profile_id',
  projection: 'provider_profile_id as id,updated_at as updated',
  filterColumns: { state: 'state' },
  rowId: (row: { id: string; updated: string }) => row.id,
  rowUpdatedAt: (row: { id: string; updated: string }) => row.updated,
  map: (row: { id: string; updated: string }) => row,
};

describe('finite collection authority in shared paging', () => {
  it('applies the same complete current READ decision before count and pagination', async () => {
    const query = vi.fn(async (sql: string, _args: readonly unknown[]) => {
      if (sql.includes('from control.action_intent')) return { rowCount: 1, rows: [{}] };
      if (sql.startsWith('select count(*)::text')) return { rowCount: 1, rows: [{ total: '0' }] };
      return { rowCount: 0, rows: [] };
    });
    const page = await selectPage({ query } as unknown as PoolClient, request, specification);
    const selections = query.mock.calls.filter(([sql]) =>
      sql.includes('from control.provider_profile'),
    );
    expect(selections).toHaveLength(2);
    for (const [sql, args] of selections) {
      expect(sql).toContain('provider_profile.participant_id=$2');
      expect(sql).toContain('provider_profile.privacy_domain_id=$3');
      expect(sql).toContain('provider_profile.provider_profile_id::text');
      expect(sql).toContain('openpc.assignment_role_permits');
      expect(sql).toContain('platform_authority_epoch');
      expect(sql).toContain(')=1');
      expect(sql).toContain('state=$7');
      expect(args.slice(1, 6)).toEqual([
        visibility.participantId,
        visibility.privacyDomainId,
        visibility.actionIntentId,
        visibility.principalId,
        visibility.sessionId,
      ]);
    }
    expect(selections[1]![0]).toContain('($8::timestamptz,$9::uuid)');
    expect(selections[1]![0]).toContain('limit $10');
    expect(page).toMatchObject({ items: [], total: '0' });
    expect(page).not.toHaveProperty('visibility');
  });
  it('rejects unknown read actions before reporting an authorized empty collection', async () => {
    const query = vi.fn(async () => ({ rowCount: 0, rows: [] }));
    await expect(
      selectPage({ query } as unknown as PoolClient, request, specification),
    ).rejects.toThrow('PC-AUTH-0005');
    expect(query).toHaveBeenCalledOnce();
  });
  it.each([
    { table: 'control.provider_profile; drop table control.principal' },
    { idColumn: 'provider_profile_id) or true --' },
  ])('rejects unsafe query metadata before database selection', async (change) => {
    const query = vi.fn();
    await expect(
      selectPage({ query } as unknown as PoolClient, request, { ...specification, ...change }),
    ).rejects.toThrow('PC-DATA-6004');
    expect(query).not.toHaveBeenCalled();
  });
});
