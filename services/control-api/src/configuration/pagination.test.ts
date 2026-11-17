import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { scopedReadSchema, collectionResponseSchema } from './resource-contracts.js';

import { listRequest, nextCursor, selectPage } from './pagination.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const resourceId = '018f0000-0000-7000-8000-000000000301';
const token = 'opaque-same-origin-session';

describe('collection pagination contract', () => {
  it('round-trips a cursor with its participant, filter, sort, and snapshot binding', () => {
    const first = listRequest(
      { limit: 25, filter: 'state:eq:ACTIVE', sort: '-updatedAt' },
      token,
      participantId,
      privacyDomainId,
      'provider-profiles',
      new Set(['state']),
    );
    const cursor = nextCursor(
      first,
      { updatedAt: '2026-09-10T01:02:03.456Z', id: resourceId },
      token,
      participantId,
      privacyDomainId,
      'provider-profiles',
    );

    expect(cursor).not.toBeNull();
    expect(
      collectionResponseSchema(z.never()).parse({
        items: [],
        nextCursor: cursor,
        total: '0',
        completeness: 'COMPLETE',
        authorizedEmpty: true,
        snapshotRevision: first.snapshotRevision,
      }).nextCursor,
    ).toBe(cursor);
    const parsed = scopedReadSchema.parse({
      cursor,
      limit: '25',
      filter: 'state:eq:ACTIVE',
      sort: '-updatedAt',
    });
    const continuation = listRequest(
      parsed,
      token,
      participantId,
      privacyDomainId,
      'provider-profiles',
      new Set(['state']),
    );
    expect(continuation).toMatchObject({
      snapshotAt: first.snapshotAt,
      snapshotRevision: first.snapshotRevision,
      after: { updatedAt: '2026-09-10T01:02:03.456Z', id: resourceId },
    });
  });

  it('rejects cursor tampering and cross-participant replay', () => {
    const first = listRequest(
      { limit: 25 },
      token,
      participantId,
      privacyDomainId,
      'runtime-targets',
      new Set(['state']),
    );
    const cursor = nextCursor(
      first,
      { updatedAt: '2026-09-10T01:02:03.456Z', id: resourceId },
      token,
      participantId,
      privacyDomainId,
      'runtime-targets',
    )!;

    expect(() =>
      listRequest(
        { cursor: `${cursor.slice(0, -1)}x`, limit: 25 },
        token,
        participantId,
        privacyDomainId,
        'runtime-targets',
        new Set(['state']),
      ),
    ).toThrow('PC-DATA-6004');
    expect(() =>
      listRequest(
        { cursor, limit: 25 },
        token,
        '018f0000-0000-7000-8000-000000000999',
        privacyDomainId,
        'runtime-targets',
        new Set(['state']),
      ),
    ).toThrow('PC-DATA-6004');
  });

  it('rejects a non-canonical Base64URL signature alias', () => {
    const first = listRequest(
      { limit: 25 },
      token,
      participantId,
      privacyDomainId,
      'runtime-targets',
      new Set(['state']),
    );
    const cursor = nextCursor(
      first,
      { updatedAt: '2026-09-10T01:02:03.456Z', id: resourceId },
      token,
      participantId,
      privacyDomainId,
      'runtime-targets',
    )!;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = cursor.at(-1)!;
    const alias = `${cursor.slice(0, -1)}${alphabet[alphabet.indexOf(last) + 1]}`;

    expect(Buffer.from(alias.split('.').at(-1)!, 'base64url')).toEqual(
      Buffer.from(cursor.split('.').at(-1)!, 'base64url'),
    );
    expect(() =>
      listRequest(
        { cursor: alias, limit: 25 },
        token,
        participantId,
        privacyDomainId,
        'runtime-targets',
        new Set(['state']),
      ),
    ).toThrow('PC-DATA-6004');
  });

  it('rejects a valid cursor after switching privacy domains within one participant', () => {
    const first = listRequest(
      { limit: 25 },
      token,
      participantId,
      privacyDomainId,
      'provider-profiles',
      new Set(),
    );
    const cursor = nextCursor(
      first,
      { updatedAt: '2026-09-10T01:02:03.456Z', id: resourceId },
      token,
      participantId,
      privacyDomainId,
      'provider-profiles',
    )!;
    expect(() =>
      listRequest(
        { cursor, limit: 25 },
        token,
        participantId,
        '018f0000-0000-7000-8000-000000000202',
        'provider-profiles',
        new Set(),
      ),
    ).toThrow('PC-DATA-6004');
    expect(() =>
      listRequest(
        { cursor: cursor.replace('pc2.', 'pc1.'), limit: 25 },
        token,
        participantId,
        privacyDomainId,
        'provider-profiles',
        new Set(),
      ),
    ).toThrow('PC-DATA-6004');
  });

  it('rejects unregistered filters and caller-controlled ordering', () => {
    expect(() =>
      listRequest(
        { limit: 25, filter: 'endpointSecretRef:eq:anything' },
        token,
        participantId,
        privacyDomainId,
        'provider-profiles',
        new Set(['state']),
      ),
    ).toThrow('PC-DATA-6004');
    expect(() =>
      listRequest(
        { limit: 25, sort: 'state' },
        token,
        participantId,
        privacyDomainId,
        'provider-profiles',
        new Set(['state']),
      ),
    ).toThrow('PC-DATA-6004');
  });
});

describe('repository-owned derived relation visibility', () => {
  const specification = {
    table: '(select * from control.policy) policy_sets',
    visibilityAlias: 'policy_sets',
    idColumn: 'policy_id',
    projection: 'policy_id',
    filterColumns: {},
    rowId: (row: { policy_id: string }) => row.policy_id,
    rowUpdatedAt: () => '2026-10-02T00:00:00.000Z',
    map: (row: { policy_id: string }) => row,
  };
  const request = {
    ...listRequest({ limit: 50 }, token, participantId, privacyDomainId, 'policy-sets', new Set()),
    visibility: {
      participantId,
      privacyDomainId,
      principalId: resourceId,
      sessionId: resourceId,
      actionIntentId: 'ACT-POLICY_SETS_READ_RESOURCE-V1',
    },
  };
  it('keeps live authority and tenant predicates on the derived row alias', async () => {
    const calls: { sql: string; values: unknown[] }[] = [];
    const client = {
      query: async (sql: string, values: unknown[]) => {
        calls.push({ sql, values: [...values] });
        return calls.length === 1
          ? { rowCount: 1, rows: [] }
          : calls.length === 2
            ? { rowCount: 1, rows: [{ total: '0' }] }
            : { rowCount: 0, rows: [] };
      },
    } as unknown as import('pg').PoolClient;
    const result = await selectPage(client, request, specification);
    expect(result).toMatchObject({ items: [], total: '0' });
    for (const call of calls.slice(1)) {
      expect(call.sql).toContain('policy_sets.participant_id=$2');
      expect(call.sql).toContain('policy_sets.privacy_domain_id=$3');
      expect(call.sql).toContain('policy_sets.policy_id::text');
      expect(call.sql).toContain('live_read_authority)=1');
      expect(call.values.slice(1, 6)).toEqual([
        participantId,
        privacyDomainId,
        request.visibility.actionIntentId,
        resourceId,
        resourceId,
      ]);
    }
  });
  it('rejects a derived relation without an explicit trusted alias', async () => {
    const { visibilityAlias, ...unbound } = specification;
    void visibilityAlias;
    await expect(selectPage({} as import('pg').PoolClient, request, unbound)).rejects.toThrow(
      'PC-DATA-6004',
    );
  });
  it('rejects SQL syntax in a visibility alias before querying', async () => {
    await expect(
      selectPage({} as import('pg').PoolClient, request, {
        ...specification,
        visibilityAlias: 'policy_sets; select 1',
      }),
    ).rejects.toThrow('PC-DATA-6004');
  });
});

it('keeps literal prefix metacharacters bound as data and escapes each SQL wildcard', async () => {
  const calls: { sql: string; values: unknown[] }[] = [];
  const client = {
    query: async (sql: string, values: unknown[]) => {
      calls.push({ sql, values: [...values] });
      return { rows: calls.length === 1 ? [{ total: '0' }] : [] };
    },
  } as unknown as import('pg').PoolClient;
  const request = listRequest(
    { limit: 25, filter: 'displayName:prefix:A_%\\' },
    token,
    participantId,
    privacyDomainId,
    'logical-contract-asset',
    new Set(['displayName']),
  );
  await selectPage(client, request, {
    table: 'control.logical_contract_asset',
    idColumn: 'logical_contract_id',
    projection: 'logical_contract_id',
    filterColumns: { displayName: 'display_name' },
    rowId: (row: { logical_contract_id: string }) => row.logical_contract_id,
    rowUpdatedAt: () => '2026-10-10T00:00:00.123456Z',
    map: (row) => row,
  });
  for (const call of calls) {
    expect(call.values[1]).toBe('A_%\\');
    expect(call.sql).not.toContain('A_%');
    expect(call.sql).toContain("replace(replace(replace($2,'\\','\\\\'),'%','\\%'),'_','\\_')");
  }
});
