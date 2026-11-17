import type { Pool } from 'pg';
import { policyAuthoritySelectionSql } from '../../../identity-service/src/db/policy-authority-selection.js';
import { describe, expect, it, vi } from 'vitest';
import type { ReadContext } from '../../../control-api/src/configuration/persistence/scoped-read.js';
import { PolicyVersionReadRepository } from './policy-version-read-store.js';

const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const authorization = {
  participantId: id(101),
  privacyDomainId: id(201),
  principalId: id(111),
  sessionId: id(117),
  sessionEpoch: '2',
  participantEpoch: '3',
  principalEpoch: '4',
  assignmentId: id(901),
  assignmentEpoch: '5',
  authorityEnvelopeId: id(902),
  authorityEpoch: '6',
  delegationEpoch: '7',
};
const context: ReadContext = {
  authorization,
  resourceType: 'policy-version',
  resourceId: id(101),
  actionIntentId: 'ACT-POLICY_VERSIONS_READ_COLLECTION-V1',
};
const row = {
  policyVersionId: id(921),
  policySetId: id(920),
  semanticVersion: '1.2.0',
  normalizedPolicyDigest: `sha256:${'a1'.repeat(32)}`,
  dependencyClosureDigest: `sha256:${'b2'.repeat(32)}`,
  createdAt: '2026-09-22T15:01:01.123456Z',
  updatedAt: '2026-09-22T15:01:01.123456Z',
};
const request = {
  limit: 1,
  filter: {
    field: 'policySetId',
    operator: 'eq' as const,
    value: `urn:openpc:policy-set:${id(920)}`,
  },
  filterText: `policySetId:eq:urn:openpc:policy-set:${id(920)}`,
  sort: '-updatedAt' as const,
  snapshotAt: '2026-10-11T00:00:00.000Z',
  snapshotRevision: '1',
};
function harness(rows = [row], stale = false) {
  const calls: { sql: string; args: readonly unknown[] }[] = [];
  const query = vi.fn(async (sql: string, args: readonly unknown[] = []) => {
    calls.push({ sql, args: [...args] });
    if (sql === policyAuthoritySelectionSql)
      return {
        rowCount: 1,
        rows: [
          {
            ...authorization,
            assignmentRowVersion: authorization.assignmentEpoch,
            sessionEpoch: stale ? '99' : authorization.sessionEpoch,
          },
        ],
      };
    if (sql.startsWith('select count(*)'))
      return { rowCount: 1, rows: [{ total: String(rows.length) }] };
    if (sql.includes('from (select v.*')) return { rowCount: rows.length, rows };
    return { rowCount: 1, rows: [] };
  });
  const release = vi.fn();
  const pool = { connect: vi.fn(async () => ({ query, release })) } as unknown as Pool;
  return { repository: new PolicyVersionReadRepository(pool), calls, release };
}
describe('native policy version reads', () => {
  it('filters counts and rows by current resource authority in a scoped read-only snapshot', async () => {
    const h = harness([row, { ...row, policyVersionId: id(922) }]);
    const page = await h.repository.list(context, request);
    expect(page).toMatchObject({
      total: '2',
      items: [{ policyVersionId: `urn:openpc:policy-version:${id(921)}`, state: 'DRAFT' }],
      next: { id: id(921), updatedAt: row.updatedAt },
    });
    expect(h.calls[0]!.sql).toBe('begin isolation level repeatable read read only');
    const queries = h.calls.filter(({ sql }) => sql.includes('from (select v.*'));
    expect(queries).toHaveLength(2);
    for (const { sql, args } of queries) {
      expect(sql).toContain('left join control.policy_artifact');
      expect(sql).toContain('policy_versions.policy_version_id::text');
      expect(sql).toContain('live_read_authority');
      expect(sql).toContain('policy_versions.participant_id=$2');
      expect(args.slice(1, 6)).toEqual([
        authorization.participantId,
        authorization.privacyDomainId,
        'ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
        authorization.principalId,
        authorization.sessionId,
      ]);
    }
    expect(h.calls.at(-1)!.sql).toBe('commit');
    expect(h.release).toHaveBeenCalledTimes(1);
  });
  it('preserves microseconds and the immutable version projection on exact reads', async () => {
    const h = harness();
    const version = await h.repository.get({
      ...context,
      actionIntentId: 'ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
      resourceId: id(921),
    });
    expect(version.createdAt).toBe(row.createdAt);
    expect(version.updatedAt).toBe(row.updatedAt);
    expect(version).not.toHaveProperty('semanticCbor');
    expect(version).toMatchObject({ state: 'DRAFT', revision: '1' });
    expect(h.calls.find(({ sql }) => sql.includes('where participant_id=$1'))!.args).toEqual([
      authorization.participantId,
      authorization.privacyDomainId,
      id(921),
    ]);
  });
  it('rejects stale session epochs before counting or returning versions', async () => {
    const h = harness([row], true);
    await expect(h.repository.list(context, request)).rejects.toMatchObject({
      code: 'PC-AUTH-0005',
    });
    expect(h.calls.some(({ sql }) => sql.includes('from (select v.*'))).toBe(false);
    expect(h.calls.at(-1)!.sql).toBe('rollback');
  });
  it('fails missing dependency evidence instead of hiding the row behind a complete empty list', async () => {
    const h = harness([{ ...row, dependencyClosureDigest: null } as unknown as typeof row]);
    await expect(h.repository.list(context, request)).rejects.toMatchObject({
      code: 'PC-INTEGRATION-5001',
    });
    expect(h.calls.at(-1)!.sql).toBe('rollback');
  });
  it('does not turn a missing exact resource into a version', async () => {
    const h = harness([]);
    await expect(h.repository.get({ ...context, resourceId: id(921) })).rejects.toMatchObject({
      code: 'PC-POLICY-2001',
    });
  });
});
