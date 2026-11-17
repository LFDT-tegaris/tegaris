import type { Pool } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { listPublicActivationOccurrences } from './public-activation-store.js';
import { listPublicReleaseBundles } from './public-release-store.js';
import type { PublicApprovalScope } from './public-approval-store.js';
import { resourceReadAuthoritySql } from './resource-read-authority.js';

vi.mock('../../../identity-service/src/db/authority-fence.js', () => ({
  fenceBoundAuthorities: vi.fn(),
  AuthorityFenceError: class extends Error {},
}));

const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const scope = {
  participantId: id(101),
  privacyDomainId: id(201),
  principalId: id(111),
  operationId: id(501),
  authority: { sessionId: id(701) },
} as PublicApprovalScope;
const request = {
  limit: 2,
  sort: '-updatedAt' as const,
  snapshotAt: '2026-10-01T15:00:00.000Z',
  snapshotRevision: '1',
  after: { updatedAt: '2026-10-01T14:00:00.000Z', id: id(601) },
};

describe('policy collection visibility', () => {
  it.each([
    {
      family: 'release-bundles',
      action: 'ACT-RELEASE_BUNDLES_READ_COLLECTION-V1',
      readAction: 'ACT-RELEASE_BUNDLES_READ_RESOURCE-V1',
      column: 'policy_release_bundle.release_bundle_id',
      list: listPublicReleaseBundles,
      state: 'ACTIVE' as const,
      table: 'control.policy_release_bundle',
    },
    {
      family: 'activation-occurrences',
      action: 'ACT-ACTIVATION_OCCURRENCES_READ_COLLECTION-V1',
      readAction: 'ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1',
      column: 'occurrence.activation_occurrence_id',
      list: listPublicActivationOccurrences,
      state: 'ACTIVE_MATCHED' as const,
      table: 'control.policy_activation_occurrence',
    },
  ])('filters both counts and pages for $family', async (spec) => {
    const queries: { sql: string; args: readonly unknown[] }[] = [];
    const query = vi.fn(async (sql: string, args: readonly unknown[] = []) => {
      queries.push({ sql, args: [...args] });
      if (sql.includes('from control.action_intent'))
        return {
          rowCount: 1,
          rows: [
            { operationClass: 'READ', resourceType: spec.family, semanticDigest: Buffer.alloc(32) },
          ],
        };
      if (sql.startsWith('select count(*)::text')) return { rowCount: 1, rows: [{ total: '0' }] };
      return { rowCount: 0, rows: [] };
    });
    const pool = { connect: vi.fn(async () => ({ query, release: vi.fn() })) } as unknown as Pool;
    // Each owner keeps its own state enum; this common test exercises SQL binding.
    const page =
      spec.family === 'release-bundles'
        ? await listPublicReleaseBundles(
            pool,
            { ...scope, actionIntentId: spec.action },
            { ...request, state: 'ACTIVE' },
          )
        : await listPublicActivationOccurrences(
            pool,
            { ...scope, actionIntentId: spec.action },
            { ...request, state: 'ACTIVE_MATCHED' },
          );
    const selected = queries.filter(({ sql }) => sql.includes(`from ${spec.table}`));
    expect(selected).toHaveLength(2);
    for (const { sql, args } of selected) {
      expect(sql).toContain(resourceReadAuthoritySql(spec.readAction, spec.column));
      expect(args.slice(0, 6)).toEqual([
        scope.participantId,
        scope.privacyDomainId,
        request.snapshotAt,
        scope.principalId,
        scope.authority.sessionId,
        spec.state,
      ]);
      expect(sql).toContain('state=$6');
    }
    expect(selected[1]!.sql).toContain('($7::timestamptz,$8::uuid)');
    expect(selected[1]!.sql).toContain('limit $9');
    expect(page).toMatchObject({ items: [], total: '0' });
  });

  it('rejects a non-resource action or untrusted SQL identifier', () => {
    expect(() =>
      resourceReadAuthoritySql(
        'ACT-APPROVAL_REQUESTS_APPROVE_RESOURCE-V1',
        'request.approval_request_id',
      ),
    ).toThrow();
    expect(() =>
      resourceReadAuthoritySql('ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'request.id) or true --'),
    ).toThrow();
  });
});
