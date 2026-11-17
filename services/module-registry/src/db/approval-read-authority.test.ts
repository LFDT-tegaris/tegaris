import type { Pool } from 'pg';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { buildLocalPolicyRuntime } from '../local-runtime.js';
import { approvalReadAuthoritySql } from './approval-read-authority.js';
import { listPublicPolicyApprovals, type PublicApprovalScope } from './public-approval-store.js';

vi.mock('../../../identity-service/src/db/authority-fence.js', () => ({
  fenceBoundAuthorities: vi.fn(),
  AuthorityFenceError: class extends Error {},
}));

const scope = {
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  principalId: '018f0000-0000-7000-8000-000000000111',
  operationId: '018f0000-0000-7000-8000-000000000501',
  actionIntentId: 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
  authority: { sessionId: '018f0000-0000-7000-8000-000000000701' },
} as PublicApprovalScope;

describe('local Policy approval connection authority', () => {
  it.each([undefined, '0', '1'] as const)(
    'requires explicit local QA opt-in for each Policy database connection (%s)',
    async (flag) => {
      const directory = await mkdtemp(
        join(
          process.env.OPENPC_TEST_TMP_ROOT ?? process.env.OPENPC_PNC_TMP_ROOT ?? tmpdir(),
          'policy-local-runtime-',
        ),
      );
      try {
        const password = `${directory}/password`,
          token = `${directory}/token`;
        const signer = `${directory}/signer.pem`;
        await Promise.all([
          writeFile(password, 'configuration-fixture-secret-value-0001', { mode: 0o600 }),
          writeFile(token, 'configuration-fixture-secret-value-0002', { mode: 0o600 }),
          writeFile(
            signer,
            generateKeyPairSync('ed25519').publicKey.export({ format: 'pem', type: 'spki' }),
            { mode: 0o600 },
          ),
        ]);
        const runtime = await buildLocalPolicyRuntime({
          OPENPC_LOCAL_RUNTIME: '1',
          ...(flag === undefined ? {} : { OPENPC_LOCAL_RUNTIME_QA_FIXTURE: flag }),
          POLICY_DATABASE_HOST: '127.0.0.1',
          POLICY_DATABASE_PORT: '5432',
          POLICY_DATABASE_NAME: 'openpc_control',
          POLICY_DATABASE_USER: 'openpc_policy_runtime',
          POLICY_DATABASE_PASSWORD_FILE: password,
          POLICY_INTERNAL_TOKEN_FILE: token,
          POLICY_IDENTITY_INTERNAL_TOKEN_FILE: token,
          POLICY_ARTIFACT_SIGNER_PUBLIC_KEY_FILE: signer,
          POLICY_IDENTITY_URL: 'http://127.0.0.1:8081',
          POLICY_LISTEN: '127.0.0.1:8082',
        });
        try {
          expect(runtime.pool.options.options).toBe(`-c openpc.local_qa_runtime=${flag ?? '0'}`);
          expect(runtime.pool.options.user).toBe('openpc_policy_runtime');
          expect(runtime.pool.totalCount).toBe(0);
        } finally {
          await runtime.app.close();
          await runtime.pool.end();
        }
      } finally {
        await rm(directory, { recursive: true });
      }
    },
  );
  it.each(['true', 'yes', '2'])(
    'rejects ambiguous QA opt-in %s before constructing a connection',
    async (flag) => {
      await expect(
        buildLocalPolicyRuntime({
          OPENPC_LOCAL_RUNTIME: '1',
          OPENPC_LOCAL_RUNTIME_QA_FIXTURE: flag,
        }),
      ).rejects.toMatchObject({
        issues: expect.arrayContaining([
          expect.objectContaining({ path: ['OPENPC_LOCAL_RUNTIME_QA_FIXTURE'] }),
        ]),
      });
    },
  );
});

describe('approval collection resource visibility', () => {
  it('uses the shared complete READ chain and requires a single unambiguous result', () => {
    expect(approvalReadAuthoritySql).toContain('request.approval_request_id::text');
    expect(approvalReadAuthoritySql).toContain("'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1'");
    expect(approvalReadAuthoritySql).toContain('openpc.assignment_role_permits');
    expect(approvalReadAuthoritySql).toContain('session.session_id=$5');
    expect(approvalReadAuthoritySql).toContain('principal.principal_id=$4');
    expect(approvalReadAuthoritySql).toContain('session.authority_epoch=principal.authority_epoch');
    expect(approvalReadAuthoritySql).toContain('platform_authority_epoch');
    expect(approvalReadAuthoritySql).toContain(')=1');
    expect(approvalReadAuthoritySql).not.toMatch(/\$(?:[6-9]|1\d)/u);
  });

  it('filters visibility before both counting and paging, including filters and cursors', async () => {
    const queries: { sql: string; args: readonly unknown[] }[] = [];
    const query = vi.fn(async (sql: string, args: readonly unknown[] = []) => {
      queries.push({ sql, args });
      if (sql.includes('from control.action_intent'))
        return {
          rowCount: 1,
          rows: [
            {
              operationClass: 'READ',
              resourceType: 'approval-requests',
              semanticDigest: Buffer.alloc(32),
            },
          ],
        };
      if (sql.startsWith('select count(*)::text')) return { rowCount: 1, rows: [{ total: '0' }] };
      return { rowCount: 0, rows: [] };
    });
    const release = vi.fn();
    const pool = { connect: vi.fn(async () => ({ query, release })) } as unknown as Pool;
    const snapshotAt = '2026-10-01T15:00:00.000Z';
    const page = await listPublicPolicyApprovals(pool, scope, {
      limit: 2,
      sort: '-updatedAt',
      snapshotAt,
      snapshotRevision: '1',
      filter: { field: 'state', operator: 'eq', value: 'REQUESTED' },
      filterText: 'state eq REQUESTED',
      after: { updatedAt: '2026-10-01T14:00:00.000Z', id: '018f0000-0000-7000-8000-000000000601' },
    });
    const selections = queries.filter(({ sql }) =>
      sql.includes('from control.approval_request request'),
    );
    expect(selections).toHaveLength(2);
    for (const { sql, args } of selections) {
      expect(sql).toContain(approvalReadAuthoritySql);
      expect(args.slice(0, 6)).toEqual([
        scope.participantId,
        scope.privacyDomainId,
        snapshotAt,
        scope.principalId,
        scope.authority.sessionId,
        'REQUESTED',
      ]);
      expect(sql).toContain('else request.state::text end=$6');
    }
    expect(selections[1]!.sql).toContain('($7::timestamptz,$8::uuid)');
    expect(selections[1]!.sql).toContain('limit $9');
    expect(page).toMatchObject({ items: [], total: '0' });
    expect(release).toHaveBeenCalledOnce();
  });
});
