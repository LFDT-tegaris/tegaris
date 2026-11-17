import { beforeEach, expect, it, vi } from 'vitest';
import { createDiscoveryCertificateRecoveryCase } from './discovery-certificate-recovery-case.js';
import { readDiscoveryCertificateRecoverySource } from './discovery-certificate-recovery-source.js';
import {
  trustFixture,
  fixture,
  id,
} from '../domain/discovery-certificate-recovery.test-fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { platformRecoveryIntent } from '../contracts/platform-recovery.js';
vi.mock('./discovery-certificate-recovery-source.js', () => ({
  readDiscoveryCertificateRecoverySource: vi.fn(),
}));
beforeEach(() => vi.resetAllMocks());
function setup() {
  const f = trustFixture();
  vi.mocked(readDiscoveryCertificateRecoverySource).mockResolvedValue({
    ...f.source,
    intentVersion: 1 as const,
    originalAdministrationDisplaced: false,
    rootAdministrationEmpty: false,
    transport: fixture().source,
  });
  const query = vi.fn(async (sql: string) => ({
    rowCount: sql.startsWith('select 1') ? 0 : 1,
    rows: [],
  }));
  const actor = {
    participantId: f.source.enrollment.participantId,
    principalId: f.source.enrollment.recoveryPrincipal.principalId,
    sessionToken: `${f.source.enrollment.participantId}.${id(999)}`,
    platform: true,
  };
  return { f, query, client: { query } as never, actor };
}
it('derives a proposal from exact installed trust without new handoff names or credential effects', async () => {
  const v = setup();
  const result = await createDiscoveryCertificateRecoveryCase(
    v.client,
    v.actor,
    v.f.source.enrollment.enrollmentId,
    true,
  );
  expect(result).toMatchObject({ state: 'DRAFT', authority: 'NONE' });
  expect(result.intent.certificateRecovery).toEqual(v.f.intent.certificateRecovery);
  expect(result.intent.administrators).toEqual(v.f.intent.administrators);
  expect(result.intent.enrollmentDigest).toBe(canonicalAuthorizationDigest(v.f.source.enrollment));
  expect(result.intent).not.toHaveProperty('preparation');
  expect(platformRecoveryIntent.safeParse(result.intent).success).toBe(false);
  expect(v.query.mock.calls.filter(([sql]) => /^(insert|update)/u.test(sql))).toHaveLength(1);
  expect(v.query.mock.calls[1]![0]).toContain("'[]'::jsonb");
});
it('bounds environment-driven QA expiry by both installation trust and current Root', async () => {
  const v = setup();
  const result = await createDiscoveryCertificateRecoveryCase(
    v.client,
    v.actor,
    v.f.source.enrollment.enrollmentId,
    true,
    { profile: 'LOCAL_QA', leaseMs: 3600000, administratorMs: 28800000 },
  );
  expect(result.intent.validUntil).toBe(v.f.source.rootValidUntil.toISOString());
  expect(result.intent.lifetimes.leaseMs).toBe(3600000);
});
it('rejects non-executor, an existing live case and QA lifetime without QA trust before inserting', async () => {
  const v = setup();
  await expect(
    createDiscoveryCertificateRecoveryCase(
      v.client,
      { ...v.actor, principalId: v.f.source.enrollment.administratorPrincipalIds[0] },
      v.f.source.enrollment.enrollmentId,
      true,
    ),
  ).rejects.toThrow();
  expect(v.query).not.toHaveBeenCalled();
  v.query.mockResolvedValueOnce({ rowCount: 1, rows: [] });
  await expect(
    createDiscoveryCertificateRecoveryCase(
      v.client,
      v.actor,
      v.f.source.enrollment.enrollmentId,
      true,
    ),
  ).rejects.toThrow();
  v.query.mockClear();
  await expect(
    createDiscoveryCertificateRecoveryCase(
      v.client,
      v.actor,
      v.f.source.enrollment.enrollmentId,
      false,
      { profile: 'LOCAL_QA', leaseMs: 3600000, administratorMs: 28800000 },
    ),
  ).rejects.toThrow();
  expect(v.query.mock.calls.every(([sql]) => !sql.startsWith('insert'))).toBe(true);
});
