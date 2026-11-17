import { expect, it, vi } from 'vitest';
import { readRecoveryEnrollmentPurpose } from './recovery-enrollment-purpose.js';
it.each([
  'pc.identity.platform-recovery-enrollment',
  'pc.identity.discovery-certificate-recovery-enrollment',
  'pc.identity.identity-envelope-recovery-enrollment',
])('derives %s from a single scoped stored source', async (schema) => {
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [{ schema }] });
  await expect(
    readRecoveryEnrollmentPurpose({ query } as never, 'part', 'enrollment'),
  ).resolves.toBe(schema);
  expect(query.mock.calls[0]![0]).toContain('openpc.matches_privacy(privacy_domain_id)');
  expect(query.mock.calls[0]![1]).toEqual(['part', 'enrollment']);
});
it.each([
  { rowCount: 0, rows: [] },
  {
    rowCount: 2,
    rows: [
      { schema: 'pc.identity.platform-recovery-enrollment' },
      { schema: 'pc.identity.identity-envelope-recovery-enrollment' },
    ],
  },
  { rowCount: 1, rows: [{ schema: 'caller-purpose' }] },
])('rejects missing, ambiguous or unsupported stored purpose', async (result) => {
  await expect(
    readRecoveryEnrollmentPurpose(
      { query: vi.fn().mockResolvedValue(result) } as never,
      'part',
      'enrollment',
    ),
  ).rejects.toThrow();
});
