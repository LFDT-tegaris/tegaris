import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import { trustFixture, id } from './discovery-certificate-recovery.test-fixture.js';
import { discoveryCertificateRotationCandidate } from '../contracts/discovery-certificate-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { readWorkloadProposal } from './workload-lifecycle-readback.js';
function fixture() {
  const { intent, source } = trustFixture(),
    candidate = discoveryCertificateRotationCandidate(intent.certificateRecovery);
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rowCount: 1, rows: [{ intent }] })
    .mockResolvedValueOnce({ rowCount: 0, rows: [] });
  const authority = {
    principalId: intent.administrators[0].principalId,
    authorityEnvelopeId: id(990),
  } as import('../db/authority-fence.js').BoundAuthority;
  const args = [
    source.enrollment.participantId,
    source.enrollment.privacyDomainId,
    candidate.replacedCredentialId,
    canonicalAuthorizationDigest(candidate),
    {
      expectedRevision: intent.certificateRecovery.predecessorRevision,
      makerPrincipalId: intent.administrators[0].principalId,
    },
    { authority, recoveryId: intent.recoveryId, enrollmentId: intent.enrollmentId },
  ] as const;
  return { query, client: { query } as unknown as PoolClient, args };
}
it('returns explicit absence only after the actual current Discovery binding has been authenticated', async () => {
  const f = fixture();
  await expect(readWorkloadProposal(f.client, ...f.args)).resolves.toEqual({
    preapprovalState: 'ABSENT',
  });
  expect(f.query.mock.calls[0]![0]).toContain('platform_recovery_envelope_current');
  expect(f.query.mock.calls[0]![1]).toEqual([
    f.args[0],
    f.args[5].authority.authorityEnvelopeId,
    f.args[5].authority.principalId,
    f.args[1],
    f.args[5].recoveryId,
    f.args[5].enrollmentId,
  ]);
  expect(f.query).toHaveBeenCalledTimes(2);
});
it.each([
  'unavailable authority',
  'wrong maker',
  'wrong resource',
  'wrong digest',
  'ambiguous authority',
])('denies %s before an absence result', async (failure) => {
  const f = fixture();
  let args = f.args;
  if (failure === 'unavailable authority')
    f.query.mockReset().mockResolvedValueOnce({ rowCount: 0, rows: [] });
  if (failure === 'ambiguous authority')
    f.query.mockReset().mockResolvedValueOnce({ rowCount: 2, rows: [{}, {}] });
  if (failure === 'wrong maker')
    args = [
      ...f.args.slice(0, 4),
      { ...f.args[4], makerPrincipalId: id(991) },
      f.args[5],
    ] as unknown as typeof args;
  if (failure === 'wrong resource')
    args = [f.args[0], f.args[1], id(991), ...f.args.slice(3)] as unknown as typeof args;
  if (failure === 'wrong digest')
    args = [
      ...f.args.slice(0, 3),
      'sha256:' + 'f'.repeat(64),
      f.args[4],
      f.args[5],
    ] as unknown as typeof args;
  await expect(readWorkloadProposal(f.client, ...args)).rejects.toBeDefined();
  expect(f.query).toHaveBeenCalledTimes(1);
});
