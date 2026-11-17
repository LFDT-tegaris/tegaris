import { expect, it, vi } from 'vitest';
import { revokeIdentityEnvelopeRecoveryTrust } from './identity-envelope-rotation-revocation.js';
const expected = {
  predecessorSignerId: 'sha256:' + '11'.repeat(32),
  operationId: '018f0000-0000-7000-8000-000000000701',
};
it('uses only the current exact database operation without supplying a key selector or permission', async () => {
  const query = vi.fn(async () => ({
    rowCount: 1,
    rows: [
      {
        revocation: {
          signerId: expected.predecessorSignerId,
          operationId: expected.operationId,
          state: 'REVOKED',
        },
      },
    ],
  }));
  expect(await revokeIdentityEnvelopeRecoveryTrust({ query } as never, expected)).toEqual({
    signerId: expected.predecessorSignerId,
    operationId: expected.operationId,
    state: 'REVOKED',
  });
  expect(query).toHaveBeenCalledWith(
    'select openpc.revoke_identity_envelope_recovery_trust() as revocation',
  );
});
it.each([
  'wrong-key',
  'wrong-operation',
  'not-revoked',
  'retired',
  'extra',
  'missing',
  'multiple',
] as const)('rejects %s revocation confirmation', async (kind) => {
  const value = {
    signerId: kind === 'wrong-key' ? 'other' : expected.predecessorSignerId,
    operationId: kind === 'wrong-operation' ? 'other' : expected.operationId,
    state: kind === 'not-revoked' ? 'ACTIVE' : kind === 'retired' ? 'RETIRED' : 'REVOKED',
    ...(kind === 'extra' ? { privateKey: 'untrusted' } : {}),
  };
  await expect(
    revokeIdentityEnvelopeRecoveryTrust(
      {
        query: vi.fn(async () => ({
          rowCount: kind === 'missing' ? 0 : kind === 'multiple' ? 2 : 1,
          rows: [{ revocation: value }],
        })),
      } as never,
      expected,
    ),
  ).rejects.toThrow();
});
