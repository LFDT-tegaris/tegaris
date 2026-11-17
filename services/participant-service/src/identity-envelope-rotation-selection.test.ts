import { expect, it, vi } from 'vitest';
import { selectIdentityEnvelopeRecoveryTrust } from './identity-envelope-rotation-selection.js';
const expected = {
  signerId: 'sha256:' + '11'.repeat(32),
  trustDigest: 'sha256:' + '22'.repeat(32),
  selectionAdmissionVersion: '2',
};
it('uses only the original scoped database cutover owner', async () => {
  const query = vi.fn(async () => ({
    rowCount: 1,
    rows: [{ selection: { ...expected, state: 'SELECTED' } }],
  }));
  expect(await selectIdentityEnvelopeRecoveryTrust({ query } as never, expected)).toEqual({
    ...expected,
    state: 'SELECTED',
  });
  expect(query).toHaveBeenCalledExactlyOnceWith(
    'select openpc.select_identity_envelope_recovery_trust() as selection',
  );
});
it.each(['signer', 'digest', 'version', 'state', 'extra', 'cardinality'] as const)(
  'rejects mismatched %s selection readback without retry',
  async (kind) => {
    const selected = {
      ...expected,
      state: 'SELECTED',
      ...(kind === 'extra' ? { consumerAccepted: true } : {}),
    };
    if (kind === 'signer') selected.signerId = 'sha256:' + '33'.repeat(32);
    if (kind === 'digest') selected.trustDigest = 'sha256:' + '44'.repeat(32);
    if (kind === 'version') selected.selectionAdmissionVersion = '3';
    if (kind === 'state') selected.state = 'RETIRED';
    const query = vi.fn(async () => ({
      rowCount: kind === 'cardinality' ? 0 : 1,
      rows: [{ selection: selected }],
    }));
    await expect(
      selectIdentityEnvelopeRecoveryTrust({ query } as never, expected),
    ).rejects.toThrow();
    expect(query).toHaveBeenCalledTimes(1);
  },
);
