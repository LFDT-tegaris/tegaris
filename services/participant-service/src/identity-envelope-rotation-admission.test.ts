import { expect, it, vi } from 'vitest';
import {
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
} from '@openpc/security-kernel';
import { identityEnvelopeDualProofFixture } from './identity-envelope-rotation-proof.test-fixture.js';
import { admitIdentityEnvelopeRecoveryTrust } from './identity-envelope-rotation-admission.js';
it('submits only canonical public trust to the exact database admission owner', async () => {
  const { trust } = identityEnvelopeDualProofFixture();
  const expected = {
    signerId: trust.signerId,
    trustDigest: identityEnvelopeSigningTrustDigest(trust),
    state: 'ADMITTED',
  };
  const query = vi.fn(async () => ({ rowCount: 1, rows: [{ admission: expected }] }));
  expect(await admitIdentityEnvelopeRecoveryTrust({ query } as never, trust)).toEqual(expected);
  expect(query.mock.calls).toHaveLength(1);
  expect(query).toHaveBeenCalledWith(
    'select openpc.admit_identity_envelope_recovery_trust($1,$2) as admission',
    [
      identityEnvelopeSigningTrustPreimage(trust),
      Buffer.from(expected.trustDigest.slice(7), 'hex'),
    ],
  );
});
it.each(['signer', 'digest', 'state', 'extra', 'cardinality'] as const)(
  'rejects %s admission readback',
  async (kind) => {
    const { trust } = identityEnvelopeDualProofFixture();
    const result = {
      signerId: trust.signerId,
      trustDigest: identityEnvelopeSigningTrustDigest(trust),
      state: 'ADMITTED',
      ...(kind === 'extra' ? { consumerAccepted: true } : {}),
    };
    if (kind === 'signer') result.signerId = 'sha256:' + '22'.repeat(32);
    if (kind === 'digest') result.trustDigest = 'sha256:' + '33'.repeat(32);
    if (kind === 'state') result.state = 'ACTIVE';
    const query = vi.fn(async () => ({
      rowCount: kind === 'cardinality' ? 2 : 1,
      rows: [{ admission: result }],
    }));
    await expect(admitIdentityEnvelopeRecoveryTrust({ query } as never, trust)).rejects.toThrow();
    expect(query).toHaveBeenCalledTimes(1);
  },
);
it('propagates database denial without replacing the request', async () => {
  const { trust } = identityEnvelopeDualProofFixture();
  const query = vi.fn(async () => {
    throw Error('denied');
  });
  await expect(admitIdentityEnvelopeRecoveryTrust({ query } as never, trust)).rejects.toThrow(
    'denied',
  );
  expect(query).toHaveBeenCalledTimes(1);
});
