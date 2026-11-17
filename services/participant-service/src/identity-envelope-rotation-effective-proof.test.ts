import { sign } from 'node:crypto';
import { expect, it } from 'vitest';
import { identityEnvelopeSigningTrustDigest } from '@openpc/security-kernel';
import { identityEnvelopeRotationPossessionPreimage } from '../../identity-service/src/domain/identity-envelope-rotation-provider.js';
import { authenticateIdentityEnvelopeRotationEffectiveProof } from './identity-envelope-rotation-proof.js';
import { identityEnvelopeEffectiveProofFixture } from './identity-envelope-rotation-proof.test-fixture.js';
it('authenticates only the original effective successor proof; possession itself establishes no consumer effect', () => {
  const f = identityEnvelopeEffectiveProofFixture();
  expect(authenticateIdentityEnvelopeRotationEffectiveProof(f.input, f.record)).toMatchObject({
    trustDigest: identityEnvelopeSigningTrustDigest(f.trust),
  });
});
it.each([
  'old-slot',
  'old-key',
  'new-challenge',
  'new-attempt',
  'foreign-operation',
  'changed-first',
  'future',
  'expired',
  'expired-lease',
  'issuer',
  'selection',
  'descriptor',
] as const)('rejects %s effective proof', (kind) => {
  const f = identityEnvelopeEffectiveProofFixture();
  if (kind === 'old-slot') f.record.slot = 'old';
  if (kind === 'old-key') {
    if (f.record.request.method !== 'PROVE') throw Error();
    f.record.observation.resultHex = sign(
      'sha256',
      identityEnvelopeRotationPossessionPreimage(f.record.request),
      { key: f.oldKey.privateKey, dsaEncoding: 'ieee-p1363' },
    ).toString('hex');
    f.record.firstObservation = { ...f.record.observation };
  }
  if (kind === 'new-challenge') {
    if (f.record.request.method !== 'PROVE') throw Error();
    f.record.request.challengeHex = '22'.repeat(32);
  }
  if (kind === 'new-attempt') f.record.request.attemptId = '018f0000-0000-7000-8000-000000000999';
  if (kind === 'foreign-operation') f.input.operationId = '018f0000-0000-7000-8000-000000000999';
  if (kind === 'changed-first') f.record.firstObservation.providerId = 'other-provider';
  if (kind === 'future') f.input.nowNs -= 3000000n;
  if (kind === 'expired') {
    if (f.record.request.method !== 'PROVE') throw Error();
    f.input.nowNs = BigInt(f.record.request.challengeExpiresAtNs);
  }
  if (kind === 'expired-lease') f.input.authorityValidUntilNs = f.input.nowNs;
  if (kind === 'issuer')
    f.input.currentIssuer = { ...f.input.currentIssuer, workloadPrincipalEpoch: '9' };
  if (kind === 'selection') f.input.selectedTrust = { ...f.trust, keyEpoch: f.trust.keyEpoch + 1n };
  if (kind === 'descriptor')
    f.input.descriptor = {
      ...f.input.descriptor!,
      validUntilNs: (BigInt(f.input.descriptor!.validUntilNs) - 1000n).toString(),
    };
  expect(() => authenticateIdentityEnvelopeRotationEffectiveProof(f.input, f.record)).toThrow();
});
