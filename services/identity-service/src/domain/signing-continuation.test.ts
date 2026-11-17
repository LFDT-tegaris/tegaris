import { createHash, generateKeyPairSync } from 'node:crypto';
import { SignJWT, decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  createSigningContinuationSigner,
  createSigningContinuationVerifier,
  signingContinuationPurpose,
  type SigningContinuationContext,
} from './signing-continuation.js';

const id = (n: number) => `01990000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (s: string) => 'sha256:' + createHash('sha256').update(s).digest('hex');
const now = new Date('2026-09-12T00:00:00Z');
const context: SigningContinuationContext = {
  version: 1,
  purpose: signingContinuationPurpose,
  effect: 'FINALIZE_EXISTING_SIGNING_ROTATION_ATTEMPT',
  participantId: id(1),
  privacyDomainId: id(2),
  rotationId: id(3),
  rotationRevision: '3',
  operationId: id(4),
  actionIntentId: 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',
  targetState: 'PREPARED',
  candidateDigest: digest('candidate'),
  approvalRequestId: id(5),
  originalActorKeyDigest: digest('actor'),
  originalAuthoritySnapshotDigest: digest('authority'),
  originalMakerSnapshotDigest: digest('maker'),
  originalCheckerSnapshotDigest: digest('checker'),
  providerAttemptId: id(6),
  providerMethod: 'PREPARE',
  providerRequestDigest: digest('request'),
  providerObservationDigest: digest('observation'),
  resultDisposition: 'APPLY_RESERVED_TARGET',
  workloadPrincipalId: id(7),
  workloadCredentialId: id(8),
  workloadCredentialEpoch: '2',
  workloadKeyDigest: digest('workload'),
  currentAuthorityStatus: 'CHANGED',
  currentAuthorityDigest: digest('current'),
};
function keys() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicDer = pair.publicKey.export({ type: 'spki', format: 'der' });
  return {
    ...pair,
    publicDer,
    privateDer: pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
  };
}
describe('closed signing rotation continuation assertions', () => {
  it('binds the exact recorded effect and fresh workload without granting a new provider mutation', async () => {
    const key = keys(),
      sign = createSigningContinuationSigner(key.privateDer, key.publicDer),
      verify = createSigningContinuationVerifier([key.publicDer]);
    const token = await sign(context, id(9), now),
      actual = await verify(token, context, now);
    expect(actual.assertionId).toBe(id(9));
    expect(actual.context.currentAuthorityStatus).toBe('CHANGED');
    expect(actual.expiresAtNs - actual.issuedAtNs).toBe(30_000_000_000n);
    for (const changed of [
      { operationId: id(10) },
      { providerAttemptId: id(10) },
      { providerObservationDigest: digest('other') },
      { privacyDomainId: id(10) },
      { rotationRevision: '4' },
      { workloadCredentialEpoch: '3' },
      { originalAuthoritySnapshotDigest: digest('other') },
      { currentAuthorityStatus: 'UNCHANGED_LIVE' as const },
    ])
      await expect(verify(token, { ...context, ...changed }, now)).rejects.toThrow();
    await expect(sign({ ...context, targetState: 'OLD_REVOKED' }, id(9), now)).rejects.toThrow();
    await expect(
      sign({ ...context, effect: 'DISPATCH_NEW_PROVIDER_MUTATION' } as never, id(9), now),
    ).rejects.toThrow();
  });
  it('rejects expired, future, wrong-audience, substituted-key and extra-claim assertions', async () => {
    const key = keys(),
      sign = createSigningContinuationSigner(key.privateDer, key.publicDer),
      verify = createSigningContinuationVerifier([key.publicDer]);
    const token = await sign(context, id(9), now);
    await expect(verify(token, context, new Date(now.getTime() + 30_000))).rejects.toThrow();
    await expect(verify(token, context, new Date(now.getTime() - 1_000))).rejects.toThrow();
    const claims = decodeJwt(token),
      header = {
        alg: 'ES256',
        typ: 'openpc-signing-rotation-attempt-reconcile+jwt',
        kid: 'sha256:' + createHash('sha256').update(key.publicDer).digest('hex'),
      };
    for (const changed of [
      { aud: 'urn:openpc:another-service' },
      { purpose: 'SESSION_LOGIN' },
      { dispatch: true },
      { exp: claims.iat! + 3600 },
    ]) {
      const invalid = await new SignJWT({ ...claims, ...changed })
        .setProtectedHeader(header)
        .sign(key.privateKey);
      await expect(verify(invalid, context, now)).rejects.toThrow();
    }
    const other = keys();
    const untrusted = await createSigningContinuationSigner(other.privateDer, other.publicDer)(
      context,
      id(9),
      now,
    );
    await expect(verify(untrusted, context, now)).rejects.toThrow();
  });
});
