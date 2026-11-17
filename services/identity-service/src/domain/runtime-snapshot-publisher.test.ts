import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { decodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import { describe, expect, it, vi } from 'vitest';
import { createLocalIdentityRuntimeCryptoAdapter } from './identity-runtime-crypto.js';
import { identityActorKeyDigest } from './identity-runtime-authorization.js';
import { RuntimeSnapshotPublisher } from './runtime-snapshot-publisher.js';

function fixture(snapshotLifetimeMs: number, remainingMs: number) {
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' });
  const adapter = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const crypto = { ...adapter, signCanonicalAssertion: vi.fn(adapter.signCanonicalAssertion) };
  const publisher = new RuntimeSnapshotPublisher(
    crypto,
    {
      profileId: 'pc.identity.r1.workload-mtls',
      profileVersion: 1n,
      applicability: [1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1],
      profileClass: 1,
      signerId: `sha256:${crypto.activeKeyDigest().toString('hex')}`,
    },
    { scope: ['workload', 'test-ca', 'TLS1.3-X509'], state: {} },
    snapshotLifetimeMs,
  );
  const subject = {
    participantId: '018f0000-0000-7000-8000-000000000101',
    principalId: '018f0000-0000-7000-8000-000000000194',
    workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000196',
    uriSan: 'spiffe://openpc/test/business-api',
    keyId: `sha256:${'01'.repeat(32)}`,
    certificateFingerprint: Buffer.alloc(32, 2),
    notAfter: new Date('2026-10-02T00:00:00Z'),
  };
  const publication = Object.freeze({
    snapshotId: '018f0000-0000-7000-8000-000000000901',
    manifestDigest: `sha256:${'03'.repeat(32)}`,
    issuedAtNs: BigInt(Date.parse('2026-10-01T00:00:00Z')) * 1_000_000n,
    expiresAtNs:
      BigInt(Date.parse('2026-10-01T00:00:00Z')) * 1_000_000n + BigInt(remainingMs) * 1_000_000n,
    profileDigest: Buffer.alloc(32, 4),
    actors: [
      {
        projection: {
          actorKeyDigest: identityActorKeyDigest(subject.participantId, subject.principalId),
          authorityVectorDigest: Buffer.alloc(32, 5),
        },
      },
    ],
    workloads: [{ principalId: subject.principalId, workloadId: subject.workloadId }],
  });
  // Isolate assertion issuance from the SQL snapshot publication owner. The
  // cryptographic issuer and the signed assertion decoder remain real.
  const snapshotOwner = publisher as unknown as {
    buildSnapshot: (...args: unknown[]) => Promise<typeof publication>;
  };
  vi.spyOn(snapshotOwner, 'buildSnapshot').mockResolvedValue(publication);
  const sign = crypto.signCanonicalAssertion;
  const issue = () =>
    publisher.publishForAuthenticatedWorkload(
      {} as PoolClient,
      {
        privacyDomainId: '018f0000-0000-7000-8000-000000000201',
        targetRuntimeId: '018f0000-0000-7000-8000-000000000902',
      },
      subject,
    );
  return { issue, publication, crypto, sign };
}

describe('authenticated workload assertion lifetime', () => {
  it.each([
    ['one-hour QA snapshot', 3_600_000, 3_600_000, 60_000],
    ['normal snapshot', 60_000, 60_000, 60_000],
    ['retained snapshot near expiry', 3_600_000, 12_000, 12_000],
    ['short credential or authority transition', 3_600_000, 2_000, 2_000],
  ])(
    'bounds the assertion for %s without changing snapshot authority',
    async (_, ttl, remaining, bound) => {
      const { issue, publication, crypto } = fixture(ttl, remaining);
      const result = await issue();
      const payload = Buffer.from(result.assertionPayload, 'base64');
      const claims = decodeIdentityAuthContextAssertionPayload(payload);
      expect(claims.expiresAtNs - claims.issuedAtNs).toBe(BigInt(bound) * 1_000_000n);
      expect(claims.expiresAtNs).toBeLessThanOrEqual(publication.expiresAtNs);
      expect(result.expiresAtNs).toBe(claims.expiresAtNs.toString());
      expect(result.snapshotId).toBe(publication.snapshotId);
      expect(publication.expiresAtNs - publication.issuedAtNs).toBe(BigInt(remaining) * 1_000_000n);
      await expect(
        crypto.verifyCanonicalAssertion(payload, Buffer.from(result.assertionCoseSign1, 'base64')),
      ).resolves.toBeDefined();
    },
  );

  it('issues distinct signed assertions when reusing the same snapshot', async () => {
    const { issue } = fixture(3_600_000, 3_600_000);
    const first = await issue();
    const second = await issue();
    expect(first.snapshotId).toBe(second.snapshotId);
    const decode = (payload: string) =>
      decodeIdentityAuthContextAssertionPayload(Buffer.from(payload, 'base64'));
    expect(decode(first.assertionPayload).assertionId).not.toBe(
      decode(second.assertionPayload).assertionId,
    );
    expect(first.assertionCoseSign1).not.toBe(second.assertionCoseSign1);
  });

  it('does not sign authority whose snapshot bound has already elapsed', async () => {
    const { issue, sign } = fixture(3_600_000, 0);
    await expect(issue()).rejects.toThrow();
    expect(sign).not.toHaveBeenCalled();
  });
});
