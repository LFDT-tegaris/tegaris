import { generateKeyPairSync } from 'node:crypto';

import { encodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import { describe, expect, it } from 'vitest';

import {
  createLocalIdentityRuntimeCryptoAdapter,
  createLocalIdentityRuntimeVerifier,
} from './identity-runtime-crypto.js';

function pair() {
  const generated = generateKeyPairSync('ed25519');
  return {
    privateKey: generated.privateKey.export({ format: 'der', type: 'pkcs8' }),
    publicKey: generated.publicKey.export({ format: 'der', type: 'spki' }),
  };
}

function payload() {
  const digest = (byte: number) => Buffer.alloc(32, byte);
  return encodeIdentityAuthContextAssertionPayload({
    assertionId: '018f0000-0000-7000-8000-000000000001',
    actorKeyDigest: digest(1),
    actorKind: 0,
    participantContextDigest: digest(2),
    audienceDigest: digest(3),
    senderBindingKind: 1,
    assuranceProfileDigest: digest(4),
    authorityVectorDigest: digest(5),
    issuedAtNs: 1n,
    expiresAtNs: 2n,
    authenticationEvidenceDigest: digest(6),
    senderCredentialBindingDigest: digest(7),
  });
}

describe('identity runtime crypto adapter', () => {
  it('signs with the active key and verifies active and retained rotation keys', async () => {
    const active = pair();
    const retired = pair();
    const activeAdapter = createLocalIdentityRuntimeCryptoAdapter({
      activePrivateKeyPkcs8Der: active.privateKey,
      activePublicKeySpkiDer: active.publicKey,
      trustedPublicKeysSpkiDer: [active.publicKey, retired.publicKey],
    });
    const retiredAdapter = createLocalIdentityRuntimeCryptoAdapter({
      activePrivateKeyPkcs8Der: retired.privateKey,
      activePublicKeySpkiDer: retired.publicKey,
      trustedPublicKeysSpkiDer: [retired.publicKey],
    });
    const evidence = payload();
    const activeSigned = await activeAdapter.signCanonicalAssertion(evidence);
    const retiredSigned = await retiredAdapter.signCanonicalAssertion(evidence);
    const publicVerifier = createLocalIdentityRuntimeVerifier([
      active.publicKey,
      retired.publicKey,
    ]);
    expect(Object.keys(publicVerifier)).toEqual(['verifyCanonicalAssertion']);
    await expect(
      publicVerifier.verifyCanonicalAssertion(evidence, activeSigned.coseSign1),
    ).resolves.toEqual({ signerKeyDigest: activeSigned.signerKeyDigest });
    await expect(
      publicVerifier.verifyCanonicalAssertion(evidence, retiredSigned.coseSign1),
    ).resolves.toEqual({ signerKeyDigest: retiredSigned.signerKeyDigest });
    expect(() => createLocalIdentityRuntimeVerifier([])).toThrow('empty');
    const noncanonical = Buffer.concat([retired.publicKey, Buffer.from([0])]);
    expect(() => createLocalIdentityRuntimeVerifier([noncanonical])).toThrow('SPKI');
    expect(() =>
      createLocalIdentityRuntimeCryptoAdapter({
        activePrivateKeyPkcs8Der: active.privateKey,
        activePublicKeySpkiDer: active.publicKey,
        trustedPublicKeysSpkiDer: [active.publicKey, noncanonical],
      }),
    ).toThrow('SPKI');
    await expect(
      activeAdapter.verifyCanonicalAssertion(evidence, activeSigned.coseSign1),
    ).resolves.toEqual({ signerKeyDigest: activeSigned.signerKeyDigest });
    await expect(
      activeAdapter.verifyCanonicalAssertion(evidence, retiredSigned.coseSign1),
    ).resolves.toEqual({ signerKeyDigest: retiredSigned.signerKeyDigest });
  });

  it('rejects foreign keys, altered assertions, mismatched pairs, and duplicate trust keys', async () => {
    const active = pair();
    const foreign = pair();
    const adapter = createLocalIdentityRuntimeCryptoAdapter({
      activePrivateKeyPkcs8Der: active.privateKey,
      activePublicKeySpkiDer: active.publicKey,
      trustedPublicKeysSpkiDer: [active.publicKey],
    });
    const foreignAdapter = createLocalIdentityRuntimeCryptoAdapter({
      activePrivateKeyPkcs8Der: foreign.privateKey,
      activePublicKeySpkiDer: foreign.publicKey,
      trustedPublicKeysSpkiDer: [foreign.publicKey],
    });
    const evidence = payload();
    const foreignSigned = await foreignAdapter.signCanonicalAssertion(evidence);
    await expect(
      adapter.verifyCanonicalAssertion(evidence, foreignSigned.coseSign1),
    ).resolves.toBeUndefined();
    const altered = Buffer.from(foreignSigned.coseSign1);
    altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
    await expect(adapter.verifyCanonicalAssertion(evidence, altered)).resolves.toBeUndefined();
    expect(() =>
      createLocalIdentityRuntimeCryptoAdapter({
        activePrivateKeyPkcs8Der: active.privateKey,
        activePublicKeySpkiDer: foreign.publicKey,
        trustedPublicKeysSpkiDer: [foreign.publicKey],
      }),
    ).toThrow('does not match');
    expect(() =>
      createLocalIdentityRuntimeCryptoAdapter({
        activePrivateKeyPkcs8Der: active.privateKey,
        activePublicKeySpkiDer: active.publicKey,
        trustedPublicKeysSpkiDer: [active.publicKey, active.publicKey],
      }),
    ).toThrow('duplicate');
  });
});
