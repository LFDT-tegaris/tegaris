import {
  createHash,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
  type KeyObject,
} from 'node:crypto';

import {
  signIdentityAuthContextAssertionCoseSign1Ed25519,
  signIdentityRuntimeSnapshotManifestCoseSign1Ed25519,
  signIdentityRuntimeAuthorityProfileCoseSign1Ed25519,
  type IdentityRuntimeAuthorityProfile,
  verifyIdentityAuthContextAssertionCoseSign1Ed25519,
} from '@openpc/security-kernel';

export interface SignedIdentityRuntimeAssertion {
  readonly coseSign1: Buffer;
  readonly evidenceCbor: Buffer;
  readonly evidenceDigest: Buffer;
  readonly signerKeyDigest: Buffer;
}

export interface VerifiedIdentityRuntimeAssertion {
  readonly signerKeyDigest: Buffer;
}

/**
 * Purpose-specific signer and verification-key ring for identity-runtime v2
 * assertions. Production adapters can keep the same boundary while delegating
 * signing to a KMS or HSM and resolving trusted public keys by their SPKI digest.
 */
export interface IdentityRuntimeVerifier {
  verifyCanonicalAssertion(
    evidenceCbor: Buffer,
    coseSign1: Buffer,
  ): Promise<VerifiedIdentityRuntimeAssertion | undefined>;
}

export interface IdentityRuntimeCryptoAdapter extends IdentityRuntimeVerifier {
  activeKeyDigest(): Buffer;
  signCanonicalAssertion(evidenceCbor: Buffer): Promise<SignedIdentityRuntimeAssertion>;
  signCanonicalSnapshotManifest(evidenceCbor: Buffer): Promise<SignedIdentityRuntimeAssertion>;
  signAuthorityProfile(profile: IdentityRuntimeAuthorityProfile): Promise<{
    readonly payload: Buffer;
    readonly coseSign1: Buffer;
    readonly semanticDigest: Buffer;
  }>;
}

function ed25519PublicKey(value: Buffer): { readonly der: Buffer; readonly key: KeyObject } {
  const der = Buffer.from(value);
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  if (
    key.asymmetricKeyType !== 'ed25519' ||
    !key.export({ format: 'der', type: 'spki' }).equals(der)
  ) {
    throw new Error('identity runtime trust key must be Ed25519 SPKI');
  }
  return { der, key };
}

function keyDigest(publicKeySpkiDer: Buffer): Buffer {
  return createHash('sha256').update(publicKeySpkiDer).digest();
}

/** Local verification-only port: consumers receive public trust, never signing material. */
export function createLocalIdentityRuntimeVerifier(
  trustedPublicKeysSpkiDer: readonly Buffer[],
): IdentityRuntimeVerifier {
  const trusted = trustedPublicKeysSpkiDer.map(ed25519PublicKey);
  if (trusted.length === 0) throw new Error('empty identity runtime trust ring');
  const distinct = new Set(trusted.map((candidate) => keyDigest(candidate.der).toString('hex')));
  if (distinct.size !== trusted.length) throw new Error('duplicate identity runtime trust key');
  return Object.freeze({
    async verifyCanonicalAssertion(evidenceCbor: Buffer, coseSign1: Buffer) {
      const payload = Buffer.from(evidenceCbor);
      const envelope = Buffer.from(coseSign1);
      for (const candidate of trusted) {
        if (verifyIdentityAuthContextAssertionCoseSign1Ed25519(candidate.der, payload, envelope)) {
          return Object.freeze({ signerKeyDigest: keyDigest(candidate.der) });
        }
      }
      return undefined;
    },
  });
}

export function createLocalIdentityRuntimeCryptoAdapter(input: {
  readonly activePrivateKeyPkcs8Der: Buffer;
  readonly activePublicKeySpkiDer: Buffer;
  readonly trustedPublicKeysSpkiDer: readonly Buffer[];
}): IdentityRuntimeCryptoAdapter {
  const privateKey = createPrivateKey({
    key: Buffer.from(input.activePrivateKeyPkcs8Der),
    format: 'der',
    type: 'pkcs8',
  });
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('identity runtime signing key must be Ed25519 PKCS8');
  }
  const active = ed25519PublicKey(input.activePublicKeySpkiDer);
  const derivedActive = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  if (derivedActive.length !== active.der.length || !timingSafeEqual(derivedActive, active.der)) {
    throw new Error('identity runtime signing key pair does not match');
  }
  const trusted = input.trustedPublicKeysSpkiDer.map(ed25519PublicKey);
  const activeDigest = keyDigest(active.der);
  if (
    trusted.length === 0 ||
    !trusted.some((candidate) => timingSafeEqual(keyDigest(candidate.der), activeDigest))
  ) {
    throw new Error('active identity runtime key is not trusted');
  }
  const verifier = createLocalIdentityRuntimeVerifier(input.trustedPublicKeysSpkiDer);

  function signCanonical(
    evidenceCbor: Buffer,
    signPayload: (privateDer: Buffer, publicDer: Buffer, payload: Buffer) => Buffer,
  ): SignedIdentityRuntimeAssertion {
    const payload = Buffer.from(evidenceCbor);
    const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });
    try {
      const coseSign1 = signPayload(privateDer, active.der, payload);
      return Object.freeze({
        coseSign1,
        evidenceCbor: payload,
        evidenceDigest: createHash('sha256').update(payload).digest(),
        signerKeyDigest: Buffer.from(activeDigest),
      });
    } finally {
      privateDer.fill(0);
    }
  }
  return Object.freeze({
    activeKeyDigest: () => Buffer.from(activeDigest),
    async signCanonicalAssertion(evidenceCbor: Buffer) {
      return signCanonical(evidenceCbor, signIdentityAuthContextAssertionCoseSign1Ed25519);
    },
    async signCanonicalSnapshotManifest(evidenceCbor: Buffer) {
      return signCanonical(evidenceCbor, signIdentityRuntimeSnapshotManifestCoseSign1Ed25519);
    },
    async signAuthorityProfile(profile: IdentityRuntimeAuthorityProfile) {
      const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });
      try {
        return signIdentityRuntimeAuthorityProfileCoseSign1Ed25519(privateDer, active.der, profile);
      } finally {
        privateDer.fill(0);
      }
    },
    verifyCanonicalAssertion: verifier.verifyCanonicalAssertion,
  });
}
