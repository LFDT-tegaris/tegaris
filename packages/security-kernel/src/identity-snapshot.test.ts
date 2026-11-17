import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  encodeIdentityAuthorityVector,
  encodeIdentityRuntimeAuthorityProfile,
  encodeIdentityRuntimeSnapshot,
  identitySemanticDigest,
  signIdentityRuntimeSnapshotManifestCoseSign1Ed25519,
  verifyIdentityRuntimeSnapshotManifestCoseSign1Ed25519,
  type IdentityAuthorityVector,
  type IdentitySnapshotInput,
} from './identity-snapshot.js';
import { verifyIdentityAuthContextAssertionCoseSign1Ed25519 } from './identity-runtime.js';

function fixture(): IdentitySnapshotInput {
  const vector: IdentityAuthorityVector = {
    profileId: 'pc.identity.r1.workload-mtls',
    profileVersion: 1n,
    profileSemanticDigest: Buffer.alloc(32, 3),
    entries: Array.from({ length: 12 }, (_, i) => ({
      domainCode: i + 1,
      applicability: i === 5 ? 0 : 1,
      scopeDigest: Buffer.alloc(32, i === 5 ? 0 : i + 1),
      version: i === 5 ? 0n : 1n,
    })),
  };
  const projection = {
    actorKeyDigest: Buffer.alloc(32, 1),
    actorKind: 1 as const,
    participantContextDigest: Buffer.alloc(32, 2),
    roleAssignmentSetDigest: Buffer.alloc(32, 4),
    participantEnvelopeDigest: Buffer.alloc(32, 5),
    authorityVectorDigest: identitySemanticDigest(3001, encodeIdentityAuthorityVector(vector)),
  };
  return {
    snapshotId: 'snapshot-1',
    targetScopeDigest: Buffer.alloc(32, 7),
    releaseProfileRegistryDigest: Buffer.alloc(32, 8),
    issuedAtNs: 1n,
    hardExpiryNs: 100n,
    signerId: 'identity-key',
    actors: [{ projection, authorityVector: vector }],
  };
}
describe('primary identity snapshot producer', () => {
  it('matches the independent CBOR vector also consumed by Rust', () => {
    const input = fixture();
    const output = encodeIdentityRuntimeSnapshot(input);
    expect(input.actors[0]!.projection.authorityVectorDigest.toString('hex')).toBe(
      '29b79a8efb262f256ea776f4377f8823ac51ab307f2764eae14263628520a288',
    );
    expect(output.shards[0]!.semanticDigest.toString('hex')).toBe(
      'a1a2aae2961dabdf83dae35023f8f544ee4e62eb45bd2b67e2d0f066f1cdd88a',
    );
    expect(output.manifestSemanticDigest.toString('hex')).toBe(
      'e31fcb9292e3dfb4110ea1d02b56a1b6b011860a03dd60e17a561ec578b4df37',
    );
  });
  it('signs only the manifest schema and rejects mutation or signature substitution', () => {
    const output = encodeIdentityRuntimeSnapshot(fixture());
    const keys = generateKeyPairSync('ed25519');
    const privateKey = keys.privateKey.export({ format: 'der', type: 'pkcs8' });
    const publicKey = keys.publicKey.export({ format: 'der', type: 'spki' });
    const cose = signIdentityRuntimeSnapshotManifestCoseSign1Ed25519(
      privateKey,
      publicKey,
      output.manifestPayload,
    );
    expect(
      verifyIdentityRuntimeSnapshotManifestCoseSign1Ed25519(
        publicKey,
        output.manifestPayload,
        cose,
      ),
    ).toBe(true);
    expect(
      verifyIdentityAuthContextAssertionCoseSign1Ed25519(publicKey, output.manifestPayload, cose),
    ).toBe(false);
    const wrong = generateKeyPairSync('ed25519').publicKey.export({
      format: 'der',
      type: 'spki',
    });
    expect(
      verifyIdentityRuntimeSnapshotManifestCoseSign1Ed25519(wrong, output.manifestPayload, cose),
    ).toBe(false);
    const tampered = Buffer.from(output.manifestPayload);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
    expect(verifyIdentityRuntimeSnapshotManifestCoseSign1Ed25519(publicKey, tampered, cose)).toBe(
      false,
    );
  });
  it('keeps every actor across shard boundaries and rejects duplicate or mismatched authority', () => {
    const input = fixture();
    const actor = input.actors[0]!;
    const actors = Array.from({ length: 33 }, (_, i) => ({
      ...actor,
      projection: { ...actor.projection, actorKeyDigest: Buffer.alloc(32, i + 1) },
    }));
    const output = encodeIdentityRuntimeSnapshot({ ...input, actors: actors.toReversed() });
    expect(output.shards).toHaveLength(2);
    expect(encodeIdentityRuntimeSnapshot({ ...input, actors }).manifestPayload).toEqual(
      output.manifestPayload,
    );
    expect(() => encodeIdentityRuntimeSnapshot({ ...input, actors: [actor, actor] })).toThrow(
      'duplicate',
    );
    expect(() =>
      encodeIdentityRuntimeSnapshot({
        ...input,
        actors: [
          {
            ...actor,
            projection: { ...actor.projection, authorityVectorDigest: Buffer.alloc(32) },
          },
        ],
      }),
    ).toThrow('vector mismatch');
    expect(() => encodeIdentityRuntimeSnapshot({ ...input, hardExpiryNs: 1n })).toThrow();
    const entries = actor.authorityVector.entries.map((e, i) =>
      i === 5 ? { ...e, version: 1n } : e,
    );
    expect(() => encodeIdentityAuthorityVector({ ...actor.authorityVector, entries })).toThrow();
    expect(() =>
      encodeIdentityRuntimeAuthorityProfile({
        profileId: 'p',
        profileVersion: 1n,
        applicability: Array<0 | 1>(12).fill(0),
        profileClass: 1,
        signerId: 's',
      }),
    ).toThrow();
  });
});
