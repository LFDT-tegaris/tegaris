import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { evidenceKeyId } from '../business-transition/cose.js';
import { encodeIdentityAuthorityEnvelope } from './codec.js';
import { identityEnvelopeFixture, envelopeFixtureId as id } from './fixture.js';
import {
  assertIdentityEnvelopeSigningTrust,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
  type IdentityEnvelopeSigningTrust,
} from './signing-trust.js';

const spki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
  format: 'der',
  type: 'spki',
});
function fixture() {
  const artifact = identityEnvelopeFixture(evidenceKeyId(spki));
  const trust: IdentityEnvelopeSigningTrust = {
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'test',
    signerId: evidenceKeyId(spki),
    publicKeySpkiDer: spki,
    workloadCredentialId: id(221),
    workloadCredentialEpoch: 11n,
    workloadParticipantEpoch: 2n,
    workloadPrincipalEpoch: 1n,
    keyEpoch: 1n,
    validFromNs: 1800000000000000000n,
    validUntilNs: 1800003600000000000n,
    admissionKind: 'BOOTSTRAP',
    admissionReference: 'independent-initial-trust',
    admissionDigest: Buffer.alloc(32, 1),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://local/identity-envelope#version-1',
    secretVersion: 'version-1',
    purpose: 'pc.cose.identity-authority-envelope.v1',
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
  };
  artifact.signer.profileId = trust.profileId;
  artifact.signer.profileDigest = trust.profileDigest;
  artifact.signer.trustContextDigest = identityEnvelopeSigningTrustDigest(trust);
  return { trust, artifact, payload: encodeIdentityAuthorityEnvelope(artifact) };
}
describe('explicit envelope signing trust', () => {
  it('pins canonical371 metadata and exact artifact key/profile/environment/workload/time context', () => {
    const { trust, payload } = fixture();
    expect(() =>
      assertIdentityEnvelopeSigningTrust(payload, trust, 1800000001000000000n),
    ).not.toThrow();
    expect(
      identityEnvelopeSigningTrustPreimage(trust).includes(
        Buffer.from('pc.identity.authority-envelope-signing-trust.v1'),
      ),
    ).toBe(true);
    expect(() => assertIdentityEnvelopeSigningTrust(payload, trust, trust.validUntilNs)).toThrow();
    expect(() =>
      assertIdentityEnvelopeSigningTrust(payload, trust, trust.validFromNs - 1000n),
    ).toThrow();
    for (const change of [
      { environmentId: 'other' },
      { participantId: id(99) },
      { privacyDomainId: id(99) },
      { workloadCredentialEpoch: 12n },
      { workloadCredentialId: id(99) },
      { keyEpoch: 2n },
      { secretVersion: '2', secretReference: 'secret://local/identity-envelope#2' },
    ])
      expect(() =>
        assertIdentityEnvelopeSigningTrust(payload, { ...trust, ...change }, 1800000001000000000n),
      ).toThrow();
  });
  it('denies receipt-purpose substitution, caller profile selection and inherited grants', () => {
    const { trust } = fixture();
    for (const change of [
      { purpose: 'pc.cose.control-business-transition.v1' },
      { profileId: 'pc.control.envelope.v1' },
      { profileVersion: 2 },
      { profileDigest: `sha256:${'0'.repeat(64)}` },
      { grants: [] },
      { secretVersion: 'latest', secretReference: 'secret://local/identity-envelope#latest' },
    ])
      expect(() =>
        identityEnvelopeSigningTrustPreimage({
          ...trust,
          ...change,
        } as IdentityEnvelopeSigningTrust),
      ).toThrow();
    const absent = { ...trust };
    Reflect.deleteProperty(absent, 'purpose');
    expect(() => identityEnvelopeSigningTrustPreimage(absent)).toThrow();
  });
  it('rejects a mutated signed key version even when the canonical artifact remains structurally valid', () => {
    const { trust, artifact } = fixture();
    artifact.signer.keyVersion = 'other';
    expect(() =>
      assertIdentityEnvelopeSigningTrust(
        encodeIdentityAuthorityEnvelope(artifact),
        trust,
        1800000001000000000n,
      ),
    ).toThrow();
  });
});
