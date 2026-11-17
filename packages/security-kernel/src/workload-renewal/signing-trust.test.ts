import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeCbor } from '../canonical-cbor.js';
import {
  renewalSigningTrustFixture,
  renewalAuthorizationFixture,
  renewalRequestFixture,
} from './fixture.js';
import {
  encodeWorkloadRenewalRequest,
  encodeWorkloadRenewalPolicyAuthorization,
  workloadRenewalDigest,
} from './codec.js';
import {
  assertWorkloadRenewalSigningTrust,
  workloadRenewalSigningTrustDigest,
  workloadRenewalSigningTrustPreimage,
  type WorkloadRenewalSigningTrust,
} from './signing-trust.js';
const spki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
  format: 'der',
  type: 'spki',
});
const uuid = (id: string) => Buffer.from(id.replaceAll('-', ''), 'hex');
const hash = (value: string) => Buffer.from(value.slice(7), 'hex');
const trust = () => renewalSigningTrustFixture(spki);
function authorization(value = trust()) {
  const artifact = renewalAuthorizationFixture(
    encodeWorkloadRenewalRequest(renewalRequestFixture()),
    value.signerId,
  );
  return {
    ...artifact,
    signer: {
      ...artifact.signer,
      profileDigest: value.profileDigest,
      trustDigest: workloadRenewalSigningTrustDigest(value),
    },
  };
}
describe('exact stable purpose376 signing trust v2', () => {
  it('uses the reviewed ordered public preimage, separate from the frozen artifact version', () => {
    const t = trust();
    expect(decodeCbor(workloadRenewalSigningTrustPreimage(t))).toEqual([
      'pc.identity.workload-renewal-signing-trust.v2',
      uuid(t.participantId),
      uuid(t.privacyDomainId),
      t.environmentId,
      uuid(t.principalId),
      t.workloadId,
      uuid(t.familyId),
      2n,
      0n,
      2n,
      hash(t.signerId),
      spki,
      2n,
      t.validFromNs,
      t.validUntilNs,
      hash(t.providerQualificationDigest),
      t.admissionKind,
      t.admissionReference,
      hash(t.admissionDigest),
      t.secretClass,
      t.secretReference,
      t.secretVersion,
      24039n,
      1n,
      376n,
      hash('sha256:0d9bb7686dc932fc17b4ccfb8700f600b9a46e765cef61e93d68b8e1d7efc10d'),
      t.profileId,
      2n,
      hash(t.profileDigest),
      'POLICY_AUTHORIZED',
      'ACT-IDENTITY_RENEW_WORKLOAD_CREDENTIAL-V1',
      'ID-OP-WORKLOAD-RENEWAL-ADMIT',
    ]);
    expect(authorization().profileVersion).toBe('1');
    expect(workloadRenewalSigningTrustDigest(t)).toBe(
      workloadRenewalDigest(workloadRenewalSigningTrustPreimage(t)),
    );
    expect(
      workloadRenewalSigningTrustPreimage(
        Object.fromEntries(Object.entries(t).reverse()) as WorkloadRenewalSigningTrust,
      ),
    ).toEqual(workloadRenewalSigningTrustPreimage(t));
  });
  it('binds current credentials separately without replacing stable key or permission provenance', () => {
    const t = trust(),
      a = authorization(t),
      current = { credentialId: a.signer.credentialId, credentialEpoch: 3n },
      now = 1800000001000000000n;
    assertWorkloadRenewalSigningTrust(encodeWorkloadRenewalPolicyAuthorization(a), t, current, now);
    const successor = { credentialId: '018f0000-0000-7000-8000-000000000099', credentialEpoch: 4n };
    expect(() =>
      assertWorkloadRenewalSigningTrust(
        encodeWorkloadRenewalPolicyAuthorization(a),
        t,
        successor,
        now,
      ),
    ).toThrow();
    const renewed = {
      ...a,
      signer: { ...a.signer, credentialId: successor.credentialId, credentialEpoch: '4' },
    };
    assertWorkloadRenewalSigningTrust(
      encodeWorkloadRenewalPolicyAuthorization(renewed),
      t,
      successor,
      now,
    );
    expect(renewed.signer.trustDigest).toBe(a.signer.trustDigest);
  });
  it.each([
    { profileVersion: 1 },
    { profileDigest: `sha256:${'f'.repeat(64)}` },
    { familySecurityEpoch: -1n },
    { participantSecurityInvalidationEpoch: 18446744073709551616n },
    { keySecurityGeneration: 0n },
    { keyEpoch: 0n },
    { validUntilNs: 1800000000000000000n },
    { validFromNs: 1800000000000000001n },
    { environmentId: 'invalid space' },
    { workloadId: 'urn:openpc:workload:foreign' },
    { providerQualificationDigest: `sha256:${'F'.repeat(64)}` },
    { secretVersion: 'current', secretReference: 'secret://local/workload-renewal#current' },
    { secretVersion: '3' },
    { admissionReference: 'e\u0301' },
    { admissionReference: 'invalid\u0000' },
    { purpose: 'pc.cose.identity-authority-envelope.v1' },
  ])('rejects substituted profile, security anchor or custody %#', (patch) => {
    expect(() =>
      workloadRenewalSigningTrustPreimage({ ...trust(), ...patch } as WorkloadRenewalSigningTrust),
    ).toThrow();
  });
  it('rejects aliases, getters, transport/permission additions and an off-curve public point', () => {
    const t = trust();
    expect(() =>
      workloadRenewalSigningTrustPreimage({
        ...t,
        workloadCredentialId: authorization().signer.credentialId,
      } as WorkloadRenewalSigningTrust),
    ).toThrow();
    const accessor = { ...t };
    Object.defineProperty(accessor, 'keyEpoch', { get: () => 2n });
    expect(() => workloadRenewalSigningTrustPreimage(accessor)).toThrow();
    const invalid = Buffer.from(spki);
    invalid.fill(0, 27);
    expect(() =>
      workloadRenewalSigningTrustPreimage({
        ...t,
        publicKeySpkiDer: invalid,
        signerId: workloadRenewalDigest(invalid),
      }),
    ).toThrow();
  });
  it.each([
    'keyId',
    'keyEpoch',
    'profileDigest',
    'trustDigest',
    'environmentId',
    'workloadId',
    'credentialEpoch',
  ] as const)('rejects artifact signer substitution %s', (field) => {
    const t = trust(),
      a = authorization(t),
      current = { credentialId: a.signer.credentialId, credentialEpoch: 3n };
    const changed = {
      ...a,
      signer: {
        ...a.signer,
        [field]: field.endsWith('Epoch')
          ? '9'
          : field === 'environmentId'
            ? 'foreign'
            : field === 'workloadId'
              ? 'urn:openpc:workload:018f0000-0000-7000-8000-000000000098'
              : `sha256:${'f'.repeat(64)}`,
      },
    };
    expect(() =>
      assertWorkloadRenewalSigningTrust(
        encodeWorkloadRenewalPolicyAuthorization(changed),
        t,
        current,
        1800000001000000000n,
      ),
    ).toThrow();
  });
  it('rejects authority before issue, at artifact expiry, or outside the finite key interval', () => {
    const t = trust(),
      a = authorization(t),
      bytes = encodeWorkloadRenewalPolicyAuthorization(a),
      current = { credentialId: a.signer.credentialId, credentialEpoch: 3n };
    for (const now of [1800000000000000000n, BigInt(a.validUntilNs), t.validUntilNs])
      expect(() => assertWorkloadRenewalSigningTrust(bytes, t, current, now)).toThrow();
  });
});
