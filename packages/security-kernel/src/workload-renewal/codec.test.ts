import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeCbor, encodeCbor, type CborValue } from '../canonical-cbor.js';
import { renewalRequestFixture, renewalAuthorizationFixture } from './fixture.js';
import {
  encodeWorkloadRenewalRequest,
  decodeWorkloadRenewalRequest,
  encodeWorkloadRenewalPolicyAuthorization,
  decodeWorkloadRenewalPolicyAuthorization,
  workloadRenewalDigest,
} from './codec.js';
import { signWorkloadRenewalCose, verifyWorkloadRenewalCose } from './cose.js';

const keys = () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    spki: pair.publicKey.export({ format: 'der', type: 'spki' }),
    pkcs8: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
  };
};
describe('distinct canonical workload renewal proofs', () => {
  it('round-trips original request bytes without JSON ordering or raw key authority', () => {
    const value = renewalRequestFixture();
    const encoded = encodeWorkloadRenewalRequest(value);
    expect(decodeWorkloadRenewalRequest(encoded)).toEqual(value);
    expect(
      encodeWorkloadRenewalRequest(
        Object.fromEntries(Object.entries(value).reverse()) as typeof value,
      ),
    ).toEqual(encoded);
    expect(() =>
      encodeWorkloadRenewalRequest({ ...value, publicKey: Buffer.alloc(32) } as typeof value),
    ).toThrow();
    expect(() =>
      encodeWorkloadRenewalRequest({ ...value, approved: true } as typeof value),
    ).toThrow();
    const getter = { ...value };
    Object.defineProperty(getter, 'policyDigest', { get: () => value.policyDigest });
    expect(() => encodeWorkloadRenewalRequest(getter)).toThrow();
  });
  it.each([
    { profileId: 'pc.identity.authority-envelope.v1' },
    { profileVersion: '2' },
    { requestValidUntilNs: '1800000120000001000' },
    { requestValidUntilNs: '1800000000000000000' },
    { requestedCertificateNotBeforeNs: '1800000000000001000' },
    { requestedCertificateNotAfterNs: '1800086401000000000' },
    { predecessorGeneration: '0' },
    { expectedFamilyRevision: '013' },
    { instanceGeneration: '18446744073709551616' },
    { workloadId: 'urn:openpc:workload:foreign' },
    { policyDigest: 'sha256:ABCD' },
  ])('rejects invalid proof context or finite bounds %j', (patch) => {
    expect(() =>
      encodeWorkloadRenewalRequest({ ...renewalRequestFixture(), ...patch } as ReturnType<
        typeof renewalRequestFixture
      >),
    ).toThrow();
  });
  it('rejects extra/absent map fields, definition substitution, trailing bytes and noncanonical encodings', () => {
    const encoded = encodeWorkloadRenewalRequest(renewalRequestFixture());
    const map = decodeCbor(encoded) as Map<number, CborValue>;
    map.set(99, 1);
    expect(() => decodeWorkloadRenewalRequest(encodeCbor(map))).toThrow();
    map.delete(99);
    map.delete(21);
    expect(() => decodeWorkloadRenewalRequest(encodeCbor(map))).toThrow();
    expect(() =>
      decodeWorkloadRenewalRequest(Buffer.concat([encoded, Buffer.from([0])])),
    ).toThrow();
    for (const bytes of [
      Buffer.from('a100f6', 'hex'),
      Buffer.from('bf00ff', 'hex'),
      Buffer.from('a1180001', 'hex'),
    ])
      expect(() => decodeWorkloadRenewalRequest(bytes)).toThrow();
  });
  it('binds original policy/instance receipts, original request and current fence evidence into authorization', () => {
    const request = encodeWorkloadRenewalRequest(renewalRequestFixture());
    const value = renewalAuthorizationFixture(request);
    const encoded = encodeWorkloadRenewalPolicyAuthorization(value);
    expect(decodeWorkloadRenewalPolicyAuthorization(encoded)).toEqual(value);
    for (const field of [
      'policyGovernanceReceiptDigest',
      'instanceAdmissionReceiptDigest',
      'businessAncestorsDigest',
      'mTlsPeerFingerprint',
      'providerRequestDigest',
    ] as const)
      expect(
        workloadRenewalDigest(
          encodeWorkloadRenewalPolicyAuthorization({
            ...value,
            [field]: `sha256:${'f'.repeat(64)}`,
          }),
        ),
      ).not.toBe(workloadRenewalDigest(encoded));
    for (const changed of [
      { ...value, authorizationMode: 'HUMAN_APPROVED' },
      { ...value, requestDigest: `sha256:${'f'.repeat(64)}` },
      { ...value, validUntilNs: '1800000031000001000' },
      { ...value, validUntilNs: value.issuedAtNs },
      { ...value, attestationValidUntilNs: '1800000030000000000' },
      { ...value, operationId: value.credentialId },
      { ...value, signer: { ...value.signer, keyId: renewalRequestFixture().newKeyDigest } },
      {
        ...value,
        signer: { ...value.signer, participantId: '018f0000-0000-7000-8000-000000000099' },
      },
    ])
      expect(() => encodeWorkloadRenewalPolicyAuthorization(changed as typeof value)).toThrow();
  });
  it('authenticates fresh independent P256 keys, with exact purpose, payload and key binding', () => {
    const successor = keys(),
      identity = keys(),
      other = keys();
    const request = encodeWorkloadRenewalRequest(
      renewalRequestFixture(workloadRenewalDigest(successor.spki)),
    );
    const requestProof = signWorkloadRenewalCose(
      'REQUEST',
      successor.pkcs8,
      successor.spki,
      request,
    );
    expect(verifyWorkloadRenewalCose('REQUEST', successor.spki, request, requestProof)).toBe(true);
    const authorization = encodeWorkloadRenewalPolicyAuthorization(
      renewalAuthorizationFixture(request, workloadRenewalDigest(identity.spki)),
    );
    const authorizationProof = signWorkloadRenewalCose(
      'POLICY_AUTHORIZATION',
      identity.pkcs8,
      identity.spki,
      authorization,
    );
    expect(
      verifyWorkloadRenewalCose(
        'POLICY_AUTHORIZATION',
        identity.spki,
        authorization,
        authorizationProof,
      ),
    ).toBe(true);
    expect(
      verifyWorkloadRenewalCose('POLICY_AUTHORIZATION', successor.spki, request, requestProof),
    ).toBe(false);
    expect(
      verifyWorkloadRenewalCose('REQUEST', identity.spki, authorization, authorizationProof),
    ).toBe(false);
    expect(verifyWorkloadRenewalCose('REQUEST', other.spki, request, requestProof)).toBe(false);
    const tampered = Buffer.from(authorizationProof);
    tampered[tampered.length - 1]! ^= 1;
    expect(
      verifyWorkloadRenewalCose('POLICY_AUTHORIZATION', identity.spki, authorization, tampered),
    ).toBe(false);
    expect(
      verifyWorkloadRenewalCose(
        'REQUEST',
        successor.spki,
        request,
        Buffer.concat([requestProof, Buffer.from([0])]),
      ),
    ).toBe(false);
    expect(() =>
      signWorkloadRenewalCose('REQUEST', other.pkcs8, successor.spki, request),
    ).toThrow();
  });
});
