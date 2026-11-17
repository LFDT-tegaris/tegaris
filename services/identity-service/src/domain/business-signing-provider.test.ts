import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { evidenceKeyId } from '@openpc/security-kernel';
import {
  businessProviderDescriptorSchema,
  businessProviderObservationSchema,
  businessProviderRequestSchema,
  businessProviderPossessionPreimage,
  businessProviderRequestDigest,
  businessSigningPurpose,
  validateBusinessProviderObservation,
  type BusinessProviderDescriptor,
  type BusinessProviderObservation,
  type BusinessProviderRequest,
} from './business-signing-provider.js';

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const spki = publicKey.export({ format: 'der', type: 'spki' });
const descriptor: BusinessProviderDescriptor = {
  participantId: '01990000-0000-7000-8000-000000000001',
  privacyDomainId: '01990000-0000-7000-8000-000000000002',
  workloadCredentialId: '01990000-0000-7000-8000-000000000003',
  environmentId: 'local',
  secretClass: 'SECRET-SIGNING-KEY',
  purpose: businessSigningPurpose,
  reference: 'secret://local/control-evidence#1',
  version: '1',
  algorithm: 'ES256',
  publicKeySpkiHex: spki.toString('hex'),
  fingerprint: evidenceKeyId(spki),
  validFromNs: '1000',
  validUntilNs: '900000',
  state: 'ACTIVE',
  revokedAtNs: null,
  retiredAtNs: null,
};
const request: Extract<BusinessProviderRequest, { method: 'PROVE' }> = {
  participantId: descriptor.participantId,
  privacyDomainId: descriptor.privacyDomainId,
  workloadCredentialId: descriptor.workloadCredentialId,
  environmentId: descriptor.environmentId,
  secretClass: descriptor.secretClass,
  purpose: descriptor.purpose,
  reference: descriptor.reference,
  version: descriptor.version,
  callerWorkloadCredentialId: '01990000-0000-7000-8000-000000000004',
  attemptId: '01990000-0000-7000-8000-000000000005',
  operationId: '01990000-0000-7000-8000-000000000006',
  rotationId: '01990000-0000-7000-8000-000000000007',
  method: 'PROVE',
  expectedFingerprint: descriptor.fingerprint,
  challengeHex: '71'.repeat(32),
};
function observation(): BusinessProviderObservation {
  return {
    schemaVersion: 1,
    providerId: 'local-ephemeral-signing-provider-v1',
    attemptId: request.attemptId,
    operationId: request.operationId,
    requestDigest: businessProviderRequestDigest(request),
    method: 'PROVE',
    recordedAtNs: '2000',
    outcome: 'SUCCEEDED',
    reason: null,
    descriptor,
    resultHex: sign('sha256', businessProviderPossessionPreimage(request), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex'),
  };
}
describe('purpose-limited business signing provider boundary', () => {
  it('accepts actual possession proof from the exact provider key and separates caller from key owner', () => {
    expect(request.callerWorkloadCredentialId).not.toBe(descriptor.workloadCredentialId);
    expect(() => validateBusinessProviderObservation(request, observation())).not.toThrow();
  });
  it('binds the attempt, operation, exact ref, scope and actual challenge rather than an acknowledgement', () => {
    const valid = observation();
    for (const change of [
      { attemptId: request.operationId },
      { operationId: request.attemptId },
      { requestDigest: 'sha256:' + '00'.repeat(32) },
      { resultHex: null },
      { resultHex: '00'.repeat(64) },
      { descriptor: { ...descriptor, privacyDomainId: request.operationId } },
      { descriptor: { ...descriptor, state: 'REVOKED', revokedAtNs: '1000' } },
      { recordedAtNs: '900000' },
      { method: 'DISTRIBUTE' },
    ])
      expect(() =>
        validateBusinessProviderObservation(request, {
          ...valid,
          ...change,
        } as BusinessProviderObservation),
      ).toThrow();
    expect(() =>
      validateBusinessProviderObservation({ ...request, challengeHex: '72'.repeat(32) }, valid),
    ).toThrow();
  });
  it('rejects key injection, private material, wildcard purpose and inconsistent revocation history at ingress', () => {
    for (const change of [
      { privateKey: 'secret' },
      { purpose: '*' },
      { secretClass: 'SECRET-DB-CREDENTIAL' },
      { reference: 'secret://local/control-evidence#latest', version: 'latest' },
      { method: 'SIGN' },
      { publicKeySpkiHex: descriptor.publicKeySpkiHex },
    ])
      expect(businessProviderRequestSchema.safeParse({ ...request, ...change }).success).toBe(
        false,
      );
    for (const change of [
      { fingerprint: 'sha256:' + '00'.repeat(32) },
      { algorithm: 'RS256' },
      { state: 'ACTIVE', revokedAtNs: '2000' },
      { state: 'REVOKED' },
      { state: 'RETIRED', revokedAtNs: '2000', retiredAtNs: '1000' },
      { validUntilNs: '1000' },
      { privateKeyPkcs8: 'secret' },
    ])
      expect(businessProviderDescriptorSchema.safeParse({ ...descriptor, ...change }).success).toBe(
        false,
      );
    expect(
      businessProviderObservationSchema.safeParse({ ...observation(), privateKey: 'secret' })
        .success,
    ).toBe(false);
  });
});
