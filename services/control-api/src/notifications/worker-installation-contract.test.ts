import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationWorkerProfileClaims,
} from '@openpc/security-kernel';
import { sha256 } from '../configuration/digest.js';
import { validateNotificationWorkerInstallation } from './worker-installation-contract.js';
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
function fixture() {
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = issuer.publicKey.export({ type: 'spki', format: 'der' });
  const claims: NotificationWorkerProfileClaims = {
    environmentId: 'local',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(3),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 2000,
    sourceId: id(4),
    serviceId: 'LS-NOTIFICATION',
    processRole: 'ROLE-NOTIFICATION-WORKER',
    subscriptionId: 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1',
    principalId: id(5),
    workloadCredentialId: id(6),
    workloadEpoch: '1',
    workloadId: 'urn:openpc:workload:test',
    producerTrustDigest: sha256('producer'),
    routingProfileDigest: sha256('route'),
    kmsInstallationDigest: sha256('kms'),
    receiptSignerSpki: signer.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
    issuerKeyId: evidenceKeyId(spki),
  };
  const signed = signNotificationClaim(
    'NotificationWorkerProfileV1',
    issuer.privateKey.export({ type: 'pkcs8', format: 'der' }),
    spki,
    claims,
  );
  const {
    environmentId,
    participantId,
    privacyDomainId,
    profileId,
    revision,
    serviceId,
    processRole,
    subscriptionId,
    principalId,
    workloadCredentialId,
    workloadEpoch,
    workloadId,
  } = claims;
  return {
    pins: {
      issuerSpkiHex: spki.toString('hex'),
      signedProfileDigest: sha256(signed.cose),
      environmentId,
      participantId,
      privacyDomainId,
      profileId,
      revision,
      serviceId,
      processRole,
      subscriptionId,
      principalId,
      workloadCredentialId,
      workloadEpoch,
      workloadId,
      workloadKeyDigest: sha256('independent-transport'),
    },
    signed: { payloadHex: signed.payload.toString('hex'), coseHex: signed.cose.toString('hex') },
    installationReference: 'initial-trust',
  };
}
it('retains immutable exact installed public trust independently of caller mutation', () => {
  const input = fixture(),
    valid = validateNotificationWorkerInstallation(input, 1500);
  input.pins.principalId = id(99);
  input.signed.payloadHex = '00';
  expect(valid.input.pins.principalId).toBe(id(5));
  expect(valid.installationDigest).toBe(sha256(valid.bytes));
  valid.bytes.fill(0);
  expect(valid.installationDigest).toBe(sha256(valid.bytes));
  expect(() => {
    valid.input.pins.principalId = id(99);
  }).toThrow();
  expect(() => {
    valid.input.signed.payloadHex = '00';
  }).toThrow();
  expect(Object.keys(valid).sort()).toEqual(['bytes', 'input', 'installationDigest', 'profile']);
});
it('denies untrusted descriptors, forged profiles, role substitutions and time boundaries', () => {
  const input = fixture();
  for (const changed of [
    { ...input, ready: true },
    { ...input, pins: { ...input.pins, principalId: id(99) } },
    { ...input, pins: { ...input.pins, processRole: 'ROLE-CONTROL-WORKER' } },
    { ...input, signed: { ...input.signed, coseHex: '00' } },
    {
      ...input,
      pins: {
        ...input.pins,
        workloadKeyDigest: sha256(Buffer.from(input.pins.issuerSpkiHex, 'hex')),
      },
    },
  ])
    expect(() => validateNotificationWorkerInstallation(changed, 1500)).toThrow(
      'Notification worker admission unavailable',
    );
  for (const clock of [999, 2000, NaN, Infinity])
    expect(() => validateNotificationWorkerInstallation(input, clock)).toThrow();
  let read = false;
  const accessor = { ...input };
  Object.defineProperty(accessor, 'pins', {
    get() {
      read = true;
      return input.pins;
    },
    enumerable: true,
  });
  expect(() => validateNotificationWorkerInstallation(accessor, 1500)).toThrow();
  expect(read).toBe(false);
});
