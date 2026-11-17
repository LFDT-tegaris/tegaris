import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationVerificationReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from './digest.js';
import {
  verifyInstalledNotificationChannel,
  type NotificationGatewayTransportV1,
} from '../notifications/gateway-contracts.js';
import {
  verifyInstalledNotificationVerification,
  createNotificationVerificationChallenge,
  notificationVerificationWire,
  parseNotificationVerificationRequest,
  verifyNotificationVerificationResponse,
} from './notification-verification-contract.js';
import type { NotificationChannelCredential } from '../notifications/endpoint-owner-contract.js';

const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const urn = (n: number) => `urn:openpc:resource:${id(n)}`;
const hash = (n: number) => `sha256:${String(n).repeat(64)}`;
const key = () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: pair.publicKey.export({ format: 'der', type: 'spki' }),
  };
};
function fixture() {
  const issuer = key(),
    signer = key();
  const scope = { environmentId: 'test', participantId: id(1), privacyDomainId: id(2) };
  const transport: NotificationGatewayTransportV1 = {
    protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
    channel: 'WEBHOOK',
    destinationRef: urn(3),
    credentialRef: urn(4),
    endpoint: 'https://gateway.test/',
    addresses: ['127.0.0.1'],
    serverSpkiDigest: hash(1),
    requestTimeoutMs: 1000,
    maxPayloadBytes: 1024,
  };
  const channelBytes = signNotificationClaim(
    'NotificationChannelProfileV1',
    issuer.privateKey,
    issuer.spki,
    {
      ...scope,
      profileId: id(5),
      revision: '1',
      validFromMs: 1000,
      validUntilMs: 10000,
      transportProfileDigest: sha256(transport),
      receiptSignerSpki: signer.spki.toString('hex'),
      issuerKeyId: evidenceKeyId(issuer.spki),
    },
  );
  const signedChannel = {
    transport,
    payloadHex: channelBytes.payload.toString('hex'),
    coseHex: channelBytes.cose.toString('hex'),
  };
  const channelTrust = {
    ...scope,
    signedProfileDigest: sha256(channelBytes.cose),
    issuerSpkiHex: issuer.spki.toString('hex'),
  };
  const channel = verifyInstalledNotificationChannel(channelTrust, signedChannel);
  const credential: NotificationChannelCredential = {
    participantId: id(1),
    privacyDomainId: id(2),
    credentialRef: urn(4),
    channel: 'WEBHOOK',
    destinationRef: urn(3),
    secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
    owner: 'LS-NOTIFICATION',
    reference: 'secret://local/notification-mtls#1',
    version: '1',
    fingerprint: hash(2),
    epoch: '1',
    validFromMs: 1000,
    validUntilMs: 10000,
    state: 'ACTIVE',
  };
  const profile = {
    ...scope,
    profileId: id(6),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 10000,
    signedChannelProfileDigest: channel.signedProfileDigest,
    credentialBindingDigest: sha256(credential),
    verificationSignerSpki: signer.spki.toString('hex'),
    issuerKeyId: evidenceKeyId(issuer.spki),
  };
  const profileBytes = signNotificationClaim(
    'NotificationVerificationProfileV1',
    issuer.privateKey,
    issuer.spki,
    profile,
  );
  const signed = {
    payloadHex: profileBytes.payload.toString('hex'),
    coseHex: profileBytes.cose.toString('hex'),
  };
  const trust = {
    ...scope,
    signedProfileDigest: sha256(profileBytes.cose),
    issuerSpkiHex: issuer.spki.toString('hex'),
  };
  const installed = verifyInstalledNotificationVerification(
    trust,
    signed,
    channelTrust,
    signedChannel,
  );
  const intent = {
    predecessor: {
      participantId: id(1),
      privacyDomainId: id(2),
      endpointId: id(7),
      revision: '1',
      channel: transport.channel,
      destinationRef: urn(3),
      credentialRef: urn(4),
      channelProfileDigest: channel.signedProfileDigest,
    },
    credential,
    principalId: id(8),
    inputDigest: hash(3),
    businessIdempotencyDigest: hash(4),
  };
  const challenge = createNotificationVerificationChallenge(installed, intent, 2000);
  const claims: NotificationVerificationReceiptClaims = {
    ...scope,
    receiptId: id(9),
    signedVerificationProfileDigest: installed.signedProfileDigest,
    challengeDigest: sha256(challenge),
    outcome: 'PROVED',
    observedAtMs: 2100,
    validUntilMs: 3000,
    signerKeyId: evidenceKeyId(signer.spki),
  };
  const response = (
    change: Partial<NotificationVerificationReceiptClaims> = {},
    signing = signer,
  ) => {
    const bytes = signNotificationClaim(
      'NotificationVerificationReceiptV1',
      signing.privateKey,
      signing.spki,
      { ...claims, ...change, signerKeyId: evidenceKeyId(signing.spki) },
    );
    return Buffer.from(
      canonicalJson({
        payloadHex: bytes.payload.toString('hex'),
        coseHex: bytes.cose.toString('hex'),
      }),
    );
  };
  return {
    installed,
    trust,
    signed,
    channelTrust,
    signedChannel,
    intent,
    challenge,
    claims,
    response,
    issuer,
    signer,
  };
}
it('authenticates the exact distinct non-delivery profile and challenge without granting execution', () => {
  const f = fixture();
  expect(
    parseNotificationVerificationRequest(
      notificationVerificationWire(f.installed, f.challenge, 2100),
    ),
  ).toEqual(f.challenge);
  const observed = verifyNotificationVerificationResponse(
    f.installed,
    f.challenge,
    f.response(),
    2200,
  );
  expect(observed.claims).toEqual(f.claims);
  expect(observed).not.toHaveProperty('operationId');
  const second = createNotificationVerificationChallenge(f.installed, f.intent, 2000);
  expect(second.nonce).not.toBe(f.challenge.nonce);
  expect(second.challengeId).not.toBe(f.challenge.challengeId);
  expect(
    verifyNotificationVerificationResponse(
      f.installed,
      f.challenge,
      f.response({ outcome: 'REJECTED' }),
      2200,
    ).claims.outcome,
  ).toBe('REJECTED');
});
it('rejects cross-purpose, wrong-signer, changed scope, expired or mismatched observations', () => {
  const f = fixture();
  for (const change of [
    { participantId: id(99) },
    { privacyDomainId: id(99) },
    { challengeDigest: hash(9) },
    { signedVerificationProfileDigest: hash(9) },
    { observedAtMs: 1999 },
    { observedAtMs: 2201 },
    { validUntilMs: 3001 },
    { validUntilMs: 2200 },
  ])
    expect(() =>
      verifyNotificationVerificationResponse(f.installed, f.challenge, f.response(change), 2200),
    ).toThrow();
  expect(() =>
    verifyNotificationVerificationResponse(
      f.installed,
      f.challenge,
      f.response({}, f.issuer),
      2200,
    ),
  ).toThrow();
  expect(() =>
    verifyNotificationVerificationResponse(f.installed, f.challenge, f.response(), 3000),
  ).toThrow();
  expect(() =>
    verifyNotificationVerificationResponse(
      f.installed,
      f.challenge,
      Buffer.from(canonicalJson(f.signed)),
      2200,
    ),
  ).toThrow();
});
it('binds current exact credential, original intent, predecessor and result revision', () => {
  const f = fixture();
  for (const change of [
    { predecessor: { ...f.intent.predecessor, destinationRef: urn(99) } },
    { credential: { ...f.intent.credential, epoch: '2' } },
    { credential: { ...f.intent.credential, state: 'REVOKED' as const } },
  ])
    expect(() =>
      createNotificationVerificationChallenge(f.installed, { ...f.intent, ...change }, 2000),
    ).toThrow();
  for (const change of [
    { nonce: '11'.repeat(32) },
    { principalId: id(99) },
    { inputDigest: hash(9) },
    { businessIdempotencyDigest: hash(9) },
    { predecessor: { ...f.challenge.predecessor, revision: '2' }, resultRevision: '3' },
  ])
    expect(() =>
      verifyNotificationVerificationResponse(
        f.installed,
        { ...f.challenge, ...change },
        f.response(),
        2200,
      ),
    ).toThrow();
  expect(() =>
    verifyInstalledNotificationVerification(
      { ...f.trust, signedProfileDigest: hash(9) },
      f.signed,
      f.channelTrust,
      f.signedChannel,
    ),
  ).toThrow();
});
it('rejects duplicate/unknown members, noncanonical JSON and oversized responses', () => {
  const f = fixture(),
    request = notificationVerificationWire(f.installed, f.challenge, 2200);
  expect(() =>
    parseNotificationVerificationRequest(Buffer.from(' ' + request.toString())),
  ).toThrow();
  expect(() =>
    parseNotificationVerificationRequest(
      Buffer.from(request.toString().replace('{', '{"challenge":{},')),
    ),
  ).toThrow();
  const response = f.response();
  expect(() =>
    verifyNotificationVerificationResponse(
      f.installed,
      f.challenge,
      Buffer.from(response.toString().replace('{', '{"unknown":1,')),
      2200,
    ),
  ).toThrow();
  expect(() =>
    verifyNotificationVerificationResponse(f.installed, f.challenge, Buffer.alloc(270337), 2200),
  ).toThrow();
});
