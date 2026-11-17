import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import {
  verifyNotificationClaim,
  type NotificationVerificationProfileClaims,
  type NotificationVerificationReceiptClaims,
} from '@openpc/security-kernel';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import { canonicalJson, sha256 } from './digest.js';
import { digestSchema, uuidSchema } from './resource-contracts.js';
import { notificationEndpointBinding } from '../notifications/endpoint-binding.js';
import {
  notificationChannelCredential,
  assertNotificationEndpointConstruction,
} from '../notifications/endpoint-owner-contract.js';
import {
  verifyInstalledNotificationChannel,
  notificationSignedReceipt,
  type NotificationGatewayInstalledTrust,
  type SignedNotificationChannelProfile,
  type InstalledNotificationChannel,
  type NotificationSignedReceipt,
} from '../notifications/gateway-contracts.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';

export const notificationVerificationPath = '/notifications/v1/verify';
export const notificationVerificationMaxWireBytes = 270336;
const time = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const hex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const trustSchema = z.strictObject({
  environmentId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
  participantId: uuidSchema,
  privacyDomainId: uuidSchema,
  signedProfileDigest: digestSchema,
  issuerSpkiHex: hex.length(182),
});
export type NotificationVerificationTrust = z.infer<typeof trustSchema>;
export interface InstalledNotificationVerification {
  readonly channel: InstalledNotificationChannel;
  readonly claims: Readonly<NotificationVerificationProfileClaims>;
  readonly signedProfileDigest: string;
}
const reject = (): never => {
  throw new Error('Notification verification rejected');
};

/** Immutable cryptographic installation, not current credential/export authority.
 * The current durable owner must independently admit every network invocation. */
export function verifyInstalledNotificationVerification(
  trustValue: NotificationVerificationTrust,
  signedValue: NotificationSignedReceipt,
  channelTrust: NotificationGatewayInstalledTrust,
  channelSigned: SignedNotificationChannelProfile,
): InstalledNotificationVerification {
  const trust = trustSchema.parse(immutableJsonCopy(trustValue));
  const signed = notificationSignedReceipt.parse(immutableJsonCopy(signedValue));
  const channel = verifyInstalledNotificationChannel(channelTrust, channelSigned);
  const payload = Buffer.from(signed.payloadHex, 'hex'),
    cose = Buffer.from(signed.coseHex, 'hex');
  const claims = verifyNotificationClaim(
    'NotificationVerificationProfileV1',
    Buffer.from(trust.issuerSpkiHex, 'hex'),
    payload,
    cose,
  );
  if (
    sha256(cose) !== trust.signedProfileDigest ||
    claims.environmentId !== trust.environmentId ||
    claims.participantId !== trust.participantId ||
    claims.privacyDomainId !== trust.privacyDomainId ||
    claims.environmentId !== channel.claims.environmentId ||
    claims.participantId !== channel.claims.participantId ||
    claims.privacyDomainId !== channel.claims.privacyDomainId ||
    claims.signedChannelProfileDigest !== channel.signedProfileDigest ||
    claims.validFromMs < channel.claims.validFromMs ||
    claims.validUntilMs > channel.claims.validUntilMs
  )
    reject();
  return immutableJsonCopy({ channel, claims, signedProfileDigest: trust.signedProfileDigest });
}

/** Private wire: complete exact intent and credential METADATA, never secret bytes.
 * Unknown members and duplicate/noncanonical wire encodings are rejected. */
export const notificationVerificationChallenge = z
  .strictObject({
    version: z.literal('NotificationVerificationChallengeV1'),
    challengeId: uuidSchema,
    nonce: hex.length(64),
    environmentId: trustSchema.shape.environmentId,
    predecessor: notificationEndpointBinding,
    resultRevision: notificationEndpointBinding.shape.revision,
    credential: notificationChannelCredential,
    signedVerificationProfileDigest: digestSchema,
    principalId: uuidSchema,
    inputDigest: digestSchema,
    businessIdempotencyDigest: digestSchema,
    issuedAtMs: time,
    expiresAtMs: time,
  })
  .refine(
    (v) =>
      BigInt(v.resultRevision) === BigInt(v.predecessor.revision) + 1n &&
      v.expiresAtMs > v.issuedAtMs,
  );
export type NotificationVerificationChallenge = z.infer<typeof notificationVerificationChallenge>;
export type NotificationVerificationIntent = Pick<
  NotificationVerificationChallenge,
  'predecessor' | 'credential' | 'principalId' | 'inputDigest' | 'businessIdempotencyDigest'
>;

export function assertNotificationVerificationChallenge(
  installed: InstalledNotificationVerification,
  value: unknown,
  nowMs: number,
): NotificationVerificationChallenge {
  const challenge = notificationVerificationChallenge.parse(immutableJsonCopy(value));
  const profile = installed.claims;
  if (
    !time.safeParse(nowMs).success ||
    nowMs < challenge.issuedAtMs ||
    nowMs >= challenge.expiresAtMs ||
    challenge.environmentId !== profile.environmentId ||
    challenge.predecessor.participantId !== profile.participantId ||
    challenge.predecessor.privacyDomainId !== profile.privacyDomainId ||
    challenge.predecessor.channelProfileDigest !== installed.channel.signedProfileDigest ||
    challenge.predecessor.channel !== installed.channel.transport.channel ||
    challenge.predecessor.destinationRef !== installed.channel.transport.destinationRef ||
    challenge.predecessor.credentialRef !== installed.channel.transport.credentialRef ||
    challenge.signedVerificationProfileDigest !== installed.signedProfileDigest ||
    sha256(challenge.credential) !== profile.credentialBindingDigest ||
    challenge.issuedAtMs < profile.validFromMs ||
    challenge.expiresAtMs > profile.validUntilMs ||
    challenge.expiresAtMs > challenge.credential.validUntilMs ||
    challenge.expiresAtMs - challenge.issuedAtMs > installed.channel.transport.requestTimeoutMs
  )
    reject();
  assertNotificationEndpointConstruction(
    challenge.predecessor,
    { binding: challenge.predecessor, credential: challenge.credential },
    nowMs,
  );
  return challenge;
}

/** Called by the durable owner under its current authority fence; creation alone
 * permits no network activity. Commit these original bytes before transport. */
export function createNotificationVerificationChallenge(
  installed: InstalledNotificationVerification,
  intent: NotificationVerificationIntent,
  nowMs: number,
): NotificationVerificationChallenge {
  return assertNotificationVerificationChallenge(
    installed,
    {
      ...immutableJsonCopy(intent),
      version: 'NotificationVerificationChallengeV1',
      challengeId: localOperationId(),
      nonce: randomBytes(32).toString('hex'),
      environmentId: installed.claims.environmentId,
      resultRevision: String(BigInt(intent.predecessor.revision) + 1n),
      signedVerificationProfileDigest: installed.signedProfileDigest,
      issuedAtMs: nowMs,
      expiresAtMs: Math.min(
        nowMs + installed.channel.transport.requestTimeoutMs,
        installed.claims.validUntilMs,
        intent.credential.validUntilMs,
      ),
    },
    nowMs,
  );
}

export function notificationVerificationWire(
  installed: InstalledNotificationVerification,
  value: NotificationVerificationChallenge,
  nowMs: number,
): Buffer {
  return Buffer.from(
    canonicalJson({ challenge: assertNotificationVerificationChallenge(installed, value, nowMs) }),
  );
}
export function parseNotificationVerificationRequest(
  bytes: Buffer,
): NotificationVerificationChallenge {
  if (bytes.length > 16384) reject();
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const value = z
    .strictObject({ challenge: notificationVerificationChallenge })
    .parse(JSON.parse(text));
  if (canonicalJson(value) !== text) reject();
  return immutableJsonCopy(value.challenge);
}
export interface AuthenticatedNotificationVerification {
  readonly signed: NotificationSignedReceipt;
  readonly claims: Readonly<NotificationVerificationReceiptClaims>;
  readonly receiptDigest: string;
}

/** Authenticates only the external non-delivery observation. The durable source
 * owner must retain the original bytes and enforce one-use atomic attachment. */
export function verifyNotificationVerificationResponse(
  installed: InstalledNotificationVerification,
  original: NotificationVerificationChallenge,
  bytes: Buffer,
  nowMs: number,
): AuthenticatedNotificationVerification {
  const challenge = assertNotificationVerificationChallenge(installed, original, nowMs);
  if (bytes.length > notificationVerificationMaxWireBytes) reject();
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const signed = notificationSignedReceipt.parse(JSON.parse(text));
  if (canonicalJson(signed) !== text) reject();
  const cose = Buffer.from(signed.coseHex, 'hex');
  const claims = verifyNotificationClaim(
    'NotificationVerificationReceiptV1',
    Buffer.from(installed.claims.verificationSignerSpki, 'hex'),
    Buffer.from(signed.payloadHex, 'hex'),
    cose,
  );
  if (
    claims.environmentId !== challenge.environmentId ||
    claims.participantId !== challenge.predecessor.participantId ||
    claims.privacyDomainId !== challenge.predecessor.privacyDomainId ||
    claims.signedVerificationProfileDigest !== installed.signedProfileDigest ||
    claims.challengeDigest !== sha256(challenge) ||
    claims.observedAtMs < challenge.issuedAtMs ||
    claims.observedAtMs > nowMs ||
    claims.validUntilMs > challenge.expiresAtMs ||
    claims.validUntilMs <= nowMs
  )
    reject();
  return immutableJsonCopy({ signed, claims, receiptDigest: sha256(cose) });
}
