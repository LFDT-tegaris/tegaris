import { isIP } from 'node:net';
import { z } from 'zod';
import {
  verifyNotificationClaim,
  type NotificationChannelProfileClaims,
  type NotificationDeliveryReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { digestSchema, openPcUrnSchema, uuidSchema } from '../configuration/resource-contracts.js';
import {
  assertAdapterCallContext,
  type AdapterCallContextV1,
} from '../contracts/privacy-explorer-adapter.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { notificationChannel, notificationRevision } from './endpoint-binding.js';

export type { AdapterCallContextV1 };
const time = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const hex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const resourceUrn = openPcUrnSchema.refine((value) => value.startsWith('urn:openpc:resource:'));
const scope = { participantId: uuidSchema, privacyDomainId: uuidSchema };
export const notificationGatewayPaths = Object.freeze({
  deliver: '/notifications/v1/deliver',
  readback: '/notifications/v1/readback',
});
/** Exact installed gateway transport. Channel/destination routing is gateway-side;
 * this is not permission to open an arbitrary webhook, SMTP or queue connection. */
export const notificationGatewayTransport = z.strictObject({
  protocol: z.literal('OPENPC_NOTIFICATION_GATEWAY_V1'),
  channel: notificationChannel,
  destinationRef: openPcUrnSchema,
  credentialRef: openPcUrnSchema,
  endpoint: z
    .url()
    .max(2048)
    .refine((value) => {
      const url = new URL(value);
      return (
        url.protocol === 'https:' &&
        !url.username &&
        !url.password &&
        !url.search &&
        !url.hash &&
        url.pathname === '/' &&
        value === `${url.origin}/`
      );
    }),
  addresses: z
    .array(
      z
        .string()
        .max(45)
        .refine((value) => !value.includes('%') && isIP(value) !== 0),
    )
    .min(1)
    .max(16)
    .refine((values) => values.every((value, index) => index === 0 || value > values[index - 1]!)),
  serverSpkiDigest: digestSchema,
  requestTimeoutMs: z.number().int().min(100).max(30000),
  maxPayloadBytes: z.number().int().min(1).max(65536),
});
export type NotificationGatewayTransportV1 = z.infer<typeof notificationGatewayTransport>;
export const notificationDeliveryAttemptBinding = z
  .strictObject({
    version: z.literal('NotificationDeliveryAttemptV1'),
    ...scope,
    notificationOccurrenceId: resourceUrn,
    endpointId: resourceUrn,
    endpointRevision: notificationRevision,
    channel: notificationChannel,
    destinationRef: openPcUrnSchema,
    credentialRef: openPcUrnSchema,
    channelProfileDigest: digestSchema,
    templateDigest: digestSchema,
    payloadDigest: digestSchema,
    payloadBytes: z.number().int().min(1).max(65536),
    attemptId: uuidSchema,
    attemptNumber: z.number().int().min(1).max(6),
    startedAtMs: time,
    deadlineAtMs: time,
  })
  .refine((value) => value.deadlineAtMs > value.startedAtMs);
export type NotificationDeliveryAttemptBinding = z.infer<typeof notificationDeliveryAttemptBinding>;
const payloadBase64 = z
  .string()
  .min(4)
  .max(87384)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u)
  .refine((value) => {
    const decoded = Buffer.from(value, 'base64');
    try {
      return decoded.toString('base64') === value;
    } finally {
      decoded.fill(0);
    }
  });
export const notificationDeliveryAttempt = z.strictObject({
  attempt: notificationDeliveryAttemptBinding,
  payloadBase64,
});
export type NotificationDeliveryAttemptV1 = z.infer<typeof notificationDeliveryAttempt>;
export const signedNotificationChannelProfile = z.strictObject({
  transport: notificationGatewayTransport,
  payloadHex: hex.max(131072),
  coseHex: hex.max(133120),
});
export type SignedNotificationChannelProfile = z.infer<typeof signedNotificationChannelProfile>;
const installedTrust = z.strictObject({
  environmentId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
  ...scope,
  signedProfileDigest: digestSchema,
  issuerSpkiHex: hex.length(182),
});
export type NotificationGatewayInstalledTrust = z.infer<typeof installedTrust>;
export interface InstalledNotificationChannel {
  readonly claims: Readonly<NotificationChannelProfileClaims>;
  readonly transport: NotificationGatewayTransportV1;
  readonly signedProfileDigest: string;
}
export const notificationSignedReceipt = z.strictObject({
  payloadHex: hex.max(131072),
  coseHex: hex.max(133120),
});
export type NotificationSignedReceipt = z.infer<typeof notificationSignedReceipt>;
export interface NotificationDeliveryReceiptV1 {
  readonly signed: NotificationSignedReceipt;
  readonly receiptDigest: string;
  readonly claims: Readonly<NotificationDeliveryReceiptClaims>;
}
export class NotificationGatewayError extends Error {
  constructor(readonly reason: 'CONTRACT' | 'AUTHORITY_EXPIRED' | 'CANCELLED' | 'AMBIGUOUS') {
    super(`Notification gateway ${reason}`);
  }
}
function contract<T>(read: () => T): T {
  try {
    return read();
  } catch {
    throw new NotificationGatewayError('CONTRACT');
  }
}
function parsed<T>(schema: z.ZodType<T>, value: unknown): T {
  return schema.parse(immutableJsonCopy(value));
}
/** Trust comes from the installer, never a request-supplied key. This authenticates
 * immutable profile bytes only; current Identity and business admission are separate. */
export function verifyInstalledNotificationChannel(
  trustValue: NotificationGatewayInstalledTrust,
  signedValue: SignedNotificationChannelProfile,
): InstalledNotificationChannel {
  return contract(() => {
    const trust = parsed(installedTrust, trustValue);
    const signed = parsed(signedNotificationChannelProfile, signedValue);
    const payload = Buffer.from(signed.payloadHex, 'hex'),
      cose = Buffer.from(signed.coseHex, 'hex');
    const claims = verifyNotificationClaim(
      'NotificationChannelProfileV1',
      Buffer.from(trust.issuerSpkiHex, 'hex'),
      payload,
      cose,
    );
    if (
      sha256(cose) !== trust.signedProfileDigest ||
      claims.environmentId !== trust.environmentId ||
      claims.participantId !== trust.participantId ||
      claims.privacyDomainId !== trust.privacyDomainId ||
      claims.transportProfileDigest !== sha256(signed.transport)
    )
      throw new Error();
    return immutableJsonCopy({
      claims,
      transport: signed.transport,
      signedProfileDigest: trust.signedProfileDigest,
    });
  });
}
/** Stable across attempt numbers; a new idempotency key cannot invent a new intent. */
export function notificationIdempotencyDigest(value: NotificationDeliveryAttemptBinding): string {
  return sha256({
    participantId: value.participantId,
    privacyDomainId: value.privacyDomainId,
    notificationOccurrenceId: value.notificationOccurrenceId,
    payloadDigest: value.payloadDigest,
  });
}
export function notificationScopeDigest(
  value: Pick<NotificationDeliveryAttemptBinding, 'participantId' | 'privacyDomainId'>,
): string {
  return sha256({ participantId: value.participantId, privacyDomainId: value.privacyDomainId });
}
/** Reuse the registered AdapterCallContextV1 and retain its complete original bytes
 * for reconciliation. Shape and digest consistency do not authorize an attempt. */
export function assertNotificationAttempt(
  original: InstalledNotificationChannel,
  value: NotificationDeliveryAttemptBinding,
  contextValue: AdapterCallContextV1,
) {
  return contract(() => {
    const attempt = parsed(notificationDeliveryAttemptBinding, value);
    const context = assertAdapterCallContext(immutableJsonCopy(contextValue));
    const p = original.claims,
      t = original.transport;
    if (
      attempt.participantId !== p.participantId ||
      attempt.privacyDomainId !== p.privacyDomainId ||
      attempt.channelProfileDigest !== original.signedProfileDigest ||
      context.profileDigest !== original.signedProfileDigest ||
      attempt.channel !== t.channel ||
      attempt.destinationRef !== t.destinationRef ||
      attempt.credentialRef !== t.credentialRef ||
      attempt.payloadBytes > t.maxPayloadBytes ||
      attempt.startedAtMs < p.validFromMs ||
      attempt.deadlineAtMs > p.validUntilMs ||
      attempt.deadlineAtMs - attempt.startedAtMs > t.requestTimeoutMs ||
      context.occurrenceId !==
        attempt.notificationOccurrenceId.slice('urn:openpc:resource:'.length) ||
      context.idempotencyDigest !== notificationIdempotencyDigest(attempt) ||
      context.scopeDigest !== notificationScopeDigest(attempt) ||
      Date.parse(context.deadlineAt) !== attempt.deadlineAtMs
    )
      throw new Error();
    return immutableJsonCopy({ attempt, context });
  });
}
/** The real owner must commit STARTED and retain its fence before INITIAL_SEND;
 * only RECONCILE is legal for an original STARTED/AMBIGUOUS attempt. No default or
 * in-memory attempt owner is provided. Readback never receives payload bytes. */
export interface NotificationGatewayWindow {
  readonly signal: AbortSignal;
  /** Remaining monotonic deadline supplied by the currently admitted owner. */
  readonly timeoutMs: number;
}
export function assertNotificationDispatch(
  current: InstalledNotificationChannel,
  original: InstalledNotificationChannel,
  attempt: NotificationDeliveryAttemptBinding,
  context: AdapterCallContextV1,
  mode: 'INITIAL_SEND' | 'RECONCILE',
  nowMs: number,
  window: NotificationGatewayWindow,
): number {
  assertNotificationAttempt(original, attempt, context);
  const p = current.claims,
    old = original.claims;
  if (
    !Number.isSafeInteger(nowMs) ||
    !Number.isSafeInteger(window.timeoutMs) ||
    window.timeoutMs <= 0 ||
    !['INITIAL_SEND', 'RECONCILE'].includes(mode) ||
    p.environmentId !== old.environmentId ||
    p.participantId !== old.participantId ||
    p.privacyDomainId !== old.privacyDomainId ||
    p.profileId !== old.profileId ||
    BigInt(p.revision) < BigInt(old.revision) ||
    p.transportProfileDigest !== old.transportProfileDigest ||
    p.receiptSignerSpki !== old.receiptSignerSpki ||
    (mode === 'INITIAL_SEND' && current.signedProfileDigest !== original.signedProfileDigest)
  )
    throw new NotificationGatewayError('CONTRACT');
  if (window.signal.aborted) throw new NotificationGatewayError('CANCELLED');
  const remaining = Math.min(
    window.timeoutMs,
    current.transport.requestTimeoutMs,
    p.validUntilMs - nowMs,
    mode === 'INITIAL_SEND' ? attempt.deadlineAtMs - nowMs : Number.MAX_SAFE_INTEGER,
  );
  if (nowMs < p.validFromMs || nowMs < attempt.startedAtMs || remaining <= 0)
    throw new NotificationGatewayError('AUTHORITY_EXPIRED');
  return remaining;
}
/** Canonical JSON rejects duplicate members and preserves exact wire digests.
 * The adapter must bound bytes while receiving, before calling this parser. */
export function parseNotificationReceiptWire(bytes: Buffer): NotificationSignedReceipt {
  return contract(() => {
    if (bytes.length > 270336) throw new Error();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const value = parsed(notificationSignedReceipt, JSON.parse(text));
    if (canonicalJson(value) !== text) throw new Error();
    return immutableJsonCopy(value);
  });
}
export function notificationDeliveryWire(
  original: InstalledNotificationChannel,
  value: NotificationDeliveryAttemptV1,
  context: AdapterCallContextV1,
): Buffer {
  const request = contract(() => parsed(notificationDeliveryAttempt, value));
  const checked = assertNotificationAttempt(original, request.attempt, context);
  const payload = Buffer.from(request.payloadBase64, 'base64');
  try {
    if (
      payload.length !== checked.attempt.payloadBytes ||
      sha256(payload) !== checked.attempt.payloadDigest
    )
      throw new NotificationGatewayError('CONTRACT');
    return Buffer.from(canonicalJson({ ...checked, payloadBase64: payload.toString('base64') }));
  } finally {
    // Only this decoded copy is owned here. Caller strings and native TLS/VM
    // copies cannot be erased by wiping a Buffer.
    payload.fill(0);
  }
}
export function notificationReadbackWire(
  original: InstalledNotificationChannel,
  attempt: NotificationDeliveryAttemptBinding,
  context: AdapterCallContextV1,
): Buffer {
  return Buffer.from(canonicalJson(assertNotificationAttempt(original, attempt, context)));
}
/** Authenticated observation only. The durable owner must retain these exact
 * signed bytes with state and outbox before exposing successful completion. */
export function verifyNotificationReceipt(
  original: InstalledNotificationChannel,
  attempt: NotificationDeliveryAttemptBinding,
  context: AdapterCallContextV1,
  value: NotificationSignedReceipt,
): NotificationDeliveryReceiptV1 {
  return contract(() => {
    const checked = assertNotificationAttempt(original, attempt, context);
    const signed = parsed(notificationSignedReceipt, value);
    const cose = Buffer.from(signed.coseHex, 'hex');
    const claims = verifyNotificationClaim(
      'NotificationDeliveryReceiptV1',
      Buffer.from(original.claims.receiptSignerSpki, 'hex'),
      Buffer.from(signed.payloadHex, 'hex'),
      cose,
    );
    if (
      claims.environmentId !== original.claims.environmentId ||
      claims.participantId !== attempt.participantId ||
      claims.privacyDomainId !== attempt.privacyDomainId ||
      claims.signedProfileDigest !== original.signedProfileDigest ||
      claims.attemptDigest !== sha256(checked.attempt) ||
      claims.contextDigest !== sha256(checked.context) ||
      claims.observedAtMs < attempt.startedAtMs
    )
      throw new Error();
    return immutableJsonCopy({ signed, claims, receiptDigest: sha256(cose) });
  });
}
/** Raw provider errors must be redacted internally; never treat an HTTP status,
 * unsigned ACK, timeout or abort as a definitive no-effect result. Implementations
 * use pinned mTLS, no redirects/proxies/retries, bounded reads and socket teardown. */
export interface NotificationGatewayAdapterV1 {
  // Construction must bind an owner-admitted NotificationGatewayWindow for this invocation.
  deliver(
    request: NotificationDeliveryAttemptV1,
    context: AdapterCallContextV1,
  ): Promise<NotificationDeliveryReceiptV1>;
  reconcile(
    attempt: NotificationDeliveryAttemptBinding,
    context: AdapterCallContextV1,
  ): Promise<NotificationDeliveryReceiptV1>;
}
