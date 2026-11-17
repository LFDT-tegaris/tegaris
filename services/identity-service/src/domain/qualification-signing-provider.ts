import {
  isExactSigningSecretReference,
  signingSecretReferencePattern,
} from '../../../../packages/security-kernel/src/business-transition/secret-reference.js';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  decodeNotificationAsync,
  verifyNotificationAsyncEnvelope,
  type NotificationAsyncFamily,
} from '../../../../packages/security-kernel/src/operations-configuration/notification-async.js';
import {
  qualificationCanonicalJson,
  qualificationDigest,
} from '../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import {
  qualificationKeyCopy,
  qualificationKeyInstallation,
  qualificationKeyPeerSchema,
  type QualificationKeyInstallation,
} from './qualification-key-provider.js';

export const qualificationSigningPurposes = Object.freeze({
  input: 'pc.cose.operations-notification-async-input.v1',
  capacity: 'pc.cose.operations-notification-async-capacity-receipt.v1',
} as const);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuid = z.uuidv7();
const epoch = z
  .string()
  .regex(/^[1-9][0-9]{0,15}$/u)
  .refine((v) => Number.isSafeInteger(Number(v)));
const time = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER)
  .refine((v) => !Object.is(v, -0));
const name = z.string().regex(/^[a-z][a-z0-9-]{2,31}$/u);
const hex = (maximum: number) =>
  z
    .string()
    .regex(/^(?:[0-9a-f]{2})+$/u)
    .max(maximum * 2);

/** Closed provider wire, not public caller input or a dispatch authorization.
 * Native owners select the payload and reserve this immutable original before I/O. */
export const qualificationSigningRequestSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    method: z.literal('SIGN'),
    family: z.enum(['input', 'capacity']),
    keyInstallationId: uuid,
    installationDigest: digest,
    qualificationInstallationId: uuid,
    participantId: uuid,
    privacyDomainId: uuid,
    environmentId: name,
    runId: uuid,
    sourceDigest: digest,
    authorityId: name,
    rootEpoch: epoch,
    keysetDigest: digest,
    revocationsDigest: digest,
    keyId: digest,
    keyEpoch: epoch,
    purpose: z.enum([qualificationSigningPurposes.input, qualificationSigningPurposes.capacity]),
    providerId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
    reference: z.string().regex(new RegExp(signingSecretReferencePattern, 'u')).max(331),
    version: z
      .string()
      .regex(/^[a-zA-Z0-9._-]{1,96}$/u)
      .refine((v) => !['latest', 'current'].includes(v.toLowerCase())),
    peer: qualificationKeyPeerSchema,
    observer: qualificationKeyPeerSchema,
    operationId: uuid,
    attemptId: uuid,
    issuedAtMs: time,
    deadlineAtMs: time,
    payloadHex: hex(65536),
    payloadDigest: digest,
  })
  .superRefine((r, c) => {
    try {
      if (
        r.purpose !== qualificationSigningPurposes[r.family] ||
        !isExactSigningSecretReference(r.reference, r.version) ||
        r.deadlineAtMs <= r.issuedAtMs ||
        r.deadlineAtMs - r.issuedAtMs > 10000 ||
        r.peer.participantEpoch !== r.observer.participantEpoch ||
        (
          ['principalId', 'credentialId', 'workloadId', 'keyDigest', 'certificateDigest'] as const
        ).some((k) => r.peer[k] === r.observer[k])
      )
        throw new Error();
      const payload = Buffer.from(r.payloadHex, 'hex');
      if (qualificationDigest(payload) !== r.payloadDigest) throw new Error();
      const claims = decodeNotificationAsync(r.family, payload);
      if (
        claims.participantId !== r.participantId ||
        claims.privacyDomainId !== r.privacyDomainId ||
        claims.environmentId !== r.environmentId ||
        claims.authorityId !== r.authorityId ||
        claims.issuerKeyId !== r.keyId ||
        claims.issuerEpoch !== r.keyEpoch
      )
        throw new Error();
      if (r.family === 'input') {
        const input = decodeNotificationAsync('input', payload);
        if (r.issuedAtMs < input.validFromMs || r.deadlineAtMs > input.validUntilMs)
          throw new Error();
      } else {
        const capacity = decodeNotificationAsync('capacity', payload);
        if (
          capacity.runId !== r.runId ||
          capacity.signerPrincipalId !== r.peer.principalId ||
          capacity.reviewerAttestationDigest !== r.sourceDigest ||
          capacity.issuedAtMs !== r.issuedAtMs ||
          capacity.expiresAtMs < r.deadlineAtMs ||
          capacity.keysetPayloadDigest !== r.keysetDigest ||
          capacity.revocationPayloadDigest !== r.revocationsDigest
        )
          throw new Error();
      }
    } catch {
      c.addIssue({ code: 'custom', message: 'Invalid qualification signing original' });
    }
  });
export type QualificationSigningRequest = z.infer<typeof qualificationSigningRequestSchema>;
export class QualificationSigningUnknown extends Error {
  readonly code = 'QUALIFICATION_SIGNING_UNKNOWN';
  constructor() {
    super('Qualification signing requires original reconciliation');
  }
}
const copy = qualificationKeyCopy;
function request(value: unknown): QualificationSigningRequest {
  return copy(qualificationSigningRequestSchema.parse(copy(value)));
}
function domainDigest(domain: string, value: unknown) {
  return (
    'sha256:' +
    createHash('sha256')
      .update(domain + '\0')
      .update(qualificationCanonicalJson(value))
      .digest('hex')
  );
}
export function qualificationSigningRequestDigest(value: QualificationSigningRequest) {
  return domainDigest('pc.qualification-signing-request.v1', request(value));
}
/** New operation/attempt/key-installation IDs do not create a new business intent. */
export function qualificationSigningIntentDigest(value: QualificationSigningRequest) {
  const r = request(value);
  return domainDigest('pc.qualification-signing-intent.v1', {
    participantId: r.participantId,
    privacyDomainId: r.privacyDomainId,
    runId: r.runId,
    family: r.family,
    sourceDigest: r.sourceDigest,
  });
}
export function qualificationSigningInstallation(value: unknown) {
  const installed = qualificationKeyInstallation(value);
  if (
    installed.pins.schemaVersion !== 2 ||
    !Object.values(qualificationSigningPurposes).some((p) => p === installed.pins.purpose)
  )
    throw new QualificationSigningUnknown();
  return Object.freeze({
    pins: installed.pins,
    digest: installed.digest,
    get bytes() {
      return installed.bytes;
    },
  });
}
export function validateQualificationSigningRequest(
  value: unknown,
  trust: QualificationKeyInstallation,
) {
  try {
    const r = request(value),
      installed = qualificationSigningInstallation(trust),
      p = installed.pins;
    if (
      r.keyInstallationId !== p.installationId ||
      r.installationDigest !== installed.digest ||
      (
        [
          'participantId',
          'privacyDomainId',
          'environmentId',
          'authorityId',
          'rootEpoch',
          'keyId',
          'keyEpoch',
          'purpose',
          'providerId',
          'reference',
          'version',
        ] as const
      ).some((k) => r[k] !== p[k]) ||
      qualificationCanonicalJson(r.peer) !== qualificationCanonicalJson(p.peer) ||
      qualificationCanonicalJson(r.observer) !== qualificationCanonicalJson(p.observer) ||
      r.issuedAtMs < p.validFromMs ||
      r.deadlineAtMs > p.validUntilMs
    )
      throw new Error();
    return r;
  } catch {
    throw new QualificationSigningUnknown();
  }
}

/** REJECTED is a retained provider statement, not permission to submit again. */
export const qualificationSigningObservationSchema = z.discriminatedUnion('outcome', [
  z.strictObject({
    schemaVersion: z.literal(1),
    attemptId: uuid,
    requestDigest: digest,
    observedAtMs: time,
    outcome: z.literal('SIGNED'),
    coseHex: hex(66560),
  }),
  z.strictObject({
    schemaVersion: z.literal(1),
    attemptId: uuid,
    requestDigest: digest,
    observedAtMs: time,
    outcome: z.literal('REJECTED'),
    reason: z.enum([
      'DENIED',
      'EXPIRED',
      'REVOKED',
      'KEY_UNAVAILABLE',
      'ATTEMPT_CONFLICT',
      'INTENT_CONFLICT',
    ]),
  }),
]);
export type QualificationSigningObservation = z.infer<typeof qualificationSigningObservationSchema>;
export function validateQualificationSigningObservation(
  original: QualificationSigningRequest,
  value: unknown,
  trust: QualificationKeyInstallation,
  first?: QualificationSigningObservation,
): QualificationSigningObservation {
  try {
    const installed = qualificationSigningInstallation(trust);
    const r = validateQualificationSigningRequest(original, installed.pins);
    const o = copy(qualificationSigningObservationSchema.parse(copy(value)));
    if (
      o.attemptId !== r.attemptId ||
      o.requestDigest !== qualificationSigningRequestDigest(r) ||
      o.observedAtMs < r.issuedAtMs ||
      (o.outcome === 'SIGNED' && o.observedAtMs >= r.deadlineAtMs) ||
      (first !== undefined && qualificationCanonicalJson(first) !== qualificationCanonicalJson(o))
    )
      throw new Error();
    if (o.outcome === 'SIGNED')
      verifyNotificationAsyncEnvelope(
        r.family,
        Buffer.from(installed.pins.publicKeySpkiHex, 'hex'),
        {
          payload: Buffer.from(r.payloadHex, 'hex'),
          cose: Buffer.from(o.coseHex, 'hex'),
        },
      );
    // No wall-clock/currentness test: an authentic historical original survives expiry/revocation.
    return o;
  } catch {
    throw new QualificationSigningUnknown();
  }
}
const lookupSchema = z.discriminatedUnion('state', [
  z.strictObject({
    schemaVersion: z.literal(1),
    state: z.literal('ABSENT'),
    attemptId: uuid,
    requestDigest: digest,
  }),
  z.strictObject({
    schemaVersion: z.literal(1),
    state: z.literal('RECORDED'),
    observation: qualificationSigningObservationSchema,
  }),
]);
export function validateQualificationSigningLookup(
  original: QualificationSigningRequest,
  value: unknown,
  trust: QualificationKeyInstallation,
  first?: QualificationSigningObservation,
) {
  try {
    const r = validateQualificationSigningRequest(original, trust);
    if (first !== undefined) validateQualificationSigningObservation(r, first, trust);
    const result = lookupSchema.parse(copy(value));
    if (result.state === 'ABSENT') {
      if (
        first !== undefined ||
        result.attemptId !== r.attemptId ||
        result.requestDigest !== qualificationSigningRequestDigest(r)
      )
        throw new Error();
      return undefined;
    }
    return validateQualificationSigningObservation(r, result.observation, trust, first);
  } catch {
    throw new QualificationSigningUnknown();
  }
}
export interface QualificationSigningProvider {
  /** Only a committed exclusive native dispatch claim permits this exchange. */
  perform(original: QualificationSigningRequest): Promise<QualificationSigningObservation>;
  /** Exact original only. ABSENT/timeout never authorizes re-signing. */
  lookup(
    original: QualificationSigningRequest,
    first?: QualificationSigningObservation,
  ): Promise<QualificationSigningObservation | undefined>;
  close(): void;
}
export type QualificationSigningFamily = NotificationAsyncFamily;
