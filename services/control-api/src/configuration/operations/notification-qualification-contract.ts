import { createPublicKey, verify } from 'node:crypto';
import { z } from 'zod';
import {
  qualificationCanonicalJson as canonical,
  qualificationDigest as digest,
} from '../../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import {
  decodeNotificationAsync,
  encodeNotificationAsync,
  type NotificationAsyncInputClaims,
  type NotificationAsyncCapacityClaims,
} from '../../../../../packages/security-kernel/src/operations-configuration/notification-async.js';
import { qualificationKeyPeerSchema } from '../../../../identity-service/src/domain/qualification-key-provider.js';

export { canonical, digest };
export const qualificationId = z.uuidv7();
export const qualificationHash = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const qualificationTime = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const positive = qualificationTime.positive();
const hex = (bytes: number) =>
  z
    .string()
    .regex(/^(?:[0-9a-f]{2})+$/u)
    .max(bytes * 2);
export const qualificationPeerSchema = qualificationKeyPeerSchema;
export type QualificationPeer = z.infer<typeof qualificationPeerSchema>;
export const qualificationSelectionSchema = z.strictObject({
  participantId: qualificationId,
  privacyDomainId: qualificationId,
  installationId: qualificationId,
});
export const qualificationRunSelectorSchema = qualificationSelectionSchema.extend({
  runId: qualificationId,
});
export type NotificationQualificationSelector = z.infer<typeof qualificationRunSelectorSchema>;
export type QualificationSelection = z.infer<typeof qualificationSelectionSchema>;
export const qualificationCases = [
  'POSITIVE',
  'DUPLICATE_REPLAY',
  'CRASH_LEASE',
  'POISON_QUARANTINE',
  'SATURATION_CANCEL',
] as const;
export const qualificationCaseSchema = z.enum(qualificationCases);
export type QualificationCase = z.infer<typeof qualificationCaseSchema>;
export const qualificationStatus = z.enum(['PASS', 'FAIL', 'BLOCKED', 'UNKNOWN']);
export class NotificationQualificationError extends Error {
  constructor(
    readonly code:
      | 'CONTEXT'
      | 'UNBOUND'
      | 'INPUT'
      | 'IMMUTABLE'
      | 'EXPIRED'
      | 'UNKNOWN'
      | 'INDEPENDENCE'
      | 'EVIDENCE',
  ) {
    super(`NOTIFICATION_QUALIFICATION_${code}`);
  }
}
export function reject(code: NotificationQualificationError['code'] = 'INPUT'): never {
  throw new NotificationQualificationError(code);
}
export function copy<T>(value: T): T {
  const json = canonical(value);
  if (Buffer.byteLength(json) > 16 * 1024 * 1024) return reject();
  return JSON.parse(json) as T;
}
export function document(value: unknown) {
  const body = copy(value),
    bytes = Buffer.from(canonical(body));
  return { body, bytes, digest: digest(bytes) };
}
export function inputClaims(value: unknown): NotificationAsyncInputClaims {
  return decodeNotificationAsync(
    'input',
    encodeNotificationAsync('input', copy(value) as NotificationAsyncInputClaims),
  );
}

/** Public installation pins only. Actual origin authorship is established by
 * a new authenticated publication and signed build-service original below. */
export const qualificationInstallationSchema = qualificationSelectionSchema
  .extend({
    schemaVersion: z.literal(1),
    environmentId: z.string().regex(/^[a-z][a-z0-9-]{2,31}$/u),
    operationsInstallationDigest: qualificationHash,
    rootPrincipalId: qualificationId,
    subjectAuthor: qualificationPeerSchema,
    harnessAuthor: qualificationPeerSchema,
    executor: qualificationPeerSchema,
    reviewer: qualificationPeerSchema,
    signer: qualificationPeerSchema,
    builder: z.strictObject({
      providerId: z.string().min(1).max(128),
      keyId: qualificationHash,
      publicKeySpkiHex: hex(91),
    }),
    subjectOriginId: qualificationId,
    harnessOriginId: qualificationId,
    executorDeploymentId: qualificationId,
    reviewerDeploymentId: qualificationId,
    storeIdentityDigest: qualificationHash,
    gatewayIdentityDigest: qualificationHash,
    capacityIssuer: z.strictObject({
      keyId: qualificationHash,
      epoch: z.string().regex(/^[1-9][0-9]{0,15}$/u),
    }),
    input: z.unknown(),
    maximumRunMs: positive.max(3600000),
    maximumSamples: positive.max(4096),
    maximumSources: positive.max(10000),
    maximumEvidenceBytes: positive.max(16777216),
    validFromMs: qualificationTime,
    validUntilMs: qualificationTime,
  })
  .superRefine((v, c) => {
    try {
      const input = inputClaims(v.input);
      if (
        v.validUntilMs <= v.validFromMs ||
        input.environmentId !== v.environmentId ||
        input.participantId !== v.participantId ||
        input.privacyDomainId !== v.privacyDomainId ||
        input.profile === 'production' ||
        input.storeProfileDigest !== v.storeIdentityDigest ||
        input.gatewayProfileDigest !== v.gatewayIdentityDigest ||
        input.validFromMs < v.validFromMs ||
        input.validUntilMs > v.validUntilMs
      )
        reject();
      const people = [v.executor, v.reviewer, v.signer];
      const authors = [v.subjectAuthor.principalId, v.harnessAuthor.principalId, v.rootPrincipalId];
      if (
        new Set(people.map((p) => p.principalId)).size !== people.length ||
        people.some((p) => authors.includes(p.principalId))
      )
        reject('INDEPENDENCE');
      if (
        ['credentialId', 'keyDigest', 'certificateDigest'].some(
          (k) => new Set(people.map((p) => p[k as keyof QualificationPeer])).size !== people.length,
        )
      )
        reject('INDEPENDENCE');
      const key = Buffer.from(v.builder.publicKeySpkiHex, 'hex');
      if (
        digest(key) !== v.builder.keyId ||
        createPublicKey({ key, type: 'spki', format: 'der' }).asymmetricKeyDetails?.namedCurve !==
          'prime256v1'
      )
        reject();
    } catch {
      c.addIssue({ code: 'custom', message: 'Invalid qualification installation or independence' });
    }
  });
export type QualificationInstallation = z.infer<typeof qualificationInstallationSchema>;

export const qualificationOriginRequestSchema = z.strictObject({
  schemaVersion: z.literal(1),
  mode: z.literal('NEW_AUTHENTICATED_ORIGIN'),
  originId: qualificationId,
  installationId: qualificationId,
  installationDigest: qualificationHash,
  participantId: qualificationId,
  privacyDomainId: qualificationId,
  environmentId: z.string(),
  kind: z.enum(['SUBJECT', 'HARNESS']),
  author: qualificationPeerSchema,
  operationId: qualificationId,
  sourceDigest: qualificationHash,
  buildDigest: qualificationHash,
  issuedAtMs: qualificationTime,
  deadlineAtMs: qualificationTime,
});
export type QualificationOriginRequest = z.infer<typeof qualificationOriginRequestSchema>;
export const qualificationOriginProofSchema = z.strictObject({
  schemaVersion: z.literal(1),
  originId: qualificationId,
  requestDigest: qualificationHash,
  signatureHex: z.string().regex(/^[0-9a-f]{128}$/u),
  retainedAtMs: qualificationTime,
  state: z.enum(['ORIGINAL_VERIFIED_WITHIN_WINDOW', 'HISTORICAL_ONLY']),
});

/** External build service signs the actual source/build originals and the
 * server-reserved authenticated author's nonce. This cannot attest old Git
 * labels. The service must validate the real build; only this external service
 * may be substituted in local acceptance. No receipt-signing capability here. */
export function verifyQualificationOrigin(
  request: QualificationOriginRequest,
  signatureHex: string,
  pins: QualificationInstallation,
) {
  const r = qualificationOriginRequestSchema.parse(copy(request));
  if (
    !/^[0-9a-f]{128}$/u.test(signatureHex) ||
    r.deadlineAtMs <= r.issuedAtMs ||
    r.installationId !== pins.installationId ||
    r.participantId !== pins.participantId ||
    r.privacyDomainId !== pins.privacyDomainId ||
    r.environmentId !== pins.environmentId ||
    r.installationDigest !== document(pins).digest ||
    canonical(r.author) !==
      canonical(r.kind === 'SUBJECT' ? pins.subjectAuthor : pins.harnessAuthor)
  )
    reject('EVIDENCE');
  if (
    r.originId !== (r.kind === 'SUBJECT' ? pins.subjectOriginId : pins.harnessOriginId) ||
    r.issuedAtMs < pins.validFromMs ||
    r.deadlineAtMs > pins.validUntilMs
  )
    reject('EVIDENCE');
  if (r.kind === 'SUBJECT') {
    const input = inputClaims(pins.input);
    if (r.sourceDigest !== input.sourceTreeDigest || r.buildDigest !== input.buildDigest)
      reject('EVIDENCE');
  }
  const bytes = Buffer.concat([
    Buffer.from('pc.external.notification-build-origin.v1\0'),
    Buffer.from(canonical(r)),
  ]);
  if (
    !verify(
      'sha256',
      bytes,
      {
        key: createPublicKey({
          key: Buffer.from(pins.builder.publicKeySpkiHex, 'hex'),
          format: 'der',
          type: 'spki',
        }),
        dsaEncoding: 'ieee-p1363',
      },
      Buffer.from(signatureHex, 'hex'),
    )
  )
    reject('EVIDENCE');
  return r;
}
export const qualificationRunRequestSchema = qualificationRunSelectorSchema.extend({
  schemaVersion: z.literal(1),
  purpose: z.literal('QUALIFICATION_RUN'),
  operationId: qualificationId,
  installationDigest: qualificationHash,
  subjectOriginDigest: qualificationHash,
  harnessOriginDigest: qualificationHash,
  inputPayloadHex: hex(65536),
  inputPayloadDigest: qualificationHash,
  executor: qualificationPeerSchema,
  reservedAtMs: qualificationTime,
  deadlineAtMs: qualificationTime,
});
export type QualificationRunRequest = z.infer<typeof qualificationRunRequestSchema>;
export const qualificationRecordKinds = [
  'INPUT',
  'DISPATCH',
  'SOURCE',
  'SAMPLE',
  'CASE',
  'RAW',
  'OUTCOMES',
  'RESULT',
  'NORMALIZED',
  'REVIEW',
  'CAPACITY',
] as const;
export type QualificationRecordKind = (typeof qualificationRecordKinds)[number];
export const qualificationRecordSchema = z.strictObject({
  schemaVersion: z.literal(1),
  runId: qualificationId,
  kind: z.enum(qualificationRecordKinds),
  key: z.string().min(1).max(128),
  operationId: qualificationId,
  recordedAtMs: qualificationTime,
  value: z.unknown(),
});
export type QualificationRecord = z.infer<typeof qualificationRecordSchema>;
export const qualificationCaseResultSchema = z.strictObject({
  caseId: qualificationCaseSchema,
  status: qualificationStatus,
  reason: z.enum(['COMPLETE', 'ASSERTION_FAILED', 'PREREQUISITE', 'INTERRUPTED']),
  sourceEventIds: z.array(qualificationId).max(10000),
});
export const qualificationSampleSchema = z.strictObject({
  atMs: qualificationTime,
  sourceEventIds: z.array(qualificationId).max(10000),
  activeLeases: qualificationTime,
  batchSize: qualificationTime,
  queueItems: qualificationTime,
  queueBytes: qualificationTime,
  maximumPayloadBytes: qualificationTime,
  maximumQueueAgeMs: qualificationTime,
  dispatched: qualificationTime,
});
export type QualificationSample = z.infer<typeof qualificationSampleSchema>;
export const qualificationMeasurementsSchema = z.strictObject({
  measuredConcurrency: positive,
  measuredBatchSize: positive,
  measuredQueueItems: positive,
  measuredQueueBytes: positive,
  measuredMaximumPayloadBytes: positive,
  measuredDispatchRatePerSecond: positive,
  observedMaximumQueueAgeMs: qualificationTime,
  observedMaximumAttemptDurationMs: qualificationTime,
});
export const qualificationOutcomeSchema = z.strictObject({
  eventId: qualificationId,
  attemptId: qualificationId,
  operationId: qualificationId,
  publishedAtMs: qualificationTime,
  startedAtMs: qualificationTime,
  completedAtMs: qualificationTime,
  startPayloadHex: hex(1048576),
  startCoseHex: hex(1049600),
  outcomePayloadHex: hex(1048576),
  outcomeCoseHex: hex(1049600),
  transitionHex: hex(2097152),
  transitionDigest: qualificationHash,
});
export type QualificationOutcome = z.infer<typeof qualificationOutcomeSchema>;
export const qualificationNormalizedSchema = z.strictObject({
  schemaVersion: z.literal(1),
  runId: qualificationId,
  rawEvidenceDigest: qualificationHash,
  originalSignedOutcomesDigest: qualificationHash,
  status: qualificationStatus,
  runStartedAtMs: qualificationTime,
  runCompletedAtMs: qualificationTime,
  measurements: qualificationMeasurementsSchema.nullable(),
  cases: z.array(qualificationCaseResultSchema).length(5),
  limitations: z
    .array(
      z.enum(['ISOLATED_LOCAL_PROFILE', 'SAMPLED_LOWER_BOUND_CAPACITY', 'NO_PRODUCTION_PROMOTION']),
    )
    .length(3),
});
export type QualificationNormalized = z.infer<typeof qualificationNormalizedSchema>;
export const qualificationReviewSchema = z.strictObject({
  schemaVersion: z.literal(1),
  runId: qualificationId,
  reviewer: qualificationPeerSchema,
  normalizedResultsDigest: qualificationHash,
  rawEvidenceDigest: qualificationHash,
  originalSignedOutcomesDigest: qualificationHash,
  subjectOriginDigest: qualificationHash,
  harnessOriginDigest: qualificationHash,
  decision: z.enum(['ACCEPTED', 'REJECTED']),
  reviewedAtMs: qualificationTime,
  claim: z.literal('ISOLATED_ASYNC_NOTIFICATION_CAPACITY_ONLY'),
});
export type QualificationReview = z.infer<typeof qualificationReviewSchema>;
export interface QualificationOriginal {
  request: QualificationRunRequest;
  records: readonly { record: QualificationRecord; bytes: Buffer; digest: string }[];
}
/** Stable canonical splice contract. Selection contains no capacity or admission
 * claims. The callback is database-only under the same authenticated client,
 * current installation/generation/run fences and actual signed369 original.
 * Ordinary EFFECTIVE/370 admission is never returned by this operation. */
export interface QualificationRunAdmission {
  readonly purpose: 'QUALIFICATION_RUN';
  readonly selector: NotificationQualificationSelector;
  readonly input: Readonly<NotificationAsyncInputClaims>;
  readonly deadlineAtMs: number;
  readonly storeIdentityDigest: string;
  readonly gatewayIdentityDigest: string;
  readonly harnessDigest: string;
}

/** Canonical native host owner must bracket actual executor/reviewer execution,
 * not replay a historical deployment observation. No default implementation is
 * provided. A selector/peer/pins object alone cannot construct this capability. */
export interface QualificationNativeExecutionOwner {
  withCurrentExecution<T>(
    client: import('pg').PoolClient,
    selector: NotificationQualificationSelector,
    capability: 'QUALIFICATION_RUN' | 'QUALIFICATION_REVIEW',
    socket: import('node:tls').TLSSocket,
    consume: (sameClient: import('pg').PoolClient) => Promise<T>,
  ): Promise<T>;
}

export type QualificationSigningFamily = 'input' | 'capacity';
export interface QualificationSigningSelector extends NotificationQualificationSelector {
  readonly family: QualificationSigningFamily;
}
export interface QualificationSignerTransport {
  /** Real current TLS transport and Identity result from the existing workload
   * owner. This structure is trusted composition, never request JSON. */
  readonly socket: import('node:tls').TLSSocket;
  readonly identity: import('../../../../identity-service/src/domain/identity-kernel.js').AuthenticatedWorkloadIdentity;
  readonly confirmCurrent: () => Promise<void>;
  readonly confirmAuthorities: import('../../../../identity-service/src/domain/workload-peer.js').ConfirmWorkloadAuthorities;
}
export interface QualificationSigningIssuer {
  readonly authorityId: string;
  readonly keyId: string;
  readonly epoch: string;
  readonly purpose:
    | 'pc.cose.operations-notification-async-input.v1'
    | 'pc.cose.operations-notification-async-capacity-receipt.v1';
}
export type QualificationCapacitySourceClaims = Omit<
  NotificationAsyncCapacityClaims,
  'receiptId' | 'issuedAtMs' | 'expiresAtMs' | 'keysetPayloadDigest' | 'revocationPayloadDigest'
>;
export type QualificationSigningIntent =
  | {
      readonly family: 'input';
      readonly selector: QualificationSigningSelector;
      readonly payload: Buffer;
      readonly sourceDigest: string;
      readonly issuer: QualificationSigningIssuer;
    }
  | {
      readonly family: 'capacity';
      readonly selector: QualificationSigningSelector;
      readonly claims: Readonly<QualificationCapacitySourceClaims>;
      readonly sourceDigest: string;
      readonly issuer: QualificationSigningIssuer;
    };
/** B's attempt is durable BEFORE provider I/O and its exact provider result is
 * durable BEFORE current A adoption. Losing current authority cannot erase B's
 * original or cause another signing request. This is not request-upload input. */
export type QualificationSignedOriginal =
  | {
      readonly family: 'input';
      readonly attemptId: string;
      readonly sourceDigest: string;
      readonly payload: Buffer;
      readonly cose: Buffer;
    }
  | {
      readonly family: 'capacity';
      readonly attemptId: string;
      readonly sourceDigest: string;
      readonly payload: Buffer;
      readonly cose: Buffer;
      readonly issuance: {
        readonly receiptId: string;
        readonly issuedAtMs: number;
        readonly expiresAtMs: number;
        readonly keysetPayloadDigest: string;
        readonly revocationPayloadDigest: string;
      };
    };
