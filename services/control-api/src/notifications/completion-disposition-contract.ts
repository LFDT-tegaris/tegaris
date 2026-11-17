import { z } from 'zod';
import {
  decodeNotificationClaim,
  encodeNotificationClaim,
  verifyNotificationClaim,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { validateNotificationCompletionWorkerOriginal } from './completion-worker-installation-contract.js';
import {
  bindNotificationCompletionDispositionSignerWorker,
  validateNotificationCompletionDispositionSignerInstallation,
} from './completion-disposition-signer.js';

export class NotificationCompletionDispositionError extends Error {
  constructor() {
    super('Notification completion disposition unavailable');
  }
}
const hash = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const time = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
export const notificationCompletionSource = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  eventId: z.uuidv7(),
  envelopeDigest: hash,
  dataDigest: hash,
  partitionDigest: hash,
  receiptDigest: hash,
  producerTrustDigest: hash,
});
export const notificationCompletionAttempt = z
  .strictObject({
    attemptId: z.uuidv7(),
    number: z.number().int().min(1).max(1000),
    workerInstallationDigest: hash,
    authorityDigest: hash,
    claimedAtMs: time,
    leaseUntilMs: time,
    state: z.enum(['LEASED', 'RELEASED', 'FAILED', 'VALIDATED']),
    finishedAtMs: time.nullable(),
    nextAttemptAtMs: time.nullable(),
  })
  .superRefine((a, c) => {
    if (
      a.leaseUntilMs <= a.claimedAtMs ||
      a.leaseUntilMs - a.claimedAtMs > 30000 ||
      (a.state === 'LEASED'
        ? a.finishedAtMs !== null || a.nextAttemptAtMs !== null
        : a.finishedAtMs === null ||
          a.finishedAtMs < a.claimedAtMs ||
          (a.state === 'VALIDATED'
            ? a.nextAttemptAtMs !== null || a.finishedAtMs >= a.leaseUntilMs
            : a.nextAttemptAtMs === null || a.nextAttemptAtMs < a.finishedAtMs))
    )
      c.addIssue({ code: 'custom', message: 'Invalid completion attempt lifecycle' });
  });
export type NotificationCompletionAttempt = z.infer<typeof notificationCompletionAttempt>;
const journalInput = z.strictObject({
  source: notificationCompletionSource,
  initialWorker: z.unknown(),
  effectiveLimit: z.number().int().min(1).max(1000),
  attempts: z.array(notificationCompletionAttempt).min(1).max(1000),
});
/** Pure consistency only. The SQL owner authenticates source provenance and loads
 * every attempt. A caller-created valid chain is never processing/effect authority. */
export function validateNotificationCompletionJournal(value: unknown) {
  try {
    const j = journalInput.parse(immutableJsonCopy(value));
    const initial = validateNotificationCompletionWorkerOriginal(j.initialWorker),
      p = initial.profile;
    if (
      j.source.participantId !== p.participantId ||
      j.source.privacyDomainId !== p.privacyDomainId ||
      j.source.producerTrustDigest !== p.producerTrustDigest ||
      j.effectiveLimit > p.maximumAttempts ||
      j.attempts.length > p.maximumAttempts
    )
      throw new Error();
    for (let i = 0; i < j.attempts.length; i++) {
      const a = j.attempts[i]!,
        before = j.attempts[i - 1];
      if (
        a.number !== i + 1 ||
        (i === 0 &&
          (a.workerInstallationDigest !== initial.installationDigest ||
            a.claimedAtMs < p.validFromMs ||
            a.claimedAtMs >= p.validUntilMs)) ||
        (before &&
          (before.state === 'LEASED' ||
            before.state === 'VALIDATED' ||
            before.nextAttemptAtMs === null ||
            a.claimedAtMs < before.nextAttemptAtMs)) ||
        j.attempts.slice(0, i).some((x) => x.attemptId === a.attemptId)
      )
        throw new Error();
      if (a.state === 'FAILED' || a.state === 'RELEASED') {
        const delay = Math.min(
          p.maximumBackoffMs,
          p.initialBackoffMs * 2 ** Math.min(a.number - 1, 52),
        );
        if (a.nextAttemptAtMs !== a.finishedAtMs! + delay) throw new Error();
      }
    }
    const result = immutableJsonCopy({ ...j, initialWorker: initial.input });
    return Object.freeze({
      journal: result,
      initial,
      attemptChainDigest: sha256({
        schema: 'pc.notification.completion-attempt-chain.v1',
        ...result,
      }),
    });
  } catch {
    throw new NotificationCompletionDispositionError();
  }
}
/** Replacement profiles may tighten capacity only. The initial signed backoff
 * stays in the journal; a new request ID cannot create another source budget. */
export function notificationCompletionRetryDecision(
  value: unknown,
  currentWorker: unknown,
  nowMs: number,
) {
  try {
    const v = validateNotificationCompletionJournal(value),
      current = validateNotificationCompletionWorkerOriginal(currentWorker);
    const p = current.profile,
      j = v.journal,
      last = j.attempts.at(-1)!;
    time.parse(nowMs);
    if (
      p.participantId !== j.source.participantId ||
      p.privacyDomainId !== j.source.privacyDomainId ||
      p.environmentId !== v.initial.profile.environmentId ||
      p.producerTrustDigest !== j.source.producerTrustDigest ||
      nowMs < p.validFromMs ||
      nowMs >= p.validUntilMs
    )
      throw new Error();
    const limit = Math.min(j.effectiveLimit, p.maximumAttempts);
    if (last.state === 'VALIDATED') return { state: 'VALIDATED' as const, limit };
    if (last.state === 'LEASED')
      return {
        state: nowMs < last.leaseUntilMs ? ('BUSY' as const) : ('EXPIRED_LEASE' as const),
        limit,
      };
    if (j.attempts.length >= limit)
      return {
        state: last.state === 'RELEASED' ? ('CAPACITY_EXHAUSTED' as const) : ('EXHAUSTED' as const),
        limit,
      };
    return {
      state: nowMs < last.nextAttemptAtMs! ? ('BACKOFF' as const) : ('READY' as const),
      limit,
    };
  } catch {
    throw new NotificationCompletionDispositionError();
  }
}
const metadata = z.strictObject({
  receiptId: z.uuidv7(),
  operationId: z.uuidv7(),
  authoritySnapshotDigest: hash,
  recordedAtMs: time,
  beforeStateDigest: hash,
  afterStateDigest: hash,
});
const input = z.strictObject({
  journal: journalInput,
  workerInstallation: z.unknown(),
  signerInstallation: z.unknown(),
  metadata,
  disposition: z.enum(['ADMITTED', 'QUARANTINED']),
  producerOutcome: z.enum(['DELIVERED', 'FAILED']).nullable(),
  producerWorkItemId: z.uuidv7().nullable(),
});
/** Receipt proposal; ADMITTED's outcome and work identity must be obtained from
 * readNotificationOutcomePublicationInTransaction, never supplied as admission. */
export function notificationCompletionDispositionClaims(value: unknown) {
  try {
    const i = input.parse(immutableJsonCopy(value)),
      v = validateNotificationCompletionJournal(i.journal),
      j = v.journal;
    const signer = validateNotificationCompletionDispositionSignerInstallation(
      i.signerInstallation,
    );
    const w = bindNotificationCompletionDispositionSignerWorker(
      signer,
      i.workerInstallation,
      i.metadata.recordedAtMs,
    );
    const d = notificationCompletionRetryDecision(j, w.input, i.metadata.recordedAtMs);
    const admitted = i.disposition === 'ADMITTED';
    if (
      i.metadata.receiptId === i.metadata.operationId ||
      [i.metadata.receiptId, i.metadata.operationId].includes(j.source.eventId) ||
      (admitted
        ? d.state !== 'VALIDATED' ||
          i.producerOutcome === null ||
          (i.producerOutcome === 'FAILED'
            ? i.producerWorkItemId !== j.source.eventId
            : i.producerWorkItemId !== null)
        : d.state !== 'EXHAUSTED' || i.producerOutcome !== null || i.producerWorkItemId !== null)
    )
      throw new Error();
    const before = {
      schema: 'pc.notification.completion-disposition-state.v1',
      journal: j,
      disposition: null,
    };
    const after = {
      ...before,
      disposition: i.disposition,
      receiptId: i.metadata.receiptId,
      operationId: i.metadata.operationId,
      workItemKind: admitted ? (i.producerWorkItemId ? 'DELIVERY_FAILURE' : 'NONE') : 'REMEDIATION',
      workItemId: i.producerWorkItemId ?? i.metadata.receiptId,
      cursorMode: admitted ? 'ADVANCE' : 'HOLD',
    };
    if (
      i.metadata.beforeStateDigest !== sha256(before) ||
      i.metadata.afterStateDigest !== sha256(after) ||
      i.metadata.recordedAtMs < j.attempts.at(-1)!.finishedAtMs!
    )
      throw new Error();
    const claims = {
      environmentId: w.profile.environmentId,
      participantId: j.source.participantId,
      privacyDomainId: j.source.privacyDomainId,
      ...i.metadata,
      sourceEventId: j.source.eventId,
      sourceEnvelopeDigest: j.source.envelopeDigest,
      sourceDataDigest: j.source.dataDigest,
      sourcePartitionDigest: j.source.partitionDigest,
      producerTrustDigest: j.source.producerTrustDigest,
      sourceReceiptDigest: j.source.receiptDigest,
      initialWorkerInstallationDigest: v.initial.installationDigest,
      initialWorkerProfileDigest: v.initial.input.pins.signedProfileDigest,
      workerInstallationDigest: w.installationDigest,
      workerProfileDigest: w.input.pins.signedProfileDigest,
      attemptChainDigest: v.attemptChainDigest,
      attemptCount: j.attempts.length,
      attemptLimit: d.limit,
      initialAttemptLimit: v.initial.profile.maximumAttempts,
      initialBackoffMs: v.initial.profile.initialBackoffMs,
      maximumBackoffMs: v.initial.profile.maximumBackoffMs,
      signerInstallationDigest: signer.digest,
      disposition: i.disposition,
      safeProblem: admitted ? ('NONE' as const) : ('PC-OPS-9001' as const),
      workItemKind: admitted
        ? i.producerOutcome === 'FAILED'
          ? ('DELIVERY_FAILURE' as const)
          : ('NONE' as const)
        : ('REMEDIATION' as const),
      workItemId: i.producerWorkItemId ?? i.metadata.receiptId,
      cursorMode: admitted ? ('ADVANCE' as const) : ('HOLD' as const),
      signerKeyId: signer.signerKeyId,
    };
    return decodeNotificationClaim(
      'NotificationCompletionDispositionReceiptV1',
      encodeNotificationClaim('NotificationCompletionDispositionReceiptV1', claims),
    );
  } catch {
    throw new NotificationCompletionDispositionError();
  }
}
export function validateNotificationCompletionDisposition(value: unknown) {
  try {
    const p = z
      .strictObject({
        schema: z.literal('pc.notification.completion-disposition.v1'),
        input,
        receipt: z.unknown(),
        payloadHex: z
          .string()
          .regex(/^(?:[0-9a-f]{2})+$/u)
          .max(131072),
        coseHex: z
          .string()
          .regex(/^(?:[0-9a-f]{2})+$/u)
          .max(262144),
      })
      .parse(immutableJsonCopy(value));
    const receipt = notificationCompletionDispositionClaims(p.input);
    const signer = validateNotificationCompletionDispositionSignerInstallation(
      p.input.signerInstallation,
    );
    const actual = verifyNotificationClaim(
      'NotificationCompletionDispositionReceiptV1',
      Buffer.from(signer.pins.publicKeySpkiHex, 'hex'),
      Buffer.from(p.payloadHex, 'hex'),
      Buffer.from(p.coseHex, 'hex'),
    );
    if (
      canonicalJson(receipt) !== canonicalJson(p.receipt) ||
      canonicalJson(receipt) !== canonicalJson(actual)
    )
      throw new Error();
    const result = immutableJsonCopy({ ...p, receipt });
    if (Buffer.byteLength(canonicalJson(result)) > 1048576) throw new Error();
    return result;
  } catch {
    throw new NotificationCompletionDispositionError();
  }
}
export function encodeNotificationCompletionDisposition(value: unknown) {
  const transition = validateNotificationCompletionDisposition(value),
    bytes = Buffer.from(canonicalJson(transition));
  return Object.freeze({
    transition,
    transitionDigest: sha256(bytes),
    get bytes() {
      return Buffer.from(bytes);
    },
    get payload() {
      return Buffer.from(transition.payloadHex, 'hex');
    },
    get cose() {
      return Buffer.from(transition.coseHex, 'hex');
    },
  });
}
export const notificationCompletionRemediationReason =
  'Notification completion could not be processed.';
/** Native immutable initial projection only. NONE's receiptId sentinel is never
 * returned as a WorkItem reference, and producer failure work is never recreated.
 * Current atomic admission and subsequent human transitions have separate owners. */
export function notificationCompletionDispositionEffects(value: unknown) {
  const encoded = encodeNotificationCompletionDisposition(value),
    t = encoded.transition,
    r = t.receipt;
  const worker = validateNotificationCompletionWorkerOriginal(t.input.workerInstallation);
  const remediation =
    r.disposition === 'QUARANTINED'
      ? immutableJsonCopy({
          participantId: r.participantId,
          privacyDomainId: r.privacyDomainId,
          workItemId: r.workItemId,
          kind: 'REMEDIATION' as const,
          state: 'OPEN' as const,
          resourceRef: `urn:openpc:resource:${r.sourceEventId}`,
          payloadDigest: sha256(encoded.payload),
          reason: notificationCompletionRemediationReason,
          createdByPrincipalId: worker.profile.principalId,
          assigneePrincipalId: null,
          claimedByPrincipalId: null,
          completedByPrincipalId: null,
          revision: '1' as const,
        })
      : null;
  return immutableJsonCopy({
    remediation,
    existingFailureWorkItemId: r.workItemKind === 'DELIVERY_FAILURE' ? r.workItemId : null,
    cursorMode: r.cursorMode,
  });
}
