import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { encodeNotificationClaim } from '@openpc/security-kernel';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import {
  withNotificationCompletionWorkerPeer,
  assertNotificationCompletionWorkerCurrent,
  admitNotificationCompletionDispositionPhase,
  admitNotificationCompletionDispositionReceipt,
  type NotificationCompletionWorkerAdmission,
} from '../../../identity-service/src/domain/notification-completion-worker.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { notificationCompletionWorkerSelector } from './completion-worker-installation.js';
import { validateNotificationCompletionWorkerOriginal } from './completion-worker-installation-contract.js';
import {
  notificationCompletionAttempt,
  notificationCompletionSource,
  notificationCompletionRetryDecision,
  validateNotificationCompletionJournal,
  notificationCompletionDispositionClaims,
  encodeNotificationCompletionDisposition,
  NotificationCompletionDispositionError,
  type NotificationCompletionAttempt,
} from './completion-disposition-contract.js';
import {
  validateNotificationCompletionDispositionSignerInstallation,
  withCurrentNotificationCompletionDispositionSigner,
} from './completion-disposition-signer.js';
import { validateNotificationDeliveryStartTransition } from './delivery-start-transition.js';
import {
  decodeNotificationDeliveryOutcomeTransition,
  NotificationDeliveryOutcomeError,
} from './delivery-outcome-contract.js';
import {
  notificationOutcomeSigningSelector,
  notificationOutcomeSigningTransition,
  readNotificationOutcomeSigningInTransaction,
} from './delivery-outcome-state.js';
import { readNotificationOutcomePublicationInTransaction } from './delivery-outcome-publication.js';
import { validateNotificationWorkerInstallation } from './worker-installation-contract.js';
import { validateNotificationOutcomeSignerInstallation } from './receipt-signer-installation.js';
import {
  createNotificationCompletionDispositionRequest,
  validateNotificationCompletionDispositionRequest,
  validateNotificationCompletionDispositionObservation,
} from '../../../identity-service/src/domain/notification-completion-disposition-provider.js';
import type { NotificationReceiptProviderObservation } from '../../../identity-service/src/domain/notification-receipt-provider.js';
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const notificationCompletionSelector = z.strictObject({
  worker: notificationCompletionWorkerSelector,
  eventId: z.uuidv7(),
});
export const notificationCompletionSigningSelector = z.strictObject({
  worker: notificationCompletionWorkerSelector,
  eventId: z.uuidv7(),
  operationId: z.uuidv7(),
});
export type NotificationCompletionSelector = z.infer<typeof notificationCompletionSelector>;
export type NotificationCompletionSigningSelector = z.infer<
  typeof notificationCompletionSigningSelector
>;
const args = (q: NotificationCompletionSelector) => [
  q.worker.participantId,
  q.worker.privacyDomainId,
  q.eventId,
];
export class NotificationCompletionDispositionUnknown extends Error {
  readonly selector: NotificationCompletionSelector;
  constructor(q: NotificationCompletionSelector) {
    super('Notification completion requires original readback');
    this.selector = immutableJsonCopy(
      notificationCompletionSelector.parse({ worker: q.worker, eventId: q.eventId }),
    );
  }
}
async function gate(
  client: PoolClient,
  a: NotificationCompletionWorkerAdmission,
  q: NotificationCompletionSelector,
  phase: 'SOURCE' | 'CLAIM' | 'LIMIT' | 'FINISH' | 'PREPARE' | 'SIGN_CLAIM' | 'OBSERVE' | 'PUBLISH',
) {
  await assertNotificationCompletionWorkerCurrent(a, client, q.worker);
  await admitNotificationCompletionDispositionPhase(a, client, q.worker, q.eventId, phase);
  // Mandatory canonical security boundary. Shared registration must implement
  // same-client native admission for each phase, not an action/GUC allow-list.
  // An absent function or grant is a hard failure, never a fallback authority.
  await client.query('select openpc.require_notification_completion_disposition_authority($1,$2)', [
    q.eventId,
    phase,
  ]);
}
async function lock(client: PoolClient, q: NotificationCompletionSelector) {
  const r = await client.query<{ allowed: boolean }>(
    "select pg_try_advisory_xact_lock(hashtextextended('notification-completion-source:'||$1::text||':'||$2::text||':'||$3::text,0)) allowed",
    args(q),
  );
  if (r.rows[0]?.allowed !== true) throw new NotificationCompletionDispositionError();
}
async function now(client: PoolClient) {
  const r = await client.query<{ now_ms: string }>(
    'select floor(extract(epoch from clock_timestamp())*1000)::text now_ms',
  );
  return z
    .number()
    .int()
    .nonnegative()
    .max(Number.MAX_SAFE_INTEGER)
    .parse(Number(r.rows[0]?.now_ms));
}
/** Original producer authentication is intentionally separate from event semantic
 * validation. A poisoned event's exact retained bytes can consume finite retries,
 * but a foreign, forged, absent or unlinked producer cannot enter this journal. */
async function originalSource(
  client: PoolClient,
  a: NotificationCompletionWorkerAdmission,
  q: NotificationCompletionSelector,
) {
  await gate(client, a, q, 'SOURCE');
  const rows = await client.query<{
    transition_bytes: Buffer;
    transition_digest: string;
    start_signer_digest: string;
    envelope: unknown;
  }>(
    `
    select o.transition_bytes,o.transition_digest,s.signer_installation_digest start_signer_digest,
    openpc.notification_completion_source_envelope(e) envelope
    from control.outbox_event e join control.notification_delivery_outcome o on o.participant_id=e.participant_id and o.privacy_domain_id=e.privacy_domain_id and o.receipt_id=e.event_id and o.operation_id=e.correlation_id
    join control.notification_delivery_signing s on s.participant_id=o.participant_id and s.privacy_domain_id=o.privacy_domain_id and s.operation_id=o.start_operation_id
    where e.participant_id=$1 and e.privacy_domain_id=$2 and e.event_id=$3
      and e.proof_kind='NOTIFICATION_DELIVERY_COMPLETION_REFERENCE' and e.sequence_namespace='NOTIFICATION_DELIVERY_COMPLETED_V1'
      and e.event_type='io.openpc.notification.delivery.completed.v1' and e.source='urn:openpc:service:LS-NOTIFICATION'`,
    args(q),
  );
  if (rows.rowCount !== 1) throw new NotificationCompletionDispositionError();
  const row = rows.rows[0]!,
    t = decodeNotificationDeliveryOutcomeTransition(row.transition_bytes, row.transition_digest),
    r = t.receipt;
  if (
    r.participantId !== q.worker.participantId ||
    r.privacyDomainId !== q.worker.privacyDomainId ||
    r.receiptId !== q.eventId
  )
    throw new NotificationCompletionDispositionError();
  const original = validateNotificationDeliveryStartTransition(t.input.observation.original);
  const producer = validateNotificationWorkerInstallation(t.workerInstallation, r.recordedAtMs);
  if (
    producer.profile.producerTrustDigest !== a.installation.profile.producerTrustDigest ||
    producer.profile.environmentId !== a.installation.profile.environmentId
  )
    throw new NotificationCompletionDispositionError();
  const selector = notificationOutcomeSigningSelector.parse({
    original: {
      operationId: r.startOperationId,
      signerInstallationDigest: row.start_signer_digest,
      source: {
        worker: {
          participantId: r.participantId,
          privacyDomainId: r.privacyDomainId,
          installationDigest: original.workerInstallationDigest,
        },
        notificationOccurrenceId: r.notificationOccurrenceId,
        eventId: original.source.eventId,
      },
    },
    worker: {
      participantId: r.participantId,
      privacyDomainId: r.privacyDomainId,
      installationDigest: producer.installationDigest,
    },
    operationId: r.operationId,
    signerInstallationDigest: validateNotificationOutcomeSignerInstallation(t.signerInstallation)
      .digest,
  });
  const signing = await readNotificationOutcomeSigningInTransaction(client, selector);
  if (
    !signing?.observation ||
    signing.state !== 'OBSERVED' ||
    canonicalJson(
      notificationOutcomeSigningTransition(signing.preparation, signing.observation),
    ) !== canonicalJson(t)
  )
    throw new NotificationCompletionDispositionError();
  const envelope = z
    .object({
      payloadHex: z
        .string()
        .regex(/^(?:[0-9a-f]{2})*$/u)
        .max(131072),
      payloadDigest: z.string().regex(/^[0-9a-f]{64}$/u),
    })
    .passthrough()
    .parse(row.envelope);
  const source = notificationCompletionSource.parse({
    participantId: r.participantId,
    privacyDomainId: r.privacyDomainId,
    eventId: r.receiptId,
    envelopeDigest: sha256(envelope),
    dataDigest: 'sha256:' + envelope.payloadDigest,
    partitionDigest: sha256({
      source: 'urn:openpc:service:LS-NOTIFICATION',
      notificationOccurrenceId: r.notificationOccurrenceId,
    }),
    receiptDigest: sha256(Buffer.from(t.payloadHex, 'hex')),
    producerTrustDigest: a.installation.profile.producerTrustDigest,
  });
  await client.query('select openpc.check_notification_completion_source_origin($1,$2)', [
    q.eventId,
    source.receiptDigest,
  ]);
  return immutableJsonCopy({ reference: source, envelope, originalSelector: selector });
}
interface SourceRow {
  source: unknown;
  source_bytes: Buffer;
  source_digest: string;
  original_selector: unknown;
  initial_worker: unknown;
  initial_worker_installation_digest: string;
  effective_limit: string;
}
/** Historical immutable original read. Caller supplies a real authorized scoped
 * transaction; this creates no current worker/signer authority or provider call. */
export async function readNotificationCompletionJournal(
  client: PoolClient,
  q: NotificationCompletionSelector,
) {
  const selected = notificationCompletionSelector.parse(
    immutableJsonCopy({ worker: q.worker, eventId: q.eventId }),
  );
  await client.query('select openpc.assert_notification_completion_disposition_shared_owner()');
  const result = await client.query<SourceRow>(
    'select source,source_bytes,source_digest,original_selector,initial_worker,initial_worker_installation_digest,effective_limit::text from control.notification_completion_source where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
    args(selected),
  );
  if (result.rowCount === 0) return null;
  if (result.rowCount !== 1) throw new NotificationCompletionDispositionError();
  const s = result.rows[0]!,
    v = z
      .strictObject({
        reference: notificationCompletionSource,
        envelope: z.unknown(),
        originalSelector: notificationOutcomeSigningSelector,
      })
      .parse(s.source);
  const initial = validateNotificationCompletionWorkerOriginal(s.initial_worker);
  if (
    !s.source_bytes.equals(Buffer.from(canonicalJson(v))) ||
    sha256(s.source_bytes) !== s.source_digest ||
    initial.installationDigest !== s.initial_worker_installation_digest ||
    canonicalJson(v.originalSelector) !== canonicalJson(s.original_selector) ||
    v.reference.eventId !== selected.eventId ||
    v.reference.participantId !== selected.worker.participantId ||
    v.reference.privacyDomainId !== selected.worker.privacyDomainId ||
    sha256(v.envelope) !== v.reference.envelopeDigest
  )
    throw new NotificationCompletionDispositionError();
  const rows = await client.query<{
    attempt: unknown;
    attempt_bytes: Buffer;
    attempt_digest: string;
    number: string;
    attempt_id: string;
  }>(
    'select attempt,attempt_bytes,attempt_digest,number::text,attempt_id::text from control.notification_completion_attempt where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 order by number',
    args(selected),
  );
  const attempts = rows.rows.map((row) => {
    const a = notificationCompletionAttempt.parse(row.attempt);
    if (
      a.number !== Number(row.number) ||
      a.attemptId !== row.attempt_id ||
      !row.attempt_bytes.equals(Buffer.from(canonicalJson(a))) ||
      sha256(row.attempt_bytes) !== row.attempt_digest
    )
      throw new NotificationCompletionDispositionError();
    return a;
  });
  return {
    ...validateNotificationCompletionJournal({
      source: v.reference,
      initialWorker: initial.input,
      effectiveLimit: Number(s.effective_limit),
      attempts,
    }),
    originalSelector: v.originalSelector,
    envelope: v.envelope,
  };
}
const claims = new WeakMap<
  object,
  { selector: NotificationCompletionSelector; attempt: NotificationCompletionAttempt }
>();
/** A process handle exists only after actual peer transaction COMMIT ACK. Lost
 * COMMIT never yields a handle; reconcile the original source by readback. */
export async function claimNotificationCompletionAttempt(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const q = notificationCompletionSelector.parse(immutableJsonCopy(value));
  try {
    const attempt = await withNotificationCompletionWorkerPeer(
      pool,
      kernel,
      socket,
      q.worker,
      async (client, a) => {
        await lock(client, q);
        await gate(client, a, q, 'CLAIM');
        const original = await originalSource(client, a, q),
          previous = await readNotificationCompletionJournal(client, q),
          n = await now(client);
        if (
          previous &&
          canonicalJson(original) !==
            canonicalJson({
              reference: previous.journal.source,
              envelope: previous.envelope,
              originalSelector: previous.originalSelector,
            })
        )
          throw new NotificationCompletionDispositionError();
        if (previous) {
          const decision = notificationCompletionRetryDecision(
            previous.journal,
            a.installation.input,
            n,
          );
          if (decision.limit < previous.journal.effectiveLimit) {
            await gate(client, a, q, 'LIMIT');
            await client.query(
              'update control.notification_completion_source set effective_limit=$4 where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
              [...args(q), decision.limit],
            );
          }
          if (decision.state !== 'READY') return null;
        } else {
          const b = Buffer.from(canonicalJson(original));
          await client.query(
            'insert into control.notification_completion_source(participant_id,privacy_domain_id,event_id,source,source_bytes,source_digest,original_selector,initial_worker,initial_worker_installation_digest,effective_limit) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
            [
              ...args(q),
              original,
              b,
              sha256(b),
              original.originalSelector,
              a.installation.input,
              a.installation.installationDigest,
              a.installation.profile.maximumAttempts,
            ],
          );
        }
        const next = notificationCompletionAttempt.parse({
          attemptId: localOperationId(),
          number: (previous?.journal.attempts.length ?? 0) + 1,
          workerInstallationDigest: a.installation.installationDigest,
          authorityDigest: a.authorityDigest,
          claimedAtMs: n,
          leaseUntilMs: Math.min(n + 30000, a.installation.profile.validUntilMs),
          state: 'LEASED',
          finishedAtMs: null,
          nextAttemptAtMs: null,
        });
        const b = Buffer.from(canonicalJson(next));
        await client.query(
          'insert into control.notification_completion_attempt(participant_id,privacy_domain_id,event_id,attempt_id,number,attempt,attempt_bytes,attempt_digest) values($1,$2,$3,$4,$5,$6,$7,$8)',
          [...args(q), next.attemptId, next.number, next, b, sha256(b)],
        );
        await gate(client, a, q, 'CLAIM');
        return next;
      },
    );
    if (!attempt) return null;
    const capability = Object.freeze({});
    claims.set(capability, { selector: q, attempt });
    return capability;
  } catch {
    throw new NotificationCompletionDispositionUnknown(q);
  }
}
export function consumeNotificationCompletionAttempt(capability: object) {
  const c = claims.get(capability);
  if (!c) throw new NotificationCompletionDispositionError();
  claims.delete(capability);
  return immutableJsonCopy(c);
}
/** VALIDATED is derived here through real publication/readback. No caller
 * success flag can bypass producer signature, event, failure-work or history. */
export async function finishNotificationCompletionAttempt(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  attemptId: string,
  releaseCapacity = false,
) {
  const q = notificationCompletionSelector.parse(immutableJsonCopy(value));
  z.uuidv7().parse(attemptId);
  return withNotificationCompletionWorkerPeer(pool, kernel, socket, q.worker, async (client, a) => {
    await lock(client, q);
    await gate(client, a, q, 'FINISH');
    const v = await readNotificationCompletionJournal(client, q),
      n = await now(client);
    if (!v) throw new NotificationCompletionDispositionError();
    const last = v.journal.attempts.at(-1)!;
    if (last.attemptId !== attemptId) throw new NotificationCompletionDispositionError();
    if (last.state !== 'LEASED') return last;
    if (
      n < last.leaseUntilMs &&
      (last.workerInstallationDigest !== a.installation.installationDigest ||
        last.authorityDigest !== a.authorityDigest)
    )
      throw new NotificationCompletionDispositionError();
    let state: NotificationCompletionAttempt['state'] = 'FAILED';
    if (releaseCapacity) state = 'RELEASED';
    else if (n < last.leaseUntilMs) {
      await client.query('savepoint notification_completion_semantic');
      try {
        const actual = await readNotificationOutcomePublicationInTransaction(
          client,
          v.originalSelector,
        );
        if (!actual?.event || actual.event.envelope.id !== q.eventId) throw new Error();
        state = 'VALIDATED';
        await client.query('release savepoint notification_completion_semantic');
      } catch (error) {
        await client.query('rollback to savepoint notification_completion_semantic');
        await client.query('release savepoint notification_completion_semantic');
        if (!(error instanceof NotificationDeliveryOutcomeError)) throw error;
      }
    }
    const finishedAtMs = await now(client);
    if (state === 'VALIDATED' && finishedAtMs >= last.leaseUntilMs) state = 'FAILED';
    const delay = Math.min(
      v.initial.profile.maximumBackoffMs,
      v.initial.profile.initialBackoffMs * 2 ** Math.min(last.number - 1, 52),
    );
    const next = notificationCompletionAttempt.parse({
      ...last,
      state,
      finishedAtMs,
      nextAttemptAtMs: state === 'VALIDATED' ? null : finishedAtMs + delay,
    });
    const b = Buffer.from(canonicalJson(next));
    await client.query(
      'update control.notification_completion_attempt set attempt=$5,attempt_bytes=$6,attempt_digest=$7 where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 and attempt_id=$4',
      [...args(q), attemptId, next, b, sha256(b)],
    );
    await gate(client, a, q, 'FINISH');
    return next;
  });
}
export function buildNotificationCompletionDispositionSigning(value: unknown) {
  const preparation = immutableJsonCopy(value),
    receipt = notificationCompletionDispositionClaims(preparation);
  const p = z
    .object({ workerInstallation: z.unknown(), signerInstallation: z.unknown() })
    .parse(preparation);
  const signer = validateNotificationCompletionDispositionSignerInstallation(p.signerInstallation),
    worker = validateNotificationCompletionWorkerOriginal(p.workerInstallation);
  const request = createNotificationCompletionDispositionRequest(
    { signer: signer.pins, worker: worker.input },
    {
      payloadHex: encodeNotificationClaim(
        'NotificationCompletionDispositionReceiptV1',
        receipt,
      ).toString('hex'),
      dispositionPreparationDigest: sha256(preparation),
    },
  );
  const bound = validateNotificationCompletionDispositionRequest(request, {
    signer: signer.pins,
    worker: worker.input,
  });
  return immutableJsonCopy({
    schema: 'pc.notification.completion-disposition-signing.v1' as const,
    preparation,
    request,
    requestDigest: bound.requestDigest,
  });
}
export function validateNotificationCompletionDispositionSigning(value: unknown) {
  const p = z
    .strictObject({
      schema: z.literal('pc.notification.completion-disposition-signing.v1'),
      preparation: z.unknown(),
      request: z.unknown(),
      requestDigest: digest,
    })
    .parse(immutableJsonCopy(value));
  const expected = buildNotificationCompletionDispositionSigning(p.preparation);
  if (canonicalJson(p) !== canonicalJson(expected))
    throw new NotificationCompletionDispositionError();
  return expected;
}
export interface NotificationCompletionSigningRecord {
  preparation: ReturnType<typeof buildNotificationCompletionDispositionSigning>;
  state: 'PREPARED' | 'DISPATCHED' | 'OBSERVED';
  dispatchToken: string | null;
  dispatchedAtMs: number | null;
  observation: NotificationReceiptProviderObservation | null;
}
export function notificationCompletionSigningTransition(
  record: NotificationCompletionSigningRecord,
) {
  if (record.state !== 'OBSERVED' || record.observation?.outcome !== 'SIGNED')
    throw new NotificationCompletionDispositionError();
  return encodeNotificationCompletionDisposition({
    schema: 'pc.notification.completion-disposition.v1',
    input: record.preparation.preparation,
    receipt: notificationCompletionDispositionClaims(record.preparation.preparation),
    payloadHex: record.preparation.request.payloadHex,
    coseHex: record.observation.coseHex,
  });
}
export async function readNotificationCompletionSigningInTransaction(
  client: PoolClient,
  value: unknown,
): Promise<NotificationCompletionSigningRecord | null> {
  const q = notificationCompletionSigningSelector.parse(immutableJsonCopy(value));
  const rows = await client.query<{
    preparation: unknown;
    preparation_bytes: Buffer;
    preparation_digest: string;
    request_digest: string;
    state: string;
    dispatch_token: string | null;
    dispatched_at_ms: string | null;
    observation: unknown;
    observation_bytes: Buffer | null;
    observation_digest: string | null;
    operation_id: string;
    signing_attempt_id: string;
    signer_installation_digest: string;
  }>(
    'select preparation,preparation_bytes,preparation_digest,request_digest,state,dispatch_token,dispatched_at_ms::text,observation,observation_bytes,observation_digest,operation_id::text,signing_attempt_id::text,signer_installation_digest from control.notification_completion_disposition_signing where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
    args(q),
  );
  if (rows.rowCount === 0) return null;
  if (rows.rowCount !== 1) throw new NotificationCompletionDispositionError();
  const r = rows.rows[0]!,
    p = validateNotificationCompletionDispositionSigning(r.preparation);
  const input = z
      .object({
        workerInstallation: z.unknown(),
        signerInstallation: z.unknown(),
        journal: z.unknown(),
      })
      .parse(p.preparation),
    original = validateNotificationCompletionWorkerOriginal(input.workerInstallation),
    signer = validateNotificationCompletionDispositionSignerInstallation(input.signerInstallation);
  if (
    !r.preparation_bytes.equals(Buffer.from(canonicalJson(p))) ||
    sha256(r.preparation_bytes) !== r.preparation_digest ||
    r.request_digest !== p.requestDigest ||
    r.operation_id !== q.operationId ||
    p.request.operationId !== q.operationId ||
    p.request.signingAttemptId !== r.signing_attempt_id ||
    p.request.signerInstallationDigest !== r.signer_installation_digest ||
    p.request.sourceEventId !== q.eventId ||
    p.request.participantId !== q.worker.participantId ||
    p.request.privacyDomainId !== q.worker.privacyDomainId
  )
    throw new NotificationCompletionDispositionError();
  const state = z.enum(['PREPARED', 'DISPATCHED', 'OBSERVED']).parse(r.state);
  if (
    state === 'PREPARED'
      ? r.dispatch_token !== null || r.dispatched_at_ms !== null
      : !r.dispatch_token?.match(/^[0-9a-f]{64}$/u)
  )
    throw new NotificationCompletionDispositionError();
  let observation: NotificationReceiptProviderObservation | null = null;
  if (
    state !== 'PREPARED' &&
    (!r.dispatched_at_ms ||
      !Number.isSafeInteger(Number(r.dispatched_at_ms)) ||
      Number(r.dispatched_at_ms) <
        notificationCompletionDispositionClaims(p.preparation).recordedAtMs)
  )
    throw new NotificationCompletionDispositionError();
  if (state === 'OBSERVED') {
    observation = validateNotificationCompletionDispositionObservation(p.request, r.observation, {
      signer: signer.pins,
      worker: original.input,
    });
    if (observation.outcome === 'SIGNED' && observation.recordedAtMs < Number(r.dispatched_at_ms))
      throw new NotificationCompletionDispositionError();
    if (
      !r.observation_bytes?.equals(Buffer.from(canonicalJson(observation))) ||
      sha256(r.observation_bytes) !== r.observation_digest
    )
      throw new NotificationCompletionDispositionError();
  } else if (
    r.observation !== null ||
    r.observation_bytes !== null ||
    r.observation_digest !== null
  )
    throw new NotificationCompletionDispositionError();
  const journal = await readNotificationCompletionJournal(client, q);
  if (!journal || canonicalJson(journal.journal) !== canonicalJson(input.journal))
    throw new NotificationCompletionDispositionError();
  return immutableJsonCopy({
    preparation: p,
    state,
    dispatchToken: r.dispatch_token,
    dispatchedAtMs: r.dispatched_at_ms === null ? null : Number(r.dispatched_at_ms),
    observation,
  });
}
/** Exact readback after lost claim/prepare COMMIT. A current successor can inspect
 * old signed authority, but cannot redispatch using an old worker installation. */
export async function readNotificationCompletionOriginal(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const q = notificationCompletionSelector.parse(immutableJsonCopy(value));
  return withNotificationCompletionWorkerPeer(pool, kernel, socket, q.worker, async (client, a) => {
    await gate(client, a, q, 'SOURCE');
    const journal = await readNotificationCompletionJournal(client, q);
    const r = await client.query<{ operation_id: string }>(
      'select operation_id::text from control.notification_completion_disposition_signing where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
      args(q),
    );
    return {
      currentWorker: a.installation.input,
      journal,
      signing: r.rowCount
        ? await readNotificationCompletionSigningInTransaction(client, {
            ...q,
            operationId: r.rows[0]!.operation_id,
          })
        : null,
    };
  });
}
export async function prepareNotificationCompletionDisposition(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const p = z
      .strictObject({ selector: notificationCompletionSelector, signerInstallationDigest: digest })
      .parse(immutableJsonCopy(value)),
    q = p.selector;
  try {
    return await withNotificationCompletionWorkerPeer(
      pool,
      kernel,
      socket,
      q.worker,
      async (client, a) => {
        await lock(client, q);
        await gate(client, a, q, 'PREPARE');
        const existing = await client.query<{ operation_id: string }>(
          'select operation_id::text from control.notification_completion_disposition_signing where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
          args(q),
        );
        if (existing.rowCount)
          return readNotificationCompletionSigningInTransaction(client, {
            ...q,
            operationId: existing.rows[0]!.operation_id,
          });
        const j = await readNotificationCompletionJournal(client, q),
          n = await now(client);
        if (!j) throw new NotificationCompletionDispositionError();
        const decision = notificationCompletionRetryDecision(j.journal, a.installation.input, n);
        if (decision.state !== 'EXHAUSTED' && decision.state !== 'VALIDATED')
          throw new NotificationCompletionDispositionError();
        if (decision.limit < j.journal.effectiveLimit) {
          await gate(client, a, q, 'LIMIT');
          await client.query(
            'update control.notification_completion_source set effective_limit=$4 where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
            [...args(q), decision.limit],
          );
          j.journal = { ...j.journal, effectiveLimit: decision.limit };
        }
        const actual =
          decision.state === 'VALIDATED'
            ? await readNotificationOutcomePublicationInTransaction(client, j.originalSelector)
            : null;
        if (decision.state === 'VALIDATED' && !actual?.event)
          throw new NotificationCompletionDispositionError();
        return withCurrentNotificationCompletionDispositionSigner(
          client,
          a,
          { worker: q.worker, signerInstallationDigest: p.signerInstallationDigest },
          async (signer) => {
            const receiptId = localOperationId(),
              operationId = localOperationId(),
              disposition =
                decision.state === 'VALIDATED' ? ('ADMITTED' as const) : ('QUARANTINED' as const);
            const producerOutcome = actual?.event?.envelope.data.state ?? null,
              producerWorkItemId = actual?.failureWork
                ? actual.encoded.transition.receipt.receiptId
                : null;
            const before = {
              schema: 'pc.notification.completion-disposition-state.v1',
              journal: j.journal,
              disposition: null,
            };
            const after = {
              ...before,
              disposition,
              receiptId,
              operationId,
              workItemKind:
                disposition === 'QUARANTINED'
                  ? 'REMEDIATION'
                  : producerWorkItemId
                    ? 'DELIVERY_FAILURE'
                    : 'NONE',
              workItemId: producerWorkItemId ?? receiptId,
              cursorMode: disposition === 'ADMITTED' ? 'ADVANCE' : 'HOLD',
            };
            const preparation = buildNotificationCompletionDispositionSigning({
              journal: j.journal,
              workerInstallation: a.installation.input,
              signerInstallation: signer.pins,
              metadata: {
                receiptId,
                operationId,
                authoritySnapshotDigest: a.authorityDigest,
                recordedAtMs: n,
                beforeStateDigest: sha256(before),
                afterStateDigest: sha256(after),
              },
              disposition,
              producerOutcome,
              producerWorkItemId,
            });
            const bytes = Buffer.from(canonicalJson(preparation));
            await client.query(
              'insert into control.notification_completion_disposition_signing(participant_id,privacy_domain_id,event_id,operation_id,signing_attempt_id,signer_installation_digest,preparation,preparation_bytes,preparation_digest,request_digest) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
              [
                ...args(q),
                operationId,
                receiptId,
                signer.digest,
                preparation,
                bytes,
                sha256(bytes),
                preparation.requestDigest,
              ],
            );
            await gate(client, a, q, 'PREPARE');
            return readNotificationCompletionSigningInTransaction(client, { ...q, operationId });
          },
        );
      },
    );
  } catch {
    throw new NotificationCompletionDispositionUnknown(q);
  }
}
const signingClaims = new WeakMap<object, NotificationCompletionSigningRecord>();
export async function claimNotificationCompletionSigning(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const q = notificationCompletionSigningSelector.parse(immutableJsonCopy(value));
  try {
    const record = await withNotificationCompletionWorkerPeer(
      pool,
      kernel,
      socket,
      q.worker,
      async (client, a) => {
        await lock(client, q);
        await gate(client, a, q, 'SIGN_CLAIM');
        const original = await readNotificationCompletionSigningInTransaction(client, q);
        if (!original || original.state !== 'PREPARED') return null;
        return withCurrentNotificationCompletionDispositionSigner(
          client,
          a,
          {
            worker: q.worker,
            signerInstallationDigest: original.preparation.request.signerInstallationDigest,
          },
          async () => {
            if (
              original.preparation.request.workerInstallationDigest !== q.worker.installationDigest
            )
              throw new NotificationCompletionDispositionError();
            await client.query(
              "update control.notification_completion_disposition_signing set state='DISPATCHED',dispatch_token=$4,dispatched_at_ms=$5 where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 and state='PREPARED'",
              [...args(q), randomBytes(32).toString('hex'), await now(client)],
            );
            await gate(client, a, q, 'SIGN_CLAIM');
            return readNotificationCompletionSigningInTransaction(client, q);
          },
        );
      },
    );
    if (!record) return null;
    const cap = Object.freeze({});
    signingClaims.set(cap, record);
    return cap;
  } catch {
    throw new NotificationCompletionDispositionUnknown(q);
  }
}
export function consumeNotificationCompletionSigningClaim(capability: object) {
  const r = signingClaims.get(capability);
  if (!r) throw new NotificationCompletionDispositionError();
  signingClaims.delete(capability);
  return r;
}
export async function attachNotificationCompletionSigningObservation(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  observation: unknown,
) {
  const q = notificationCompletionSigningSelector.parse(immutableJsonCopy(value)),
    o = immutableJsonCopy(observation);
  return withNotificationCompletionWorkerPeer(pool, kernel, socket, q.worker, async (client, a) => {
    await lock(client, q);
    await gate(client, a, q, 'OBSERVE');
    const r = await readNotificationCompletionSigningInTransaction(client, q);
    if (!r || r.state === 'PREPARED') throw new NotificationCompletionDispositionError();
    const p = z
      .object({ workerInstallation: z.unknown(), signerInstallation: z.unknown() })
      .parse(r.preparation.preparation);
    const valid = validateNotificationCompletionDispositionObservation(
      r.preparation.request,
      o,
      { worker: p.workerInstallation, signer: p.signerInstallation },
      r.observation ?? undefined,
    );
    if (valid.outcome === 'SIGNED')
      await admitNotificationCompletionDispositionReceipt(
        a,
        client,
        q.worker,
        q.eventId,
        'OBSERVE',
        valid,
      );
    if (!r.observation) {
      const bytes = Buffer.from(canonicalJson(valid));
      await client.query(
        "update control.notification_completion_disposition_signing set state='OBSERVED',observation=$4,observation_bytes=$5,observation_digest=$6 where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 and state='DISPATCHED'",
        [...args(q), valid, bytes, sha256(bytes)],
      );
    }
    await gate(client, a, q, 'OBSERVE');
    const result = await readNotificationCompletionSigningInTransaction(client, q);
    if (!result) throw new NotificationCompletionDispositionError();
    return result;
  });
}
/** Native result plus all shared terminal effects in one actual transaction.
 * Canonical shared hook owns inbox, WorkItem, evidence and cursor privileges;
 * no success is returned until deferred completeness and outer COMMIT pass. */
export async function publishNotificationCompletionDisposition(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const q = notificationCompletionSigningSelector.parse(immutableJsonCopy(value));
  try {
    return await withNotificationCompletionWorkerPeer(
      pool,
      kernel,
      socket,
      q.worker,
      async (client, a) => {
        await lock(client, q);
        await gate(client, a, q, 'PUBLISH');
        const record = await readNotificationCompletionSigningInTransaction(client, q);
        if (!record) throw new NotificationCompletionDispositionError();
        await admitNotificationCompletionDispositionReceipt(
          a,
          client,
          q.worker,
          q.eventId,
          'PUBLISH',
          record.observation,
        );
        const encoded = notificationCompletionSigningTransition(record),
          r = encoded.transition.receipt;
        const retained = await client.query<{ transition_digest: string }>(
          'select transition_digest from control.notification_completion_disposition where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
          args(q),
        );
        if (retained.rowCount) {
          if (retained.rows[0]!.transition_digest !== encoded.transitionDigest)
            throw new NotificationCompletionDispositionError();
          await client.query(
            'select openpc.check_notification_completion_disposition_original($1)',
            [q.eventId],
          );
          return encoded.transition;
        }
        if (r.disposition === 'ADMITTED') {
          const j = await readNotificationCompletionJournal(client, q);
          if (
            !j ||
            !(await readNotificationOutcomePublicationInTransaction(client, j.originalSelector))
          )
            throw new NotificationCompletionDispositionError();
        }
        // Historical signed result survives signer replacement. Current publication
        // authority must separately admit the original result through canonical gate.
        await client.query(
          'insert into control.notification_completion_disposition(participant_id,privacy_domain_id,event_id,operation_id,receipt_id,disposition,transition,transition_bytes,transition_digest,receipt_payload,cose_sign1) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
          [
            ...args(q),
            r.operationId,
            r.receiptId,
            r.disposition,
            encoded.transition,
            encoded.bytes,
            encoded.transitionDigest,
            encoded.payload,
            encoded.cose,
          ],
        );
        await client.query(
          'select openpc.publish_notification_completion_disposition_effects($1)',
          [q.eventId],
        );
        await client.query('select openpc.check_notification_completion_disposition_original($1)', [
          q.eventId,
        ]);
        await gate(client, a, q, 'PUBLISH');
        return encoded.transition;
      },
    );
  } catch {
    throw new NotificationCompletionDispositionUnknown(q);
  }
}
