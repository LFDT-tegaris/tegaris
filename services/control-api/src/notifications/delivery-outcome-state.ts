import {
  withNotificationWorkerLease,
  notificationWorkerLeaseSelector,
  type NotificationWorkerLeaseSelector,
  type NotificationWorkerLeaseWindow,
} from './async-worker-state.js';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { randomBytes } from 'node:crypto';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import { encodeNotificationClaim } from '@openpc/security-kernel';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { validateNotificationWorkerInstallation } from './worker-installation-contract.js';
import {
  validateNotificationOutcomeSignerInstallation,
  notificationReceiptSignerSelector,
  type NotificationReceiptSignerSelector,
  type NotificationReceiptSigner,
} from './receipt-signer-installation.js';
import {
  assertNotificationDeliveryWorkerAdmission,
  assertNotificationDeliveryWorkerCurrent,
  withNotificationDeliveryWorkerPeer,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import {
  assertNotificationDeliveryResultAuthority,
  withNotificationDeliveryResultAuthority,
} from './delivery-result-admission.js';
import { notificationFailureWorkItem } from './delivery-failure-work-contract.js';
import { notificationWorkerSelector } from './worker-installation.js';
import { readPublishedNotificationDeliveryRequest } from './delivery-source.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  readNotificationDeliveryStartInTransaction,
  decodeNotificationDispatchClaim,
} from './delivery-start-atomic.js';
import {
  notificationDeliverySigningSelector,
  type NotificationDeliverySigningSelector,
} from './delivery-signing-contract.js';
import {
  createNotificationOutcomeReceiptRequest,
  validateNotificationOutcomeReceiptRequest,
  validateNotificationOutcomeReceiptObservation,
} from '../../../identity-service/src/domain/notification-outcome-receipt-provider.js';
import type { NotificationReceiptProviderObservation } from '../../../identity-service/src/domain/notification-receipt-provider.js';
import type { NotificationDeliveryDispatchRecord } from './delivery-dispatch-state.js';
import {
  decodeNotificationOutcomeObservation,
  decodeNotificationDeliveryOutcomeTransition,
  notificationOutcomeProjection,
  NotificationDeliveryOutcomeError,
  notificationDeliveryOutcomeClaims,
  validateNotificationDeliveryOutcomeTransition,
  proposeNotificationDeliveryOutcome,
} from './delivery-outcome-contract.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const notificationOutcomeSigningSelector = z
  .strictObject({
    original: notificationDeliverySigningSelector,
    worker: notificationWorkerSelector,
    operationId: z.uuidv7(),
    signerInstallationDigest: digest,
  })
  .refine(
    (value) =>
      value.worker.participantId === value.original.source.worker.participantId &&
      value.worker.privacyDomainId === value.original.source.worker.privacyDomainId,
  );
export type NotificationOutcomeSigningSelector = z.infer<typeof notificationOutcomeSigningSelector>;
const signingInput = z.strictObject({
  input: z.unknown(),
  workerInstallation: z.unknown(),
  signerInstallation: z.unknown(),
  metadata: z.unknown(),
});
/** Native request construction only. Actual operation metadata and authoritative
 * original/projection/worker/signer inputs belong to canonical durable admission.
 * Nothing here prepares a database row, mints a claim or invokes perform. */
export function buildNotificationOutcomeSigning(value: unknown) {
  try {
    const preparation = signingInput.parse(immutableJsonCopy(value));
    const receipt = notificationDeliveryOutcomeClaims(preparation);
    const signer = validateNotificationOutcomeSignerInstallation(preparation.signerInstallation);
    const worker = validateNotificationWorkerInstallation(
      preparation.workerInstallation,
      receipt.recordedAtMs,
    );
    const trust = { signer: signer.pins, worker: worker.input };
    const request = createNotificationOutcomeReceiptRequest(trust, {
      payloadHex: encodeNotificationClaim('NotificationDeliveryOutcomeReceiptV1', receipt).toString(
        'hex',
      ),
      outcomePreparationDigest: sha256(preparation),
    });
    const bound = validateNotificationOutcomeReceiptRequest(request, trust);
    return immutableJsonCopy({
      schema: 'pc.notification.delivery-outcome-signing.v1' as const,
      preparation,
      request,
      requestDigest: bound.requestDigest,
    });
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}
export function validateNotificationOutcomeSigning(value: unknown) {
  try {
    const p = z
      .strictObject({
        schema: z.literal('pc.notification.delivery-outcome-signing.v1'),
        preparation: signingInput,
        request: z.unknown(),
        requestDigest: digest,
      })
      .parse(immutableJsonCopy(value));
    const expected = buildNotificationOutcomeSigning(p.preparation);
    if (canonicalJson(p) !== canonicalJson(expected)) throw new Error();
    return expected;
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}
export type NotificationOutcomeSigningPreparation = ReturnType<
  typeof buildNotificationOutcomeSigning
>;

/** Actual same-client input join for canonical durable preparation. The genuine
 * worker is checked before queries; canonical admits the OUTCOME signer, owns
 * lifecycle fencing and restores transaction context. Source/STARTED/CLAIMED/current
 * projection are read from the real owners. This input-only helper is separate
 * from durable preparation/claim below and from final publication.
 * The returned bytes grant no provider perform authority. */
export async function buildAdmittedNotificationOutcomeSigning(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  selector: NotificationReceiptSignerSelector,
  value: unknown,
) {
  try {
    const q = notificationReceiptSignerSelector.parse(immutableJsonCopy(selector));
    assertNotificationDeliveryWorkerAdmission(admission, client, q.worker);
    const p = admittedSigningInput.parse(immutableJsonCopy(value));
    if (
      p.original.source.worker.participantId !== q.worker.participantId ||
      p.original.source.worker.privacyDomainId !== q.worker.privacyDomainId
    )
      throw new Error();
    return await withNotificationDeliveryResultAuthority(client, admission, q, (signer) =>
      readSigningPreparation(client, admission, signer, q, p),
    );
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}

const admittedSigningInput = z.strictObject({
  original: notificationDeliverySigningSelector,
  operationId: z.uuidv7(),
  receiptId: z.uuidv7(),
  observation: z.unknown(),
});
async function readSigningPreparation(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  signer: NotificationReceiptSigner,
  q: NotificationReceiptSignerSelector,
  p: z.infer<typeof admittedSigningInput>,
) {
  const source = await readPublishedNotificationDeliveryRequest(client, admission, {
    ...p.original.source,
    worker: q.worker,
  });
  const actual = await readNotificationOutcomeInputInTransaction(client, p.original);
  if (canonicalJson(source.claims) !== canonicalJson(actual.record.original.source))
    throw new Error();
  if (actual.first !== null) throw new Error();
  const rows = await client.query<{ now_ms: string }>(
    'select floor(extract(epoch from clock_timestamp())*1000)::text now_ms',
  );
  if (rows.rowCount !== 1 || !/^(0|[1-9][0-9]*)$/u.test(rows.rows[0]!.now_ms)) throw new Error();
  const prepared = buildNotificationOutcomeSigning({
    input: {
      observation: { ...actual.record, observation: p.observation },
      current: actual.current,
      configuredLimit: actual.current.snapshot.attemptLimit,
    },
    workerInstallation: admission.installation.input,
    signerInstallation: signer.pins,
    metadata: {
      operationId: p.operationId,
      receiptId: p.receiptId,
      recordedAtMs: Number(rows.rows[0]!.now_ms),
      authoritySnapshotDigest: admission.authorityDigest,
    },
  });
  assertNotificationDeliveryResultAuthority(
    client,
    admission,
    signer,
    q,
    notificationDeliveryOutcomeClaims(prepared.preparation),
  );
  return prepared;
}

/** Exact effects derived from a fully verified historical result. This is NOT
 * a WorkItem writer, publication grant or evidence/outbox completeness claim. */
export function notificationOutcomeFinalEffects(value: unknown) {
  const transition = validateNotificationDeliveryOutcomeTransition(value);
  const proposal = proposeNotificationDeliveryOutcome(transition.input);
  return immutableJsonCopy({
    completionData: proposal.completionData,
    failureWork:
      transition.receipt.afterDeliveryState === 'FAILED'
        ? notificationFailureWorkItem({
            workerInstallation: transition.workerInstallation,
            payloadHex: transition.payloadHex,
            coseHex: transition.coseHex,
          })
        : null,
  });
}
export function notificationOutcomeSigningObservation(
  p: NotificationOutcomeSigningPreparation,
  value: unknown,
  first?: NotificationReceiptProviderObservation,
) {
  const checked = validateNotificationOutcomeSigning(p);
  const bound = validateNotificationOutcomeReceiptRequest(checked.request, {
    signer: validateNotificationOutcomeSignerInstallation(checked.preparation.signerInstallation)
      .pins,
    worker: validateNotificationWorkerInstallation(
      checked.preparation.workerInstallation,
      notificationDeliveryOutcomeClaims(checked.preparation).recordedAtMs,
    ).input,
  });
  return validateNotificationOutcomeReceiptObservation(
    bound.request,
    value,
    { signer: bound.signer.pins, worker: bound.worker.input },
    first,
  );
}
export function notificationOutcomeSigningTransition(
  p: NotificationOutcomeSigningPreparation,
  value: unknown,
) {
  const checked = validateNotificationOutcomeSigning(p),
    observation = notificationOutcomeSigningObservation(checked, value);
  if (observation.outcome !== 'SIGNED') throw new NotificationDeliveryOutcomeError();
  return validateNotificationDeliveryOutcomeTransition({
    schema: 'pc.notification.delivery-outcome-transition.v1',
    ...checked.preparation,
    receipt: notificationDeliveryOutcomeClaims(checked.preparation),
    payloadHex: checked.request.payloadHex,
    coseHex: observation.coseHex,
  });
}
export interface NotificationOutcomeSigningRow {
  preparation_bytes: Buffer;
  preparation_digest: string;
  state: string;
  dispatch_token: string | null;
  dispatched_at_ms: string | null;
  observation_bytes: Buffer | null;
  observation_digest: string | null;
}
/** Exact durable signing-intent shape. DISPATCHED is historical state, never an
 * executable local claim; even a successfully decoded row cannot call perform. */
export function decodeNotificationOutcomeSigningRow(
  row: NotificationOutcomeSigningRow,
  selector: NotificationOutcomeSigningSelector,
) {
  try {
    const q = notificationOutcomeSigningSelector.parse(immutableJsonCopy(selector));
    if (
      !Buffer.isBuffer(row.preparation_bytes) ||
      row.preparation_bytes.length < 1 ||
      row.preparation_bytes.length > 524288 ||
      sha256(row.preparation_bytes) !== row.preparation_digest
    )
      throw new Error();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(row.preparation_bytes);
    const p = validateNotificationOutcomeSigning(JSON.parse(text));
    if (
      canonicalJson(p) !== text ||
      p.request.operationId !== q.operationId ||
      p.request.startOperationId !== q.original.operationId ||
      p.request.signerInstallationDigest !== q.signerInstallationDigest ||
      p.request.participantId !== q.original.source.worker.participantId ||
      p.request.privacyDomainId !== q.original.source.worker.privacyDomainId ||
      !['PREPARED', 'DISPATCHED', 'OBSERVED'].includes(row.state)
    )
      throw new Error();
    const claims = notificationDeliveryOutcomeClaims(p.preparation);
    const original = proposeNotificationDeliveryOutcome(p.preparation.input).original;
    if (
      q.original.source.eventId !== original.source.eventId ||
      q.original.source.worker.installationDigest !== original.workerInstallationDigest
    )
      throw new Error();
    const bound = validateNotificationOutcomeReceiptRequest(p.request, {
      signer: validateNotificationOutcomeSignerInstallation(p.preparation.signerInstallation).pins,
      worker: validateNotificationWorkerInstallation(
        p.preparation.workerInstallation,
        claims.recordedAtMs,
      ).input,
    });
    if (
      claims.notificationOccurrenceId !== q.original.source.notificationOccurrenceId ||
      (row.state === 'PREPARED'
        ? row.dispatch_token !== null || row.dispatched_at_ms !== null
        : row.dispatch_token === null ||
          !/^[0-9a-f]{64}$/u.test(row.dispatch_token) ||
          row.dispatched_at_ms === null ||
          !/^(0|[1-9][0-9]*)$/u.test(row.dispatched_at_ms) ||
          !Number.isSafeInteger(Number(row.dispatched_at_ms)) ||
          Number(row.dispatched_at_ms) < claims.recordedAtMs ||
          Number(row.dispatched_at_ms) >= bound.notAfterMs)
    )
      throw new Error();
    let observation: NotificationReceiptProviderObservation | null = null;
    if (row.state === 'OBSERVED') {
      if (
        !Buffer.isBuffer(row.observation_bytes) ||
        row.observation_bytes.length < 1 ||
        row.observation_bytes.length > 196608 ||
        sha256(row.observation_bytes) !== row.observation_digest
      )
        throw new Error();
      const text = new TextDecoder('utf-8', { fatal: true }).decode(row.observation_bytes);
      observation = notificationOutcomeSigningObservation(p, JSON.parse(text));
      if (
        canonicalJson(observation) !== text ||
        (observation.outcome === 'SIGNED' &&
          observation.recordedAtMs < Number(row.dispatched_at_ms))
      )
        throw new Error();
    } else if (row.observation_bytes !== null || row.observation_digest !== null) throw new Error();
    return immutableJsonCopy({
      preparation: p,
      state: row.state as 'PREPARED' | 'DISPATCHED' | 'OBSERVED',
      dispatchToken: row.dispatch_token,
      dispatchedAtMs: row.dispatched_at_ms,
      observation,
    });
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}
export async function readNotificationOutcomeSigningInTransaction(
  client: PoolClient,
  selector: NotificationOutcomeSigningSelector,
  locked = false,
) {
  const q = notificationOutcomeSigningSelector.parse(immutableJsonCopy(selector));
  const original = await readNotificationDeliveryStartInTransaction(client, q.original);
  if (!original) throw new NotificationDeliveryOutcomeError();
  const rows = await client.query<NotificationOutcomeSigningRow>(
    `select preparation_bytes,preparation_digest,state,dispatch_token,dispatched_at_ms::text,observation_bytes,observation_digest,openpc.check_notification_outcome_signing_original(s) from control.notification_delivery_outcome_signing s where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3${locked ? ' for update' : ''}`,
    [
      q.original.source.worker.participantId,
      q.original.source.worker.privacyDomainId,
      q.operationId,
    ],
  );
  if (rows.rowCount === 0) return null;
  if (rows.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
  const record = decodeNotificationOutcomeSigningRow(rows.rows[0]!, q);
  const input = z
    .object({ observation: z.object({ original: z.unknown(), claim: z.unknown() }) })
    .parse(record.preparation.preparation.input);
  const claims = await client.query<{
    state: string;
    claim_token: string | null;
    claimed_at_ms: string | null;
  }>(
    `select state,claim_token,claimed_at_ms::text from control.notification_delivery_dispatch_intent where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
    [
      q.original.source.worker.participantId,
      q.original.source.worker.privacyDomainId,
      q.original.operationId,
    ],
  );
  if (
    claims.rowCount !== 1 ||
    canonicalJson(input.observation.original) !== canonicalJson(original) ||
    canonicalJson(input.observation.claim) !==
      canonicalJson(decodeNotificationDispatchClaim(claims.rows[0]!))
  )
    throw new NotificationDeliveryOutcomeError();
  return record;
}

export interface NotificationSignedOutcomeRow {
  participant_id: string;
  privacy_domain_id: string;
  operation_id: string;
  receipt_id: string;
  attempt_id: string;
  start_operation_id: string;
  notification_occurrence_id: string;
  payload_digest: string;
  worker_installation_digest: string;
  signer_installation_digest: string;
  delivery_revision: string;
  transition_bytes: Buffer;
  transition_digest: string;
  receipt_payload: Buffer;
  receipt_digest: string;
  cose_sign1: Buffer;
}
/** Historical signed bytes plus original DB-row consistency, not the missing
 * publication/completeness proof. Readback must also verify the actual final
 * operation/evidence/outbox/failure-work owner before exposing completion. */
export function decodeNotificationSignedOutcomeRow(
  record: NotificationDeliveryDispatchRecord,
  firstRow: NotificationOutcomeObservationRow,
  row: NotificationSignedOutcomeRow,
) {
  try {
    const first = decodeNotificationOutcomeRow(record, firstRow);
    const t = decodeNotificationDeliveryOutcomeTransition(
        row.transition_bytes,
        row.transition_digest,
      ),
      r = t.receipt;
    const worker = validateNotificationWorkerInstallation(t.workerInstallation, r.recordedAtMs);
    if (
      canonicalJson(t.input.observation.original) !== canonicalJson(record.original) ||
      canonicalJson(t.input.observation.claim) !== canonicalJson(record.claim) ||
      canonicalJson(t.input.observation.observation) !== canonicalJson(first.observation) ||
      row.operation_id !== first.operationId ||
      row.operation_id !== r.operationId ||
      row.participant_id !== r.participantId ||
      row.privacy_domain_id !== r.privacyDomainId ||
      row.receipt_id !== r.receiptId ||
      row.attempt_id !== r.attemptId ||
      row.start_operation_id !== r.startOperationId ||
      row.notification_occurrence_id !== r.notificationOccurrenceId ||
      row.payload_digest !== r.payloadDigest ||
      row.worker_installation_digest !== worker.installationDigest ||
      row.signer_installation_digest !==
        validateNotificationOutcomeSignerInstallation(t.signerInstallation).digest ||
      row.delivery_revision !== r.deliveryRevision ||
      !Buffer.isBuffer(row.receipt_payload) ||
      !row.receipt_payload.equals(Buffer.from(t.payloadHex, 'hex')) ||
      row.receipt_digest !== sha256(row.receipt_payload) ||
      !Buffer.isBuffer(row.cose_sign1) ||
      !row.cose_sign1.equals(Buffer.from(t.coseHex, 'hex'))
    )
      throw new Error();
    return t;
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}

export interface NotificationOutcomeObservationRow {
  participant_id: string;
  privacy_domain_id: string;
  observation_id: string;
  attempt_id: string;
  start_operation_id: string;
  dispatch_claim_token: string;
  operation_id: string;
  outcome: string;
  observed_at_ms: string;
  observation_bytes: Buffer;
  observation_digest: string;
}
/** Structural/native verification of one original DB row. It does not verify the
 * absent Control signed-result/evidence chain and must not expose completion. */
export function decodeNotificationOutcomeRow(
  record: NotificationDeliveryDispatchRecord,
  row: NotificationOutcomeObservationRow,
) {
  try {
    const { original, claim } = record;
    const receipt = decodeNotificationOutcomeObservation(
      original,
      claim,
      row.observation_bytes,
      row.observation_digest,
    );
    if (
      claim.state !== 'CLAIMED' ||
      row.dispatch_claim_token !== claim.claimToken ||
      row.participant_id !== original.receipt.participantId ||
      row.privacy_domain_id !== original.receipt.privacyDomainId ||
      row.attempt_id !== original.receipt.attemptId ||
      row.start_operation_id !== original.receipt.operationId ||
      row.observation_id !== receipt.claims.receiptId ||
      row.outcome !== receipt.claims.outcome ||
      row.observed_at_ms !== String(receipt.claims.observedAtMs) ||
      !z.uuidv7().safeParse(row.operation_id).success ||
      [
        original.receipt.operationId,
        original.sourceOperationId,
        original.receipt.attemptId,
      ].includes(row.operation_id)
    )
      throw new Error();
    return immutableJsonCopy({ operationId: row.operation_id, observation: receipt });
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}

/** Same-client historical input read. The existing real Identity/history wrapper
 * owns scope/admission. Locks preserve delivery -> dispatch order. This reads no
 * fresh channel/material/send eligibility and performs no writes. Canonical must
 * install the existing-table splice before this query is executable. */
export async function readNotificationOutcomeInputInTransaction(
  client: PoolClient,
  q: NotificationDeliverySigningSelector,
  locked = false,
) {
  const original = await readNotificationDeliveryStartInTransaction(client, q);
  if (!original) throw new NotificationDeliveryOutcomeError();
  const scope = [q.source.worker.participantId, q.source.worker.privacyDomainId];
  const delivery = await client.query(
    `select participant_id::text as "participantId",privacy_domain_id::text as "privacyDomainId",notification_occurrence_id::text as "notificationOccurrenceId",payload_digest as "payloadDigest",state,attempt_count as "attemptCount",attempt_limit as "attemptLimit",next_attempt_at_ms::float8 as "nextAttemptAtMs",last_started_at_ms::float8 as "lastStartedAtMs",cancel_requested as "cancelRequested",revision::text from control.notification_delivery where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 ${locked ? 'for update' : 'for share'}`,
    [...scope, original.receipt.notificationOccurrenceId],
  );
  if (delivery.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
  const { revision, ...snapshot } = delivery.rows[0]!;
  const current = notificationOutcomeProjection.parse({ snapshot, revision });
  const claimed = await client.query<{
    state: string;
    claim_token: string | null;
    claimed_at_ms: string | null;
  }>(
    `select state,claim_token,claimed_at_ms::text from control.notification_delivery_dispatch_intent where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 ${locked ? 'for update' : 'for share'}`,
    [...scope, q.operationId],
  );
  if (claimed.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
  const claim = decodeNotificationDispatchClaim(claimed.rows[0]!);
  if (claim.state !== 'CLAIMED') throw new NotificationDeliveryOutcomeError();
  const rows = await client.query<NotificationOutcomeObservationRow>(
    `select participant_id::text,privacy_domain_id::text,observation_id::text,attempt_id::text,start_operation_id::text,dispatch_claim_token,operation_id::text,outcome,observed_at_ms::text,observation_bytes,observation_digest from control.notification_delivery_observation where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
    [...scope, original.receipt.attemptId],
  );
  if (rows.rowCount !== 0 && rows.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
  const record = { original, claim };
  return immutableJsonCopy({
    record,
    current,
    first: rows.rowCount === 1 ? decodeNotificationOutcomeRow(record, rows.rows[0]!) : null,
  });
}

const preparationSelector = z
  .strictObject({
    original: notificationDeliverySigningSelector,
    worker: notificationWorkerSelector,
    signerInstallationDigest: digest,
    expectedRevision: notificationOutcomeProjection.shape.revision,
    observation: z.unknown(),
  })
  .refine(
    (q) =>
      q.worker.participantId === q.original.source.worker.participantId &&
      q.worker.privacyDomainId === q.original.source.worker.privacyDomainId,
  );
export type NotificationOutcomeSigningRecord = NonNullable<
  Awaited<ReturnType<typeof readNotificationOutcomeSigningInTransaction>>
>;
type OutcomeOwnerSelector = Pick<
  NotificationOutcomeSigningSelector,
  'original' | 'worker' | 'signerInstallationDigest'
>;
/** Real outer peer transaction; a successful return includes its COMMIT ACK.
 * Lifecycle precedes delivery/dispatch and signing locks, including recovery.
 * Recovery needs a current reader, not the original revoked signing authority. */
async function withOutcomeOwner<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  q: OutcomeOwnerSelector,
  operation: (client: PoolClient, admission: NotificationWorkerAdmission) => Promise<T>,
  lease?: NotificationWorkerLeaseSelector,
) {
  return withNotificationDeliveryWorkerPeer(
    pool,
    kernel,
    socket,
    q.worker,
    async (client, admission) => {
      const executeOwner = async () => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        try {
          await lockEvidenceLifecycle(client, q.worker.participantId, q.worker.privacyDomainId);
          await assertNotificationDeliveryWorkerCurrent(admission, client, q.worker);
          await client.query('select openpc.assert_notification_outcome_signing_owner()');
          await readPublishedNotificationDeliveryRequest(client, admission, {
            ...q.original.source,
            worker: q.worker,
          });
          const result = await operation(client, admission);
          await assertNotificationDeliveryWorkerCurrent(admission, client, q.worker);
          return result;
        } finally {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          );
        }
      };
      if (lease === undefined) return executeOwner();
      await client.query(
        "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
      );
      try {
        return await withNotificationWorkerLease(
          client,
          q.original.source,
          lease,
          'OUTCOME',
          async () => {
            await client.query(
              "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
            );
            try {
              return await executeOwner();
            } finally {
              await client.query(
                "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
              );
            }
          },
        );
      } finally {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        );
      }
    },
  );
}
async function withOutcomeSigner<T>(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  q: OutcomeOwnerSelector,
  operation: (signer: NotificationReceiptSigner) => Promise<T>,
) {
  await client.query(
    "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
  );
  try {
    return await withNotificationDeliveryResultAuthority(
      client,
      admission,
      { worker: q.worker, signerInstallationDigest: q.signerInstallationDigest },
      operation,
    );
  } finally {
    await client.query(
      "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
    );
  }
}
/** One immutable intent per original attempt. Even a stale/unknown signature is
 * retained: this owner never manufactures a successor or varies native evidence.
 * Callers recover using the returned selector or the same preparation input. */
export async function prepareNotificationOutcomeSigning(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
) {
  const q = preparationSelector.parse(immutableJsonCopy(value));
  return withOutcomeOwner(
    pool,
    kernel,
    socket,
    q,
    async (client, admission) => {
      const execute = async () => {
        const actual = await readNotificationOutcomeInputInTransaction(client, q.original, true);
        const prior = await client.query<{ operation_id: string }>(
          `select operation_id::text from control.notification_delivery_outcome_signing
         where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 for update`,
          [
            q.worker.participantId,
            q.worker.privacyDomainId,
            actual.record.original.receipt.attemptId,
          ],
        );
        if (prior.rowCount !== 0) {
          if (prior.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
          const selector = notificationOutcomeSigningSelector.parse({
            original: q.original,
            worker: q.worker,
            signerInstallationDigest: q.signerInstallationDigest,
            operationId: prior.rows[0]!.operation_id,
          });
          const record = await readNotificationOutcomeSigningInTransaction(client, selector);
          if (!record) throw new NotificationDeliveryOutcomeError();
          const original = proposeNotificationDeliveryOutcome(record.preparation.preparation.input);
          if (
            original.before.revision !== q.expectedRevision ||
            canonicalJson(original.observation) !== canonicalJson(q.observation)
          )
            throw new NotificationDeliveryOutcomeError();
          return { selector, record };
        }
        if (actual.current.revision !== q.expectedRevision || actual.first !== null)
          throw new NotificationDeliveryOutcomeError();
        return withOutcomeSigner(client, admission, q, async (signer) => {
          const prepared = await readSigningPreparation(
            client,
            admission,
            signer,
            { worker: q.worker, signerInstallationDigest: q.signerInstallationDigest },
            {
              original: q.original,
              operationId: localOperationId(),
              receiptId: localOperationId(),
              observation: q.observation,
            },
          );
          const r = notificationDeliveryOutcomeClaims(prepared.preparation),
            bytes = Buffer.from(canonicalJson(prepared));
          await client.query(
            `insert into control.notification_delivery_outcome_signing
        (participant_id,privacy_domain_id,operation_id,signing_attempt_id,start_operation_id,attempt_id,notification_occurrence_id,payload_digest,delivery_revision,signer_installation_digest,request_digest,preparation,preparation_bytes,preparation_digest)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
            [
              r.participantId,
              r.privacyDomainId,
              r.operationId,
              r.receiptId,
              r.startOperationId,
              r.attemptId,
              r.notificationOccurrenceId,
              r.payloadDigest,
              r.deliveryRevision,
              prepared.request.signerInstallationDigest,
              prepared.requestDigest,
              prepared,
              bytes,
              sha256(bytes),
            ],
          );
          const selector = notificationOutcomeSigningSelector.parse({
            original: q.original,
            worker: q.worker,
            signerInstallationDigest: q.signerInstallationDigest,
            operationId: r.operationId,
          });
          const record = await readNotificationOutcomeSigningInTransaction(client, selector);
          if (
            !record ||
            record.state !== 'PREPARED' ||
            canonicalJson(record.preparation) !== canonicalJson(prepared)
          )
            throw new NotificationDeliveryOutcomeError();
          return { selector, record };
        });
      };
      return lease === undefined
        ? execute()
        : withNotificationWorkerLease(client, q.original.source, lease, 'OUTCOME', async () => {
            return execute();
          });
    },
    lease,
  );
}
/** Compare the retained request against live result authority and locked original
 * inputs without changing its recorded time, IDs, signature or gateway result. */
export function assertNotificationOutcomeSigningCurrent(
  record: NotificationOutcomeSigningRecord,
  actual: Awaited<ReturnType<typeof readNotificationOutcomeInputInTransaction>>,
  nowMs: number,
) {
  const p = record.preparation,
    proposal = proposeNotificationDeliveryOutcome(p.preparation.input);
  const bound = validateNotificationOutcomeReceiptRequest(p.request, {
    signer: validateNotificationOutcomeSignerInstallation(p.preparation.signerInstallation).pins,
    worker: validateNotificationWorkerInstallation(
      p.preparation.workerInstallation,
      notificationDeliveryOutcomeClaims(p.preparation).recordedAtMs,
    ).input,
  });
  if (
    !Number.isSafeInteger(nowMs) ||
    nowMs < bound.notBeforeMs ||
    nowMs >= bound.notAfterMs ||
    actual.first !== null ||
    canonicalJson(actual.current) !== canonicalJson(proposal.before) ||
    canonicalJson(actual.record.original) !== canonicalJson(proposal.original) ||
    canonicalJson(actual.record.claim) !== canonicalJson(proposal.claim)
  )
    throw new NotificationDeliveryOutcomeError();
}
const outcomeSigningClaims = new WeakMap<object, NotificationOutcomeSigningRecord>();
/** No retained row/selector is an executable capability. Only the ACK from the
 * real outer peer transaction mints a local one-use handle. Lost ACK means lookup. */
export async function claimNotificationOutcomeSigning(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
) {
  let claimedWindow: NotificationWorkerLeaseWindow | undefined;

  const q = notificationOutcomeSigningSelector.parse(immutableJsonCopy(value));
  const claimed = await withOutcomeOwner(
    pool,
    kernel,
    socket,
    q,
    async (client, admission) => {
      const execute = async () => {
        const actual = await readNotificationOutcomeInputInTransaction(client, q.original, true);
        const record = await readNotificationOutcomeSigningInTransaction(client, q, true);
        if (!record || record.state !== 'PREPARED') return null;
        return withOutcomeSigner(client, admission, q, async (signer) => {
          const clock = await client.query<{ now_ms: string }>(
            'select floor(extract(epoch from clock_timestamp())*1000)::text now_ms',
          );
          if (clock.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
          assertNotificationOutcomeSigningCurrent(record, actual, Number(clock.rows[0]!.now_ms));
          assertNotificationDeliveryResultAuthority(
            client,
            admission,
            signer,
            { worker: q.worker, signerInstallationDigest: q.signerInstallationDigest },
            notificationDeliveryOutcomeClaims(record.preparation.preparation),
          );
          const changed = await client.query(
            `update control.notification_delivery_outcome_signing set state='DISPATCHED',dispatch_token=$4,dispatched_at_ms=floor(extract(epoch from statement_timestamp())*1000)
        where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='PREPARED' returning operation_id`,
            [
              q.worker.participantId,
              q.worker.privacyDomainId,
              q.operationId,
              randomBytes(32).toString('hex'),
            ],
          );
          if (changed.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
          const retained = await readNotificationOutcomeSigningInTransaction(client, q);
          if (!retained || retained.state !== 'DISPATCHED')
            throw new NotificationDeliveryOutcomeError();
          return retained;
        });
      };
      return lease === undefined
        ? execute()
        : withNotificationWorkerLease(
            client,
            q.original.source,
            lease,
            'OUTCOME',
            async (window) => {
              claimedWindow = window;
              return execute();
            },
          );
    },
    lease,
  );
  if (!claimed) return null;
  const capability = Object.freeze(Object.create(null)) as object;
  outcomeSigningClaims.set(capability, claimed);
  if (claimedWindow) leasedOutcomeSigningClaims.set(capability, claimedWindow);
  return capability;
}
const leasedOutcomeSigningClaims = new WeakMap<object, NotificationWorkerLeaseWindow>();
export function consumeNotificationLeasedOutcomeSigningClaim(capability: object) {
  const window = leasedOutcomeSigningClaims.get(capability);
  if (!window) throw new NotificationDeliveryOutcomeError();
  return { record: consumeNotificationOutcomeSigningClaim(capability), window };
}
export function consumeNotificationOutcomeSigningClaim(capability: object) {
  leasedOutcomeSigningClaims.delete(capability);
  const record = outcomeSigningClaims.get(capability);
  outcomeSigningClaims.delete(capability);
  if (!record) throw new NotificationDeliveryOutcomeError();
  return record;
}
export async function readNotificationOutcomeSigning(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const q = notificationOutcomeSigningSelector.parse(immutableJsonCopy(value));
  return withOutcomeOwner(pool, kernel, socket, q, async (client) => {
    await readNotificationOutcomeInputInTransaction(client, q.original);
    return readNotificationOutcomeSigningInTransaction(client, q);
  });
}
/** Recovery attaches the first native response under current reader authority.
 * It does not require current original signer lifetime or rewrite stale intent.
 * A signature received after cancellation remains historical, never publication. */
export async function attachNotificationOutcomeSigningObservation(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  observed: unknown,
) {
  const q = notificationOutcomeSigningSelector.parse(immutableJsonCopy(value)),
    supplied = immutableJsonCopy(observed);
  return withOutcomeOwner(pool, kernel, socket, q, async (client) => {
    await readNotificationOutcomeInputInTransaction(client, q.original, true);
    const prior = await readNotificationOutcomeSigningInTransaction(client, q, true);
    if (!prior || prior.state === 'PREPARED') throw new NotificationDeliveryOutcomeError();
    const observation = notificationOutcomeSigningObservation(
      prior.preparation,
      supplied,
      prior.observation ?? undefined,
    );
    if (prior.observation) return prior;
    const bytes = Buffer.from(canonicalJson(observation));
    const changed = await client.query(
      `update control.notification_delivery_outcome_signing set state='OBSERVED',observation_bytes=$4,observation_digest=$5
       where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='DISPATCHED' returning operation_id`,
      [q.worker.participantId, q.worker.privacyDomainId, q.operationId, bytes, sha256(bytes)],
    );
    if (changed.rowCount !== 1) throw new NotificationDeliveryOutcomeError();
    const retained = await readNotificationOutcomeSigningInTransaction(client, q);
    if (
      !retained?.observation ||
      canonicalJson(retained.observation) !== canonicalJson(observation)
    )
      throw new NotificationDeliveryOutcomeError();
    return retained;
  });
}

/** Leased production entry; original API remains available to existing owners. */
export function prepareNotificationOutcomeSigningLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  return prepareNotificationOutcomeSigning(
    pool,
    kernel,
    socket,
    value,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}

/** Leased production entry; original API remains available to existing owners. */
export function claimNotificationOutcomeSigningLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  return claimNotificationOutcomeSigning(
    pool,
    kernel,
    socket,
    value,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}
