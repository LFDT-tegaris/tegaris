import {
  withNotificationWorkerLease,
  notificationWorkerLeaseSelector,
  type NotificationWorkerLeaseSelector,
  type NotificationWorkerLeaseWindow,
} from './async-worker-state.js';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import {
  withNotificationWorkerPeer,
  assertNotificationDeliveryWorkerAdmission,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import { withNotificationDeliveryRequest } from './delivery-admission.js';
import { readPublishedNotificationDeliveryRequest } from './delivery-source.js';
import {
  NotificationPayloadReferenceGate,
  assertNotificationDeliveryPayloadReference,
} from './payload-reference.js';
import { currentNotificationChannel } from './endpoint-admission.js';
import {
  withCurrentNotificationReceiptSigner,
  assertNotificationReceiptSigner,
  type NotificationReceiptSigner,
} from './receipt-signer-installation.js';
import {
  decodeNotificationDeliveryPreparation,
  type NotificationDeliveryPreparation,
} from './delivery-start-preparation.js';
import { notificationDeliveryBudgetRecord } from './delivery-start-state.js';
import {
  buildNotificationDeliverySigning,
  decodeNotificationDeliverySigning,
  notificationSigningObservation,
  notificationDeliverySigningSelector,
  NotificationDeliverySigningError,
  type NotificationDeliverySigningSelector,
  type NotificationDeliverySigningPreparation,
} from './delivery-signing-contract.js';
import type { NotificationReceiptProviderObservation } from '../../../identity-service/src/domain/notification-receipt-provider.js';

export interface NotificationDeliverySigningRecord {
  readonly preparation: NotificationDeliverySigningPreparation;
  readonly state: 'PREPARED' | 'DISPATCHED' | 'OBSERVED';
  readonly dispatchToken: string | null;
  readonly observation: NotificationReceiptProviderObservation | null;
}
type Stored = {
  preparation_bytes: Buffer;
  preparation_digest: string;
  state: string;
  dispatch_token: string | null;
  observation_bytes: Buffer | null;
  observation_digest: string | null;
};
export function decodeNotificationSigningRecord(
  row: Stored,
  q: NotificationDeliverySigningSelector,
): NotificationDeliverySigningRecord {
  const p = decodeNotificationDeliverySigning(row.preparation_bytes, row.preparation_digest),
    s = p.deliveryPreparation.source;
  if (
    p.request.operationId !== q.operationId ||
    p.request.signerInstallationDigest !== q.signerInstallationDigest ||
    s.notificationOccurrenceId !== q.source.notificationOccurrenceId ||
    s.eventId !== q.source.eventId ||
    s.worker.participantId !== q.source.worker.participantId ||
    s.worker.privacyDomainId !== q.source.worker.privacyDomainId ||
    !['PREPARED', 'DISPATCHED', 'OBSERVED'].includes(row.state) ||
    (row.state === 'PREPARED') !== (row.dispatch_token === null)
  )
    throw new NotificationDeliverySigningError();
  let observation: NotificationReceiptProviderObservation | null = null;
  if (row.state === 'OBSERVED') {
    if (
      !row.observation_bytes ||
      row.observation_bytes.length > 196608 ||
      sha256(row.observation_bytes) !== row.observation_digest
    )
      throw new NotificationDeliverySigningError();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(row.observation_bytes);
    observation = notificationSigningObservation(p, JSON.parse(text));
    if (canonicalJson(observation) !== text) throw new NotificationDeliverySigningError();
  } else if (row.observation_bytes !== null || row.observation_digest !== null)
    throw new NotificationDeliverySigningError();
  return immutableJsonCopy({
    preparation: p,
    state: row.state as NotificationDeliverySigningRecord['state'],
    dispatchToken: row.dispatch_token,
    observation,
  });
}
export async function readNotificationSigningRecord(
  client: PoolClient,
  q: NotificationDeliverySigningSelector,
  locked = false,
) {
  const rows = await client.query<Stored>(
    `select preparation_bytes,preparation_digest,state,dispatch_token,observation_bytes,observation_digest from control.notification_delivery_signing
    where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 ${locked ? 'for update' : ''}`,
    [q.source.worker.participantId, q.source.worker.privacyDomainId, q.operationId],
  );
  if (!rows.rowCount) return null;
  if (rows.rowCount !== 1) throw new NotificationDeliverySigningError();
  return decodeNotificationSigningRecord(rows.rows[0]!, q);
}
/** Authoritative original readback. No configuration, signer freshness or payload
 * capability is fabricated when an old receipt/request has expired. */
export async function withNotificationSigningHistory<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  operation: (client: PoolClient, q: NotificationDeliverySigningSelector) => Promise<T>,
) {
  try {
    const q = notificationDeliverySigningSelector.parse(immutableJsonCopy(value));
    return await withNotificationDeliveryRequest(
      pool,
      kernel,
      socket,
      q.source,
      async (client, admission) => {
        assertNotificationDeliveryWorkerAdmission(admission, client, q.source.worker);
        await client.query('select openpc.assert_notification_delivery_signing_owner()');
        return operation(client, q);
      },
    );
  } catch {
    throw new NotificationDeliverySigningError();
  }
}
const projection = `participant_id::text as "participantId",privacy_domain_id::text as "privacyDomainId",notification_occurrence_id::text as "notificationOccurrenceId",payload_digest as "payloadDigest",state,
 attempt_count as "attemptCount",attempt_limit as "attemptLimit",next_attempt_at_ms::float8 as "nextAttemptAtMs",last_started_at_ms::float8 as "lastStartedAtMs",cancel_requested as "cancelRequested",revision::text,
 delivery_request_event_id::text as "deliveryRequestEventId",delivery_request_operation_id::text as "deliveryRequestOperationId",budget_environment_id as "budgetEnvironmentId",budget_generation_id::text as "budgetGenerationId",budget_effective_digest as "budgetEffectiveDigest",budget_configured_limit as "budgetConfiguredLimit",budget_worker_installation_digest as "budgetWorkerInstallationDigest"`;
/** Complete current authority join shared by request creation, one dispatch claim
 * and atomic STARTED. No provider or gateway I/O is legal inside this callback. */
export async function withCurrentNotificationSigning<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
  operation: (
    client: PoolClient,
    q: NotificationDeliverySigningSelector,
    original: NotificationDeliveryPreparation,
    signer: NotificationReceiptSigner,
    admission: NotificationWorkerAdmission,
    source: Awaited<ReturnType<typeof readPublishedNotificationDeliveryRequest>>,
  ) => Promise<T>,
  lease?: NotificationWorkerLeaseSelector,
) {
  try {
    const q = notificationDeliverySigningSelector.parse(immutableJsonCopy(value));
    return await withNotificationWorkerPeer(
      pool,
      kernel,
      socket,
      q.source.worker,
      async (client, admission) => {
        const executeOwner = async () => {
          const selector = {
            worker: q.source.worker,
            signerInstallationDigest: q.signerInstallationDigest,
          };
          return withCurrentNotificationReceiptSigner(
            client,
            admission,
            selector,
            async (signer) => {
              assertNotificationReceiptSigner(signer, client, selector);
              await client.query(
                "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
              );
              try {
                await lockEvidenceLifecycle(
                  client,
                  q.source.worker.participantId,
                  q.source.worker.privacyDomainId,
                );
                await client.query('select openpc.assert_notification_delivery_signing_owner()');
                const rows = await client.query<{
                  preparation_bytes: Buffer;
                  preparation_digest: string;
                }>(
                  `select preparation_bytes,preparation_digest from control.notification_delivery_preparation where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
                  [q.source.worker.participantId, q.source.worker.privacyDomainId, q.operationId],
                );
                if (rows.rowCount !== 1) throw new Error();
                const p = decodeNotificationDeliveryPreparation(
                  rows.rows[0]!.preparation_bytes,
                  rows.rows[0]!.preparation_digest,
                );
                if (
                  canonicalJson(p.source) !== canonicalJson(q.source) ||
                  p.operationId !== q.operationId ||
                  p.authorityDigest !== admission.authorityDigest
                )
                  throw new Error();
                const source = await readPublishedNotificationDeliveryRequest(
                  client,
                  admission,
                  q.source,
                );
                if (
                  source.sourceReceiptDigest !== p.sourceReceiptDigest ||
                  source.sourceOperationId !== p.sourceOperationId
                )
                  throw new Error();
                const config = await client.query<{
                  generation_id: string;
                  effective_digest: string;
                  configured_limit: number;
                }>('select * from openpc.current_notification_delivery_limit($1)', [
                  source.claims.environmentId,
                ]);
                if (
                  config.rowCount !== 1 ||
                  config.rows[0]!.generation_id !== p.generationId ||
                  config.rows[0]!.effective_digest !== p.effectiveDigest ||
                  config.rows[0]!.configured_limit !== p.configuredLimit ||
                  p.configuredLimit === 0
                )
                  throw new Error();
                return await gate.withDeliveryCurrent(
                  client,
                  admission,
                  q.source,
                  async (reference) => {
                    assertNotificationDeliveryPayloadReference(reference, client, q.source);
                    const channel = await currentNotificationChannel(
                      client,
                      source.claims,
                      p.attempt.credentialRef,
                    );
                    if (canonicalJson(channel.channel) !== canonicalJson(p.channel))
                      throw new Error();
                    const before = await client.query(
                      `select ${projection} from control.notification_delivery where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 for update`,
                      [
                        q.source.worker.participantId,
                        q.source.worker.privacyDomainId,
                        q.source.notificationOccurrenceId,
                      ],
                    );
                    if (
                      before.rowCount !== 1 ||
                      canonicalJson(notificationDeliveryBudgetRecord.parse(before.rows[0])) !==
                        canonicalJson(p.before)
                    )
                      throw new Error();
                    const fresh = async () => {
                      const clock = await client.query<{ now_ms: string }>(
                        'select floor(extract(epoch from clock_timestamp())*1000)::text now_ms',
                      );
                      const now = Number(clock.rows[0]!.now_ms);
                      if (
                        now < p.attempt.startedAtMs ||
                        now >= p.attempt.deadlineAtMs ||
                        now >= p.authorityValidUntilMs
                      )
                        throw new Error();
                    };
                    await fresh();
                    const result = await operation(client, q, p, signer, admission, source);
                    await fresh();
                    return result;
                  },
                );
              } finally {
                await client.query(
                  "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
                );
              }
            },
          );
        };
        if (lease === undefined) return executeOwner();
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        try {
          return await withNotificationWorkerLease(client, q.source, lease, 'SIGN', async () => {
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
          });
        } finally {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          );
        }
      },
    );
  } catch {
    throw new NotificationDeliverySigningError();
  }
}
export async function prepareNotificationDeliverySigning(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
) {
  const existing = await withNotificationSigningHistory(pool, kernel, socket, value, (client, q) =>
    readNotificationSigningRecord(client, q),
  );
  if (existing) return existing;
  return withCurrentNotificationSigning(
    pool,
    kernel,
    socket,
    gate,
    value,
    async (client, q, p, signer, admission, source) => {
      const execute = async () => {
        const prior = await readNotificationSigningRecord(client, q, true);
        if (prior) return prior;
        const prepared = buildNotificationDeliverySigning({
          deliveryPreparation: p,
          sourceClaims: source.claims,
          trust: { signer: signer.pins, worker: admission.installation.input },
          receiptId: localOperationId(),
        });
        const bytes = Buffer.from(canonicalJson(prepared));
        await client.query(
          `insert into control.notification_delivery_signing(participant_id,privacy_domain_id,operation_id,signing_attempt_id,signer_installation_digest,request_digest,preparation,preparation_bytes,preparation_digest)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            q.source.worker.participantId,
            q.source.worker.privacyDomainId,
            q.operationId,
            prepared.request.signingAttemptId,
            q.signerInstallationDigest,
            prepared.requestDigest,
            prepared,
            bytes,
            sha256(bytes),
          ],
        );
        return (await readNotificationSigningRecord(client, q))!;
      };
      return lease === undefined
        ? execute()
        : withNotificationWorkerLease(client, q.source, lease, 'SIGN', async () => {
            return execute();
          });
    },
    lease,
  );
}
/** Caller receives claimed=true only after the real peer transaction COMMIT has
 * returned successfully. A thrown/uncertain commit cannot reach external perform. */
export async function claimNotificationDeliverySigning(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
): Promise<{
  claimed: boolean;
  record: NotificationDeliverySigningRecord;
  leaseWindow?: NotificationWorkerLeaseWindow;
}> {
  return withCurrentNotificationSigning(
    pool,
    kernel,
    socket,
    gate,
    value,
    async (client, q, p) => {
      const execute = async () => {
        const original = await readNotificationSigningRecord(client, q, true);
        if (!original) throw new NotificationDeliverySigningError();
        if (canonicalJson(original.preparation.deliveryPreparation) !== canonicalJson(p))
          throw new NotificationDeliverySigningError();
        if (original.state !== 'PREPARED') return { claimed: false, record: original };
        const token = localOperationId();
        const changed = await client.query(
          `update control.notification_delivery_signing set state='DISPATCHED',dispatch_token=$4,dispatched_at_ms=floor(extract(epoch from clock_timestamp())*1000)
      where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='PREPARED' returning operation_id`,
          [q.source.worker.participantId, q.source.worker.privacyDomainId, q.operationId, token],
        );
        if (changed.rowCount !== 1) throw new NotificationDeliverySigningError();
        return { claimed: true, record: (await readNotificationSigningRecord(client, q))! };
      };
      return lease === undefined
        ? execute()
        : withNotificationWorkerLease(client, q.source, lease, 'SIGN', async (window) => {
            return { ...(await execute()), leaseWindow: window };
          });
    },
    lease,
  );
}
/** First authenticated original observation only. Historical attachment cannot
 * create STARTED and deliberately does not require a still-live receipt deadline. */
export async function attachNotificationDeliverySigningObservation(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  observed: unknown,
) {
  return withNotificationSigningHistory(pool, kernel, socket, value, async (client, q) => {
    const row = await readNotificationSigningRecord(client, q, true);
    if (!row || row.state === 'PREPARED') throw new NotificationDeliverySigningError();
    const observation = notificationSigningObservation(
      row.preparation,
      observed,
      row.observation ?? undefined,
    );
    if (row.observation) return row;
    const bytes = Buffer.from(canonicalJson(observation));
    const updated = await client.query(
      `update control.notification_delivery_signing set state='OBSERVED',observation=$4,observation_bytes=$5,observation_digest=$6
      where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='DISPATCHED' returning operation_id`,
      [
        q.source.worker.participantId,
        q.source.worker.privacyDomainId,
        q.operationId,
        observation,
        bytes,
        sha256(bytes),
      ],
    );
    if (updated.rowCount !== 1) throw new NotificationDeliverySigningError();
    return (await readNotificationSigningRecord(client, q))!;
  });
}

/** Leased production entry; original API remains available to existing owners. */
export function prepareNotificationDeliverySigningLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
) {
  return prepareNotificationDeliverySigning(
    pool,
    kernel,
    socket,
    gate,
    value,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}

/** Leased production entry; original API remains available to existing owners. */
export function claimNotificationDeliverySigningLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  gate: NotificationPayloadReferenceGate,
  value: unknown,
) {
  return claimNotificationDeliverySigning(
    pool,
    kernel,
    socket,
    gate,
    value,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}
