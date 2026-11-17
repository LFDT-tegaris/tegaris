import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../../../control-api/src/configuration/digest.js';
import { readNotificationCompletionSigningInTransaction } from '../../../control-api/src/notifications/completion-disposition-state.js';
import { validateNotificationCompletionDispositionSignerInstallation } from '../../../control-api/src/notifications/completion-disposition-signer.js';
import type { NotificationCompletionWorkerSelector } from '../../../control-api/src/notifications/completion-worker-installation.js';
import { NotificationCompletionWorkerAdmissionError } from '../../../control-api/src/notifications/completion-worker-installation-contract.js';
import {
  validateNotificationCompletionDispositionObservation,
  validateNotificationCompletionDispositionRequest,
} from './notification-completion-disposition-provider.js';

/** Cryptographic verification and immutable installed provenance only. This
 * result is not an admission capability; only the private live-TLS owner can
 * bind it to an event/phase and attest it to PostgreSQL. No supplied signer,
 * original request, key or success flag is accepted from the caller. */
export async function verifyNotificationCompletionReceiptInTransaction(
  client: PoolClient,
  worker: NotificationCompletionWorkerSelector,
  eventId: string,
  phase: 'OBSERVE' | 'PUBLISH',
  observation: unknown,
) {
  await client.query('select openpc.assert_notification_completion_disposition_shared_owner()');
  const args = [worker.participantId, worker.privacyDomainId, eventId];
  const lock = await client.query<{ allowed: boolean }>(
    "select pg_try_advisory_xact_lock(hashtextextended('notification-completion-source:'||$1::text||':'||$2::text||':'||$3::text,0)) allowed",
    args,
  );
  if (lock.rows[0]?.allowed !== true) throw new NotificationCompletionWorkerAdmissionError();
  const rows = await client.query<{ operation_id: string }>(
    'select operation_id::text from control.notification_completion_disposition_signing where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
    args,
  );
  if (rows.rowCount !== 1) throw new NotificationCompletionWorkerAdmissionError();
  const record = await readNotificationCompletionSigningInTransaction(client, {
    worker,
    eventId,
    operationId: rows.rows[0]!.operation_id,
  });
  if (
    !record ||
    record.state === 'PREPARED' ||
    (phase === 'PUBLISH' && record.state !== 'OBSERVED')
  )
    throw new NotificationCompletionWorkerAdmissionError();
  const pins = z
    .object({ signerInstallation: z.unknown(), workerInstallation: z.unknown() })
    .parse(record.preparation.preparation);
  const trust = { signer: pins.signerInstallation, worker: pins.workerInstallation };
  const bound = validateNotificationCompletionDispositionRequest(record.preparation.request, trust);
  const observed = validateNotificationCompletionDispositionObservation(
    bound.request,
    observation,
    trust,
    record.observation ?? undefined,
  );
  if (observed.outcome !== 'SIGNED' || observed.recordedAtMs < record.dispatchedAtMs!)
    throw new NotificationCompletionWorkerAdmissionError();
  // Stored preparation cannot invent its own trusted key. Require the exact
  // privileged installation bytes; withdrawal does not erase historical trust.
  const trustFence = await client.query<{ allowed: boolean }>(
    "select pg_try_advisory_xact_lock_shared(hashtextextended('notification-completion-disposition-signer:'||$1::text||':'||$2::text,0)) allowed",
    [worker.participantId, worker.privacyDomainId],
  );
  if (trustFence.rows[0]?.allowed !== true) throw new NotificationCompletionWorkerAdmissionError();
  // Existing source/signer/worker guards take these same fences. Keep runtime
  // access read-only; PostgreSQL row locking would require UPDATE privileges
  // on the privileged installation tables.
  const installed = await client.query<{
    trust_bytes: Buffer;
    trust_digest: string;
    state: string;
    installation_bytes: Buffer;
    installation_digest: string;
  }>(
    `select s.trust_bytes,s.trust_digest,s.state,w.installation_bytes,w.installation_digest
     from control.notification_completion_disposition_signer_installation s
     join control.installed_notification_completion_worker w on w.participant_id=s.participant_id
      and w.privacy_domain_id=s.privacy_domain_id and w.installation_digest=s.worker_installation_digest
     where s.participant_id=$1 and s.privacy_domain_id=$2 and s.trust_digest=$3`,
    [worker.participantId, worker.privacyDomainId, bound.signer.digest],
  );
  const row = installed.rows[0];
  if (
    installed.rowCount !== 1 ||
    !row ||
    !['ACTIVE', 'REVOKED'].includes(row.state) ||
    row.trust_digest !== bound.signer.digest ||
    !row.trust_bytes.equals(bound.signer.bytes) ||
    row.installation_digest !== bound.worker.installationDigest ||
    !row.installation_bytes.equals(bound.worker.bytes)
  )
    throw new NotificationCompletionWorkerAdmissionError();
  // Reconstruct from the existing canonical signer verifier, never from a
  // database framing check or caller-provided verification result.
  const signer = validateNotificationCompletionDispositionSignerInstallation(trust.signer);
  return Object.freeze({
    schema: 'pc.notification.completion-verified-receipt.v1' as const,
    purpose: signer.pins.purpose,
    requestDigest: bound.requestDigest,
    preparationDigest: bound.request.dispositionPreparationDigest,
    payloadDigest: sha256(bound.payload),
    coseDigest: sha256(Buffer.from(observed.coseHex!, 'hex')),
    observationDigest: sha256(Buffer.from(canonicalJson(observed))),
    signerInstallationDigest: signer.digest,
    signerKeyId: signer.signerKeyId,
    originalWorkerInstallationDigest: bound.worker.installationDigest,
    producerTrustDigest: bound.worker.profile.producerTrustDigest,
    environmentId: bound.worker.profile.environmentId,
  });
}
