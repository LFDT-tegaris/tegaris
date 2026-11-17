import { isAsyncFunction } from 'node:util/types';
import { performance } from 'node:perf_hooks';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { withEvidenceKeyRecipient } from '../../../identity-service/src/domain/evidence-key-recipient.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { withCurrentNotificationRouting } from '../notifications/routing-installation.js';
import { readPublishedNotificationSource } from '../notifications/published-source.js';
import { renderEvidenceExportNotification } from '../notifications/template-renderer.js';
import {
  decodeNotificationOccurrencePreparation,
  verifyNotificationOccurrenceObservation,
} from '../notifications/occurrence-contract.js';
import { EvidenceKmsRuntime, type EvidenceKmsTlsMaterial } from './kms-runtime.js';
import { inspectEvidenceKmsPrepareRequest } from './kms-state.js';
import { EvidenceKmsError, verifyStoredEvidenceWrappedKey } from './kms-contracts.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { openVaultDirectory, readVaultFile } from './immutable-vault.js';
import { openNotificationPayload } from './notification-payload-crypto.js';
import {
  NotificationKeyCustodyError,
  notificationKeySelector,
  parseNotificationKey,
  decodeNotificationKeyPreparation,
  assertNotificationKeySelector,
  notificationKeyFile,
  inspectNotificationKeyCiphertext,
  type NotificationKeySelector,
} from './notification-key-contracts.js';

function reject(): never {
  throw new NotificationKeyCustodyError('UNAVAILABLE');
}
const recipient = (q: NotificationKeySelector) => ({
  participantId: q.participantId,
  privacyDomainId: q.privacyDomainId,
  producerTrustDigest: q.producerTrustDigest,
  installationDigest: q.kmsInstallationDigest,
});

/** Memory discipline only, NOT an admission or decryption API. The owning
 * reader invokes this only after its real authorization and KMS checks. */
export function consumeNotificationPayloadLocally(
  plaintext: Buffer,
  signal: AbortSignal,
  deadline: number,
  consume: (plaintext: Buffer) => undefined,
): void {
  try {
    if (
      !Buffer.isBuffer(plaintext) ||
      plaintext.length < 1 ||
      plaintext.length > 65536 ||
      !(signal instanceof AbortSignal) ||
      signal.aborted ||
      !Number.isFinite(deadline) ||
      performance.now() >= deadline ||
      typeof consume !== 'function' ||
      isAsyncFunction(consume)
    )
      reject();
    const returned: unknown = consume(plaintext);
    if (returned !== undefined) {
      if (
        returned !== null &&
        (typeof returned === 'object' || typeof returned === 'function') &&
        'then' in returned
      )
        void Promise.resolve(returned).catch(() => undefined);
      reject();
    }
    if (signal.aborted || performance.now() >= deadline) reject();
  } finally {
    if (Buffer.isBuffer(plaintext)) plaintext.fill(0);
  }
}

/** Evidence-owned local consumption only. Root supplies the actual Evidence
 * producer TLS peer and KMS TLS owner separately from any notification worker.
 * No endpoint, delivery, STARTED, disclosure-to-worker or retirement authority
 * is conferred. The internal callback MUST perform synchronous local work only;
 * no network, serialization, retained copies or detached work is permitted.
 * Identity/SQL fences have ended before this callback. These completed checks
 * are not a serialized live-authority lease and cannot authorize later delivery.
 * JavaScript cannot prevent a trusted callback from deliberately copying bytes.
 */
export class NotificationPayloadReader {
  private readonly kms: EvidenceKmsRuntime;
  constructor(
    private readonly pool: Pool,
    private readonly kernel: IdentityKernel,
    tls: EvidenceKmsTlsMaterial,
    private readonly vaultDirectory: string,
  ) {
    this.kms = new EvidenceKmsRuntime(pool, kernel, tls);
  }

  private async original(client: PoolClient, q: NotificationKeySelector) {
    const result = await client.query<{
      preparation_bytes: Buffer;
      preparation_digest: string;
      key_id: string;
      encrypted_object_digest: string;
      encryption_context_digest: string;
      request_bytes: Buffer;
      request_digest: string;
      object_intent_digest: string;
      installation_digest: string;
      state: string;
      record_bytes: Buffer;
      record_cose: Buffer;
    }>(
      `select p.preparation_bytes,p.preparation_digest,c.key_id,c.encrypted_object_digest,
       c.encryption_context_digest,a.request_bytes,a.request_digest,a.object_intent_digest,
       a.installation_digest,a.state,k.record_bytes,k.record_cose
       from control.notification_key_preparation p
       join control.notification_key_ciphertext c using(participant_id,privacy_domain_id,preparation_id)
       join control.evidence_kms_attempt a on a.participant_id=p.participant_id
        and a.privacy_domain_id=p.privacy_domain_id and a.attempt_id=p.preparation_id
       join control.evidence_wrapped_key k on k.participant_id=a.participant_id
        and k.privacy_domain_id=a.privacy_domain_id and k.attempt_id=a.attempt_id and k.key_id=c.key_id
       where p.participant_id=$1 and p.privacy_domain_id=$2 and p.preparation_id=$3
       and exists(select 1 from control.evidence_kms_exchange e
        where e.participant_id=p.participant_id and e.privacy_domain_id=p.privacy_domain_id
         and e.attempt_id=p.preparation_id and e.exchange_id=c.encryption_exchange_id and e.kind='UNWRAP'
         and convert_from(e.request_bytes,'UTF8')::jsonb->>'keyUse'='ENCRYPT'
         and convert_from(e.request_bytes,'UTF8')::jsonb->>'keyId'=c.key_id
         and ((e.state='PROVED' and openpc.evidence_kms_stored_outcome(e.receipt_bytes)='1') or exists(
          select 1 from control.evidence_kms_exchange r where r.participant_id=e.participant_id
           and r.privacy_domain_id=e.privacy_domain_id and r.attempt_id=e.attempt_id
           and r.kind='READ_ATTEMPT' and r.state='PROVED'
           and openpc.evidence_kms_stored_outcome(r.receipt_bytes)='1'
           and convert_from(r.request_bytes,'UTF8')::jsonb->>'readExchangeId'=e.exchange_id::text
           and convert_from(r.request_bytes,'UTF8')::jsonb->>'readRequestDigest'=e.request_digest)))
       for share of a`,
      [q.participantId, q.privacyDomainId, q.preparationId],
    );
    if (result.rowCount !== 1) reject();
    const row = result.rows[0]!,
      preparation = decodeNotificationKeyPreparation(row.preparation_bytes, row.preparation_digest),
      original = inspectEvidenceKmsPrepareRequest(row.request_bytes);
    assertNotificationKeySelector(preparation, q);
    if (
      row.state !== 'PROVED' ||
      row.installation_digest !== q.kmsInstallationDigest ||
      sha256(row.request_bytes) !== row.request_digest ||
      row.object_intent_digest !== sha256(preparation.objectIntent) ||
      original.attemptId !== q.preparationId ||
      canonicalJson(original.recipient) !== canonicalJson(recipient(q)) ||
      canonicalJson(original.objectIntent) !== canonicalJson(preparation.objectIntent)
    )
      reject();
    verifyStoredEvidenceWrappedKey(row.record_bytes, row.record_cose, preparation.kms, {
      attemptId: q.preparationId,
      originalRequestDigest: row.request_digest,
      objectIntentDigest: row.object_intent_digest,
      keyId: row.key_id,
    });
    const bytes = await readVaultFile(
      await openVaultDirectory(this.vaultDirectory),
      notificationKeyFile(preparation),
      131072,
    );
    const inspected = inspectNotificationKeyCiphertext(preparation, row.key_id, bytes);
    if (
      inspected.encryptedObjectDigest !== row.encrypted_object_digest ||
      inspected.encryptionContextDigest !== row.encryption_context_digest
    )
      reject();
    return {
      preparation,
      keyId: row.key_id,
      bytes,
      encryptedObjectDigest: row.encrypted_object_digest,
    };
  }

  private async current(socket: TLSSocket, q: NotificationKeySelector) {
    return withEvidenceKeyRecipient(
      this.pool,
      this.kernel,
      socket,
      recipient(q),
      'DECRYPT',
      async (client, admission) => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        try {
          await lockEvidenceLifecycle(client, q.participantId, q.privacyDomainId);
          const original = await this.original(client, q),
            p = original.preparation;
          if (canonicalJson(admission.installation.pins) !== canonicalJson(p.kms)) reject();
          const source = await readPublishedNotificationSource(client, {
            scope: p.input.scope,
            evidenceExportId: p.input.evidenceExportId,
            eventId: p.sourceEventId,
          });
          if (
            source.claims.dataDigest !== p.sourceDataDigest ||
            sha256(source.payload) !== p.sourceReceiptDigest
          )
            reject();
          await withCurrentNotificationRouting(
            client,
            {
              participantId: q.participantId,
              privacyDomainId: q.privacyDomainId,
              ...p.input.routing,
              producerTrustDigest: q.producerTrustDigest,
            },
            async (route) => {
              const rendered = renderEvidenceExportNotification(route.input, source.envelope.data);
              try {
                if (
                  route.installationDigest !== p.routingInstallationDigest ||
                  rendered.payloadDigest !== p.objectIntent.payloadDigest ||
                  route.route.claims.payloadKeyPolicyDigest !== p.kms.policyDigest ||
                  route.route.claims.environmentId !== p.objectIntent.environmentId ||
                  route.route.claims.templateDigest !== p.objectIntent.templateDigest ||
                  route.route.claims.recipientSetDigest !== p.objectIntent.recipientSetDigest ||
                  route.route.claims.redactionProfileDigest !==
                    p.objectIntent.redactionProfileDigest ||
                  String(route.route.claims.preferenceGeneration) !==
                    p.objectIntent.preferenceGeneration
                )
                  reject();
              } finally {
                rendered.bytes.fill(0);
              }
            },
          );
          // Custody may precede occurrence publication. If consumer state exists,
          // require the original signed publication, never repair partial effects.
          const occurrence = await client.query(
            `select 1 from control.notification_occurrence where participant_id=$1 and privacy_domain_id=$2
             and (notification_occurrence_id=$3 or payload_object_id=$4)
             union all select 1 from control.notification_payload where participant_id=$1 and privacy_domain_id=$2
             and (payload_object_id=$4 or key_preparation_id=$5)
             union all select 1 from control.notification_payload_object where participant_id=$1 and privacy_domain_id=$2 and payload_object_id=$4`,
            [
              q.participantId,
              q.privacyDomainId,
              p.occurrenceId,
              p.objectIntent.payloadObjectId,
              q.preparationId,
            ],
          );
          if (occurrence.rowCount) {
            const proofs = await client.query<{
              preparation_bytes: Buffer;
              preparation_digest: string;
              cose_sign1: Buffer;
            }>(
              `select p.preparation_bytes,p.preparation_digest,o.cose_sign1
               from control.notification_occurrence_preparation p
               join control.notification_occurrence_observation o using(participant_id,privacy_domain_id,preparation_id)
               where p.participant_id=$1 and p.privacy_domain_id=$2 and p.key_preparation_id=$3
               and p.family='NotificationDeliveryRequestedReceiptV1' and p.state='OBSERVED'`,
              [q.participantId, q.privacyDomainId, q.preparationId],
            );
            if (proofs.rowCount !== 1) reject();
            const proof = proofs.rows[0]!,
              prepared = decodeNotificationOccurrencePreparation(
                proof.preparation_bytes,
                proof.preparation_digest,
              );
            const { claims } = verifyNotificationOccurrenceObservation(prepared, proof.cose_sign1);
            if (
              !('eventId' in claims) ||
              prepared.input.keyPreparationId !== q.preparationId ||
              claims.notificationOccurrenceId !== p.occurrenceId ||
              claims.payloadObjectId !== p.objectIntent.payloadObjectId ||
              claims.payloadDigest !== p.objectIntent.payloadDigest
            )
              reject();
            const published = await client.query(
              `select openpc.check_notification_delivery_requested_event(e) from control.outbox_event e
               where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
              [q.participantId, q.privacyDomainId, claims.eventId],
            );
            if (published.rowCount !== 1) reject();
          }
          return original;
        } finally {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          );
        }
      },
    );
  }

  async consume(
    socket: TLSSocket,
    value: unknown,
    signal: AbortSignal,
    consume: (plaintext: Buffer) => undefined,
  ): Promise<void> {
    const q = parseNotificationKey(notificationKeySelector, value);
    if (
      !(signal instanceof AbortSignal) ||
      signal.aborted ||
      typeof consume !== 'function' ||
      isAsyncFunction(consume)
    )
      reject();
    let plaintext: Buffer | undefined;
    let deadline = 0;
    let expiry: ReturnType<typeof setTimeout> | undefined;
    const erase = () => {
      plaintext?.fill(0);
    };
    signal.addEventListener('abort', erase, { once: true });
    try {
      const original = await this.current(socket, q);
      if (signal.aborted) reject();
      await this.kms.withObjectKey(
        socket,
        {
          recipient: recipient(q),
          attemptId: q.preparationId,
          keyId: original.keyId,
          use: 'DECRYPT',
        },
        signal,
        (material) => {
          if (signal.aborted || material.signal.aborted) reject();
          plaintext = openNotificationPayload(
            original.bytes,
            original.encryptedObjectDigest,
            { ...original.preparation.objectIntent, keyId: original.keyId },
            material,
          );
          // A local buffer lifetime bound, not renewal of the KMS material lease.
          const remaining = Math.min(1000, original.preparation.kms.validUntilMs - Date.now());
          if (remaining <= 0) reject();
          deadline = performance.now() + remaining;
          expiry = setTimeout(erase, remaining);
          expiry.unref();
          return undefined;
        },
      );
      const checked = await this.current(socket, q);
      if (
        !plaintext ||
        signal.aborted ||
        performance.now() >= deadline ||
        checked.keyId !== original.keyId ||
        !checked.bytes.equals(original.bytes) ||
        canonicalJson(checked.preparation) !== canonicalJson(original.preparation) ||
        sha256(plaintext) !== original.preparation.objectIntent.payloadDigest
      )
        reject();
      // Both Identity transactions and the KMS receipt commit have completed.
      // This is local Evidence consumption, never an external dispatch window.
      consumeNotificationPayloadLocally(plaintext, signal, deadline, consume);
    } catch (error) {
      // Includes provider/COMMIT uncertainty. No raw SQL, peer or payload detail.
      throw new NotificationKeyCustodyError(
        error instanceof EvidenceKmsError && error.code === 'UNKNOWN' ? 'UNKNOWN' : 'UNAVAILABLE',
      );
    } finally {
      clearTimeout(expiry);
      signal.removeEventListener('abort', erase);
      erase();
    }
  }
}
