import type { PoolClient } from 'pg';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import {
  assertNotificationWorkerAdmission,
  assertNotificationDeliveryWorkerAdmission,
  assertNotificationDeliveryWorkerCurrent,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { fenceNotificationKmsReference } from '../evidence/kms-installation.js';
import { inspectEvidenceKmsPrepareRequest } from '../evidence/kms-state.js';
import {
  verifyStoredEvidenceKmsStatus,
  verifyStoredEvidenceWrappedKey,
} from '../evidence/kms-contracts.js';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import { openVaultDirectory, readVaultFile } from '../evidence/immutable-vault.js';
import {
  decodeNotificationKeyPreparation,
  inspectNotificationKeyCiphertext,
  notificationKeyFile,
  type NotificationKeyPreparation,
} from '../evidence/notification-key-contracts.js';
import { evidenceKmsCoseProfiles } from '../../../../packages/security-kernel/src/evidence-kms/generated.js';
import { notificationWorkerSelector } from './worker-installation.js';
import { readPublishedNotificationSource } from './published-source.js';
import { withCurrentNotificationRouting } from './routing-installation.js';
import { renderEvidenceExportNotification } from './template-renderer.js';
import {
  notificationDeliverySourceSelector,
  readPublishedNotificationDeliveryRequest,
  type NotificationDeliverySourceSelector,
  type PublishedNotificationDeliveryRequest,
} from './delivery-source.js';

type CurrentReferenceRouting = Parameters<Parameters<typeof withCurrentNotificationRouting>[2]>[0];

export const notificationPayloadReferenceSelector = z.strictObject({
  worker: notificationWorkerSelector,
  keyPreparationId: z.uuidv7(),
});
export type NotificationPayloadReferenceSelector = z.infer<
  typeof notificationPayloadReferenceSelector
>;
export interface NotificationPayloadReference {
  readonly preparation: NotificationKeyPreparation;
  readonly reference: Readonly<{
    keyId: string;
    encryptionExchangeId: string;
    encryptedObjectDigest: string;
    encryptionContextDigest: string;
  }>;
  readonly custodyDigest: string;
  readonly workerProfileDigest: string;
  readonly workerAuthorityDigest: string;
}
/** Current delivery custody only; not publisher, plaintext or dispatch authority.
 * Later STARTED owners must join their genuine retained reservation to these
 * exact original source/object fields rather than passing a preparation DTO. */
export interface NotificationDeliveryPayloadReference extends NotificationPayloadReference {
  readonly deliverySource: PublishedNotificationDeliveryRequest['claims'];
  readonly deliverySourceReceiptDigest: string;
}
/** Only authorizes preparation of the original key use under retained fences.
 * This purpose is deliberately absent from deliveryActive: it is not full
 * current custody, a plaintext lease, STARTED or a gateway dispatch claim. */
export interface NotificationDeliveryMaterialStage extends NotificationDeliveryPayloadReference {
  readonly purpose: 'DELIVERY_UNWRAP_PREPARATION';
}
const materialActive = new WeakMap<
  object,
  { client: PoolClient; source: NotificationDeliverySourceSelector }
>();
export function assertNotificationDeliveryMaterialStage(
  stage: NotificationDeliveryMaterialStage,
  client: PoolClient,
  source: NotificationDeliverySourceSelector,
) {
  try {
    const selected = notificationDeliverySourceSelector.parse(immutableJsonCopy(source));
    const admitted = materialActive.get(stage);
    if (
      !admitted ||
      admitted.client !== client ||
      canonicalJson(admitted.source) !== canonicalJson(selected)
    )
      throw new Error();
  } catch {
    throw new NotificationPayloadReferenceError();
  }
}
export class NotificationPayloadReferenceError extends Error {
  constructor() {
    super('Notification payload reference unavailable');
  }
}
const active = new WeakMap<object, PoolClient>();
const deliveryActive = new WeakMap<
  object,
  { client: PoolClient; source: NotificationDeliverySourceSelector }
>();
/** Purpose-specific identity: neither a publisher reference nor copied/escaped
 * delivery metadata can satisfy this assertion, even with identical fields. */
export function assertNotificationDeliveryPayloadReference(
  reference: NotificationDeliveryPayloadReference,
  client: PoolClient,
  source: NotificationDeliverySourceSelector,
) {
  try {
    const selected = notificationDeliverySourceSelector.parse(immutableJsonCopy(source));
    const admitted = deliveryActive.get(reference);
    if (
      !admitted ||
      admitted.client !== client ||
      canonicalJson(admitted.source) !== canonicalJson(selected)
    )
      throw new Error();
  } catch {
    throw new NotificationPayloadReferenceError();
  }
}
/** Copied metadata or a value retained after the callback grants no publication. */
export function assertNotificationPayloadReference(
  reference: NotificationPayloadReference,
  client: PoolClient,
) {
  if (active.get(reference) !== client) throw new NotificationPayloadReferenceError();
}
const keyStateField = evidenceKmsCoseProfiles.EvidenceKmsReceiptV1.fields.find(
  (f) => f.name === 'keyState',
)!.key;

/** Trusted root supplies the vault. No provider call, signing, sealing, material,
 * transaction boundary or caller-selected readiness is introduced here. The
 * worker's transaction supplies its own occurrence/inbox/outbox/cursor writes.
 * A fresh STATUS must already have been acquired by the existing Evidence KMS
 * owner; its five-second signed validity is rechecked after the callback. */
export class NotificationPayloadReferenceGate {
  constructor(private readonly vaultDirectory: string) {}

  async withCurrent<T>(
    client: PoolClient,
    admission: NotificationWorkerAdmission,
    value: NotificationPayloadReferenceSelector,
    operation: (reference: NotificationPayloadReference) => Promise<T>,
  ): Promise<T> {
    try {
      const q = notificationPayloadReferenceSelector.parse(immutableJsonCopy(value));
      assertNotificationWorkerAdmission(admission, client, q.worker);
      if (
        admission.installation.profile.subscriptionId ===
        'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
      )
        throw new Error();
      return await this.withCustody(client, admission, q, async (reference) => {
        active.set(reference, client);
        try {
          return await operation(reference);
        } finally {
          active.delete(reference);
        }
      });
    } catch {
      throw new NotificationPayloadReferenceError();
    }
  }

  /** Separate delivery admission. The key selector is derived from the actual
   * signed PUBLISHED source, not accepted from the caller. No effective generation
   * or STARTED state is needed to check custody; neither is granted by this gate. */
  async withDeliveryCurrent<T>(
    client: PoolClient,
    admission: NotificationWorkerAdmission,
    value: NotificationDeliverySourceSelector,
    operation: (reference: NotificationDeliveryPayloadReference) => Promise<T>,
  ): Promise<T> {
    return this.withDeliverySource(client, admission, value, operation, true);
  }

  /** Retain lifecycle/source/routing/endpoint/Identity fences while the existing
   * KMS owner commits its distinct unwrap exchange on another connection. The
   * original attempt is inspected here without FOR UPDATE to avoid self-deadlock.
   * Re-enter withDeliveryCurrent AFTER unwrap commit, joining the exact original
   * stage, before consuming plaintext. The root retains configuration and
   * cancellation fences throughout; neither gate grants gateway dispatch. */
  async withDeliveryMaterialStage<T>(
    client: PoolClient,
    admission: NotificationWorkerAdmission,
    value: NotificationDeliverySourceSelector,
    operation: (stage: NotificationDeliveryMaterialStage) => Promise<T>,
  ): Promise<T> {
    try {
      const q = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
      return await this.withDeliverySource(
        client,
        admission,
        q,
        async (reference) => {
          await assertNotificationDeliveryWorkerCurrent(admission, client, q.worker);
          const stage = immutableJsonCopy({
            ...reference,
            purpose: 'DELIVERY_UNWRAP_PREPARATION' as const,
          });
          materialActive.set(stage, { client, source: q });
          try {
            return await operation(stage);
          } finally {
            materialActive.delete(stage);
          }
        },
        false,
      );
    } catch {
      throw new NotificationPayloadReferenceError();
    }
  }

  private async withDeliverySource<T>(
    client: PoolClient,
    admission: NotificationWorkerAdmission,
    value: NotificationDeliverySourceSelector,
    operation: (reference: NotificationDeliveryPayloadReference) => Promise<T>,
    lockOriginal: boolean,
  ): Promise<T> {
    try {
      const q = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
      assertNotificationDeliveryWorkerAdmission(admission, client, q.worker);
      if (!lockOriginal) await assertNotificationDeliveryWorkerCurrent(admission, client, q.worker);
      return await this.protected(client, async () => {
        await lockEvidenceLifecycle(client, q.worker.participantId, q.worker.privacyDomainId);
        const source = await readPublishedNotificationDeliveryRequest(client, admission, q);
        return this.withCustody(
          client,
          admission,
          { worker: q.worker, keyPreparationId: source.claims.keyPreparationId },
          async (reference, route) => {
            const current = async () => {
              assertNotificationDeliveryWorkerAdmission(admission, client, q.worker);
              if (!lockOriginal)
                await assertNotificationDeliveryWorkerCurrent(admission, client, q.worker);
              const checked = await readPublishedNotificationDeliveryRequest(client, admission, q);
              if (
                checked.sourceReceiptDigest !== source.sourceReceiptDigest ||
                !checked.receiptPayload.equals(source.receiptPayload) ||
                !checked.coseSign1.equals(source.coseSign1)
              )
                throw new Error();
              this.bindDeliverySource(checked, reference, route);
            };
            await current();
            const admitted = immutableJsonCopy({
              ...reference,
              deliverySource: source.claims,
              deliverySourceReceiptDigest: source.sourceReceiptDigest,
            });
            if (lockOriginal) deliveryActive.set(admitted, { client, source: q });
            try {
              const result = await operation(admitted);
              await current();
              return result;
            } finally {
              deliveryActive.delete(admitted);
            }
          },
          lockOriginal,
        );
      });
    } catch {
      throw new NotificationPayloadReferenceError();
    }
  }

  private bindDeliverySource(
    source: PublishedNotificationDeliveryRequest,
    reference: NotificationPayloadReference,
    route: CurrentReferenceRouting,
  ) {
    const c = source.claims,
      p = reference.preparation,
      o = p.objectIntent;
    if (
      c.environmentId !== o.environmentId ||
      c.participantId !== o.participantId ||
      c.privacyDomainId !== o.privacyDomainId ||
      c.keyPreparationId !== p.preparationId ||
      c.notificationOccurrenceId !== p.occurrenceId ||
      c.payloadObjectId !== o.payloadObjectId ||
      c.payloadDigest !== o.payloadDigest ||
      c.templateDigest !== o.templateDigest ||
      c.routingProfileDigest !== o.routingProfileDigest ||
      c.sourceEventId !== p.sourceEventId ||
      c.sourceDataDigest !== p.sourceDataDigest ||
      c.sourceReceiptDigest !== p.sourceReceiptDigest ||
      c.keyId !== reference.reference.keyId ||
      c.encryptedObjectDigest !== reference.reference.encryptedObjectDigest ||
      c.custodyDigest !== reference.custodyDigest ||
      c.endpointId !== route.endpoint.endpointId ||
      c.endpointRevision !== route.endpoint.revision ||
      route.endpoint.channelProfileDigest !== route.channel.channel.signedProfileDigest ||
      route.endpoint.credentialRef !== route.channel.credential.credentialRef ||
      route.endpoint.channel !== route.channel.credential.channel ||
      route.endpoint.destinationRef !== route.channel.credential.destinationRef
    )
      throw new NotificationPayloadReferenceError();
  }

  /** Shared mechanics only, unreachable without an explicit public entry check.
   * One STATUS/vault/original-request implementation for both distinct purposes. */
  private async withCustody<T>(
    client: PoolClient,
    admission: NotificationWorkerAdmission,
    q: NotificationPayloadReferenceSelector,
    operation: (
      reference: NotificationPayloadReference,
      route: CurrentReferenceRouting,
    ) => Promise<T>,
    lockOriginal = true,
  ): Promise<T> {
    return this.protected(client, async () => {
      assertNotificationWorkerAdmission(admission, client, q.worker);
      const profile = admission.installation.profile;
      await lockEvidenceLifecycle(client, q.worker.participantId, q.worker.privacyDomainId);
      const rows = await client.query<{
        preparation_bytes: Buffer;
        preparation_digest: string;
        key_id: string;
        encryption_exchange_id: string;
        encrypted_object_digest: string;
        encryption_context_digest: string;
      }>(
        `select p.preparation_bytes,p.preparation_digest,c.key_id,c.encryption_exchange_id,
        c.encrypted_object_digest,c.encryption_context_digest from control.notification_key_preparation p
        join control.notification_key_ciphertext c using(participant_id,privacy_domain_id,preparation_id)
        where p.participant_id=$1 and p.privacy_domain_id=$2 and p.preparation_id=$3`,
        [q.worker.participantId, q.worker.privacyDomainId, q.keyPreparationId],
      );
      if (rows.rowCount !== 1) throw new Error();
      const row = rows.rows[0]!,
        p = decodeNotificationKeyPreparation(row.preparation_bytes, row.preparation_digest);
      if (
        p.preparationId !== q.keyPreparationId ||
        p.input.scope.participantId !== q.worker.participantId ||
        p.input.scope.privacyDomainId !== q.worker.privacyDomainId ||
        p.input.producerTrustDigest !== profile.producerTrustDigest ||
        p.input.kmsInstallationDigest !== profile.kmsInstallationDigest ||
        p.input.routing.signedProfileDigest !== profile.routingProfileDigest ||
        p.objectIntent.environmentId !== profile.environmentId
      )
        throw new Error();
      const pins = await fenceNotificationKmsReference(client, admission, q.worker);
      if (canonicalJson(pins.pins) !== canonicalJson(p.kms)) throw new Error();
      // Same original-attempt lock used by every KMS exchange transition. New
      // dispatch/observations cannot race this reference transaction.
      const attempts = await client.query<{
        state: string;
        request_bytes: Buffer;
        request_digest: string;
        object_intent_digest: string;
        installation_digest: string;
      }>(
        `select state,request_bytes,request_digest,object_intent_digest,installation_digest
        from control.evidence_kms_attempt where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3${lockOriginal ? ' for update' : ''}`,
        [q.worker.participantId, q.worker.privacyDomainId, p.preparationId],
      );
      if (attempts.rowCount !== 1) throw new Error();
      const a = attempts.rows[0]!,
        original = inspectEvidenceKmsPrepareRequest(a.request_bytes);
      if (
        a.state !== 'PROVED' ||
        a.installation_digest !== p.input.kmsInstallationDigest ||
        sha256(a.request_bytes) !== a.request_digest ||
        a.object_intent_digest !== sha256(p.objectIntent) ||
        original.attemptId !== p.preparationId ||
        canonicalJson(original.objectIntent) !== canonicalJson(p.objectIntent) ||
        canonicalJson(original.recipient) !==
          canonicalJson({
            // Authenticate the original Evidence producer independently of the
            // current notification worker; never relabel the original request.
            participantId: p.input.scope.participantId,
            privacyDomainId: p.input.scope.privacyDomainId,
            producerTrustDigest: p.input.producerTrustDigest,
            installationDigest: p.input.kmsInstallationDigest,
          })
      )
        throw new Error();
      const keys = await client.query<{ record_bytes: Buffer; record_cose: Buffer }>(
        `select record_bytes,record_cose from control.evidence_wrapped_key where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and key_id=$4`,
        [q.worker.participantId, q.worker.privacyDomainId, p.preparationId, row.key_id],
      );
      if (keys.rowCount !== 1) throw new Error();
      verifyStoredEvidenceWrappedKey(keys.rows[0]!.record_bytes, keys.rows[0]!.record_cose, p.kms, {
        attemptId: p.preparationId,
        originalRequestDigest: a.request_digest,
        objectIntentDigest: a.object_intent_digest,
        keyId: row.key_id,
      });
      const source = await readPublishedNotificationSource(client, {
        scope: p.input.scope,
        evidenceExportId: p.input.evidenceExportId,
        eventId: p.sourceEventId,
      });
      if (
        source.claims.dataDigest !== p.sourceDataDigest ||
        sha256(source.payload) !== p.sourceReceiptDigest
      )
        throw new Error();
      const result = await withCurrentNotificationRouting(
        client,
        {
          participantId: q.worker.participantId,
          privacyDomainId: q.worker.privacyDomainId,
          ...p.input.routing,
          producerTrustDigest: p.input.producerTrustDigest,
        },
        async (route) => {
          const rendered = renderEvidenceExportNotification(route.input, source.envelope.data);
          try {
            if (
              route.installationDigest !== p.routingInstallationDigest ||
              route.route.claims.payloadKeyPolicyDigest !== p.kms.policyDigest ||
              rendered.payloadDigest !== p.objectIntent.payloadDigest ||
              route.route.claims.environmentId !== profile.environmentId ||
              route.route.claims.templateDigest !== p.objectIntent.templateDigest ||
              route.route.claims.recipientSetDigest !== p.objectIntent.recipientSetDigest ||
              route.route.claims.redactionProfileDigest !== p.objectIntent.redactionProfileDigest ||
              String(route.route.claims.preferenceGeneration) !==
                p.objectIntent.preferenceGeneration
            )
              throw new Error();
          } finally {
            rendered.bytes.fill(0);
          }
          const reference = immutableJsonCopy({
            keyId: row.key_id,
            encryptionExchangeId: row.encryption_exchange_id,
            encryptedObjectDigest: row.encrypted_object_digest,
            encryptionContextDigest: row.encryption_context_digest,
          });
          const verifyBytes = async () => {
            const bytes = await readVaultFile(
              await openVaultDirectory(this.vaultDirectory),
              notificationKeyFile(p),
              131072,
            );
            const actual = inspectNotificationKeyCiphertext(p, reference.keyId, bytes);
            if (
              actual.encryptedObjectDigest !== reference.encryptedObjectDigest ||
              actual.encryptionContextDigest !== reference.encryptionContextDigest
            )
              throw new Error();
          };
          const current = async () => {
            assertNotificationWorkerAdmission(admission, client, q.worker);
            await fenceNotificationKmsReference(client, admission, q.worker);
            await this.status(client, p, a.request_digest, reference.keyId);
            await verifyBytes();
          };
          await current();
          const admitted = immutableJsonCopy({
            preparation: p,
            reference,
            custodyDigest: sha256({ preparationDigest: row.preparation_digest, ...reference }),
            workerProfileDigest: admission.installation.input.pins.signedProfileDigest,
            workerAuthorityDigest: admission.authorityDigest,
          });
          const result = await operation(admitted, route);
          await current();
          return result;
        },
      );
      return result;
    });
  }

  private async protected<T>(client: PoolClient, operation: () => Promise<T>): Promise<T> {
    const savepoint = `notification_reference_${randomBytes(8).toString('hex')}`;
    let entered = false;
    try {
      await client.query(`savepoint ${savepoint}`);
      entered = true;
      const result = await operation();
      await client.query(`release savepoint ${savepoint}`);
      return result;
    } catch {
      // Caught errors cannot retain callback writes after a final freshness or
      // integrity failure. Failed transactions still belong to their outer owner.
      if (entered) {
        try {
          await client.query(`rollback to savepoint ${savepoint}`);
          await client.query(`release savepoint ${savepoint}`);
        } catch {
          /* The outer owner must roll back a failed transaction. */
        }
      }
      throw new NotificationPayloadReferenceError();
    }
  }

  private async status(
    client: PoolClient,
    p: NotificationKeyPreparation,
    originalRequestDigest: string,
    keyId: string,
  ) {
    const scope = [p.input.scope.participantId, p.input.scope.privacyDomainId, p.preparationId];
    const blocked = await client.query(
      `select 1 from control.evidence_kms_exchange e
      where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and (
      (state in ('PREPARED','DISPATCHED','UNKNOWN') and not exists(
        select 1 from control.evidence_kms_exchange r where r.participant_id=e.participant_id
        and r.privacy_domain_id=e.privacy_domain_id and r.attempt_id=e.attempt_id and r.kind='READ_ATTEMPT'
        and r.state='PROVED' and openpc.evidence_kms_stored_outcome(r.receipt_bytes) in ('1','2')
        and convert_from(r.request_bytes,'UTF8')::jsonb->>'readExchangeId'=e.exchange_id::text
        and convert_from(r.request_bytes,'UTF8')::jsonb->>'readRequestDigest'=e.request_digest))
      or (receipt_bytes is not null and openpc.business_cbor(decode(convert_from(receipt_bytes,'UTF8')::jsonb->'receipt'->>'payloadHex','hex'))->>'${keyStateField}' in ('3','4')))
      limit 1`,
      scope,
    );
    if (blocked.rowCount) throw new Error();
    const rows = await client.query<{
      exchange_id: string;
      challenge: string;
      request_bytes: Buffer;
      request_digest: string;
      receipt_bytes: Buffer;
      receipt_digest: string;
    }>(
      `select exchange_id,challenge,request_bytes,request_digest,receipt_bytes,receipt_digest
      from control.evidence_kms_exchange where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3
      and kind='STATUS' and state='PROVED' order by provider_sequence desc,exchange_id desc limit 1`,
      scope,
    );
    if (rows.rowCount !== 1) throw new Error();
    const s = rows.rows[0]!;
    const expectedRequest = {
      operation: 'STATUS',
      exchangeId: s.exchange_id,
      attemptId: p.preparationId,
      recipient: {
        participantId: scope[0],
        privacyDomainId: scope[1],
        producerTrustDigest: p.input.producerTrustDigest,
        installationDigest: p.input.kmsInstallationDigest,
      },
      originalRequestDigest,
      objectIntentDigest: sha256(p.objectIntent),
      keyId,
      keyUse: 'NONE',
      challenge: s.challenge,
    };
    if (
      !s.request_bytes.equals(Buffer.from(canonicalJson(expectedRequest))) ||
      sha256(s.request_bytes) !== s.request_digest ||
      sha256(s.receipt_bytes) !== s.receipt_digest
    )
      throw new Error();
    const floors = await client.query<{ sequence: string; floor: string; now_ms: string }>(
      `select coalesce(max(e.provider_sequence),1)::text sequence,coalesce(max(e.recovery_floor),1)::text floor,
      floor(extract(epoch from clock_timestamp())*1000)::text now_ms from control.evidence_kms_exchange e
      join control.evidence_kms_attempt a using(participant_id,privacy_domain_id,attempt_id)
      join control.evidence_kms_installation i using(participant_id,privacy_domain_id,installation_digest)
      where e.participant_id=$1 and e.privacy_domain_id=$2 and i.pins->>'providerId'=$3
      and i.pins->>'providerKeyId'=$4 and i.pins->>'providerKeyVersion'=$5`,
      [scope[0], scope[1], p.kms.providerId, p.kms.providerKeyId, p.kms.providerKeyVersion],
    );
    if (floors.rowCount !== 1) throw new Error();
    verifyStoredEvidenceKmsStatus(s.receipt_bytes, p.kms, {
      operation: 'STATUS',
      attemptId: p.preparationId,
      exchangeId: s.exchange_id,
      requestDigest: s.request_digest,
      originalRequestDigest,
      objectIntentDigest: sha256(p.objectIntent),
      challenge: s.challenge,
      keyId,
      keyUse: 'NONE',
      nowMs: Number(floors.rows[0]!.now_ms),
      minimumSequence: floors.rows[0]!.sequence,
      minimumRecoveryFloor: floors.rows[0]!.floor,
    });
  }
}
