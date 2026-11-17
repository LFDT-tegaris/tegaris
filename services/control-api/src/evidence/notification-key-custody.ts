import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import { withEvidenceKeyRecipient } from '../../../identity-service/src/domain/evidence-key-recipient.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  withCurrentNotificationRouting,
  readInstalledNotificationRouting,
} from '../notifications/routing-installation.js';
import { renderEvidenceExportNotification } from '../notifications/template-renderer.js';
import { readEvidenceExportCompletionSource } from './export-completion-source.js';
import { readPreparedEvidenceExportCompletion } from './export-completion.js';
import { EvidenceKmsRuntime, type EvidenceKmsTlsMaterial } from './kms-runtime.js';
import { readNotificationPayloadRetirementSource } from './notification-payload-retirement-source.js';
import { EvidenceKmsError } from './kms-contracts.js';
import type { EvidenceKmsCiphertext } from './kms-state.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { openVaultDirectory, putVaultFile, readVaultFile } from './immutable-vault.js';
import { sealNotificationPayload, openNotificationPayload } from './notification-payload-crypto.js';
import {
  NotificationKeyCustodyError,
  notificationKeyPrepareInput,
  notificationKeySelector,
  notificationKeyPurpose,
  notificationOccurrenceUrn,
  notificationKeyFile,
  parseNotificationKey,
  validateNotificationKeyPreparation,
  decodeNotificationKeyPreparation,
  assertNotificationKeySelector,
  inspectNotificationKeyCiphertext,
  type NotificationKeyPreparation,
  type NotificationKeyPrepareInput,
  type NotificationKeySelector,
} from './notification-key-contracts.js';

type Reference = {
  keyId: string;
  encryptionExchangeId: string;
  encryptedObjectDigest: string;
  encryptionContextDigest: string;
};
const recipient = (p: NotificationKeySelector) => ({
  participantId: p.participantId,
  privacyDomainId: p.privacyDomainId,
  producerTrustDigest: p.producerTrustDigest,
  installationDigest: p.kmsInstallationDigest,
});
const selectorFor = (p: NotificationKeyPreparation): NotificationKeySelector => ({
  participantId: p.input.scope.participantId,
  privacyDomainId: p.input.scope.privacyDomainId,
  preparationId: p.preparationId,
  producerTrustDigest: p.input.producerTrustDigest,
  kmsInstallationDigest: p.input.kmsInstallationDigest,
});
const routeFor = (i: NotificationKeyPrepareInput) => ({
  participantId: i.scope.participantId,
  privacyDomainId: i.scope.privacyDomainId,
  ...i.routing,
  producerTrustDigest: i.producerTrustDigest,
});
const unavailable = (): never => {
  throw new NotificationKeyCustodyError('UNKNOWN');
};

/** Root composition supplies the real pool, Identity kernel, TLS key owner and
 * existing vault directory. No caller callback can grant admission or fabricate
 * provider success. This owner stores custody, never publishes an occurrence. */
export class NotificationKeyCustody {
  private readonly kms: EvidenceKmsRuntime;
  constructor(
    private readonly pool: Pool,
    private readonly kernel: IdentityKernel,
    tls: EvidenceKmsTlsMaterial,
    private readonly vaultDirectory: string,
  ) {
    this.kms = new EvidenceKmsRuntime(pool, kernel, tls);
  }
  private async admitted<T>(
    socket: TLSSocket,
    q: NotificationKeySelector,
    use: 'ENCRYPT' | 'DECRYPT' | 'READBACK',
    operation: (client: PoolClient, pins: NotificationKeyPreparation['kms']) => Promise<T>,
  ): Promise<T> {
    return withEvidenceKeyRecipient(
      this.pool,
      this.kernel,
      socket,
      recipient(q),
      use,
      async (client, admission) => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        await lockEvidenceLifecycle(client, q.participantId, q.privacyDomainId);
        return operation(client, admission.installation.pins);
      },
    );
  }
  private async prepared(client: PoolClient, q: NotificationKeySelector) {
    const rows = await client.query<{ preparation_bytes: Buffer; preparation_digest: string }>(
      `select preparation_bytes,preparation_digest from control.notification_key_preparation
       where participant_id=$1 and privacy_domain_id=$2 and preparation_id=$3`,
      [q.participantId, q.privacyDomainId, q.preparationId],
    );
    if (rows.rowCount !== 1) throw new NotificationKeyCustodyError('UNAVAILABLE');
    const p = decodeNotificationKeyPreparation(
      rows.rows[0]!.preparation_bytes,
      rows.rows[0]!.preparation_digest,
    );
    assertNotificationKeySelector(p, q);
    return p;
  }
  private async reference(
    client: PoolClient,
    q: NotificationKeySelector,
  ): Promise<Reference | undefined> {
    const rows = await client.query<Reference>(
      `select key_id as "keyId",encryption_exchange_id as "encryptionExchangeId",
      encrypted_object_digest as "encryptedObjectDigest",encryption_context_digest as "encryptionContextDigest"
      from control.notification_key_ciphertext where participant_id=$1 and privacy_domain_id=$2 and preparation_id=$3`,
      [q.participantId, q.privacyDomainId, q.preparationId],
    );
    if (rows.rowCount! > 1) throw new NotificationKeyCustodyError('INTEGRITY');
    return rows.rows[0];
  }
  private async source(client: PoolClient, i: NotificationKeyPrepareInput) {
    const prepared = await readPreparedEvidenceExportCompletion(
      client,
      i.scope,
      i.evidenceExportId,
    );
    const governed = await readEvidenceExportCompletionSource(client, i.scope, i.evidenceExportId);
    if (
      !prepared ||
      prepared.trustDigest !== i.producerTrustDigest ||
      !prepared.sourceData.equals(governed.data) ||
      prepared.claims.dataDigest !== governed.dataDigest
    )
      throw new NotificationKeyCustodyError('INTEGRITY');
    return {
      prepared,
      data: {
        evidenceExportId: `urn:openpc:resource:${governed.source.evidenceExportId}`,
        checkpoint: governed.source.checkpoint,
        outputDigest: governed.source.outputDigest,
        recordCount: governed.source.recordCount,
      },
    };
  }
  private async current<T>(
    client: PoolClient,
    p: NotificationKeyPreparation,
    operation: (plaintext: Buffer) => Promise<T>,
  ): Promise<T> {
    return withCurrentNotificationRouting(client, routeFor(p.input), async (route) => {
      const { prepared, data } = await this.source(client, p.input);
      const rendered = renderEvidenceExportNotification(route.input, data);
      try {
        if (
          route.route.claims.payloadKeyPolicyDigest !== p.kms.policyDigest ||
          route.installationDigest !== p.routingInstallationDigest ||
          prepared.claims.eventId !== p.sourceEventId ||
          prepared.receiptPayloadDigest !== p.sourceReceiptDigest ||
          prepared.claims.dataDigest !== p.sourceDataDigest ||
          canonicalJson(p.objectIntent) !==
            canonicalJson({
              environmentId: route.route.claims.environmentId,
              participantId: p.input.scope.participantId,
              privacyDomainId: p.input.scope.privacyDomainId,
              payloadObjectId: p.objectIntent.payloadObjectId,
              objectVersion: '1',
              notificationOccurrenceRef: notificationOccurrenceUrn(p.occurrenceId),
              routingProfileDigest: route.route.signedProfileDigest,
              templateDigest: route.route.claims.templateDigest,
              recipientSetDigest: route.route.claims.recipientSetDigest,
              redactionProfileDigest: route.route.claims.redactionProfileDigest,
              preferenceGeneration: String(route.route.claims.preferenceGeneration),
              payloadDigest: rendered.payloadDigest,
            })
        )
          throw new NotificationKeyCustodyError('INTEGRITY');
        return await operation(rendered.bytes);
      } finally {
        rendered.bytes.fill(0);
      }
    });
  }
  async prepare(socket: TLSSocket, value: unknown): Promise<NotificationKeyPreparation> {
    const input = parseNotificationKey(notificationKeyPrepareInput, value);
    const q = {
      ...input.scope,
      preparationId: localOperationId(),
      producerTrustDigest: input.producerTrustDigest,
      kmsInstallationDigest: input.kmsInstallationDigest,
    };
    return this.admitted(socket, q, 'ENCRYPT', async (client, kms) =>
      withCurrentNotificationRouting(client, routeFor(input), async (route) => {
        if (route.route.claims.payloadKeyPolicyDigest !== kms.policyDigest)
          throw new NotificationKeyCustodyError('INTEGRITY');
        const { prepared, data } = await this.source(client, input);
        const prior = await client.query<{ preparation_bytes: Buffer; preparation_digest: string }>(
          `select preparation_bytes,preparation_digest from control.notification_key_preparation
           where participant_id=$1 and privacy_domain_id=$2 and source_event_id=$3 and routing_profile_id=$4`,
          [q.participantId, q.privacyDomainId, prepared.claims.eventId, input.routing.profileId],
        );
        if (prior.rowCount) {
          const original = decodeNotificationKeyPreparation(
            prior.rows[0]!.preparation_bytes,
            prior.rows[0]!.preparation_digest,
          );
          if (
            canonicalJson(original.input) !== canonicalJson(input) ||
            canonicalJson(original.kms) !== canonicalJson(kms)
          )
            throw new NotificationKeyCustodyError('CONFLICT');
          return original;
        }
        const rendered = renderEvidenceExportNotification(route.input, data),
          occurrenceId = localOperationId();
        try {
          const p = validateNotificationKeyPreparation({
            purpose: notificationKeyPurpose,
            preparationId: q.preparationId,
            occurrenceId,
            input,
            sourceEventId: prepared.claims.eventId,
            sourceDataDigest: prepared.claims.dataDigest,
            sourceReceiptDigest: prepared.receiptPayloadDigest,
            routingInstallationDigest: route.installationDigest,
            kms,
            objectIntent: {
              environmentId: route.route.claims.environmentId,
              participantId: q.participantId,
              privacyDomainId: q.privacyDomainId,
              payloadObjectId: localOperationId(),
              objectVersion: '1',
              notificationOccurrenceRef: notificationOccurrenceUrn(occurrenceId),
              routingProfileDigest: input.routing.signedProfileDigest,
              templateDigest: route.route.claims.templateDigest,
              recipientSetDigest: route.route.claims.recipientSetDigest,
              redactionProfileDigest: route.route.claims.redactionProfileDigest,
              preferenceGeneration: String(route.route.claims.preferenceGeneration),
              payloadDigest: rendered.payloadDigest,
            },
          });
          const bytes = Buffer.from(canonicalJson(p));
          await client.query(
            `insert into control.notification_key_preparation(participant_id,privacy_domain_id,preparation_id,
            occurrence_id,payload_object_id,source_event_id,routing_profile_id,kms_installation_digest,preparation,preparation_bytes,preparation_digest)
            values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
            [
              q.participantId,
              q.privacyDomainId,
              p.preparationId,
              p.occurrenceId,
              p.objectIntent.payloadObjectId,
              p.sourceEventId,
              input.routing.profileId,
              input.kmsInstallationDigest,
              p,
              bytes,
              sha256(bytes),
            ],
          );
          return this.prepared(client, selectorFor(p));
        } finally {
          rendered.bytes.fill(0);
        }
      }),
    );
  }
  private async bytes(p: NotificationKeyPreparation, keyId: string) {
    const directory = await openVaultDirectory(this.vaultDirectory);
    const bytes = await readVaultFile(directory, notificationKeyFile(p), 131072);
    return { bytes, inspected: inspectNotificationKeyCiphertext(p, keyId, bytes) };
  }
  private async encryption(client: PoolClient, q: NotificationKeySelector) {
    const result = await client.query<{ exchange_id: string; key_id: string; proved: boolean }>(
      `select e.exchange_id,convert_from(e.request_bytes,'UTF8')::jsonb->>'keyId' key_id,
        ((e.state='PROVED' and openpc.evidence_kms_stored_outcome(e.receipt_bytes)='1') or exists(
          select 1 from control.evidence_kms_exchange r where r.participant_id=e.participant_id and r.privacy_domain_id=e.privacy_domain_id
          and r.attempt_id=e.attempt_id and r.kind='READ_ATTEMPT' and r.state='PROVED'
          and openpc.evidence_kms_stored_outcome(r.receipt_bytes)='1'
          and convert_from(r.request_bytes,'UTF8')::jsonb->>'readExchangeId'=e.exchange_id::text
          and convert_from(r.request_bytes,'UTF8')::jsonb->>'readRequestDigest'=e.request_digest)) proved
       from control.evidence_kms_exchange e where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3
       and kind='UNWRAP' and convert_from(request_bytes,'UTF8')::jsonb->>'keyUse'='ENCRYPT'`,
      [q.participantId, q.privacyDomainId, q.preparationId],
    );
    if (result.rowCount! > 1) throw new NotificationKeyCustodyError('INTEGRITY');
    return result.rows[0];
  }
  private async attach(
    client: PoolClient,
    p: NotificationKeyPreparation,
    keyId: string,
    exchangeId: string,
    bytes: Buffer,
  ) {
    const i = inspectNotificationKeyCiphertext(p, keyId, bytes),
      q = selectorFor(p);
    const original = await this.encryption(client, q);
    if (!original?.proved || original.exchange_id !== exchangeId || original.key_id !== keyId)
      unavailable();
    await client.query(
      `insert into control.notification_key_ciphertext(participant_id,privacy_domain_id,preparation_id,key_id,
      encryption_exchange_id,encrypted_object_digest,encryption_context_digest) values($1,$2,$3,$4,$5,$6,$7) on conflict do nothing`,
      [
        q.participantId,
        q.privacyDomainId,
        q.preparationId,
        keyId,
        exchangeId,
        i.encryptedObjectDigest,
        i.encryptionContextDigest,
      ],
    );
    const reference = await this.reference(client, q);
    if (
      !reference ||
      reference.keyId !== keyId ||
      reference.encryptionExchangeId !== exchangeId ||
      reference.encryptedObjectDigest !== i.encryptedObjectDigest ||
      reference.encryptionContextDigest !== i.encryptionContextDigest
    )
      throw new NotificationKeyCustodyError('INTEGRITY');
    return reference;
  }
  private async persist(
    client: PoolClient,
    p: NotificationKeyPreparation,
    ciphertext: EvidenceKmsCiphertext,
  ) {
    // KMS supplies its actual admitted transaction, whose initial workload-peer
    // context has the read-access action. Select this custody owner's action
    // before its source/routing checks and protected reference insertion.
    await client.query(
      "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
    );
    await lockEvidenceLifecycle(client, p.input.scope.participantId, p.input.scope.privacyDomainId);
    const retained = await this.prepared(client, selectorFor(p));
    if (
      canonicalJson(retained) !== canonicalJson(p) ||
      ciphertext.attemptId !== p.preparationId ||
      ciphertext.objectIntentDigest !== sha256(p.objectIntent)
    )
      throw new NotificationKeyCustodyError('INTEGRITY');
    return this.current(client, p, async () => {
      inspectNotificationKeyCiphertext(p, ciphertext.keyId, ciphertext.bytes);
      const directory = await openVaultDirectory(this.vaultDirectory);
      await putVaultFile(directory, notificationKeyFile(p), ciphertext.bytes);
      const original = await this.bytes(p, ciphertext.keyId);
      if (!original.bytes.equals(ciphertext.bytes))
        throw new NotificationKeyCustodyError('INTEGRITY');
      await this.attach(client, p, ciphertext.keyId, ciphertext.exchangeId, original.bytes);
      return original.bytes;
    });
  }
  /** First call may seal once. All existing encryption attempts go to original
   * readback, including PREPARED/UNKNOWN; a new key or nonce is never a retry. */
  async seal(socket: TLSSocket, value: unknown, signal: AbortSignal) {
    const q = parseNotificationKey(notificationKeySelector, value);
    let plaintext: Buffer | undefined;
    try {
      const prepared = await this.admitted(socket, q, 'ENCRYPT', async (client) => {
        const p = await this.prepared(client, q);
        return this.current(client, p, async (bytes) => {
          plaintext = Buffer.from(bytes);
          return { p, plaintext, encrypted: Boolean(await this.encryption(client, q)) };
        });
      });
      if (prepared.encrypted) return await this.reconcile(socket, q, signal);
      const p = prepared.p;
      const key = await this.kms.prepareObjectKey(
        socket,
        { recipient: recipient(q), attemptId: p.preparationId, objectIntent: p.objectIntent },
        signal,
      );
      await this.kms.withObjectKey(
        socket,
        { recipient: recipient(q), attemptId: p.preparationId, keyId: key.keyId, use: 'ENCRYPT' },
        signal,
        (material) =>
          sealNotificationPayload(
            { ...p.objectIntent, keyId: material.keyId },
            prepared.plaintext,
            material,
          ),
        (client, ciphertext) => this.persist(client, p, ciphertext),
      );
      return await this.readOriginal(socket, q);
    } finally {
      plaintext?.fill(0);
    }
  }
  /** Reconciliation never seals. Fresh provider/recovery authority authenticates
   * the original key; DECRYPT verifies AEAD before original SQL references attach. */
  async reconcile(socket: TLSSocket, value: unknown, signal: AbortSignal) {
    const q = parseNotificationKey(notificationKeySelector, value);
    const p = await this.admitted(socket, q, 'READBACK', (client) => this.prepared(client, q));
    const key = await this.kms.readAttempt(
      socket,
      { recipient: recipient(q), attemptId: p.preparationId },
      signal,
    );
    let original: Awaited<ReturnType<NotificationKeyCustody['bytes']>>;
    try {
      original = await this.bytes(p, key.keyId);
    } catch {
      return unavailable();
    }
    await this.kms.withObjectKey(
      socket,
      { recipient: recipient(q), attemptId: p.preparationId, keyId: key.keyId, use: 'DECRYPT' },
      signal,
      (material) => {
        const plaintext = openNotificationPayload(
          original.bytes,
          original.inspected.encryptedObjectDigest,
          { ...p.objectIntent, keyId: key.keyId },
          material,
        );
        plaintext.fill(0);
        return undefined;
      },
    );
    return this.admitted(socket, q, 'READBACK', async (client) => {
      const retained = await this.prepared(client, q);
      const route = await readInstalledNotificationRouting(client, routeFor(retained.input));
      if (
        route.installationDigest !== p.routingInstallationDigest ||
        canonicalJson(retained) !== canonicalJson(p)
      )
        throw new NotificationKeyCustodyError('INTEGRITY');
      const exchange = await this.encryption(client, q);
      if (!exchange?.proved || exchange.key_id !== key.keyId) return unavailable();
      await this.attach(client, p, key.keyId, exchange.exchange_id, original.bytes);
      return this.describe(p, (await this.reference(client, q))!);
    });
  }
  private describe(p: NotificationKeyPreparation, reference?: Reference, uncertain = false) {
    return {
      preparationId: p.preparationId,
      payloadObjectId: p.objectIntent.payloadObjectId,
      notificationOccurrenceRef: p.objectIntent.notificationOccurrenceRef,
      objectVersion: '1' as const,
      payloadDigest: p.objectIntent.payloadDigest,
      state: reference
        ? ('CUSTODIED' as const)
        : uncertain
          ? ('UNKNOWN' as const)
          : ('PREPARED' as const),
      reference: reference ? { ...reference } : undefined,
      publicationAuthority: 'NONE' as const,
    };
  }
  async readOriginal(socket: TLSSocket, value: unknown) {
    const q = parseNotificationKey(notificationKeySelector, value);
    return this.admitted(socket, q, 'READBACK', async (client) => {
      const p = await this.prepared(client, q),
        reference = await this.reference(client, q);
      if (reference) {
        const original = await this.bytes(p, reference.keyId);
        if (
          original.inspected.encryptedObjectDigest !== reference.encryptedObjectDigest ||
          original.inspected.encryptionContextDigest !== reference.encryptionContextDigest
        )
          throw new NotificationKeyCustodyError('INTEGRITY');
      }
      const attempt = await client.query<{ state: string }>(
        'select state from control.evidence_kms_attempt where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3',
        [q.participantId, q.privacyDomainId, q.preparationId],
      );
      return this.describe(
        p,
        reference,
        Boolean(await this.encryption(client, q)) ||
          ['DISPATCHED', 'UNKNOWN'].includes(attempt.rows[0]?.state ?? ''),
      );
    });
  }
  /** No plaintext export/disclosure or delivery authority is implied. The real
   * KMS DECRYPT path distinguishes current/retained keys and denies restored
   * revoked state. Exact object validation cannot substitute for that admission. */
  async verifyRetained(socket: TLSSocket, value: unknown, signal: AbortSignal) {
    const result = await this.reconcile(socket, value, signal);
    const q = parseNotificationKey(notificationKeySelector, value);
    await this.admitted(socket, q, 'DECRYPT', async (client) =>
      this.current(client, await this.prepared(client, q), async () => undefined),
    );
    return result;
  }
  async protection(socket: TLSSocket, value: unknown) {
    const q = parseNotificationKey(notificationKeySelector, value);
    return this.admitted(socket, q, 'READBACK', async (client) => {
      const p = await this.prepared(client, q);
      const holds = await client.query<{ retention_hold_id: string }>(
        `select retention_hold_id from control.retention_hold
        where participant_id=$1 and state='ACTIVE' and (selector_type='PARTICIPANT' or privacy_domain_id=$2)`,
        [q.participantId, q.privacyDomainId],
      );
      // Preserve coarse reference protection even when a newer owner or an
      // exact custody join is unavailable. It can add blockers, never clear one.
      const consumer = await client.query<{ installed: boolean }>(
        "select to_regclass('control.notification_occurrence') is not null installed",
      );
      const consumerInstalled = consumer.rows[0]?.installed === true;
      const references = consumerInstalled
        ? await client.query(
            `select 1 from control.notification_occurrence where participant_id=$1 and privacy_domain_id=$2
        and (notification_occurrence_id=$3 or payload_object_id=$4)`,
            [q.participantId, q.privacyDomainId, p.occurrenceId, p.objectIntent.payloadObjectId],
          )
        : undefined;
      let sourceBlockers: readonly string[];
      try {
        const source = await readNotificationPayloadRetirementSource(
          client,
          q,
          this.vaultDirectory,
        );
        if (canonicalJson(source.custody.preparation) !== canonicalJson(p))
          throw new NotificationKeyCustodyError('INTEGRITY');
        sourceBlockers = source.publication.blockers;
      } catch (error) {
        if (!(error instanceof NotificationKeyCustodyError) || error.code !== 'UNKNOWN')
          throw error;
        sourceBlockers = ['CUSTODY_UNRESOLVED'];
      }
      // Until the actual consumer/attempt/retirement owner closes this reference,
      // even an empty query cannot prove absence of future/unknown delivery use.
      return {
        retirementAllowed: false as const,
        blockers: [
          ...new Set([
            'CONSUMER_CLOSURE_UNAVAILABLE',
            ...(!consumerInstalled ? ['OCCURRENCE_OWNER_UNAVAILABLE'] : []),
            ...(references?.rowCount ? ['OCCURRENCE_REFERENCE'] : []),
            ...sourceBlockers,
            ...(holds.rowCount ? ['ACTIVE_SCOPE_HOLD_REQUIRES_EVALUATION'] : []),
          ]),
        ],
      };
    });
  }
}

/** Preserve typed uncertainty for callers without exposing provider/SQL text. */
export function notificationKeyFailure(error: unknown): NotificationKeyCustodyError {
  if (error instanceof NotificationKeyCustodyError) return error;
  return new NotificationKeyCustodyError(
    error instanceof EvidenceKmsError && error.code === 'UNKNOWN' ? 'UNKNOWN' : 'UNAVAILABLE',
  );
}
