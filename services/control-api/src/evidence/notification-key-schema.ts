import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
} from './schema.js';
import { evidenceKmsInstallations, evidenceWrappedKeys } from './kms-schema.js';
import { evidenceExportCompletions } from './export-completion-schema.js';
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});
/** Durable, protected reservation before any provider I/O. No occurrence,
 * notification, outbox or cursor row is manufactured by this custody leaf. */
export const notificationKeyPreparations = control
  .table(
    'notification_key_preparation',
    {
      ...scope(),
      preparationId: uuid('preparation_id').notNull(),
      occurrenceId: uuid('occurrence_id').notNull(),
      payloadObjectId: uuid('payload_object_id').notNull(),
      sourceEventId: uuid('source_event_id').notNull(),
      routingProfileId: uuid('routing_profile_id').notNull(),
      kmsInstallationDigest: text('kms_installation_digest').notNull(),
      preparation: jsonb('preparation').notNull(),
      preparationBytes: bytes('preparation_bytes').notNull(),
      preparationDigest: text('preparation_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.preparationId] }),
      unique('notification_key_source_route_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.sourceEventId,
        t.routingProfileId,
      ),
      unique('notification_key_object_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.payloadObjectId,
      ),
      unique('notification_key_occurrence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.occurrenceId,
      ),
      foreignKey({
        name: 'notification_key_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.sourceEventId],
        foreignColumns: [
          evidenceExportCompletions.participantId,
          evidenceExportCompletions.privacyDomainId,
          evidenceExportCompletions.eventId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_key_installation_fk',
        columns: [t.participantId, t.privacyDomainId, t.kmsInstallationDigest],
        foreignColumns: [
          evidenceKmsInstallations.participantId,
          evidenceKmsInstallations.privacyDomainId,
          evidenceKmsInstallations.installationDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_key_preparation_bytes_ck',
        sql`octet_length(${t.preparationBytes}) between 1 and 32768 and ${t.preparationDigest}='sha256:'||encode(sha256(${t.preparationBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
/** Exact references to immutable vault bytes. A rollback may leave those bytes
 * without this reference; recovery must authenticate and attach the originals. */
export const notificationKeyCiphertexts = control
  .table(
    'notification_key_ciphertext',
    {
      ...scope(),
      preparationId: uuid('preparation_id').notNull(),
      keyId: text('key_id').notNull(),
      encryptionExchangeId: uuid('encryption_exchange_id').notNull(),
      encryptedObjectDigest: text('encrypted_object_digest').notNull(),
      encryptionContextDigest: text('encryption_context_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.preparationId] }),
      foreignKey({
        name: 'notification_key_ciphertext_preparation_fk',
        columns: [t.participantId, t.privacyDomainId, t.preparationId],
        foreignColumns: [
          notificationKeyPreparations.participantId,
          notificationKeyPreparations.privacyDomainId,
          notificationKeyPreparations.preparationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_key_ciphertext_wrapped_fk',
        columns: [t.participantId, t.privacyDomainId, t.keyId],
        foreignColumns: [
          evidenceWrappedKeys.participantId,
          evidenceWrappedKeys.privacyDomainId,
          evidenceWrappedKeys.keyId,
        ],
      }).onDelete('restrict'),
      check(
        'notification_key_ciphertext_digest_ck',
        sql`${t.encryptedObjectDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.encryptionContextDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
