import { sql } from 'drizzle-orm';
import { check, foreignKey, integer, jsonb, primaryKey, text, uuid } from 'drizzle-orm/pg-core';
import { protectedProofObjects } from './protected-schema.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceTimestamp as time,
} from './schema.js';

/** Independent exact-version raw-body custody. An authentication segment receipt
 * proves a different object and cannot satisfy this checkpoint. */
export const protectedProofCheckpoints = control
  .table(
    'protected_proof_checkpoint',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      objectId: uuid('object_id').notNull(),
      sinkId: text('sink_id').notNull(),
      payloadDigest: text('payload_digest').notNull(),
      ciphertextBytes: integer('ciphertext_bytes').notNull(),
      receipt: jsonb('receipt').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
      checkpointDigest: text('checkpoint_digest').notNull(),
      acknowledgedAt: time('acknowledged_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.objectId, t.sinkId] }),
      foreignKey({
        name: 'protected_proof_checkpoint_object_fk',
        columns: [t.participantId, t.privacyDomainId, t.objectId],
        foreignColumns: [
          protectedProofObjects.participantId,
          protectedProofObjects.privacyDomainId,
          protectedProofObjects.objectId,
        ],
      }).onDelete('restrict'),
      check(
        'protected_proof_checkpoint_digest_ck',
        sql`${t.payloadDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.receiptDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.checkpointDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'protected_proof_checkpoint_size_ck',
        sql`${t.ciphertextBytes} between 17 and 65552 and ${t.sinkId} ~ '^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
