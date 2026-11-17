import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
} from '../evidence/schema.js';
import { notificationDeliveryPreparations } from './delivery-start-schema.js';
import { notificationReceiptSignerInstallations } from './receipt-signer-schema.js';
/** One immutable original per reserved delivery operation. DISPATCHED is never
 * made PREPARED again; an absent provider result never authorizes a new send. */
export const notificationDeliverySigningAttempts = control
  .table(
    'notification_delivery_signing',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      signingAttemptId: uuid('signing_attempt_id').notNull(),
      signerInstallationDigest: text('signer_installation_digest').notNull(),
      requestDigest: text('request_digest').notNull(),
      preparation: jsonb('preparation').notNull(),
      preparationBytes: bytes('preparation_bytes').notNull(),
      preparationDigest: text('preparation_digest').notNull(),
      state: text('state').notNull().default('PREPARED'),
      dispatchToken: uuid('dispatch_token'),
      dispatchedAtMs: ordinal('dispatched_at_ms'),
      observation: jsonb('observation'),
      observationBytes: bytes('observation_bytes'),
      observationDigest: text('observation_digest'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.operationId] }),
      unique('notification_delivery_signing_receipt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.signingAttemptId,
      ),
      foreignKey({
        name: 'notification_delivery_signing_preparation_fk',
        columns: [t.participantId, t.privacyDomainId, t.operationId],
        foreignColumns: [
          notificationDeliveryPreparations.participantId,
          notificationDeliveryPreparations.privacyDomainId,
          notificationDeliveryPreparations.operationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_delivery_signing_signer_fk',
        columns: [t.participantId, t.privacyDomainId, t.signerInstallationDigest],
        foreignColumns: [
          notificationReceiptSignerInstallations.participantId,
          notificationReceiptSignerInstallations.privacyDomainId,
          notificationReceiptSignerInstallations.trustDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_delivery_signing_bytes_ck',
        sql`octet_length(${t.preparationBytes}) between 1 and 524288 and ${t.preparationDigest}='sha256:'||encode(sha256(${t.preparationBytes}),'hex')`,
      ),
      check(
        'notification_delivery_signing_state_ck',
        sql`(${t.state}='PREPARED' and ${t.dispatchToken} is null and ${t.dispatchedAtMs} is null and ${t.observation} is null and ${t.observationBytes} is null and ${t.observationDigest} is null)
 or (${t.state}='DISPATCHED' and ${t.dispatchToken} is not null and ${t.dispatchedAtMs} is not null and ${t.dispatchedAtMs} between 0 and 9007199254740991 and ${t.observation} is null and ${t.observationBytes} is null and ${t.observationDigest} is null)
 or (${t.state}='OBSERVED' and ${t.dispatchToken} is not null and ${t.dispatchedAtMs} is not null and ${t.dispatchedAtMs} between 0 and 9007199254740991 and ${t.observation} is not null and ${t.observationBytes} is not null and ${t.observationDigest} is not null and octet_length(${t.observationBytes}) between 1 and 196608 and ${t.observationDigest}='sha256:'||encode(sha256(${t.observationBytes}),'hex'))`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
