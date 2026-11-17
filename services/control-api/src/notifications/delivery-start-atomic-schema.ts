import { sql } from 'drizzle-orm';
import { check, foreignKey, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
} from '../evidence/schema.js';
import { notificationDeliveryStarts } from './delivery-start-schema.js';
/** Internal ordered dispatch intent, not a public event or gateway result.
 * Claim is terminal ownership, never delivery success or permission to send. */
export const notificationDeliveryDispatchIntents = control
  .table(
    'notification_delivery_dispatch_intent',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      notificationOccurrenceId: uuid('notification_occurrence_id').notNull(),
      payloadDigest: text('payload_digest').notNull(),
      deliveryRevision: ordinal('delivery_revision').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
      state: text('state').notNull().default('PENDING'),
      claimToken: text('claim_token'),
      claimedAtMs: ordinal('claimed_at_ms'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.operationId] }),
      unique('notification_dispatch_claim_token_uq').on(t.claimToken),
      unique('notification_dispatch_revision_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
        t.deliveryRevision,
      ),
      unique('notification_dispatch_attempt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.attemptId,
      ),
      foreignKey({
        name: 'notification_dispatch_start_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.operationId,
          t.attemptId,
          t.notificationOccurrenceId,
          t.payloadDigest,
        ],
        foreignColumns: [
          notificationDeliveryStarts.participantId,
          notificationDeliveryStarts.privacyDomainId,
          notificationDeliveryStarts.operationId,
          notificationDeliveryStarts.attemptId,
          notificationDeliveryStarts.notificationOccurrenceId,
          notificationDeliveryStarts.payloadDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_dispatch_state_ck',
        sql`${t.deliveryRevision} between 2 and 18446744073709551615 and ${t.receiptDigest} ~ '^sha256:[0-9a-f]{64}$'
 and ((${t.state}='PENDING' and ${t.claimToken} is null and ${t.claimedAtMs} is null)
 or (${t.state}='CLAIMED' and ${t.claimToken} is not null and ${t.claimToken} ~ '^[0-9a-f]{64}$' and ${t.claimedAtMs} is not null and ${t.claimedAtMs} between 0 and 9007199254740991))`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
