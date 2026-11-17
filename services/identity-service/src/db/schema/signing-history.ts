import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  primaryKey,
  text,
  uuid,
  numeric,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { signingKeyRotations } from './signing-rotation.js';

/** Protected product audit history, one immutable entry per lifecycle revision. */
export const signingRotationHistory = control
  .table(
    'signing_rotation_history',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      revision: bigint('revision', { mode: 'bigint' }).notNull(),
      priorState: text('prior_state'),
      state: text('state').notNull(),
      operationId: uuid('operation_id').notNull(),
      priorDigest: bytea('prior_digest'),
      historyPreimage: bytea('history_preimage').notNull(),
      historyDigest: bytea('history_digest').notNull(),
      eventId: uuid('event_id'),
      receiptId: uuid('receipt_id'),
      evidenceId: uuid('evidence_id'),
      receiptNamespace: text('receipt_namespace'),
      receiptOrdinal: numeric('receipt_ordinal', { precision: 20, scale: 0, mode: 'bigint' }),
    },
    (t) => [
      primaryKey({
        name: 'signing_history_1_pk',
        columns: [t.participantId, t.privacyDomainId, t.rotationId, t.revision],
      }),
      foreignKey({
        name: 'signing_history_scope_1_fk',
        columns: [t.participantId, t.privacyDomainId, t.rotationId],
        foreignColumns: [
          signingKeyRotations.participantId,
          signingKeyRotations.privacyDomainId,
          signingKeyRotations.rotationId,
        ],
      }),
      check(
        'signing_history_revision_ck',
        sql`${t.revision}>0 and ((${t.revision}=1 and ${t.priorState} is null and ${t.priorDigest} is null) or (${t.revision}>1 and ${t.priorState} is not null and octet_length(${t.priorDigest})=32))`,
      ),
      check(
        'signing_history_digest_ck',
        sql`octet_length(${t.historyPreimage}) between 2 and 262144 and ${t.historyDigest}=sha256(${t.historyPreimage}) and octet_length(${t.historyDigest})=32`,
      ),
      check(
        'signing_history_protected_effect_ck',
        sql`${t.state} not in ('OLD_REVOKED','COMPLETE') or (${t.receiptId} is not null and ${t.evidenceId} is not null and (${t.priorState}=${t.state} or ${t.eventId} is not null))`,
      ),
      uniqueIndex('signing_history_receipt_ordinal_uq')
        .on(t.participantId, t.privacyDomainId, t.rotationId, t.receiptOrdinal)
        .where(sql`${t.receiptOrdinal} is not null`),
      check(
        'signing_history_receipt_ordinal_ck',
        sql`(${t.receiptId} is null and ${t.receiptNamespace} is null and ${t.receiptOrdinal} is null) or (${t.receiptId} is not null and ${t.receiptNamespace} is not null and ${t.receiptNamespace}='CONTROL_SIGNING_LIFECYCLE_V1' and ${t.receiptOrdinal} is not null and ${t.receiptOrdinal}>0)`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
