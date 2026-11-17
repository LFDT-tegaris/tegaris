import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  numeric,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { auditOccurrences } from './business-receipts.js';
const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
export const qualifiedReceiptInbox = control
  .table(
    'qualified_receipt_inbox',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      namespace: text('namespace').notNull(),
      aggregateType: text('aggregate_type').notNull(),
      aggregateId: uuid('aggregate_id').notNull(),
      sequence: u64('sequence').notNull(),
      receiptId: uuid('receipt_id').notNull(),
      receiptDigest: bytea('receipt_digest').notNull(),
      signerId: text('signer_id').notNull(),
      keyEpoch: u64('key_epoch').notNull(),
      acceptedAt: timestamp('accepted_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => [
      primaryKey({
        name: 'qualified_receipt_1_pk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.namespace,
          t.aggregateType,
          t.aggregateId,
          t.sequence,
        ],
      }),
      unique('qualified_receipt_inbox_id_uq').on(t.participantId, t.privacyDomainId, t.receiptId),
      foreignKey({
        name: 'qualified_receipt_scope_1_fk',
        columns: [t.participantId, t.privacyDomainId, t.receiptId, t.receiptDigest],
        foreignColumns: [
          auditOccurrences.participantId,
          auditOccurrences.privacyDomainId,
          auditOccurrences.receiptId,
          auditOccurrences.receiptDigest,
        ],
      }),
      check(
        'qualified_receipt_namespace_ck',
        sql`${t.namespace} in ('CONTROL_BUSINESS_TRANSITION_V1','CONTROL_SIGNING_LIFECYCLE_V1')`,
      ),
      check(
        'qualified_receipt_sequence_ck',
        sql`${t.sequence}>0 and ${t.sequence}<=18446744073709551615 and ${t.keyEpoch}>0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
export const qualifiedReceiptCheckpoints = control
  .table(
    'qualified_receipt_checkpoint',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      namespace: text('namespace').notNull(),
      aggregateType: text('aggregate_type').notNull(),
      aggregateId: uuid('aggregate_id').notNull(),
      lastSequence: u64('last_sequence')
        .notNull()
        .default(sql`0`),
      lastReceiptId: uuid('last_receipt_id'),
    },
    (t) => [
      primaryKey({
        name: 'qualified_receipt_2_pk',
        columns: [t.participantId, t.privacyDomainId, t.namespace, t.aggregateType, t.aggregateId],
      }),
      foreignKey({
        name: 'qualified_receipt_scope_2_fk',
        columns: [t.participantId, t.privacyDomainId, t.lastReceiptId],
        foreignColumns: [
          qualifiedReceiptInbox.participantId,
          qualifiedReceiptInbox.privacyDomainId,
          qualifiedReceiptInbox.receiptId,
        ],
      }),
      check(
        'qualified_checkpoint_initial_ck',
        sql`(${t.lastSequence}=0 and ${t.lastReceiptId} is null) or (${t.lastSequence}>0 and ${t.lastReceiptId} is not null)`,
      ),
      check(
        'qualified_checkpoint_namespace_ck',
        sql`${t.namespace} in ('CONTROL_BUSINESS_TRANSITION_V1','CONTROL_SIGNING_LIFECYCLE_V1')`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
