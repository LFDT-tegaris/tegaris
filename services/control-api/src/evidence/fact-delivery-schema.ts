import { sql } from 'drizzle-orm';
import { check, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceOrdinal as ordinal,
  evidenceScopePolicies as scoped,
} from './schema.js';
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});
const factTypes = "'CONTRACT_STATE_CALL','RELATIONSHIP','EXTERNAL_DECISION'";

/** Immutable transactional consumer inbox. This proves local custody, never
 * current Fact readiness, sink export or the Fleet consumer's acknowledgement. */
export const evidenceFactAdmissionInbox = control
  .table(
    'evidence_fact_admission_inbox',
    {
      ...scope(),
      eventId: uuid('event_id').notNull(),
      factType: text('fact_type').notNull(),
      sequence: ordinal('sequence').notNull(),
      candidateId: uuid('candidate_id').notNull(),
      streamId: text('stream_id').notNull(),
      recordId: text('record_id').notNull(),
      sourceReceiptDigest: text('source_receipt_digest').notNull(),
      envelope: jsonb('envelope').notNull(),
      envelopeDigest: text('envelope_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId] }),
      unique('fact_admission_inbox_sequence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.factType,
        t.sequence,
      ),
      unique('fact_admission_inbox_candidate_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.candidateId,
      ),
      check('fact_admission_inbox_type_ck', sql`${t.factType} in (${sql.raw(factTypes)})`),
      check(
        'fact_admission_inbox_sequence_ck',
        sql`${t.sequence} between 1 and 18446744073709551615`,
      ),
      check(
        'fact_admission_inbox_digest_ck',
        sql`${t.sourceReceiptDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.envelopeDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'fact_admission_inbox_size_ck',
        sql`jsonb_typeof(${t.envelope})='object' and octet_length(${t.envelope}::text)<=8192`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Highest contiguous original producer sequence whose custody effect committed. */
export const evidenceFactAdmissionCursor = control
  .table(
    'evidence_fact_admission_cursor',
    {
      ...scope(),
      factType: text('fact_type').notNull(),
      sequence: ordinal('sequence').notNull().default('0'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.factType] }),
      check('fact_admission_cursor_type_ck', sql`${t.factType} in (${sql.raw(factTypes)})`),
      check(
        'fact_admission_cursor_sequence_ck',
        sql`${t.sequence} between 0 and 18446744073709551615`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
