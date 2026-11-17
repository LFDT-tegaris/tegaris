import { sql } from 'drizzle-orm';
import { check, foreignKey, integer, jsonb, text, unique, uuid } from 'drizzle-orm/pg-core';
import { evidenceDeletionJobs } from './deletion-schema.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceSegments,
} from './schema.js';

/** Actual OLD projection identity and the preservation minimum captured only by
 * the destructive trigger. This is the immutable deletion effect, not a second
 * searchable catalogue or permission to rebuild retired material. */
export const evidenceProjectionRetirement = control
  .table(
    'evidence_projection_retirement',
    {
      deletionJobId: uuid('deletion_job_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      dataClass: text('data_class').notNull(),
      evidenceId: uuid('evidence_id').notNull(),
      streamId: text('stream_id').notNull(),
      segmentId: uuid('segment_id').notNull(),
      recordId: text('record_id').notNull(),
      sequence: ordinal('sequence').notNull(),
      sourceReceiptDigest: text('source_receipt_digest').notNull(),
      projectionDigest: text('projection_digest').notNull(),
      projectionBytes: integer('projection_bytes').notNull(),
      preservationMetadata: jsonb('preservation_metadata').notNull(),
      retirementDigest: text('retirement_digest').notNull(),
    },
    (t) => [
      unique('evidence_projection_retirement_record_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.dataClass,
        t.streamId,
        t.recordId,
      ),
      unique('evidence_projection_retirement_id_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.dataClass,
        t.evidenceId,
      ),
      foreignKey({
        name: 'evidence_projection_retirement_job_fk',
        columns: [t.participantId, t.privacyDomainId, t.deletionJobId],
        foreignColumns: [
          evidenceDeletionJobs.participantId,
          evidenceDeletionJobs.privacyDomainId,
          evidenceDeletionJobs.deletionJobId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'evidence_projection_retirement_segment_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.segmentId],
        foreignColumns: [
          evidenceSegments.participantId,
          evidenceSegments.privacyDomainId,
          evidenceSegments.streamId,
          evidenceSegments.segmentId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_projection_retirement_class_ck',
        sql`${t.dataClass} in ('NORMALIZED_JSON_PROJECTION','SEARCH_PROJECTION')`,
      ),
      check(
        'evidence_projection_retirement_digest_ck',
        sql`${t.sourceReceiptDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.projectionDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.retirementDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'evidence_projection_retirement_size_ck',
        sql`${t.projectionBytes} between 1 and 16384 and ${t.sequence}>0 and jsonb_typeof(${t.preservationMetadata})='object' and octet_length(${t.preservationMetadata}::text)<=2048`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
