import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopeColumns as scope,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceTimestamp as time,
  evidenceBytes as bytes,
  evidenceStreams,
} from './schema.js';

/** Server-derived, immutable range membership, independent of later additions. */
export const evidenceExportSelections = control
  .table(
    'evidence_export_selection',
    {
      ...scope(),
      requestDigest: text('request_digest').notNull(),
      selection: jsonb('selection').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.requestDigest] }),
      unique('evidence_export_selection_stream_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.streamId,
        t.requestDigest,
      ),
      foreignKey({
        name: 'evidence_export_selection_stream_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId],
        foreignColumns: [
          evidenceStreams.participantId,
          evidenceStreams.privacyDomainId,
          evidenceStreams.streamId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_export_selection_digest_ck',
        sql`${t.requestDigest} ~ '^sha256:[0-9a-f]{64}$' and jsonb_typeof(${t.selection})='object'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Request acceptance and artifact completion have distinct durable states. */
export const evidenceExportRequests = control
  .table(
    'evidence_export_request',
    {
      ...scope(),
      evidenceExportId: uuid('evidence_export_id').primaryKey(),
      requestDigest: text('request_digest').notNull(),
      state: text('state').notNull().default('REQUESTED'),
      checkpoint: ordinal('checkpoint').notNull().default('0'),
      outputDigest: text('output_digest'),
      creationOperationId: uuid('creation_operation_id').notNull(),
      startOperationId: uuid('start_operation_id'),
      lastOperationId: uuid('last_operation_id').notNull(),
      revision: ordinal('revision').notNull().default('1'),
      lastErrorCode: text('last_error_code'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('evidence_export_request_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.streamId,
        t.evidenceExportId,
      ),
      unique('evidence_export_request_start_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.startOperationId,
      ),
      foreignKey({
        name: 'evidence_export_request_selection_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.requestDigest],
        foreignColumns: [
          evidenceExportSelections.participantId,
          evidenceExportSelections.privacyDomainId,
          evidenceExportSelections.streamId,
          evidenceExportSelections.requestDigest,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_export_request_state_ck',
        sql`${t.state} in ('REQUESTED','RUNNING','SUCCEEDED','FAILED','BACKLOGGED')
    and (${t.state}='REQUESTED')=(${t.startOperationId} is null)
    and (${t.state}='SUCCEEDED')=(${t.outputDigest} is not null)
    and (${t.state}='SUCCEEDED' or ${t.checkpoint}=0)
    and (${t.outputDigest} is null or ${t.outputDigest} ~ '^sha256:[0-9a-f]{64}$')`,
      ),
      check(
        'evidence_export_request_revision_ck',
        sql`${t.revision} between 1 and 18446744073709551615 and ${t.checkpoint} between 0 and 18446744073709551615`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Only the worker may append an exact verified redacted artifact. */
export const evidenceExportOutputs = control
  .table(
    'evidence_export_output',
    {
      ...scope(),
      evidenceExportId: uuid('evidence_export_id').primaryKey(),
      sinkId: text('sink_id').notNull(),
      outputDigest: text('output_digest').notNull(),
      artifact: bytes('artifact').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      foreignKey({
        name: 'evidence_export_output_request_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.evidenceExportId],
        foreignColumns: [
          evidenceExportRequests.participantId,
          evidenceExportRequests.privacyDomainId,
          evidenceExportRequests.streamId,
          evidenceExportRequests.evidenceExportId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_export_output_digest_ck',
        sql`octet_length(${t.artifact}) between 1 and 1048576 and ${t.outputDigest}='sha256:'||encode(sha256(${t.artifact}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
