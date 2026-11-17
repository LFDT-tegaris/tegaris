import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  customType,
  foreignKey,
  integer,
  jsonb,
  numeric,
  pgPolicy,
  pgRole,
  pgSchema,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';

const control = pgSchema('control');
const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);
const bytes = customType<{ data: Buffer; driverData: Buffer }>({ dataType: () => 'bytea' });
const ordinal = (name: string) => numeric(name, { precision: 20, scale: 0 });
const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
  streamId: text('stream_id').notNull(),
});
const scoped = (t: { participantId: unknown; privacyDomainId: unknown }) => [
  pgPolicy('participant_isolation', {
    as: 'permissive',
    for: 'all',
    to: roles,
    using: sql`openpc.matches_participant(${t.participantId})`,
    withCheck: sql`openpc.matches_participant(${t.participantId})`,
  }),
  pgPolicy('privacy_domain_isolation', {
    as: 'restrictive',
    for: 'all',
    to: roles,
    using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
    withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
  }),
];

export {
  control as evidenceControlSchema,
  scope as evidenceScopeColumns,
  scoped as evidenceScopePolicies,
  ordinal as evidenceOrdinal,
  time as evidenceTimestamp,
  bytes as evidenceBytes,
};

/** Serialized local custody, independent of any sink's availability. */
export const evidenceStreams = control
  .table(
    'evidence_stream',
    {
      ...scope(),
      lastSequence: ordinal('last_sequence').notNull().default('0'),
      lastSegmentDigest: text('last_segment_digest'),
      usedBytes: bigint('used_bytes', { mode: 'bigint' })
        .notNull()
        .default(sql`0`),
      capacityBytes: bigint('capacity_bytes', { mode: 'bigint' }).notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.streamId] }),
      check(
        'evidence_stream_sequence_ck',
        sql`${t.lastSequence} between 0 and 18446744073709551615 and ((${t.lastSequence}=0 and ${t.lastSegmentDigest} is null) or (${t.lastSequence}>0 and ${t.lastSegmentDigest} ~ '^sha256:[0-9a-f]{64}$'))`,
      ),
      check(
        'evidence_stream_capacity_ck',
        sql`${t.capacityBytes} between 1024 and 1073741824 and ${t.usedBytes} between 0 and ${t.capacityBytes}`,
      ),
      check('evidence_stream_id_ck', sql`${t.streamId} ~ '^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$'`),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Immutable custody metadata remains after separately governed local payload deletion. */
export const evidenceSegments = control
  .table(
    'evidence_segment',
    {
      ...scope(),
      segmentId: uuid('segment_id').primaryKey(),
      firstSequence: ordinal('first_sequence').notNull(),
      throughSequence: ordinal('through_sequence').notNull(),
      previousSegmentDigest: text('previous_segment_digest'),
      objectDigest: text('object_digest').notNull(),
      keyId: text('key_id').notNull(),
      retentionUntil: time('retention_until').notNull(),
      admittedAt: time('admitted_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('evidence_segment_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.streamId,
        t.segmentId,
      ),
      unique('evidence_segment_sequence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.streamId,
        t.firstSequence,
      ),
      foreignKey({
        name: 'evidence_segment_stream_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId],
        foreignColumns: [
          evidenceStreams.participantId,
          evidenceStreams.privacyDomainId,
          evidenceStreams.streamId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_segment_range_ck',
        sql`${t.firstSequence}>0 and ${t.throughSequence} between ${t.firstSequence} and 18446744073709551615 and ${t.throughSequence}-${t.firstSequence}<128`,
      ),
      check('evidence_segment_digest_ck', sql`${t.objectDigest} ~ '^sha256:[0-9a-f]{64}$'`),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Local ciphertext has a separate lifetime from immutable custody metadata. */
export const evidenceSegmentPayloads = control
  .table(
    'evidence_segment_payload',
    {
      ...scope(),
      segmentId: uuid('segment_id').primaryKey(),
      encryptedSegment: bytes('encrypted_segment').notNull(),
      ciphertextBytes: integer('ciphertext_bytes')
        .generatedAlwaysAs(sql`octet_length(encrypted_segment)`)
        .notNull(),
    },
    (t) => [
      foreignKey({
        name: 'evidence_segment_payload_segment_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.segmentId],
        foreignColumns: [
          evidenceSegments.participantId,
          evidenceSegments.privacyDomainId,
          evidenceSegments.streamId,
          evidenceSegments.segmentId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_segment_payload_size_ck',
        sql`octet_length(${t.encryptedSegment}) between 1 and 2097152`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Rebuildable minimized catalogue; never sufficient to establish archive durability. */
export const evidenceCatalogue = control
  .table(
    'evidence_catalogue',
    {
      ...scope(),
      evidenceId: uuid('evidence_id')
        .notNull()
        .default(sql`uuidv7()`),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      recordId: text('record_id').notNull(),
      segmentId: uuid('segment_id').notNull(),
      sequence: ordinal('sequence').notNull(),
      evidenceClass: text('evidence_class').notNull(),
      sourceFormat: text('source_format').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
      occurredAt: time('occurred_at').notNull(),
    },
    (t) => [
      unique('evidence_catalogue_id_uq').on(t.evidenceId),
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId] }),
      unique('evidence_catalogue_sequence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.streamId,
        t.sequence,
      ),
      foreignKey({
        name: 'evidence_catalogue_segment_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.segmentId],
        foreignColumns: [
          evidenceSegments.participantId,
          evidenceSegments.privacyDomainId,
          evidenceSegments.streamId,
          evidenceSegments.segmentId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_catalogue_class_ck',
        sql`${t.evidenceClass} in ('AUTHENTICATION','BUSINESS_TRANSITION','EFFECT') and ${t.receiptDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Append-only sink-bound checkpoint chain; no global checkpoint or mutable latest alias. */
export const evidenceCheckpoints = control
  .table(
    'evidence_checkpoint',
    {
      ...scope(),
      sinkId: text('sink_id').notNull(),
      throughSequence: ordinal('through_sequence').notNull(),
      segmentId: uuid('segment_id').notNull(),
      objectDigest: text('object_digest').notNull(),
      previousCheckpointDigest: text('previous_checkpoint_digest'),
      receipt: jsonb('receipt').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
      checkpointDigest: text('checkpoint_digest').notNull(),
      acknowledgedAt: time('acknowledged_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.sinkId, t.throughSequence],
      }),
      unique('evidence_checkpoint_segment_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.streamId,
        t.sinkId,
        t.segmentId,
      ),
      foreignKey({
        name: 'evidence_checkpoint_segment_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.segmentId],
        foreignColumns: [
          evidenceSegments.participantId,
          evidenceSegments.privacyDomainId,
          evidenceSegments.streamId,
          evidenceSegments.segmentId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_checkpoint_digest_ck',
        sql`${t.objectDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.receiptDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.checkpointDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
