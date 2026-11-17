import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  primaryKey,
  text,
  unique,
  uuid,
  pgPolicy,
  pgRole,
} from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceTimestamp as time,
  evidenceBytes as bytes,
  evidenceSegments,
} from './schema.js';

/** Approved rule persists independently of any adapter's current availability. */
export const evidenceHolds = control
  .table(
    'retention_hold',
    {
      retentionHoldId: uuid('retention_hold_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      holdKind: text('hold_kind').notNull(),
      selectorType: text('selector_type').notNull(),
      selector: jsonb('selector').notNull(),
      selectorCbor: bytes('selector_cbor').notNull(),
      selectorDigest: text('selector_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
      approvalRequestId: uuid('approval_request_id').notNull(),
      releaseApprovalRequestId: uuid('release_approval_request_id'),
      creationOperationId: uuid('creation_operation_id').notNull(),
      releaseOperationId: uuid('release_operation_id'),
      revision: ordinal('revision').notNull().default('1'),
      effectiveAt: time('effective_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('retention_hold_participant_uq').on(t.participantId, t.retentionHoldId),
      unique('retention_hold_scope_uq').on(t.participantId, t.privacyDomainId, t.retentionHoldId),
      unique('retention_hold_creation_uq').on(t.creationOperationId),
      check('retention_hold_kind_ck', sql`${t.holdKind} in ('LEGAL','REGULATORY','INCIDENT')`),
      check(
        'retention_hold_selector_ck',
        sql`${t.selectorType} in ('PARTICIPANT','PRIVACY_DOMAIN','PROJECTION','FACT_TYPE_KEY','SEQUENCE_RANGE','BLOCK_RANGE','GENERATION','DIGEST') and ${t.selector}->>'type'=${t.selectorType}
    and octet_length(${t.selectorCbor}) between 1 and 65536
    and ${t.selectorDigest}='sha256:'||encode(sha256(${t.selectorCbor}),'hex')`,
      ),
      check(
        'retention_hold_state_ck',
        sql`(${t.state}='ACTIVE' and ${t.revision}=1 and ${t.releaseOperationId} is null and ${t.releaseApprovalRequestId} is null)
    or (${t.state}='RELEASED' and ${t.revision}=2 and ${t.releaseOperationId} is not null and ${t.releaseApprovalRequestId} is not null)`,
      ),
      scoped(t)[0]!,
      pgPolicy('privacy_domain_isolation', {
        as: 'restrictive',
        for: 'all',
        to: ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
          (name) => pgRole(name, { inherit: false }),
        ),
        using: sql`openpc.matches_participant(${t.participantId}) and (${t.selectorType}='PARTICIPANT' or openpc.matches_privacy(${t.privacyDomainId}))`,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
    ],
  )
  .enableRLS();

/** Original acknowledgements stay immutable when a later approved release arrives. */
export const evidenceHoldCoverage = control
  .table(
    'evidence_hold_coverage',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      retentionHoldId: uuid('retention_hold_id').notNull(),
      holdRevision: ordinal('hold_revision').notNull(),
      streamId: text('stream_id').notNull(),
      segmentId: uuid('segment_id').notNull(),
      objectDigest: text('object_digest').notNull(),
      sinkId: text('sink_id').notNull(),
      receipt: jsonb('receipt').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
      acknowledgedAt: time('acknowledged_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.retentionHoldId,
          t.holdRevision,
          t.sinkId,
          t.segmentId,
        ],
      }),
      foreignKey({
        name: 'evidence_hold_coverage_rule_fk',
        columns: [t.participantId, t.retentionHoldId],
        foreignColumns: [evidenceHolds.participantId, evidenceHolds.retentionHoldId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'evidence_hold_coverage_segment_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.segmentId],
        foreignColumns: [
          evidenceSegments.participantId,
          evidenceSegments.privacyDomainId,
          evidenceSegments.streamId,
          evidenceSegments.segmentId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_hold_coverage_digest_ck',
        sql`${t.holdRevision} in (1,2) and ${t.objectDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.receiptDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
