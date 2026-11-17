import { sql } from 'drizzle-orm';
import { check, foreignKey, integer, jsonb, text, unique, uuid } from 'drizzle-orm/pg-core';
import { privacyDomains } from '../../../identity-service/src/db/schema/participants.js';
import { retentionPolicies } from './retention-schema.js';
import { protectedProofObjects } from './protected-schema.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceTimestamp as time,
  evidenceSegments,
} from './schema.js';

/** One approved bounded local batch. Its data effect, result and signed receipt
 * commit together; uncertain COMMIT is reconciled by the shared operation owner.
 */
export const evidenceDeletionJobs = control
  .table(
    'deletion_job',
    {
      deletionJobId: uuid('deletion_job_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      retentionPolicyId: uuid('retention_policy_id').notNull(),
      streamId: text('stream_id'),
      segmentId: uuid('segment_id'),
      protectedObjectId: uuid('protected_object_id'),
      previousDeletionJobId: uuid('previous_deletion_job_id'),
      targetDatabase: text('target_database').notNull().default('openpc_control'),
      targetDataClass: text('target_data_class').notNull().default('AUDIT_EVIDENCE'),
      selection: jsonb('selection').notNull(),
      targetSelectorDigest: text('target_selector_digest').notNull(),
      eligibilityDigest: text('eligibility_digest').notNull(),
      beforeDigest: text('before_digest').notNull(),
      afterDigest: text('after_digest'),
      approvalRequestId: uuid('approval_request_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      externalAttemptState: text('external_attempt_state').notNull().default('NOT_STARTED'),
      state: text('state').notNull().default('EXECUTING'),
      revision: ordinal('revision').notNull().default('0'),
      deletedCount: integer('deleted_count').notNull().default(0),
      deletedBytes: integer('deleted_bytes').notNull().default(0),
      beforeUsedBytes: integer('before_used_bytes').notNull().default(0),
      afterUsedBytes: integer('after_used_bytes'),
      retainedAliasCount: integer('retained_alias_count').notNull().default(0),
      startedAt: time('started_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      completedAt: time('completed_at'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('deletion_job_scope_uq').on(t.participantId, t.privacyDomainId, t.deletionJobId),
      unique('deletion_job_operation_uq').on(t.operationId),
      unique('deletion_job_attempt_uq').on(t.attemptId),
      unique('deletion_job_continuation_uq').on(t.previousDeletionJobId),
      foreignKey({
        name: 'deletion_job_previous_fk',
        columns: [t.participantId, t.privacyDomainId, t.previousDeletionJobId],
        foreignColumns: [t.participantId, t.privacyDomainId, t.deletionJobId],
      }).onDelete('restrict'),
      unique('deletion_job_eligibility_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.targetSelectorDigest,
        t.eligibilityDigest,
      ),
      foreignKey({
        name: 'deletion_job_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'deletion_job_policy_fk',
        columns: [t.participantId, t.privacyDomainId, t.retentionPolicyId],
        foreignColumns: [
          retentionPolicies.participantId,
          retentionPolicies.privacyDomainId,
          retentionPolicies.retentionPolicyId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'deletion_job_segment_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.segmentId],
        foreignColumns: [
          evidenceSegments.participantId,
          evidenceSegments.privacyDomainId,
          evidenceSegments.streamId,
          evidenceSegments.segmentId,
        ],
      }).onDelete('restrict'),
      check(
        'deletion_job_target_ck',
        sql`${t.targetDatabase}='openpc_control' and ${t.externalAttemptState}='NOT_STARTED' and ${t.retainedAliasCount}=0 and
        ((${t.targetDataClass} in ('AUDIT_EVIDENCE','NORMALIZED_JSON_PROJECTION','SEARCH_PROJECTION') and ${t.streamId} is not null and ${t.segmentId} is not null and ${t.protectedObjectId} is null)
        or (${t.targetDataClass}='RUNTIME_ARTIFACT' and ${t.streamId} is not null and ${t.segmentId} is null and ${t.protectedObjectId} is null)
        or (${t.targetDataClass}='RAW_SOURCE_BODY' and ${t.streamId} is null and ${t.segmentId} is null and ${t.protectedObjectId} is not null))`,
      ),
      foreignKey({
        name: 'deletion_job_protected_object_fk',
        columns: [t.participantId, t.privacyDomainId, t.protectedObjectId],
        foreignColumns: [
          protectedProofObjects.participantId,
          protectedProofObjects.privacyDomainId,
          protectedProofObjects.objectId,
        ],
      }).onDelete('restrict'),
      check(
        'deletion_job_digest_ck',
        sql`${t.targetSelectorDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.eligibilityDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.beforeDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'deletion_job_accounting_ck',
        sql`${t.beforeUsedBytes} between 1 and 1073741824 and
    ((${t.state}='EXECUTING' and ${t.afterUsedBytes} is null) or (${t.state}='SUCCEEDED' and ${t.afterUsedBytes} is not null and ${t.afterUsedBytes}>=0 and ${t.afterUsedBytes}=${t.beforeUsedBytes}-${t.deletedBytes}))`,
      ),
      check(
        'deletion_job_state_ck',
        sql`(${t.state}='EXECUTING' and ${t.revision}=0 and ${t.deletedCount}=0 and ${t.deletedBytes}=0 and ${t.afterDigest} is null and ${t.completedAt} is null)
    or (${t.state}='SUCCEEDED' and ${t.revision}=1 and ${t.deletedCount}=1 and ${t.deletedBytes} between 1 and (case when ${t.targetDataClass}='RUNTIME_ARTIFACT' then 4194304 else 2097152 end) and ${t.afterDigest} is not null and ${t.afterDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.completedAt} is not null and ${t.completedAt}>=${t.startedAt})`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Actual OLD payload metadata is captured by deletion's database guard, never
 * accepted as an asserted effect from an HTTP caller or the repository writer.
 */
export const evidenceDeletionItems = control
  .table(
    'evidence_deletion_item',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      deletionJobId: uuid('deletion_job_id').primaryKey(),
      segmentId: uuid('segment_id').unique(),
      protectedObjectId: uuid('protected_object_id').unique(),
      objectDigest: text('object_digest').notNull(),
      ciphertextBytes: integer('ciphertext_bytes').notNull(),
    },
    (t) => [
      foreignKey({
        name: 'evidence_deletion_item_job_fk',
        columns: [t.participantId, t.privacyDomainId, t.deletionJobId],
        foreignColumns: [
          evidenceDeletionJobs.participantId,
          evidenceDeletionJobs.privacyDomainId,
          evidenceDeletionJobs.deletionJobId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_deletion_item_digest_ck',
        sql`${t.objectDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.ciphertextBytes} between 1 and 2097152`,
      ),
      check(
        'evidence_deletion_item_target_ck',
        sql`(${t.segmentId} is null)<>(${t.protectedObjectId} is null)`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
