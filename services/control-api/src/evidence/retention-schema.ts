import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  foreignKey,
  smallint,
  text,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { privacyDomains } from '../../../identity-service/src/db/schema/participants.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceTimestamp as time,
  evidenceBytes as bytes,
} from './schema.js';

/** Immutable version contents; a separate governed retirement closes its interval. */
export const retentionPolicies = control
  .table(
    'retention_policy',
    {
      retentionPolicyId: uuid('retention_policy_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      predecessorPolicyId: uuid('predecessor_policy_id'),
      dataClass: text('data_class').notNull(),
      policyVersion: text('policy_version').notNull(),
      retentionPeriodMs: ordinal('retention_period_ms').notNull(),
      localGraceMs: ordinal('local_grace_ms').notNull(),
      sinkQuorum: smallint('sink_quorum').notNull(),
      deletionMode: text('deletion_mode').notNull(),
      makerCheckerRequired: boolean('maker_checker_required').notNull(),
      policyCbor: bytes('policy_cbor').notNull(),
      policyDigest: text('policy_digest').notNull(),
      approvalRequestId: uuid('approval_request_id').notNull(),
      retirementApprovalRequestId: uuid('retirement_approval_request_id'),
      activationOperationId: uuid('activation_operation_id').notNull(),
      retirementOperationId: uuid('retirement_operation_id'),
      revision: ordinal('revision').notNull().default('1'),
      activeFrom: time('active_from')
        .notNull()
        .default(sql`clock_timestamp()`),
      activeUntil: time('active_until'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('retention_policy_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.retentionPolicyId,
      ),
      unique('retention_policy_version_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.dataClass,
        t.policyVersion,
      ),
      unique('retention_policy_activation_uq').on(t.activationOperationId),
      foreignKey({
        name: 'retention_policy_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'retention_policy_predecessor_fk',
        columns: [t.participantId, t.privacyDomainId, t.predecessorPolicyId],
        foreignColumns: [t.participantId, t.privacyDomainId, t.retentionPolicyId],
      }).onDelete('restrict'),
      uniqueIndex('retention_policy_active_uq')
        .on(t.participantId, t.privacyDomainId, t.dataClass)
        .where(sql`${t.activeUntil} is null`),
      check(
        'retention_policy_class_ck',
        sql`${t.dataClass} in ('RAW_SOURCE_BODY','NORMALIZED_JSON_PROJECTION','SEARCH_PROJECTION','RUNTIME_ARTIFACT','ADMITTED_FACT','CANDIDATE_PROJECTION','AUDIT_EVIDENCE','NOTIFICATION_PAYLOAD','OUTBOX_INBOX','IDENTITY_RECORD')`,
      ),
      check(
        'retention_policy_version_ck',
        sql`${t.policyVersion} ~ '^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:[+][0-9A-Za-z.-]+)?$' and length(${t.policyVersion})<=128`,
      ),
      check(
        'retention_policy_duration_ck',
        sql`${t.retentionPeriodMs} between 0 and 9223372036854775807 and ${t.localGraceMs} between 0 and 9223372036854775807 and ${t.sinkQuorum} between 0 and 8`,
      ),
      check(
        'retention_policy_mode_ck',
        sql`${t.deletionMode} in ('ROW_DELETE','PROJECTION_DELETE','IDENTIFIER_ALIAS','CRYPTO_SHRED')`,
      ),
      check(
        'retention_policy_digest_ck',
        sql`octet_length(${t.policyCbor}) between 1 and 65536 and ${t.policyDigest}='sha256:'||encode(sha256(${t.policyCbor}),'hex')`,
      ),
      check(
        'retention_policy_interval_ck',
        sql`(${t.revision}=1 and ${t.activeUntil} is null and ${t.retirementOperationId} is null and ${t.retirementApprovalRequestId} is null) or (${t.revision}=2 and ${t.activeUntil}>${t.activeFrom} and ${t.retirementOperationId} is not null and ${t.retirementApprovalRequestId} is not null)`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
