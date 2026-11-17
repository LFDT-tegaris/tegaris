import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  numeric,
  smallint,
  text,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { businessTransitionProfiles } from './business-evidence.js';
import { businessSigningKeys } from './business-signing.js';
import { idempotencyRecords } from './workflow.js';

const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });

/** Atomic local audit occurrence carrying the committed business receipt and its retained inputs. */
export const auditOccurrences = control
  .table(
    'audit_occurrence',
    {
      receiptId: uuid('receipt_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      idempotencyRecordId: uuid('idempotency_record_id').notNull(),
      schemaDefinitionDigest: bytea('schema_definition_digest').notNull(),
      profileId: text('profile_id').notNull(),
      profileVersion: bigint('profile_version', { mode: 'number' }).notNull(),
      profileDigest: bytea('profile_digest').notNull(),
      environmentId: text('environment_id').notNull(),
      actionIntentId: text('action_intent_id').notNull(),
      catalogOperationId: text('catalog_operation_id').notNull(),
      aggregateType: text('aggregate_type').notNull(),
      aggregateId: uuid('aggregate_id').notNull(),
      actorKeyDigest: bytea('actor_key_digest').notNull(),
      preCommitAuthorityDigest: bytea('pre_commit_authority_digest').notNull(),
      actionIntentDigest: bytea('action_intent_digest').notNull(),
      candidateDigest: bytea('candidate_digest').notNull(),
      requestDigest: bytea('request_digest').notNull(),
      beforeExistence: smallint('before_existence').notNull(),
      beforeRevision: u64('before_revision').notNull(),
      beforeStateDigest: bytea('before_state_digest').notNull(),
      beforeStatePreimage: bytea('before_state_preimage').notNull(),
      afterExistence: smallint('after_existence').notNull(),
      afterRevision: u64('after_revision').notNull(),
      afterStateDigest: bytea('after_state_digest').notNull(),
      afterStatePreimage: bytea('after_state_preimage').notNull(),
      authoritySnapshot: bytea('authority_snapshot').notNull(),
      transitionKind: smallint('transition_kind').notNull(),
      recordedAtNs: u64('recorded_at_ns').notNull(),
      signerId: text('signer_id').notNull(),
      signerTrustSnapshotDigest: bytea('signer_trust_snapshot_digest').notNull(),
      receiptCbor: bytea('receipt_cbor').notNull(),
      receiptDigest: bytea('receipt_digest').notNull(),
      coseSign1: bytea('cose_sign1').notNull(),
    },
    (table) => [
      unique('audit_occurrence_scope_id_uq').on(
        table.participantId,
        table.privacyDomainId,
        table.receiptId,
      ),
      unique('audit_occurrence_scope_operation_uq').on(
        table.participantId,
        table.privacyDomainId,
        table.operationId,
      ),
      unique('audit_occurrence_scope_id_digest_uq').on(
        table.participantId,
        table.privacyDomainId,
        table.receiptId,
        table.receiptDigest,
      ),
      foreignKey({
        name: 'audit_occurrence_profile_fk',
        columns: [table.profileId, table.profileVersion, table.profileDigest],
        foreignColumns: [
          businessTransitionProfiles.profileId,
          businessTransitionProfiles.profileVersion,
          businessTransitionProfiles.profileDigest,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'audit_occurrence_trust_fk',
        columns: [
          table.participantId,
          table.privacyDomainId,
          table.signerId,
          table.signerTrustSnapshotDigest,
        ],
        foreignColumns: [
          businessSigningKeys.participantId,
          businessSigningKeys.privacyDomainId,
          businessSigningKeys.signerId,
          businessSigningKeys.trustDigest,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'audit_occurrence_idempotency_fk',
        columns: [
          table.participantId,
          table.privacyDomainId,
          table.operationId,
          table.idempotencyRecordId,
        ],
        foreignColumns: [
          idempotencyRecords.participantId,
          idempotencyRecords.privacyDomainId,
          idempotencyRecords.operationId,
          idempotencyRecords.idempotencyRecordId,
        ],
      }).onDelete('restrict'),
      check(
        'audit_occurrence_v7_ck',
        sql`substring(${table.receiptId}::text from 15 for 1)='7' and substring(${table.operationId}::text from 15 for 1)='7' and substring(${table.idempotencyRecordId}::text from 15 for 1)='7'`,
      ),
      check(
        'audit_occurrence_time_ck',
        sql`${table.recordedAtNs} between 0 and 18446744073709551615 and mod(${table.recordedAtNs},1000)=0`,
      ),
      check(
        'audit_occurrence_states_ck',
        sql`${table.beforeExistence} in (0,1,2) and ${table.afterExistence} in (1,2) and ${table.beforeRevision} between 0 and 18446744073709551615 and ${table.afterRevision} between 1 and 18446744073709551615 and (${table.beforeExistence}<>0 or ${table.beforeRevision}=0)`,
      ),
      check(
        'audit_occurrence_digests_ck',
        sql`octet_length(${table.receiptCbor}) between 1 and 65536 and octet_length(${table.coseSign1}) between 1 and 66560 and ${table.receiptDigest}=sha256(${table.receiptCbor}) and ${table.beforeStateDigest}=sha256(${table.beforeStatePreimage}) and ${table.afterStateDigest}=sha256(${table.afterStatePreimage}) and ${table.preCommitAuthorityDigest}=sha256(${table.authoritySnapshot})`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();

/** Local custody catalog only: durable control-store receipt, with no external sink quorum claim. */
export const evidenceRecords = control
  .table(
    'evidence_record',
    {
      evidenceRecordId: uuid('evidence_record_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      receiptId: uuid('receipt_id').notNull(),
      receiptDigest: bytea('receipt_digest').notNull(),
      evidenceRole: text('evidence_role').notNull(),
      evidenceFormat: text('evidence_format').notNull(),
      custody: text('custody').notNull(),
      sinkQuorum: smallint('sink_quorum').notNull(),
      recordedAtNs: u64('recorded_at_ns').notNull(),
    },
    (table) => [
      unique('evidence_record_scope_receipt_uq').on(
        table.participantId,
        table.privacyDomainId,
        table.receiptId,
      ),
      foreignKey({
        name: 'evidence_record_occurrence_fk',
        columns: [table.participantId, table.privacyDomainId, table.receiptId, table.receiptDigest],
        foreignColumns: [
          auditOccurrences.participantId,
          auditOccurrences.privacyDomainId,
          auditOccurrences.receiptId,
          auditOccurrences.receiptDigest,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_record_custody_ck',
        sql`${table.evidenceRole}='BUSINESS_TRANSITION_RECEIPT' and ${table.evidenceFormat} in ('COSE_SIGN1_24001_1_338','COSE_SIGN1_24001_2_338') and ${table.custody}='CONTROL_STORE' and ${table.sinkQuorum}=0`,
      ),
      check(
        'evidence_record_time_ck',
        sql`${table.recordedAtNs} between 0 and 18446744073709551615 and mod(${table.recordedAtNs},1000)=0`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();
