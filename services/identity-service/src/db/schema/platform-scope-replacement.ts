import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  numeric,
  pgPolicy,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  controlOwnerRole,
  controlRuntimeRole,
  controlPlatformRuntimeRole,
  controlReaderRole,
  controlWorkerRole,
} from './common.js';
import { platformContexts } from './platform-context.js';
import { participants, privacyDomains } from './participants.js';
import { approvalRequests, mutationCandidates } from './workflow.js';

const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });

/** The genesis source stays immutable. Preparation is an approved intent,
 * not a new root or permission; only committed successors can be selected. */
export const platformScopeReplacements = control
  .table(
    'platform_scope_replacement',
    {
      replacementId: uuid('replacement_id').primaryKey(),
      platformContextId: uuid('platform_context_id')
        .notNull()
        .references(() => platformContexts.platformContextId, { onDelete: 'restrict' }),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      predecessorEpoch: u64('predecessor_epoch').notNull(),
      expectedRootRevision: u64('expected_root_revision').notNull(),
      predecessorDigest: bytea('predecessor_digest').notNull(),
      candidate: jsonb('candidate').notNull(),
      candidateDigest: bytea('candidate_digest').notNull(),
      successorScopeCbor: bytea('successor_scope_cbor').notNull(),
      successorPreimage: bytea('successor_preimage').notNull(),
      successorDigest: bytea('successor_digest').notNull(),
      prepareOperationId: uuid('prepare_operation_id').notNull().unique(),
      prepareCandidateId: uuid('prepare_candidate_id').notNull(),
      prepareApprovalId: uuid('prepare_approval_id').notNull(),
      state: text('state').notNull().default('WITHDRAWING'),
      rowVersion: u64('row_version')
        .notNull()
        .default(sql`1`),
      commitOperationId: uuid('commit_operation_id').unique(),
      commitCandidateId: uuid('commit_candidate_id'),
      commitApprovalId: uuid('commit_approval_id'),
      readinessDigest: bytea('readiness_digest'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      committedAt: time('committed_at'),
      supersededBy: uuid('superseded_by'),
    },
    (t) => [
      unique('platform_scope_replacement_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.replacementId,
      ),
      uniqueIndex('platform_scope_replacement_pending_uq')
        .on(t.platformContextId)
        .where(sql`${t.state}='WITHDRAWING'`),
      foreignKey({
        name: 'platform_scope_replacement_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'platform_scope_replacement_candidate_fk',
        columns: [t.participantId, t.prepareCandidateId],
        foreignColumns: [mutationCandidates.participantId, mutationCandidates.mutationCandidateId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'platform_scope_replacement_approval_fk',
        columns: [t.participantId, t.prepareApprovalId],
        foreignColumns: [approvalRequests.participantId, approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'platform_scope_replacement_commit_candidate_fk',
        columns: [t.participantId, t.commitCandidateId],
        foreignColumns: [mutationCandidates.participantId, mutationCandidates.mutationCandidateId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'platform_scope_replacement_commit_approval_fk',
        columns: [t.participantId, t.commitApprovalId],
        foreignColumns: [approvalRequests.participantId, approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      check(
        'platform_scope_replacement_epoch_ck',
        sql`${t.predecessorEpoch} between 1 and 18446744073709551614
    and ${t.expectedRootRevision} between 1 and 18446744073709551615`,
      ),
      check(
        'platform_scope_replacement_bytes_ck',
        sql`octet_length(${t.predecessorDigest})=32
    and octet_length(${t.candidateDigest})=32 and octet_length(${t.successorDigest})=32
    and octet_length(${t.successorScopeCbor}) between 1 and 60000
    and octet_length(${t.successorPreimage}) between 1 and 65536
    and ${t.successorDigest}=sha256(${t.successorPreimage})`,
      ),
      check(
        'platform_scope_replacement_state_ck',
        sql`
    (${t.state}='WITHDRAWING' and ${t.supersededBy} is null and ${t.rowVersion}=1 and ${t.commitOperationId} is null
      and ${t.commitCandidateId} is null and ${t.commitApprovalId} is null
      and ${t.readinessDigest} is null and ${t.committedAt} is null)
    or (${t.state}='SUPERSEDED' and ${t.rowVersion}=2 and ${t.supersededBy} is not null
      and ${t.supersededBy}<>${t.replacementId} and ${t.commitOperationId} is null
      and ${t.commitCandidateId} is null and ${t.commitApprovalId} is null
      and ${t.readinessDigest} is null and ${t.committedAt} is null)
    or (${t.state}='COMMITTED' and ${t.supersededBy} is null and ${t.rowVersion}=2 and ${t.commitOperationId} is not null
      and ${t.commitCandidateId} is not null and ${t.commitApprovalId} is not null
        and ${t.readinessDigest} is not null and octet_length(${t.readinessDigest})=32 and ${t.committedAt} is not null)`,
      ),
      pgPolicy('platform_scope_replacement_read', {
        for: 'select',
        to: [
          controlOwnerRole,
          controlRuntimeRole,
          controlPlatformRuntimeRole,
          controlReaderRole,
          controlWorkerRole,
        ],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      // No application role gets a write policy. The governed SQL owner admits writes.
      pgPolicy('platform_scope_replacement_owner', {
        for: 'all',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
    ],
  )
  .enableRLS();

/** Append-only effective roots. No successor overwrites the initial source. */
export const platformEnvelopeScopeSuccessors = control
  .table(
    'platform_envelope_scope_successor',
    {
      platformContextId: uuid('platform_context_id')
        .notNull()
        .references(() => platformContexts.platformContextId, { onDelete: 'restrict' }),
      platformAuthorityEpoch: u64('platform_authority_epoch').notNull(),
      replacementId: uuid('replacement_id')
        .notNull()
        .references(() => platformScopeReplacements.replacementId, { onDelete: 'restrict' }),
      preparationOperationId: uuid('preparation_operation_id').notNull(),
      predecessorEpoch: u64('predecessor_epoch').notNull(),
      predecessorDigest: bytea('predecessor_digest').notNull(),
      ownerParticipantId: uuid('owner_participant_id').notNull(),
      installationPrivacyDomainId: uuid('installation_privacy_domain_id').notNull(),
      environmentId: text('environment_id').notNull(),
      installationDigest: text('installation_digest').notNull(),
      scopeCbor: bytea('scope_cbor').notNull(),
      admissionPreimage: bytea('admission_preimage').notNull(),
      admissionDigest: bytea('admission_digest').notNull(),
      committedAt: time('committed_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        name: 'platform_scope_successor_pk',
        columns: [t.platformContextId, t.platformAuthorityEpoch],
      }),
      unique('platform_scope_successor_replacement_uq').on(t.replacementId),
      foreignKey({
        name: 'platform_scope_successor_owner_fk',
        columns: [t.ownerParticipantId, t.installationPrivacyDomainId, t.replacementId],
        foreignColumns: [
          platformScopeReplacements.participantId,
          platformScopeReplacements.privacyDomainId,
          platformScopeReplacements.replacementId,
        ],
      }).onDelete('restrict'),
      check(
        'platform_scope_successor_epoch_ck',
        sql`${t.platformAuthorityEpoch} between 2 and 18446744073709551615
    and ${t.predecessorEpoch}=${t.platformAuthorityEpoch}-1`,
      ),
      check(
        'platform_scope_successor_bytes_ck',
        sql`octet_length(${t.scopeCbor}) between 1 and 60000
    and octet_length(${t.admissionPreimage}) between 1 and 65536
    and octet_length(${t.admissionDigest})=32 and ${t.admissionDigest}=sha256(${t.admissionPreimage})
    and octet_length(${t.predecessorDigest})=32`,
      ),
      pgPolicy('platform_scope_successor_owner', {
        for: 'all',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.ownerParticipantId}) and openpc.matches_privacy(${t.installationPrivacyDomainId})`,
        withCheck: sql`openpc.matches_participant(${t.ownerParticipantId}) and openpc.matches_privacy(${t.installationPrivacyDomainId})`,
      }),
      pgPolicy('platform_scope_successor_read', {
        for: 'select',
        to: [
          controlOwnerRole,
          controlRuntimeRole,
          controlPlatformRuntimeRole,
          controlReaderRole,
          controlWorkerRole,
        ],
        using: sql`exists(select 1 from control.authority_envelope e
      where e.platform_context_id=${t.platformContextId} and openpc.matches_participant(e.participant_id)
        and openpc.current_privacy_domain_id()::text=any(e.privacy_domain_ids))`,
      }),
    ],
  )
  .enableRLS();
