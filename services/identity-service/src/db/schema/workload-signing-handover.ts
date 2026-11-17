import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  numeric,
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
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { privacyDomains, principals, credentials } from './participants.js';
import type { WorkloadSigningHandoverRequest } from '../../contracts/workload-signing-handover.js';
import type { HandoverProviderBinding } from '../../domain/workload-signing-handover-provider.js';
import type {
  HandoverProviderAttempt,
  HandoverPossessionGeneration,
  HandoverPossessionGenerationRequest,
} from '../../domain/workload-signing-handover-possession.js';

/** Immutable preparation inputs. This row is neither approval nor key admission. */
export const workloadSigningHandovers = control
  .table(
    'workload_signing_handover',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      handoverId: uuid('handover_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      idempotencyKey: text('idempotency_key').notNull(),
      predecessorCredentialId: uuid('predecessor_credential_id').notNull(),
      successorCredentialId: uuid('successor_credential_id').notNull(),
      workloadPrincipalId: uuid('workload_principal_id').notNull(),
      environmentId: text('environment_id').notNull(),
      request: jsonb('request').$type<WorkloadSigningHandoverRequest>().notNull(),
      requestCanonical: bytea('request_canonical').notNull(),
      requestDigest: bytea('request_digest').notNull(),
      source: jsonb('source').$type<Record<string, unknown>>().notNull(),
      sourceCanonical: bytea('source_canonical').notNull(),
      sourceDigest: bytea('source_digest').notNull(),
      authoritySnapshot: bytea('authority_snapshot').notNull(),
      authoritySnapshotDigest: bytea('authority_snapshot_digest').notNull(),
      recordedAtNs: numeric('recorded_at_ns', {
        precision: 20,
        scale: 0,
        mode: 'bigint',
      }).notNull(),
      createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => [
      primaryKey({
        name: 'workload_signing_handover_pk',
        columns: [t.participantId, t.privacyDomainId, t.handoverId],
      }),
      unique('workload_signing_handover_id_uq').on(t.handoverId),
      unique('workload_signing_handover_replay_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.makerPrincipalId,
        t.idempotencyKey,
      ),
      unique('workload_signing_handover_successor_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.environmentId,
        t.successorCredentialId,
      ),
      foreignKey({
        name: 'workload_signing_handover_scope_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }),
      foreignKey({
        name: 'workload_signing_handover_maker_fk',
        columns: [t.participantId, t.makerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }),
      foreignKey({
        name: 'workload_signing_handover_principal_fk',
        columns: [t.participantId, t.workloadPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }),
      foreignKey({
        name: 'workload_signing_handover_predecessor_fk',
        columns: [t.participantId, t.predecessorCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }),
      foreignKey({
        name: 'workload_signing_handover_successor_fk',
        columns: [t.participantId, t.successorCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }),
      check(
        'workload_signing_handover_distinct_ck',
        sql`${t.predecessorCredentialId}<>${t.successorCredentialId}`,
      ),
      check(
        'workload_signing_handover_digests_ck',
        sql`octet_length(${t.requestDigest})=32 and octet_length(${t.sourceDigest})=32 and octet_length(${t.authoritySnapshotDigest})=32`,
      ),
      check(
        'workload_signing_handover_sizes_ck',
        sql`octet_length(${t.requestCanonical}) between 1 and 262144 and octet_length(${t.sourceCanonical}) between 1 and 8388608 and octet_length(${t.authoritySnapshot}) between 1 and 65536`,
      ),
      check(
        'workload_signing_handover_time_ck',
        sql`${t.recordedAtNs}>0 and mod(${t.recordedAtNs},1000)=0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** One immutable complete proof generation. Renewal of a settled, expired
 * challenge is an explicit successor generation, never a command overwrite. */
export const workloadSigningHandoverGenerations = control
  .table(
    'workload_signing_handover_generation',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      handoverId: uuid('handover_id').notNull(),
      generationId: uuid('generation_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      idempotencyKey: text('idempotency_key').notNull(),
      supersedesGenerationId: uuid('supersedes_generation_id'),
      request: jsonb('request').$type<HandoverPossessionGenerationRequest>().notNull(),
      requestCanonical: bytea('request_canonical').notNull(),
      requestDigest: bytea('request_digest').notNull(),
      document: jsonb('document').$type<HandoverPossessionGeneration>().notNull(),
      documentCanonical: bytea('document_canonical').notNull(),
      documentDigest: bytea('document_digest').notNull(),
      authoritySnapshot: bytea('authority_snapshot').notNull(),
      authoritySnapshotDigest: bytea('authority_snapshot_digest').notNull(),
      recordedAtNs: numeric('recorded_at_ns', {
        precision: 20,
        scale: 0,
        mode: 'bigint',
      }).notNull(),
      createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => [
      primaryKey({
        name: 'workload_handover_generation_pk',
        columns: [t.participantId, t.privacyDomainId, t.generationId],
      }),
      unique('workload_handover_generation_id_uq').on(t.generationId),
      unique('workload_handover_generation_replay_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.makerPrincipalId,
        t.idempotencyKey,
      ),
      uniqueIndex('workload_handover_generation_initial_uq')
        .on(t.participantId, t.privacyDomainId, t.handoverId)
        .where(sql`${t.supersedesGenerationId} is null`),
      uniqueIndex('workload_handover_generation_successor_uq')
        .on(t.participantId, t.privacyDomainId, t.supersedesGenerationId)
        .where(sql`${t.supersedesGenerationId} is not null`),
      foreignKey({
        name: 'workload_handover_generation_owner_fk',
        columns: [t.participantId, t.privacyDomainId, t.handoverId],
        foreignColumns: [
          workloadSigningHandovers.participantId,
          workloadSigningHandovers.privacyDomainId,
          workloadSigningHandovers.handoverId,
        ],
      }),
      foreignKey({
        name: 'workload_handover_generation_maker_fk',
        columns: [t.participantId, t.makerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }),
      foreignKey({
        name: 'workload_handover_generation_parent_fk',
        columns: [t.participantId, t.privacyDomainId, t.supersedesGenerationId],
        foreignColumns: [t.participantId, t.privacyDomainId, t.generationId],
      }),
      check(
        'workload_handover_generation_digest_ck',
        sql`octet_length(${t.requestDigest})=32 and octet_length(${t.documentDigest})=32 and octet_length(${t.authoritySnapshotDigest})=32`,
      ),
      check(
        'workload_handover_generation_size_ck',
        sql`octet_length(${t.requestCanonical}) between 1 and 8192 and octet_length(${t.documentCanonical}) between 1 and 1048576 and octet_length(${t.authoritySnapshot}) between 1 and 65536`,
      ),
      check(
        'workload_handover_generation_time_ck',
        sql`${t.recordedAtNs}>0 and mod(${t.recordedAtNs},1000)=0 and (${t.supersedesGenerationId} is null or ${t.supersedesGenerationId}<>${t.generationId})`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** Exact commands are retained before dispatch. Later outcomes must refer to
 * this immutable attempt, never replace its bytes or scope. */
export const workloadSigningHandoverAttempts = control
  .table(
    'workload_signing_handover_attempt',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      handoverId: uuid('handover_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      predecessorFingerprint: text('predecessor_fingerprint').notNull(),
      providerId: text('provider_id').notNull(),
      stage: text('stage', { enum: ['PREPARATION', 'POSSESSION'] })
        .notNull()
        .default('PREPARATION'),
      generationId: uuid('generation_id'),
      preparationAttemptId: uuid('preparation_attempt_id'),
      binding: jsonb('binding').$type<HandoverProviderBinding>().notNull(),
      bindingCanonical: bytea('binding_canonical').notNull(),
      bindingDigest: bytea('binding_digest').notNull(),
      attempt: jsonb('attempt').$type<HandoverProviderAttempt>().notNull(),
      attemptCanonical: bytea('attempt_canonical').notNull(),
      attemptDigest: bytea('attempt_digest').notNull(),
      authoritySnapshot: bytea('authority_snapshot').notNull(),
      authoritySnapshotDigest: bytea('authority_snapshot_digest').notNull(),
      recordedAtNs: numeric('recorded_at_ns', {
        precision: 20,
        scale: 0,
        mode: 'bigint',
      }).notNull(),
      createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => [
      primaryKey({
        name: 'workload_handover_attempt_pk',
        columns: [t.participantId, t.privacyDomainId, t.attemptId],
      }),
      unique('workload_handover_attempt_id_uq').on(t.attemptId),
      uniqueIndex('workload_handover_preparation_key_uq')
        .on(t.participantId, t.privacyDomainId, t.handoverId, t.predecessorFingerprint)
        .where(sql`${t.stage}='PREPARATION'`),
      uniqueIndex('workload_handover_possession_key_uq')
        .on(
          t.participantId,
          t.privacyDomainId,
          t.handoverId,
          t.generationId,
          t.predecessorFingerprint,
        )
        .where(sql`${t.stage}='POSSESSION'`),
      foreignKey({
        name: 'workload_handover_attempt_generation_fk',
        columns: [t.participantId, t.privacyDomainId, t.generationId],
        foreignColumns: [
          workloadSigningHandoverGenerations.participantId,
          workloadSigningHandoverGenerations.privacyDomainId,
          workloadSigningHandoverGenerations.generationId,
        ],
      }),
      foreignKey({
        name: 'workload_handover_attempt_preparation_fk',
        columns: [t.participantId, t.privacyDomainId, t.preparationAttemptId],
        foreignColumns: [t.participantId, t.privacyDomainId, t.attemptId],
      }),
      check(
        'workload_handover_attempt_stage_ck',
        sql`(${t.stage}='PREPARATION' and ${t.generationId} is null and ${t.preparationAttemptId} is null) or (${t.stage}='POSSESSION' and ${t.generationId} is not null and ${t.preparationAttemptId} is not null and ${t.preparationAttemptId}<>${t.attemptId})`,
      ),
      foreignKey({
        name: 'workload_handover_attempt_owner_fk',
        columns: [t.participantId, t.privacyDomainId, t.handoverId],
        foreignColumns: [
          workloadSigningHandovers.participantId,
          workloadSigningHandovers.privacyDomainId,
          workloadSigningHandovers.handoverId,
        ],
      }),
      foreignKey({
        name: 'workload_handover_attempt_maker_fk',
        columns: [t.participantId, t.makerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }),
      check(
        'workload_handover_attempt_digest_ck',
        sql`octet_length(${t.bindingDigest})=32 and octet_length(${t.attemptDigest})=32 and octet_length(${t.authoritySnapshotDigest})=32`,
      ),
      check(
        'workload_handover_attempt_size_ck',
        sql`octet_length(${t.bindingCanonical}) between 1 and 16384 and octet_length(${t.attemptCanonical}) between 1 and 16384 and octet_length(${t.authoritySnapshot}) between 1 and 65536`,
      ),
      check(
        'workload_handover_attempt_time_ck',
        sql`${t.recordedAtNs}>0 and mod(${t.recordedAtNs},1000)=0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
