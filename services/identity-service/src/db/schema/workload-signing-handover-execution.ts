import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  integer,
  jsonb,
  numeric,
  primaryKey,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { workloadSigningHandoverAttempts } from './workload-signing-handover.js';
import { principals } from './participants.js';
import type { HandoverProviderResult } from '../../domain/workload-signing-handover-result.js';

export const workloadSigningHandoverDispatches = control
  .table(
    'workload_signing_handover_dispatch',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      handoverId: uuid('handover_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      dispatchId: uuid('dispatch_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      attemptDigest: bytea('attempt_digest').notNull(),
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
        name: 'workload_handover_dispatch_pk',
        columns: [t.participantId, t.privacyDomainId, t.dispatchId],
      }),
      unique('workload_handover_dispatch_id_uq').on(t.dispatchId),
      unique('workload_handover_dispatch_attempt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.attemptId,
      ),
      foreignKey({
        name: 'workload_handover_dispatch_attempt_fk',
        columns: [t.participantId, t.privacyDomainId, t.attemptId],
        foreignColumns: [
          workloadSigningHandoverAttempts.participantId,
          workloadSigningHandoverAttempts.privacyDomainId,
          workloadSigningHandoverAttempts.attemptId,
        ],
      }),
      foreignKey({
        name: 'workload_handover_dispatch_maker_fk',
        columns: [t.participantId, t.makerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }),
      check(
        'workload_handover_dispatch_digest_ck',
        sql`octet_length(${t.attemptDigest})=32 and octet_length(${t.sourceDigest})=32 and octet_length(${t.authoritySnapshotDigest})=32`,
      ),
      check(
        'workload_handover_dispatch_size_ck',
        sql`octet_length(${t.authoritySnapshot}) between 1 and 65536`,
      ),
      check(
        'workload_handover_dispatch_time_ck',
        sql`${t.recordedAtNs}>0 and mod(${t.recordedAtNs},1000)=0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** Append-only external observations. Recording truth confers no current authority. */
export const workloadSigningHandoverObservations = control
  .table(
    'workload_signing_handover_observation',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      handoverId: uuid('handover_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      dispatchId: uuid('dispatch_id').notNull(),
      observationId: uuid('observation_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      sequence: integer('sequence').notNull(),
      result: jsonb('result').$type<HandoverProviderResult>().notNull(),
      resultCanonical: bytea('result_canonical').notNull(),
      resultDigest: bytea('result_digest').notNull(),
      previousDigest: bytea('previous_digest'),
      entryCanonical: bytea('entry_canonical').notNull(),
      entryDigest: bytea('entry_digest').notNull(),
      recordedAtNs: numeric('recorded_at_ns', {
        precision: 20,
        scale: 0,
        mode: 'bigint',
      }).notNull(),
      createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => [
      primaryKey({
        name: 'workload_handover_observation_pk',
        columns: [t.participantId, t.privacyDomainId, t.observationId],
      }),
      unique('workload_handover_observation_id_uq').on(t.observationId),
      unique('workload_handover_observation_sequence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.attemptId,
        t.sequence,
      ),
      foreignKey({
        name: 'workload_handover_observation_dispatch_fk',
        columns: [t.participantId, t.privacyDomainId, t.dispatchId],
        foreignColumns: [
          workloadSigningHandoverDispatches.participantId,
          workloadSigningHandoverDispatches.privacyDomainId,
          workloadSigningHandoverDispatches.dispatchId,
        ],
      }),
      check(
        'workload_handover_observation_digest_ck',
        sql`octet_length(${t.resultDigest})=32 and octet_length(${t.entryDigest})=32 and (${t.previousDigest} is null or octet_length(${t.previousDigest})=32)`,
      ),
      check(
        'workload_handover_observation_size_ck',
        sql`octet_length(${t.resultCanonical}) between 1 and 262144 and octet_length(${t.entryCanonical}) between 1 and 8192`,
      ),
      check(
        'workload_handover_observation_time_ck',
        sql`${t.recordedAtNs}>0 and mod(${t.recordedAtNs},1000)=0 and ${t.sequence}>0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
