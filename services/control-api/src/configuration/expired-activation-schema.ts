import { sql } from 'drizzle-orm';
import { bigint, check, jsonb, text, uuid } from 'drizzle-orm/pg-core';
import { configurationWork } from './schema.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceTimestamp as time,
} from '../evidence/schema.js';

/** Native, denial-only admission for an installed effect whose serving
 * confirmation expired. Original approval, observation and work remain separate. */
export const runtimeExpiredActivationDenials = control
  .table(
    'runtime_expired_activation_denial',
    {
      configurationWorkId: uuid('configuration_work_id')
        .primaryKey()
        .references(() => configurationWork.configurationWorkId, { onDelete: 'restrict' }),
      requestId: uuid('request_id').notNull().unique(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      runtimeTargetId: uuid('runtime_target_id').notNull(),
      executionAttemptId: uuid('execution_attempt_id').notNull(),
      admissionRevision: bigint('admission_revision', { mode: 'number' }).notNull(),
      admissionDigest: text('admission_digest').notNull(),
      capsuleDigest: text('capsule_digest').notNull(),
      capsuleGeneration: bigint('capsule_generation', { mode: 'number' }).notNull(),
      proof: jsonb('proof').notNull(),
      intentBytes: bytes('intent_bytes').notNull(),
      intentDigest: text('intent_digest').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      ...scoped(t),
      check(
        'runtime_expired_denial_intent_ck',
        sql`${t.intentDigest}='sha256:'||encode(sha256(${t.intentBytes}),'hex') and octet_length(${t.intentBytes}) between 2 and 16384`,
      ),
      check(
        'runtime_expired_denial_generation_ck',
        sql`${t.capsuleGeneration}>0 and ${t.admissionRevision}>1`,
      ),
    ],
  )
  .enableRLS();

/** An acknowledged, non-serving physical predecessor. This never changes the
 * public active-generation field. A newer confirmed effect supersedes the
 * projection through its ordinary atomic target/head update. */
export const runtimeDeniedPredecessors = control
  .table(
    'runtime_denied_predecessor',
    {
      configurationWorkId: uuid('configuration_work_id')
        .primaryKey()
        .references(() => runtimeExpiredActivationDenials.configurationWorkId, {
          onDelete: 'restrict',
        }),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      runtimeTargetId: uuid('runtime_target_id').notNull(),
      capsuleDigest: text('capsule_digest').notNull(),
      lastConfirmedCapsuleDigest: text('last_confirmed_capsule_digest').notNull(),
      xdsVersionDigest: text('xds_version_digest').notNull(),
      capsuleGeneration: bigint('capsule_generation', { mode: 'number' }).notNull(),
      denialRevision: bigint('denial_revision', { mode: 'number' }).notNull(),
      deliveryDigest: text('delivery_digest').notNull(),
      acknowledgementDigest: text('acknowledgement_digest').notNull(),
      resultEventId: uuid('result_event_id').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [...scoped(t)],
  )
  .enableRLS();

/** One NEW, denial-only handover. Its abandoned admission and original denial
 * fact remain immutable. A primary key prevents an automatic recovery chain. */
export const runtimeExpiredDenialHandovers = control
  .table(
    'runtime_expired_denial_handover',
    {
      configurationWorkId: uuid('configuration_work_id')
        .primaryKey()
        .references(() => runtimeExpiredActivationDenials.configurationWorkId, {
          onDelete: 'restrict',
        }),
      requestId: uuid('request_id').notNull().unique(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      runtimeTargetId: uuid('runtime_target_id').notNull(),
      abandonedRevision: bigint('abandoned_revision', { mode: 'number' }).notNull(),
      abandonedAdmissionDigest: text('abandoned_admission_digest').notNull(),
      admissionRevision: bigint('admission_revision', { mode: 'number' }).notNull(),
      admissionDigest: text('admission_digest').notNull(),
      proof: jsonb('proof').notNull(),
      intentBytes: bytes('intent_bytes').notNull(),
      intentDigest: text('intent_digest').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      ...scoped(t),
      check(
        'runtime_expired_handover_intent_ck',
        sql`${t.intentDigest}='sha256:'||encode(sha256(${t.intentBytes}),'hex') and octet_length(${t.intentBytes}) between 2 and 16384`,
      ),
      check(
        'runtime_expired_handover_order_ck',
        sql`${t.abandonedRevision}>1 and ${t.admissionRevision}=${t.abandonedRevision}+1`,
      ),
    ],
  )
  .enableRLS();
