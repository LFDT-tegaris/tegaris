import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  primaryKey,
  text,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopeColumns as scope,
  evidenceScopePolicies as scoped,
  evidenceTimestamp as time,
  evidenceSegments,
  evidenceOrdinal as ordinal,
} from './schema.js';
import { protectedProofObjects } from './protected-schema.js';

/** The business object, independent of transport attempts and response loss.
 * An observed remote object is not a signed checkpoint or WORM qualification. */
export const evidenceRemoteArchiveIntents = control
  .table(
    'evidence_remote_archive_intent',
    {
      ...scope(),
      intentId: uuid('intent_id').notNull(),
      sourceKind: text('source_kind').notNull().default('SEGMENT'),
      segmentId: uuid('segment_id'),
      protectedObjectId: uuid('protected_object_id'),
      protectedObjectVersion: ordinal('protected_object_version'),
      protectedObjectDigest: text('protected_object_digest'),
      sinkId: text('sink_id').notNull(),
      profileDigest: text('profile_digest').notNull(),
      // Immutable transport configuration, retained independently of current host
      // configuration. This is not signed profile authority.
      profile: jsonb('profile').notNull(),
      intent: jsonb('intent').notNull(),
      intentDigest: text('intent_digest').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.intentId] }),
      unique('evidence_remote_archive_object_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.streamId,
        t.segmentId,
        t.sinkId,
      ),
      foreignKey({
        name: 'evidence_remote_archive_segment_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.segmentId],
        foreignColumns: [
          evidenceSegments.participantId,
          evidenceSegments.privacyDomainId,
          evidenceSegments.streamId,
          evidenceSegments.segmentId,
        ],
      }).onDelete('restrict'),
      unique('evidence_remote_archive_proof_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.protectedObjectId,
        t.protectedObjectVersion,
        t.sinkId,
      ),
      // Retain immutable object identity; never reference removable ciphertext.
      foreignKey({
        name: 'evidence_remote_archive_proof_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.protectedObjectId,
          t.protectedObjectVersion,
          t.protectedObjectDigest,
        ],
        foreignColumns: [
          protectedProofObjects.participantId,
          protectedProofObjects.privacyDomainId,
          protectedProofObjects.objectId,
          protectedProofObjects.objectVersion,
          protectedProofObjects.objectDigest,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_remote_archive_source_ck',
        sql`(
        ${t.sourceKind}='SEGMENT' and ${t.segmentId} is not null
        and ${t.protectedObjectId} is null and ${t.protectedObjectVersion} is null and ${t.protectedObjectDigest} is null
      ) or (
        ${t.sourceKind}='PROTECTED_PROOF' and ${t.segmentId} is null
        and ${t.protectedObjectId} is not null and ${t.protectedObjectVersion} is not null and ${t.protectedObjectDigest} is not null
      )`,
      ),
      check(
        'evidence_remote_archive_intent_ck',
        sql`${t.intentId}::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' and ${t.intentDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.profileDigest} ~ '^sha256:[0-9a-f]{64}$' and jsonb_typeof(${t.intent})='object' and octet_length(${t.intent}::text) between 1 and 524288`,
      ),
      check(
        'evidence_remote_archive_profile_ck',
        sql`jsonb_typeof(${t.profile})='object' and octet_length(${t.profile}::text) between 1 and 8192`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** STARTED is durable before I/O. OBSERVED retains the exact verified transport
 * observation only; a separate signed custody commit must authorize checkpoint
 * advancement. Missing/ambiguous rows never authorize a repeated PUT. */
export const evidenceRemoteArchiveAttempts = control
  .table(
    'evidence_remote_archive_attempt',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      intentId: uuid('intent_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      action: text('action').notNull(),
      binding: jsonb('binding').notNull(),
      bindingDigest: text('binding_digest').notNull(),
      protectionDigest: text('protection_digest').notNull(),
      state: text('state').notNull(),
      observation: jsonb('observation'),
      observationDigest: text('observation_digest'),
      startedAt: time('started_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.attemptId] }),
      foreignKey({
        name: 'evidence_remote_archive_attempt_intent_fk',
        columns: [t.participantId, t.privacyDomainId, t.intentId],
        foreignColumns: [
          evidenceRemoteArchiveIntents.participantId,
          evidenceRemoteArchiveIntents.privacyDomainId,
          evidenceRemoteArchiveIntents.intentId,
        ],
      }).onDelete('restrict'),
      unique('evidence_remote_archive_attempt_binding_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.intentId,
        t.action,
        t.protectionDigest,
      ),
      uniqueIndex('evidence_remote_archive_initial_put_uq')
        .on(t.participantId, t.privacyDomainId, t.intentId)
        .where(sql`${t.action}='PUT'`),
      check(
        'evidence_remote_archive_attempt_ck',
        sql`${t.action} in ('PUT','PROTECTION') and ${t.state} in ('STARTED','AMBIGUOUS','OBSERVED') and ${t.bindingDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.protectionDigest} ~ '^sha256:[0-9a-f]{64}$' and jsonb_typeof(${t.binding})='object' and octet_length(${t.binding}::text) between 1 and 1048576`,
      ),
      check(
        'evidence_remote_archive_attempt_id_ck',
        sql`${t.attemptId}::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`,
      ),
      check(
        'evidence_remote_archive_observation_ck',
        sql`((${t.state}='OBSERVED' and ${t.observation} is not null and jsonb_typeof(${t.observation})='object' and octet_length(${t.observation}::text) between 1 and 1048576 and ${t.observationDigest} is not null and ${t.observationDigest} ~ '^sha256:[0-9a-f]{64}$') or (${t.state}<>'OBSERVED' and ${t.observation} is null and ${t.observationDigest} is null))`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
