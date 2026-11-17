import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  foreignKey,
  jsonb,
  primaryKey,
  text,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceBytes as bytes,
} from '../evidence/schema.js';
import { notificationOccurrences } from './schema.js';
import { outboxEvents } from '../../../identity-service/src/db/schema/workflow.js';

/** Scheduling custody only. Existing occurrence/delivery/receipt rows remain
 * business truth. Canonical registration must install the matching guards and
 * native/protected-event owners before granting any worker write. */
export const notificationAsyncWork = control
  .table(
    'notification_async_work',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      eventId: uuid('event_id').notNull(),
      notificationOccurrenceId: uuid('notification_occurrence_id').notNull(),
      environmentId: text('environment_id').notNull(),
      generationId: uuid('generation_id').notNull(),
      workerInstallationDigest: text('worker_installation_digest').notNull(),
      inputPayloadDigest: text('input_payload_digest').notNull(),
      capacityPayloadDigest: text('capacity_payload_digest').notNull(),
      partition: text('partition').notNull(),
      sequence: ordinal('sequence').notNull(),
      payloadBytes: ordinal('payload_bytes').notNull(),
      sourceDigest: text('source_digest').notNull(),
      publishedAtMs: ordinal('published_at_ms').notNull(),
      deadlineAtMs: ordinal('deadline_at_ms').notNull(),
      state: text('state').notNull(),
      leaseOwner: text('lease_owner'),
      leaseEpoch: ordinal('lease_epoch').notNull(),
      leaseUntilMs: ordinal('lease_until_ms'),
      charged: boolean('charged').notNull(),
      effectUncertain: boolean('effect_uncertain').notNull(),
      nextAtMs: ordinal('next_at_ms'),
      original: jsonb('original'),
      reason: text('reason'),
      revision: ordinal('revision').notNull(),
      transitionEventId: uuid('transition_event_id').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId] }),
      unique('notification_async_occurrence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
      ),
      unique('notification_async_partition_sequence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.environmentId,
        t.partition,
        t.sequence,
      ),
      foreignKey({
        name: 'notification_async_occurrence_fk',
        columns: [t.participantId, t.privacyDomainId, t.notificationOccurrenceId],
        foreignColumns: [
          notificationOccurrences.participantId,
          notificationOccurrences.privacyDomainId,
          notificationOccurrences.notificationOccurrenceId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_async_source_event_fk',
        columns: [t.participantId, t.eventId],
        foreignColumns: [outboxEvents.participantId, outboxEvents.eventId],
      }).onDelete('restrict'),
      check(
        'notification_async_state_ck',
        sql`${t.state} in ('PENDING','LEASED','RECONCILING','RETRY_WAIT','QUARANTINED','DONE','CANCELLED')`,
      ),
      check(
        'notification_async_numbers_ck',
        sql`${t.sequence}>0 and ${t.payloadBytes}>0 and ${t.publishedAtMs}>=0 and ${t.deadlineAtMs}>${t.publishedAtMs} and ${t.deadlineAtMs}<=9007199254740991 and ${t.leaseEpoch}>=0 and ${t.leaseEpoch}<=18446744073709551615 and ${t.revision}>0 and ${t.revision}<=18446744073709551615`,
      ),
      check(
        'notification_async_lease_ck',
        sql`(${t.leaseOwner} is null or length(${t.leaseOwner}) between 1 and 256) and (${t.leaseOwner} is null)=(${t.leaseUntilMs} is null) and (${t.leaseUntilMs} is null or (${t.leaseEpoch}>0 and ${t.leaseUntilMs}<=${t.deadlineAtMs})) and (${t.state}<>'LEASED' or (${t.leaseOwner} is not null and ${t.charged})) and (not ${t.effectUncertain} or ${t.charged})`,
      ),
      check(
        'notification_async_schedule_ck',
        sql`(${t.state}='RETRY_WAIT')=(${t.nextAtMs} is not null) and (${t.nextAtMs} is null or (${t.nextAtMs}>=${t.publishedAtMs} and ${t.nextAtMs}<${t.deadlineAtMs})) and (${t.state} not in ('DONE','CANCELLED') or (not ${t.charged} and not ${t.effectUncertain} and ${t.leaseOwner} is null))`,
      ),
      check(
        'notification_async_digest_ck',
        sql`${t.workerInstallationDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.inputPayloadDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.capacityPayloadDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.sourceDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Immutable operational transition bytes. This table alone does not substitute
 * for the canonical protected outbox proof/atomic admission. */
export const notificationAsyncWorkTransitions = control
  .table(
    'notification_async_work_transition',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      eventId: uuid('event_id').notNull(),
      revision: ordinal('revision').notNull(),
      operationId: uuid('operation_id').notNull(),
      proofEventId: uuid('proof_event_id').notNull(),
      transition: jsonb('transition').notNull(),
      transitionBytes: bytes('transition_bytes').notNull(),
      transitionDigest: text('transition_digest').notNull(),
      recordedAtMs: ordinal('recorded_at_ms').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId, t.revision] }),
      unique('notification_async_transition_proof_uq').on(t.participantId, t.proofEventId),
      foreignKey({
        name: 'notification_async_transition_work_fk',
        columns: [t.participantId, t.privacyDomainId, t.eventId],
        foreignColumns: [
          notificationAsyncWork.participantId,
          notificationAsyncWork.privacyDomainId,
          notificationAsyncWork.eventId,
        ],
      }).onDelete('restrict'),
      check(
        'notification_async_transition_bytes_ck',
        sql`octet_length(${t.transitionBytes}) between 1 and 1048576 and ${t.transitionDigest}='sha256:'||encode(sha256(${t.transitionBytes}),'hex') and ${t.recordedAtMs} between 0 and 9007199254740991`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
