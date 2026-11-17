import { sql } from 'drizzle-orm';
import { check, foreignKey, integer, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
  evidenceScopePolicies as scoped,
} from '../evidence/schema.js';
import { factConsumerProfiles } from './profile-schema.js';

const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});

/** Durable original transport/retry state. EXHAUSTED is blocked pending the
 * separately signed quarantine/work-item effect; it is never a delivery ACK. */
export const fleetFactDeliveries = control
  .table(
    'fleet_fact_delivery',
    {
      ...scope(),
      eventId: uuid('event_id').notNull(),
      candidateId: uuid('candidate_id').notNull(),
      generationId: uuid('generation_id').notNull(),
      factType: text('fact_type').notNull(),
      sequence: ordinal('sequence').notNull(),
      material: bytes('material').notNull(),
      materialDigest: bytes('material_digest').notNull(),
      initialProfileDigest: text('initial_profile_digest').notNull(),
      maximumAttempts: integer('maximum_attempts').notNull(),
      initialBackoffMs: integer('initial_backoff_ms').notNull(),
      maximumBackoffMs: integer('maximum_backoff_ms').notNull(),
      failedAttempts: integer('failed_attempts').notNull().default(0),
      leaseGeneration: ordinal('lease_generation').notNull().default('0'),
      state: text('state').notNull().default('WAITING'),
      leaseId: uuid('lease_id'),
      leaseUntilMs: ordinal('lease_until_ms'),
      nextAttemptMs: ordinal('next_attempt_ms').notNull(),
      lastProblem: text('last_problem'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId] }),
      unique('fleet_delivery_candidate_uq').on(t.participantId, t.privacyDomainId, t.candidateId),
      unique('fleet_delivery_sequence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.factType,
        t.sequence,
      ),
      foreignKey({
        name: 'fleet_delivery_profile_fk',
        columns: [t.participantId, t.privacyDomainId, t.initialProfileDigest],
        foreignColumns: [
          factConsumerProfiles.participantId,
          factConsumerProfiles.privacyDomainId,
          factConsumerProfiles.profileDigest,
        ],
      }).onDelete('restrict'),
      check(
        'fleet_delivery_identity_ck',
        sql`${t.factType} in ('CONTRACT_STATE_CALL','RELATIONSHIP','EXTERNAL_DECISION') and ${t.sequence} between 1 and 9223372036854775807`,
      ),
      check(
        'fleet_delivery_material_ck',
        sql`octet_length(${t.material}) between 1 and 65536 and ${t.materialDigest}=sha256(${t.material})`,
      ),
      check(
        'fleet_delivery_budget_ck',
        sql`${t.maximumAttempts} between 1 and 1000 and ${t.failedAttempts} between 0 and ${t.maximumAttempts} and ${t.initialBackoffMs} between 1 and 3600000 and ${t.maximumBackoffMs} between ${t.initialBackoffMs} and 3600000 and ${t.leaseGeneration} between 0 and 18446744073709551615`,
      ),
      check(
        'fleet_delivery_state_ck',
        sql`${t.state} in ('WAITING','LEASED','EXHAUSTED','QUARANTINED','COMMITTED') and ((${t.state}='LEASED' and ${t.leaseId} is not null and ${t.leaseUntilMs} is not null) or (${t.state}<>'LEASED' and ${t.leaseId} is null and ${t.leaseUntilMs} is null)) and (${t.state} not in ('EXHAUSTED','QUARANTINED') or ${t.failedAttempts}=${t.maximumAttempts})`,
      ),
      check(
        'fleet_delivery_time_ck',
        sql`${t.nextAttemptMs} between 0 and 9007199254740991 and (${t.leaseUntilMs} is null or ${t.leaseUntilMs} between 0 and 9007199254740991)`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Each lease retains its original identity and admitted profile. Completed
 * outcomes are immutable; a new lease cannot erase a failure or renew budget. */
export const fleetFactDeliveryAttempts = control
  .table(
    'fleet_fact_delivery_attempt',
    {
      ...scope(),
      eventId: uuid('event_id').notNull(),
      leaseGeneration: ordinal('lease_generation').notNull(),
      leaseId: uuid('lease_id').notNull(),
      profileDigest: text('profile_digest').notNull(),
      startedAtMs: ordinal('started_at_ms').notNull(),
      leaseUntilMs: ordinal('lease_until_ms').notNull(),
      endedAtMs: ordinal('ended_at_ms'),
      outcome: text('outcome').notNull().default('ACTIVE'),
      problem: text('problem'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId, t.leaseGeneration] }),
      unique('fleet_delivery_lease_uq').on(t.leaseId),
      foreignKey({
        name: 'fleet_delivery_attempt_event_fk',
        columns: [t.participantId, t.privacyDomainId, t.eventId],
        foreignColumns: [
          fleetFactDeliveries.participantId,
          fleetFactDeliveries.privacyDomainId,
          fleetFactDeliveries.eventId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'fleet_delivery_attempt_profile_fk',
        columns: [t.participantId, t.privacyDomainId, t.profileDigest],
        foreignColumns: [
          factConsumerProfiles.participantId,
          factConsumerProfiles.privacyDomainId,
          factConsumerProfiles.profileDigest,
        ],
      }).onDelete('restrict'),
      check(
        'fleet_delivery_attempt_time_ck',
        sql`${t.startedAtMs} between 0 and 9007199254740991 and ${t.leaseUntilMs}>${t.startedAtMs} and ${t.leaseUntilMs}<=9007199254740991 and (${t.endedAtMs} is null or ${t.endedAtMs} between ${t.startedAtMs} and 9007199254740991) and ${t.leaseGeneration} between 1 and 18446744073709551615`,
      ),
      check(
        'fleet_delivery_attempt_outcome_ck',
        sql`${t.outcome} in ('ACTIVE','FAILED','LEASE_EXPIRED','CAPACITY_RELEASE','UNAVAILABLE_RELEASE','COMMITTED') and ((${t.outcome}='ACTIVE' and ${t.endedAtMs} is null) or (${t.outcome}<>'ACTIVE' and ${t.endedAtMs} is not null))`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
