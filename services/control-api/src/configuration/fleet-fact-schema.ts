import { sql } from 'drizzle-orm';
import { check, foreignKey, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import { factConsumerProfiles } from '../fact-consumers/profile-schema.js';
import {
  evidenceControlSchema as control,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
  evidenceScopePolicies as scoped,
} from '../evidence/schema.js';

const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});

/** Installed local verifier for the native Fleet consumer. No runtime role can
 * enroll or read this key. It grants no policy/runtime authority. */
export const fleetFactAdmissionKeys = control.table(
  'fleet_fact_admission_key',
  {
    databaseRole: text('database_role').primaryKey(),
    verifierSecret: bytes('verifier_secret').notNull(),
  },
  (t) => [check('fleet_fact_key_size_ck', sql`octet_length(${t.verifierSecret})=32`)],
);

/** Metadata custody used by Fleet's actual runtime assembly. Original payload
 * bytes remain with the Fact owner; consuming this event never renews them. */
export const fleetFactAdmissionInbox = control
  .table(
    'fleet_fact_admission_inbox',
    {
      ...scope(),
      eventId: uuid('event_id').notNull(),
      candidateId: uuid('candidate_id').notNull(),
      generationId: uuid('generation_id').notNull(),
      factType: text('fact_type').notNull(),
      sequence: ordinal('sequence').notNull(),
      factDigest: text('fact_digest').notNull(),
      signedFactDigest: text('signed_fact_digest').notNull(),
      material: bytes('material').notNull(),
      materialDigest: bytes('material_digest').notNull(),
      commitNonce: bytes('commit_nonce').notNull(),
      consumerProfileDigest: text('consumer_profile_digest'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId] }),
      unique('fleet_fact_inbox_candidate_uq').on(t.participantId, t.privacyDomainId, t.candidateId),
      unique('fleet_fact_inbox_sequence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.factType,
        t.sequence,
      ),
      unique('fleet_fact_inbox_nonce_uq').on(t.commitNonce),
      foreignKey({
        name: 'fleet_fact_inbox_profile_fk',
        columns: [t.participantId, t.privacyDomainId, t.consumerProfileDigest],
        foreignColumns: [
          factConsumerProfiles.participantId,
          factConsumerProfiles.privacyDomainId,
          factConsumerProfiles.profileDigest,
        ],
      }).onDelete('restrict'),
      check(
        'fleet_fact_inbox_type_ck',
        sql`${t.factType} in ('CONTRACT_STATE_CALL','RELATIONSHIP','EXTERNAL_DECISION')`,
      ),
      check('fleet_fact_inbox_sequence_ck', sql`${t.sequence} between 1 and 9223372036854775807`),
      check(
        'fleet_fact_inbox_digest_ck',
        sql`${t.factDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.signedFactDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.materialDigest}=sha256(${t.material}) and octet_length(${t.commitNonce})=32`,
      ),
      check('fleet_fact_inbox_material_ck', sql`octet_length(${t.material}) between 1 and 16384`),
      ...scoped(t),
    ],
  )
  .enableRLS();

export const fleetFactAdmissionCursor = control
  .table(
    'fleet_fact_admission_cursor',
    {
      ...scope(),
      factType: text('fact_type').notNull(),
      sequence: ordinal('sequence').notNull().default('0'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.factType] }),
      check(
        'fleet_fact_cursor_type_ck',
        sql`${t.factType} in ('CONTRACT_STATE_CALL','RELATIONSHIP','EXTERNAL_DECISION')`,
      ),
      check('fleet_fact_cursor_sequence_ck', sql`${t.sequence} between 0 and 9223372036854775807`),
      ...scoped(t),
    ],
  )
  .enableRLS();
