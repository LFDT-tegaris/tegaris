import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  credentials,
  privacyDomains,
} from '../../../identity-service/src/db/schema/participants.js';
import {
  evidenceControlSchema as control,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
  evidenceScopePolicies as scoped,
  evidenceTimestamp as time,
} from '../evidence/schema.js';

/** Public installation trust and signed policy history. Runtime roles may read
 * their scope but cannot install, replace or remove a profile. */
export const factConsumerProfiles = control
  .table(
    'fact_consumer_profile',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      consumerId: text('consumer_id').notNull(),
      profileId: text('profile_id').notNull(),
      revision: ordinal('revision').notNull(),
      profileDigest: text('profile_digest').notNull(),
      issuerSpki: bytes('issuer_spki').notNull(),
      databaseRole: text('database_role').notNull(),
      workloadCredentialId: uuid('workload_credential_id').notNull(),
      workloadCredentialEpoch: ordinal('workload_credential_epoch').notNull(),
      claims: jsonb('claims').notNull(),
      payload: bytes('payload').notNull(),
      cose: bytes('cose').notNull(),
      admissionReference: text('admission_reference').notNull(),
      admittedAt: time('admitted_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.consumerId, t.revision] }),
      unique('fact_consumer_profile_digest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.profileDigest,
      ),
      foreignKey({
        name: 'fact_consumer_profile_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'fact_consumer_profile_workload_fk',
        columns: [t.participantId, t.workloadCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'fact_consumer_profile_id_ck',
        sql`${t.consumerId} in ('LS-CONTROL-WORK','LS-FLEET-CONTROL') and ${t.revision} between 1 and 18446744073709551615 and ${t.workloadCredentialEpoch} between 0 and 18446744073709551615`,
      ),
      check(
        'fact_consumer_profile_bytes_ck',
        sql`${t.profileDigest}='sha256:'||encode(sha256(${t.cose}),'hex') and octet_length(${t.payload}) between 1 and 65536 and octet_length(${t.cose}) between 65 and 66560 and octet_length(${t.issuerSpki})=91`,
      ),
      check(
        'fact_consumer_profile_reference_ck',
        sql`length(${t.admissionReference}) between 1 and 256`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
