import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  credentials,
  privacyDomains,
} from '../../../identity-service/src/db/schema/participants.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
} from './schema.js';

const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});

/** One installed, purpose-bound public signer identity. Initial trust is an
 * operational action; runtime readers cannot replace, renew or enroll it. */
export const evidenceExportProducerInstallations = control
  .table(
    'evidence_export_producer_installation',
    {
      ...scope(),
      sourceId: uuid('source_id').notNull(),
      signerId: text('signer_id').notNull(),
      environmentId: text('environment_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      workloadCredentialId: uuid('workload_credential_id').notNull(),
      workloadEpoch: ordinal('workload_epoch').notNull(),
      trust: jsonb('trust').notNull(),
      trustBytes: bytes('trust_bytes').notNull(),
      trustDigest: text('trust_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.sourceId, t.signerId] }),
      unique('evidence_export_producer_trust_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.trustDigest,
      ),
      foreignKey({
        name: 'evidence_export_producer_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'evidence_export_producer_credential_fk',
        columns: [t.participantId, t.workloadCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check('evidence_export_producer_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      check(
        'evidence_export_producer_digest_ck',
        sql`${t.trustDigest}='sha256:'||encode(sha256(${t.trustBytes}),'hex') and octet_length(${t.trustBytes}) between 1 and 16384`,
      ),
      check(
        'evidence_export_producer_epoch_ck',
        sql`${t.workloadEpoch} between 1 and 18446744073709551615`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
