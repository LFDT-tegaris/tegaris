import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  numeric,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { credentials, privacyDomains } from './participants.js';

/** Immutable installation trust; runtime may select its scope but never install it. */
export const installedSecretRecipients = control
  .table(
    'installed_secret_recipient',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      installationDigest: text('installation_digest').notNull(),
      consumerId: text('consumer_id').notNull(),
      storeId: text('store_id').notNull(),
      generation: numeric('generation', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
      workloadCredentialId: uuid('workload_credential_id').notNull(),
      workloadCredentialEpoch: numeric('workload_credential_epoch', {
        precision: 20,
        scale: 0,
        mode: 'bigint',
      }).notNull(),
      issuerSpki: bytea('issuer_spki').notNull(),
      bindingDigest: text('binding_digest').notNull(),
      payload: bytea('payload').notNull(),
      cose: bytea('cose').notNull(),
      state: text('state').notNull().default('ACTIVE'),
      admissionReference: text('admission_reference').notNull(),
      admittedAt: timestamp('admitted_at', { withTimezone: true })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.installationDigest,
          t.consumerId,
          t.storeId,
        ],
      }),
      uniqueIndex('installed_secret_recipient_active_uq')
        .on(t.participantId, t.privacyDomainId, t.consumerId, t.storeId)
        .where(sql`${t.state}='ACTIVE'`),
      foreignKey({
        name: 'installed_secret_recipient_scope_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'installed_secret_recipient_workload_fk',
        columns: [t.participantId, t.workloadCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'installed_secret_recipient_owner_ck',
        sql`${t.consumerId}='LS-FACT-BRIDGE' and ${t.storeId}='STORE-CANDIDATE-INDEX-PG' and ${t.state} in ('ACTIVE','REVOKED')`,
      ),
      check(
        'installed_secret_recipient_bounds_ck',
        sql`${t.generation} between 1 and 18446744073709551615 and ${t.workloadCredentialEpoch} between 0 and 18446744073709551615 and length(${t.admissionReference}) between 1 and 256`,
      ),
      check(
        'installed_secret_recipient_bytes_ck',
        sql`${t.installationDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.bindingDigest}='sha256:'||encode(sha256(${t.cose}),'hex') and octet_length(${t.issuerSpki})=91 and octet_length(${t.payload}) between 1 and 65536 and octet_length(${t.cose}) between 65 and 66560`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
