import { identityEnvelopeRecoveryInstallationSourcePolicies } from './identity-envelope-recovery-source.js';
import { platformRecoveryInstallationSourcePolicies } from './platform-recovery-source.js';
import { sql } from 'drizzle-orm';
import { check, foreignKey, numeric, text, timestamp, uuid } from 'drizzle-orm/pg-core';
import { control, participantIsolationPolicy } from './common.js';
import { credentials, principals, privacyDomains } from './participants.js';

/** Verified external authenticator provenance, written by the registration owner only. */
export const hardwareAuthenticators = control
  .table(
    'hardware_authenticator',
    {
      credentialId: uuid('credential_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      profileId: text('profile_id').notNull(),
      profileDigest: text('profile_digest').notNull(),
      aaguid: uuid('aaguid').notNull(),
      attestationDigest: text('attestation_digest').notNull(),
      createdAt: timestamp('created_at', { withTimezone: true, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      foreignKey({
        columns: [t.participantId, t.credentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      check(
        'hardware_authenticator_digests_ck',
        sql`${t.profileDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.attestationDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      participantIsolationPolicy(t.participantId),
      ...platformRecoveryInstallationSourcePolicies(
        t.participantId,
        t.credentialId,
        'credential',
        false,
      ),
      ...identityEnvelopeRecoveryInstallationSourcePolicies(
        t.participantId,
        t.credentialId,
        'credential',
        false,
      ),
    ],
  )
  .enableRLS();

/** Qualification is separate from presentation roles and grants no authority. */
export const recoveryPrincipals = control
  .table(
    'recovery_principal',
    {
      principalId: uuid('principal_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      credentialId: uuid('credential_id').notNull(),
      credentialEpoch: numeric('credential_epoch', {
        precision: 20,
        scale: 0,
        mode: 'bigint',
      }).notNull(),
      principalEpoch: numeric('principal_epoch', {
        precision: 20,
        scale: 0,
        mode: 'bigint',
      }).notNull(),
      state: text('state').notNull(),
      rowVersion: numeric('row_version', { precision: 20, scale: 0, mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: timestamp('created_at', { withTimezone: true, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: timestamp('updated_at', { withTimezone: true, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      foreignKey({
        columns: [t.participantId, t.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.credentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check('recovery_principal_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      check(
        'recovery_principal_epochs_ck',
        sql`${t.principalEpoch} >= 0 and ${t.credentialEpoch} >= 0 and ${t.rowVersion} > 0`,
      ),
      participantIsolationPolicy(t.participantId),
    ],
  )
  .enableRLS();
