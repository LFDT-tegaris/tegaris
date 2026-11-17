import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  numeric,
  pgPolicy,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  controlOwnerRole,
  controlPlatformRuntimeRole,
  controlRuntimeRole,
} from './common.js';
import { privacyDomains } from './participants.js';
import { platformContexts } from './platform-context.js';

const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const version = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
const readers = [controlOwnerRole, controlPlatformRuntimeRole, controlRuntimeRole];

/** Dedicated independent receiving pin, never inferred from Operations or COSE
 * keys. Installation can add initial trust only; immutable bytes cannot rotate
 * or widen an already enrolled custody record. */
export const identityEnvelopeRecoveryCustodyTrust = control
  .table(
    'identity_envelope_recovery_custody_trust',
    {
      custodyTrustId: uuid('custody_trust_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      platformContextId: uuid('platform_context_id')
        .notNull()
        .references(() => platformContexts.platformContextId, { onDelete: 'restrict' }),
      document: jsonb('document').notNull(),
      documentDigest: bytea('document_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
      rowVersion: version('row_version')
        .notNull()
        .default(sql`1`),
      validFrom: time('valid_from').notNull(),
      validUntil: time('valid_until').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      revokedAt: time('revoked_at'),
      revocationReasonDigest: bytea('revocation_reason_digest'),
    },
    (t) => [
      unique('identity_envelope_recovery_trust_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.custodyTrustId,
        t.documentDigest,
      ),
      foreignKey({
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      check(
        'identity_envelope_recovery_trust_state_ck',
        sql`${t.state} in ('ACTIVE','REVOKED') and ${t.rowVersion}>0`,
      ),
      check(
        'identity_envelope_recovery_trust_digest_ck',
        sql`octet_length(${t.documentDigest})=32 and (${t.revocationReasonDigest} is null or octet_length(${t.revocationReasonDigest})=32)`,
      ),
      check(
        'identity_envelope_recovery_trust_time_ck',
        sql`${t.validUntil}>${t.validFrom} and ((${t.state}='ACTIVE' and ${t.revokedAt} is null and ${t.revocationReasonDigest} is null) or (${t.state}='REVOKED' and ${t.revokedAt} is not null and ${t.revocationReasonDigest} is not null))`,
      ),
      pgPolicy('identity_envelope_recovery_trust_read', {
        for: 'select',
        to: readers,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('identity_envelope_recovery_trust_install', {
        for: 'insert',
        to: [controlOwnerRole],
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId}) and ${t.state}='ACTIVE' and ${t.rowVersion}=1`,
      }),
      pgPolicy('identity_envelope_recovery_trust_revoke', {
        for: 'update',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`${t.state}='REVOKED'`,
      }),
    ],
  )
  .enableRLS();

/** Verified immutable installation custody, separate from every RecoveryCase.
 * It contains no approval result, lease, authority envelope or assignment. */
export const identityEnvelopeRecoveryEnrollments = control
  .table(
    'identity_envelope_recovery_enrollment',
    {
      enrollmentId: uuid('enrollment_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      custodyTrustId: uuid('custody_trust_id').notNull(),
      custodyTrustDigest: bytea('custody_trust_digest').notNull(),
      platformContextId: uuid('platform_context_id')
        .notNull()
        .references(() => platformContexts.platformContextId, { onDelete: 'restrict' }),
      document: jsonb('document').notNull(),
      documentDigest: bytea('document_digest').notNull(),
      signature: bytea('signature').notNull(),
      state: text('state').notNull().default('ACTIVE'),
      rowVersion: version('row_version')
        .notNull()
        .default(sql`1`),
      validFrom: time('valid_from').notNull(),
      validUntil: time('valid_until').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      revokedAt: time('revoked_at'),
      revocationReasonDigest: bytea('revocation_reason_digest'),
    },
    (t) => [
      unique('identity_envelope_recovery_enrollment_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.enrollmentId,
      ),
      foreignKey({
        name: 'identity_envelope_recovery_enrollment_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_recovery_enrollment_custody_fk',
        columns: [t.participantId, t.privacyDomainId, t.custodyTrustId, t.custodyTrustDigest],
        foreignColumns: [
          identityEnvelopeRecoveryCustodyTrust.participantId,
          identityEnvelopeRecoveryCustodyTrust.privacyDomainId,
          identityEnvelopeRecoveryCustodyTrust.custodyTrustId,
          identityEnvelopeRecoveryCustodyTrust.documentDigest,
        ],
      }).onDelete('restrict'),
      check(
        'identity_envelope_recovery_enrollment_state_ck',
        sql`${t.state} in ('ACTIVE','REVOKED') and ${t.rowVersion}>0`,
      ),
      check(
        'identity_envelope_recovery_enrollment_digest_ck',
        sql`octet_length(${t.documentDigest})=32 and octet_length(${t.custodyTrustDigest})=32 and octet_length(${t.signature})=64 and (${t.revocationReasonDigest} is null or octet_length(${t.revocationReasonDigest})=32)`,
      ),
      check(
        'identity_envelope_recovery_enrollment_time_ck',
        sql`${t.validUntil}>${t.validFrom} and ((${t.state}='ACTIVE' and ${t.revokedAt} is null and ${t.revocationReasonDigest} is null) or (${t.state}='REVOKED' and ${t.revokedAt} is not null and ${t.revocationReasonDigest} is not null))`,
      ),
      pgPolicy('identity_envelope_recovery_enrollment_read', {
        for: 'select',
        to: readers,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('identity_envelope_recovery_enrollment_install', {
        for: 'insert',
        to: [controlOwnerRole],
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId}) and ${t.state}='ACTIVE' and ${t.rowVersion}=1`,
      }),
      pgPolicy('identity_envelope_recovery_enrollment_owner_read', {
        for: 'select',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.participantId})`,
      }),
      pgPolicy('identity_envelope_recovery_enrollment_revoke', {
        for: 'update',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`${t.state}='REVOKED'`,
      }),
    ],
  )
  .enableRLS();
