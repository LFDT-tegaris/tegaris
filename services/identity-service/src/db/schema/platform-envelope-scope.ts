import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  numeric,
  pgPolicy,
  smallint,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  controlOwnerRole,
  controlRuntimeRole,
  controlReaderRole,
  controlPlatformRuntimeRole,
} from './common.js';
import { platformContexts } from './platform-context.js';
import { participants, privacyDomains } from './participants.js';

/** One initial, immutable upper bound. A root epoch change invalidates it;
 * governed successors have their separate append-only replacement owner. */
export const platformEnvelopeScopes = control
  .table(
    'platform_envelope_scope',
    {
      platformContextId: uuid('platform_context_id')
        .primaryKey()
        .references(() => platformContexts.platformContextId, { onDelete: 'restrict' }),
      ownerParticipantId: uuid('owner_participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      installationPrivacyDomainId: uuid('installation_privacy_domain_id').notNull(),
      platformAuthorityEpoch: numeric('platform_authority_epoch', {
        precision: 20,
        scale: 0,
        mode: 'bigint',
      }).notNull(),
      admissionVersion: smallint('admission_version').notNull().default(1),
      environmentId: text('environment_id').notNull(),
      installationDigest: text('installation_digest').notNull(),
      scopeCbor: bytea('scope_cbor').notNull(),
      admissionPreimage: bytea('admission_preimage').notNull(),
      admissionDigest: bytea('admission_digest').notNull(),
      installedBy: text('installed_by')
        .notNull()
        .default(sql`session_user`),
      installedAt: timestamp('installed_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      foreignKey({
        name: 'platform_envelope_scope_privacy_fk',
        columns: [t.ownerParticipantId, t.installationPrivacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      check(
        'platform_envelope_scope_initial_ck',
        sql`${t.platformAuthorityEpoch}=1 and ${t.admissionVersion}=1`,
      ),
      check(
        'platform_envelope_scope_environment_ck',
        sql`${t.environmentId} ~ '^[a-z][a-z0-9-]{2,31}$'`,
      ),
      check(
        'platform_envelope_scope_provenance_ck',
        sql`${t.installationDigest} ~ '^sha256:[0-9a-f]{64}$' and length(${t.installedBy}) between 1 and 128`,
      ),
      check(
        'platform_envelope_scope_bytes_ck',
        sql`octet_length(${t.scopeCbor}) between 1 and 60000 and octet_length(${t.admissionPreimage}) between 1 and 65536
    and octet_length(${t.admissionDigest})=32 and ${t.admissionDigest}=sha256(${t.admissionPreimage})`,
      ),
      pgPolicy('platform_envelope_scope_owner', {
        for: 'all',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.ownerParticipantId}) and openpc.matches_privacy(${t.installationPrivacyDomainId})`,
        withCheck: sql`openpc.matches_participant(${t.ownerParticipantId}) and openpc.matches_privacy(${t.installationPrivacyDomainId})`,
      }),
      pgPolicy('platform_envelope_scope_read', {
        for: 'select',
        to: [controlOwnerRole, controlRuntimeRole, controlReaderRole, controlPlatformRuntimeRole],
        using: sql`exists(select 1 from control.authority_envelope envelope where envelope.platform_context_id=${t.platformContextId}
      and openpc.matches_participant(envelope.participant_id)
      and openpc.current_privacy_domain_id()::text=any(envelope.privacy_domain_ids))`,
      }),
    ],
  )
  .enableRLS();
