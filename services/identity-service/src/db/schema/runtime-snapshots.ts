import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  numeric,
  primaryKey,
  smallint,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { participants, principals, privacyDomains } from './participants.js';

const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
const time = (name: string) =>
  timestamp(name, { precision: 6, withTimezone: true, mode: 'string' });

/** Stable identities for the materialized authority sets used by one actor in
 * one privacy context. Creating a set grants nothing; its contents come only
 * from the committed Identity/Participant graph. */
export const identityRuntimeAuthoritySets = control
  .table(
    'identity_runtime_authority_set',
    {
      setId: uuid('set_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      domainCode: smallint('domain_code').notNull(),
    },
    (t) => [
      unique('identity_runtime_authority_set_owner_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.principalId,
        t.domainCode,
      ),
      foreignKey({
        name: 'identity_runtime_set_principal_fk',
        columns: [t.participantId, t.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }),
      foreignKey({
        name: 'identity_runtime_set_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }),
      check('identity_runtime_authority_set_domain_ck', sql`${t.domainCode} in (4,6,7,9)`),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** Monotonic versions belong to exact canonical authority scopes. Source state
 * includes retained row versions, so a grant/remove/regrant cannot reuse a version. */
export const identityRuntimeAuthorityScopes = control
  .table(
    'identity_runtime_authority_scope',
    {
      participantId: uuid('participant_id').notNull(),
      domainCode: smallint('domain_code').notNull(),
      scopeDigest: bytea('scope_digest').notNull(),
      scopeCbor: bytea('scope_cbor').notNull(),
      sourceStateDigest: bytea('source_state_digest').notNull(),
      version: u64('version').notNull(),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        name: 'identity_runtime_scope_pk',
        columns: [t.participantId, t.domainCode, t.scopeDigest],
      }),
      foreignKey({
        name: 'identity_runtime_scope_participant_fk',
        columns: [t.participantId],
        foreignColumns: [participants.participantId],
      }),
      check('identity_runtime_scope_domain_ck', sql`${t.domainCode} between 1 and 12`),
      check(
        'identity_runtime_scope_digest_ck',
        sql`octet_length(${t.scopeDigest})=32 and ${t.scopeDigest}<>decode(repeat('00',32),'hex') and ${t.scopeDigest}=sha256(${t.scopeCbor}) and octet_length(${t.sourceStateDigest})=32`,
      ),
      check(
        'identity_runtime_scope_bytes_ck',
        sql`octet_length(${t.scopeCbor}) between 1 and 32768`,
      ),
      check(
        'identity_runtime_scope_version_ck',
        sql`${t.version} between 1 and 18446744073709551615`,
      ),
      participantIsolationPolicy(t.participantId),
    ],
  )
  .enableRLS();

/** Immutable publication. Manifest, shards, and referenced role/envelope content
 * are inserted in one transaction before the head can point at this snapshot. */
export const identityRuntimeSnapshots = control
  .table(
    'identity_runtime_snapshot',
    {
      snapshotId: uuid('snapshot_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      targetRuntimeId: uuid('target_runtime_id').notNull(),
      sourceStateDigest: bytea('source_state_digest').notNull(),
      manifestDigest: bytea('manifest_digest').notNull(),
      manifestPayload: bytea('manifest_payload').notNull(),
      manifestCose: bytea('manifest_cose').notNull(),
      profilePayload: bytea('profile_payload').notNull(),
      profileCose: bytea('profile_cose').notNull(),
      profileDigest: bytea('profile_digest').notNull(),
      issuedAtNs: u64('issued_at_ns').notNull(),
      expiresAtNs: u64('expires_at_ns').notNull(),
      actorCount: smallint('actor_count').notNull(),
      shardCount: smallint('shard_count').notNull(),
    },
    (t) => [
      unique('identity_runtime_snapshot_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.targetRuntimeId,
        t.snapshotId,
      ),
      unique('identity_runtime_snapshot_content_owner_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.snapshotId,
      ),
      unique('identity_runtime_snapshot_manifest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.manifestDigest,
      ),
      foreignKey({
        name: 'identity_runtime_snapshot_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }),
      check(
        'identity_runtime_snapshot_digest_ck',
        sql`octet_length(${t.manifestDigest})=32 and octet_length(${t.profileDigest})=32 and octet_length(${t.sourceStateDigest})=32`,
      ),
      check(
        'identity_runtime_snapshot_time_ck',
        sql`${t.issuedAtNs}>=0 and ${t.expiresAtNs}>${t.issuedAtNs} and ${t.expiresAtNs}<=18446744073709551615`,
      ),
      check(
        'identity_runtime_snapshot_count_ck',
        sql`${t.actorCount} between 1 and 8192 and ${t.shardCount} between 1 and 256`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const identityRuntimeSnapshotContent = control
  .table(
    'identity_runtime_snapshot_content',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      snapshotId: uuid('snapshot_id').notNull(),
      contentDigest: bytea('content_digest').notNull(),
      contentKind: text('content_kind').notNull(),
      ordinal: smallint('ordinal').notNull(),
      payload: bytea('payload').notNull(),
    },
    (t) => [
      primaryKey({
        name: 'identity_runtime_content_pk',
        columns: [t.snapshotId, t.contentKind, t.contentDigest],
      }),
      foreignKey({
        name: 'identity_runtime_content_snapshot_fk',
        columns: [t.participantId, t.privacyDomainId, t.snapshotId],
        foreignColumns: [
          identityRuntimeSnapshots.participantId,
          identityRuntimeSnapshots.privacyDomainId,
          identityRuntimeSnapshots.snapshotId,
        ],
      }),
      check(
        'identity_runtime_content_kind_ck',
        sql`${t.contentKind} in ('SHARD','ROLE_ASSIGNMENTS','PARTICIPANT_ENVELOPES')`,
      ),
      check(
        'identity_runtime_content_digest_ck',
        sql`octet_length(${t.contentDigest})=32 and ${t.contentDigest}=sha256(${t.payload})`,
      ),
      check(
        'identity_runtime_content_bounds_ck',
        sql`${t.ordinal}>=0 and octet_length(${t.payload}) between 1 and 4194304`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const identityRuntimeSnapshotHeads = control
  .table(
    'identity_runtime_snapshot_head',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      targetRuntimeId: uuid('target_runtime_id').notNull(),
      snapshotId: uuid('snapshot_id').notNull(),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        name: 'identity_runtime_head_pk',
        columns: [t.participantId, t.privacyDomainId, t.targetRuntimeId],
      }),
      foreignKey({
        name: 'identity_runtime_head_snapshot_fk',
        columns: [t.participantId, t.privacyDomainId, t.targetRuntimeId, t.snapshotId],
        foreignColumns: [
          identityRuntimeSnapshots.participantId,
          identityRuntimeSnapshots.privacyDomainId,
          identityRuntimeSnapshots.targetRuntimeId,
          identityRuntimeSnapshots.snapshotId,
        ],
      }),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
