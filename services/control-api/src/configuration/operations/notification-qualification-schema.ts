import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, uniqueIndex, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceBytes as bytes,
  evidenceScopePolicies as scoped,
} from '../../evidence/schema.js';
import { operationsInstallations } from './schema.js';
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});
const envelope = () => ({
  body: jsonb('body').notNull(),
  bodyBytes: bytes('body_bytes').notNull(),
  bodyDigest: text('body_digest').notNull(),
});
/** Canonical owns schema exports, generated migration order, role grants and
 * guard registration. These declarations confer no runtime write authority. */
export const notificationQualificationInstallations = control
  .table(
    'notification_qualification_installation',
    {
      ...scope(),
      installationId: uuid('installation_id').primaryKey(),
      environmentId: text('environment_id').notNull(),
      ...envelope(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      foreignKey({
        name: 'notification_qualification_environment_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId],
        foreignColumns: [
          operationsInstallations.participantId,
          operationsInstallations.privacyDomainId,
          operationsInstallations.environmentId,
        ],
      }).onDelete('restrict'),
      check(
        'notification_qualification_installation_state_ck',
        sql`${t.state} in ('ACTIVE','REVOKED')`,
      ),
      check(
        'notification_qualification_installation_bytes_ck',
        sql`octet_length(${t.bodyBytes}) between 1 and 131072 and ${t.bodyDigest}='sha256:'||encode(sha256(${t.bodyBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
export const notificationQualificationOrigins = control
  .table(
    'notification_qualification_origin',
    {
      ...scope(),
      originId: uuid('origin_id').primaryKey(),
      installationId: uuid('installation_id')
        .notNull()
        .references(() => notificationQualificationInstallations.installationId, {
          onDelete: 'restrict',
        }),
      ...envelope(),
      sourceBytes: bytes('source_bytes').notNull(),
      buildBytes: bytes('build_bytes').notNull(),
    },
    (t) => [
      check(
        'notification_qualification_origin_bytes_ck',
        sql`octet_length(${t.bodyBytes}) between 1 and 131072 and ${t.bodyDigest}='sha256:'||encode(sha256(${t.bodyBytes}),'hex') and octet_length(${t.sourceBytes}) between 1 and 16777216 and octet_length(${t.buildBytes}) between 1 and 16777216`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
export const notificationQualificationOriginProofs = control
  .table(
    'notification_qualification_origin_proof',
    {
      ...scope(),
      originId: uuid('origin_id')
        .primaryKey()
        .references(() => notificationQualificationOrigins.originId, { onDelete: 'restrict' }),
      ...envelope(),
    },
    (t) => [
      check(
        'notification_qualification_origin_proof_bytes_ck',
        sql`octet_length(${t.bodyBytes}) between 1 and 131072 and ${t.bodyDigest}='sha256:'||encode(sha256(${t.bodyBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
export const notificationQualificationRuns = control
  .table(
    'notification_qualification_run',
    {
      ...scope(),
      runId: uuid('run_id').primaryKey(),
      installationId: uuid('installation_id')
        .notNull()
        .references(() => notificationQualificationInstallations.installationId, {
          onDelete: 'restrict',
        }),
      reservationTransaction: text('reservation_transaction').notNull(),
      ...envelope(),
    },
    (t) => [
      check(
        'notification_qualification_run_bytes_ck',
        sql`octet_length(${t.bodyBytes}) between 1 and 262144 and ${t.bodyDigest}='sha256:'||encode(sha256(${t.bodyBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
export const notificationQualificationRecords = control
  .table(
    'notification_qualification_record',
    {
      ...scope(),
      runId: uuid('run_id')
        .notNull()
        .references(() => notificationQualificationRuns.runId, { onDelete: 'restrict' }),
      kind: text('kind').notNull(),
      key: text('record_key').notNull(),
      ...envelope(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.runId, t.kind, t.key] }),
      uniqueIndex('notification_qualification_source_original_uq')
        .on(t.participantId, t.privacyDomainId, t.key)
        .where(sql`${t.kind}='SOURCE'`),
      check(
        'notification_qualification_record_kind_ck',
        sql`${t.kind} in ('INPUT','DISPATCH','SOURCE','SAMPLE','CASE','RAW','OUTCOMES','RESULT','NORMALIZED','REVIEW','CAPACITY')`,
      ),
      check(
        'notification_qualification_record_bytes_ck',
        sql`octet_length(${t.bodyBytes}) between 1 and 16777216 and ${t.bodyDigest}='sha256:'||encode(sha256(${t.bodyBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
