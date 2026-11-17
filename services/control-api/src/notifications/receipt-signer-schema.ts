import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  primaryKey,
  text,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
} from '../evidence/schema.js';
import { installedNotificationWorkers } from './worker-installation-schema.js';
/** Public initial trust only. Canonical registry/migration/RLS dispatch owns adoption. */
export const notificationReceiptSignerInstallations = control
  .table(
    'notification_receipt_signer_installation',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      installationId: uuid('installation_id').notNull(),
      workerInstallationDigest: text('worker_installation_digest').notNull(),
      signerId: text('signer_id').notNull(),
      trust: jsonb('trust').notNull(),
      trustBytes: bytes('trust_bytes').notNull(),
      trustDigest: text('trust_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.installationId] }),
      unique('notification_receipt_signer_trust_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.trustDigest,
      ),
      uniqueIndex('notification_receipt_signer_current_uq')
        .on(
          t.participantId,
          t.privacyDomainId,
          t.workerInstallationDigest,
          sql`(${t.trust}->>'purpose')`,
        )
        .where(sql`${t.state}='ACTIVE'`),
      foreignKey({
        name: 'notification_receipt_signer_worker_fk',
        columns: [t.participantId, t.privacyDomainId, t.workerInstallationDigest],
        foreignColumns: [
          installedNotificationWorkers.participantId,
          installedNotificationWorkers.privacyDomainId,
          installedNotificationWorkers.installationDigest,
        ],
      }).onDelete('restrict'),
      check('notification_receipt_signer_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      check(
        'notification_receipt_signer_digest_ck',
        sql`${t.trustDigest}='sha256:'||encode(sha256(${t.trustBytes}),'hex') and octet_length(${t.trustBytes}) between 1 and 16384`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
