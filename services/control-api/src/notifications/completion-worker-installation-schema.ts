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
  credentials,
  privacyDomains,
} from '../../../identity-service/src/db/schema/participants.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
} from '../evidence/schema.js';
/** Completion consumer installation only. Shared migrations/grants and all consumer effects remain separately owned. */
export const installedNotificationCompletionWorkers = control
  .table(
    'installed_notification_completion_worker',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      profileId: uuid('profile_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      workloadCredentialId: uuid('workload_credential_id').notNull(),
      serviceId: text('service_id').notNull(),
      subscriptionId: text('subscription_id').notNull(),
      producerTrustDigest: text('producer_trust_digest').notNull(),
      signedProfileDigest: text('signed_profile_digest').notNull(),
      installation: jsonb('installation').notNull(),
      installationBytes: bytes('installation_bytes').notNull(),
      installationDigest: text('installation_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.profileId] }),
      unique('notification_completion_worker_installation_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.installationDigest,
      ),
      uniqueIndex('notification_completion_worker_current_uq')
        .on(t.participantId, t.privacyDomainId, t.serviceId, t.subscriptionId)
        .where(sql`${t.state}='ACTIVE'`),
      foreignKey({
        name: 'notification_completion_worker_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_completion_worker_credential_fk',
        columns: [t.participantId, t.workloadCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'notification_completion_worker_subscription_ck',
        sql`${t.serviceId}='LS-CONTROL-WORK' and ${t.subscriptionId}='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'`,
      ),
      check('notification_completion_worker_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      check(
        'notification_completion_worker_installation_ck',
        sql`${t.installationDigest}='sha256:'||encode(sha256(${t.installationBytes}),'hex') and octet_length(${t.installationBytes}) between 1 and 262144`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
