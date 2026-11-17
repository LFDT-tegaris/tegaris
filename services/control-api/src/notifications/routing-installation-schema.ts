import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
} from '../evidence/schema.js';
import { evidenceExportProducerInstallations } from '../evidence/export-producer-schema.js';
import { notificationEndpoints } from './schema.js';

/** One independently installed current profile. Runtime cannot enroll, replace or
 * reactivate it. Revision authoring/rotation is a separate governed owner; this
 * initial owner never treats a newer caller-supplied signature as current. */
export const installedNotificationRouting = control
  .table(
    'installed_notification_routing',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      profileId: uuid('profile_id').notNull(),
      revision: ordinal('revision').notNull(),
      signedProfileDigest: text('signed_profile_digest').notNull(),
      endpointId: uuid('endpoint_id').notNull(),
      producerTrustDigest: text('producer_trust_digest').notNull(),
      installation: jsonb('installation').notNull(),
      installationBytes: bytes('installation_bytes').notNull(),
      installationDigest: text('installation_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.profileId] }),
      foreignKey({
        name: 'notification_routing_producer_fk',
        columns: [t.participantId, t.privacyDomainId, t.producerTrustDigest],
        foreignColumns: [
          evidenceExportProducerInstallations.participantId,
          evidenceExportProducerInstallations.privacyDomainId,
          evidenceExportProducerInstallations.trustDigest,
        ],
      }),
      foreignKey({
        name: 'notification_routing_endpoint_fk',
        columns: [t.participantId, t.privacyDomainId, t.endpointId],
        foreignColumns: [
          notificationEndpoints.participantId,
          notificationEndpoints.privacyDomainId,
          notificationEndpoints.endpointId,
        ],
      }),
      check(
        'notification_routing_revision_ck',
        sql`${t.revision} between 1 and 18446744073709551615`,
      ),
      check('notification_routing_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      check(
        'notification_routing_digest_ck',
        sql`${t.installationDigest}='sha256:'||encode(sha256(${t.installationBytes}),'hex') and octet_length(${t.installationBytes}) between 1 and 131072`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
