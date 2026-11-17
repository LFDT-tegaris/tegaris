import { sql } from 'drizzle-orm';
import {
  check,
  customType,
  foreignKey,
  numeric,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

import {
  pendingDeliverySql,
  pendingDeliveryReasonCodes,
  pendingDeliveryStates,
  pendingDeliverySurfaces,
} from '../../generated/pending-delivery-projection.js';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { privacyDomains } from './participants.js';

const cText = customType<{ data: string; driverData: string }>({
  dataType: () => 'text COLLATE "C"',
});
const auditTimestamp = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const uint64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });

export const pendingDeliverySurface = control.enum(
  'pending_delivery_surface',
  pendingDeliverySurfaces,
);
export const pendingDeliveryState = control.enum('pending_delivery_state', pendingDeliveryStates);
export const pendingDeliveryReason = control.enum(
  'pending_delivery_reason',
  pendingDeliveryReasonCodes,
);

export const pendingDeliveries = control
  .table(
    'pending_delivery',
    {
      pendingDeliveryId: uuid('pending_delivery_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      chainId: uint64('chain_id').notNull(),
      profileId: cText('profile_id').notNull(),
      profileVersion: cText('profile_version').notNull(),
      correlatedLogIdentityHmac: bytea('correlated_log_identity_hmac').notNull(),
      entityHmac: bytea('entity_hmac').notNull(),
      entityScopeDigest: bytea('entity_scope_digest').notNull(),
      deliverySurface: pendingDeliverySurface('delivery_surface').notNull(),
      protectedDeliveryReferenceDigest: bytea('protected_delivery_reference_digest').notNull(),
      subscriptionReferenceDigest: bytea('subscription_reference_digest'),
      sessionReferenceDigest: bytea('session_reference_digest'),
      state: pendingDeliveryState().notNull().default('PENDING'),
      leaseOwner: uuid('lease_owner'),
      leaseExpiresAt: auditTimestamp('lease_expires_at'),
      nextRetryAt: auditTimestamp('next_retry_at'),
      safeReason: pendingDeliveryReason('safe_reason'),
      firstObservedAt: auditTimestamp('first_observed_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      lastObservedAt: auditTimestamp('last_observed_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'pending_delivery_privacy_domain_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      unique('pending_delivery_full_identity_history_uq')
        .on(
          table.participantId,
          table.privacyDomainId,
          table.chainId,
          table.profileId,
          table.profileVersion,
          table.correlatedLogIdentityHmac,
          table.entityHmac,
          table.entityScopeDigest,
          table.deliverySurface,
          table.protectedDeliveryReferenceDigest,
          table.subscriptionReferenceDigest,
          table.sessionReferenceDigest,
        )
        .nullsNotDistinct(),
      unique('pending_delivery_successor_guard_uq').on(
        table.participantId,
        table.privacyDomainId,
        table.profileVersion,
        table.protectedDeliveryReferenceDigest,
      ),
      uniqueIndex('pending_delivery_active_full_identity_uq')
        .on(
          table.participantId,
          table.privacyDomainId,
          table.chainId,
          table.profileId,
          table.profileVersion,
          table.correlatedLogIdentityHmac,
          table.entityHmac,
          table.entityScopeDigest,
          table.deliverySurface,
          table.protectedDeliveryReferenceDigest,
          table.subscriptionReferenceDigest,
          table.sessionReferenceDigest,
        )
        .where(sql.raw(pendingDeliverySql.activePredicate)),
      check('pending_delivery_chain_id_ck', sql.raw(pendingDeliverySql.chainIdCheck)),
      check('pending_delivery_profile_id_ck', sql.raw(pendingDeliverySql.profileIdCheck)),
      check('pending_delivery_profile_version_ck', sql.raw(pendingDeliverySql.profileVersionCheck)),
      check('pending_delivery_digest_lengths_ck', sql.raw(pendingDeliverySql.digestLengthsCheck)),
      check(
        'pending_delivery_surface_references_ck',
        sql.raw(pendingDeliverySql.surfaceReferencesCheck),
      ),
      check('pending_delivery_lifecycle_facts_ck', sql.raw(pendingDeliverySql.lifecycleFactsCheck)),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();
