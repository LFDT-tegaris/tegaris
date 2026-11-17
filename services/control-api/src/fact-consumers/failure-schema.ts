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
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
  evidenceScopePolicies as scoped,
} from '../evidence/schema.js';
import { fleetFactDeliveries } from './fleet-delivery-schema.js';

const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});

/** Host-installed public signing grant. Runtime roles never install/renew it.
 * Separate from profile issuance, human sessions and notification authority. */
export const factConsumerFailureSigners = control
  .table(
    'fact_consumer_failure_signer',
    {
      ...scope(),
      consumerId: text('consumer_id').notNull(),
      signerKeyId: text('signer_key_id').notNull(),
      publicKeySpki: bytes('public_key_spki').notNull(),
      environmentId: text('environment_id').notNull(),
      databaseRole: text('database_role').notNull(),
      workloadCredentialId: uuid('workload_credential_id').notNull(),
      workloadCredentialEpoch: ordinal('workload_credential_epoch').notNull(),
      signerRole: text('signer_role').notNull(),
      purposeCode: ordinal('purpose_code').notNull(),
      validFromMs: ordinal('valid_from_ms').notNull(),
      validUntilMs: ordinal('valid_until_ms').notNull(),
      state: text('state').notNull().default('ACTIVE'),
      admissionReference: text('admission_reference').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.consumerId, t.signerKeyId] }),
      uniqueIndex('fact_failure_active_signer_uq')
        .on(t.participantId, t.privacyDomainId, t.consumerId)
        .where(sql`${t.state}='ACTIVE'`),
      foreignKey({
        name: 'fact_failure_signer_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'fact_failure_signer_credential_fk',
        columns: [t.participantId, t.workloadCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'fact_failure_signer_scope_ck',
        sql`${t.consumerId} in ('LS-FLEET-CONTROL','LS-CONTROL-WORK') and ${t.signerRole}='FACT_CONSUMER_FAILURE' and ${t.purposeCode}=344 and ${t.state} in ('ACTIVE','REVOKED') and ${t.workloadCredentialEpoch} between 0 and 18446744073709551615`,
      ),
      check(
        'fact_failure_signer_key_ck',
        sql`${t.signerKeyId}='sha256:'||encode(sha256(${t.publicKeySpki}),'hex') and octet_length(${t.publicKeySpki})=91`,
      ),
      check(
        'fact_failure_signer_time_ck',
        sql`${t.validFromMs} between 0 and 9007199254740991 and ${t.validUntilMs} between ${t.validFromMs}+1 and 9007199254740991`,
      ),
      check(
        'fact_failure_signer_reference_ck',
        sql`length(${t.admissionReference}) between 1 and 256`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Stable original failure identity before local signing. Source bytes stay in
 * fleet_fact_delivery; no draft is a quarantine, receipt, work item or ACK. */
export const fleetFactQuarantines = control
  .table(
    'fleet_fact_quarantine',
    {
      ...scope(),
      eventId: uuid('event_id').notNull(),
      receiptId: uuid('receipt_id').notNull(),
      workItemId: uuid('work_item_id').notNull(),
      materialDigest: bytes('material_digest').notNull(),
      claims: jsonb('claims').notNull(),
      state: text('state').notNull().default('PREPARED'),
      payload: bytes('payload'),
      cose: bytes('cose'),
      receiptDigest: text('receipt_digest'),
      signerKeyId: text('signer_key_id'),
      committedAtMs: ordinal('committed_at_ms'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId] }),
      unique('fleet_quarantine_receipt_uq').on(t.participantId, t.privacyDomainId, t.receiptId),
      unique('fleet_quarantine_work_item_uq').on(t.participantId, t.workItemId),
      foreignKey({
        name: 'fleet_quarantine_delivery_fk',
        columns: [t.participantId, t.privacyDomainId, t.eventId],
        foreignColumns: [
          fleetFactDeliveries.participantId,
          fleetFactDeliveries.privacyDomainId,
          fleetFactDeliveries.eventId,
        ],
      }).onDelete('restrict'),
      check(
        'fleet_quarantine_identity_ck',
        sql`octet_length(${t.materialDigest})=32 and ${t.receiptId}<>${t.workItemId}`,
      ),
      check(
        'fleet_quarantine_state_ck',
        sql`((${t.state}='PREPARED' and ${t.payload} is null and ${t.cose} is null and ${t.receiptDigest} is null and ${t.signerKeyId} is null and ${t.committedAtMs} is null) or (${t.state}='COMMITTED' and octet_length(${t.payload}) between 1 and 65536 and octet_length(${t.cose}) between 65 and 66560 and ${t.receiptDigest}='sha256:'||encode(sha256(${t.cose}),'hex') and ${t.signerKeyId} ~ '^sha256:[0-9a-f]{64}$' and ${t.committedAtMs} between 0 and 9007199254740991)) is true`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Dedicated durable receipt-reference outbox. Publication/custody must verify
 * the linked exact canonical failure; insertion is not delivery acknowledgement. */
export const fleetFactFailureOutbox = control
  .table(
    'fleet_fact_failure_outbox',
    {
      ...scope(),
      receiptId: uuid('receipt_id').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.receiptId] }),
      foreignKey({
        name: 'fleet_failure_outbox_receipt_fk',
        columns: [t.participantId, t.privacyDomainId, t.receiptId],
        foreignColumns: [
          fleetFactQuarantines.participantId,
          fleetFactQuarantines.privacyDomainId,
          fleetFactQuarantines.receiptId,
        ],
      }).onDelete('restrict'),
      check('fleet_failure_outbox_digest_ck', sql`${t.receiptDigest} ~ '^sha256:[0-9a-f]{64}$'`),
      ...scoped(t),
    ],
  )
  .enableRLS();
