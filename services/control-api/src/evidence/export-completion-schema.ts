import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
} from './schema.js';
import { evidenceExportOutputs } from './export-schema.js';
import { evidenceExportProducerInstallations } from './export-producer-schema.js';
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});

/** Original signing input is durable before external signing I/O. Observation
 * and final event publication are separate transitions; ambiguity never creates
 * a second completion identity or replaces these bytes. */
export const evidenceExportCompletions = control
  .table(
    'evidence_export_completion',
    {
      ...scope(),
      eventId: uuid('event_id').primaryKey(),
      evidenceExportId: uuid('evidence_export_id').notNull(),
      streamId: text('stream_id').notNull(),
      trustDigest: text('trust_digest').notNull(),
      claims: jsonb('claims').notNull(),
      receiptPayload: bytes('receipt_payload').notNull(),
      receiptPayloadDigest: text('receipt_payload_digest').notNull(),
      authoritySnapshot: bytes('authority_snapshot').notNull(),
      sourceData: bytes('source_data').notNull(),
      eventPayload: bytes('event_payload').notNull(),
      eventPayloadDigest: text('event_payload_digest').notNull(),
      state: text('state').notNull().default('PREPARED'),
      coseSign1: bytes('cose_sign1'),
    },
    (t) => [
      unique('evidence_export_completion_export_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.evidenceExportId,
      ),
      unique('evidence_export_completion_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.eventId,
      ),
      foreignKey({
        name: 'evidence_export_completion_source_fk',
        columns: [t.evidenceExportId],
        foreignColumns: [evidenceExportOutputs.evidenceExportId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'evidence_export_completion_trust_fk',
        columns: [t.participantId, t.privacyDomainId, t.trustDigest],
        foreignColumns: [
          evidenceExportProducerInstallations.participantId,
          evidenceExportProducerInstallations.privacyDomainId,
          evidenceExportProducerInstallations.trustDigest,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_export_completion_state_ck',
        sql`(${t.state}='PREPARED' and ${t.coseSign1} is null) or (${t.state} in ('OBSERVED','PUBLISHED') and octet_length(${t.coseSign1}) between 1 and 66560)`,
      ),
      check(
        'evidence_export_completion_digest_ck',
        sql`${t.receiptPayloadDigest}='sha256:'||encode(sha256(${t.receiptPayload}),'hex') and ${t.eventPayloadDigest}='sha256:'||encode(sha256(${t.eventPayload}),'hex') and octet_length(${t.receiptPayload}) between 1 and 65536 and octet_length(${t.eventPayload}) between 1 and 65536 and octet_length(${t.authoritySnapshot}) between 1 and 16384 and octet_length(${t.sourceData}) between 1 and 4096`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
