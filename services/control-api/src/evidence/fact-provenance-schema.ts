import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopeColumns as scope,
  evidenceScopePolicies as scoped,
  evidenceCatalogue,
} from './schema.js';

/** Fact-owner-verified historical identities for preservation. Original receipt bytes
 * remain in encrypted custody; current readiness is a separate source decision. */
export const evidenceFactProvenance = control
  .table(
    'evidence_fact_provenance',
    {
      ...scope(),
      recordId: text('record_id').notNull(),
      projection: jsonb('projection').notNull(),
      projectionDigest: text('projection_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId] }),
      foreignKey({
        name: 'evidence_fact_provenance_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId],
        foreignColumns: [
          evidenceCatalogue.participantId,
          evidenceCatalogue.privacyDomainId,
          evidenceCatalogue.streamId,
          evidenceCatalogue.recordId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_fact_provenance_digest_ck',
        sql`${t.projectionDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'evidence_fact_provenance_size_ck',
        sql`jsonb_typeof(${t.projection})='object' and octet_length(${t.projection}::text) between 1 and 4096`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
