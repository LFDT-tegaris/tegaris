import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopeColumns as scope,
  evidenceScopePolicies as scoped,
  evidenceCatalogue,
} from './schema.js';

/** Purpose-verified historical anchors for preservation. Original receipt bytes
 * remain in encrypted custody; current finality is a separate source decision. */
export const evidenceDeploymentLineage = control
  .table(
    'evidence_deployment_lineage',
    {
      ...scope(),
      recordId: text('record_id').notNull(),
      projection: jsonb('projection').notNull(),
      projectionDigest: text('projection_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId] }),
      foreignKey({
        name: 'evidence_deployment_lineage_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId],
        foreignColumns: [
          evidenceCatalogue.participantId,
          evidenceCatalogue.privacyDomainId,
          evidenceCatalogue.streamId,
          evidenceCatalogue.recordId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_deployment_lineage_digest_ck',
        sql`${t.projectionDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'evidence_deployment_lineage_size_ck',
        sql`jsonb_typeof(${t.projection})='object' and octet_length(${t.projection}::text) between 1 and 4096`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
