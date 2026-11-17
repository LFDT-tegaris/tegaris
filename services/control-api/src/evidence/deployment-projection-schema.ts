import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopeColumns as scope,
  evidenceScopePolicies as scoped,
  evidenceCatalogue,
} from './schema.js';

/** The operator's normalized observation has its own retention lifecycle.
 * Original signed results and immutable hold lineage remain separate owners. */
export const evidenceDeploymentProvenance = control
  .table(
    'evidence_deployment_provenance',
    {
      ...scope(),
      recordId: text('record_id').notNull(),
      projection: jsonb('projection').notNull(),
      projectionDigest: text('projection_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId] }),
      foreignKey({
        name: 'evidence_deployment_provenance_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId],
        foreignColumns: [
          evidenceCatalogue.participantId,
          evidenceCatalogue.privacyDomainId,
          evidenceCatalogue.streamId,
          evidenceCatalogue.recordId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_deployment_provenance_digest_ck',
        sql`${t.projectionDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'evidence_deployment_provenance_size_ck',
        sql`jsonb_typeof(${t.projection})='object' and octet_length(${t.projection}::text) between 1 and 8192`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
