import { sql } from 'drizzle-orm';
import { check, foreignKey, index, jsonb, primaryKey, text } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopeColumns as scope,
  evidenceScopePolicies as scoped,
  evidenceCatalogue,
} from './schema.js';

/** Rebuildable, minimized metadata. No ciphertext/key, hold, archive truth or
 * new authorization; admission belongs exclusively to the verified worker. */
export const evidenceRpcProvenance = control
  .table(
    'evidence_rpc_provenance',
    {
      ...scope(),
      recordId: text('record_id').notNull(),
      projection: jsonb('projection').notNull(),
      projectionDigest: text('projection_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId] }),
      index('evidence_rpc_provenance_decision_idx').on(
        t.participantId,
        t.privacyDomainId,
        t.streamId,
        sql`(${t.projection}->>'decisionId')`,
      ),
      foreignKey({
        name: 'evidence_rpc_provenance_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId],
        foreignColumns: [
          evidenceCatalogue.participantId,
          evidenceCatalogue.privacyDomainId,
          evidenceCatalogue.streamId,
          evidenceCatalogue.recordId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_rpc_provenance_digest_ck',
        sql`${t.projectionDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'evidence_rpc_provenance_size_ck',
        sql`jsonb_typeof(${t.projection})='object' and octet_length(${t.projection}::text) between 1 and 8192`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
