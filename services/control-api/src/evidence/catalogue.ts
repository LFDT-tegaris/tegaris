import type { Pool } from 'pg';
import { z } from 'zod';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../configuration/persistence/scoped-read.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { selectPage, type ListRequest } from '../configuration/pagination.js';
import { evidenceClass } from './segment.js';
import { evidenceRecordView } from './catalogue-contracts.js';
export { evidenceRecordView } from './catalogue-contracts.js';
import { evidenceRecordExportRange } from './export-contracts.js';
import { readEvidenceProvenance } from './provenance.js';

type CatalogueRow = {
  evidenceId: string;
  participantId: string;
  evidenceClass: z.infer<typeof evidenceClass>;
  recordDigest: string;
  sequence: string;
  occurredAt: string;
  updatedAt: string;
  state: 'ADMITTED' | 'HELD';
};
const projection = `evidence_id::text as "evidenceId",participant_id::text as "participantId",evidence_class as "evidenceClass",
  receipt_digest as "recordDigest",sequence::text,to_char(occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt",
  to_char(updated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "updatedAt",state`;
// Explicit tenant predicates complement RLS; encrypted bytes never enter this projection.
const source = `(select c.*,c.created_at as updated_at,case when exists(select 1 from control.retention_hold h
    where h.participant_id=c.participant_id and (h.selector_type='PARTICIPANT' or h.privacy_domain_id=c.privacy_domain_id) and h.state='ACTIVE'
    and openpc.evidence_hold_matches(h.selector,c.participant_id,c.privacy_domain_id,c.stream_id,c.segment_id))
    then 'HELD' else 'ADMITTED' end state from control.evidence_catalogue c
  where c.participant_id=current_setting('openpc.participant_id')::uuid
   and c.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid) evidence`;
function view(row: CatalogueRow) {
  return evidenceRecordView.parse({
    ...row,
    evidenceId: `urn:openpc:resource:${row.evidenceId}`,
    participantId: `urn:openpc:participant:${row.participantId}`,
    revision: '1',
    createdAt: row.updatedAt,
  });
}
export class EvidenceCatalogueRepository {
  private readonly reads: ScopedConfigurationRead;
  constructor(pool: Pool) {
    this.reads = new ScopedConfigurationRead(pool);
  }
  provenance(context: ReadContext) {
    return this.reads.execute(context, (client) =>
      readEvidenceProvenance(
        client,
        context.resourceId,
        context.authorization.participantId,
        context.authorization.privacyDomainId,
      ),
    );
  }
  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query<CatalogueRow>(
        `select ${projection} from ${source} where evidence_id=$1`,
        [context.resourceId],
      );
      if (result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      return view(result.rows[0]!);
    });
  }
  exportRange(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query<{
        streamId: string;
        sequence: string;
        recordDigest: string;
      }>(
        `select stream_id as "streamId",sequence::text,receipt_digest as "recordDigest"
        from ${source} where evidence_id=$1`,
        [context.resourceId],
      );
      const row = result.rows[0];
      if (result.rowCount !== 1 || !row)
        throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      return evidenceRecordExportRange.parse({
        evidenceId: `urn:openpc:resource:${context.resourceId}`,
        recordDigest: row.recordDigest,
        range: {
          streamId: row.streamId,
          fromSequence: row.sequence,
          throughSequence: row.sequence,
          redactionProfileId: 'pc.evidence.minimized-audit.v1',
        },
      });
    });
  }
  list(context: ReadContext, request: ListRequest) {
    return this.reads.execute(context, (client) =>
      selectPage(client, request, {
        table: source,
        idColumn: 'evidence_id',
        projection,
        filterColumns: { evidenceClass: 'evidence_class', recordDigest: 'receipt_digest' },
        rowId: (row: CatalogueRow) => row.evidenceId,
        rowUpdatedAt: (row: CatalogueRow) => row.updatedAt,
        map: view,
      }),
    );
  }
}
