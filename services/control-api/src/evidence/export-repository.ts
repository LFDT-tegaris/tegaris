import type { Pool, PoolClient } from 'pg';
import { AtomicConfigurationMutation } from '../configuration/persistence/atomic-mutation.js';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../configuration/persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import type { ResourceApiOptions } from '../configuration/governed-mutation-http.js';
import { selectPage, type ListRequest } from '../configuration/pagination.js';
import { sha256 } from '../configuration/digest.js';
import { evidenceExportArtifact } from './export-artifact.js';
import {
  evidenceExportRange,
  evidenceExportSelection,
  evidenceExportView,
  evidenceExportSelectionView,
  selectedEvidenceRecord,
  type EvidenceExportRange,
} from './export-contracts.js';

interface ExportRow {
  evidenceExportId: string;
  participantId: string;
  requestDigest: string;
  state: string;
  checkpoint: string;
  outputDigest: string | null;
  revision: string;
  createdAt: string;
  updatedAt: string;
}
const projection = `evidence_export_id::text as "evidenceExportId",participant_id::text as "participantId",
 request_digest as "requestDigest",state,checkpoint::text,output_digest as "outputDigest",revision::text,
 to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "createdAt",
 to_char(updated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "updatedAt"`;
const view = (row: ExportRow) =>
  evidenceExportView.parse({
    ...row,
    evidenceExportId: `urn:openpc:resource:${row.evidenceExportId}`,
    participantId: `urn:openpc:participant:${row.participantId}`,
  });
const scopeValues = (context: MutationContext | ReadContext) => [
  context.authorization.participantId,
  context.authorization.privacyDomainId,
];

/** Resolve user ranges to authoritative immutable receipt identities. */
async function selectionForRange(
  client: PoolClient,
  context: MutationContext,
  value: EvidenceExportRange,
) {
  const range = evidenceExportRange.parse(value);
  const result = await client.query(
    `select 'urn:openpc:resource:'||c.evidence_id::text as "evidenceId",
   c.record_id as "sourceRecordId",c.segment_id::text as "segmentId",s.object_digest as "objectDigest",
   c.sequence::text,c.evidence_class as "evidenceClass",c.receipt_digest as "recordDigest",
   to_char(c.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt"
   from control.evidence_catalogue c join control.evidence_segment s
    using(participant_id,privacy_domain_id,stream_id,segment_id)
   where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3
    and c.sequence between $4 and $5 order by c.sequence`,
    [...scopeValues(context), range.streamId, range.fromSequence, range.throughSequence],
  );
  const count = Number(BigInt(range.throughSequence) - BigInt(range.fromSequence) + 1n);
  if (result.rowCount !== count) throw new ConfigurationRepositoryError('PC-DATA-6007');
  const records = result.rows.map((row) => selectedEvidenceRecord.parse(row));
  if (
    records.some(
      (row, index) => BigInt(row.sequence) !== BigInt(range.fromSequence) + BigInt(index),
    )
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  return evidenceExportSelection.parse({
    version: 'OPENPC_EVIDENCE_EXPORT_SELECTION_V1',
    participantId: context.authorization.participantId,
    privacyDomainId: context.authorization.privacyDomainId,
    range,
    records,
  });
}

export class EvidenceExportRepository {
  private readonly reads: ScopedConfigurationRead;
  private readonly mutations: AtomicConfigurationMutation;
  constructor(
    pool: Pool,
    options: Pick<ResourceApiOptions, 'identityRuntimeVerifier' | 'businessEvidence'> = {},
  ) {
    this.reads = new ScopedConfigurationRead(pool);
    this.mutations = new AtomicConfigurationMutation(
      pool,
      options.identityRuntimeVerifier,
      options.businessEvidence,
    );
  }
  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<ExportRow>(
        `select ${projection} from control.evidence_export_request
        where participant_id=$1 and privacy_domain_id=$2 and evidence_export_id=$3`,
        [...scopeValues(context), context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      return view(selected.rows[0]!);
    });
  }
  list(context: ReadContext, request: ListRequest) {
    return this.reads.execute(context, (client) =>
      selectPage(client, request, {
        table: 'control.evidence_export_request',
        idColumn: 'evidence_export_id',
        projection,
        filterColumns: { state: 'state', requestDigest: 'request_digest' },
        rowId: (row: ExportRow) => row.evidenceExportId,
        rowUpdatedAt: (row: ExportRow) => row.updatedAt,
        map: view,
      }),
    );
  }
  download(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query<{ artifact: Buffer; outputDigest: string }>(
        `select o.artifact,o.output_digest as "outputDigest"
        from control.evidence_export_request e join control.evidence_export_output o
        using(participant_id,privacy_domain_id,stream_id,evidence_export_id,output_digest)
        where e.participant_id=$1 and e.privacy_domain_id=$2 and e.evidence_export_id=$3 and e.state='SUCCEEDED'`,
        [...scopeValues(context), context.resourceId],
      );
      const row = result.rows[0];
      if (!row) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      if (sha256(row.artifact) !== row.outputDigest)
        throw new ConfigurationRepositoryError('PC-OPS-9002');
      return {
        outputDigest: row.outputDigest,
        artifact: evidenceExportArtifact.parse(JSON.parse(row.artifact.toString('utf8'))),
      };
    });
  }
  selection(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query<{ requestDigest: string; selection: unknown }>(
        `select e.request_digest as "requestDigest",s.selection
        from control.evidence_export_request e join control.evidence_export_selection s
          using(participant_id,privacy_domain_id,stream_id,request_digest)
        where e.participant_id=$1 and e.privacy_domain_id=$2 and e.evidence_export_id=$3`,
        [...scopeValues(context), context.resourceId],
      );
      const row = result.rows[0];
      if (!row) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      const selection = evidenceExportSelection.parse(row.selection);
      if (sha256(selection) !== row.requestDigest)
        throw new ConfigurationRepositoryError('PC-OPS-9002');
      return evidenceExportSelectionView.parse({
        requestDigest: row.requestDigest,
        range: selection.range,
        records: selection.records.map(
          ({ evidenceId, sequence, evidenceClass, recordDigest, occurredAt }) => ({
            evidenceId,
            sequence,
            evidenceClass,
            recordDigest,
            occurredAt,
          }),
        ),
      });
    });
  }
  create(
    context: MutationContext,
    input: { selection: EvidenceExportRange } | { requestDigest: string },
  ) {
    return this.mutations.execute(context, async (client, id, operationId) => {
      let requestDigest: string;
      let streamId: string;
      if ('selection' in input) {
        const selection = await selectionForRange(client, context, input.selection);
        requestDigest = sha256(selection);
        streamId = selection.range.streamId;
        await client.query(
          `insert into control.evidence_export_selection(participant_id,privacy_domain_id,stream_id,request_digest,selection)
          values($1,$2,$3,$4,$5::jsonb) on conflict do nothing`,
          [...scopeValues(context), streamId, requestDigest, JSON.stringify(selection)],
        );
      } else {
        const selected = await client.query<{ streamId: string }>(
          `select stream_id as "streamId" from control.evidence_export_selection
          where participant_id=$1 and privacy_domain_id=$2 and request_digest=$3`,
          [...scopeValues(context), input.requestDigest],
        );
        if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        requestDigest = input.requestDigest;
        streamId = selected.rows[0]!.streamId;
      }
      const written = await client.query<ExportRow>(
        `insert into control.evidence_export_request
        (participant_id,privacy_domain_id,stream_id,evidence_export_id,request_digest,creation_operation_id,last_operation_id)
        values($1,$2,$3,$4,$5,$6,$6) returning ${projection}`,
        [...scopeValues(context), streamId, id, requestDigest, operationId],
      );
      return {
        result: view(written.rows[0]!),
        revision: '1',
        outboxEventType: 'openpc.evidence.export.requested.v1',
      };
    });
  }
  update(context: MutationContext, replacementDigest: string) {
    return this.mutations.execute(context, async (client, id, operationId) => {
      const changed = await client.query<ExportRow>(
        `update control.evidence_export_request e
        set request_digest=$4,stream_id=s.stream_id,revision=e.revision+1,updated_at=clock_timestamp(),last_operation_id=$6
        from control.evidence_export_selection s
        where e.participant_id=$1 and e.privacy_domain_id=$2 and e.evidence_export_id=$3
         and e.revision=$5 and e.state='REQUESTED' and e.request_digest<>$4
         and s.participant_id=e.participant_id and s.privacy_domain_id=e.privacy_domain_id and s.request_digest=$4
        returning e.evidence_export_id::text as "evidenceExportId"`,
        [...scopeValues(context), id, replacementDigest, context.expectedRevision, operationId],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      return {
        result: { evidenceExportId: id },
        revision: String(BigInt(context.expectedRevision) + 1n),
        outboxEventType: 'openpc.evidence.export.updated.v1',
      };
    });
  }
  start(context: MutationContext, inputDigest: string) {
    return this.mutations.execute(context, async (client, id, operationId) => {
      const changed = await client.query(
        `update control.evidence_export_request set state='RUNNING',start_operation_id=$6,
        last_operation_id=$6,revision=revision+1,updated_at=clock_timestamp()
        where participant_id=$1 and privacy_domain_id=$2 and evidence_export_id=$3
         and revision=$5 and request_digest=$4 and state='REQUESTED'`,
        [...scopeValues(context), id, inputDigest, context.expectedRevision, operationId],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      return {
        result: { evidenceExportId: id },
        revision: String(BigInt(context.expectedRevision) + 1n),
        outboxEventType: 'openpc.evidence.export.started.v1',
        asynchronous: true,
      };
    });
  }
}
