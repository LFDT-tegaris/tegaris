import type { Pool, PoolClient } from 'pg';
import { sha256 } from '../configuration/digest.js';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import { buildEvidenceExportArtifact } from './export-artifact.js';
import { readEvidenceExportCompletionSource } from './export-completion-source.js';
import { evidenceExportSelection, type EvidenceExportSelection } from './export-contracts.js';
import { RemoteArchiveEvidenceReader } from './remote-archive-reader.js';
import { LocalEvidenceVault, vaultObject } from './local-vault.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import {
  evidenceScope,
  EvidenceCustodyError,
  openSegment,
  type EvidenceScope,
  type SegmentHeader,
} from './segment.js';

interface PendingExport {
  evidenceExportId: string;
  requestDigest: string;
  startOperationId: string;
  selection: unknown;
}
interface ArchivedSegment {
  header: SegmentHeader;
  objectDigest: string;
  checkpointDigest: string;
}

/** Scoped, restart-safe worker. Only an approved, committed start is executable.
 * Row locking serializes competing workers; output and completion commit together.
 * A lost database response is recovered by reading the original immutable output.
 */
export class EvidenceExportWorker {
  constructor(
    private readonly pool: Pool,
    private readonly sink: LocalEvidenceVault | RemoteArchiveEvidenceReader,
    private readonly resolveKey: (scope: EvidenceScope, keyId: string) => Promise<Buffer>,
  ) {}

  async runNext(scopeValue: EvidenceScope) {
    const scope = evidenceScope.parse(scopeValue),
      client = await this.pool.connect();
    try {
      await client.query('begin');
      await client.query('set local synchronous_commit=on');
      await client.query('set local row_security=on');
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
        [scope.participantId, scope.privacyDomainId, uuidv7()],
      );
      await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
      const pending = await client.query<PendingExport>(
        `select e.evidence_export_id::text as "evidenceExportId",
        e.request_digest as "requestDigest",e.start_operation_id::text as "startOperationId",s.selection
        from control.evidence_export_request e join control.evidence_export_selection s
        using(participant_id,privacy_domain_id,stream_id,request_digest)
        where e.participant_id=$1 and e.privacy_domain_id=$2 and e.stream_id=$3 and e.state in ('RUNNING','BACKLOGGED')
        order by e.updated_at,e.evidence_export_id for update of e skip locked limit 1`,
        [scope.participantId, scope.privacyDomainId, scope.streamId],
      );
      const row = pending.rows[0];
      if (!row) {
        await client.query('commit');
        return null;
      }
      await client.query(`select set_config('openpc.operation_id',$1,true)`, [
        row.startOperationId,
      ]);
      const selection = evidenceExportSelection.parse(row.selection);
      if (
        sha256(selection) !== row.requestDigest ||
        selection.participantId !== scope.participantId ||
        selection.privacyDomainId !== scope.privacyDomainId ||
        selection.range.streamId !== scope.streamId
      )
        throw new EvidenceCustodyError('INTEGRITY');
      try {
        const checkpoints = await this.verifySources(client, scope, selection);
        const result = buildEvidenceExportArtifact(
          row.evidenceExportId,
          selection,
          this.sink.sinkId,
          checkpoints,
          this.sink instanceof RemoteArchiveEvidenceReader
            ? this.sink.assurance
            : 'LOCAL_FSYNC_READBACK',
        );
        await client.query(
          `insert into control.evidence_export_output
          (participant_id,privacy_domain_id,stream_id,evidence_export_id,sink_id,output_digest,artifact)
          values($1,$2,$3,$4,$5,$6,$7)`,
          [
            scope.participantId,
            scope.privacyDomainId,
            scope.streamId,
            row.evidenceExportId,
            this.sink.sinkId,
            result.outputDigest,
            result.bytes,
          ],
        );
        await client.query(
          `update control.evidence_export_request set state='SUCCEEDED',checkpoint=$2,
          output_digest=$3,last_error_code=null,revision=revision+1 where evidence_export_id=$1`,
          [row.evidenceExportId, selection.range.throughSequence, result.outputDigest],
        );
        const completion = await readEvidenceExportCompletionSource(
          client,
          scope,
          row.evidenceExportId,
        );
        if (
          completion.source.startOperationId !== row.startOperationId ||
          completion.source.requestDigest !== row.requestDigest ||
          completion.source.outputDigest !== result.outputDigest ||
          completion.source.recordCount !== String(result.artifact.records.length)
        )
          throw new EvidenceCustodyError('INTEGRITY');
        await client.query('commit');
        return {
          evidenceExportId: row.evidenceExportId,
          state: 'SUCCEEDED' as const,
          outputDigest: result.outputDigest,
        };
      } catch (error) {
        // Only known storage/key unavailability is retryable. Integrity failures
        // are terminal; unknown/database failures roll back rather than fabricate a result.
        if (
          !(error instanceof EvidenceCustodyError) ||
          !['UNAVAILABLE', 'INTEGRITY'].includes(error.code)
        )
          throw error;
        const state = error.code === 'UNAVAILABLE' ? 'BACKLOGGED' : 'FAILED';
        await client.query(
          `update control.evidence_export_request set state=$2,last_error_code='PC-OPS-9002',revision=revision+1
          where evidence_export_id=$1`,
          [row.evidenceExportId, state],
        );
        await client.query('commit');
        return { evidenceExportId: row.evidenceExportId, state };
      }
    } catch (error) {
      await client.query('rollback').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  private async verifySources(
    client: PoolClient,
    scope: EvidenceScope,
    selection: EvidenceExportSelection,
  ) {
    const checkpoints = new Map<string, string>();
    for (const segmentId of new Set(selection.records.map((record) => record.segmentId))) {
      const result = await client.query<ArchivedSegment>(
        `select jsonb_build_object(
        'version','OPENPC_EVIDENCE_SEGMENT_V1','participantId',s.participant_id::text,'privacyDomainId',s.privacy_domain_id::text,
        'streamId',s.stream_id,'segmentId',s.segment_id::text,'firstSequence',s.first_sequence::text,
        'throughSequence',s.through_sequence::text,'previousSegmentDigest',s.previous_segment_digest,'keyId',s.key_id,
        'retentionUntil',to_char(s.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) as header,
        s.object_digest as "objectDigest",c.checkpoint_digest as "checkpointDigest"
        from control.evidence_segment s join control.evidence_checkpoint c
        using(participant_id,privacy_domain_id,stream_id,segment_id,object_digest)
        where s.participant_id=$1 and s.privacy_domain_id=$2 and s.stream_id=$3 and s.segment_id=$4 and c.sink_id=$5`,
        [scope.participantId, scope.privacyDomainId, scope.streamId, segmentId, this.sink.sinkId],
      );
      const row = result.rows[0];
      if (result.rowCount !== 1 || !row) throw new EvidenceCustodyError('UNAVAILABLE');
      const object = vaultObject(this.sink.sinkId, row.header, row.objectDigest);
      const bytes =
        this.sink instanceof RemoteArchiveEvidenceReader
          ? await this.sink.read(client, object, row.checkpointDigest)
          : await this.sink.read(object);
      const { records } = openSegment(
        bytes,
        row.objectDigest,
        row.header,
        await this.resolveKey(scope, row.header.keyId),
      );
      for (const selected of selection.records.filter((record) => record.segmentId === segmentId)) {
        const source = records.find((record) => record.sequence === selected.sequence);
        if (
          !source ||
          source.recordId !== selected.sourceRecordId ||
          source.receiptDigest !== selected.recordDigest ||
          source.evidenceClass !== selected.evidenceClass ||
          source.occurredAt !== selected.occurredAt ||
          row.objectDigest !== selected.objectDigest
        )
          throw new EvidenceCustodyError('INTEGRITY');
      }
      checkpoints.set(segmentId, row.checkpointDigest);
    }
    return checkpoints;
  }
}
