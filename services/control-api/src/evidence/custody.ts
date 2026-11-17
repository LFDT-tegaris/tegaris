import {
  readRuntimeArtifactArchiveSource,
  runtimeArtifactArchiveRequest,
} from './runtime-artifact-archive-source.js';
import {
  verifyRuntimeArtifactArchiveReadback,
  retainRuntimeArtifactArchive,
} from './runtime-artifact-archive-custody.js';
import type { ArchiveKeyResolver } from './archive-source-readback.js';
import { readNotificationOutcomeEvidenceSources } from './notification-outcome-source.js';
import { uncustodiedFactSources } from './fact-custody-recovery.js';
import { retainFactAdmissionDelivery } from './fact-delivery.js';
import {
  readCandidateArchiveSource,
  nextCandidateArchiveRecords,
  retainCandidateArchive,
  candidateArchiveSource,
  type CandidateArchiveSource,
  type CandidateArchiveKeyResolver,
} from './candidate-archive/source.js';
import type { CandidateArchiveRequest } from './candidate-archive/contract.js';
import {
  readFactEvidenceBatch,
  retainFactProvenance,
  type FactEvidenceSource,
} from './fact-source.js';
import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import { LocalEvidenceVault, vaultObject } from './local-vault.js';
import { readBusinessEvidenceSources } from './business-source.js';
import { readFactFailureEvidenceSources } from './fact-failure-source.js';
import { readAuthenticationEvidenceSources } from './authentication-source.js';
import { readEffectEvidenceBatch } from './effect-source.js';
import { retainDeploymentLineage } from './deployment-lineage.js';
import { readRpcEvidenceBatch, type RpcEvidenceSource } from './rpc-source.js';
import { retainRpcProjections } from './rpc-provenance.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { coverObjectHolds, pendingHoldObjects } from './hold-custody.js';
import {
  EvidenceCustodyError,
  evidenceScope,
  sealSegment,
  type EvidenceScope,
  type SegmentHeader,
  type SourceReceipt,
} from './segment.js';

export interface EvidenceEncryptionKey {
  readonly keyId: string;
  readonly key: Buffer;
}
interface SegmentRow {
  segmentId: string;
  firstSequence: string;
  throughSequence: string;
  previousSegmentDigest: string | null;
  objectDigest: string;
  keyId: string;
  retentionUntil: string;
  admittedAt: string;
}
const projection = `segment_id::text as "segmentId",first_sequence::text as "firstSequence",
 through_sequence::text as "throughSequence",previous_segment_digest as "previousSegmentDigest",
 object_digest as "objectDigest",key_id as "keyId",
 to_char(retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "retentionUntil",
 to_char(admitted_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "admittedAt"`;
const values = (scope: EvidenceScope) => [
  scope.participantId,
  scope.privacyDomainId,
  scope.streamId,
];
const admission = (scope: EvidenceScope, row: SegmentRow) => ({
  ...scope,
  segmentId: row.segmentId,
  firstSequence: row.firstSequence,
  throughSequence: row.throughSequence,
  objectDigest: row.objectDigest,
  admittedAt: row.admittedAt,
  custody: 'CONTROL_POSTGRES' as const,
  sinkQuorum: 0 as const,
});

/**
 * Internal source-to-custody owner. Source adapters authenticate the original
 * receipt before calling admit; no public API accepts these internal arguments.
 * Remote availability never enters original business/runtime decision admission.
 */
export class EvidenceCustody {
  constructor(private readonly pool: Pool) {}

  private async transaction<T>(
    scopeValue: EvidenceScope,
    operation: (client: PoolClient, scope: EvidenceScope) => Promise<T>,
  ) {
    const scope = evidenceScope.parse(scopeValue);
    const client = await this.pool.connect();
    try {
      await client.query('begin');
      await client.query('set local synchronous_commit=on');
      await client.query('set local row_security=on');
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true),openpc.assert_request_context(true)`,
        [scope.participantId, scope.privacyDomainId, uuidv7()],
      );
      await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
      const result = await operation(client, scope);
      await client.query('commit');
      return result;
    } catch (error) {
      await client.query('rollback').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async admit(
    scope: EvidenceScope,
    records: readonly SourceReceipt[],
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
  ) {
    if (records.length < 1 || records.length > 128) throw new EvidenceCustodyError('INVALID');
    const result = await this.admitSource(
      scope,
      () => Promise.resolve(records),
      encryption,
      retentionUntil,
      capacityBytes,
    );
    if (result === null) throw new EvidenceCustodyError('INVALID');
    return result;
  }

  /** Select and authenticate committed receipts under the same stream lock as admission. */
  async ingestBusiness(
    scope: EvidenceScope,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
  ) {
    return this.admitSource(
      scope,
      readBusinessEvidenceSources,
      encryption,
      retentionUntil,
      capacityBytes,
    );
  }

  async ingestAuthentication(
    scope: EvidenceScope,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
  ) {
    return this.admitSource(
      scope,
      readAuthenticationEvidenceSources,
      encryption,
      retentionUntil,
      capacityBytes,
    );
  }

  async ingestFactFailure(
    scope: EvidenceScope,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
  ) {
    return this.admitSource(
      scope,
      readFactFailureEvidenceSources,
      encryption,
      retentionUntil,
      capacityBytes,
    );
  }

  /** Reconcile already archived sources without resubmitting business intent or
   * requiring expired acquisition authority. Original signatures still verify. */
  async reconcileEffectLineage(scope: EvidenceScope) {
    return this.transaction(scope, async (client, boundScope) => {
      const batch = await readEffectEvidenceBatch(client, boundScope, true);
      await retainDeploymentLineage(client, boundScope, batch);
      return batch.length;
    });
  }

  async ingestEffect(
    scope: EvidenceScope,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
  ) {
    await this.reconcileEffectLineage(scope);
    let batch: Awaited<ReturnType<typeof readEffectEvidenceBatch>> = [];
    return this.admitSource(
      scope,
      async (client, boundScope) => {
        batch = await readEffectEvidenceBatch(client, boundScope);
        const existing = await client.query<{ record_id: string }>(
          `select record_id from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=any($4::text[])`,
          [...values(boundScope), batch.map((entry) => entry.source.recordId)],
        );
        const ids = new Set(existing.rows.map((row) => row.record_id));
        return batch
          .filter((entry) => !ids.has(entry.source.recordId))
          .map((entry) => entry.source);
      },
      encryption,
      retentionUntil,
      capacityBytes,
      (client, boundScope) => retainDeploymentLineage(client, boundScope, batch),
    );
  }

  async ingestNotificationOutcomes(
    scope: EvidenceScope,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
  ) {
    return this.admitSource(
      scope,
      readNotificationOutcomeEvidenceSources,
      encryption,
      retentionUntil,
      capacityBytes,
    );
  }

  async ingestFact(
    scope: EvidenceScope,
    source: FactEvidenceSource,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
  ) {
    let batch: Awaited<ReturnType<typeof readFactEvidenceBatch>> = [];
    return this.admitSource(
      scope,
      async (client, boundScope) => {
        batch = await readFactEvidenceBatch(client, boundScope, source);
        return uncustodiedFactSources(client, boundScope, batch, encryption);
      },
      encryption,
      retentionUntil,
      capacityBytes,
      async (client, boundScope) => {
        await retainFactProvenance(client, boundScope, batch);
        await retainFactAdmissionDelivery(client, boundScope, batch);
      },
    );
  }

  async ingestRuntimeArtifact(
    scope: EvidenceScope,
    requestInput: unknown,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
    resolveKey: ArchiveKeyResolver,
  ) {
    const request = runtimeArtifactArchiveRequest.parse(requestInput);
    return this.transaction(scope, async (client, boundScope) => {
      if (
        request.participantId !== boundScope.participantId ||
        request.privacyDomainId !== boundScope.privacyDomainId
      )
        throw new EvidenceCustodyError('INTEGRITY');
      const existing = await client.query<{ manifest: unknown }>(
        `select manifest from control.evidence_runtime_artifact_archive where participant_id=$1 and privacy_domain_id=$2
          and runtime_configuration_input_id=$3 and stream_id=$4`,
        [
          scope.participantId,
          scope.privacyDomainId,
          request.runtimeConfigurationInputId,
          scope.streamId,
        ],
      );
      if (existing.rowCount) {
        // Reconcile the original committed archive without reading/repackaging
        // source plaintext or issuing another native materialization request.
        await verifyRuntimeArtifactArchiveReadback(
          client,
          boundScope,
          existing.rows[0]!.manifest,
          resolveKey,
        );
        return null;
      }
      const prepared = await readRuntimeArtifactArchiveSource(client, request, boundScope.streamId);
      let result = null;
      for (const group of prepared.groups) {
        result = await this.admitSourceTransaction(
          client,
          boundScope,
          () => Promise.resolve(group),
          encryption,
          retentionUntil,
          capacityBytes,
        );
      }
      if (
        !(await retainRuntimeArtifactArchive(
          client,
          boundScope,
          prepared.manifest,
          resolveKey,
          prepared.pendingOriginal,
        ))
      )
        throw new EvidenceCustodyError('INTEGRITY');
      return result;
    });
  }

  async ingestCandidate(
    scopeInput: EvidenceScope,
    sourceInput: CandidateArchiveSource,
    request: CandidateArchiveRequest,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
    resolveKey: CandidateArchiveKeyResolver,
  ) {
    const scope = evidenceScope.parse(scopeInput);
    const source = candidateArchiveSource.parse(sourceInput);
    if (
      source.participantId !== scope.participantId ||
      source.privacyDomainId !== scope.privacyDomainId
    )
      throw new EvidenceCustodyError('INTEGRITY');
    // Native read-only I/O completes before taking the custody lifecycle lock.
    // Each batch and its completion index use the existing atomic stream owner.
    const prepared = await readCandidateArchiveSource(source, request);
    return this.admitSource(
      scope,
      (client, boundScope) => nextCandidateArchiveRecords(client, boundScope, prepared, resolveKey),
      encryption,
      retentionUntil,
      capacityBytes,
      async (client, boundScope) => {
        await retainCandidateArchive(client, boundScope, prepared.manifest, resolveKey);
      },
    );
  }

  async ingestRpc(
    scope: EvidenceScope,
    source: RpcEvidenceSource,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
  ) {
    let batch: Awaited<ReturnType<typeof readRpcEvidenceBatch>> = [];
    return this.admitSource(
      scope,
      async (client, boundScope) => {
        batch = await readRpcEvidenceBatch(client, boundScope, source, true);
        const existing = await client.query<{ record_id: string }>(
          `select record_id from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=any($4::text[])`,
          [...values(boundScope), batch.map((entry) => entry.source.recordId)],
        );
        const ids = new Set(existing.rows.map((row) => row.record_id));
        return batch
          .filter((entry) => !ids.has(entry.source.recordId))
          .map((entry) => entry.source);
      },
      encryption,
      retentionUntil,
      capacityBytes,
      (client, boundScope) => retainRpcProjections(client, boundScope, batch),
    );
  }

  private async admitSource(
    scope: EvidenceScope,
    source: (client: PoolClient, scope: EvidenceScope) => Promise<readonly SourceReceipt[]>,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
    retainMetadata?: (client: PoolClient, scope: EvidenceScope) => Promise<void>,
  ) {
    return this.transaction(scope, (client, boundScope) =>
      this.admitSourceTransaction(
        client,
        boundScope,
        source,
        encryption,
        retentionUntil,
        capacityBytes,
        retainMetadata,
      ),
    );
  }

  private async admitSourceTransaction(
    client: PoolClient,
    scope: EvidenceScope,
    source: (client: PoolClient, scope: EvidenceScope) => Promise<readonly SourceReceipt[]>,
    encryption: EvidenceEncryptionKey,
    retentionUntil: string,
    capacityBytes: number,
    retainMetadata?: (client: PoolClient, scope: EvidenceScope) => Promise<void>,
  ) {
    if (!Number.isSafeInteger(capacityBytes) || capacityBytes < 1024 || capacityBytes > 1073741824)
      throw new EvidenceCustodyError('INVALID');
    await client.query(
      `insert into control.evidence_stream(participant_id,privacy_domain_id,stream_id,capacity_bytes)
       values($1,$2,$3,$4) on conflict do nothing`,
      [...values(scope), capacityBytes],
    );
    const selected = await client.query<{
      lastSequence: string;
      lastSegmentDigest: string | null;
      usedBytes: string;
      capacityBytes: string;
    }>(
      `select last_sequence::text as "lastSequence",last_segment_digest as "lastSegmentDigest",used_bytes::text as "usedBytes",capacity_bytes::text as "capacityBytes"
         from control.evidence_stream where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 for update`,
      values(scope),
    );
    const stream = selected.rows[0];
    if (!stream || stream.capacityBytes !== String(capacityBytes))
      throw new EvidenceCustodyError('CONFLICT');
    const records = await source(client, scope);
    if (records.length === 0) {
      await retainMetadata?.(client, scope);
      return null;
    }
    if (records.length > 128) throw new EvidenceCustodyError('INVALID');
    const retired = await client.query(
      `select 1 from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2
         and stream_id=$3 and data_class='SEARCH_PROJECTION' and record_id=any($4::text[]) limit 1`,
      [...values(scope), records.map((record) => record.recordId)],
    );
    if (retired.rowCount) throw new EvidenceCustodyError('CONFLICT');
    const existing = await client.query<{ segmentId: string }>(
      `select distinct segment_id::text as "segmentId" from control.evidence_catalogue
        where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=any($4::text[])`,
      [...values(scope), records.map((record) => record.recordId)],
    );
    if (existing.rowCount !== 0) {
      if (existing.rowCount !== 1) throw new EvidenceCustodyError('CONFLICT');
      const retained = await client.query<SegmentRow>(
        `select ${projection} from control.evidence_segment where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and segment_id=$4`,
        [...values(scope), existing.rows[0]!.segmentId],
      );
      const row = retained.rows[0];
      const catalogue = await client.query(
        `select record_id as "recordId",evidence_class as "evidenceClass",source_format as "sourceFormat",receipt_digest as "receiptDigest",
          to_char(occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt"
          from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and segment_id=$4 order by sequence`,
        [...values(scope), row?.segmentId],
      );
      const requested = records.map(({ receiptBase64, ...record }) => {
        if (sha256(Buffer.from(receiptBase64, 'base64')) !== record.receiptDigest)
          throw new EvidenceCustodyError('INTEGRITY');
        return record;
      });
      if (
        !row ||
        row.retentionUntil !== retentionUntil ||
        row.keyId !== encryption.keyId ||
        canonicalJson(catalogue.rows) !== canonicalJson(requested)
      )
        throw new EvidenceCustodyError('CONFLICT');
      const payload = await client.query(
        `select 1 from control.evidence_segment_payload
          where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and segment_id=$4`,
        [...values(scope), row.segmentId],
      );
      if (payload.rowCount !== 1) throw new EvidenceCustodyError('CONFLICT');
      await retainMetadata?.(client, scope);
      return admission(scope, row);
    }
    const header: SegmentHeader = {
      ...scope,
      version: 'OPENPC_EVIDENCE_SEGMENT_V1',
      segmentId: randomUUID(),
      firstSequence: String(BigInt(stream.lastSequence) + 1n),
      throughSequence: String(BigInt(stream.lastSequence) + BigInt(records.length)),
      previousSegmentDigest: stream.lastSegmentDigest,
      keyId: encryption.keyId,
      retentionUntil,
    };
    const sealed = sealSegment(header, records, encryption.key);
    if (BigInt(stream.usedBytes) + BigInt(sealed.bytes.length) > BigInt(capacityBytes))
      throw new EvidenceCustodyError('CAPACITY');
    const inserted = await client.query<SegmentRow>(
      `insert into control.evidence_segment(participant_id,privacy_domain_id,stream_id,segment_id,
        first_sequence,through_sequence,previous_segment_digest,object_digest,key_id,retention_until)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning ${projection}`,
      [
        ...values(scope),
        header.segmentId,
        header.firstSequence,
        header.throughSequence,
        header.previousSegmentDigest,
        sealed.objectDigest,
        header.keyId,
        retentionUntil,
      ],
    );
    await client.query(
      `insert into control.evidence_segment_payload(participant_id,privacy_domain_id,stream_id,segment_id,encrypted_segment)
         values($1,$2,$3,$4,$5)`,
      [...values(scope), header.segmentId, sealed.bytes],
    );
    for (let index = 0; index < records.length; index += 1) {
      const record = records[index]!;
      await client.query(
        `insert into control.evidence_catalogue(participant_id,privacy_domain_id,stream_id,record_id,segment_id,sequence,evidence_class,source_format,receipt_digest,occurred_at)
          values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          ...values(scope),
          record.recordId,
          header.segmentId,
          String(BigInt(header.firstSequence) + BigInt(index)),
          record.evidenceClass,
          record.sourceFormat,
          record.receiptDigest,
          record.occurredAt,
        ],
      );
    }
    await client.query(
      `update control.evidence_stream set last_sequence=$4,last_segment_digest=$5,used_bytes=used_bytes+$6
        where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
      [...values(scope), header.throughSequence, sealed.objectDigest, sealed.bytes.length],
    );
    await retainMetadata?.(client, scope);
    return admission(scope, inserted.rows[0]!);
  }

  /** Sink acknowledgement is obtained here; callers cannot submit it as input. */
  async exportNext(scope: EvidenceScope, sink: LocalEvidenceVault) {
    return this.transaction(scope, async (client, scope) => {
      const stream = await client.query(
        `select 1 from control.evidence_stream where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 for update`,
        values(scope),
      );
      if (stream.rowCount !== 1) throw new EvidenceCustodyError('UNAVAILABLE');
      const last = await client.query<{ throughSequence: string; checkpointDigest: string }>(
        `select through_sequence::text as "throughSequence",checkpoint_digest as "checkpointDigest" from control.evidence_checkpoint
        where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and sink_id=$4 order by through_sequence desc limit 1`,
        [...values(scope), sink.sinkId],
      );
      const previous = last.rows[0];
      const next = await client.query<SegmentRow>(
        `select ${projection} from control.evidence_segment where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and first_sequence=$4`,
        [...values(scope), String(BigInt(previous?.throughSequence ?? '0') + 1n)],
      );
      const row = next.rows[0];
      if (!row) return null;
      const identity = vaultObject(
        sink.sinkId,
        { ...scope, ...row, version: 'OPENPC_EVIDENCE_SEGMENT_V1' },
        row.objectDigest,
      );
      const payload = await client.query<{ encryptedSegment: Buffer }>(
        `select encrypted_segment as "encryptedSegment" from control.evidence_segment_payload
         where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and segment_id=$4`,
        [...values(scope), row.segmentId],
      );
      if (payload.rowCount !== 1) throw new EvidenceCustodyError('UNAVAILABLE');
      const verified = await sink.put(identity, payload.rows[0]!.encryptedSegment);
      // Commit bounded hold progress while withholding the checkpoint until all rules are covered.
      if (!(await coverObjectHolds(client, identity, sink))) return null;
      const checkpoint = {
        ...scope,
        sinkId: sink.sinkId,
        segmentId: row.segmentId,
        throughSequence: row.throughSequence,
        objectDigest: row.objectDigest,
        previousCheckpointDigest: previous?.checkpointDigest ?? null,
        receiptDigest: verified.receiptDigest,
      };
      const checkpointDigest = sha256(checkpoint);
      await client.query(
        `insert into control.evidence_checkpoint(participant_id,privacy_domain_id,stream_id,sink_id,through_sequence,segment_id,object_digest,previous_checkpoint_digest,receipt,receipt_digest,checkpoint_digest)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)`,
        [
          ...values(scope),
          sink.sinkId,
          row.throughSequence,
          row.segmentId,
          row.objectDigest,
          checkpoint.previousCheckpointDigest,
          JSON.stringify(verified),
          verified.receiptDigest,
          checkpointDigest,
        ],
      );
      return { ...checkpoint, checkpointDigest, assurance: verified.assurance };
    });
  }

  async reconcileHolds(scope: EvidenceScope, sink: LocalEvidenceVault) {
    return this.transaction(scope, async (client, scope) => {
      const objects = await pendingHoldObjects(client, scope, sink.sinkId);
      for (const object of objects) await coverObjectHolds(client, object, sink);
      return objects.length;
    });
  }
}
