import type { PoolClient } from 'pg';
import {
  readAuthenticationProvenance,
  readBusinessProvenance,
  readRejectionProvenance,
} from './receipt-provenance.js';
import { readRpcProvenance } from './rpc-provenance.js';
import { readFactProvenance } from './fact-provenance.js';
import { sha256 } from '../configuration/digest.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { readDeploymentProvenance, type ProvenanceSource } from './deployment-provenance.js';
import { sinkDurabilityReceipt } from './local-vault.js';
import { evidenceProvenanceView, type EvidenceProvenance } from './provenance-contracts.js';

interface RecordRow extends ProvenanceSource {
  evidenceId: string;
  evidenceClass: EvidenceProvenance['evidenceClass'];
  sourceFormat: string;
  streamId: string;
  sequence: string;
  segmentId: string;
}
interface CheckpointRow {
  sinkId: string;
  throughSequence: string;
  objectDigest: string;
  previousCheckpointDigest: string | null;
  receipt: unknown;
  receiptDigest: string;
  checkpointDigest: string;
  acknowledgedAt: string;
}
const fail = () => new ConfigurationRepositoryError('PC-DATA-6007');

/** Authenticate recorded metadata; do not read archive bytes or turn a past
 * fsync acknowledgement into a current availability, WORM or deletion claim. */
export function recordedCheckpoint(
  record: RecordRow,
  row: CheckpointRow,
): EvidenceProvenance['custody']['checkpoints'][number] {
  const receipt = sinkDurabilityReceipt.parse(row.receipt);
  const { receiptDigest, ...body } = receipt;
  const object = receipt.object;
  const checkpoint = {
    participantId: record.participantId,
    privacyDomainId: record.privacyDomainId,
    streamId: record.streamId,
    sinkId: row.sinkId,
    segmentId: record.segmentId,
    throughSequence: row.throughSequence,
    objectDigest: row.objectDigest,
    previousCheckpointDigest: row.previousCheckpointDigest,
    receiptDigest: row.receiptDigest,
  };
  if (
    object.participantId !== record.participantId ||
    object.privacyDomainId !== record.privacyDomainId ||
    object.streamId !== record.streamId ||
    object.segmentId !== record.segmentId ||
    object.sinkId !== row.sinkId ||
    object.objectDigest !== row.objectDigest ||
    object.throughSequence !== row.throughSequence ||
    receipt.versionId !== row.objectDigest ||
    BigInt(object.firstSequence) < 1n ||
    BigInt(record.sequence) < BigInt(object.firstSequence) ||
    BigInt(record.sequence) > BigInt(object.throughSequence) ||
    (object.firstSequence === '1') !== (row.previousCheckpointDigest === null) ||
    (object.firstSequence === '1') !== (object.previousSegmentDigest === null) ||
    receiptDigest !== row.receiptDigest ||
    sha256(body) !== receiptDigest ||
    sha256(checkpoint) !== row.checkpointDigest
  )
    throw fail();
  return {
    sinkId: row.sinkId,
    throughSequence: row.throughSequence,
    objectDigest: row.objectDigest,
    versionId: receipt.versionId,
    receiptDigest,
    checkpointDigest: row.checkpointDigest,
    previousCheckpointDigest: row.previousCheckpointDigest,
    assurance: receipt.assurance,
    acknowledgedAt: row.acknowledgedAt,
  };
}

export async function readEvidenceProvenance(
  client: PoolClient,
  evidenceId: string,
  participantId: string,
  privacyDomainId: string,
) {
  const selected = await client.query<RecordRow>(
    `select evidence_id::text as "evidenceId",participant_id::text as "participantId",
     privacy_domain_id::text as "privacyDomainId",record_id as "recordId",receipt_digest as "recordDigest",
     evidence_class as "evidenceClass",source_format as "sourceFormat",stream_id as "streamId",
     sequence::text,segment_id::text as "segmentId",
     to_char(occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt"
     from control.evidence_catalogue where evidence_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
    [evidenceId, participantId, privacyDomainId],
  );
  const record = selected.rows[0];
  if (selected.rowCount !== 1 || !record)
    throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
  const rows = await client.query<CheckpointRow>(
    `select sink_id as "sinkId",through_sequence::text as "throughSequence",object_digest as "objectDigest",
     previous_checkpoint_digest as "previousCheckpointDigest",receipt,receipt_digest as "receiptDigest",
     checkpoint_digest as "checkpointDigest",
     to_char(acknowledged_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "acknowledgedAt"
     from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3
      and segment_id=$4 order by sink_id limit 17`,
    [participantId, privacyDomainId, record.streamId, record.segmentId],
  );
  if (rows.rows.length > 16) throw fail();
  const checkpoints = rows.rows.map((row) => recordedCheckpoint(record, row));
  let status: EvidenceProvenance['status'] = 'SOURCE_NOT_SUPPORTED';
  let deployment = null,
    authentication = null,
    business = null,
    rejection = null,
    rpc = null,
    fact = null;
  switch (record.sourceFormat) {
    case 'OPENPC_CANONICAL_FACT_V1':
      if (record.evidenceClass !== 'EFFECT') throw fail();
      fact = await readFactProvenance(client, record);
      status = fact
        ? 'VERIFIED_FACT_CUSTODY_PROJECTION'
        : await retiredProjectionStatus(client, record);
      break;
    case 'PC-DEPLOYMENT-JOURNAL-PROJECTION-1':
      if (record.evidenceClass !== 'EFFECT') throw fail();
      deployment = await readDeploymentProvenance(client, record);
      status = deployment
        ? 'VERIFIED_DEPLOYMENT_OBSERVATION'
        : await retiredProjectionStatus(client, record);
      break;
    case 'OPENPC_AUTHENTICATION_OCCURRENCE_V1':
      if (record.evidenceClass !== 'AUTHENTICATION') throw fail();
      authentication = await readAuthenticationProvenance(client, record);
      status = 'VERIFIED_AUTHENTICATION_OCCURRENCE';
      break;
    case 'COSE_SIGN1_24001_1_338':
    case 'COSE_SIGN1_24001_2_338':
      if (record.evidenceClass !== 'BUSINESS_TRANSITION') throw fail();
      business = await readBusinessProvenance(client, record, record.sourceFormat);
      status = 'VERIFIED_BUSINESS_TRANSITION';
      break;
    case 'PC-DEPLOYMENT-RESERVATION-REJECTION-1':
      if (record.evidenceClass !== 'EFFECT') throw fail();
      rejection = await readRejectionProvenance(client, record);
      status = 'VERIFIED_TERMINAL_REJECTION';
      break;
    case 'OPENPC_RPC_DECISION_TRANSITION_V1':
      if (record.evidenceClass !== 'EFFECT') throw fail();
      rpc = await readRpcProvenance(client, record);
      if (rpc) status = 'VERIFIED_RPC_CUSTODY_PROJECTION';
      else status = await retiredProjectionStatus(client, record);
      break;
  }
  return evidenceProvenanceView.parse({
    evidenceId: `urn:openpc:resource:${record.evidenceId}`,
    participantId: `urn:openpc:participant:${participantId}`,
    privacyDomainId,
    evidenceClass: record.evidenceClass,
    recordId: record.recordId,
    recordDigest: record.recordDigest,
    sourceFormat: record.sourceFormat,
    status,
    deployment,
    authentication,
    business,
    rejection,
    rpc,
    fact,
    custody: {
      streamId: record.streamId,
      sequence: record.sequence,
      segmentId: record.segmentId,
      checkpoints,
      checkpointState: checkpoints.length ? 'RECORDED' : 'NONE_RECORDED',
      archiveAvailability: 'NOT_RECHECKED',
    },
  });
}

async function retiredProjectionStatus(
  client: PoolClient,
  record: RecordRow,
): Promise<EvidenceProvenance['status']> {
  const retired = await client.query(
    `select 1 from control.evidence_projection_retirement r join control.deletion_job j using(participant_id,privacy_domain_id,deletion_job_id)
     where r.participant_id=$1 and r.privacy_domain_id=$2 and r.evidence_id=$3 and r.data_class='NORMALIZED_JSON_PROJECTION'
      and j.state='SUCCEEDED' and r.source_receipt_digest=$4 and r.stream_id=$5 and r.record_id=$6
      and r.retirement_digest=openpc.projection_retirement_digest(r)`,
    [
      record.participantId,
      record.privacyDomainId,
      record.evidenceId,
      record.recordDigest,
      record.streamId,
      record.recordId,
    ],
  );
  return retired.rowCount === 1 ? 'PROJECTION_RETIRED' : 'SOURCE_RECONCILIATION_REQUIRED';
}
