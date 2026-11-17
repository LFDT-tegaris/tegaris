import type { PoolClient } from 'pg';
import { sha256 } from '../configuration/digest.js';
import type { ProvenanceSource } from './deployment-provenance.js';
import { rpcProvenance, type RpcProvenance } from './rpc-provenance-contract.js';
import { EvidenceCustodyError, type EvidenceScope, type SourceReceipt } from './segment.js';

const fail = () => new EvidenceCustodyError('INTEGRITY');
export function verifyRpcProjection(
  record: ProvenanceSource,
  value: unknown,
  projectionDigest: string,
) {
  const parsed = rpcProvenance.parse(value);
  const ns = BigInt(parsed.occurredAtNs);
  const occurredAt = `${new Date(Number(ns / 1000000n)).toISOString().slice(0, 19)}.${String((ns % 1000000000n) / 1000n).padStart(6, '0')}Z`;
  if (
    sha256(parsed) !== projectionDigest ||
    parsed.sourceDigest !== record.recordDigest ||
    occurredAt !== record.occurredAt ||
    record.recordId !==
      `rpc:${sha256([parsed.targetRuntimeId, parsed.spoolId]).slice(7)}:${parsed.sourceSequence}`
  )
    throw fail();
  return parsed;
}

async function verifyActivationBinding(
  client: PoolClient,
  scope: Pick<EvidenceScope, 'participantId' | 'privacyDomainId'>,
  projection: RpcProvenance,
) {
  const binding = projection.activation;
  const result = await client.query(
    `select 1 from control.runtime_activation_observation o join control.configuration_work w
     on w.configuration_work_id=o.configuration_work_id and w.participant_id=o.participant_id
      and w.privacy_domain_id=o.privacy_domain_id and w.runtime_target_id=o.runtime_target_id
      and w.runtime_configuration_generation_id=o.runtime_configuration_generation_id
      and w.operation_id=o.operation_id and w.execution_attempt_id=o.execution_attempt_id
      and w.generation_digest=o.generation_digest and w.state='COMPLETED'
     where o.participant_id=$1 and o.privacy_domain_id=$2 and o.runtime_target_id=$3
      and o.capsule_digest=$4 and o.operation_id=$5 and o.execution_attempt_id=$6
      and o.configuration_work_id=$7 and o.runtime_configuration_generation_id=$8 and o.generation_digest=$9
      and 'sha256:'||encode(sha256(decode(o.activation_receipt->>'activationReceiptCoseHex','hex')),'hex')=$10`,
    [
      scope.participantId,
      scope.privacyDomainId,
      projection.targetRuntimeId,
      projection.capsuleDigest,
      binding.operationId,
      binding.attemptId,
      binding.configurationWorkId,
      binding.generationId,
      binding.generationDigest,
      binding.receiptDigest,
    ],
  );
  if (result.rowCount !== 1) throw fail();
}

export async function retainRpcProjections(
  client: PoolClient,
  scope: EvidenceScope,
  records: readonly { source: SourceReceipt; provenance: RpcProvenance }[],
) {
  for (const entry of records) {
    const identity = [
      scope.participantId,
      scope.privacyDomainId,
      scope.streamId,
      entry.source.recordId,
    ];
    const source = await client.query<{
      receipt_digest: string;
      occurred_at: string;
      source_format: string;
      sequence: string;
    }>(
      `select receipt_digest,to_char(occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') occurred_at,
       source_format,sequence::text from control.evidence_catalogue
       where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4`,
      identity,
    );
    const row = source.rows[0];
    if (
      source.rowCount !== 1 ||
      !row ||
      row.source_format !== entry.source.sourceFormat ||
      row.sequence !== entry.provenance.sourceSequence
    )
      throw fail();
    const digest = sha256(entry.provenance);
    verifyRpcProjection(
      {
        ...scope,
        recordId: entry.source.recordId,
        recordDigest: row.receipt_digest,
        occurredAt: row.occurred_at,
      },
      entry.provenance,
      digest,
    );
    await verifyActivationBinding(client, scope, entry.provenance);
    const retirement = await client.query<{ projection_digest: string }>(
      `select projection_digest from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2
       and stream_id=$3 and record_id=$4 and data_class='NORMALIZED_JSON_PROJECTION'`,
      identity,
    );
    if (retirement.rowCount) {
      if (retirement.rowCount !== 1 || retirement.rows[0]!.projection_digest !== digest)
        throw fail();
      continue;
    }
    await client.query(
      `insert into control.evidence_rpc_provenance(participant_id,privacy_domain_id,stream_id,record_id,projection,projection_digest)
       values($1,$2,$3,$4,$5,$6) on conflict do nothing`,
      [...identity, entry.provenance, digest],
    );
    const retained = await client.query<{ projection: unknown; projection_digest: string }>(
      `select projection,projection_digest from control.evidence_rpc_provenance where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4`,
      identity,
    );
    if (
      retained.rowCount !== 1 ||
      retained.rows[0]!.projection_digest !== digest ||
      sha256(retained.rows[0]!.projection) !== digest
    )
      throw fail();
  }
}

export async function readRpcProvenance(
  client: PoolClient,
  record: ProvenanceSource & { streamId: string },
): Promise<RpcProvenance | null> {
  const selected = await client.query<{ projection: unknown; projection_digest: string }>(
    `select projection,projection_digest from control.evidence_rpc_provenance where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4`,
    [record.participantId, record.privacyDomainId, record.streamId, record.recordId],
  );
  // Historical sources are reconciled by their original key-owning worker.
  // Absence is not a successful verification or permission to decrypt here.
  if (selected.rowCount === 0) return null;
  if (selected.rowCount !== 1) throw fail();
  const row = selected.rows[0]!;
  const projection = verifyRpcProjection(record, row.projection, row.projection_digest);
  await verifyActivationBinding(client, record, projection);
  return projection;
}
