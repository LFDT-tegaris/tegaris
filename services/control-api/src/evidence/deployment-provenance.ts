import type { PoolClient } from 'pg';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import { selectDeploymentResultSource } from '../configuration/deployment/result-source.js';
import { verifyDeploymentResult } from '../configuration/deployment/result-verification.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { effectOccurrenceTime } from './effect-source.js';
import { deploymentProvenanceProjection, type EvidenceProvenance } from './provenance-contracts.js';
import { sequence } from './segment.js';

type Verified = ReturnType<typeof verifyDeploymentResult>;
type Deployment = NonNullable<EvidenceProvenance['deployment']>;
const hash = (value: unknown) =>
  `sha256:${z
    .string()
    .regex(/^[0-9a-f]{64}$/u)
    .parse(value)}`;
const fail = () => new ConfigurationRepositoryError('PC-DATA-6007');

/** Called only after the original purpose verifier has authenticated the complete
 * owner-defined outcome. Select fields rather than returning its generic maps. */
export function deploymentObservation(value: Verified): Deployment['historical'] {
  const occurrence = value.outcome.occurrence;
  const invalidation = value.outcome.invalidation;
  return {
    sourceVersion: value.sequence,
    receiptDigest: hash(value.resultDigest),
    observedAt: value.observedAt,
    state: value.status.state as Deployment['historical']['state'],
    truthState: value.status.truthState as Deployment['historical']['truthState'],
    journalEvidenceDigest: value.status.evidenceDigest,
    finality: invalidation
      ? invalidation.reason === 'REORG'
        ? 'REORG'
        : 'INVALIDATED'
      : occurrence
        ? 'FINALIZED'
        : 'NOT_ESTABLISHED',
    occurrence: occurrence
      ? {
          occurrenceId: z.string().parse(occurrence.occurrenceId),
          occurrenceDigest: hash(occurrence.semanticDigest),
          blockHash: hash(occurrence.blockHash),
          blockNumber: sequence.parse(occurrence.blockNumber),
          reorgStatus: z.literal('CANONICAL').parse(occurrence.reorgStatus),
        }
      : null,
    invalidation: invalidation
      ? {
          occurrenceId: z.string().parse(invalidation.occurrenceId),
          occurrenceDigest: hash(invalidation.occurrenceDigest),
          observationDigest: hash(invalidation.observationDigest),
          reason: z.enum(['REORG', 'CODE_IDENTITY_MISMATCH']).parse(invalidation.reason),
        }
      : null,
  };
}

export function retainedObservationHistory(
  first: string,
  last: string,
  count: string,
): Deployment['history'] {
  for (const value of [first, last, count]) sequence.parse(value);
  const span = BigInt(last) - BigInt(first) + 1n;
  if (BigInt(first) < 1n || BigInt(count) < 1n || span < BigInt(count)) throw fail();
  return {
    coverage: 'RETAINED_SNAPSHOTS_ONLY',
    firstVersion: first,
    lastVersion: last,
    retainedCount: count,
    missingVersionsBetweenSnapshots: String(span - BigInt(count)),
    journalCompleteness: 'NOT_ESTABLISHED',
  };
}

export interface ProvenanceSource {
  participantId: string;
  privacyDomainId: string;
  recordId: string;
  recordDigest: string;
  occurredAt: string;
}
export async function readDeploymentProvenance(
  client: Pick<PoolClient, 'query'>,
  record: ProvenanceSource & { streamId: string },
): Promise<Deployment | null> {
  const identity = /^deployment:([0-9a-f-]{36}):([1-9][0-9]*)$/u.exec(record.recordId);
  if (!identity) throw fail();
  const command = z.uuidv7().parse(identity[1]);
  const version = sequence.parse(identity[2]);
  const values = [command, record.participantId, record.privacyDomainId];
  const selected = await selectDeploymentResultSource(
    client,
    command,
    record.participantId,
    record.privacyDomainId,
  );
  const binding = selected.rows[0];
  if (selected.rowCount !== 1 || !binding || !binding.signed_bytes) throw fail();
  const original = await client.query<{
    sequence: string;
    signed_bytes: Buffer;
    result_digest: string;
  }>(
    `select sequence::text,signed_bytes,result_digest from control.deployment_result
     where command_id=$1 and participant_id=$2 and privacy_domain_id=$3 and sequence=$4`,
    [...values, version],
  );
  const row = original.rows[0];
  if (
    original.rowCount !== 1 ||
    !row ||
    row.result_digest !== record.recordDigest ||
    sha256(row.signed_bytes) !== record.recordDigest
  )
    throw fail();
  const historical = verifyDeploymentResult(
    { ...binding, ...row },
    command,
    record.participantId,
    record.privacyDomainId,
    false,
  );
  if (
    historical.identity !== 'PC-DEPLOYMENT-JOURNAL-PROJECTION-1' ||
    effectOccurrenceTime(historical.observedAt) !== record.occurredAt
  )
    throw fail();
  const latest =
    binding.sequence === version
      ? historical
      : verifyDeploymentResult(
          binding,
          command,
          record.participantId,
          record.privacyDomainId,
          false,
        );
  if (sha256(binding.signed_bytes) !== `sha256:${latest.resultDigest}`) throw fail();
  const history = await client.query<{ first: string; last: string; count: string }>(
    `select min(sequence)::text first,max(sequence)::text last,count(*)::text count
     from control.deployment_result where command_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
    values,
  );
  const bounds = history.rows[0];
  if (!bounds || bounds.last !== latest.sequence) throw fail();
  const projection = deploymentProvenanceProjection.parse({
    integrity: 'VERIFIED_PURPOSE_SIGNATURE',
    authority: 'OBSERVATION_ONLY',
    operationId: historical.status.operationId,
    attemptId: binding.attempt_id,
    deploymentIntentId: `urn:openpc:resource:${binding.deployment_intent_id}`,
    targetRuntimeId: `urn:openpc:resource:${binding.target_runtime_id}`,
    executionPrincipalId: binding.execution_principal_id,
    workloadId: binding.execution_workload_id,
    intentDigest: hash(binding.intent_digest),
    preparationDigest: hash(binding.preparation_digest),
    chainId: binding.chain_id,
    genesisDigest: hash(binding.genesis_digest),
    transactionHash: binding.transaction_hash,
    historical: deploymentObservation(historical),
  });
  const stored = await client.query<{ projection: unknown; projection_digest: string }>(
    `select projection,projection_digest from control.evidence_deployment_provenance
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4`,
    [record.participantId, record.privacyDomainId, record.streamId, record.recordId],
  );
  if (stored.rowCount === 0) return null;
  const retained = stored.rows[0];
  if (
    stored.rowCount !== 1 ||
    !retained ||
    retained.projection_digest !== sha256(projection) ||
    sha256(deploymentProvenanceProjection.parse(retained.projection)) !== sha256(projection)
  )
    throw fail();
  return {
    ...projection,
    latestRetained: deploymentObservation(latest),
    historicalIsLatest: version === latest.sequence,
    currentChainTruth: 'NOT_QUERIED',
    history: retainedObservationHistory(bounds.first, bounds.last, bounds.count),
  };
}
