import type { PoolClient } from 'pg';
import { z } from 'zod';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { businessOccurrenceTime } from './business-source.js';
import { evidenceDeletionRpcRetirement } from './deletion-contracts.js';
import { readBusinessProvenance } from './receipt-provenance.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const proofIdentity = z.strictObject({
  recordId: z.uuidv7(),
  recordDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  recordedAtNs: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  sourceFormat: z.string(),
  deletionJobId: z.uuidv7(),
  operationId: z.uuidv7(),
  sourceEvidenceId: evidenceDeletionRpcRetirement.shape.evidenceId,
  sourceRecordId: evidenceDeletionRpcRetirement.shape.recordId,
  sourceReceiptDigest: evidenceDeletionRpcRetirement.shape.sourceReceiptDigest,
  retirementDigest: evidenceDeletionRpcRetirement.shape.retirementDigest,
});
/** Shape of the SQL owner's historical proof, never stand-alone authority. A
 * pre-admission denial must not borrow a request's terminal-closure witness. */
export const rpcCatalogueRetirementProof = z.discriminatedUnion('sourceKind', [
  proofIdentity.extend({ sourceKind: z.literal('RPC_CLOSED_TRANSITION'), identityDigest: digest }),
  proofIdentity.extend({
    sourceKind: z.literal('RPC_PRE_ADMISSION_DENIAL'),
    identityDigest: z.null(),
  }),
]);

/** Verify the historical COSE, typed committed state and outbox through their
 * actual owner. The SQL proof also binds the physical retirement and original
 * source; neither a tombstone nor a source digest alone is sufficient. */
export async function verifyRetiredRpcCatalogueSource(
  client: PoolClient,
  source: {
    participantId: string;
    privacyDomainId: string;
    streamId: string;
    recordId: string;
    recordDigest: string;
  },
) {
  const selected = await client.query<{ proof: unknown }>(
    `select openpc.rpc_retired_catalogue_proof(c) proof from control.evidence_catalogue c
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4 and receipt_digest=$5`,
    [
      source.participantId,
      source.privacyDomainId,
      source.streamId,
      source.recordId,
      source.recordDigest,
    ],
  );
  const parsed = rpcCatalogueRetirementProof.safeParse(selected.rows[0]?.proof);
  if (selected.rowCount !== 1 || !parsed.success)
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const proof = parsed.data;
  const receipt = await readBusinessProvenance(
    client,
    { ...source, ...proof, occurredAt: businessOccurrenceTime(BigInt(proof.recordedAtNs)) },
    proof.sourceFormat,
  );
  if (
    receipt.aggregateType !== 'evidence-deletion' ||
    receipt.aggregateId !== proof.deletionJobId ||
    receipt.operationId !== `urn:openpc:operation:${proof.operationId}` ||
    receipt.profileId !== 'pc.control.evidence-deletion.projection' ||
    receipt.profileVersion !== '1' ||
    receipt.actionIntentId !== 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1' ||
    receipt.catalogOperationId !== 'CFG-OP-DELETE-PROJECTION-BATCH'
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  return evidenceDeletionRpcRetirement.parse({
    evidenceId: proof.sourceEvidenceId,
    recordId: proof.sourceRecordId,
    sourceReceiptDigest: proof.sourceReceiptDigest,
    retirementJobId: `urn:openpc:resource:${proof.deletionJobId}`,
    retirementReceiptDigest: proof.recordDigest,
    retirementDigest: proof.retirementDigest,
  });
}
