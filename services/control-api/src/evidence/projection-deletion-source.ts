import type { PoolClient } from 'pg';
import type { z } from 'zod';
import { projectionDeletionSelection } from './projection-deletion-contracts.js';
import { readRpcProvenance } from './rpc-provenance.js';
import { verifyAuthenticationSource } from './authentication-source.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { rpcProjectionClosedBy } from './rpc-retirement.js';
import { rpcRetirementWitness } from './projection-deletion-contracts.js';
import { acquireFactRetirementFence } from './fact-retirement.js';
import { readDeploymentProvenance } from './deployment-provenance.js';
import { verifyRetiredRpcCatalogueSource } from './rpc-search-retirement.js';
import { readBusinessProvenance } from './receipt-provenance.js';

/** The original producer's independent verification still precedes deletion.
 * SQL additionally fences exact current rows at the physical effect boundary. */
export async function verifyProjectionDeletionSource(
  client: PoolClient,
  selection: z.infer<typeof projectionDeletionSelection>,
) {
  if (selection.sourceKind === 'FACT_PROVENANCE') {
    const fence = await acquireFactRetirementFence(client, selection);
    try {
      await fence.revalidate();
    } finally {
      await fence.release();
    }
    return;
  }
  const participantId = selection.participantId.slice(-36),
    privacyDomainId = selection.privacyDomainId;
  const rows = await client.query<{
    recordId: string;
    recordDigest: string;
    occurredAt: string;
    sourceFormat: string;
  }>(
    `select record_id as "recordId",receipt_digest as "recordDigest",source_format as "sourceFormat",to_char(occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt"
     from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and evidence_id=$3 and stream_id=$4`,
    [participantId, privacyDomainId, selection.evidenceId.slice(-36), selection.streamId],
  );
  const source = rows.rows[0];
  if (
    rows.rowCount !== 1 ||
    !source ||
    source.recordId !== selection.recordId ||
    source.recordDigest !== selection.sourceReceiptDigest
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  if (selection.dataClass === 'NORMALIZED_JSON_PROJECTION') {
    if (selection.sourceKind === 'DEPLOYMENT_PROVENANCE') {
      const deployment = await readDeploymentProvenance(client, {
        ...source,
        participantId,
        privacyDomainId,
        streamId: selection.streamId,
      });
      if (!deployment) throw new ConfigurationRepositoryError('PC-DATA-6007');
      return;
    }
    const rpc = await readRpcProvenance(client, {
      ...source,
      participantId,
      privacyDomainId,
      streamId: selection.streamId,
    });
    if (!rpc) throw new ConfigurationRepositoryError('PC-DATA-6007');
    if (selection.sourceKind === 'RPC_PRE_ADMISSION_DENIAL') {
      if (rpc.transition.phase !== 'PRE_ADMISSION_DENIAL')
        throw new ConfigurationRepositoryError('PC-DATA-6007');
    } else {
      if (!selection.rpcClosure) throw new ConfigurationRepositoryError('PC-DATA-6007');
      const { archive, ...closure } = selection.rpcClosure;
      const witness = rpcRetirementWitness.parse(closure);
      if (!rpcProjectionClosedBy(rpc, witness))
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      const terminal = await client.query<{
        recordId: string;
        recordDigest: string;
        occurredAt: string;
      }>(
        `select record_id as "recordId",receipt_digest as "recordDigest",to_char(occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt"
         from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and evidence_id=$3 and stream_id=$4
          and record_id=$5 and receipt_digest=$6 and sequence=$7 and segment_id=$8
          and exists(select 1 from control.evidence_segment s where s.participant_id=$1 and s.privacy_domain_id=$2
           and s.stream_id=$4 and s.segment_id=$8 and s.object_digest=$9)`,
        [
          participantId,
          privacyDomainId,
          witness.terminalEvidenceId.slice(-36),
          selection.streamId,
          witness.terminalRecordId,
          witness.terminalSourceDigest,
          witness.terminalSequence,
          archive.segmentId,
          archive.objectDigest,
        ],
      );
      if (terminal.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      const retained = await readRpcProvenance(client, {
        ...terminal.rows[0]!,
        participantId,
        privacyDomainId,
        streamId: selection.streamId,
      });
      if (retained) {
        if (!rpcProjectionClosedBy(retained, witness))
          throw new ConfigurationRepositoryError('PC-DATA-6007');
      } else {
        const retired = await client.query(
          `select 1 from control.evidence_projection_retirement r join control.deletion_job j using(participant_id,privacy_domain_id,deletion_job_id)
           where r.participant_id=$1 and r.privacy_domain_id=$2 and r.stream_id=$3 and r.record_id=$4
            and r.data_class='NORMALIZED_JSON_PROJECTION' and j.state='SUCCEEDED'
            and r.retirement_digest=openpc.projection_retirement_digest(r) and r.projection_digest=$5 and r.source_receipt_digest=$6
            and (j.selection->'rpcClosure')-'archive'=$7::jsonb`,
          [
            participantId,
            privacyDomainId,
            selection.streamId,
            witness.terminalRecordId,
            witness.terminalProjectionDigest,
            witness.terminalSourceDigest,
            witness,
          ],
        );
        if (retired.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      }
    }
  } else if (selection.sourceKind === 'RPC_RETIRED_CATALOGUE') {
    await verifyRetiredRpcCatalogueSource(client, {
      ...source,
      participantId,
      privacyDomainId,
      streamId: selection.streamId,
    });
  } else if (selection.sourceKind === 'RETENTION_POLICY_CATALOGUE') {
    const business = await readBusinessProvenance(
      client,
      {
        ...source,
        participantId,
        privacyDomainId,
      },
      source.sourceFormat,
    );
    if (
      business.aggregateType !== 'retention-policy' ||
      business.profileVersion !== '1' ||
      !['pc.control.retention-policy.activate', 'pc.control.retention-policy.retire'].includes(
        business.profileId,
      )
    )
      throw new ConfigurationRepositoryError('PC-DATA-6007');
  } else {
    const original = await client.query<{ id: string; receipt: Buffer; receiptDigest: Buffer }>(
      `select occurrence_id::text id,receipt,receipt_digest as "receiptDigest" from control.authentication_occurrence
       where participant_id=$1 and privacy_domain_id=$2 and occurrence_id::text=$3`,
      [participantId, privacyDomainId, source.recordId],
    );
    if (original.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
    const proof = verifyAuthenticationSource(original.rows[0]!, { participantId, privacyDomainId });
    if (
      proof.occurredAt !== source.occurredAt ||
      `sha256:${original.rows[0]!.receiptDigest.toString('hex')}` !== source.recordDigest
    )
      throw new ConfigurationRepositoryError('PC-DATA-6007');
  }
}
