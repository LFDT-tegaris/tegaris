import type { PoolClient } from 'pg';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import type { DeploymentResultSource } from '../configuration/deployment/result-source.js';
import type { verifyDeploymentResult } from '../configuration/deployment/result-verification.js';
import { deploymentObservation } from './deployment-provenance.js';
import { retainDeploymentProjection } from './deployment-projection.js';
import { evidenceProvenanceView } from './provenance-contracts.js';
import { EvidenceCustodyError, type EvidenceScope, type SourceReceipt } from './segment.js';

const deployment = evidenceProvenanceView.shape.deployment.unwrap();
export const deploymentHoldLineage = z.strictObject({
  chainId: deployment.shape.chainId,
  genesisDigest: deployment.shape.genesisDigest,
  historical: deployment.shape.historical,
});
export type DeploymentHoldLineage = z.infer<typeof deploymentHoldLineage>;

/** The caller first verifies the original purpose signature and preparation.
 * Preserve the historical anchor even after freshness, association or reorg
 * changes. This projection grants neither readiness nor deletion authority. */
export function deploymentLineage(
  verified: ReturnType<typeof verifyDeploymentResult>,
  source: Pick<DeploymentResultSource, 'chain_id' | 'genesis_digest'>,
) {
  return deploymentHoldLineage.parse({
    chainId: source.chain_id,
    genesisDigest: `sha256:${source.genesis_digest}`,
    historical: deploymentObservation(verified),
  });
}

export async function retainDeploymentLineage(
  client: PoolClient,
  scope: EvidenceScope,
  entries: readonly { source: SourceReceipt; lineage: DeploymentHoldLineage | null }[],
) {
  for (const { source, lineage } of entries) {
    if (lineage === null) continue;
    const value = deploymentHoldLineage.parse(lineage);
    const hash = sha256(value);
    const identity = [scope.participantId, scope.privacyDomainId, scope.streamId, source.recordId];
    await client.query(
      `insert into control.evidence_deployment_lineage
       (participant_id,privacy_domain_id,stream_id,record_id,projection,projection_digest)
       values($1,$2,$3,$4,$5,$6) on conflict do nothing`,
      [...identity, value, hash],
    );
    const retained = await client.query<{ projection: unknown; projection_digest: string }>(
      `select projection,projection_digest from control.evidence_deployment_lineage
       where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4`,
      identity,
    );
    if (
      retained.rowCount !== 1 ||
      retained.rows[0]!.projection_digest !== hash ||
      sha256(retained.rows[0]!.projection) !== hash
    )
      throw new EvidenceCustodyError('INTEGRITY');
    await retainDeploymentProjection(client, scope, source);
  }
}
