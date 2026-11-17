import type { PoolClient } from 'pg';
import type { z } from 'zod';
import { readDeploymentRejection } from '../configuration/deployment/rejection-readback.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { canonicalJson } from '../configuration/digest.js';
import { verifyRetiredRpcCatalogueSource } from './rpc-search-retirement.js';
import type { localEvidenceDeletionSelection } from './deletion-contracts.js';

/** Never infer no-send from missing custody or from unverified JSON claims.
 * The existing purpose-specific verifier reconstructs the complete prepared
 * command and independently verifies its signer, scope, attempt and authority.
 */
export async function verifyEvidenceDeletionSources(
  client: PoolClient,
  selection: Pick<
    z.infer<typeof localEvidenceDeletionSelection>,
    'participantId' | 'privacyDomainId' | 'streamId' | 'sourceRejections' | 'sourceRpcRetirements'
  > | null,
) {
  for (const proof of selection?.sourceRejections ?? []) {
    const result = await readDeploymentRejection(
      client,
      proof.commandId,
      selection!.participantId.slice(-36),
      selection!.privacyDomainId,
    );
    if (
      !result ||
      result.authority !== 'NONE' ||
      result.identity !== proof.sourceFormat ||
      result.sequence !== '1' ||
      `sha256:${result.resultDigest}` !== proof.receiptDigest ||
      result.status.operationId !== `urn:openpc:operation:${proof.commandId}` ||
      result.attemptId !== proof.attemptId ||
      `sha256:${result.status.evidenceDigest}` !== proof.authorizationEvidenceDigest ||
      result.status.state !== 'REJECTED' ||
      result.status.truthState !== 'DENIED' ||
      Object.values(result.outcome).some((value) => value !== null)
    )
      throw new ConfigurationRepositoryError('PC-FACT-4001');
  }
  for (const proof of selection?.sourceRpcRetirements ?? []) {
    const verified = await verifyRetiredRpcCatalogueSource(client, {
      participantId: selection!.participantId.slice(-36),
      privacyDomainId: selection!.privacyDomainId,
      streamId: selection!.streamId,
      recordId: proof.recordId,
      recordDigest: proof.sourceReceiptDigest,
    });
    if (canonicalJson(verified) !== canonicalJson(proof))
      throw new ConfigurationRepositoryError('PC-FACT-4001');
  }
}
