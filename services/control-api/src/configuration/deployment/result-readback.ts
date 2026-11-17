import { sha256 } from '../digest.js';
import type { PoolClient } from 'pg';
import { ConfigurationRepositoryError, type OperationRecord } from '../persistence/types.js';
import { deploymentProjectionReadbackSchema } from './result-contract.js';
import { readDeploymentRejection } from './rejection-readback.js';
import { selectDeploymentResultSource } from './result-source.js';
import { verifyDeploymentResult } from './result-verification.js';

export async function readDeploymentResult(
  client: PoolClient,
  command: string,
  participant: string,
  privacy: string,
  maker?: string,
  followReplacement = true,
): Promise<
  | (ReturnType<typeof deploymentProjectionReadbackSchema.parse> & {
      updatedAt: string;
      attemptId: string;
      associationCurrent: boolean;
    })
  | Awaited<ReturnType<typeof readDeploymentRejection>>
> {
  const selected = await selectDeploymentResultSource(client, command, participant, privacy);
  if (selected.rowCount === 0)
    return readDeploymentRejection(client, command, participant, privacy, maker);
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row || (maker !== undefined && row.actor_principal_id !== maker))
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  if (row.signed_bytes === null) return undefined;
  try {
    const parsed = verifyDeploymentResult(row, command, participant, privacy, true);
    if (row.successor_command_id !== null) {
      if (!followReplacement) throw new ConfigurationRepositoryError('PC-FACT-4001');
      // The reservation guard permits one scoped successor, never a chain.
      // Verify its normal signed projection through the same read owner. A
      // submitted successor, timeout or nonce change cannot supersede anything.
      const successor = await readDeploymentResult(
        client,
        row.successor_command_id,
        participant,
        privacy,
        maker,
        false,
      );
      if (successor !== undefined) {
        const final =
          (successor.status.state === 'CONFIRMED' && successor.status.truthState === 'SUCCESS') ||
          (successor.status.state === 'FAILED' && successor.status.truthState === 'FAILED');
        if (
          final &&
          (parsed.status.state === 'CONFIRMED' ||
            (parsed.status.state === 'FAILED' && parsed.status.truthState === 'FAILED'))
        )
          throw new ConfigurationRepositoryError('PC-FACT-4001');
        if (final)
          parsed.status = { ...parsed.status, state: 'REJECTED', truthState: 'CONFLICTING' };
        parsed.status.evidenceDigest = sha256({
          purpose: 'openpc:replacement-readback:v1',
          predecessor: row.result_digest,
          successor: successor.resultDigest,
          successorOperation: successor.status.operationId,
        });
        parsed.sequence = (BigInt(parsed.sequence) + BigInt(successor.sequence)).toString();
      }
    }
    return {
      ...parsed,
      updatedAt: row.result_created_at!,
      attemptId: row.attempt_id,
      associationCurrent: row.association_current === true,
    };
  } catch {
    // Unverifiable stored evidence is withheld as an unavailable fact. It is
    // never treated as malformed caller input or a successful operation.
    throw new ConfigurationRepositoryError('PC-FACT-4001');
  }
}

/** Deployment effect truth is independent of successful command acceptance. */
export function managementDeploymentState(status: {
  state: string;
  truthState: string;
}): Pick<OperationRecord, 'state' | 'truthState'> {
  if (status.state === 'CONFIRMED' && status.truthState === 'SUCCESS')
    return { state: 'SUCCEEDED', truthState: 'SUCCESS' };
  // The frozen management operation vocabulary has no REORG/UNAVAILABLE.
  // Deployment readback retains the signed reason and invalidation document.
  if (status.state === 'REORG' || status.state === 'FAILED' || status.state === 'REJECTED')
    return { state: 'FAILED', truthState: 'FAILED' };
  return { state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' };
}
