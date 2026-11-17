import { readFileSync } from 'node:fs';
import type { PoolClient } from 'pg';
import { configurationCoreCommand } from '../core-command.js';
import { ConfigurationRepositoryError } from '../persistence/types.js';
import { deploymentRejectionReadbackSchema } from './result-contract.js';

/** A rejection before handoff has no target journal or association. Its signer
 * and the approved immutable candidate independently bind this Control result. */
export async function readVerifiedDeploymentRejection(
  client: PoolClient,
  command: string,
  participant: string,
  privacy: string,
  maker?: string,
) {
  const selected = await client.query<{
    signed_bytes: Buffer;
    result_digest: string;
    created_at: string;
    preparation_bytes: Buffer;
    publication_bytes: Buffer;
    signed_transaction: string;
    candidate_digest: string;
    evidence_digest: string;
    attempt_id: string;
    actor_principal_id: string;
  }>('select * from openpc.deployment_rejection_source($1::uuid,$2::uuid,$3::uuid)', [
    command,
    participant,
    privacy,
  ]);
  if (selected.rowCount === 0) return undefined;
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row || (maker !== undefined && maker !== row.actor_principal_id))
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  try {
    const path = process.env.OPENPC_DEPLOYMENT_REJECTION_PUBLIC_KEY_FILE;
    if (!path) throw new Error('missing worker trust');
    const key = readFileSync(path, 'utf8').trim();
    if (!/^(02|03)[0-9a-f]{64}$/u.test(key)) throw new Error('invalid worker trust');
    const parsed = deploymentRejectionReadbackSchema.parse(
      configurationCoreCommand('READ_DEPLOYMENT_REJECTION', {
        publication: JSON.parse(row.publication_bytes.toString('utf8')),
        recordBytes: `0x${row.preparation_bytes.toString('hex')}`,
        signedTransaction: row.signed_transaction,
        commandId: command,
        attemptId: row.attempt_id,
        candidateDigest: row.candidate_digest,
        authorizationEvidenceDigest: row.evidence_digest,
        signedBytes: `0x${row.signed_bytes.toString('hex')}`,
        verificationKey: `0x${key}`,
      }),
    );
    if (`sha256:${parsed.resultDigest}` !== row.result_digest)
      throw new Error('result digest mismatch');
    return {
      candidateDigest: `sha256:${row.candidate_digest}`,
      authorizationEvidenceDigest: `sha256:${row.evidence_digest}`,
      result: {
        ...parsed,
        updatedAt: row.created_at,
        attemptId: row.attempt_id,
        associationCurrent: false,
      },
    };
  } catch {
    throw new ConfigurationRepositoryError('PC-FACT-4001');
  }
}

/** Preserve the established deployment readback contract. */
export async function readDeploymentRejection(
  client: PoolClient,
  command: string,
  participant: string,
  privacy: string,
  maker?: string,
) {
  return (await readVerifiedDeploymentRejection(client, command, participant, privacy, maker))
    ?.result;
}
