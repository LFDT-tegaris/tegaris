import { readFileSync } from 'node:fs';
import { ConfigurationRepositoryError } from '../persistence/types.js';
import { deploymentProjectionCore } from './intent-core.js';
import { deploymentProjectionReadbackSchema } from './result-contract.js';
import type { DeploymentResultSource } from './result-source.js';

const hex = (bytes: Buffer) => `0x${bytes.toString('hex')}`;

/** Verify one immutable observation against its original command and independent
 * target trust. Historical custody excludes the mutable current association. */
export function verifyDeploymentResult(
  row: DeploymentResultSource,
  command: string,
  participant: string,
  privacy: string,
  includeAssociation: boolean,
) {
  if (row.signed_bytes === null) throw new ConfigurationRepositoryError('PC-FACT-4001');
  let key: string;
  try {
    const path = process.env.OPENPC_DEPLOYMENT_PROJECTION_PUBLIC_KEY_FILE;
    if (!path) throw new Error('missing target trust');
    key = readFileSync(path, 'utf8').trim();
    if (!/^(02|03)[0-9a-f]{64}$/u.test(key)) throw new Error('invalid target trust');
  } catch {
    throw new ConfigurationRepositoryError('PC-FACT-4001');
  }
  try {
    const parsed = deploymentProjectionReadbackSchema.parse(
      deploymentProjectionCore({
        publication: JSON.parse(row.publication_bytes.toString('utf8')),
        recordBytes: hex(row.preparation_bytes),
        signedBytes: hex(row.signed_bytes),
        verificationKey: `0x${key}`,
        expected: {
          targetRuntimeId: row.target_runtime_id,
          owner: {
            participant_id: participant,
            privacy_domain_id: privacy,
            actor_principal_id: row.execution_principal_id,
            workload_id: row.execution_workload_id,
          },
          commandId: command,
          attemptId: row.attempt_id,
          intentDigest: row.intent_digest,
          preparationDigest: row.preparation_digest,
          chainId: row.chain_id,
          genesisDigest: row.genesis_digest,
          transactionHash: row.transaction_hash,
        },
        association:
          !includeAssociation || row.association_bytes === null
            ? null
            : {
                documentBytes: hex(row.association_bytes),
                activationBytes: hex(row.activation_bytes ?? Buffer.alloc(0)),
                activationSequence: row.activation_sequence,
                currentSequence: row.association_sequence,
              },
      }),
    );
    if (`sha256:${parsed.resultDigest}` !== row.result_digest || parsed.sequence !== row.sequence)
      throw new ConfigurationRepositoryError('PC-FACT-4001');
    return parsed;
  } catch {
    throw new ConfigurationRepositoryError('PC-FACT-4001');
  }
}
