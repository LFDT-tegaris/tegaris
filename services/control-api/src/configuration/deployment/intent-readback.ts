import type { PoolClient } from 'pg';
import { ConfigurationRepositoryError } from '../persistence/types.js';
import { deploymentIntentCore } from './intent-core.js';
import { deploymentIntentResponseSchema } from './intent-contract.js';

/** Called only inside a fenced read transaction. Normal reads name the current
 * maker; approval reviews name the maker of the exact scoped stored candidate.
 * Restoring this historical intent never establishes current send authority. */
export async function readStoredDeploymentIntent(
  client: PoolClient,
  scope: {
    participantId: string;
    privacyDomainId: string;
    makerPrincipalId: string;
    deploymentIntentId: string;
  },
) {
  const result = await client.query<{
    deploymentPolicyId: string;
    runtimeTargetId: string;
    walletBindingId: string;
    preparationBytes: Buffer;
    publicationBytes: Buffer;
    preparationDigest: string;
    intentDigest: string;
    createdAt: Date;
    expiresAt: Date;
    expired: boolean;
  }>(
    `select deployment_policy_id::text as "deploymentPolicyId",runtime_target_id::text as "runtimeTargetId",wallet_binding_id::text as "walletBindingId",
    preparation_bytes as "preparationBytes",publication_bytes as "publicationBytes",preparation_digest as "preparationDigest",intent_digest as "intentDigest",
    created_at as "createdAt",expires_at as "expiresAt",expires_at<=clock_timestamp() as expired from control.deployment_intent
    where deployment_intent_id=$1 and participant_id=$2 and privacy_domain_id=$3 and actor_principal_id=$4`,
    [scope.deploymentIntentId, scope.participantId, scope.privacyDomainId, scope.makerPrincipalId],
  );
  const row = result.rows[0];
  if (result.rowCount !== 1 || !row) throw new ConfigurationRepositoryError('PC-AUTH-0005');
  const prepared = deploymentIntentCore('READ_DEPLOYMENT_INTENT', {
    publication: JSON.parse(row.publicationBytes.toString('utf8')),
    recordBytes: `0x${row.preparationBytes.toString('hex')}`,
  });
  if (
    `sha256:${prepared.recordDigest}` !== row.preparationDigest ||
    `sha256:${prepared.intentDigest}` !== row.intentDigest ||
    prepared.expiresAtMs !== row.expiresAt.getTime()
  )
    throw new ConfigurationRepositoryError('PC-FACT-4001');
  return deploymentIntentResponseSchema.parse({
    deploymentIntentId: `urn:openpc:resource:${scope.deploymentIntentId}`,
    deploymentPolicyId: `urn:openpc:resource:${row.deploymentPolicyId}`,
    runtimeTargetId: `urn:openpc:resource:${row.runtimeTargetId}`,
    walletBindingId: `urn:openpc:resource:${row.walletBindingId}`,
    state: row.expired ? 'EXPIRED' : 'DRAFT',
    authority: 'NONE',
    revision: '1',
    signingPayload: prepared.signingPayload,
    signingHash: prepared.signingHash,
    sender: prepared.sender,
    chainId: prepared.chainId,
    nonce: prepared.nonce,
    gasLimit: prepared.gasLimit,
    transactionType: prepared.transactionType,
    expectedContractAddress: prepared.expectedContractAddress,
    intentDigest: row.intentDigest,
    preparationDigest: row.preparationDigest,
    intentDocument: prepared.intentBytes,
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
  });
}
