import type { Pool } from 'pg';
import type { TrustedPolicyArtifactSigner } from '../domain/policy-artifact.js';
import {
  compilePolicyArtifact,
  type PolicyArtifactCompilerSigner,
} from '../domain/policy-artifact-compiler.js';
import { pcCbor1 } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';
import {
  admitPolicyArtifactInTransaction,
  createPolicyVersionInTransaction,
} from './policy-artifact-store.js';
import {
  assertActionIntent,
  completeOperation,
  inScope,
  reserveOperation,
  type PublicApprovalScope,
} from './public-approval-store.js';

type VersionInput = { readonly semanticVersion: string; readonly reason: string } & (
  | { readonly semanticDocument: unknown }
  | { readonly normalizedPolicyDigest: string; readonly dependencyClosureDigest: string }
);

/** The public command shares the governance transaction, actor fence and replay
 * owner. Compiler artifacts are integrity evidence, never activation authority. */
export function createPublicPolicyVersion(
  pool: Pool,
  scope: PublicApprovalScope,
  policyId: string,
  input: VersionInput,
  trustedSigners: readonly TrustedPolicyArtifactSigner[],
  signer?: PolicyArtifactCompilerSigner,
) {
  return inScope(pool, scope, async (client) => {
    const intent = await assertActionIntent(client, scope, 'CREATE', ['policy-version']);
    const prior = await reserveOperation(client, scope, pcCbor1({ policyId, input }).digest, '0');
    if (prior) return prior;
    const identity = {
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      policyId,
      semanticVersion: input.semanticVersion,
      operationId: scope.operationId,
      actionIntentId: scope.actionIntentId,
    };
    let normalizedPolicyDigest: Buffer, dependencyClosureDigest: Buffer;
    if ('semanticDocument' in input) {
      if (!signer) throw new ContractError('PC-POLICY-2003', 'policy compiler signing unavailable');
      const artifact = compilePolicyArtifact(
        { ...identity, semanticDocument: input.semanticDocument },
        signer,
      );
      const admitted = await admitPolicyArtifactInTransaction(client, {
        ...identity,
        ...artifact,
        admittedByPrincipalId: scope.principalId,
        trustedSigners,
      });
      normalizedPolicyDigest = admitted.semanticDigest;
      dependencyClosureDigest = artifact.dependencyClosureDigest;
    } else {
      normalizedPolicyDigest = Buffer.from(input.normalizedPolicyDigest.slice(7), 'hex');
      dependencyClosureDigest = Buffer.from(input.dependencyClosureDigest.slice(7), 'hex');
    }
    const version = await createPolicyVersionInTransaction(client, {
      ...identity,
      createdByPrincipalId: scope.principalId,
      normalizedPolicyDigest,
      dependencyClosureDigest,
    });
    // One immutable version has one creation event even when a different valid
    // command selects the same already-admitted artifact.
    const head = await client.query(
      `insert into control.outbox_aggregate_head
      (participant_id,aggregate_type,aggregate_id,last_sequence) values($1,'policy-version',$2,1)
      on conflict (participant_id,aggregate_type,aggregate_id) do nothing returning aggregate_id`,
      [scope.participantId, version.policyVersionId],
    );
    if (head.rowCount === 1) {
      const event = await client.query(
        `insert into control.outbox_event
        (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,aggregate_sequence,payload_cbor,payload_digest,cose_sign1,occurred_at)
        select participant_id,privacy_domain_id,uuidv7(),'openpc.policy.version.created.v1','policy-version',$4,1,payload_cbor,payload_digest,cose_sign1,clock_timestamp()
          from control.policy_artifact where participant_id=$1 and privacy_domain_id=$2 and semantic_digest=$3`,
        [
          scope.participantId,
          scope.privacyDomainId,
          normalizedPolicyDigest,
          version.policyVersionId,
        ],
      );
      if (event.rowCount !== 1) throw new ContractError('PC-POLICY-2005');
    }
    return completeOperation(client, scope, intent, version.policyVersionId, '1', 'policy-version');
  });
}
