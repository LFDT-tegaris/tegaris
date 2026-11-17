import type { PoolClient } from 'pg';
import type { TrustedPolicyArtifactSigner } from '../domain/policy-artifact.js';
import {
  authenticatePolicyDeploymentSource,
  type StoredPolicyDeploymentSource,
} from '../domain/policy-deployment-source.js';
import {
  policyDeploymentSourceReference,
  type PolicyDeploymentSourceReference,
} from '../policy-deployment-source-contract.js';
import { ContractError } from '../domain/errors.js';

/** Caller retains authenticated scoped read/candidate authority and transaction.
 * This owner writes nothing and cannot issue a deployment or activation. */
export async function loadPolicyDeploymentSource(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string },
  input: PolicyDeploymentSourceReference,
  trustedSigners: readonly TrustedPolicyArtifactSigner[],
) {
  const selected = policyDeploymentSourceReference.safeParse(input);
  if (!selected.success) throw new ContractError('PC-POLICY-2000');
  const reference = selected.data;
  const result = await client.query<StoredPolicyDeploymentSource>(
    `select artifact.participant_id::text as "participantId",artifact.privacy_domain_id::text as "privacyDomainId",artifact.policy_id::text as "policyId",
      version.policy_version_id::text as "policyVersionId",artifact.policy_artifact_id::text as "policyArtifactId",release.release_bundle_id::text as "releaseBundleId",
      generation.policy_generation_id::text as "retiredGenerationId",artifact.semantic_version as "semanticVersion",version.state::text as "versionState",
      version.semantic_cbor as "versionSemanticCbor",version.schema_digest as "versionSchemaDigest",version.semantic_digest as "versionSemanticDigest",version.cose_sign1 as "versionCoseSign1",
      artifact.semantic_cbor as "semanticCbor",artifact.semantic_digest as "semanticDigest",artifact.semantic_bytes_digest as "semanticBytesDigest",
      artifact.policy_schema_digest as "policySchemaDigest",artifact.dependency_closure_digest as "dependencyClosureDigest",artifact.payload_cbor as "payloadCbor",
      artifact.payload_digest as "payloadDigest",artifact.cose_sign1 as "coseSign1",artifact.signer_key_digest as "signerKeyDigest",
      release.manifest_digest as "releaseManifestDigest",release.dependency_closure_digest as "releaseDependencyClosureDigest",release.revision::text as "releaseRevision",release.state as "releaseState",
      generation.generation::text as "originalGeneration",generation.generation_digest as "originalGenerationDigest",generation.artifact_digest as "generationArtifactDigest",
      generation.compiler_manifest_digest as "generationCompilerManifestDigest",generation.dependency_closure_digest as "generationDependencyClosureDigest",
      generation.state::text as "generationState",generation.active as "generationActive"
     from control.policy_artifact artifact join control.policy_version version
      on version.participant_id=artifact.participant_id and version.privacy_domain_id=artifact.privacy_domain_id and version.policy_id=artifact.policy_id
       and version.version=artifact.semantic_version and version.semantic_digest=artifact.semantic_digest
     join control.policy_release_bundle release on release.participant_id=version.participant_id and release.privacy_domain_id=version.privacy_domain_id
      and release.policy_version_id=version.policy_version_id
     join control.policy_generation generation on generation.participant_id=version.participant_id and generation.privacy_domain_id=version.privacy_domain_id
      and generation.policy_version_id=version.policy_version_id and generation.generation_digest=release.manifest_digest
     where artifact.participant_id=$1 and artifact.privacy_domain_id=$2 and artifact.policy_id=$3 and version.policy_version_id=$4
      and artifact.policy_artifact_id=$5 and release.release_bundle_id=$6 and generation.policy_generation_id=$7
      and generation.state='RETIRED' and not generation.active and release.state in ('PUBLISHED','ROLLED_BACK') and release.published_at is not null`,
    [
      scope.participantId,
      scope.privacyDomainId,
      reference.policyId,
      reference.policyVersionId,
      reference.policyArtifactId,
      reference.releaseBundleId,
      reference.retiredGenerationId,
    ],
  );
  if (result.rowCount !== 1 || !result.rows[0]) throw new ContractError('PC-POLICY-2001');
  return authenticatePolicyDeploymentSource(scope, reference, result.rows[0], trustedSigners);
}
