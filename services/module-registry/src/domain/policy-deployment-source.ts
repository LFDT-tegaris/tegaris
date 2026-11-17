import { createHash } from 'node:crypto';
import { validatePolicySemantics } from './policy-semantics.js';
import { ContractError } from './errors.js';
import {
  decodePolicyArtifactPayload,
  verifyPolicyArtifactCose,
  type TrustedPolicyArtifactSigner,
} from './policy-artifact.js';
import {
  policyDeploymentSourceReference,
  policyDeploymentSourceView,
  type PolicyDeploymentSourceReference,
} from '../policy-deployment-source-contract.js';

export interface StoredPolicyDeploymentSource {
  participantId: string;
  privacyDomainId: string;
  policyId: string;
  policyVersionId: string;
  policyArtifactId: string;
  releaseBundleId: string;
  retiredGenerationId: string;
  semanticVersion: string;
  versionState: string;
  versionSemanticCbor: Buffer;
  versionSchemaDigest: Buffer;
  versionSemanticDigest: Buffer;
  versionCoseSign1: Buffer;
  semanticCbor: Buffer;
  semanticDigest: Buffer;
  semanticBytesDigest: Buffer;
  policySchemaDigest: Buffer;
  dependencyClosureDigest: Buffer;
  payloadCbor: Buffer;
  payloadDigest: Buffer;
  coseSign1: Buffer;
  signerKeyDigest: Buffer;
  releaseManifestDigest: Buffer;
  releaseDependencyClosureDigest: Buffer;
  releaseRevision: string;
  releaseState: string;
  originalGeneration: string;
  originalGenerationDigest: Buffer;
  generationArtifactDigest: Buffer;
  generationCompilerManifestDigest: Buffer;
  generationDependencyClosureDigest: Buffer;
  generationState: string;
  generationActive: boolean;
}
const sha256 = (value: Buffer) => createHash('sha256').update(value).digest();
const encoded = (value: Buffer) => 'sha256:' + value.toString('hex');

/** Authenticate the retained compiler signature and every original byte/digest
 * join. Historical release/retirement does not supply fresh authority, Facts or
 * approval. Only the installed compiler trust is accepted, never a UI key. */
export function authenticatePolicyDeploymentSource(
  scope: { participantId: string; privacyDomainId: string },
  selected: PolicyDeploymentSourceReference,
  row: StoredPolicyDeploymentSource,
  trustedSigners: readonly TrustedPolicyArtifactSigner[],
) {
  try {
    const reference = policyDeploymentSourceReference.parse(selected);
    if (
      row.participantId !== scope.participantId ||
      row.privacyDomainId !== scope.privacyDomainId ||
      Object.entries(reference).some(
        ([name, value]) => row[name as keyof typeof reference] !== value,
      ) ||
      row.versionState !== 'IMMUTABLE_VERSION' ||
      row.generationState !== 'RETIRED' ||
      row.generationActive !== false ||
      !['PUBLISHED', 'ROLLED_BACK'].includes(row.releaseState) ||
      trustedSigners.length === 0
    )
      throw Error();
    const digests = [
      row.versionSchemaDigest,
      row.versionSemanticDigest,
      row.semanticDigest,
      row.semanticBytesDigest,
      row.policySchemaDigest,
      row.dependencyClosureDigest,
      row.payloadDigest,
      row.signerKeyDigest,
      row.releaseManifestDigest,
      row.releaseDependencyClosureDigest,
      row.originalGenerationDigest,
      row.generationArtifactDigest,
      row.generationCompilerManifestDigest,
      row.generationDependencyClosureDigest,
    ];
    if (
      digests.some((value) => !Buffer.isBuffer(value) || value.length !== 32) ||
      !row.versionSemanticCbor.equals(row.semanticCbor) ||
      !row.versionCoseSign1.equals(row.coseSign1) ||
      !row.versionSchemaDigest.equals(row.policySchemaDigest) ||
      !row.versionSemanticDigest.equals(row.semanticDigest) ||
      !row.semanticDigest.equals(row.semanticBytesDigest) ||
      !sha256(row.semanticCbor).equals(row.semanticDigest) ||
      !sha256(row.payloadCbor).equals(row.payloadDigest) ||
      !row.releaseManifestDigest.equals(row.semanticDigest) ||
      !row.releaseDependencyClosureDigest.equals(row.dependencyClosureDigest) ||
      !row.originalGenerationDigest.equals(row.releaseManifestDigest) ||
      !row.generationArtifactDigest.equals(row.payloadDigest) ||
      !row.generationCompilerManifestDigest.equals(row.policySchemaDigest) ||
      !row.generationDependencyClosureDigest.equals(row.dependencyClosureDigest)
    )
      throw Error();
    const payload = decodePolicyArtifactPayload(row.payloadCbor);
    if (
      payload.participantId !== 'urn:openpc:participant:' + row.participantId ||
      payload.privacyDomainId !== 'urn:openpc:privacy-domain:' + row.privacyDomainId ||
      payload.policySetId !== 'urn:openpc:policy-set:' + row.policyId ||
      payload.semanticVersion !== row.semanticVersion ||
      !payload.policySchemaDigest.equals(row.policySchemaDigest) ||
      !payload.semanticDigest.equals(row.semanticDigest) ||
      !payload.semanticBytesDigest.equals(row.semanticBytesDigest) ||
      !payload.dependencyClosureDigest.equals(row.dependencyClosureDigest)
    )
      throw Error();
    const semantic = validatePolicySemantics(Array.from(row.semanticCbor), 'DECODE_SEMANTICS');
    if (
      !semantic.bytes.equals(row.semanticCbor) ||
      !semantic.digest.equals(row.semanticDigest) ||
      semantic.document.participantId !== scope.participantId ||
      semantic.document.privacyDomainId !== scope.privacyDomainId
    )
      throw Error();
    const signer = verifyPolicyArtifactCose(trustedSigners, row.payloadCbor, row.coseSign1);
    if (!signer?.equals(row.signerKeyDigest)) throw Error();
    const view = policyDeploymentSourceView.parse({
      ...reference,
      ...scope,
      semanticVersion: row.semanticVersion,
      semanticDigest: encoded(row.semanticDigest),
      semanticBytesDigest: encoded(row.semanticBytesDigest),
      policySchemaDigest: encoded(row.policySchemaDigest),
      dependencyClosureDigest: encoded(row.dependencyClosureDigest),
      artifactPayloadDigest: encoded(row.payloadDigest),
      artifactSignerKeyDigest: encoded(row.signerKeyDigest),
      originalGenerationDigest: encoded(row.originalGenerationDigest),
      originalGeneration: row.originalGeneration,
      releaseRevision: row.releaseRevision,
      releaseState: row.releaseState,
      generationState: 'RETIRED',
      sourceFormat: 'LEGACY_ARTIFACT_GENERATION_V1',
      authority: 'NONE',
      runtimePermission: 'REQUIRES_FRESH_DEPLOYMENT_AUTHORITY',
    });
    return {
      view,
      artifact: {
        semanticCbor: Buffer.from(row.semanticCbor),
        payloadCbor: Buffer.from(row.payloadCbor),
        coseSign1: Buffer.from(row.coseSign1),
      },
    };
  } catch {
    throw new ContractError('PC-POLICY-2003');
  }
}
