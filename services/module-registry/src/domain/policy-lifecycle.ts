import { isReleaseSimulation } from './policy-simulation-eligibility.js';
import { pcCbor1Digest } from './digest.js';
import { ContractError } from './errors.js';

export interface ImmutablePolicyVersion {
  policyVersionId: string;
  version: number;
  semanticDigest: string;
  makerPrincipalId: string;
  state: 'IMMUTABLE_VERSION';
}
export interface ApprovalBinding {
  subjectDigest: string;
  makerPrincipalId: string;
  checkerPrincipalId: string;
  expiresAt: Date;
  approved: boolean;
}
export interface PolicyGeneration {
  generation: bigint;
  generationDigest: string;
  artifactDigest: string;
  dependencyClosureDigest: string;
  state: 'DESIRED' | 'PREPARED' | 'ACTIVE' | 'RETIRED';
}

export function createImmutableVersion(
  policyVersionId: string,
  version: number,
  semanticDocument: unknown,
  makerPrincipalId: string,
): ImmutablePolicyVersion {
  if (version <= 0) throw new ContractError('PC-POLICY-2000');
  return Object.freeze({
    policyVersionId,
    version,
    semanticDigest: pcCbor1Digest(semanticDocument),
    makerPrincipalId,
    state: 'IMMUTABLE_VERSION',
  });
}
export function releasePolicy(
  version: ImmutablePolicyVersion,
  approval: ApprovalBinding,
  simulation: {
    truthState: string;
    authority: string;
    inputDigest: string;
    resultDigest?: string;
    resultDocument?: unknown;
  },
  dependencyClosureDigest: string,
  now: Date,
): PolicyGeneration {
  if (
    !approval.approved ||
    approval.expiresAt <= now ||
    approval.makerPrincipalId === approval.checkerPrincipalId ||
    approval.subjectDigest !== version.semanticDigest
  )
    throw new ContractError('PC-POLICY-2004');
  if (
    !isReleaseSimulation({
      truthState: simulation.truthState,
      authorityLabel: simulation.authority,
      resultDocument: simulation.resultDocument,
      inputDigest: Buffer.from(simulation.inputDigest, 'hex'),
      resultDigest: simulation.resultDigest
        ? Buffer.from(simulation.resultDigest, 'hex')
        : undefined,
    })
  )
    throw new ContractError('PC-POLICY-2003');
  const artifactDigest = pcCbor1Digest({ version, dependencyClosureDigest });
  return Object.freeze({
    generation: 1n,
    generationDigest: pcCbor1Digest({
      artifactDigest,
      simulationInputDigest: simulation.inputDigest,
      approval: approval.subjectDigest,
    }),
    artifactDigest,
    dependencyClosureDigest,
    state: 'DESIRED',
  });
}
