import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

import { ContractError } from './errors.js';
import type { EvaluationResult } from './policy-evaluator.js';
import type { AdmittedVisibilityResource, VisibilityPolicy } from './visibility-policy.js';

// Wire projections only. The Rust policy core owns validation and semantic identity.
export interface PolicySemanticDocument {
  readonly visibilityPolicies?: readonly VisibilityPolicy[];
  readonly factConditions?: readonly (
    | {
        readonly kind: 'RELATIONSHIP';
        readonly fact: {
          readonly candidateId: string;
          readonly generationId: string;
          readonly factDigest: string;
        };
        readonly factProfileId: string;
        readonly profileDigest: string;
        readonly namespace: string;
        readonly entityKeyDigest: string;
        readonly relationshipKind: string;
        readonly rolePredicate: string;
        readonly trustedSubjectSelector: 'WORKLOAD_UUID_V1';
      }
    | {
        readonly kind: 'EXTERNAL_OBSERVATION';
        readonly fact: {
          readonly candidateId: string;
          readonly generationId: string;
          readonly factDigest: string;
        };
        readonly providerId: string;
        readonly providerVersion: string;
        readonly providerConfigurationDigest: string;
        readonly requestDigest: string;
        readonly condition: string;
      }
  )[];
  readonly schemaVersion: '1.0.0';
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly moduleBindings: readonly {
    readonly moduleId: string;
    readonly semanticVersion: string;
    readonly manifestDigest: string;
    readonly configurationDigest: string;
  }[];
  readonly rpcPolicies: readonly {
    readonly schemaVersion: '1.0.0';
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly rules: readonly {
      readonly method: string;
      readonly effect: 'ALLOW' | 'DENY';
      readonly requiredRoles: readonly string[];
    }[];
  }[];
  readonly contractPolicies: readonly {
    readonly contractMethodPolicyId: string;
    readonly revision: string;
  }[];
  readonly deploymentPolicies?: readonly {
    readonly deploymentPolicyId: string;
    readonly definitionDigest: string;
  }[];
  readonly indexerPolicies?: readonly {
    readonly schemaVersion: '1.0.0';
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly workloadId: string;
    readonly indexerProfileId: string;
    readonly profileArtifactDigest: string;
    readonly projectionPlanId: string;
    readonly planArtifactDigest: string;
    readonly acquisitionConfigurationDigest: string;
    readonly rpcPolicyDigest: string;
    readonly rangeStart: string;
    readonly rangeEnd: string;
    readonly maximumRangeBlocks: string;
    readonly maximumResponseBytes: number;
    readonly rules: readonly {
      readonly dataClass:
        | 'EVENT_LOG'
        | 'STATE_CALL'
        | 'RECEIPT'
        | 'BLOCK_HEADER'
        | 'FULL_BLOCK_TRANSACTIONS'
        | 'EXTERNAL_OBSERVATION';
      readonly effect: 'ALLOW' | 'DENY';
      readonly requiredRoles: readonly string[];
    }[];
  }[];
  readonly requiredFacts: readonly {
    readonly candidateId: string;
    readonly generationId: string;
    readonly factDigest: string;
  }[];
}

function coreCommand(command: string, value: unknown): Record<string, unknown> {
  const executable =
    process.env.OPENPC_POLICY_CORE_BIN ??
    fileURLToPath(new URL('../../../../target/debug/openpc-policy-evaluator', import.meta.url));
  return JSON.parse(
    execFileSync(executable, [], {
      encoding: 'utf8',
      input: JSON.stringify({ command, value }),
      timeout: 10_000,
      maxBuffer: 4 * 1024 * 1024,
      windowsHide: true,
    }),
  ) as Record<string, unknown>;
}

export function compilePolicySemantics(
  document: PolicySemanticDocument,
  admitted: readonly unknown[],
  workloadId: string,
  deployments: readonly unknown[] = [],
  indexerInputs: readonly IndexerCompilationInput[] = [],
  visibilityInputs: readonly AdmittedVisibilityResource[] = [],
): void {
  try {
    const output = coreCommand('COMPILE_SEMANTICS', {
      document,
      admitted,
      workloadId,
      deployments,
      indexerInputs,
      visibilityInputs,
    });
    if (output.identity !== 'PC-CONTRACT-COMPILER-1/PC-CBOR-1')
      throw new Error('policy compilation rejected');
  } catch {
    throw new ContractError('PC-POLICY-2003', 'policy compilation rejected');
  }
}

/** Internal owner-resolved bytes, never part of the public policy document. */
export interface IndexerCompilationInput {
  readonly configurationCbor: readonly number[];
  readonly configurationDigest: string;
}

export function validatePolicySemantics(
  value: unknown,
  command: 'SEMANTICS' | 'DECODE_SEMANTICS' = 'SEMANTICS',
): {
  readonly document: PolicySemanticDocument;
  readonly bytes: Buffer;
  readonly digest: Buffer;
} {
  try {
    const output = coreCommand(command, value) as unknown as {
      identity: string;
      document: PolicySemanticDocument;
      bytes: string;
      digest: string;
    };
    if (
      output.identity !== 'PC-POLICY-SEMANTICS-1/PC-CBOR-1' ||
      !/^(?:[0-9a-f]{2})+$/.test(output.bytes) ||
      !/^[0-9a-f]{64}$/.test(output.digest)
    )
      throw new Error('policy semantic identity rejected');
    return {
      document: output.document,
      bytes: Buffer.from(output.bytes, 'hex'),
      digest: Buffer.from(output.digest, 'hex'),
    };
  } catch {
    throw new ContractError('PC-POLICY-2003', 'policy semantic document rejected');
  }
}

export function policySemanticSchemaDigest(): Buffer {
  return createHash('sha256')
    .update('OpenPC typed RPC/contract/argument policy semantic document v1')
    .digest();
}

/** A legacy compiled generation supplies no typed visibility readback. Keep
 * invalid canonical typed artifacts distinguishable from an absent family. */
export function readActiveVisibilityDocument(
  bytes: Buffer,
  schemaDigest: Buffer,
  policyId: string,
) {
  let document: PolicySemanticDocument;
  try {
    document = validatePolicySemantics(Array.from(bytes), 'DECODE_SEMANTICS').document;
  } catch (error) {
    if (schemaDigest.equals(policySemanticSchemaDigest())) throw error;
    throw new ContractError('PC-POLICY-2001', 'typed visibility policy unavailable');
  }
  if (!document.visibilityPolicies?.some((policy) => policy.policyId === policyId))
    throw new ContractError('PC-POLICY-2001', 'active visibility policy unavailable');
  return document;
}

export interface ContractSimulationRequest {
  readonly contractMethodPolicyId: string;
  readonly method: 'eth_call' | 'eth_sendRawTransaction';
  readonly calldata: string;
  /** Required at the HTTP boundary. Optional here only for compatibility with
   * owner-internal semantic fixtures that do not exercise Identity resolution. */
  readonly workloadId?: string;
  readonly assignmentId?: string;
}

export interface DeploymentSimulationRequest {
  readonly deploymentPolicyId: string;
  readonly method: 'eth_sendRawTransaction';
  readonly signedTransaction: string;
}
export interface IndexerSimulationRequest {
  readonly indexerProfileId: string;
  readonly projectionPlanId: string;
  readonly dataClass: NonNullable<
    PolicySemanticDocument['indexerPolicies']
  >[number]['rules'][number]['dataClass'];
  readonly rangeStart: string;
  readonly rangeEnd: string;
  readonly maximumResponseBytes: number;
}
export type PolicySimulationRequest =
  | ContractSimulationRequest
  | DeploymentSimulationRequest
  | IndexerSimulationRequest
  | VisibilitySimulationRequest;

export interface VisibilitySimulationRequest {
  readonly visibilityPolicyId: string;
  readonly purpose: string;
  readonly dimensions: VisibilityPolicy['dimensions'];
  readonly fields: readonly string[];
}

/** Internal Identity-owned prediction, never accepted from a public request. */
export interface WorkloadPolicyPrediction {
  readonly workloadId: string;
  readonly principal: unknown;
  readonly paths: readonly unknown[];
  readonly envelopes: readonly unknown[];
  readonly revocations: readonly unknown[];
  readonly sourceDigest: string;
  readonly evaluatedAtNs: string;
  readonly credentialValidUntilNs: string;
}

export function simulateContractSemantics(
  document: PolicySemanticDocument,
  admitted: readonly unknown[],
  actor: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly principalId: string;
    readonly workloadId?: string;
    readonly assignmentId: string;
    readonly roles: readonly string[];
    readonly authorityDigest: string;
  },
  request: PolicySimulationRequest,
  facts: readonly unknown[],
  deployments: readonly unknown[] = [],
  evaluatedAtMs = Date.now(),
  indexerInputs: readonly IndexerCompilationInput[] = [],
  workloadPrediction?: WorkloadPolicyPrediction,
  visibilityInputs: readonly AdmittedVisibilityResource[] = [],
): EvaluationResult & { readonly factGenerationDigest: string } {
  try {
    const deployment = 'deploymentPolicyId' in request;
    const indexer = 'indexerProfileId' in request;
    const visibility = 'visibilityPolicyId' in request;
    const command = visibility
      ? 'VISIBILITY_SIMULATION'
      : indexer
        ? 'INDEXER_SIMULATION'
        : deployment
          ? 'DEPLOYMENT_SIMULATION'
          : 'CONTRACT_SIMULATION';
    const evaluatorRequest =
      command === 'CONTRACT_SIMULATION' && 'contractMethodPolicyId' in request
        ? {
            contractMethodPolicyId: request.contractMethodPolicyId,
            method: request.method,
            calldata: request.calldata,
          }
        : request;
    const result = coreCommand(command, {
      document,
      admitted,
      actor,
      request: evaluatorRequest,
      facts,
      deployments,
      ...(indexer || indexerInputs.length > 0 ? { indexerInputs } : {}),
      ...(indexer || visibility ? { workloadPrediction } : {}),
      ...(visibility ? { visibilityInputs } : {}),
      ...(deployment ? { evaluatedAtMs } : {}),
    });
    if (
      result.identity !==
        (visibility
          ? 'PC-VISIBILITY-SIMULATION-1/PC-CBOR-1'
          : indexer
            ? 'PC-INDEXER-SIMULATION-1/PC-CBOR-1'
            : deployment
              ? 'PC-DEPLOYMENT-SIMULATION-1/PC-CBOR-1'
              : 'PC-CONTRACT-SIMULATION-1/PC-CBOR-1') ||
      result.authority !== 'SIMULATION_ONLY'
    )
      throw new Error('simulation rejected');
    const digest = z.string().regex(/^[0-9a-f]{64}$/u);
    const bytes = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
    return z
      .strictObject({
        evaluatorIdentity: z.literal('PC-POLICY-EVALUATOR-1/PC-CBOR-1'),
        truthState: z.enum([
          'SUCCESS',
          'AUTHORIZED_EMPTY',
          'DENIED',
          'STALE',
          'PARTIAL',
          'CONFLICTING',
        ]),
        permissions: z.array(z.string()),
        obligations: z.array(z.string()),
        conflicts: z.array(z.string()),
        explanationCodes: z.array(z.string()),
        inputDigest: digest,
        resultDigest: digest,
        factGenerationDigest: digest,
        inputBytes: bytes,
        resultBytes: bytes,
      })
      .parse(result.evaluation);
  } catch {
    throw new ContractError('PC-POLICY-2003', 'typed simulation rejected');
  }
}
