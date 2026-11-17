import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { ContractError } from './errors.js';

export type Effect = 'ALLOW' | 'DENY';
export interface PolicyContribution {
  moduleId: string;
  moduleVersion: string;
  manifestDigest: string;
  family: string;
  priority: number;
  effect: Effect;
  permissions: readonly string[];
  obligations: readonly string[];
  visibility: string;
  inputType: string;
  outputType: string;
  schemaDigest: string;
  capabilityId: string;
  providerId: string;
  generationDigest: string;
  selectorDigest: string;
  existenceRule: string;
  payloadRule: string;
  terminalLayer: string;
  broaderDelegation: boolean;
  unsupportedSemantics: boolean;
  futureDependency: boolean;
  missingBridge: boolean;
  terminal: boolean;
}

export interface EvaluationContext {
  evaluatorVersion: 'PC-POLICY-EVALUATOR-1';
  profileId: string;
  platformTerminalDeny: boolean;
  participantEnvelopeAllows: boolean;
  assignmentAllows: boolean;
  epochs: {
    platform: bigint;
    currentPlatform: bigint;
    participant: bigint;
    currentParticipant: bigint;
    authority: bigint;
    currentAuthority: bigint;
    delegation: bigint;
    currentDelegation: bigint;
    assignment: bigint;
    currentAssignment: bigint;
    credential: bigint;
    currentCredential: bigint;
  };
  identities: {
    participantId: string;
    currentParticipantId: string;
    privacyDomainId: string;
    currentPrivacyDomainId: string;
    actorId: string;
    currentActorId: string;
    workloadId: string;
    currentWorkloadId: string;
    walletId: string;
    currentWalletId: string;
    assignmentId: string;
    currentAssignmentId: string;
  };
  request: {
    actionIntentId: string;
    currentActionIntentId: string;
    scopeDigest: string;
    currentScopeDigest: string;
    resourceId: string;
    currentResourceId: string;
    resourceDigest: string;
    currentResourceDigest: string;
  };
  simulation: {
    scenarioId: string;
    currentScenarioId: string;
    requestId: string;
    currentRequestId: string;
    chainId: string;
    currentChainId: string;
    routeDigest: string;
    currentRouteDigest: string;
    requestedDisclosureCapabilities: readonly string[];
    currentDisclosureCapabilities: readonly string[];
  };
  versions: {
    participantEnvelopeDigest: string;
    currentParticipantEnvelopeDigest: string;
    policyVersionDigest: string;
    currentPolicyVersionDigest: string;
    policyReleaseDigest: string;
    currentPolicyReleaseDigest: string;
    policyGenerationDigest: string;
    currentPolicyGenerationDigest: string;
    factGenerationDigest: string;
    currentFactGenerationDigest: string;
    providerGenerationDigest: string;
    currentProviderGenerationDigest: string;
    checkpointGenerationDigest: string;
    currentCheckpointGenerationDigest: string;
    dependencyClosureDigest: string;
    currentDependencyClosureDigest: string;
    schemaDigest: string;
    currentSchemaDigest: string;
    typeRegistryDigest: string;
    currentTypeRegistryDigest: string;
    moduleManifestSetDigest: string;
    currentModuleManifestSetDigest: string;
    stackProfileDigest: string;
    currentStackProfileDigest: string;
  };
  completeness: {
    selectorDigest: string;
    currentSelectorDigest: string;
    windowDigest: string;
    currentWindowDigest: string;
    obligationDigest: string;
    currentObligationDigest: string;
    selectorComplete: boolean;
    windowComplete: boolean;
    obligationComplete: boolean;
    factComplete: boolean;
    checkpointComplete: boolean;
    providerComplete: boolean;
    moduleManifestComplete: boolean;
    routeComplete: boolean;
    disclosureComplete: boolean;
    compatibilityComplete: boolean;
    complete: boolean;
  };
  contributions: readonly PolicyContribution[];
}

export interface EvaluationResult {
  evaluatorIdentity: 'PC-POLICY-EVALUATOR-1/PC-CBOR-1';
  truthState: 'SUCCESS' | 'AUTHORIZED_EMPTY' | 'DENIED' | 'STALE' | 'PARTIAL' | 'CONFLICTING';
  permissions: readonly string[];
  obligations: readonly string[];
  conflicts: readonly string[];
  explanationCodes: readonly string[];
  inputDigest: string;
  resultDigest: string;
  inputBytes: string;
  resultBytes: string;
}

const defaultEvaluator = fileURLToPath(
  new URL('../../../../target/debug/openpc-policy-evaluator', import.meta.url),
);

function bytes(hex: string): number[] {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new ContractError('PC-POLICY-2003', 'invalid digest');
  return Array.from(Buffer.from(hex, 'hex'));
}

function wireInput(input: EvaluationContext): unknown {
  return {
    ...input,
    epochs: Object.fromEntries(
      Object.entries(input.epochs).map(([name, value]) => [name, value.toString()]),
    ),
    request: {
      ...input.request,
      scopeDigest: bytes(input.request.scopeDigest),
      currentScopeDigest: bytes(input.request.currentScopeDigest),
      resourceDigest: bytes(input.request.resourceDigest),
      currentResourceDigest: bytes(input.request.currentResourceDigest),
    },
    simulation: {
      ...input.simulation,
      routeDigest: bytes(input.simulation.routeDigest),
      currentRouteDigest: bytes(input.simulation.currentRouteDigest),
    },
    versions: Object.fromEntries(
      Object.entries(input.versions).map(([name, value]) => [name, bytes(value)]),
    ),
    completeness: {
      ...input.completeness,
      selectorDigest: bytes(input.completeness.selectorDigest),
      currentSelectorDigest: bytes(input.completeness.currentSelectorDigest),
      windowDigest: bytes(input.completeness.windowDigest),
      currentWindowDigest: bytes(input.completeness.currentWindowDigest),
      obligationDigest: bytes(input.completeness.obligationDigest),
      currentObligationDigest: bytes(input.completeness.currentObligationDigest),
    },
    contributions: input.contributions.map((item) => ({
      ...item,
      manifestDigest: bytes(item.manifestDigest),
      schemaDigest: bytes(item.schemaDigest),
      generationDigest: bytes(item.generationDigest),
      selectorDigest: bytes(item.selectorDigest),
    })),
  };
}

/** Invoke the sole Rust policy core. The binary has stdin/stdout only and no DB or network API. */
export function evaluatePolicy(input: EvaluationContext): EvaluationResult {
  const evaluator = process.env.OPENPC_POLICY_CORE_BIN ?? defaultEvaluator;
  if (!existsSync(evaluator))
    throw new ContractError('PC-POLICY-2003', 'shared policy evaluator is unavailable');
  const output = execFileSync(evaluator, [], {
    encoding: 'utf8',
    input: JSON.stringify(wireInput(input)),
    maxBuffer: 4 * 1024 * 1024,
    timeout: 10_000,
    windowsHide: true,
  });
  const result = JSON.parse(output) as EvaluationResult;
  if (result.evaluatorIdentity !== 'PC-POLICY-EVALUATOR-1/PC-CBOR-1')
    throw new ContractError('PC-POLICY-2003', 'unexpected evaluator identity');
  return Object.freeze({
    ...result,
    permissions: Object.freeze(result.permissions),
    obligations: Object.freeze(result.obligations),
    conflicts: Object.freeze(result.conflicts),
    explanationCodes: Object.freeze(result.explanationCodes),
  });
}

export function simulatePolicy(input: EvaluationContext) {
  return withSimulationAuthority(evaluatePolicy(input));
}

function withSimulationAuthority<T extends object>(value: T) {
  return Object.freeze({ ...value, authority: 'SIMULATION_ONLY' as const });
}
