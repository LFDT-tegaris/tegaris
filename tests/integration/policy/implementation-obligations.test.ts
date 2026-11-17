import { generateKeyPairSync, sign } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  ContractError,
  createImmutableVersion,
  errorForNegativeProfile,
  evaluatePolicy,
  executeTraceAuthorityOracle,
  releasePolicy,
  resolveDependencies,
  sha256,
  simulatePolicy,
  transitionModule,
  traceExecutionOwners,
  verifyModuleAdmission,
  type EvaluationContext,
  type ModuleNode,
  type TraceObligation,
  type TraceAuthorityCatalog,
  type TraceAuthorityExecution,
  type TraceBehaviorOracle,
  type TraceOwnerExecution,
  type TraceSemanticRecord,
} from '../../../services/module-registry/src/index.js';
import {
  installEdges,
  installOrder,
} from '../../../services/module-registry/src/generated/contracts.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const generated = path.join(root, 'policies/modules/generated');
const readJson = async (name: string) =>
  JSON.parse(await readFile(path.join(generated, name), 'utf8')) as Record<string, unknown>;
type Mutable<T> = {
  -readonly [Key in keyof T]: T[Key] extends readonly (infer Item)[]
    ? Mutable<Item>[]
    : T[Key] extends object
      ? Mutable<T[Key]>
      : T[Key];
};
const digest = (value: string) => value.repeat(64).slice(0, 64);
const context = (contributions: EvaluationContext['contributions']): EvaluationContext => ({
  evaluatorVersion: 'PC-POLICY-EVALUATOR-1',
  profileId: 'test.yaml',
  platformTerminalDeny: false,
  participantEnvelopeAllows: true,
  assignmentAllows: true,
  epochs: {
    platform: 1n,
    currentPlatform: 1n,
    participant: 2n,
    currentParticipant: 2n,
    authority: 3n,
    currentAuthority: 3n,
    delegation: 4n,
    currentDelegation: 4n,
    assignment: 5n,
    currentAssignment: 5n,
    credential: 6n,
    currentCredential: 6n,
  },
  identities: {
    participantId: '00000000-0000-7000-8000-000000000001',
    currentParticipantId: '00000000-0000-7000-8000-000000000001',
    privacyDomainId: '00000000-0000-7000-8000-000000000002',
    currentPrivacyDomainId: '00000000-0000-7000-8000-000000000002',
    actorId: '00000000-0000-7000-8000-000000000003',
    currentActorId: '00000000-0000-7000-8000-000000000003',
    workloadId: '00000000-0000-7000-8000-000000000004',
    currentWorkloadId: '00000000-0000-7000-8000-000000000004',
    walletId: 'eip155:1:0x0000000000000000000000000000000000000005',
    currentWalletId: 'eip155:1:0x0000000000000000000000000000000000000005',
    assignmentId: '00000000-0000-7000-8000-000000000006',
    currentAssignmentId: '00000000-0000-7000-8000-000000000006',
  },
  request: {
    actionIntentId: 'ACT-POLICY_CREATE_SIMULATION-V1',
    currentActionIntentId: 'ACT-POLICY_CREATE_SIMULATION-V1',
    scopeDigest: digest('1'),
    currentScopeDigest: digest('1'),
    resourceId: 'policy:00000000-0000-7000-8000-000000000007',
    currentResourceId: 'policy:00000000-0000-7000-8000-000000000007',
    resourceDigest: digest('2'),
    currentResourceDigest: digest('2'),
  },
  simulation: {
    scenarioId: 'C04-MODULE-LANE-POSITIVE',
    currentScenarioId: 'C04-MODULE-LANE-POSITIVE',
    requestId: '00000000-0000-7000-8000-000000000008',
    currentRequestId: '00000000-0000-7000-8000-000000000008',
    chainId: 'eip155:1',
    currentChainId: 'eip155:1',
    routeDigest: digest('d'),
    currentRouteDigest: digest('d'),
    requestedDisclosureCapabilities: ['RESULT', 'EXPLANATION'],
    currentDisclosureCapabilities: ['RESULT', 'EXPLANATION'],
  },
  versions: {
    participantEnvelopeDigest: digest('3'),
    currentParticipantEnvelopeDigest: digest('3'),
    policyVersionDigest: digest('f'),
    currentPolicyVersionDigest: digest('f'),
    policyReleaseDigest: digest('4'),
    currentPolicyReleaseDigest: digest('4'),
    policyGenerationDigest: digest('5'),
    currentPolicyGenerationDigest: digest('5'),
    factGenerationDigest: digest('6'),
    currentFactGenerationDigest: digest('6'),
    providerGenerationDigest: digest('d'),
    currentProviderGenerationDigest: digest('d'),
    checkpointGenerationDigest: digest('e'),
    currentCheckpointGenerationDigest: digest('e'),
    dependencyClosureDigest: digest('7'),
    currentDependencyClosureDigest: digest('7'),
    schemaDigest: digest('8'),
    currentSchemaDigest: digest('8'),
    typeRegistryDigest: digest('9'),
    currentTypeRegistryDigest: digest('9'),
    moduleManifestSetDigest: digest('d'),
    currentModuleManifestSetDigest: digest('d'),
    stackProfileDigest: digest('e'),
    currentStackProfileDigest: digest('e'),
  },
  completeness: {
    selectorDigest: digest('a'),
    currentSelectorDigest: digest('a'),
    windowDigest: digest('b'),
    currentWindowDigest: digest('b'),
    obligationDigest: digest('c'),
    currentObligationDigest: digest('c'),
    selectorComplete: true,
    windowComplete: true,
    obligationComplete: true,
    factComplete: true,
    checkpointComplete: true,
    providerComplete: true,
    moduleManifestComplete: true,
    routeComplete: true,
    disclosureComplete: true,
    compatibilityComplete: true,
    complete: true,
  },
  contributions,
});
const contribution = (
  moduleId: string,
  priority: number,
  effect: 'ALLOW' | 'DENY',
  permissions: string[],
  family = moduleId,
) => ({
  moduleId,
  moduleVersion: '1.0.0',
  manifestDigest: String(priority).padStart(64, '0'),
  family,
  priority,
  effect,
  permissions,
  obligations: ['AUDIT'],
  visibility: 'AUTHORIZED_ONLY',
  inputType: 'POLICY-REQUEST',
  outputType: 'POLICY-DECISION',
  schemaDigest: digest('8'),
  capabilityId: `capability:${family}`,
  providerId: moduleId,
  generationDigest: digest('5'),
  selectorDigest: digest('a'),
  existenceRule: 'AUTHORIZED_ONLY',
  payloadRule: 'REDACTED',
  terminalLayer: 'MODULE',
  broaderDelegation: false,
  unsupportedSemantics: false,
  futureDependency: false,
  missingBridge: false,
  terminal: false,
});

const traceKeyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });

function traceAdmissionEnvelope(concreteInputDigest: string, semanticPayload: string | Buffer) {
  const manifest = Buffer.from(semanticPayload);
  const sidecar = Buffer.from(`i03-trace-owner-sidecar:${concreteInputDigest}:${sha256(manifest)}`);
  return {
    manifestBytes: manifest,
    manifestDigest: sha256(manifest),
    signatureP1363: sign('sha256', manifest, {
      key: traceKeyPair.privateKey,
      dsaEncoding: 'ieee-p1363',
    }),
    signerPublicKeyPem: traceKeyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    signerState: 'ACTIVE' as 'ACTIVE' | 'REVOKED' | 'EXPIRED',
    sbomBytes: sidecar,
    sbomDigest: sha256(sidecar),
    provenanceBytes: sidecar,
    provenanceDigest: sha256(sidecar),
    buildReceiptBytes: sidecar,
    buildReceiptDigest: sha256(sidecar),
  };
}

function executeDeclaredTraceOwner(
  row: TraceObligation,
  authority: TraceAuthorityExecution,
): TraceOwnerExecution {
  const plan = authority.behaviorPlan;
  if (
    plan.targetSectionId === 'MOD-POLICY' ||
    plan.targetSectionId === 'MOD-OPERATIONS' ||
    plan.targetSectionId === 'MOD-PARTICIPANT'
  )
    throw new Error(`Trace requires its non-harness runtime owner: ${row.traceId}`);
  const acceptedBySemantics = plan.semanticDisposition === 'IMPLEMENTATION_REQUIREMENT';
  const mutation = plan.productInput.mutation;
  const token = plan.concreteInputDigest.slice(0, 16);
  const zeroEffectBeforeDigest = sha256({
    owner: plan.declaredOwner,
    traceId: row.traceId,
    semanticRecordDigest: plan.recordDigest,
    state: 'NO_PRODUCT_AUTHORITY_EFFECT',
  });
  let zeroEffectAfterDigest = zeroEffectBeforeDigest;
  let accepted = false;
  let behaviorId = '';
  let actualEvidence: unknown = null;
  try {
    if (row.targetSectionId === 'MOD-DEPENDENCY') {
      behaviorId = `dependency-resolver:${authority.oracleId}`;
      const ownerInput = plan.productInput.ownerInput;
      if (ownerInput.kind !== 'DEPENDENCY_RESOLUTION_INPUT')
        throw new Error('owner input mismatch');
      const provider: ModuleNode = {
        moduleId: ownerInput.providerModuleId,
        semanticVersion: ownerInput.semanticVersion,
        manifestDigest: ownerInput.providerManifestDigest,
        capabilities: [ownerInput.capabilityId],
        future: mutation === 'FUTURE_PROVIDER',
      };
      const consumer: ModuleNode = {
        moduleId: ownerInput.consumerModuleId,
        semanticVersion: '1.0.0',
        manifestDigest: ownerInput.consumerManifestDigest,
        capabilities: [],
      };
      const edge = {
        edgeId: row.traceId,
        consumerModuleId: consumer.moduleId,
        providerModuleId: provider.moduleId,
        capabilityId:
          mutation === 'CAPABILITY_MISMATCH'
            ? `trace-capability:substituted:${token}`
            : ownerInput.capabilityId,
        semanticVersion: mutation === 'VERSION_MISMATCH' ? '2.0.0' : '1.0.0',
        providerManifestDigest:
          mutation === 'MANIFEST_MISMATCH' ? plan.concreteInputDigest : provider.manifestDigest,
      };
      let nodes: ModuleNode[] = mutation === 'MISSING_PROVIDER' ? [consumer] : [provider, consumer];
      let edges = [edge];
      if (mutation === 'DUPLICATE_PROVIDER') {
        const other = { ...provider, moduleId: `${provider.moduleId}.other` };
        nodes = [provider, other, consumer];
        edges = [
          edge,
          { ...edge, edgeId: `${row.traceId}:other`, providerModuleId: other.moduleId },
        ];
      } else if (mutation === 'SELF_DEPENDENCY') {
        consumer.capabilities = [ownerInput.capabilityId];
        edges = [
          {
            ...edge,
            providerModuleId: consumer.moduleId,
            providerManifestDigest: consumer.manifestDigest,
          },
        ];
      } else if (mutation === 'CYCLE') {
        provider.capabilities = [...provider.capabilities, `trace-cycle:${token}`];
        edges.push({
          ...edge,
          edgeId: `${row.traceId}:cycle`,
          consumerModuleId: provider.moduleId,
          providerModuleId: consumer.moduleId,
          capabilityId: `trace-cycle:${token}`,
          providerManifestDigest: consumer.manifestDigest,
        });
        consumer.capabilities = [`trace-cycle:${token}`];
      }
      const resolution = resolveDependencies(nodes, edges);
      accepted = resolution.order.length === 2;
      actualEvidence = resolution;
    } else if (row.targetSectionId === 'MOD-LIFECYCLE') {
      behaviorId = `module-lifecycle:${authority.oracleId}`;
      const ownerInput = plan.productInput.ownerInput;
      if (ownerInput.kind !== 'MODULE_LIFECYCLE_INPUT') throw new Error('owner input mismatch');
      const preflight = {
        expectedVersion: BigInt(ownerInput.aggregateVersion),
        authorityEpoch: BigInt(ownerInput.authorityEpoch),
        delegationEpoch: BigInt(ownerInput.delegationEpoch),
        approvalValid: true,
        distinctChecker: true,
        dependencyClosed: true,
        custodyClosed: true,
        activeDependents: 0,
        simulationSuccessful: true,
        supplyChainValid: true,
      };
      const lifecycleMutations: Record<string, () => void> = {
        VERSION_STALE: () => (preflight.expectedVersion = 2n),
        AUTHORITY_EPOCH_STALE: () => (preflight.authorityEpoch = 9n),
        APPROVAL_MISSING: () => (preflight.approvalValid = false),
        CHECKER_NOT_DISTINCT: () => (preflight.distinctChecker = false),
        DEPENDENCY_OPEN: () => (preflight.dependencyClosed = false),
        SIMULATION_FAILED: () => (preflight.simulationSuccessful = false),
        SUPPLY_CHAIN_INVALID: () => (preflight.supplyChainValid = false),
        DELEGATION_EPOCH_STALE: () => (preflight.delegationEpoch = 9n),
      };
      lifecycleMutations[mutation]?.();
      const transitioned = transitionModule(
        {
          state: ownerInput.currentState,
          aggregateVersion: BigInt(ownerInput.aggregateVersion),
          manifestDigest: ownerInput.currentManifestDigest,
          authorityEpoch: BigInt(ownerInput.authorityEpoch),
          delegationEpoch: BigInt(ownerInput.delegationEpoch),
        },
        ownerInput.operation,
        ownerInput.targetManifestDigest,
        preflight,
      );
      accepted = transitioned.state === 'ENABLED';
      actualEvidence = transitioned;
    } else if (row.targetSectionId === 'MOD-MANIFEST') {
      behaviorId = `module-admission:${authority.oracleId}`;
      const ownerInput = plan.productInput.ownerInput;
      if (ownerInput.kind !== 'MODULE_ADMISSION_INPUT') throw new Error('owner input mismatch');
      const envelope = traceAdmissionEnvelope(
        ownerInput.supplyChainPayloadDigest,
        Buffer.from(plan.semanticInputDigest, 'hex'),
      );
      if (sha256(envelope.manifestBytes) !== ownerInput.manifestPayloadDigest)
        throw new Error('manifest semantic payload mismatch');
      if (mutation === 'SIGNER_REVOKED') envelope.signerState = 'REVOKED';
      if (mutation === 'SIGNER_UNKNOWN') envelope.signerState = 'EXPIRED';
      if (mutation === 'MANIFEST_DIGEST_MISMATCH')
        envelope.manifestDigest = plan.concreteInputDigest;
      if (mutation === 'SIGNATURE_INVALID') envelope.signatureP1363 = Buffer.alloc(64);
      if (mutation === 'SBOM_DIGEST_MISMATCH') envelope.sbomDigest = plan.semanticInputDigest;
      if (mutation === 'PROVENANCE_DIGEST_MISMATCH')
        envelope.provenanceDigest = plan.semanticInputDigest;
      if (mutation === 'BUILD_RECEIPT_DIGEST_MISMATCH')
        envelope.buildReceiptDigest = plan.semanticInputDigest;
      if (mutation === 'MANIFEST_EMPTY') envelope.manifestBytes = Buffer.alloc(0);
      const admitted = verifyModuleAdmission(envelope);
      accepted = admitted.manifestDigest === envelope.manifestDigest;
      actualEvidence = admitted;
    } else if (row.targetSectionId === 'MOD-SIMULATION') {
      behaviorId = `typescript-policy-simulation:${authority.oracleId}`;
      const ownerInput = plan.productInput.ownerInput;
      if (ownerInput.kind !== 'TYPESCRIPT_SIMULATION_INPUT')
        throw new Error('owner input mismatch');
      const input = context([
        {
          ...contribution(`pc.trace.${token}`, 1, 'ALLOW', [`permission:${token}`]),
          obligations: [
            ...plan.productInput.decisionDigests,
            ...plan.productInput.sourceDigests,
            ...plan.productInput.claimDigests,
            plan.productInput.negativeBehaviorDigest,
            plan.productInput.closureDigest,
          ],
          manifestDigest: plan.concreteInputDigest,
          schemaDigest: plan.concreteInputDigest,
          generationDigest: plan.semanticInputDigest,
          selectorDigest: plan.productInput.requirementDigest,
        },
      ]);
      input.request.actionIntentId = ownerInput.actionIntentId;
      input.request.currentActionIntentId = input.request.actionIntentId;
      input.request.scopeDigest = ownerInput.scopeDigest;
      input.request.currentScopeDigest = input.request.scopeDigest;
      input.request.resourceDigest = ownerInput.resourceDigest;
      input.request.currentResourceDigest = input.request.resourceDigest;
      input.simulation.scenarioId = ownerInput.scenarioId;
      input.simulation.currentScenarioId = input.simulation.scenarioId;
      input.simulation.routeDigest = ownerInput.routeDigest;
      input.simulation.currentRouteDigest = input.simulation.routeDigest;
      input.versions.policyGenerationDigest = ownerInput.policyGenerationDigest;
      input.versions.currentPolicyGenerationDigest = ownerInput.policyGenerationDigest;
      input.versions.schemaDigest = ownerInput.schemaDigest;
      input.versions.currentSchemaDigest = ownerInput.schemaDigest;
      input.completeness.selectorDigest = ownerInput.selectorDigest;
      input.completeness.currentSelectorDigest = ownerInput.selectorDigest;
      if (mutation === 'INCOMPLETE_INPUT') input.completeness.complete = false;
      if (mutation === 'AUTHORITY_EPOCH_STALE') input.epochs.currentAuthority = 99n;
      if (mutation === 'PLATFORM_TERMINAL_DENY') input.platformTerminalDeny = true;
      if (mutation === 'UNSUPPORTED_SEMANTICS') input.contributions[0]!.unsupportedSemantics = true;
      if (mutation === 'SCENARIO_SUBSTITUTION')
        input.simulation.currentScenarioId = 'trace:substituted';
      if (mutation === 'CHECKPOINT_GENERATION_STALE')
        input.versions.currentCheckpointGenerationDigest = plan.semanticInputDigest;
      if (mutation === 'ROUTE_MISMATCH')
        input.simulation.currentRouteDigest = plan.concreteInputDigest;
      if (mutation === 'DISCLOSURE_INCOMPLETE') input.completeness.disclosureComplete = false;
      const result = simulatePolicy(input);
      accepted = result.truthState === 'SUCCESS' && result.authority === 'SIMULATION_ONLY';
      actualEvidence = result;
    } else throw new Error(`No TypeScript harness owner for ${row.traceId}`);
  } catch (error) {
    if (acceptedBySemantics) throw error;
    accepted = false;
  }
  if (accepted !== acceptedBySemantics)
    throw new Error(`trace owner result mismatch: ${row.traceId}`);
  const actualEvidenceJson = JSON.stringify(actualEvidence, (_key, value: unknown) =>
    typeof value === 'bigint' ? value.toString() : value,
  );
  if (acceptedBySemantics) {
    zeroEffectAfterDigest = sha256({ zeroEffectBeforeDigest, accepted, actualEvidenceJson });
  }
  return {
    traceId: row.traceId,
    owner: plan.declaredOwner,
    behaviorId,
    outcome: plan.productAssertion.outcome,
    authorityEffect: plan.productAssertion.authorityEffect,
    authorityOracleDigest: authority.oracleDigest,
    semanticInputDigest: plan.semanticInputDigest,
    concreteInputDigest: plan.concreteInputDigest,
    behavioralEvidenceDigest: sha256({
      traceId: row.traceId,
      owner: plan.declaredOwner,
      semanticRecordDigest: plan.recordDigest,
      productInput: plan.productInput,
      accepted,
      actualEvidenceJson,
    }),
    ownerRuntime: plan.declaredRuntime,
    zeroEffectBeforeDigest,
    zeroEffectAfterDigest,
  };
}

describe('I03 seven frozen implementation gate classes', () => {
  it('G1 validates the complete 33-manifest exact dependency closure', async () => {
    const registry = await readJson('module-registry.json');
    const modules = registry.modules as Array<{
      moduleId: string;
      manifestPath: string;
      manifestSha256: string;
    }>;
    const edges = installEdges.map((edge) => {
      const provider = modules.find((item) => item.moduleId === edge.from)!;
      return {
        edgeId: edge.edgeId,
        consumerModuleId: edge.to,
        providerModuleId: edge.from,
        capabilityId: `urn:openpc:install-edge:${edge.edgeId}`,
        semanticVersion: '1.0.0',
        providerManifestDigest: provider.manifestSha256,
      };
    });
    const nodes: ModuleNode[] = modules.map((item) => ({
      moduleId: item.moduleId,
      semanticVersion: '1.0.0',
      manifestDigest: item.manifestSha256,
      capabilities: edges
        .filter((edge) => edge.providerModuleId === item.moduleId)
        .map((edge) => edge.capabilityId),
    }));
    const result = resolveDependencies(nodes, edges);
    expect(edges).toHaveLength(69);
    expect(result.order).toHaveLength(33);
    expect(new Set(result.order)).toEqual(new Set(installOrder));
    const positions = new Map(result.order.map((moduleId, index) => [moduleId, index]));
    for (const edge of installEdges)
      expect(positions.get(edge.from)!, edge.edgeId).toBeLessThan(positions.get(edge.to)!);
    expect(result.closureDigest).toMatch(/^[0-9a-f]{64}$/);
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const manifest = Buffer.from('local-i03-manifest');
    const sidecar = Buffer.from('local-sidecar');
    const envelope = {
      manifestBytes: manifest,
      manifestDigest: sha256(manifest),
      signatureP1363: sign('sha256', manifest, { key: privateKey, dsaEncoding: 'ieee-p1363' }),
      signerPublicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      signerState: 'ACTIVE' as const,
      sbomBytes: sidecar,
      sbomDigest: sha256(sidecar),
      provenanceBytes: sidecar,
      provenanceDigest: sha256(sidecar),
      buildReceiptBytes: sidecar,
      buildReceiptDigest: sha256(sidecar),
    };
    expect(verifyModuleAdmission(envelope).manifestDigest).toBe(envelope.manifestDigest);
    expect(() => verifyModuleAdmission({ ...envelope, signerState: 'REVOKED' })).toThrowError(
      ContractError,
    );
  });

  it('G2 rejects all 264 registered negative fixtures with exact error and no authority effect', async () => {
    const fixtures = await readJson('module-conformance-fixtures.json');
    const cases = fixtures.negativeCases as Array<{
      caseId: string;
      profile: string;
      targetModuleId: string;
      expectedError: string;
      expectedAuthorityEffect: string;
    }>;
    expect(cases).toHaveLength(264);
    const registry = await readJson('module-registry.json');
    const modules = registry.modules as Array<{
      moduleId: string;
      manifestSha256: string;
    }>;
    const execute = (item: (typeof cases)[number]) => {
      const target = modules.find((module) => module.moduleId === item.targetModuleId)!;
      const capabilityId = `negative:${item.caseId}`;
      if (['ACTIVE_DEPENDENT', 'UNCLOSED_DATA_CUSTODY'].includes(item.profile)) {
        const aggregate = {
          state: 'INSTALLED_DISABLED' as const,
          aggregateVersion: 1n,
          manifestDigest: target.manifestSha256,
          authorityEpoch: 1n,
          delegationEpoch: 1n,
        };
        transitionModule(aggregate, 'UNINSTALL', target.manifestSha256, {
          expectedVersion: 1n,
          authorityEpoch: 1n,
          delegationEpoch: 1n,
          approvalValid: true,
          distinctChecker: true,
          dependencyClosed: true,
          custodyClosed: item.profile !== 'UNCLOSED_DATA_CUSTODY',
          activeDependents: item.profile === 'ACTIVE_DEPENDENT' ? 1 : 0,
          simulationSuccessful: true,
          supplyChainValid: true,
        });
        return;
      }
      const provider: ModuleNode = {
        moduleId: 'pc.fixture.provider',
        semanticVersion: '1.0.0',
        manifestDigest: digest('c'),
        capabilities: [capabilityId],
        future: item.profile === 'FUTURE_HOST_AS_R1',
      };
      const consumer: ModuleNode = {
        moduleId: target.moduleId,
        semanticVersion: '1.0.0',
        manifestDigest: target.manifestSha256,
        capabilities: item.profile === 'CYCLE' ? [capabilityId] : [],
      };
      if (item.profile === 'CYCLE') {
        resolveDependencies(
          [consumer],
          [
            {
              edgeId: item.caseId,
              consumerModuleId: consumer.moduleId,
              providerModuleId: consumer.moduleId,
              capabilityId,
              semanticVersion: consumer.semanticVersion,
              providerManifestDigest: consumer.manifestDigest,
            },
          ],
        );
        return;
      }
      const nodes = item.profile === 'MISSING_DEPENDENCY' ? [consumer] : [provider, consumer];
      const dependencies = [
        {
          edgeId: item.caseId,
          consumerModuleId: consumer.moduleId,
          providerModuleId: provider.moduleId,
          capabilityId,
          semanticVersion: item.profile === 'INCOMPATIBLE_VERSION' ? '2.0.0' : '1.0.0',
          providerManifestDigest:
            item.profile === 'DIGEST_MISMATCH' ? digest('d') : provider.manifestDigest,
        },
      ];
      if (item.profile === 'CONFLICTING_PROVIDER') {
        const second = { ...provider, moduleId: 'pc.fixture.provider-two' };
        resolveDependencies(
          [provider, second, consumer],
          [
            ...dependencies,
            { ...dependencies[0], edgeId: `${item.caseId}:2`, providerModuleId: second.moduleId },
          ],
        );
      } else resolveDependencies(nodes, dependencies);
    };
    for (const item of cases) {
      let code = 'NO_ERROR';
      try {
        execute(item as (typeof cases)[number] & { targetModuleId: string; caseId: string });
      } catch (error) {
        code = error instanceof ContractError ? error.code : 'UNEXPECTED_ERROR';
      }
      expect(code, item.caseId).toBe(item.expectedError);
      expect(errorForNegativeProfile(item.profile).code).toBe(item.expectedError);
      expect(item.expectedAuthorityEffect).toBe('NONE');
    }
  });

  it('G3 enforces exact lifecycle, optimistic version, dependency, custody, epochs and maker-checker preflight', () => {
    const aggregate = {
      state: 'INSTALLED_DISABLED' as const,
      aggregateVersion: 1n,
      manifestDigest: 'aa',
      authorityEpoch: 2n,
      delegationEpoch: 3n,
    };
    const preflight = {
      expectedVersion: 1n,
      authorityEpoch: 2n,
      delegationEpoch: 3n,
      approvalValid: true,
      distinctChecker: true,
      dependencyClosed: true,
      custodyClosed: true,
      activeDependents: 0,
      simulationSuccessful: true,
      supplyChainValid: true,
    };
    expect(transitionModule(aggregate, 'ENABLE', 'bb', preflight)).toEqual({
      ...aggregate,
      state: 'ENABLED',
      manifestDigest: 'bb',
      aggregateVersion: 2n,
    });
    expect(() => transitionModule(aggregate, 'UPGRADE', 'bb', preflight)).toThrowError(
      ContractError,
    );
  });

  it('G4 composes deterministically by priority/identity and intersects permissions', () => {
    const values = [
      contribution('pc.b', 2, 'ALLOW', ['read', 'write']),
      contribution('pc.a', 1, 'ALLOW', ['read']),
    ];
    const forward = evaluatePolicy(context(values));
    const reverse = evaluatePolicy(context([...values].reverse()));
    expect(forward).toEqual(reverse);
    expect(forward.permissions).toEqual(['read']);
    expect(forward.truthState).toBe('SUCCESS');
  });

  it('G5 fails closed on native denial and contradictory peer contribution', () => {
    expect(
      evaluatePolicy(
        context([contribution('pc.a', 1, 'ALLOW', ['read']), contribution('pc.b', 2, 'DENY', [])]),
      ).truthState,
    ).toBe('DENIED');
    const conflict = evaluatePolicy(
      context([
        contribution('pc.a', 1, 'ALLOW', ['read'], 'same'),
        contribution('pc.b', 2, 'DENY', [], 'same'),
      ]),
    );
    expect(conflict.truthState).toBe('CONFLICTING');
    expect(conflict.permissions).toEqual([]);
    expect(conflict.explanationCodes).toContain('PC-POLICY-2001');
  });

  it('G5 rejects every stale, mixed, incomplete, type, obligation and conflict binding', () => {
    const baseline = context([contribution('pc.a', 1, 'ALLOW', ['read'])]);
    const mutations: Array<[string, (value: EvaluationContext) => void]> = [
      ['platform epoch', (value) => (value.epochs.currentPlatform = 99n)],
      ['participant epoch', (value) => (value.epochs.currentParticipant = 99n)],
      ['authority epoch', (value) => (value.epochs.currentAuthority = 99n)],
      ['delegation epoch', (value) => (value.epochs.currentDelegation = 99n)],
      ['assignment epoch', (value) => (value.epochs.currentAssignment = 99n)],
      ['credential epoch', (value) => (value.epochs.currentCredential = 99n)],
      ['participant', (value) => (value.identities.currentParticipantId = 'other')],
      ['privacy domain', (value) => (value.identities.currentPrivacyDomainId = 'other')],
      ['actor', (value) => (value.identities.currentActorId = 'other')],
      ['workload', (value) => (value.identities.currentWorkloadId = 'other')],
      ['wallet', (value) => (value.identities.currentWalletId = 'other')],
      ['assignment', (value) => (value.identities.currentAssignmentId = 'other')],
      ['action', (value) => (value.request.currentActionIntentId = 'other')],
      ['scope', (value) => (value.request.currentScopeDigest = digest('f'))],
      ['resource id', (value) => (value.request.currentResourceId = 'other')],
      ['resource digest', (value) => (value.request.currentResourceDigest = digest('f'))],
      ['scenario', (value) => (value.simulation.currentScenarioId = 'other')],
      ['request identity', (value) => (value.simulation.currentRequestId = 'other')],
      ['chain', (value) => (value.simulation.currentChainId = 'other')],
      ['route', (value) => (value.simulation.currentRouteDigest = digest('f'))],
      [
        'disclosure capabilities',
        (value) => (value.simulation.currentDisclosureCapabilities = ['RESULT']),
      ],
      ['envelope', (value) => (value.versions.currentParticipantEnvelopeDigest = digest('f'))],
      ['policy version', (value) => (value.versions.currentPolicyVersionDigest = digest('0'))],
      ['release', (value) => (value.versions.currentPolicyReleaseDigest = digest('f'))],
      ['generation', (value) => (value.versions.currentPolicyGenerationDigest = digest('f'))],
      ['fact generation', (value) => (value.versions.currentFactGenerationDigest = digest('f'))],
      [
        'provider generation',
        (value) => (value.versions.currentProviderGenerationDigest = digest('f')),
      ],
      [
        'checkpoint generation',
        (value) => (value.versions.currentCheckpointGenerationDigest = digest('f')),
      ],
      ['dependency', (value) => (value.versions.currentDependencyClosureDigest = digest('f'))],
      ['schema', (value) => (value.versions.currentSchemaDigest = digest('f'))],
      ['type registry', (value) => (value.versions.currentTypeRegistryDigest = digest('f'))],
      [
        'module manifest set',
        (value) => (value.versions.currentModuleManifestSetDigest = digest('f')),
      ],
      ['stack profile', (value) => (value.versions.currentStackProfileDigest = digest('f'))],
      [
        'selector completeness',
        (value) => (value.completeness.currentSelectorDigest = digest('f')),
      ],
      ['window completeness', (value) => (value.completeness.currentWindowDigest = digest('f'))],
      ['obligation', (value) => (value.completeness.currentObligationDigest = digest('f'))],
      ['incomplete', (value) => (value.completeness.complete = false)],
      ['selector incomplete', (value) => (value.completeness.selectorComplete = false)],
      ['window incomplete', (value) => (value.completeness.windowComplete = false)],
      ['obligation incomplete', (value) => (value.completeness.obligationComplete = false)],
      ['fact incomplete', (value) => (value.completeness.factComplete = false)],
      ['checkpoint incomplete', (value) => (value.completeness.checkpointComplete = false)],
      ['provider incomplete', (value) => (value.completeness.providerComplete = false)],
      [
        'module manifest incomplete',
        (value) => (value.completeness.moduleManifestComplete = false),
      ],
      ['route incomplete', (value) => (value.completeness.routeComplete = false)],
      ['disclosure incomplete', (value) => (value.completeness.disclosureComplete = false)],
      ['compatibility incomplete', (value) => (value.completeness.compatibilityComplete = false)],
      ['input type', (value) => (value.contributions[0]!.inputType = 'WRONG')],
      ['output type', (value) => (value.contributions[0]!.outputType = 'WRONG')],
      ['contribution schema', (value) => (value.contributions[0]!.schemaDigest = digest('f'))],
      [
        'contribution generation',
        (value) => (value.contributions[0]!.generationDigest = digest('f')),
      ],
      ['contribution selector', (value) => (value.contributions[0]!.selectorDigest = digest('f'))],
      ['unsupported semantics', (value) => (value.contributions[0]!.unsupportedSemantics = true)],
      ['broader delegation', (value) => (value.contributions[0]!.broaderDelegation = true)],
      ['future dependency', (value) => (value.contributions[0]!.futureDependency = true)],
      ['missing bridge', (value) => (value.contributions[0]!.missingBridge = true)],
    ];
    for (const [name, mutate] of mutations) {
      const value = structuredClone(baseline);
      mutate(value);
      expect(evaluatePolicy(value).truthState, name).not.toBe('SUCCESS');
    }
    const obligationConflict = context([
      contribution('pc.a', 1, 'ALLOW', ['read'], 'same'),
      { ...contribution('pc.b', 2, 'ALLOW', ['read'], 'same'), obligations: ['STEP_UP'] },
    ]);
    expect(evaluatePolicy(obligationConflict).truthState).toBe('CONFLICTING');
    expect(evaluatePolicy(context([])).truthState).toBe('AUTHORIZED_EMPTY');
    const incompleteEmpty = context([]);
    incompleteEmpty.completeness.complete = false;
    expect(evaluatePolicy(incompleteEmpty).truthState).toBe('PARTIAL');
    expect(() =>
      evaluatePolicy({ ...baseline, unknownNormativeField: 'forbidden' } as EvaluationContext),
    ).toThrow();
    expect(() =>
      evaluatePolicy({
        ...baseline,
        simulation: { ...baseline.simulation, unknownSimulationField: 'forbidden' },
      } as EvaluationContext),
    ).toThrow();
  });

  it('G6 simulation is labelled and byte-equivalent to the shared pure evaluator', () => {
    const input = context([contribution('pc.a', 1, 'ALLOW', ['read'])]);
    const authoritative = evaluatePolicy(input);
    const simulated = simulatePolicy(input);
    expect(simulated).toEqual({ ...authoritative, authority: 'SIMULATION_ONLY' });
    expect(simulated.inputBytes).toEqual(authoritative.inputBytes);
    expect(simulated.resultBytes).toEqual(authoritative.resultBytes);
    expect(simulated.inputDigest).toBe(authoritative.inputDigest);
    expect(simulated.resultDigest).toBe(authoritative.resultDigest);
    expect(simulated.evaluatorIdentity).toBe('PC-POLICY-EVALUATOR-1/PC-CBOR-1');
    expect(Object.isFrozen(simulated)).toBe(true);
  });

  it('G7 binds immutable version, fresh distinct approval, successful simulation and generated atomic SQL barriers', async () => {
    const version = createImmutableVersion(
      '00000000-0000-7000-8000-000000000010',
      1,
      { effect: 'ALLOW' },
      'maker',
    );
    const simulation = {
      ...simulatePolicy(context([contribution('pc.a', 1, 'ALLOW', ['read'])])),
      inputDigest: '55'.repeat(32),
    };
    const release = releasePolicy(
      version,
      {
        subjectDigest: version.semanticDigest,
        makerPrincipalId: 'maker',
        checkerPrincipalId: 'checker',
        expiresAt: new Date('2030-01-01T00:00:00Z'),
        approved: true,
      },
      simulation,
      '66'.repeat(32),
      new Date('2029-01-01T00:00:00Z'),
    );
    expect(release.state).toBe('DESIRED');
    const sql = await readFile(
      path.join(root, 'migrations/postgres/policy/0000_yummy_plazm.sql'),
      'utf8',
    );
    expect(sql).toContain('policy_activation_prerequisite');
    expect(sql).toContain('privacy_domain_isolation');
    const store = await readFile(
      path.join(root, 'services/module-registry/src/db/policy-store.ts'),
      'utf8',
    );
    for (const token of [
      'begin isolation level serializable',
      'control.idempotency_record',
      'control.mutation_evidence',
      'control.outbox_event',
      'commit',
    ])
      expect(store).toContain(token);
  });
});

describe('I03 5470-row trace denominator', () => {
  it('authenticates all typed semantics and dispatches every row to its exact runtime suite', async () => {
    const rows = (await readFile(path.join(generated, 'module-traceability.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const authorityCatalogBytes = await readFile(
      path.join(generated, 'module-trace-authority-catalog.json'),
    );
    const authorityCatalog = JSON.parse(
      authorityCatalogBytes.toString('utf8'),
    ) as TraceAuthorityCatalog;
    const behaviorOracleBytes = await readFile(
      path.join(generated, 'module-trace-behavior-oracles.jsonl'),
    );
    const behaviorOracles = new Map(
      behaviorOracleBytes
        .toString('utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line) as TraceBehaviorOracle)
        .map((oracle) => [oracle.traceId, oracle]),
    );
    const semanticCorpusBytes = await readFile(
      path.join(generated, 'module-trace-semantic-corpus.jsonl'),
    );
    const semanticRecords = new Map(
      semanticCorpusBytes
        .toString('utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line) as TraceSemanticRecord)
        .map((record) => [record.traceId, record]),
    );
    const corpusManifest = (await readJson('module-trace-corpus-manifest.json')) as {
      schemaVersion: string;
      corpusId: string;
      rowCount: number;
      corpusFileSha256: string;
      authorityCatalogFileSha256: string;
      behaviorOracleFileSha256: string;
      orderedRecordDigestAggregateSha256: string;
      orderedOracleDigestAggregateSha256: string;
      rootCommitmentSha256: string;
      frozenAuthoritySources: Record<string, string>;
      recordCommitments: Array<{
        traceId: string;
        recordDigest: string;
        rawRecordSha256: string;
        oracleDigest: string;
        semanticInputDigest: string;
        concreteInputDigest: string;
        componentDigestsSha256: string;
      }>;
      reconstructionCommand: string;
    };
    expect(rows).toHaveLength(5470);
    expect(behaviorOracles.size).toBe(5470);
    expect(semanticRecords.size).toBe(5470);
    expect(corpusManifest.rowCount).toBe(5470);
    expect(corpusManifest.schemaVersion).toBe('2.0');
    expect(corpusManifest.corpusId).toBe('OPENPC-I03-TRACE-SEMANTIC-CORPUS-R8');
    expect(corpusManifest.corpusFileSha256).toBe(sha256(semanticCorpusBytes));
    expect(corpusManifest.authorityCatalogFileSha256).toBe(sha256(authorityCatalogBytes));
    expect(corpusManifest.behaviorOracleFileSha256).toBe(sha256(behaviorOracleBytes));
    expect(corpusManifest.orderedRecordDigestAggregateSha256).toBe(
      sha256([...semanticRecords.values()].map((record) => record.recordDigest).join('\n')),
    );
    expect(corpusManifest.orderedOracleDigestAggregateSha256).toBe(
      sha256([...behaviorOracles.values()].map((oracle) => oracle.oracleDigest).join('\n')),
    );
    const manifestPreimage = structuredClone(corpusManifest) as Record<string, unknown>;
    delete manifestPreimage.rootCommitmentSha256;
    expect(corpusManifest.rootCommitmentSha256).toBe(sha256(manifestPreimage));
    expect(corpusManifest.frozenAuthoritySources).toEqual({
      sourceUnits: '3fbd1d00639aeb3fb1f568942e89ae505b7ac1cf45b2c4aa2faea2c74e70dd29',
      decisions: '397c0becca904297e172141d8bfe18712b255b05d0bd1b3f0f187da15680aae1',
      claimCeilings: 'b9c866b671a06d475fd601a85ecb75789baca0da8e7356fe7b96dd1195fb0858',
      requirements: 'e49a27645e39168fdc6b3aad94cea40de0db496d99bb7b6140595d744fcbcafd',
      closures: '3fed5ae229aca36f2cd9a48f866ae4918e63310c68026578a7becdeb74932f07',
    });
    expect(corpusManifest.recordCommitments).toHaveLength(5470);
    const semanticLines = semanticCorpusBytes.toString('utf8').trim().split('\n');
    for (const [index, commitment] of corpusManifest.recordCommitments.entries()) {
      const record = JSON.parse(semanticLines[index]!) as TraceSemanticRecord;
      const oracle = behaviorOracles.get(record.traceId)!;
      expect(commitment.traceId).toBe(record.traceId);
      expect(commitment.recordDigest).toBe(record.recordDigest);
      expect(commitment.rawRecordSha256).toBe(sha256(semanticLines[index]!));
      expect(commitment.oracleDigest).toBe(oracle.oracleDigest);
      expect(commitment.semanticInputDigest).toBe(record.semanticInputDigest);
      expect(commitment.concreteInputDigest).toBe(record.concreteInputDigest);
      expect(commitment.componentDigestsSha256).toMatch(/^[0-9a-f]{64}$/u);
    }
    expect(corpusManifest.reconstructionCommand).toContain('pnpm --filter @openpc/module-registry');
    const authorityExecutions = new Map<string, TraceAuthorityExecution>();
    for (const row of rows) {
      const obligation = row as unknown as TraceObligation;
      const oracle = behaviorOracles.get(obligation.traceId);
      const semanticRecord = semanticRecords.get(obligation.traceId);
      expect(oracle, obligation.traceId).toBeDefined();
      expect(semanticRecord, obligation.traceId).toBeDefined();
      authorityExecutions.set(
        obligation.traceId,
        executeTraceAuthorityOracle(
          obligation,
          semanticRecord!.semanticDisposition === 'IMPLEMENTATION_REQUIREMENT'
            ? 'IMPLEMENT'
            : 'PRESERVE',
          authorityCatalog,
          oracle!,
          semanticRecord!,
        ),
      );
    }
    const traceIds = new Set<string>();
    const results = new Set<string>();
    const concreteInputs = new Set<string>();
    const behavioralEvidence = new Set<string>();
    let rustNativeExecutions = 0;
    let typescriptExecutions = 0;
    let policyStoreLiveExecutions = 0;
    for (const row of rows) {
      const traceId = String(row.traceId);
      const mapping =
        traceExecutionOwners[row.targetSectionId as keyof typeof traceExecutionOwners];
      expect(mapping, traceId).toBeDefined();
      expect(existsSync(path.join(root, mapping[1])), `${traceId}:${mapping[1]}`).toBe(true);
      expect(mapping[0]).toMatch(/^G[1-7]$/);
      expect(traceIds.has(traceId), traceId).toBe(false);
      traceIds.add(traceId);

      const oracle = behaviorOracles.get(traceId);
      const semanticRecord = semanticRecords.get(traceId)!;
      const acceptedBySemantics =
        semanticRecord.semanticDisposition === 'IMPLEMENTATION_REQUIREMENT';
      expect(oracle, traceId).toBeDefined();
      const authority = authorityExecutions.get(traceId)!;
      expect(authority.requirementStatement.length, traceId).toBeGreaterThan(0);
      expect(authority.decisionResults.length, traceId).toBeGreaterThan(0);
      expect(authority.sourceStatements.length, traceId).toBe(
        (row.sourceUnitIds as string[]).length,
      );
      expect(authority.enforcedClaimRules.length, traceId).toBe(
        (row.claimCeilingIds as string[]).length,
      );
      expect(authority.negativeBehavior, traceId).toBe(row.negativeBehavior);
      expect(semanticRecord.productInput.requirementDigest, traceId).toMatch(/^[0-9a-f]{64}$/u);
      expect(semanticRecord.productInput.decisionDigests.length, traceId).toBe(
        authority.decisionResults.length,
      );
      expect(semanticRecord.productInput.sourceDigests.length, traceId).toBe(
        authority.sourceStatements.length,
      );
      expect(semanticRecord.productInput.claimDigests.length, traceId).toBe(
        authority.enforcedClaimRules.length,
      );
      expect(concreteInputs.has(semanticRecord.concreteInputDigest), traceId).toBe(false);
      concreteInputs.add(semanticRecord.concreteInputDigest);
      if (semanticRecord.declaredRuntime === 'RUST_NATIVE') {
        rustNativeExecutions += 1;
        continue;
      }
      if (
        semanticRecord.targetSectionId === 'MOD-OPERATIONS' ||
        semanticRecord.targetSectionId === 'MOD-PARTICIPANT'
      ) {
        expect(semanticRecord.declaredOwner, traceId).toBe(
          'services/module-registry/src/db/policy-store.ts',
        );
        policyStoreLiveExecutions += 1;
        continue;
      }
      const result = executeDeclaredTraceOwner(row, authority);
      expect(result.traceId, traceId).toBe(traceId);
      expect(result.owner, traceId).toBe(mapping[1]);
      expect(result.authorityEffect, traceId).toBe(semanticRecord.productAssertion.authorityEffect);
      expect(result.behaviorId, traceId).toContain(`ORACLE-${traceId}`);
      expect(result.authorityOracleDigest, traceId).toBe(oracle!.oracleDigest);
      expect(result.outcome, traceId).toBe(semanticRecord.productAssertion.outcome);
      expect(result.semanticInputDigest, traceId).toBe(authority.behaviorPlan.semanticInputDigest);
      expect(result.concreteInputDigest, traceId).toBe(authority.behaviorPlan.concreteInputDigest);
      expect(result.behavioralEvidenceDigest, traceId).toMatch(/^[0-9a-f]{64}$/u);
      expect(result.ownerRuntime, traceId).toBe('TYPESCRIPT');
      if (!acceptedBySemantics)
        expect(result.zeroEffectAfterDigest, traceId).toBe(result.zeroEffectBeforeDigest);
      expect(behavioralEvidence.has(result.behavioralEvidenceDigest), traceId).toBe(false);
      behavioralEvidence.add(result.behavioralEvidenceDigest);
      typescriptExecutions += 1;
      results.add(result.traceId);
    }
    expect(traceIds.size).toBe(5470);
    expect(results.size).toBe(2429);
    expect(concreteInputs.size).toBe(5470);
    expect(behavioralEvidence.size).toBe(2429);
    expect(rustNativeExecutions).toBe(2_619);
    expect(typescriptExecutions).toBe(2_429);
    expect(policyStoreLiveExecutions).toBe(422);
    const first = rows[0] as unknown as TraceObligation;
    const firstOracle: TraceBehaviorOracle = {
      ...structuredClone(behaviorOracles.get(first.traceId)!),
      negativeBehaviorSha256: '00'.repeat(32),
    };
    expect(() =>
      executeTraceAuthorityOracle(
        first,
        semanticRecords.get(first.traceId)!.semanticDisposition === 'IMPLEMENTATION_REQUIREMENT'
          ? 'IMPLEMENT'
          : 'PRESERVE',
        authorityCatalog,
        firstOracle,
        semanticRecords.get(first.traceId)!,
      ),
    ).toThrow('TRACE_AUTHORITY_INVALID');
    const rustRow = rows.find((row) => row.targetSectionId === 'MOD-POLICY') as unknown as
      TraceObligation | undefined;
    expect(rustRow).toBeDefined();
    const rustOracle = behaviorOracles.get(rustRow!.traceId)!;
    const rustRecord = semanticRecords.get(rustRow!.traceId)!;
    const surrogateRecord = {
      ...structuredClone(rustRecord),
      declaredRuntime: 'TYPESCRIPT' as const,
    };
    expect(() =>
      executeTraceAuthorityOracle(
        rustRow!,
        rustRecord.semanticDisposition === 'IMPLEMENTATION_REQUIREMENT' ? 'IMPLEMENT' : 'PRESERVE',
        authorityCatalog,
        rustOracle,
        surrogateRecord,
      ),
    ).toThrow('TRACE_AUTHORITY_INVALID');
    for (const mutate of [
      (record: Mutable<TraceSemanticRecord>) =>
        (record.authority.requirement.statement = 'tampered'),
      (record: Mutable<TraceSemanticRecord>) =>
        (record.authority.decisions[0]!.selectedResult[0] = 'tampered'),
      (record: Mutable<TraceSemanticRecord>) =>
        (record.authority.sources[0]!.statement = 'tampered'),
      (record: Mutable<TraceSemanticRecord>) => (record.authority.claims[0]!.rule = 'tampered'),
      (record: Mutable<TraceSemanticRecord>) =>
        (record.productAssertion.outcome =
          record.productAssertion.outcome === 'ACCEPTED' ? 'REJECTED_FAIL_CLOSED' : 'ACCEPTED'),
    ]) {
      const tampered = structuredClone(
        semanticRecords.get(first.traceId)!,
      ) as Mutable<TraceSemanticRecord>;
      mutate(tampered);
      expect(() =>
        executeTraceAuthorityOracle(
          first,
          tampered.semanticDisposition === 'IMPLEMENTATION_REQUIREMENT' ? 'IMPLEMENT' : 'PRESERVE',
          authorityCatalog,
          behaviorOracles.get(first.traceId)!,
          tampered,
        ),
      ).toThrow('TRACE_AUTHORITY_INVALID');
    }
    const evaluatorBinary = await readFile(
      path.join(root, 'services/policy-compiler/src/bin/openpc-policy-evaluator.rs'),
      'utf8',
    );
    expect(evaluatorBinary).not.toContain('TRACE_OWNER_BATCH');
  }, 120_000);
});
