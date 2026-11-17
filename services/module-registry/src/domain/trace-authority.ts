import { sha256 } from './digest.js';
import { traceExecutionOwners, type TraceObligation } from './trace-obligation.js';

interface AuthorityRecord {
  readonly sourceRecordSha256: string;
}
interface RequirementRecord extends AuthorityRecord {
  readonly requirementId: string;
  readonly normativeStatement: string;
  readonly negativeBehavior: string;
  readonly semanticBundleId: string;
}
interface DecisionRecord extends AuthorityRecord {
  readonly decisionId: string;
  readonly status: string;
  readonly selectedResult: string[];
}
interface SourceUnitRecord extends AuthorityRecord {
  readonly sourceUnitId: string;
  readonly statement: string;
  readonly normativity: TraceSemanticDisposition;
  readonly authorityClass: string;
}
interface ClaimCeilingRecord extends AuthorityRecord {
  readonly claimCeilingId: string;
  readonly binding: boolean;
  readonly rule: string;
}
interface ClosureRecord extends AuthorityRecord {
  readonly requirementId: string;
  readonly closureId: string;
  readonly finalState: string;
  readonly finalNormativeStatement: string;
  readonly negativeBehavior: string;
}

export interface TraceAuthorityCatalog {
  readonly schemaVersion: '2.0';
  readonly catalogId: 'OPENPC-I03-TRACE-AUTHORITY-CATALOG-R7';
  readonly requirements: RequirementRecord[];
  readonly decisions: DecisionRecord[];
  readonly sourceUnits: SourceUnitRecord[];
  readonly claimCeilings: ClaimCeilingRecord[];
  readonly closures: ClosureRecord[];
}

export type TraceSemanticDisposition =
  | 'IMPLEMENTATION_REQUIREMENT'
  | 'OPEN_EVIDENCE_GATE_NOT_READY_FOR_IMPLEMENTATION'
  | 'NEGATIVE_ORACLE_EXCLUDED_BEHAVIOR';
type BehaviorKind =
  | 'DEPENDENCY_RESOLUTION'
  | 'MODULE_LIFECYCLE'
  | 'MODULE_ADMISSION'
  | 'POLICY_ACTIVATION_ARTIFACT'
  | 'PARTICIPANT_ACTIVATION_BINDING'
  | 'NATIVE_POLICY_EVALUATION'
  | 'TYPESCRIPT_SIMULATION';

interface TypedAuthority {
  readonly requirement: {
    readonly requirementId: string;
    readonly statement: string;
    readonly recordSha256: string;
  };
  readonly decisions: readonly {
    readonly decisionId: string;
    readonly selectedResult: readonly string[];
    readonly recordSha256: string;
  }[];
  readonly sources: readonly {
    readonly sourceUnitId: string;
    readonly statement: string;
    readonly normativity: TraceSemanticDisposition;
    readonly recordSha256: string;
  }[];
  readonly claims: readonly {
    readonly claimCeilingId: string;
    readonly rule: string;
    readonly binding: boolean;
    readonly recordSha256: string;
  }[];
  readonly closure: {
    readonly closureId: string;
    readonly finalState: string;
    readonly finalNormativeStatement: string;
    readonly recordSha256: string;
  };
  readonly negativeBehavior: string;
}

export interface TraceProductInput {
  readonly subjectId: string;
  readonly authorityEnvelopeDigest: string;
  readonly requirementDigest: string;
  readonly decisionDigests: readonly string[];
  readonly sourceDigests: readonly string[];
  readonly claimDigests: readonly string[];
  readonly negativeBehaviorDigest: string;
  readonly closureDigest: string;
  readonly ownerInput:
    | {
        readonly kind: 'DEPENDENCY_RESOLUTION_INPUT';
        readonly providerModuleId: string;
        readonly consumerModuleId: string;
        readonly capabilityId: string;
        readonly providerManifestDigest: string;
        readonly consumerManifestDigest: string;
        readonly semanticVersion: '1.0.0';
      }
    | {
        readonly kind: 'MODULE_LIFECYCLE_INPUT';
        readonly operation: 'ENABLE';
        readonly currentState: 'INSTALLED_DISABLED';
        readonly aggregateVersion: '1';
        readonly authorityEpoch: '2';
        readonly delegationEpoch: '3';
        readonly currentManifestDigest: string;
        readonly targetManifestDigest: string;
      }
    | {
        readonly kind: 'MODULE_ADMISSION_INPUT';
        readonly manifestPayloadDigest: string;
        readonly supplyChainPayloadDigest: string;
        readonly signerState: 'ACTIVE';
      }
    | {
        readonly kind: 'POLICY_STORE_ACTIVATION_INPUT';
        readonly semanticFacet: 'OPERATIONS' | 'PARTICIPANT';
        readonly participantId: string;
        readonly privacyDomainId: string;
        readonly checkerPrincipalId: string;
        readonly checkerPrincipalEpoch: '6';
        readonly operationId: 'POL-OP-ACTIVATE';
        readonly actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1';
        readonly candidateDigest: string;
        readonly approvalRequestId: string;
        readonly aggregateId: string;
        readonly expectedAggregateVersion: '1';
        readonly evidenceAuthorityDigest: string;
      }
    | {
        readonly kind: 'NATIVE_POLICY_EVALUATION_INPUT' | 'TYPESCRIPT_SIMULATION_INPUT';
        readonly profileId: string;
        readonly actionIntentId: string;
        readonly scopeDigest: string;
        readonly resourceDigest: string;
        readonly scenarioId: string;
        readonly routeDigest: string;
        readonly policyGenerationDigest: string;
        readonly schemaDigest: string;
        readonly selectorDigest: string;
      };
  readonly mutation: string;
}

export interface TraceSemanticRecord {
  readonly schemaVersion: '2.0';
  readonly traceId: string;
  readonly targetSectionId: TraceObligation['targetSectionId'];
  readonly declaredOwner: string;
  readonly declaredRuntime: 'TYPESCRIPT' | 'RUST_NATIVE';
  readonly behaviorKind: BehaviorKind;
  readonly semanticDisposition: TraceSemanticDisposition;
  readonly authority: TypedAuthority;
  readonly productInput: TraceProductInput;
  readonly productAssertion: {
    readonly outcome: 'ACCEPTED' | 'REJECTED_FAIL_CLOSED';
    readonly authorityEffect: 'R1_AUTHORITY_BOUND' | 'NONE';
    readonly zeroEffectRequired: boolean;
  };
  readonly semanticInputDigest: string;
  readonly concreteInputDigest: string;
  readonly recordDigest: string;
}

export interface TraceBehaviorOracle {
  readonly schemaVersion: '2.0';
  readonly oracleId: string;
  readonly traceId: string;
  readonly requirementId: string;
  readonly requirementRecordSha256: string;
  readonly closureRecordSha256: string;
  readonly decisionRecordSha256s: string[];
  readonly sourceUnitRecordSha256s: string[];
  readonly claimCeilingRecordSha256s: string[];
  readonly normativeStatementSha256: string;
  readonly negativeBehaviorSha256: string;
  readonly exactResult: string;
  readonly action: 'IMPLEMENT' | 'PRESERVE';
  readonly owner: string;
  readonly ownerOutcome: 'ACCEPTED' | 'REJECTED_FAIL_CLOSED';
  readonly authorityEffect: 'R1_AUTHORITY_BOUND' | 'NONE';
  readonly semanticRecordDigest: string;
  readonly oracleDigest: string;
}

export interface TraceAuthorityExecution {
  readonly oracleId: string;
  readonly oracleDigest: string;
  readonly requirementStatement: string;
  readonly decisionResults: string[];
  readonly sourceStatements: string[];
  readonly enforcedClaimRules: string[];
  readonly negativeBehavior: string;
  readonly behaviorPlan: TraceSemanticRecord;
}

const behaviorKinds: Record<TraceObligation['targetSectionId'], BehaviorKind> = {
  'MOD-DEPENDENCY': 'DEPENDENCY_RESOLUTION',
  'MOD-LIFECYCLE': 'MODULE_LIFECYCLE',
  'MOD-MANIFEST': 'MODULE_ADMISSION',
  'MOD-OPERATIONS': 'POLICY_ACTIVATION_ARTIFACT',
  'MOD-PARTICIPANT': 'PARTICIPANT_ACTIVATION_BINDING',
  'MOD-POLICY': 'NATIVE_POLICY_EVALUATION',
  'MOD-SIMULATION': 'TYPESCRIPT_SIMULATION',
};
const mutations: Record<BehaviorKind, readonly string[]> = {
  DEPENDENCY_RESOLUTION: [
    'MISSING_PROVIDER',
    'VERSION_MISMATCH',
    'MANIFEST_MISMATCH',
    'FUTURE_PROVIDER',
    'CAPABILITY_MISMATCH',
    'DUPLICATE_PROVIDER',
    'SELF_DEPENDENCY',
    'CYCLE',
  ],
  MODULE_LIFECYCLE: [
    'VERSION_STALE',
    'AUTHORITY_EPOCH_STALE',
    'APPROVAL_MISSING',
    'CHECKER_NOT_DISTINCT',
    'DEPENDENCY_OPEN',
    'SIMULATION_FAILED',
    'SUPPLY_CHAIN_INVALID',
    'DELEGATION_EPOCH_STALE',
  ],
  MODULE_ADMISSION: [
    'SIGNER_REVOKED',
    'MANIFEST_DIGEST_MISMATCH',
    'SIGNATURE_INVALID',
    'SBOM_DIGEST_MISMATCH',
    'PROVENANCE_DIGEST_MISMATCH',
    'BUILD_RECEIPT_DIGEST_MISMATCH',
    'SIGNER_UNKNOWN',
    'MANIFEST_EMPTY',
  ],
  POLICY_ACTIVATION_ARTIFACT: [
    'RECEIPT_DIGEST_MISMATCH',
    'CANDIDATE_SUBSTITUTION',
    'ACTION_SUBSTITUTION',
    'APPROVAL_SUBSTITUTION',
    'AGGREGATE_SUBSTITUTION',
    'DECISION_SUBSTITUTION',
    'COSE_SIGNATURE_INVALID',
    'EVIDENCE_DIGEST_MISMATCH',
  ],
  PARTICIPANT_ACTIVATION_BINDING: [
    'PARTICIPANT_SUBSTITUTION',
    'CHECKER_SUBSTITUTION',
    'PRINCIPAL_EPOCH_STALE',
    'CREDENTIAL_SUBSTITUTION',
    'CHALLENGE_SUBSTITUTION',
    'PRIVACY_DOMAIN_SUBSTITUTION',
    'ASSIGNMENT_SUBSTITUTION',
    'WEBAUTHN_PROOF_REPLAY',
  ],
  NATIVE_POLICY_EVALUATION: [
    'INCOMPLETE_INPUT',
    'AUTHORITY_EPOCH_STALE',
    'PLATFORM_TERMINAL_DENY',
    'UNSUPPORTED_SEMANTICS',
    'RESOURCE_SUBSTITUTION',
    'PROVIDER_GENERATION_STALE',
    'DISCLOSURE_MISMATCH',
    'OBLIGATION_INCOMPLETE',
  ],
  TYPESCRIPT_SIMULATION: [
    'INCOMPLETE_INPUT',
    'AUTHORITY_EPOCH_STALE',
    'PLATFORM_TERMINAL_DENY',
    'UNSUPPORTED_SEMANTICS',
    'SCENARIO_SUBSTITUTION',
    'CHECKPOINT_GENERATION_STALE',
    'ROUTE_MISMATCH',
    'DISCLOSURE_INCOMPLETE',
  ],
};
const outcomes = {
  IMPLEMENTATION_REQUIREMENT: {
    outcome: 'ACCEPTED',
    authorityEffect: 'R1_AUTHORITY_BOUND',
    zeroEffectRequired: false,
  },
  OPEN_EVIDENCE_GATE_NOT_READY_FOR_IMPLEMENTATION: {
    outcome: 'REJECTED_FAIL_CLOSED',
    authorityEffect: 'NONE',
    zeroEffectRequired: true,
  },
  NEGATIVE_ORACLE_EXCLUDED_BEHAVIOR: {
    outcome: 'REJECTED_FAIL_CLOSED',
    authorityEffect: 'NONE',
    zeroEffectRequired: true,
  },
} as const;

function mapBy<T>(records: T[], field: keyof T): Map<string, T> {
  return new Map(records.map((record) => [String(record[field]), record]));
}
function exact(left: unknown, right: unknown): boolean {
  return sha256(left) === sha256(right);
}

function ownerInputFor(
  behaviorKind: BehaviorKind,
  obligation: TraceObligation,
  semanticInputDigest: string,
  concreteInputDigest: string,
  digests: {
    requirement: string;
    negativeBehavior: string;
    exactResult: string;
  },
): TraceProductInput['ownerInput'] {
  const token = concreteInputDigest.slice(0, 16);
  if (behaviorKind === 'DEPENDENCY_RESOLUTION')
    return {
      kind: 'DEPENDENCY_RESOLUTION_INPUT',
      providerModuleId: `pc.trace.provider.${token}`,
      consumerModuleId: `pc.trace.consumer.${token}`,
      capabilityId: `trace-capability:${digests.requirement}`,
      providerManifestDigest: semanticInputDigest,
      consumerManifestDigest: concreteInputDigest,
      semanticVersion: '1.0.0',
    };
  if (behaviorKind === 'MODULE_LIFECYCLE')
    return {
      kind: 'MODULE_LIFECYCLE_INPUT',
      operation: 'ENABLE',
      currentState: 'INSTALLED_DISABLED',
      aggregateVersion: '1',
      authorityEpoch: '2',
      delegationEpoch: '3',
      currentManifestDigest: semanticInputDigest,
      targetManifestDigest: concreteInputDigest,
    };
  if (behaviorKind === 'MODULE_ADMISSION')
    return {
      kind: 'MODULE_ADMISSION_INPUT',
      manifestPayloadDigest: sha256(Buffer.from(semanticInputDigest, 'hex')),
      supplyChainPayloadDigest: concreteInputDigest,
      signerState: 'ACTIVE',
    };
  if (
    behaviorKind === 'POLICY_ACTIVATION_ARTIFACT' ||
    behaviorKind === 'PARTICIPANT_ACTIVATION_BINDING'
  )
    return {
      kind: 'POLICY_STORE_ACTIVATION_INPUT',
      semanticFacet: behaviorKind === 'POLICY_ACTIVATION_ARTIFACT' ? 'OPERATIONS' : 'PARTICIPANT',
      participantId: '018f0000-0000-7000-8000-000000000901',
      privacyDomainId: '018f0000-0000-7000-8000-000000000902',
      checkerPrincipalId: '018f0000-0000-7000-8000-000000000904',
      checkerPrincipalEpoch: '6',
      operationId: 'POL-OP-ACTIVATE',
      actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
      candidateDigest: concreteInputDigest,
      approvalRequestId: `00000000-0000-7000-8000-${concreteInputDigest.slice(0, 12)}`,
      aggregateId: `00000000-0000-7000-8000-${concreteInputDigest.slice(12, 24)}`,
      expectedAggregateVersion: '1',
      evidenceAuthorityDigest: semanticInputDigest,
    };
  return {
    kind:
      behaviorKind === 'NATIVE_POLICY_EVALUATION'
        ? 'NATIVE_POLICY_EVALUATION_INPUT'
        : 'TYPESCRIPT_SIMULATION_INPUT',
    profileId: `trace:${obligation.requirementId}:${concreteInputDigest}`,
    actionIntentId: `ACT-TRACE-${obligation.requirementId}`,
    scopeDigest: digests.requirement,
    resourceDigest: digests.exactResult,
    scenarioId: `trace:${obligation.traceId}`,
    routeDigest: digests.negativeBehavior,
    policyGenerationDigest: semanticInputDigest,
    schemaDigest: concreteInputDigest,
    selectorDigest: digests.requirement,
  };
}

function deriveSemanticRecord(
  obligation: TraceObligation,
  catalog: TraceAuthorityCatalog,
): TraceSemanticRecord {
  const requirements = mapBy(catalog.requirements, 'requirementId');
  const decisions = mapBy(catalog.decisions, 'decisionId');
  const sources = mapBy(catalog.sourceUnits, 'sourceUnitId');
  const claims = mapBy(catalog.claimCeilings, 'claimCeilingId');
  const closures = mapBy(catalog.closures, 'requirementId');
  const requirement = requirements.get(obligation.requirementId);
  const closure = closures.get(obligation.requirementId);
  const decisionRecords = obligation.decisionIds.map((id) => decisions.get(id));
  const sourceRecords = obligation.sourceUnitIds.map((id) => sources.get(id));
  const claimRecords = obligation.claimCeilingIds.map((id) => claims.get(id));
  if (
    requirement === undefined ||
    closure === undefined ||
    decisionRecords.some((record) => record === undefined) ||
    sourceRecords.some((record) => record === undefined) ||
    claimRecords.some((record) => record === undefined)
  )
    throw new Error('TRACE_AUTHORITY_INVALID');
  const resolvedDecisions = decisionRecords as DecisionRecord[];
  const resolvedSources = sourceRecords as SourceUnitRecord[];
  const resolvedClaims = claimRecords as ClaimCeilingRecord[];
  const semanticDispositions = [...new Set(resolvedSources.map((record) => record.normativity))];
  if (
    semanticDispositions.length !== 1 ||
    !(semanticDispositions[0]! in outcomes) ||
    requirement.negativeBehavior !== obligation.negativeBehavior ||
    requirement.semanticBundleId !== obligation.semanticBundleId ||
    closure.finalNormativeStatement !== requirement.normativeStatement ||
    closure.negativeBehavior !== obligation.negativeBehavior ||
    !obligation.closureIds.includes(closure.closureId) ||
    resolvedDecisions.some(
      (record) => !record.status.startsWith('ACCEPTED') || record.selectedResult.length === 0,
    ) ||
    resolvedSources.some(
      (record) => record.statement.length === 0 || record.authorityClass.length === 0,
    ) ||
    resolvedClaims.some((record) => !record.binding || record.rule.length === 0)
  )
    throw new Error('TRACE_AUTHORITY_INVALID');
  const semanticDisposition = semanticDispositions[0]!;
  const authority: TypedAuthority = {
    requirement: {
      requirementId: requirement.requirementId,
      statement: requirement.normativeStatement,
      recordSha256: requirement.sourceRecordSha256,
    },
    decisions: resolvedDecisions.map((record) => ({
      decisionId: record.decisionId,
      selectedResult: record.selectedResult,
      recordSha256: record.sourceRecordSha256,
    })),
    sources: resolvedSources.map((record) => ({
      sourceUnitId: record.sourceUnitId,
      statement: record.statement,
      normativity: record.normativity,
      recordSha256: record.sourceRecordSha256,
    })),
    claims: resolvedClaims.map((record) => ({
      claimCeilingId: record.claimCeilingId,
      rule: record.rule,
      binding: record.binding,
      recordSha256: record.sourceRecordSha256,
    })),
    closure: {
      closureId: closure.closureId,
      finalState: closure.finalState,
      finalNormativeStatement: closure.finalNormativeStatement,
      recordSha256: closure.sourceRecordSha256,
    },
    negativeBehavior: obligation.negativeBehavior,
  };
  const componentDigests = {
    requirement: sha256(requirement.normativeStatement),
    decisions: resolvedDecisions.flatMap((record) => record.selectedResult).map(sha256),
    sources: resolvedSources.map((record) => sha256(record.statement)),
    claims: resolvedClaims.map((record) => sha256(record.rule)),
    negativeBehavior: sha256(obligation.negativeBehavior),
    exactResult: sha256(obligation.finalClosureState),
  };
  const semanticInputDigest = sha256(authority);
  const declaredOwner = traceExecutionOwners[obligation.targetSectionId][1];
  const declaredRuntime: TraceSemanticRecord['declaredRuntime'] =
    obligation.targetSectionId === 'MOD-POLICY' ? 'RUST_NATIVE' : 'TYPESCRIPT';
  const behaviorKind = behaviorKinds[obligation.targetSectionId];
  const concreteInputDigest = sha256({
    traceId: obligation.traceId,
    owner: declaredOwner,
    semanticInputDigest,
    componentDigests,
  });
  const productInput: TraceProductInput = {
    subjectId: obligation.traceId,
    authorityEnvelopeDigest: semanticInputDigest,
    requirementDigest: componentDigests.requirement,
    decisionDigests: componentDigests.decisions,
    sourceDigests: componentDigests.sources,
    claimDigests: componentDigests.claims,
    negativeBehaviorDigest: componentDigests.negativeBehavior,
    closureDigest: componentDigests.exactResult,
    ownerInput: ownerInputFor(
      behaviorKind,
      obligation,
      semanticInputDigest,
      concreteInputDigest,
      componentDigests,
    ),
    mutation:
      semanticDisposition === 'IMPLEMENTATION_REQUIREMENT'
        ? 'NONE'
        : mutations[behaviorKind][Number.parseInt(concreteInputDigest.slice(0, 8), 16) % 8]!,
  };
  const preimage = {
    traceId: obligation.traceId,
    targetSectionId: obligation.targetSectionId,
    declaredOwner,
    declaredRuntime,
    behaviorKind,
    semanticDisposition,
    authority,
    productInput,
    productAssertion: outcomes[semanticDisposition],
    semanticInputDigest,
    concreteInputDigest,
  };
  return Object.freeze({ schemaVersion: '2.0', ...preimage, recordDigest: sha256(preimage) });
}

/** Authenticates and resolves one immutable typed semantic trace into its exact owner plan. */
export function executeTraceAuthorityOracle(
  obligation: TraceObligation,
  action: 'IMPLEMENT' | 'PRESERVE',
  catalog: TraceAuthorityCatalog,
  oracle: TraceBehaviorOracle,
  suppliedRecord: TraceSemanticRecord,
): TraceAuthorityExecution {
  if (
    catalog.schemaVersion !== '2.0' ||
    catalog.catalogId !== 'OPENPC-I03-TRACE-AUTHORITY-CATALOG-R7' ||
    oracle.schemaVersion !== '2.0'
  )
    throw new Error('TRACE_AUTHORITY_INVALID');
  const record = deriveSemanticRecord(obligation, catalog);
  const expectedAction =
    record.semanticDisposition === 'IMPLEMENTATION_REQUIREMENT' ? 'IMPLEMENT' : 'PRESERVE';
  if (
    action !== expectedAction ||
    !exact(suppliedRecord, record) ||
    suppliedRecord.recordDigest !== record.recordDigest ||
    oracle.oracleId !== `ORACLE-${obligation.traceId}` ||
    oracle.traceId !== obligation.traceId ||
    oracle.requirementId !== obligation.requirementId ||
    oracle.action !== expectedAction ||
    oracle.exactResult !== obligation.finalClosureState ||
    oracle.owner !== record.declaredOwner ||
    oracle.ownerOutcome !== record.productAssertion.outcome ||
    oracle.authorityEffect !== record.productAssertion.authorityEffect ||
    oracle.semanticRecordDigest !== record.recordDigest
  )
    throw new Error('TRACE_AUTHORITY_INVALID');
  const preimage = {
    traceId: oracle.traceId,
    requirementId: oracle.requirementId,
    requirementRecordSha256: oracle.requirementRecordSha256,
    closureRecordSha256: oracle.closureRecordSha256,
    decisionRecordSha256s: oracle.decisionRecordSha256s,
    sourceUnitRecordSha256s: oracle.sourceUnitRecordSha256s,
    claimCeilingRecordSha256s: oracle.claimCeilingRecordSha256s,
    normativeStatementSha256: oracle.normativeStatementSha256,
    negativeBehaviorSha256: oracle.negativeBehaviorSha256,
    exactResult: oracle.exactResult,
    action: oracle.action,
    owner: oracle.owner,
    ownerOutcome: oracle.ownerOutcome,
    authorityEffect: oracle.authorityEffect,
    semanticRecordDigest: oracle.semanticRecordDigest,
  };
  if (sha256(preimage) !== oracle.oracleDigest) throw new Error('TRACE_AUTHORITY_INVALID');
  return Object.freeze({
    oracleId: oracle.oracleId,
    oracleDigest: oracle.oracleDigest,
    requirementStatement: record.authority.requirement.statement,
    decisionResults: record.authority.decisions.flatMap((item) => [...item.selectedResult]),
    sourceStatements: record.authority.sources.map((item) => item.statement),
    enforcedClaimRules: record.authority.claims.map((item) => item.rule),
    negativeBehavior: record.authority.negativeBehavior,
    behaviorPlan: record,
  });
}
