export const traceExecutionOwners = {
  'MOD-DEPENDENCY': ['G1', 'services/module-registry/src/domain/dependency-resolver.ts'],
  'MOD-LIFECYCLE': ['G3', 'services/module-registry/src/domain/module-lifecycle.ts'],
  'MOD-MANIFEST': ['G1', 'services/module-registry/src/domain/module-admission.ts'],
  'MOD-OPERATIONS': ['G7', 'services/module-registry/src/db/policy-store.ts'],
  'MOD-PARTICIPANT': ['G7', 'services/module-registry/src/db/policy-store.ts'],
  'MOD-POLICY': ['G4', 'crates/pc-policy-core/src/evaluator.rs'],
  'MOD-SIMULATION': ['G6', 'services/module-registry/src/domain/policy-evaluator.ts'],
} as const;

type TraceSection = keyof typeof traceExecutionOwners;
type TraceState =
  'NORMATIVE_R1' | 'NON_R1_EMPIRICAL_OR_FUTURE_EVIDENCE_GATE' | 'NEGATIVE_ORACLE_EXCLUDED_BEHAVIOR';

export interface TraceObligation {
  claimCeilingIds: string[];
  closureIds: string[];
  componentIds: string[];
  decisionIds: string[];
  finalClosureState: string;
  negativeBehavior: string;
  requirementId: string;
  schemaVersion: string;
  scopeDisposition: string;
  semanticBundleId: string;
  sourceUnitIds: string[];
  specificationState: TraceState;
  targetSectionId: TraceSection;
  traceId: string;
}

export interface TraceOwnerExecution {
  readonly traceId: string;
  readonly owner: string;
  readonly behaviorId: string;
  readonly outcome: 'ACCEPTED' | 'REJECTED_FAIL_CLOSED';
  readonly authorityEffect: 'R1_AUTHORITY_BOUND' | 'NONE';
  readonly authorityOracleDigest: string;
  readonly semanticInputDigest: string;
  readonly concreteInputDigest: string;
  readonly behavioralEvidenceDigest: string;
  readonly ownerRuntime: 'TYPESCRIPT' | 'RUST_NATIVE';
  readonly zeroEffectBeforeDigest: string;
  readonly zeroEffectAfterDigest: string;
}
