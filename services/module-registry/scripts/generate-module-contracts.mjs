import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

import { loadPublicModuleSource, moduleGenerationArguments } from './public-module-source.mjs';
import { publishModuleOutputs } from './module-generation-output.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const { profile, checkOnly } = moduleGenerationArguments(process.argv.slice(2));
const publicSource =
  profile === 'public-v2' ? await loadPublicModuleSource(repositoryRoot) : undefined;
const packageRoot = publicSource
  ? path.join(repositoryRoot, 'policies/modules/source')
  : process.env.OPENPC_C17_PACKAGE_ROOT;

if (!packageRoot || !path.isAbsolute(packageRoot)) {
  throw new Error('OPENPC_C17_PACKAGE_ROOT must be an absolute authenticated C17 package path.');
}

const sourceRoot = publicSource?.sourceRoot ?? path.join(packageRoot, 'SPECIFICATIONS', 'MODULES');
const outputRoot = path.join(repositoryRoot, 'policies', 'modules', 'generated');

const authoritySources = {
  sourceUnits: {
    path: path.join(packageRoot, 'CATALOGS', 'source-units.jsonl'),
    sha256: '3fbd1d00639aeb3fb1f568942e89ae505b7ac1cf45b2c4aa2faea2c74e70dd29',
  },
  decisions: {
    path: path.join(packageRoot, 'GOVERNANCE', 'decision-and-supersession-map.jsonl'),
    sha256: '397c0becca904297e172141d8bfe18712b255b05d0bd1b3f0f187da15680aae1',
  },
  claimCeilings: {
    path: path.join(
      packageRoot,
      'COMPLETE_SCOPE_AND_REQUIREMENTS',
      'PRODUCT',
      'exclusions-and-claim-ceilings.json',
    ),
    sha256: 'b9c866b671a06d475fd601a85ecb75789baca0da8e7356fe7b96dd1195fb0858',
  },
  requirements: {
    path: path.join(
      packageRoot,
      'COMPLETE_SCOPE_AND_REQUIREMENTS',
      'PRODUCT',
      'normative-requirements.jsonl',
    ),
    sha256: 'e49a27645e39168fdc6b3aad94cea40de0db496d99bb7b6140595d744fcbcafd',
  },
  closures: {
    path: path.join(packageRoot, 'CLOSURE', 'AF31', 'requirement-closure-22131.jsonl'),
    sha256: '3fed5ae229aca36f2cd9a48f866ae4918e63310c68026578a7becdeb74932f07',
  },
};

const fixedSourceFiles = [
  'module-manifest.schema.json',
  'module-registry.json',
  'module-contract-catalog.json',
  'module-conformance-fixtures.json',
  'module-trace-sets.json',
  'module-traceability.jsonl',
  'dependency-resolution.md',
  'module-lifecycle.md',
  'policy-composition.md',
  'simulator-and-simulation-guard.md',
  'delegated-participant-governance.md',
  'machine-validation-report.json',
];

const criticalHashes = new Map([
  [
    'module-manifest.schema.json',
    'b7fc11a37e3295daaa31222c358e9031dd9ebe8813185fb1c3ca9599ad4a6a03',
  ],
  ['module-registry.json', 'd94fc0394a0418a7d92a04f19c48badb694eff407a5c46092de40c7cd08108ca'],
  [
    'module-contract-catalog.json',
    'b3b1a5beee2f02db6db98e09a2683fd6af3fd5a16f82367d03a27876510e5538',
  ],
  [
    'module-conformance-fixtures.json',
    '10ffec0cf02ad7305567f6d4003bcc8c5ffc0f61492ce00b199a5ce4917c9f34',
  ],
  ['module-trace-sets.json', '6b9dd9d47bbe4357a647bc1012482846fd067065fbfab76486106c9022a88ae1'],
  ['module-traceability.jsonl', '9a43ad78fabd825eeb36fc87defb0b94985f3f6d0c5266f04626e6e320fc35c6'],
  [
    'machine-validation-report.json',
    '37385ee53db39c19e942d78253331df955be6cc31aded33ebe34f9ed984c173c',
  ],
]);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.entries(value)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
    .join(',')}}`;
}

function parseJson(bytes, relativePath) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new Error(`Invalid frozen JSON ${relativePath}: ${String(error)}`);
  }
}

async function assertFileDigest(source) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(source.path)) hash.update(chunk);
  if (hash.digest('hex') !== source.sha256) {
    throw new Error(`Frozen C17 authority source hash mismatch: ${source.path}`);
  }
}

async function readJsonlSelection(source, idField, requiredIds, project) {
  await assertFileDigest(source);
  const records = new Map();
  const lines = createInterface({
    input: createReadStream(source.path, { encoding: 'utf8' }),
    crlfDelay: Infinity,
  });
  for await (const line of lines) {
    if (line.length === 0) continue;
    const record = JSON.parse(line);
    const id = record[idField];
    if (typeof id === 'string' && requiredIds.has(id)) {
      records.set(id, { ...project(record), sourceRecordSha256: sha256(Buffer.from(line)) });
    }
  }
  const missing = [...requiredIds].filter((id) => !records.has(id));
  if (missing.length > 0) {
    throw new Error(`Missing frozen ${idField} records: ${missing.slice(0, 5).join(',')}`);
  }
  return records;
}

function traceAuthorityOwner(section) {
  return {
    'MOD-DEPENDENCY': 'services/module-registry/src/domain/dependency-resolver.ts',
    'MOD-LIFECYCLE': 'services/module-registry/src/domain/module-lifecycle.ts',
    'MOD-MANIFEST': 'services/module-registry/src/domain/module-admission.ts',
    'MOD-OPERATIONS': 'services/module-registry/src/db/policy-store.ts',
    'MOD-PARTICIPANT': 'services/module-registry/src/db/policy-store.ts',
    'MOD-POLICY': 'crates/pc-policy-core/src/evaluator.rs',
    'MOD-SIMULATION': 'services/module-registry/src/domain/policy-evaluator.ts',
  }[section];
}

function traceBehaviorKind(section) {
  return {
    'MOD-DEPENDENCY': 'DEPENDENCY_RESOLUTION',
    'MOD-LIFECYCLE': 'MODULE_LIFECYCLE',
    'MOD-MANIFEST': 'MODULE_ADMISSION',
    'MOD-OPERATIONS': 'POLICY_ACTIVATION_ARTIFACT',
    'MOD-PARTICIPANT': 'PARTICIPANT_ACTIVATION_BINDING',
    'MOD-POLICY': 'NATIVE_POLICY_EVALUATION',
    'MOD-SIMULATION': 'TYPESCRIPT_SIMULATION',
  }[section];
}

function traceOwnerInput(behaviorKind, row, semanticInputDigest, concreteInputDigest, digests) {
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
    profileId: `trace:${row.requirementId}:${concreteInputDigest}`,
    actionIntentId: `ACT-TRACE-${row.requirementId}`,
    scopeDigest: digests.requirement,
    resourceDigest: digests.exactResult,
    scenarioId: `trace:${row.traceId}`,
    routeDigest: digests.negativeBehavior,
    policyGenerationDigest: semanticInputDigest,
    schemaDigest: concreteInputDigest,
    selectorDigest: digests.requirement,
  };
}

const traceSemanticOutcomes = {
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
};

const traceMutations = {
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

function traceBehaviorPlan(
  row,
  requirement,
  closure,
  decisions,
  sourceUnits,
  claimCeilings,
  owner,
) {
  const decisionRecords = row.decisionIds.map((id) => decisions.get(id));
  const sourceRecords = row.sourceUnitIds.map((id) => sourceUnits.get(id));
  const claimRecords = row.claimCeilingIds.map((id) => claimCeilings.get(id));
  const decisionResults = row.decisionIds.flatMap((id) => decisions.get(id).selectedResult);
  const sourceStatements = row.sourceUnitIds.map((id) => sourceUnits.get(id).statement);
  const claimRules = row.claimCeilingIds.map((id) => claimCeilings.get(id).rule);
  const sourceNormativities = [...new Set(sourceRecords.map((record) => record.normativity))];
  if (sourceNormativities.length !== 1 || !(sourceNormativities[0] in traceSemanticOutcomes)) {
    throw new Error(`Trace source semantics are not singular and executable: ${row.traceId}`);
  }
  const semanticDisposition = sourceNormativities[0];
  const derived = traceSemanticOutcomes[semanticDisposition];
  const authority = {
    requirement: {
      requirementId: requirement.requirementId,
      statement: requirement.normativeStatement,
      recordSha256: requirement.sourceRecordSha256,
    },
    decisions: decisionRecords.map((record) => ({
      decisionId: record.decisionId,
      selectedResult: record.selectedResult,
      recordSha256: record.sourceRecordSha256,
    })),
    sources: sourceRecords.map((record) => ({
      sourceUnitId: record.sourceUnitId,
      statement: record.statement,
      normativity: record.normativity,
      recordSha256: record.sourceRecordSha256,
    })),
    claims: claimRecords.map((record) => ({
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
    negativeBehavior: row.negativeBehavior,
  };
  const componentDigests = {
    requirement: sha256(Buffer.from(requirement.normativeStatement)),
    decisions: decisionResults.map((value) => sha256(Buffer.from(value))),
    sources: sourceStatements.map((value) => sha256(Buffer.from(value))),
    claims: claimRules.map((value) => sha256(Buffer.from(value))),
    negativeBehavior: sha256(Buffer.from(row.negativeBehavior)),
    exactResult: sha256(Buffer.from(row.finalClosureState)),
  };
  const semanticInputDigest = sha256(Buffer.from(canonicalJson(authority)));
  const behaviorKind = traceBehaviorKind(row.targetSectionId);
  const concreteInputDigest = sha256(
    Buffer.from(
      canonicalJson({
        traceId: row.traceId,
        owner,
        semanticInputDigest,
        componentDigests,
      }),
    ),
  );
  const mutation =
    semanticDisposition === 'IMPLEMENTATION_REQUIREMENT'
      ? 'NONE'
      : traceMutations[behaviorKind][Number.parseInt(concreteInputDigest.slice(0, 8), 16) % 8];
  const productInput = {
    subjectId: row.traceId,
    authorityEnvelopeDigest: semanticInputDigest,
    requirementDigest: componentDigests.requirement,
    decisionDigests: componentDigests.decisions,
    sourceDigests: componentDigests.sources,
    claimDigests: componentDigests.claims,
    negativeBehaviorDigest: componentDigests.negativeBehavior,
    closureDigest: componentDigests.exactResult,
    ownerInput: traceOwnerInput(
      behaviorKind,
      row,
      semanticInputDigest,
      concreteInputDigest,
      componentDigests,
    ),
    mutation,
  };
  const planPreimage = {
    planId: `TRACE-BEHAVIOR-${row.traceId}`,
    traceId: row.traceId,
    owner,
    ownerRuntime: row.targetSectionId === 'MOD-POLICY' ? 'RUST_NATIVE' : 'TYPESCRIPT',
    behaviorKind,
    semanticDisposition,
    authority,
    componentDigests,
    semanticInputDigest,
    concreteInputDigest,
    productInput,
    productAssertion: {
      outcome: derived.outcome,
      authorityEffect: derived.authorityEffect,
      zeroEffectRequired: derived.zeroEffectRequired,
    },
  };
  return {
    schemaVersion: '2.0',
    ...planPreimage,
    planDigest: sha256(Buffer.from(canonicalJson(planPreimage))),
  };
}

function rustStrings(values) {
  return values.map((value) => `    ${JSON.stringify(value)},`).join('\n');
}

function typescriptSource(registry, catalog) {
  const edgeProjection = registry.edges.map(({ edgeId, from, relation, to }) => ({
    edgeId,
    from,
    relation,
    to,
  }));
  const declarations = [
    ['moduleIds', registry.modules.map(({ moduleId }) => moduleId)],
    ['installOrder', registry.installOrder],
    ['installEdges', edgeProjection],
    ['typeIds', catalog.types.map(({ id }) => id)],
    ['stateIds', catalog.states.map(({ id }) => id)],
    ['operationIds', catalog.operations.map(({ id }) => id)],
    ['errorIds', catalog.errors.map(({ id }) => id)],
    ['eventTypes', catalog.events.map(({ eventType }) => eventType)],
    ['configurationKeys', catalog.configuration.map(({ key }) => key)],
    ['migrationIds', catalog.migrations.map(({ id }) => id)],
    ['testIds', catalog.tests.map(({ id }) => id)],
  ];
  const lines = [
    '// Generated by services/module-registry/scripts/generate-module-contracts.mjs.',
    '// Do not edit directly.',
    '',
  ];
  for (const [name, value] of declarations) {
    lines.push(`export const ${name} = ${JSON.stringify(value, null, 2)} as const;`, '');
  }
  lines.push(
    `export const contractCounts = ${JSON.stringify(
      {
        modules: registry.moduleCount,
        dagNodes: registry.dagNodeCount,
        dagEdges: registry.dagEdgeCount,
        types: catalog.types.length,
        states: catalog.states.length,
        operations: catalog.operations.length,
        errors: catalog.errors.length,
        events: catalog.events.length,
        configuration: catalog.configuration.length,
        migrations: catalog.migrations.length,
        tests: catalog.tests.length,
      },
      null,
      2,
    )} as const;`,
    '',
  );
  return Buffer.from(lines.join('\n'));
}

function moduleRustSource(registry) {
  return Buffer.from(`// Generated by services/module-registry/scripts/generate-module-contracts.mjs.
// Do not edit directly.

pub const MODULE_IDS: &[&str] = &[
${rustStrings(registry.modules.map(({ moduleId }) => moduleId))}
];

pub const INSTALL_ORDER: &[&str] = &[
${rustStrings(registry.installOrder)}
];

pub const MODULE_COUNT: usize = ${registry.moduleCount};
pub const INSTALL_DAG_NODE_COUNT: usize = ${registry.dagNodeCount};
pub const INSTALL_DAG_EDGE_COUNT: usize = ${registry.dagEdgeCount};
pub const INSTALL_DAG_CYCLE_POLICY: &str = ${JSON.stringify(registry.cyclePolicy)};
`);
}

function policyRustSource(catalog) {
  const groups = [
    ['CONTRACT_TYPE_IDS', catalog.types.map(({ id }) => id)],
    ['STATE_IDS', catalog.states.map(({ id }) => id)],
    ['OPERATION_IDS', catalog.operations.map(({ id }) => id)],
    ['ERROR_IDS', catalog.errors.map(({ id }) => id)],
    ['EVENT_TYPES', catalog.events.map(({ eventType }) => eventType)],
    ['CONFIGURATION_KEYS', catalog.configuration.map(({ key }) => key)],
    ['MIGRATION_IDS', catalog.migrations.map(({ id }) => id)],
    ['TEST_IDS', catalog.tests.map(({ id }) => id)],
  ];
  const output = [
    '// Generated by services/module-registry/scripts/generate-module-contracts.mjs.',
    '// Do not edit directly.',
    '',
  ];
  for (const [name, values] of groups) {
    if (values.length <= 2) {
      output.push(
        `pub const ${name}: &[&str] = &[${values.map((value) => JSON.stringify(value)).join(', ')}];`,
        '',
      );
    } else {
      output.push(`pub const ${name}: &[&str] = &[`, rustStrings(values), '];', '');
    }
  }
  return Buffer.from(output.join('\n'));
}

const outputs = new Map();
async function verifyOrWrite(destination, expected) {
  if (outputs.has(destination)) throw new Error('Duplicate module generation output');
  outputs.set(destination, expected);
}

const manifestNames = (await readdir(path.join(sourceRoot, 'manifests')))
  .filter((name) => name.endsWith('.json'))
  .sort();
if (manifestNames.length !== 33) {
  throw new Error(`Expected 33 frozen module manifests, received ${manifestNames.length}.`);
}

const sourceFiles = [...fixedSourceFiles, ...manifestNames.map((name) => `manifests/${name}`)];
const sourceBytes = new Map();
const sourceIndex = [];
for (const relativePath of sourceFiles) {
  const bytes = await readFile(path.join(sourceRoot, relativePath));
  const digest = sha256(bytes);
  const criticalHash = criticalHashes.get(relativePath);
  if (criticalHash && digest !== criticalHash) {
    throw new Error(`Frozen C17 source hash mismatch for ${relativePath}.`);
  }
  sourceBytes.set(relativePath, bytes);
  sourceIndex.push({ path: `SPECIFICATIONS/MODULES/${relativePath}`, sha256: digest });
}

const registry = parseJson(sourceBytes.get('module-registry.json'), 'module-registry.json');
const catalog = parseJson(
  sourceBytes.get('module-contract-catalog.json'),
  'module-contract-catalog.json',
);
const fixtures = parseJson(
  sourceBytes.get('module-conformance-fixtures.json'),
  'module-conformance-fixtures.json',
);
const manifestSchema = parseJson(
  sourceBytes.get('module-manifest.schema.json'),
  'module-manifest.schema.json',
);
const traces = sourceBytes
  .get('module-traceability.jsonl')
  .toString('utf8')
  .split('\n')
  .filter((line) => line.trim().length > 0);
const traceRows = traces.map((line) => JSON.parse(line));

const requirementIds = new Set(traceRows.map((row) => row.requirementId));
const decisionIds = new Set(traceRows.flatMap((row) => row.decisionIds));
const sourceUnitIds = new Set(traceRows.flatMap((row) => row.sourceUnitIds));
const claimCeilingIds = new Set(traceRows.flatMap((row) => row.claimCeilingIds));

let requirements, decisions, sourceUnits, closures, claimCeilings;
if (publicSource) {
  const records = (name, id) => {
    const values = publicSource.authorityCatalog[name];
    if (!Array.isArray(values)) throw new Error('Invalid public authority projection');
    const result = new Map();
    for (const value of values) {
      if (!value || typeof value[id] !== 'string' || result.has(value[id]))
        throw new Error('Invalid or duplicate public authority record');
      result.set(value[id], value);
    }
    return result;
  };
  requirements = records('requirements', 'requirementId');
  decisions = records('decisions', 'decisionId');
  sourceUnits = records('sourceUnits', 'sourceUnitId');
  closures = records('closures', 'requirementId');
  claimCeilings = records('claimCeilings', 'claimCeilingId');
} else {
  requirements = await readJsonlSelection(
    authoritySources.requirements,
    'requirementId',
    requirementIds,
    (record) => ({
      requirementId: record.requirementId,
      normativeStatement: record.normativeStatement,
      negativeBehavior: record.negativeBehavior,
      specificationState: record.specificationState,
      scopeDisposition: record.scopeDisposition,
      finalClosureState: record.finalClosureState,
      truthState: record.truthState,
      semanticBundleId: record.semanticBundleId,
      decisionIds: record.decisionIds,
      sourceUnitIds: record.sourceUnitIds,
      claimCeilingIds: record.claimCeilingIds,
    }),
  );
  decisions = await readJsonlSelection(
    authoritySources.decisions,
    'decisionId',
    decisionIds,
    (record) => ({
      decisionId: record.decisionId,
      title: record.title,
      status: record.status,
      decisionClass: record.decisionClass,
      authorityRanking: record.authorityRanking,
      selectedResult: record.selectedResult,
      rejectedAlternatives: record.rejectedAlternatives,
      migrationEffect: record.migrationEffect,
      rollbackEffect: record.rollbackEffect,
    }),
  );
  sourceUnits = await readJsonlSelection(
    authoritySources.sourceUnits,
    'sourceUnitId',
    sourceUnitIds,
    (record) => ({
      sourceUnitId: record.sourceUnitId,
      statement: record.statement,
      normativity: record.normativity,
      authorityClass: record.authorityClass,
      negativeBehavior: record.negativeBehavior,
      decisionRefs: record.decisionRefs,
      claimCeilingRefs: record.claimCeilingRefs,
      semanticBundleId: record.semanticBundleId,
      sourceObjectId: record.sourceObjectId,
      objectSha256: record.objectSha256,
    }),
  );
  closures = await readJsonlSelection(
    authoritySources.closures,
    'requirementId',
    requirementIds,
    (record) => ({
      requirementId: record.requirementId,
      requirementClosureId: record.requirementClosureId,
      closureId: record.acceptedClosure?.closureId,
      finalState: record.finalState,
      finalNormativeStatement: record.finalNormativeStatement,
      negativeBehavior: record.negativeBehavior,
      terminalRationale: record.terminalRationale,
      decisionIds: record.decisionIds,
      sourceUnitIds: record.sourceUnitIds,
      claimCeilingIds: record.claimCeilingIds,
      sourceRequirementRecordSha256: record.sourceRequirementRecordSha256,
    }),
  );
  await assertFileDigest(authoritySources.claimCeilings);
  const claimDocument = parseJson(
    await readFile(authoritySources.claimCeilings.path),
    'exclusions-and-claim-ceilings.json',
  );
  claimCeilings = new Map(
    claimDocument.claimCeilings
      .filter((record) => claimCeilingIds.has(record.claimCeilingId))
      .map((record) => [
        record.claimCeilingId,
        {
          claimCeilingId: record.claimCeilingId,
          binding: record.binding,
          rule: record.rule,
          sourceRecordSha256: sha256(Buffer.from(JSON.stringify(record))),
        },
      ]),
  );
  const missingClaims = [...claimCeilingIds].filter((id) => !claimCeilings.has(id));
  if (missingClaims.length > 0) {
    throw new Error(`Missing frozen claim ceilings: ${missingClaims.join(',')}`);
  }
}

const authorityCatalog = {
  schemaVersion: '2.0',
  catalogId: 'OPENPC-I03-TRACE-AUTHORITY-CATALOG-R7',
  sourceFiles: Object.fromEntries(
    Object.entries(authoritySources).map(([name, source]) => [
      name,
      { path: path.relative(packageRoot, source.path), sha256: source.sha256 },
    ]),
  ),
  requirements: [...requirements.values()].sort((left, right) =>
    left.requirementId.localeCompare(right.requirementId),
  ),
  decisions: [...decisions.values()].sort((left, right) =>
    left.decisionId.localeCompare(right.decisionId),
  ),
  sourceUnits: [...sourceUnits.values()].sort((left, right) =>
    left.sourceUnitId.localeCompare(right.sourceUnitId),
  ),
  claimCeilings: [...claimCeilings.values()].sort((left, right) =>
    left.claimCeilingId.localeCompare(right.claimCeilingId),
  ),
  closures: [...closures.values()].sort((left, right) =>
    left.requirementId.localeCompare(right.requirementId),
  ),
};
const authorityCatalogBytes = Buffer.from(`${JSON.stringify(authorityCatalog, null, 2)}\n`);
const semanticRecords = [];
const behaviorOracleLines = traceRows.map((row) => {
  const requirement = requirements.get(row.requirementId);
  const closure = closures.get(row.requirementId);
  const owner = traceAuthorityOwner(row.targetSectionId);
  if (!requirement || !closure || !owner) throw new Error(`Incomplete trace oracle ${row.traceId}`);
  if (
    requirement.normativeStatement !==
      (sourceUnits.get(row.sourceUnitIds[0])?.statement ?? requirement.normativeStatement) &&
    requirement.semanticBundleId !== row.semanticBundleId
  ) {
    throw new Error(`Trace semantic bundle mismatch ${row.traceId}`);
  }
  if (
    requirement.negativeBehavior !== row.negativeBehavior ||
    requirement.specificationState !== row.specificationState ||
    requirement.scopeDisposition !== row.scopeDisposition ||
    requirement.finalClosureState !== row.finalClosureState ||
    closure.closureId === undefined ||
    !row.closureIds.includes(closure.closureId)
  ) {
    throw new Error(`Trace requirement or closure mismatch ${row.traceId}`);
  }
  const behaviorPlan = traceBehaviorPlan(
    row,
    requirement,
    closure,
    decisions,
    sourceUnits,
    claimCeilings,
    owner,
  );
  semanticRecords.push({
    schemaVersion: '2.0',
    traceId: row.traceId,
    targetSectionId: row.targetSectionId,
    declaredOwner: owner,
    declaredRuntime: behaviorPlan.ownerRuntime,
    behaviorKind: behaviorPlan.behaviorKind,
    semanticDisposition: behaviorPlan.semanticDisposition,
    authority: behaviorPlan.authority,
    productInput: behaviorPlan.productInput,
    productAssertion: behaviorPlan.productAssertion,
    semanticInputDigest: behaviorPlan.semanticInputDigest,
    concreteInputDigest: behaviorPlan.concreteInputDigest,
    recordDigest: sha256(
      Buffer.from(
        canonicalJson({
          traceId: row.traceId,
          targetSectionId: row.targetSectionId,
          declaredOwner: owner,
          declaredRuntime: behaviorPlan.ownerRuntime,
          behaviorKind: behaviorPlan.behaviorKind,
          semanticDisposition: behaviorPlan.semanticDisposition,
          authority: behaviorPlan.authority,
          productInput: behaviorPlan.productInput,
          productAssertion: behaviorPlan.productAssertion,
          semanticInputDigest: behaviorPlan.semanticInputDigest,
          concreteInputDigest: behaviorPlan.concreteInputDigest,
        }),
      ),
    ),
  });
  const semanticRecord = semanticRecords.at(-1);
  const preimage = {
    traceId: row.traceId,
    requirementId: row.requirementId,
    requirementRecordSha256: requirement.sourceRecordSha256,
    closureRecordSha256: closure.sourceRecordSha256,
    decisionRecordSha256s: row.decisionIds.map((id) => decisions.get(id).sourceRecordSha256),
    sourceUnitRecordSha256s: row.sourceUnitIds.map((id) => sourceUnits.get(id).sourceRecordSha256),
    claimCeilingRecordSha256s: row.claimCeilingIds.map(
      (id) => claimCeilings.get(id).sourceRecordSha256,
    ),
    normativeStatementSha256: sha256(Buffer.from(requirement.normativeStatement)),
    negativeBehaviorSha256: sha256(Buffer.from(row.negativeBehavior)),
    exactResult: row.finalClosureState,
    action:
      behaviorPlan.semanticDisposition === 'IMPLEMENTATION_REQUIREMENT' ? 'IMPLEMENT' : 'PRESERVE',
    owner,
    ownerOutcome: behaviorPlan.productAssertion.outcome,
    authorityEffect: behaviorPlan.productAssertion.authorityEffect,
    semanticRecordDigest: semanticRecord.recordDigest,
  };
  return JSON.stringify({
    schemaVersion: '2.0',
    oracleId: `ORACLE-${row.traceId}`,
    ...preimage,
    oracleDigest: sha256(Buffer.from(canonicalJson(preimage))),
  });
});
const behaviorOracleBytes = Buffer.from(`${behaviorOracleLines.join('\n')}\n`);
const semanticRecordLines = semanticRecords.map((record) => JSON.stringify(record));
const semanticCorpusBytes = Buffer.from(`${semanticRecordLines.join('\n')}\n`);
const semanticCorpusAggregateDigest = sha256(
  Buffer.from(semanticRecords.map((record) => record.recordDigest).join('\n')),
);
const orderedOracleDigestAggregateSha256 = sha256(
  Buffer.from(behaviorOracleLines.map((line) => JSON.parse(line).oracleDigest).join('\n')),
);
const recordCommitments = semanticRecords.map((record, index) => {
  const oracle = JSON.parse(behaviorOracleLines[index]);
  return {
    traceId: record.traceId,
    recordDigest: record.recordDigest,
    rawRecordSha256: sha256(Buffer.from(semanticRecordLines[index])),
    oracleDigest: oracle.oracleDigest,
    semanticInputDigest: record.semanticInputDigest,
    concreteInputDigest: record.concreteInputDigest,
    componentDigestsSha256: sha256(
      Buffer.from(
        canonicalJson({
          authorityRecordSha256s: [
            record.authority.requirement.recordSha256,
            ...record.authority.decisions.map((item) => item.recordSha256),
            ...record.authority.sources.map((item) => item.recordSha256),
            ...record.authority.claims.map((item) => item.recordSha256),
            record.authority.closure.recordSha256,
          ],
          requirementDigest: record.productInput.requirementDigest,
          decisionDigests: record.productInput.decisionDigests,
          sourceDigests: record.productInput.sourceDigests,
          claimDigests: record.productInput.claimDigests,
          negativeBehaviorDigest: record.productInput.negativeBehaviorDigest,
          closureDigest: record.productInput.closureDigest,
        }),
      ),
    ),
  };
});
const policyStoreRecords = semanticRecords.filter(
  (record) =>
    record.targetSectionId === 'MOD-OPERATIONS' || record.targetSectionId === 'MOD-PARTICIPANT',
);
const semanticCorpusManifestPreimage = {
  schemaVersion: '2.0',
  corpusId: 'OPENPC-I03-TRACE-SEMANTIC-CORPUS-R8',
  rowCount: semanticRecords.length,
  orderedRecordDigestAggregateSha256: semanticCorpusAggregateDigest,
  orderedOracleDigestAggregateSha256,
  corpusFile: 'policies/modules/generated/module-trace-semantic-corpus.jsonl',
  corpusFileSha256: sha256(semanticCorpusBytes),
  authorityCatalogFile: 'policies/modules/generated/module-trace-authority-catalog.json',
  authorityCatalogFileSha256: sha256(authorityCatalogBytes),
  behaviorOracleFile: 'policies/modules/generated/module-trace-behavior-oracles.jsonl',
  behaviorOracleFileSha256: sha256(behaviorOracleBytes),
  frozenAuthoritySources: Object.fromEntries(
    Object.entries(authoritySources).map(([name, source]) => [name, source.sha256]),
  ),
  recordCommitments,
  reconstructionCommand:
    'OPENPC_C17_PACKAGE_ROOT=<authenticated-c17-package-root> pnpm --filter @openpc/module-registry run generate',
  checkCommand:
    'OPENPC_C17_PACKAGE_ROOT=<authenticated-c17-package-root> pnpm --filter @openpc/module-registry run generate:check',
  ownerRuntimeCounts: Object.fromEntries(
    Object.entries(Object.groupBy(semanticRecords, (record) => record.declaredRuntime)).map(
      ([runtime, records]) => [runtime, records.length],
    ),
  ),
  policyStoreLiveOwner: {
    owner: 'services/module-registry/src/db/policy-store.ts',
    operation: 'activatePolicyGeneration',
    rowCount: policyStoreRecords.length,
    accepted: policyStoreRecords.filter((record) => record.productAssertion.outcome === 'ACCEPTED')
      .length,
    rejectedFailClosed: policyStoreRecords.filter(
      (record) => record.productAssertion.outcome === 'REJECTED_FAIL_CLOSED',
    ).length,
    orderedRecordDigestAggregateSha256: sha256(
      Buffer.from(policyStoreRecords.map((record) => record.recordDigest).join('\n')),
    ),
  },
};
const semanticCorpusManifest = {
  ...semanticCorpusManifestPreimage,
  rootCommitmentSha256: sha256(Buffer.from(canonicalJson(semanticCorpusManifestPreimage))),
};
const semanticCorpusManifestBytes = Buffer.from(
  `${JSON.stringify(semanticCorpusManifest, null, 2)}\n`,
);

if (
  registry.moduleCount !== 33 ||
  registry.dagNodeCount !== 33 ||
  registry.dagEdgeCount !== 69 ||
  registry.cyclePolicy !== 'FORBIDDEN'
) {
  throw new Error('Frozen module registry denominator mismatch.');
}
if (
  catalog.types.length !== 16 ||
  catalog.states.length !== 26 ||
  catalog.operations.length !== 15 ||
  catalog.errors.length !== 16 ||
  catalog.events.length !== 10 ||
  catalog.configuration.length !== 3 ||
  catalog.migrations.length !== 2 ||
  catalog.tests.length !== 14
) {
  throw new Error('Frozen module contract catalog denominator mismatch.');
}
if (
  fixtures.positiveCases.length !== 4 ||
  fixtures.negativeProfiles.length !== 8 ||
  fixtures.negativeCases.length !== 264 ||
  traces.length !== 5470
) {
  throw new Error('Frozen module conformance or trace denominator mismatch.');
}
for (const module of registry.modules) {
  const relativePath = module.manifestPath;
  const bytes = sourceBytes.get(relativePath);
  if (!bytes || sha256(bytes) !== module.manifestSha256) {
    throw new Error(`Registry-to-manifest digest mismatch for ${module.moduleId}.`);
  }
  const manifest = parseJson(bytes, relativePath);
  if (manifest.$schema !== '../module-manifest.schema.json') {
    throw new Error(`Unexpected frozen schema reference for ${module.moduleId}.`);
  }
}

if (manifestSchema.properties?.$schema?.const !== 'pkg://modules/module-manifest.schema.json') {
  throw new Error('Frozen module schema compatibility baseline changed.');
}
const compatibleManifestSchema = structuredClone(manifestSchema);
compatibleManifestSchema.properties.$schema.const = '../module-manifest.schema.json';
const compatibleManifestSchemaBytes = Buffer.from(
  `${JSON.stringify(compatibleManifestSchema, null, 2)}\n`,
);

for (const [relativePath, bytes] of sourceBytes) {
  await verifyOrWrite(path.join(outputRoot, relativePath), bytes);
}
await verifyOrWrite(
  path.join(outputRoot, 'module-manifest.compat.schema.json'),
  compatibleManifestSchemaBytes,
);
await verifyOrWrite(
  path.join(outputRoot, 'module-trace-authority-catalog.json'),
  authorityCatalogBytes,
);
await verifyOrWrite(
  path.join(outputRoot, 'module-trace-behavior-oracles.jsonl'),
  behaviorOracleBytes,
);
await verifyOrWrite(
  path.join(outputRoot, 'module-trace-semantic-corpus.jsonl'),
  semanticCorpusBytes,
);
await verifyOrWrite(
  path.join(outputRoot, 'module-trace-corpus-manifest.json'),
  semanticCorpusManifestBytes,
);

for (const source of Object.values(authoritySources)) {
  sourceIndex.push({ path: path.relative(packageRoot, source.path), sha256: source.sha256 });
}

const generatedIndex = Buffer.from(
  `${JSON.stringify(
    {
      schemaVersion: '1.0',
      generator: 'services/module-registry/scripts/generate-module-contracts.mjs',
      sourcePackageId: publicSource
        ? publicSource.baseline.sourcePackageId
        : 'OPENPC-C17-RECEIVING-AUTHORITY-COHERENCE-20260827-01',
      semanticImpact: publicSource
        ? 'PUBLIC_CATALOGUE_WORDING_REVISION_UNCHANGED_MODULE_CONTRACTS'
        : 'EXACT_C17_CONTRACT_PROJECTION_NO_PRODUCT_DECISION',
      files: sourceIndex,
      compatibilitySidecars: [
        {
          path: 'policies/modules/generated/module-manifest.compat.schema.json',
          sourcePath: 'SPECIFICATIONS/MODULES/module-manifest.schema.json',
          sourceSha256: sha256(sourceBytes.get('module-manifest.schema.json')),
          sha256: sha256(compatibleManifestSchemaBytes),
          correction: 'SCHEMA_REFERENCE_CONST_MATCHES_ALL_33_FROZEN_MANIFESTS',
        },
        {
          path: 'policies/modules/generated/module-trace-authority-catalog.json',
          sha256: sha256(authorityCatalogBytes),
          correction: publicSource
            ? 'PUBLIC_AUTHORITY_RECORD_PROJECTION_WITH_REVISED_WORDING'
            : 'AUTHENTICATED_EXACT_AUTHORITY_RECORD_PROJECTION_FOR_ALL_TRACE_REFERENCES',
        },
        {
          path: 'policies/modules/generated/module-trace-behavior-oracles.jsonl',
          sha256: sha256(behaviorOracleBytes),
          correction: 'PER_ROW_AUTHENTICATED_TYPED_SEMANTIC_BEHAVIOR_ORACLE',
        },
        {
          path: 'policies/modules/generated/module-trace-semantic-corpus.jsonl',
          sha256: sha256(semanticCorpusBytes),
          orderedRecordDigestAggregateSha256: semanticCorpusAggregateDigest,
          correction: 'MATERIAL_RECONSTRUCTABLE_5470_ROW_TYPED_SEMANTIC_CORPUS',
        },
        {
          path: 'policies/modules/generated/module-trace-corpus-manifest.json',
          sha256: sha256(semanticCorpusManifestBytes),
          correction: 'CORPUS_PREIMAGE_MANIFEST_RECONSTRUCTION_AND_AGGREGATE_BINDING',
        },
      ],
      denominator: {
        manifests: 33,
        dagNodes: 33,
        dagEdges: 69,
        traceRows: 5470,
        negativeCases: 264,
      },
    },
    null,
    2,
  )}\n`,
);

await verifyOrWrite(path.join(outputRoot, 'generated-source-index.json'), generatedIndex);
await verifyOrWrite(
  path.join(repositoryRoot, 'services/module-registry/src/generated/contracts.ts'),
  typescriptSource(registry, catalog),
);
await verifyOrWrite(
  path.join(repositoryRoot, 'crates/pc-module-sdk/src/generated.rs'),
  moduleRustSource(registry),
);
await verifyOrWrite(
  path.join(repositoryRoot, 'crates/pc-policy-core/src/generated.rs'),
  policyRustSource(catalog),
);
await verifyOrWrite(
  path.join(repositoryRoot, 'tests/conformance/modules/generated-source-index.json'),
  generatedIndex,
);

if (publicSource) {
  publicSource.verifyOutputs(outputs);
  await verifyOrWrite(
    path.join(outputRoot, 'public-source-provenance.json'),
    publicSource.provenance(),
  );
}
await publishModuleOutputs(repositoryRoot, outputs, { checkOnly });

process.stdout.write(
  `${JSON.stringify({
    result: 'PASS',
    mode: checkOnly ? 'CHECK' : 'WRITE',
    ...(publicSource
      ? {
          sourceProfile: 'TEGARIS_PUBLIC_MODULE_SOURCE_V2',
          historicalSourceVerification: 'NOT_PERFORMED',
        }
      : {}),
    manifests: 33,
    dagNodes: 33,
    dagEdges: 69,
    traceRows: 5470,
    negativeCases: 264,
    generatedFiles: sourceFiles.length + 10,
  })}\n`,
);
