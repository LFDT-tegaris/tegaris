import { requireModuleDisablePredicates } from '../../../services/module-registry/src/db/module-disable-fence.js';
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  assertModuleLifecycleObservationUnchanged,
  declarationSql,
  inspectModulePolicyReferences,
  inspectModuleReferenceWriteFences,
  inspectModuleDisableWriteFences,
  inspectModuleReverseDependencies,
  moduleLifecyclePreflightRequest,
  type ModulePreflightPolicyRow,
} from '../../../services/module-registry/src/db/module-lifecycle-preflight.js';
import { resolveDependencies } from '../../../services/module-registry/src/domain/dependency-resolver.js';
import { pcCbor1 } from '../../../services/module-registry/src/domain/digest.js';
import { validatePolicySemantics } from '../../../services/module-registry/src/domain/policy-semantics.js';

type Snapshot = Parameters<typeof inspectModuleReverseDependencies>[0];
const id = (suffix: string) => `018f0000-0000-7000-8000-${suffix.padStart(12, '0')}`;
const hash = (byte: number) => Buffer.alloc(32, byte);
const tagged = (bytes: Buffer) => `sha256:${bytes.toString('hex')}`;

// Pure classifier inputs only. These objects are never inserted or passed to an
// admission/mutation owner; real release verification remains mandatory there.
function node(name: string, suffix: string, providers: Snapshot = []): Snapshot[number] {
  const manifestDigest = hash(Number(suffix));
  const configurationDigest = hash(42);
  const manifest = {
    metadata: { id: name, version: '1.0.0', displayName: name },
    capabilities: {
      required: [],
      provided: [{ capabilityId: `cap:${name}`, providerModuleId: name }],
    },
    dependencies: providers.map((provider) => ({
      edgeId: `${name}:${provider.release.manifest.metadata.id}`,
      providerModuleId: provider.release.manifest.metadata.id,
      moduleId: provider.release.manifest.metadata.id,
      capabilityId: provider.release.manifest.capabilities.provided[0]!.capabilityId,
      version: '1.0.0',
      manifestDigest: tagged(provider.release.manifestDigest),
    })),
  };
  return {
    stored: {
      moduleInstallationId: id(suffix),
      revision: '3',
      state: 'ENABLED',
      admissionDependencyDigest: null,
    },
    release: { manifest, manifestDigest, configurationDigest },
    configuration: {
      id: id(suffix),
      configurationId: id(`1${suffix}`),
      generation: '1',
      active: true,
      digest: configurationDigest,
      activeManifest: manifestDigest,
      operationId: id(`2${suffix}`),
      evaluationDigest: hash(4),
    },
  } as unknown as Snapshot[number];
}
function graph(): Snapshot {
  const root = node('pc.foundation.kernel', '1');
  const direct = node('pc.config.assets', '2', [root]);
  const transitive = node('pc.transaction.delivery', '3', [direct]);
  const unrelated = node('pc.observability', '4');
  const rows = [root, direct, transitive, unrelated];
  for (const row of rows) {
    const included = new Set([row.release.manifest.metadata.id]);
    for (let index = 0; index < rows.length; index += 1) {
      for (const selected of rows.filter((candidate) =>
        included.has(candidate.release.manifest.metadata.id),
      )) {
        for (const edge of selected.release.manifest.dependencies)
          included.add(edge.providerModuleId);
      }
    }
    const closure = rows.filter((selected) => included.has(selected.release.manifest.metadata.id));
    const resolved = resolveDependencies(
      closure.map(({ release }) => ({
        moduleId: release.manifest.metadata.id,
        semanticVersion: release.manifest.metadata.version,
        manifestDigest: tagged(release.manifestDigest),
        capabilities: release.manifest.capabilities.provided.map(
          (capability) => capability.capabilityId,
        ),
      })),
      closure.flatMap(({ release }) =>
        release.manifest.dependencies.map((edge) => ({
          edgeId: edge.edgeId,
          consumerModuleId: release.manifest.metadata.id,
          providerModuleId: edge.providerModuleId,
          capabilityId: edge.capabilityId,
          semanticVersion: edge.version,
          providerManifestDigest: edge.manifestDigest,
        })),
      ),
    );
    Object.assign(row.stored, {
      admissionDependencyDigest: Buffer.from(resolved.closureDigest, 'hex'),
    });
  }
  return rows;
}

describe('module reverse-reference classification (TS-MOD-DEPENDENCY, component only)', () => {
  it('finds exact direct and transitive active dependents without blocking an unrelated module', () => {
    const rows = graph();
    expect(inspectModuleReverseDependencies(rows, id('1'))).toEqual({
      status: 'BLOCKED',
      references: [`MODULE:${id('2')}:3`, `MODULE:${id('3')}:3`],
      unresolved: [],
    });
    expect(inspectModuleReverseDependencies(rows, id('4'))).toEqual({
      status: 'CLEAR',
      references: [],
      unresolved: [],
    });
    expect(inspectModuleReverseDependencies([...rows].reverse(), id('1'))).toEqual(
      inspectModuleReverseDependencies(rows, id('1')),
    );
  });
  it('does not turn a missing provider, substituted digest/capability, duplicate or cycle into absence', () => {
    const original = graph();
    for (const change of [
      (rows: Snapshot) => {
        rows.splice(1, 1);
      },
      (rows: Snapshot) => {
        Object.assign(rows[1]!.release.manifest.dependencies[0]!, {
          manifestDigest: tagged(hash(90)),
        });
      },
      (rows: Snapshot) => {
        Object.assign(rows[1]!.release.manifest.dependencies[0]!, { capabilityId: 'foreign' });
      },
      (rows: Snapshot) => {
        rows.push(rows[1]!);
      },
      (rows: Snapshot) => {
        Object.assign(rows[0]!.release.manifest, {
          dependencies: [
            {
              ...rows[2]!.release.manifest.dependencies[0]!,
              providerModuleId: 'pc.transaction.delivery',
              manifestDigest: tagged(rows[2]!.release.manifestDigest),
              capabilityId: 'cap:pc.transaction.delivery',
            },
          ],
        });
      },
    ]) {
      const rows = graph();
      change(rows);
      expect(inspectModuleReverseDependencies(rows, id('1')).status).toBe('UNRESOLVED');
    }
    expect(inspectModuleReverseDependencies(original, id('1')).status).toBe('BLOCKED');
  });
  it('rejects stale active configuration, admission closure and disabled providers', () => {
    for (const change of [
      (rows: Snapshot) => {
        rows[0]!.configuration.activeManifest = hash(91);
      },
      (rows: Snapshot) => {
        Object.assign(rows[0]!.stored, { admissionDependencyDigest: hash(92) });
      },
      (rows: Snapshot) => {
        Object.assign(rows[0]!.stored, { state: 'INSTALLED_DISABLED' });
        rows[0]!.configuration.active = false;
        rows[0]!.configuration.activeManifest = null;
      },
    ]) {
      const rows = graph();
      change(rows);
      expect(inspectModuleReverseDependencies(rows, id('1')).status).toBe('UNRESOLVED');
    }
  });
});

const target = {
  participantId: id('101'),
  privacyDomainId: id('201'),
  moduleInstallationId: id('301'),
  moduleId: 'pc.policy.rpc-surface',
  semanticVersion: '1.0.0',
  revision: '3',
  generation: '1',
  configurationId: id('401'),
  manifestDigest: tagged(hash(1)),
  configurationDigest: tagged(hash(2)),
  state: 'ENABLED',
};
// Same meaningful RPC/contract family as typed-policy-semantics.test.ts.
// Keep the target's exact binding independently mutable for the mismatch oracle.
function policyBindings(targetOverrides: Record<string, string> = {}) {
  const binding = {
    moduleId: target.moduleId,
    semanticVersion: target.semanticVersion,
    manifestDigest: target.manifestDigest,
    configurationDigest: target.configurationDigest,
  };
  return [
    { ...binding, ...targetOverrides },
    { ...binding, moduleId: 'pc.policy.contract-method' },
    { ...binding, moduleId: 'pc.policy.argument-guard' },
  ];
}
function policyRow(overrides: Record<string, unknown> = {}): ModulePreflightPolicyRow {
  const participantId = overrides.participantId ?? target.participantId;
  const privacyDomainId = overrides.privacyDomainId ?? target.privacyDomainId;
  const semantic = validatePolicySemantics({
    schemaVersion: '1.0.0',
    participantId,
    privacyDomainId,
    moduleBindings: policyBindings(),
    rpcPolicies: [
      {
        schemaVersion: '1.0.0',
        participantId,
        privacyDomainId,
        rules: [
          { method: 'eth_call', effect: 'ALLOW', requiredRoles: [`urn:openpc:role:${id('501')}`] },
        ],
      },
    ],
    contractPolicies: [{ contractMethodPolicyId: id('701'), revision: '1' }],
    requiredFacts: [
      { candidateId: 'fact', generationId: 'generation', factDigest: tagged(hash(9)) },
    ],
    ...overrides,
  });
  const dependency = pcCbor1(semantic.document.moduleBindings).digest;
  return {
    id: id('601'),
    generation: '1',
    state: 'DESIRED',
    active: false,
    generationDigest: hash(8),
    dependencyDigest: dependency,
    artifactDependency: dependency,
    semantic: semantic.bytes,
    versionSemantic: semantic.bytes,
    semanticDigest: semantic.digest,
    artifactDigest: semantic.digest,
  };
}
describe('policy references decoded by the production semantic core', () => {
  it('blocks pending and active exact bindings, retains retired identity, and clears only an unrelated module', () => {
    const row = policyRow();
    for (const state of ['DESIRED', 'PREPARED', 'ACTIVE', 'FAILED_FENCED']) {
      expect(inspectModulePolicyReferences([{ ...row, state }], target).predicate.status).toBe(
        'BLOCKED',
      );
    }
    const retired = inspectModulePolicyReferences([{ ...row, state: 'RETIRED' }], target);
    expect(retired.predicate.status).toBe('CLEAR');
    expect(retired.matching.has(tagged(row.generationDigest))).toBe(true);
    expect(
      inspectModulePolicyReferences([row], { ...target, moduleId: 'pc.observability' }).predicate
        .status,
    ).toBe('CLEAR');
  });
  it('keeps foreign scope, malformed CBOR, digest and configuration/version substitutions unresolved', () => {
    const row = policyRow();
    const mismatches = [
      { ...row, semantic: Buffer.from('00', 'hex') },
      { ...row, artifactDigest: hash(15) },
      { ...row, dependencyDigest: hash(16) },
      { ...row, versionSemantic: Buffer.from('a0', 'hex') },
      policyRow({ privacyDomainId: id('202') }),
      policyRow({
        moduleBindings: policyBindings({ semanticVersion: '2.0.0' }),
      }),
      policyRow({
        moduleBindings: policyBindings({ configurationDigest: tagged(hash(12)) }),
      }),
    ];
    for (const mismatch of mismatches)
      expect(inspectModulePolicyReferences([mismatch], target).predicate.status).toBe('UNRESOLVED');
  });
});

// Catalog-shaped observations only; real migrated definitions, RLS and SQL
// contention are exercised by postgres18-runtime.test.ts, not this fixture.
function fenceCatalog() {
  const policyGenerationFenceSql = readFileSync(
    new URL(
      '../../../services/module-registry/src/db/policy-generation-fence.mjs',
      import.meta.url,
    ),
    'utf8',
  );
  const ciglGrantGuardsSql = readFileSync(
    new URL(
      '../../../services/control-api/src/configuration/cigl/grant-guards.mjs',
      import.meta.url,
    ),
    'utf8',
  );
  const functionBody = (sql: string, signature: string) => {
    const start = sql.indexOf(`CREATE OR REPLACE FUNCTION openpc.${signature}`);
    const body = start >= 0 ? sql.slice(start).match(/AS \$\$([\s\S]*?)\$\$;/u)?.[1] : undefined;
    if (body === undefined) throw new Error('missing canonical fence declaration');
    return body;
  };
  const owner = {
    schema: 'openpc',
    owner: 'openpc_control_owner',
    name: 'guard_policy_generation_fence',
    language: 'plpgsql',
    kind: 'f',
    volatility: 'v',
    securityDefiner: false,
    strict: false,
    leakproof: false,
    parallel: 'u',
    returnsSet: false,
    support: '0',
    returnSchema: 'pg_catalog',
    returnType: 'trigger',
    signature: '',
    defaults: 0,
    variadic: '0',
    argumentModes: null,
    configuration: ['search_path=pg_catalog'],
    body: functionBody(policyGenerationFenceSql, 'guard_policy_generation_fence()'),
  };
  return {
    triggers: [
      ['runtime_configuration_generation', 'TRY_CIGL_INSERT'],
      ['policy_activation_occurrence', 'TRY'],
      ['policy_activation_occurrence_target', 'TRY'],
      ['cigl_settings', 'TRY'],
    ].map(([table, mode]) => ({
      tableSchema: 'control',
      tableName: table!,
      tableOwner: 'openpc_control_owner',
      tableKind: 'r',
      rowSecurity: true,
      inherits: false,
      name: `${table}_reference_fence`,
      type: 30,
      enabled: 'O',
      internal: false,
      constraint: '0',
      parent: '0',
      deferrable: false,
      initiallyDeferred: false,
      argumentCount: 1,
      arguments: Buffer.from(`${mode}\0`).toString('hex'),
      columns: '',
      condition: null,
      oldTable: null,
      newTable: null,
      function: { ...owner },
    })),
    grantFunctions: [
      {
        ...owner,
        name: 'lock_cigl_grant_sources',
        returnType: 'void',
        signature: 'p_fail_fast boolean',
        configuration: ['search_path=pg_catalog, control'],
        body: functionBody(ciglGrantGuardsSql, 'lock_cigl_grant_sources(p_fail_fast boolean)'),
      },
    ],
  };
}
const allFenceIssues = [
  'ACTIVATION_OCCURRENCE_WRITE_FENCE',
  'CIGL_SETTINGS_WRITE_FENCE',
  'RUNTIME_GENERATION_WRITE_FENCE',
];
describe('named migration declaration exports', () => {
  it('reads the actual named SQL export through the active module loader', async () => {
    const namespace = await import(
      new URL(
        '../../../services/module-registry/src/db/policy-generation-fence.mjs',
        import.meta.url,
      ).href
    );
    expect(Object.getOwnPropertyDescriptor(namespace, Symbol.toStringTag)?.value).toBe('Module');
    expect(declarationSql(namespace.policyGenerationFenceSql)).toContain(
      'CREATE OR REPLACE FUNCTION openpc.guard_policy_generation_fence()',
    );
  });
  it('rejects missing or non-string declaration values without coercion', () => {
    const accessor = Object.defineProperty({}, 'toString', {
      get: () => {
        throw new Error('must not coerce');
      },
    });
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    for (const value of [null, undefined, false, [], {}, accessor, 1, () => 'SQL', revoked.proxy])
      expect(declarationSql(value)).toBe('');
  });
});
describe('module reference fence catalog verification', () => {
  it('recognizes exact owned definitions and complete statement coverage without an authority result', () => {
    const catalog = fenceCatalog();
    expect(inspectModuleReferenceWriteFences(catalog)).toEqual([]);
    for (const trigger of catalog.triggers) trigger.enabled = 'A';
    catalog.grantFunctions[0]!.configuration = ['search_path=pg_catalog,control'];
    expect(inspectModuleReferenceWriteFences(catalog)).toEqual([]);
  });
  it('requires both occurrence tables and isolates missing or duplicated coverage to its owner', () => {
    for (const [index, marker] of [
      [0, 'RUNTIME_GENERATION_WRITE_FENCE'],
      [1, 'ACTIVATION_OCCURRENCE_WRITE_FENCE'],
      [2, 'ACTIVATION_OCCURRENCE_WRITE_FENCE'],
      [3, 'CIGL_SETTINGS_WRITE_FENCE'],
    ] as const) {
      const missing = fenceCatalog();
      missing.triggers.splice(index, 1);
      expect(inspectModuleReferenceWriteFences(missing)).toEqual([marker]);
      const duplicate = fenceCatalog();
      duplicate.triggers.push(duplicate.triggers[index]!);
      expect(inspectModuleReferenceWriteFences(duplicate)).toEqual([marker]);
    }
  });
  it('rejects disabled, conditional, row-level, partial or malformed trigger coverage', () => {
    for (const change of [
      { enabled: 'D' },
      { enabled: 'R' },
      { type: 31 },
      { type: 28 },
      { type: 22 },
      { arguments: '' },
      { arguments: Buffer.from('BLOCKING\0').toString('hex') },
      { arguments: Buffer.from('TRY\0EXTRA\0').toString('hex') },
      { arguments: Buffer.from('TRY').toString('hex') },
      { argumentCount: 0 },
      { argumentCount: 2 },
      { condition: 'false' },
      { columns: '1' },
      { name: 'substituted_reference_fence' },
      { tableSchema: 'shadow' },
      { tableOwner: 'openpc_control_runtime' },
      { tableKind: 'p' },
      { inherits: true },
      { rowSecurity: false },
      { internal: true },
      { constraint: '42' },
      { parent: '42' },
      { deferrable: true },
      { initiallyDeferred: true },
      { oldTable: 'old_rows' },
      { newTable: 'new_rows' },
    ]) {
      const catalog = fenceCatalog();
      Object.assign(catalog.triggers[3]!, change);
      expect(inspectModuleReferenceWriteFences(catalog), JSON.stringify(change)).toEqual([
        'CIGL_SETTINGS_WRITE_FENCE',
      ]);
    }
  });
  it('rejects a same-name replaced function and unsafe execution metadata', () => {
    for (const change of [
      { body: '\nBEGIN RETURN NULL; END ' },
      { schema: 'shadow' },
      { name: 'private_fence' },
      { owner: 'openpc_control_runtime' },
      { language: 'sql' },
      { kind: 'p' },
      { volatility: 's' },
      { securityDefiner: true },
      { strict: true },
      { leakproof: true },
      { parallel: 's' },
      { returnsSet: true },
      { support: '42' },
      { signature: 'scope uuid' },
      { defaults: 1 },
      { variadic: '16' },
      { argumentModes: ['i'] },
      { returnSchema: 'shadow' },
      { returnType: 'void' },
      { configuration: null },
      { configuration: ['search_path=public,pg_catalog'] },
      { configuration: ['search_path=pg_catalog', 'session_replication_role=replica'] },
    ]) {
      const catalog = fenceCatalog();
      for (const trigger of catalog.triggers) Object.assign(trigger.function, change);
      expect(inspectModuleReferenceWriteFences(catalog), JSON.stringify(change)).toEqual(
        allFenceIssues,
      );
    }
  });
  it('requires the exact nonblocking grant overload only for generation INSERT coverage', () => {
    for (const change of [
      { signature: '' },
      { signature: 'p_fail_fast text' },
      { body: '\nBEGIN RETURN; END ' },
      { securityDefiner: true },
      { owner: 'openpc_control_worker' },
      { configuration: ['search_path=pg_catalog'] },
    ]) {
      const catalog = fenceCatalog();
      Object.assign(catalog.grantFunctions[0]!, change);
      expect(inspectModuleReferenceWriteFences(catalog)).toEqual([
        'RUNTIME_GENERATION_WRITE_FENCE',
      ]);
    }
    const catalog = fenceCatalog();
    catalog.grantFunctions.push(catalog.grantFunctions[0]!);
    expect(inspectModuleReferenceWriteFences(catalog)).toEqual(['RUNTIME_GENERATION_WRITE_FENCE']);
    catalog.grantFunctions.length = 0;
    expect(inspectModuleReferenceWriteFences(catalog)).toEqual(['RUNTIME_GENERATION_WRITE_FENCE']);
    const wrongMode = fenceCatalog();
    wrongMode.triggers[0]!.arguments = Buffer.from('TRY\0').toString('hex');
    expect(inspectModuleReferenceWriteFences(wrongMode)).toEqual([
      'RUNTIME_GENERATION_WRITE_FENCE',
    ]);
  });
  it('treats caller readiness, malformed catalogs and subsequent definition loss as unresolved', () => {
    for (const value of [
      null,
      {},
      { ready: true },
      { triggers: true, grantFunctions: [] },
      { triggers: [], grantFunctions: [], ready: true },
      { triggers: [null], grantFunctions: [] },
    ])
      expect(inspectModuleReferenceWriteFences(value)).toEqual(allFenceIssues);
    const catalog = fenceCatalog();
    expect(inspectModuleReferenceWriteFences(catalog)).toEqual([]);
    catalog.triggers[1]!.function.body = '\nBEGIN RETURN NULL; END ';
    expect(inspectModuleReferenceWriteFences(catalog)).toEqual([
      'ACTIVATION_OCCURRENCE_WRITE_FENCE',
    ]);
  });
});

describe('module preflight observations grant no lifecycle authority', () => {
  const request = {
    operation: 'MOD-OP-DISABLE',
    moduleInstallationId: id('1'),
    expectedRevision: '3',
    generation: '1',
    manifestDigest: tagged(hash(1)),
    configurationDigest: tagged(hash(2)),
  };
  it('rejects caller readiness fields, unsupported operations, lossy revisions and extra scope', () => {
    expect(moduleLifecyclePreflightRequest.safeParse(request).success).toBe(true);
    for (const changes of [
      { dependencyClosed: true },
      { custodyClosed: true },
      { operation: 'MOD-OP-ENABLE' },
      { expectedRevision: 3 },
      { expectedRevision: '03' },
      { participantId: id('101') },
    ])
      expect(moduleLifecyclePreflightRequest.safeParse({ ...request, ...changes }).success).toBe(
        false,
      );
  });
  it('requires the exact prior observation identity on revalidation', () => {
    const observed = { observationDigest: tagged(hash(7)) } as Parameters<
      typeof assertModuleLifecycleObservationUnchanged
    >[1];
    expect(() => assertModuleLifecycleObservationUnchanged(tagged(hash(6)), observed)).toThrow(
      'PC-MODULE-7009',
    );
    expect(() => assertModuleLifecycleObservationUnchanged('true', observed)).toThrow(
      'PC-MODULE-7009',
    );
  });
});

const disableFenceTables = [
  'module_installation',
  'module_configuration_generation',
  'module_version',
  'module_dependency',
  'module_capability',
  'policy_generation',
  'policy_version',
  'policy_artifact',
  'runtime_configuration_input',
  'configuration_work',
  'runtime_configuration_generation',
  'runtime_target',
  'policy_activation_occurrence',
  'policy_activation_occurrence_target',
  'provider_profile',
  'indexer_profile',
  'projection_plan',
];
function disableFenceCatalog() {
  // Classifier fixture only; installed SQL bodies and executable lock behavior
  // are checked separately on real PostgreSQL in the existing runtime suite.
  const declaration = readFileSync(
    new URL(
      '../../../services/module-registry/src/db/module-lifecycle-guards.mjs',
      import.meta.url,
    ),
    'utf8',
  );
  const body = declaration
    .split('CREATE OR REPLACE FUNCTION openpc.guard_module_reference_write_fence()')[1]
    ?.match(/AS \$\$([\s\S]*?)\$\$;/u)?.[1];
  if (!body) throw new Error('missing module reference fence declaration');
  const original = fenceCatalog().triggers[0]!;
  return disableFenceTables.map((table) => ({
    ...original,
    tableName: table,
    name: `a_module_reference_fence_${table}`,
    type: 62,
    rowSecurity: !['module_version', 'module_dependency', 'module_capability'].includes(table),
    forceRowSecurity: ![
      'module_version',
      'module_dependency',
      'module_capability',
      'runtime_configuration_input',
      'configuration_work',
      'runtime_configuration_generation',
      'runtime_target',
      'provider_profile',
      'indexer_profile',
      'projection_plan',
    ].includes(table),
    argumentCount: 0,
    arguments: '',
    function: { ...original.function, name: 'guard_module_reference_write_fence', body },
  }));
}

describe('DISABLE complete producer fences and closed owner predicates', () => {
  it('recognizes complete global/scoped statement and truncate coverage and rejects each missing table', () => {
    const catalog = disableFenceCatalog();
    expect(inspectModuleDisableWriteFences(catalog)).toEqual([]);
    for (const table of disableFenceTables) {
      expect(
        inspectModuleDisableWriteFences(catalog.filter((row) => row.tableName !== table)),
      ).toEqual([`MODULE_REFERENCE_WRITE_FENCE:${table}`]);
      const row = catalog.find((item) => item.tableName === table)!;
      expect(inspectModuleDisableWriteFences([...catalog, row])).toEqual([
        `MODULE_REFERENCE_WRITE_FENCE:${table}`,
      ]);
    }
  });
  it('rejects names without the complete owned execution body, statement events and safe metadata', () => {
    for (const change of [
      { type: 30 },
      { type: 63 },
      { enabled: 'D' },
      { enabled: 'R' },
      { argumentCount: 1 },
      { condition: 'false' },
      { tableOwner: 'openpc_control_runtime' },
      { rowSecurity: false },
      { forceRowSecurity: false },
      { inherits: true },
    ]) {
      const catalog = disableFenceCatalog();
      Object.assign(catalog[0]!, change);
      expect(inspectModuleDisableWriteFences(catalog)).toEqual([
        'MODULE_REFERENCE_WRITE_FENCE:module_installation',
      ]);
    }
    for (const change of [
      { body: 'BEGIN RETURN NULL; END' },
      { securityDefiner: true },
      { owner: 'openpc_control_runtime' },
      { configuration: ['search_path=public'] },
    ]) {
      const catalog = disableFenceCatalog();
      Object.assign(catalog[0]!.function, change);
      expect(inspectModuleDisableWriteFences(catalog)).toEqual([
        'MODULE_REFERENCE_WRITE_FENCE:module_installation',
      ]);
    }
  });
  it('does not confuse absent, unknown or non-applicable owner evidence with a clear DISABLE predicate', () => {
    const names = [
      'reverseDependencies',
      'policyReferences',
      'configurationReferences',
      'runtimeReferences',
      'factProjectionDrain',
      'uiInvalidation',
      'grantAndOwnedDataSafety',
      'custodyDisposition',
    ];
    const observation = () =>
      ({
        operation: 'MOD-OP-DISABLE',
        target,
        observationDigest: tagged(hash(8)),
        predicates: Object.fromEntries(
          names.map((key) => [
            key,
            {
              status: key === 'custodyDisposition' ? 'NOT_APPLICABLE' : 'CLEAR',
              references: [],
              unresolved: [],
            },
          ]),
        ),
      }) as unknown as Parameters<typeof requireModuleDisablePredicates>[0];
    expect(() => requireModuleDisablePredicates(observation())).not.toThrow();
    for (const name of names) {
      const missing = observation();
      Reflect.deleteProperty(missing.predicates, name);
      expect(() => requireModuleDisablePredicates(missing)).toThrow('PC-MODULE-7009');
      for (const status of ['BLOCKED', 'UNRESOLVED']) {
        const unresolved = observation();
        Object.assign(Reflect.get(unresolved.predicates, name), { status });
        expect(() => requireModuleDisablePredicates(unresolved)).toThrow('PC-MODULE-7009');
      }
      for (const field of ['references', 'unresolved']) {
        const retained = observation();
        Object.assign(Reflect.get(retained.predicates, name), { [field]: ['retained obligation'] });
        expect(() => requireModuleDisablePredicates(retained)).toThrow('PC-MODULE-7009');
      }
    }
    for (const name of names.slice(0, -1)) {
      const unresolved = observation();
      Object.assign(Reflect.get(unresolved.predicates, name), { status: 'NOT_APPLICABLE' });
      expect(() => requireModuleDisablePredicates(unresolved)).toThrow('PC-MODULE-7009');
    }
  });
});

it('stops a bounded observation before native work when its lifetime ends', () => {
  expect(() =>
    inspectModulePolicyReferences([], target, () => {
      throw new Error('observer expired');
    }),
  ).toThrow('observer expired');
});
