import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
// @ts-expect-error The existing migration owner is JavaScript-only; its export is checked below.
import { preparationGuardsSql as preparationDeclaration } from '../../../control-api/src/configuration/preparation-guards.mjs';
// @ts-expect-error The existing migration owner is JavaScript-only; its export is checked below.
import { ciglGrantGuardsSql as ciglGrantDeclaration } from '../../../control-api/src/configuration/cigl/grant-guards.mjs';
import {
  AuthorityFenceError,
  fenceBoundAuthorities,
} from '../../../identity-service/src/db/authority-fence.js';
import { pcCbor1 } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';
import { validatePolicySemantics } from '../domain/policy-semantics.js';
import { resolveDependencies } from '../domain/dependency-resolver.js';
import { readVerifiedModuleLifecycleSnapshot } from './module-lifecycle-snapshot.js';
import type { ModuleReleaseVerifier } from './module-release-store.js';
import { assertActionIntent, type PublicApprovalScope } from './public-approval-store.js';
// @ts-expect-error The existing migration owner is JavaScript-only; its export is checked below.
import { policyGenerationFenceSql as policyFenceDeclaration } from './policy-generation-fence.mjs';

// @ts-expect-error The migration declaration is JavaScript-only; catalogue checked below.
import * as moduleWriteFences from './module-lifecycle-guards.mjs';
const { moduleReferenceWriteFenceSql, moduleReferenceWriteTables, moduleControlReferenceTables } =
  moduleWriteFences;

const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => /^[1-9][0-9]{0,19}$/u.test(value) && BigInt(value) <= 18446744073709551615n);
const hex = (bytes: Buffer) => `sha256:${bytes.toString('hex')}`;
const limit = 128;

export const moduleLifecyclePreflightRequest = z.strictObject({
  operation: z.enum(['MOD-OP-DISABLE', 'MOD-OP-UNINSTALL']),
  moduleInstallationId: uuid,
  expectedRevision: revision,
  generation: revision,
  manifestDigest: digest,
  configurationDigest: digest,
});
export type ModuleLifecyclePreflightRequest = z.infer<typeof moduleLifecyclePreflightRequest>;
type Snapshot = Awaited<ReturnType<typeof readVerifiedModuleLifecycleSnapshot>>;
type Target = {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly moduleInstallationId: string;
  readonly moduleId: string;
  readonly semanticVersion: string;
  readonly revision: string;
  readonly generation: string;
  readonly configurationId: string;
  readonly manifestDigest: string;
  readonly configurationDigest: string;
  readonly state: string;
};
export interface ModuleReferencePredicate {
  readonly status: 'CLEAR' | 'BLOCKED' | 'UNRESOLVED' | 'NOT_APPLICABLE';
  readonly references: readonly string[];
  readonly unresolved: readonly string[];
}
export interface ModuleLifecyclePreflightObservation {
  readonly operation: ModuleLifecyclePreflightRequest['operation'];
  readonly target: Target;
  readonly predicates: Readonly<
    Record<
      | 'reverseDependencies'
      | 'policyReferences'
      | 'configurationReferences'
      | 'runtimeReferences'
      | 'factProjectionDrain'
      | 'uiInvalidation'
      | 'grantAndOwnedDataSafety'
      | 'custodyDisposition',
      ModuleReferencePredicate
    >
  >;
  /** Observation identity only. It grants no permission and is not a transition receipt. */
  readonly observationDigest: string;
}
const predicate = (
  references: string[] = [],
  unresolved: string[] = [],
): ModuleReferencePredicate => ({
  status: unresolved.length ? 'UNRESOLVED' : references.length ? 'BLOCKED' : 'CLEAR',
  references: [...new Set(references)].sort(),
  unresolved: [...new Set(unresolved)].sort(),
});

/** Pure classification of a transaction-local, owner-verified snapshot; never authorization. */
export function inspectModuleReverseDependencies(
  rows: Snapshot,
  targetId: string,
): ModuleReferencePredicate {
  const target = rows.find((row) => row.stored.moduleInstallationId === targetId);
  if (!target) throw new ContractError('PC-MODULE-7009');
  const unresolved: string[] = [];
  const edges = new Map<string, string[]>();
  for (const row of rows) {
    const id = row.stored.moduleInstallationId;
    const providers: string[] = [];
    const { configuration, stored, release } = row;
    if (
      rows.filter((other) => other.release.manifest.metadata.id === release.manifest.metadata.id)
        .length !== 1
    )
      unresolved.push(`AMBIGUOUS_MODULE:${id}`);
    if (
      !revision.safeParse(stored.revision).success ||
      configuration.generation !== '1' ||
      (stored.state === 'ENABLED') !== configuration.active ||
      (configuration.active
        ? !configuration.activeManifest?.equals(release.manifestDigest) ||
          !configuration.operationId ||
          !configuration.evaluationDigest
        : configuration.activeManifest !== null)
    )
      unresolved.push(`MODULE_STATE:${id}`);
    for (const edge of release.manifest.dependencies) {
      const matches = rows.filter(
        (provider) =>
          provider.release.manifest.metadata.id === edge.providerModuleId &&
          provider.release.manifest.metadata.version === edge.version &&
          hex(provider.release.manifestDigest) === edge.manifestDigest &&
          provider.release.manifest.capabilities.provided.some(
            (capability) => capability.capabilityId === edge.capabilityId,
          ),
      );
      if (matches.length !== 1) unresolved.push(`DEPENDENCY_TUPLE:${id}:${edge.edgeId}`);
      else {
        providers.push(matches[0]!.stored.moduleInstallationId);
        if (stored.state === 'ENABLED' && matches[0]!.stored.state !== 'ENABLED')
          unresolved.push(`INACTIVE_PROVIDER:${id}:${edge.edgeId}`);
      }
    }
    edges.set(id, providers);
  }
  const memo = new Map<string, boolean>();
  const reaches = (id: string, visiting: Set<string>): boolean => {
    if (visiting.has(id)) {
      unresolved.push(`DEPENDENCY_CYCLE:${id}`);
      return false;
    }
    if (memo.has(id)) return memo.get(id)!;
    const next = new Set(visiting).add(id);
    // Visit every edge, even after finding the target, so a cycle is never hidden.
    const result = (edges.get(id) ?? [])
      .map((provider) => {
        const downstream = reaches(provider, next);
        return provider === targetId || downstream;
      })
      .some(Boolean);
    memo.set(id, result);
    return result;
  };
  const references = rows
    .filter((row) => {
      const dependent = reaches(row.stored.moduleInstallationId, new Set());
      return (
        row.stored.moduleInstallationId !== targetId && row.stored.state === 'ENABLED' && dependent
      );
    })
    .map((row) => `MODULE:${row.stored.moduleInstallationId}:${row.stored.revision}`);
  // Reuse the dependency owner's digest definition for each retained admission.
  for (const root of rows) {
    const included = new Set<string>();
    const visit = (id: string) => {
      if (included.has(id)) return;
      included.add(id);
      for (const provider of edges.get(id) ?? []) visit(provider);
    };
    visit(root.stored.moduleInstallationId);
    const closure = rows.filter((row) => included.has(row.stored.moduleInstallationId));
    try {
      const resolved = resolveDependencies(
        closure.map(({ release }) => ({
          moduleId: release.manifest.metadata.id,
          semanticVersion: release.manifest.metadata.version,
          manifestDigest: hex(release.manifestDigest),
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
      if (root.stored.admissionDependencyDigest?.toString('hex') !== resolved.closureDigest)
        throw new Error();
    } catch {
      unresolved.push(`ADMISSION_CLOSURE:${root.stored.moduleInstallationId}`);
    }
  }
  return predicate(references, unresolved);
}

export interface ModulePreflightPolicyRow {
  id: string;
  generation: string;
  state: string;
  active: boolean;
  generationDigest: Buffer;
  dependencyDigest: Buffer;
  semanticDigest: Buffer;
  semantic: Buffer | null;
  versionSemantic: Buffer | null;
  artifactDigest: Buffer | null;
  artifactDependency: Buffer | null;
}
/** Production decoder and exact signed artifact/version binding; no caller authority. */
export function inspectModulePolicyReferences(
  rows: readonly ModulePreflightPolicyRow[],
  target: Target,
  assertCurrent: () => void = () => undefined,
) {
  const issues: string[] = rows.length > limit ? ['POLICY_LIMIT'] : [];
  const matching = new Set<string>();
  const references: string[] = [];
  const known = new Map<string, string>();
  const decodedVersions = new Map<string, ReturnType<typeof validatePolicySemantics>>();
  for (const row of rows.slice(0, limit)) {
    assertCurrent();
    try {
      if (
        !Buffer.isBuffer(row.semantic) ||
        !Buffer.isBuffer(row.generationDigest) ||
        row.generationDigest.length !== 32 ||
        !row.semantic.equals(row.versionSemantic ?? Buffer.alloc(0))
      )
        throw new Error();
      const key = row.semanticDigest.toString('hex');
      const cached = decodedVersions.get(key);
      const decoded = cached?.bytes.equals(row.semantic)
        ? cached
        : validatePolicySemantics(Array.from(row.semantic), 'DECODE_SEMANTICS');
      if (
        !decoded.bytes.equals(row.semantic) ||
        !decoded.digest.equals(row.semanticDigest) ||
        !decoded.digest.equals(row.artifactDigest ?? Buffer.alloc(0)) ||
        decoded.document.participantId !== target.participantId ||
        decoded.document.privacyDomainId !== target.privacyDomainId ||
        !pcCbor1(decoded.document.moduleBindings).digest.equals(row.dependencyDigest) ||
        !row.dependencyDigest.equals(row.artifactDependency ?? Buffer.alloc(0))
      )
        throw new Error();
      decodedVersions.set(key, decoded);
      const policyDigest = hex(row.generationDigest);
      if (known.has(policyDigest)) throw new Error();
      known.set(policyDigest, row.id);
      const bindings = decoded.document.moduleBindings.filter(
        (binding) => binding.moduleId === target.moduleId,
      );
      if (bindings.length > 1) throw new Error();
      if (!bindings.length) continue;
      const binding = bindings[0]!;
      if (
        binding.semanticVersion !== target.semanticVersion ||
        binding.manifestDigest !== target.manifestDigest ||
        binding.configurationDigest !== target.configurationDigest
      )
        throw new Error();
      matching.add(policyDigest);
      if (row.state !== 'RETIRED' || row.active)
        references.push(`POLICY:${row.id}:${row.generation}`);
    } catch {
      issues.push(`POLICY_BINDING:${row.id}`);
    }
  }
  assertCurrent();
  return { predicate: predicate(references, issues), matching, known };
}
const common = {
  id: uuid,
  revision: z.string().regex(/^(0|[1-9][0-9]{0,18})$/u),
  state: z.string().min(1),
};
const ownerReference = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('INPUT'),
    ...common,
    installation: uuid,
    configurationId: uuid,
    configuration: digest,
    bindings: z.array(z.record(z.string(), z.unknown())).max(1024),
    bindingsCurrent: z.boolean(),
  }),
  z.strictObject({
    kind: z.literal('WORK'),
    ...common,
    policy: digest.nullable(),
    configuration: digest,
    generationId: uuid.nullable(),
    targetId: uuid.nullable(),
  }),
  z.strictObject({
    kind: z.literal('RUNTIME'),
    ...common,
    policy: digest,
    generation: digest,
    predecessor: digest.nullable(),
    targetId: uuid,
  }),
  z.strictObject({
    kind: z.literal('TARGET'),
    ...common,
    policy: digest.nullable(),
    active: digest.nullable(),
    desired: digest.nullable(),
  }),
  z.strictObject({ kind: z.literal('ACTIVATION'), ...common, policyId: uuid }),
  z.strictObject({
    kind: z.literal('ACTIVATION_TARGET'),
    ...common,
    policyId: uuid,
    generationId: uuid.nullable(),
    targetId: uuid,
    phase: z.enum(['FORWARD', 'ROLLBACK']),
  }),
  z.strictObject({
    kind: z.enum(['PROVIDER', 'INDEXER', 'PROJECTION']),
    ...common,
    policy: digest.nullable(),
  }),
]);
type OwnerReference = z.infer<typeof ownerReference>;

// Select original rows, not only "current" views: an invalidated view must never
// conceal retained obligations. Each branch is bounded independently.
const referenceQueries = [
  `select jsonb_build_object('kind','INPUT','id',runtime_configuration_input_id,'revision','1',
    'state',case when selected then 'SELECTED' else 'RETAINED' end,'installation',module_installation_id,
    'configurationId',module_configuration_generation_id,'configuration','sha256:'||encode(configuration_digest,'hex'),
    'bindings',resource_bindings,'bindingsCurrent',openpc.runtime_configuration_bindings_current(participant_id,privacy_domain_id,resource_bindings)) reference from control.runtime_configuration_input`,
  `select jsonb_build_object('kind','WORK','id',configuration_work_id,'revision',attempt_count::text||'',
    'state',state,'policy',policy_generation_digest,'configuration',configuration_digest,
    'generationId',runtime_configuration_generation_id,'targetId',runtime_target_id) reference from control.configuration_work`,
  `select jsonb_build_object('kind','RUNTIME','id',runtime_configuration_generation_id,'revision',revision::text,
    'state',state,'policy',policy_generation_digest,'generation',generation_digest,'predecessor',predecessor_digest,
    'targetId',runtime_target_id) reference from control.runtime_configuration_generation`,
  `select jsonb_build_object('kind','TARGET','id',runtime_target_id,'revision',revision::text,'state',state,
    'policy',policy_generation_digest,'active',active_generation_digest,'desired',desired_generation_digest) reference from control.runtime_target`,
  `select jsonb_build_object('kind','ACTIVATION','id',activation_occurrence_id,'revision',revision::text,
    'state',state,'policyId',policy_generation_id) reference from control.policy_activation_occurrence`,
  `select jsonb_build_object('kind','ACTIVATION_TARGET','id',t.activation_occurrence_id,'revision',t.expected_target_revision::text,
    'state',t.state,'policyId',o.policy_generation_id,'generationId',t.runtime_configuration_generation_id,
    'targetId',t.runtime_target_id,'phase',t.phase) reference from control.policy_activation_occurrence_target t
    left join control.policy_activation_occurrence o on o.participant_id=t.participant_id
      and o.privacy_domain_id=t.privacy_domain_id and o.activation_occurrence_id=t.activation_occurrence_id`,
  ...[
    ['PROVIDER', 'provider_profile', 'provider_profile_id'],
    ['INDEXER', 'indexer_profile', 'indexer_profile_id'],
    ['PROJECTION', 'projection_plan', 'projection_plan_id'],
  ].map(
    ([kind, table, id]) =>
      `select jsonb_build_object('kind','${kind}','id',${id},'revision',revision::text,'state',state,
      'policy',policy_generation_digest) reference from control.${table}`,
  ),
];

async function readOwners(
  client: Pick<PoolClient, 'query'>,
  scope: Pick<PublicApprovalScope, 'participantId' | 'privacyDomainId'>,
  assertCurrent: () => void = () => undefined,
) {
  const rows: OwnerReference[] = [];
  const unresolved: string[] = [];
  for (const [index, query] of referenceQueries.entries()) {
    assertCurrent();
    const alias = index === 5 ? 't.' : '';
    const result = await client.query<{ reference: unknown }>(
      `select reference from (${query}
      where ${alias}participant_id=$1 and ${alias}privacy_domain_id=$2) observed order by reference::text limit $3`,
      [scope.participantId, scope.privacyDomainId, limit + 1],
    );
    if (result.rows.length > limit) unresolved.push(`REFERENCE_LIMIT:${index}`);
    for (const row of result.rows.slice(0, limit)) {
      const parsed = ownerReference.safeParse(row.reference);
      if (!parsed.success) unresolved.push(`REFERENCE_SHAPE:${index}`);
      else rows.push(parsed.data);
    }
  }
  assertCurrent();
  return { rows, unresolved };
}

/** Validate the named value imported from each trusted migration owner. Module
 * namespace descriptors vary across Node and the test loader and are not SQL. */
export function declarationSql(value: unknown): string {
  return typeof value === 'string' ? value : '';
}
const preparationGuardsSql = declarationSql(preparationDeclaration);
const ciglGrantGuardsSql = declarationSql(ciglGrantDeclaration);
const policyGenerationFenceSql = declarationSql(policyFenceDeclaration);

const referenceFenceOwners = [
  [
    'runtime_configuration_generation',
    'TRY_CIGL_INSERT',
    'RUNTIME_GENERATION_WRITE_FENCE',
    preparationGuardsSql,
  ],
  [
    'policy_activation_occurrence',
    'TRY',
    'ACTIVATION_OCCURRENCE_WRITE_FENCE',
    policyGenerationFenceSql,
  ],
  [
    'policy_activation_occurrence_target',
    'TRY',
    'ACTIVATION_OCCURRENCE_WRITE_FENCE',
    policyGenerationFenceSql,
  ],
  ['cigl_settings', 'TRY', 'CIGL_SETTINGS_WRITE_FENCE', preparationGuardsSql],
] as const;
const ownedFenceFunction = z.strictObject({
  schema: z.literal('openpc'),
  owner: z.literal('openpc_control_owner'),
  name: z.string(),
  language: z.literal('plpgsql'),
  kind: z.literal('f'),
  volatility: z.literal('v'),
  securityDefiner: z.literal(false),
  strict: z.literal(false),
  leakproof: z.literal(false),
  parallel: z.literal('u'),
  returnsSet: z.literal(false),
  support: z.literal('0'),
  returnSchema: z.literal('pg_catalog'),
  returnType: z.string(),
  signature: z.string(),
  defaults: z.literal(0),
  variadic: z.literal('0'),
  argumentModes: z.null(),
  configuration: z.array(z.string()).length(1),
  body: z.string(),
});
const ownedFenceTrigger = z.strictObject({
  tableSchema: z.literal('control'),
  tableName: z.string(),
  tableOwner: z.literal('openpc_control_owner'),
  tableKind: z.literal('r'),
  rowSecurity: z.literal(true),
  inherits: z.literal(false),
  name: z.string(),
  type: z.literal(30),
  enabled: z.enum(['O', 'A']),
  internal: z.literal(false),
  constraint: z.literal('0'),
  parent: z.literal('0'),
  deferrable: z.literal(false),
  initiallyDeferred: z.literal(false),
  argumentCount: z.literal(1),
  arguments: z.string(),
  columns: z.literal(''),
  condition: z.null(),
  oldTable: z.null(),
  newTable: z.null(),
  function: ownedFenceFunction,
});

// Read the body from its existing migration declaration, never a second SQL
// implementation or a name-only allowlist. An unsupported declaration shape
// fails closed until this reader is deliberately updated with its owner.
function declaredFenceBody(sql: string, signature: string, result: string, searchPath: string) {
  const declaration = `CREATE OR REPLACE FUNCTION openpc.${signature}\nRETURNS ${result} LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=${searchPath} AS $$`;
  const parts = sql.split(declaration);
  if (parts.length !== 2) return undefined;
  const end = parts[1]!.indexOf('$$;');
  return end > 0 ? parts[1]!.slice(0, end) : undefined;
}
function matchesFenceFunction(value: unknown, grant: boolean) {
  const parsed = ownedFenceFunction.safeParse(value);
  if (!parsed.success) return false;
  const expectedBody = grant
    ? declaredFenceBody(
        ciglGrantGuardsSql,
        'lock_cigl_grant_sources(p_fail_fast boolean)',
        'void',
        'pg_catalog,control',
      )
    : declaredFenceBody(
        policyGenerationFenceSql,
        'guard_policy_generation_fence()',
        'trigger',
        'pg_catalog',
      );
  const row = parsed.data;
  return (
    expectedBody !== undefined &&
    row.body === expectedBody &&
    row.name === (grant ? 'lock_cigl_grant_sources' : 'guard_policy_generation_fence') &&
    row.signature === (grant ? 'p_fail_fast boolean' : '') &&
    row.returnType === (grant ? 'void' : 'trigger') &&
    row.configuration[0]!.split(',')
      .map((part) => part.trim())
      .join(',') === (grant ? 'search_path=pg_catalog,control' : 'search_path=pg_catalog')
  );
}

/** Pure catalog classification for the internal reader. It grants no authority;
 * the actual connection supplies these rows again on every revalidation. */
export function inspectModuleReferenceWriteFences(value: unknown): readonly string[] {
  const catalog = z
    .strictObject({ triggers: z.array(z.unknown()), grantFunctions: z.array(z.unknown()) })
    .safeParse(value);
  const unresolved = new Set<string>();
  for (const [table, mode, marker, declaration] of referenceFenceOwners) {
    const rows = catalog.success
      ? catalog.data.triggers.filter((row) => {
          const identity = z.object({ tableName: z.string() }).safeParse(row);
          return identity.success && identity.data.tableName === table;
        })
      : [];
    const parsed = rows.length === 1 ? ownedFenceTrigger.safeParse(rows[0]) : undefined;
    const expectedTrigger = `CREATE TRIGGER ${table}_reference_fence BEFORE INSERT OR UPDATE OR DELETE ON control.${table}\n FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence('${mode}');`;
    if (
      !parsed?.success ||
      declaration.split(expectedTrigger).length !== 2 ||
      parsed.data.name !== `${table}_reference_fence` ||
      parsed.data.arguments !== Buffer.from(`${mode}\0`).toString('hex') ||
      !matchesFenceFunction(parsed.data.function, false) ||
      (mode === 'TRY_CIGL_INSERT' &&
        (!catalog.success ||
          catalog.data.grantFunctions.length !== 1 ||
          !matchesFenceFunction(catalog.data.grantFunctions[0], true)))
    )
      unresolved.add(marker);
  }
  return [...unresolved].sort();
}

/** M2 writers cover every observed producer, including statements affecting no
 * current rows. Validate implementation and complete catalogue, not trigger names. */
export function inspectModuleDisableWriteFences(value: unknown): readonly string[] {
  const parsed = z.array(z.unknown()).safeParse(value);
  const expectedBody = declaredFenceBody(
    declarationSql(moduleReferenceWriteFenceSql),
    'guard_module_reference_write_fence()',
    'trigger',
    'pg_catalog',
  );
  const trigger = ownedFenceTrigger.extend({
    type: z.literal(62),
    argumentCount: z.literal(0),
    arguments: z.literal(''),
    rowSecurity: z.boolean(),
    forceRowSecurity: z.boolean(),
  });
  if (
    !Array.isArray(moduleReferenceWriteTables) ||
    !moduleReferenceWriteTables.length ||
    !expectedBody
  )
    return ['MODULE_REFERENCE_DECLARATION'];
  const issues: string[] = [];
  for (const table of moduleReferenceWriteTables as readonly string[]) {
    const matches = parsed.success
      ? parsed.data.filter((row) => {
          const name = z.object({ tableName: z.string() }).safeParse(row);
          return name.success && name.data.tableName === table;
        })
      : [];
    const item = matches.length === 1 ? trigger.safeParse(matches[0]) : undefined;
    const fn = item?.success ? item.data.function : undefined;
    const scoped = !['module_version', 'module_dependency', 'module_capability'].includes(table);
    if (
      !item?.success ||
      item.data.rowSecurity !== scoped ||
      item.data.forceRowSecurity !== (scoped && !moduleControlReferenceTables.includes(table)) ||
      item.data.name !== `a_module_reference_fence_${table}` ||
      !fn ||
      fn.name !== 'guard_module_reference_write_fence' ||
      fn.signature !== '' ||
      fn.returnType !== 'trigger' ||
      fn.configuration[0] !== 'search_path=pg_catalog' ||
      fn.body !== expectedBody
    )
      issues.push(`MODULE_REFERENCE_WRITE_FENCE:${table}`);
  }
  return issues;
}

const fenceFunctionProjection = `jsonb_build_object(
  'schema',fn.nspname,'owner',fo.rolname,'name',p.proname,'language',l.lanname,
  'kind',p.prokind,'volatility',p.provolatile,'securityDefiner',p.prosecdef,
  'strict',p.proisstrict,'leakproof',p.proleakproof,'parallel',p.proparallel,
  'returnsSet',p.proretset,'support',p.prosupport::oid::text,
  'returnSchema',rn.nspname,'returnType',r.typname,
  'signature',pg_catalog.pg_get_function_identity_arguments(p.oid),
  'defaults',p.pronargdefaults,'variadic',p.provariadic::text,'argumentModes',p.proargmodes,
  'configuration',p.proconfig,'body',p.prosrc)`;
const fenceFunctionJoins = `join pg_catalog.pg_namespace fn on fn.oid=p.pronamespace
  join pg_catalog.pg_roles fo on fo.oid=p.proowner
  join pg_catalog.pg_language l on l.oid=p.prolang
  join pg_catalog.pg_type r on r.oid=p.prorettype
  join pg_catalog.pg_namespace rn on rn.oid=r.typnamespace`;
async function readReferenceWriteFences(client: Pick<PoolClient, 'query'>) {
  const triggers = await client.query<{ definition: unknown }>(
    `select jsonb_build_object(
    'tableSchema',n.nspname,'tableName',c.relname,'tableOwner',o.rolname,'tableKind',c.relkind,
    'rowSecurity',c.relrowsecurity,
    'inherits',c.relispartition or exists(select 1 from pg_catalog.pg_inherits i where i.inhparent=c.oid or i.inhrelid=c.oid),
    'name',t.tgname,'type',t.tgtype,'enabled',t.tgenabled,'internal',t.tgisinternal,
    'constraint',t.tgconstraint::text,'parent',t.tgparentid::text,
    'deferrable',t.tgdeferrable,'initiallyDeferred',t.tginitdeferred,
    'argumentCount',t.tgnargs,'arguments',encode(t.tgargs,'hex'),'columns',t.tgattr::text,
    'condition',t.tgqual::text,'oldTable',t.tgoldtable,'newTable',t.tgnewtable,
    'function',${fenceFunctionProjection}) definition
    from pg_catalog.pg_trigger t join pg_catalog.pg_class c on c.oid=t.tgrelid
    join pg_catalog.pg_namespace n on n.oid=c.relnamespace join pg_catalog.pg_roles o on o.oid=c.relowner
    join pg_catalog.pg_proc p on p.oid=t.tgfoid ${fenceFunctionJoins}
    where n.nspname='control' and c.relname=any($1::text[])
      and t.tgname=c.relname||'_reference_fence'`,
    [referenceFenceOwners.map(([table]) => table)],
  );
  const grants = await client.query<{
    definition: unknown;
  }>(`select ${fenceFunctionProjection} definition
    from pg_catalog.pg_proc p ${fenceFunctionJoins}
    where fn.nspname='openpc' and p.proname='lock_cigl_grant_sources'
      and p.pronargs=1 and p.proargtypes[0]='pg_catalog.bool'::regtype`);
  return inspectModuleReferenceWriteFences({
    triggers: triggers.rows.map((row) => row.definition),
    grantFunctions: grants.rows.map((row) => row.definition),
  });
}

async function readDisableWriteFences(client: Pick<PoolClient, 'query'>) {
  const rows = await client.query<{ definition: unknown }>(
    `select jsonb_build_object(
    'tableSchema',n.nspname,'tableName',c.relname,'tableOwner',o.rolname,'tableKind',c.relkind,
    'rowSecurity',c.relrowsecurity,'forceRowSecurity',c.relforcerowsecurity,
    'inherits',c.relispartition or exists(select 1 from pg_catalog.pg_inherits i where i.inhparent=c.oid or i.inhrelid=c.oid),
    'name',t.tgname,'type',t.tgtype,'enabled',t.tgenabled,'internal',t.tgisinternal,
    'constraint',t.tgconstraint::text,'parent',t.tgparentid::text,
    'deferrable',t.tgdeferrable,'initiallyDeferred',t.tginitdeferred,
    'argumentCount',t.tgnargs,'arguments',encode(t.tgargs,'hex'),'columns',t.tgattr::text,
    'condition',t.tgqual::text,'oldTable',t.tgoldtable,'newTable',t.tgnewtable,
    'function',${fenceFunctionProjection}) definition
    from pg_catalog.pg_trigger t join pg_catalog.pg_class c on c.oid=t.tgrelid
    join pg_catalog.pg_namespace n on n.oid=c.relnamespace join pg_catalog.pg_roles o on o.oid=c.relowner
    join pg_catalog.pg_proc p on p.oid=t.tgfoid ${fenceFunctionJoins}
    where n.nspname='control' and c.relname=any($1::text[])
      and t.tgname='a_module_reference_fence_'||c.relname`,
    [moduleReferenceWriteTables],
  );
  return inspectModuleDisableWriteFences(rows.rows.map((row) => row.definition));
}

export async function observeModuleLifecycleReferences(
  client: Pick<PoolClient, 'query'>,
  scope: Pick<PublicApprovalScope, 'participantId' | 'privacyDomainId'>,
  request: ModuleLifecyclePreflightRequest,
  verify: ModuleReleaseVerifier,
  assertCurrent: () => void = () => undefined,
): Promise<ModuleLifecyclePreflightObservation> {
  assertCurrent();
  const inventory = await client.query<{ id: string; state: string }>(
    `select module_installation_id::text id,state from control.module_installation
     where participant_id=$1 and privacy_domain_id=$2 order by module_installation_id limit 34`,
    [scope.participantId, scope.privacyDomainId],
  );
  if (inventory.rows.length > 33) throw new ContractError('PC-MODULE-7003');
  const modules = await readVerifiedModuleLifecycleSnapshot(
    client,
    scope.participantId,
    scope.privacyDomainId,
    verify,
  );
  assertCurrent();
  const root = modules.find(
    (row) => row.stored.moduleInstallationId === request.moduleInstallationId,
  );
  if (
    !root ||
    root.stored.revision !== request.expectedRevision ||
    root.configuration.generation !== request.generation ||
    hex(root.release.manifestDigest) !== request.manifestDigest ||
    hex(root.release.configurationDigest) !== request.configurationDigest ||
    root.stored.state !==
      (request.operation === 'MOD-OP-DISABLE' ? 'ENABLED' : 'INSTALLED_DISABLED')
  )
    throw new ContractError('PC-MODULE-7009');
  const target: Target = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    moduleInstallationId: root.stored.moduleInstallationId,
    moduleId: root.release.manifest.metadata.id,
    semanticVersion: root.release.manifest.metadata.version,
    revision: root.stored.revision,
    generation: root.configuration.generation,
    configurationId: root.configuration.configurationId,
    manifestDigest: hex(root.release.manifestDigest),
    configurationDigest: hex(root.release.configurationDigest),
    state: root.stored.state,
  };
  const reverse = inspectModuleReverseDependencies(modules, target.moduleInstallationId);
  const projections = await client.query<{
    id: string;
    dependencies: unknown;
    capabilities: unknown;
  }>(
    `select i.module_installation_id::text id,
    coalesce((select jsonb_agg(jsonb_build_object('edgeId',d.edge_id,'providerModuleId',d.provider_module_id,
      'capabilityId',d.capability_id,'version',d.semantic_version,'manifestDigest','sha256:'||encode(d.provider_manifest_digest,'hex'))
      order by d.edge_id) from control.module_dependency d where d.consumer_module_version_id=i.module_version_id),'[]'::jsonb) dependencies,
    coalesce((select jsonb_agg(jsonb_build_object('capabilityId',c.capability_id,'contractDigest','sha256:'||encode(c.contract_digest,'hex'))
      order by c.capability_id) from control.module_capability c where c.module_version_id=i.module_version_id),'[]'::jsonb) capabilities
    from control.module_installation i where i.participant_id=$1 and i.privacy_domain_id=$2 order by i.module_installation_id`,
    [scope.participantId, scope.privacyDomainId],
  );
  const projectionIssues: string[] = [];
  const projectionDigest = (value: unknown) =>
    Array.isArray(value) ? sha256(value.map((item: unknown) => sha256(item)).sort()) : null;
  for (const row of modules) {
    const projection = projections.rows.find((item) => item.id === row.stored.moduleInstallationId);
    const dependencies = row.release.manifest.dependencies
      .map((edge) => ({
        edgeId: edge.edgeId,
        providerModuleId: edge.providerModuleId,
        capabilityId: edge.capabilityId,
        version: edge.version,
        manifestDigest: edge.manifestDigest,
      }))
      .sort((a, b) => a.edgeId.localeCompare(b.edgeId));
    const capabilities = row.release.manifest.capabilities.provided
      .map((capability) => ({
        capabilityId: capability.capabilityId,
        contractDigest: sha256(capability),
      }))
      .sort((a, b) => a.capabilityId.localeCompare(b.capabilityId));
    if (
      !projection ||
      projectionDigest(projection.dependencies) !== projectionDigest(dependencies) ||
      projectionDigest(projection.capabilities) !== projectionDigest(capabilities)
    )
      projectionIssues.push(`MODULE_PROJECTION:${row.stored.moduleInstallationId}`);
  }
  const missing = inventory.rows.filter(
    (row) => !modules.some((module) => module.stored.moduleInstallationId === row.id),
  );
  assertCurrent();
  const policies = await client.query<ModulePreflightPolicyRow>(
    `select g.policy_generation_id::text id,g.generation::text,g.state,g.active,
      g.generation_digest as "generationDigest",g.dependency_closure_digest as "dependencyDigest",
      v.semantic_digest as "semanticDigest",v.semantic_cbor as "versionSemantic",a.semantic_cbor as semantic,
      a.semantic_digest as "artifactDigest",a.dependency_closure_digest as "artifactDependency"
     from control.policy_generation g
     left join control.policy_version v on (v.participant_id,v.privacy_domain_id,v.policy_version_id)=
       (g.participant_id,g.privacy_domain_id,g.policy_version_id)
     left join control.policy_artifact a on (a.participant_id,a.privacy_domain_id,a.policy_id,a.semantic_version,a.semantic_digest)=
       (v.participant_id,v.privacy_domain_id,v.policy_id,v.version,v.semantic_digest)
     where g.participant_id=$1 and g.privacy_domain_id=$2 order by g.policy_generation_id limit $3`,
    [scope.participantId, scope.privacyDomainId, limit + 1],
  );
  const policy = inspectModulePolicyReferences(policies.rows, target, assertCurrent);
  const { matching, known: knownPolicies } = policy;
  const policyIssues = policy.predicate.unresolved;
  const owners = await readOwners(client, scope, assertCurrent);
  assertCurrent();
  const unresolvedFences = await readReferenceWriteFences(client);
  const configurationReferences: string[] = [];
  const configurationIssues: string[] = [...owners.unresolved];
  const inputFence = await client.query<{ installed: boolean }>(`select exists (
    select 1 from pg_catalog.pg_trigger t join pg_catalog.pg_proc p on p.oid=t.tgfoid
    where t.tgrelid='control.runtime_configuration_input'::regclass
      and t.tgname='runtime_input_reference_fence' and t.tgenabled in ('O','A')
      and t.tgtype=30 and p.proname='guard_runtime_input_reference_fence'
      and p.pronamespace='openpc'::regnamespace) installed`);
  if (inputFence.rows[0]?.installed !== true)
    configurationIssues.push('RUNTIME_INPUT_REFERENCE_FENCE_NOT_INSTALLED');
  const runtimeReferences: string[] = [];
  const runtimeIssues: string[] = [...owners.unresolved, ...policyIssues];
  const inputs = owners.rows.filter((row) => row.kind === 'INPUT');
  const relevantConfigurations = new Set(
    inputs
      .filter((row) => row.installation === target.moduleInstallationId)
      .map((row) => row.configuration),
  );
  for (const row of owners.rows) {
    const ref = `${row.kind}:${row.id}:${row.revision}`;
    if (row.kind === 'INPUT') {
      if (row.installation !== target.moduleInstallationId) continue;
      if (row.configurationId !== target.configurationId)
        configurationIssues.push(`CONFIGURATION_GENERATION:${row.id}`);
      if (!row.bindingsCurrent) configurationIssues.push(`RESOURCE_BINDINGS:${row.id}`);
      if (
        row.bindings.some((binding) => binding.kind === 'CiglSettings') &&
        unresolvedFences.includes('CIGL_SETTINGS_WRITE_FENCE')
      )
        configurationIssues.push('CIGL_SETTINGS_WRITE_FENCE');
      if (row.state === 'SELECTED') configurationReferences.push(ref);
      continue;
    }
    const policy = 'policy' in row ? row.policy : undefined;
    if (policy && !knownPolicies.has(policy)) runtimeIssues.push(`POLICY_LINK:${ref}`);
    const policyId = 'policyId' in row ? row.policyId : undefined;
    if (policyId && ![...knownPolicies.values()].includes(policyId))
      runtimeIssues.push(`POLICY_LINK:${ref}`);
    const linked =
      (policy && matching.has(policy)) ||
      (policyId && [...matching].some((value) => knownPolicies.get(value) === policyId)) ||
      (row.kind === 'WORK' && relevantConfigurations.has(row.configuration));
    if (linked) runtimeReferences.push(ref);
    if (row.kind === 'WORK' && !inputs.some((input) => input.configuration === row.configuration))
      runtimeIssues.push(`CONFIGURATION_LINK:${ref}`);
    if (
      'generationId' in row &&
      row.generationId !== null &&
      !owners.rows.some(
        (generation) => generation.kind === 'RUNTIME' && generation.id === row.generationId,
      )
    )
      runtimeIssues.push(`RUNTIME_LINK:${ref}`);
    if (
      'targetId' in row &&
      row.targetId !== null &&
      !owners.rows.some((targetRow) => targetRow.kind === 'TARGET' && targetRow.id === row.targetId)
    )
      runtimeIssues.push(`TARGET_LINK:${ref}`);
  }
  runtimeIssues.push(
    ...unresolvedFences.filter((marker) => marker !== 'CIGL_SETTINGS_WRITE_FENCE'),
    ...(request.operation === 'MOD-OP-DISABLE' ? await readDisableWriteFences(client) : []),
  );
  const predicates: ModuleLifecyclePreflightObservation['predicates'] = {
    reverseDependencies: predicate(
      [...reverse.references],
      [
        ...reverse.unresolved,
        ...projectionIssues,
        ...missing.map((row) => `UNVERIFIED_MODULE:${row.id}`),
      ],
    ),
    policyReferences: policy.predicate,
    configurationReferences: predicate(configurationReferences, configurationIssues),
    runtimeReferences: predicate(runtimeReferences, runtimeIssues),
    factProjectionDrain: predicate([], ['FACT_CANDIDATE_DRAIN_OWNER_REQUIRED']),
    uiInvalidation: predicate([], ['MODULE_UI_GENERATION_OWNER_REQUIRED']),
    grantAndOwnedDataSafety: predicate([], ['MODULE_GRANT_DATA_REFERENCE_OWNER_REQUIRED']),
    custodyDisposition:
      request.operation === 'MOD-OP-UNINSTALL'
        ? predicate([], ['MODULE_CUSTODY_DISPOSITION_OWNER_REQUIRED'])
        : { status: 'NOT_APPLICABLE', references: [], unresolved: [] },
  };
  assertCurrent();
  const observationDigest = sha256({
    operation: request.operation,
    target,
    predicates,
    modules: modules.map(({ stored, release, configuration }) => ({
      id: stored.moduleInstallationId,
      revision: stored.revision,
      state: stored.state,
      manifest: hex(release.manifestDigest),
      configuration: hex(configuration.digest),
      generation: configuration.generation,
      active: configuration.active,
      configurationId: configuration.configurationId,
      activeManifest: configuration.activeManifest ? hex(configuration.activeManifest) : null,
      evaluation: configuration.evaluationDigest ? hex(configuration.evaluationDigest) : null,
      operationId: configuration.operationId,
      admissionDependency: stored.admissionDependencyDigest
        ? hex(stored.admissionDependencyDigest)
        : null,
      signerKey: hex(release.signerKeyDigest),
    })),
    policies: policies.rows.map((row) => ({
      id: row.id,
      generation: row.generation,
      state: row.state,
      active: row.active,
      digest: Buffer.isBuffer(row.generationDigest) ? hex(row.generationDigest) : null,
      semanticDigest: Buffer.isBuffer(row.semanticDigest) ? hex(row.semanticDigest) : null,
      dependencyDigest: Buffer.isBuffer(row.dependencyDigest) ? hex(row.dependencyDigest) : null,
      artifactDigest: row.artifactDigest ? hex(row.artifactDigest) : null,
      artifactDependency: row.artifactDependency ? hex(row.artifactDependency) : null,
    })),
    references: owners.rows,
  });
  return { operation: request.operation, target, predicates, observationDigest };
}

/** Fences are nonblocking and acquired before reference row reads. The caller
 * owns a READ COMMITTED transaction: later rereads must not reuse an MVCC snapshot. */
export async function lockModuleLifecycleReferences(
  client: Pick<PoolClient, 'query'>,
  scope: Pick<PublicApprovalScope, 'participantId' | 'privacyDomainId'>,
) {
  for (const [key, shared] of [
    ['module-release-catalog', true],
    [`module-admission:${scope.participantId}:${scope.privacyDomainId}`, false],
    [`openpc-policy-generations:${scope.participantId}:${scope.privacyDomainId}`, true],
  ] as const) {
    const result = await client.query<{ acquired: boolean }>(
      `select pg_try_advisory_xact_lock${shared ? '_shared' : ''}(hashtextextended($1,0)) acquired`,
      [key],
    );
    if (result.rows[0]?.acquired !== true) throw new ContractError('PC-MODULE-7009');
  }
}

export function assertModuleLifecycleObservationUnchanged(
  expected: string,
  observed: ModuleLifecyclePreflightObservation,
) {
  if (!digest.safeParse(expected).success || expected !== observed.observationDigest)
    throw new ContractError('PC-MODULE-7009');
}

export function freezeModuleLifecycleObservation(observation: ModuleLifecyclePreflightObservation) {
  Object.freeze(observation.target);
  for (const value of Object.values(observation.predicates)) {
    Object.freeze(value.references);
    Object.freeze(value.unresolved);
    Object.freeze(value);
  }
  Object.freeze(observation.predicates);
  return Object.freeze(observation);
}

/** Internal authorized read owner. Callback results cannot escape this lifetime;
 * the returned observation is data only. No transition or signing capability is exposed. */
export async function withModuleLifecyclePreflight(
  pool: Pool,
  scope: PublicApprovalScope,
  input: ModuleLifecyclePreflightRequest,
  verify: ModuleReleaseVerifier,
  inspect: (
    observation: ModuleLifecyclePreflightObservation,
    revalidate: () => Promise<void>,
  ) => Promise<void>,
): Promise<ModuleLifecyclePreflightObservation> {
  const parsed = moduleLifecyclePreflightRequest.safeParse(input);
  if (!parsed.success) throw new ContractError('PC-MODULE-7000');
  const request = parsed.data;
  scope = { ...scope, authority: { ...scope.authority } };
  if (
    scope.authority.privacyDomainId !== scope.privacyDomainId ||
    scope.authority.actionIntentId !== scope.actionIntentId ||
    scope.authority.principalId !== scope.principalId ||
    scope.authority.resourceId !== request.moduleInstallationId
  )
    throw new ContractError('PC-POLICY-2004');
  if (
    !uuid.safeParse(scope.participantId).success ||
    !uuid.safeParse(scope.privacyDomainId).success
  )
    throw new ContractError('PC-POLICY-2004');
  const participant = scope.participantId;
  const privacy = scope.privacyDomainId;
  const client = await pool.connect();
  let open = false;
  let pending = Promise.resolve();
  let failed = false;
  let firstFailure: unknown;
  try {
    // Identity's existing authority fence uses row locks. No business DML or
    // client handle is exposed by this read owner.
    await client.query('begin isolation level read committed');
    await client.query("set local statement_timeout='5s'");
    await client.query("set local lock_timeout='2s'");
    await client.query('set local row_security=on');
    await client.query(
      `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
      [participant, privacy, scope.operationId, scope.actionIntentId],
    );
    await fenceBoundAuthorities(client, participant, [scope.authority]);
    await assertActionIntent(client, scope, 'READ', ['modules']);
    await lockModuleLifecycleReferences(client, scope);
    const observation = freezeModuleLifecycleObservation(
      await observeModuleLifecycleReferences(client, scope, request, verify),
    );
    const expectedDigest = observation.observationDigest;
    open = true;
    const revalidate = () => {
      if (!open) return Promise.reject(new ContractError('PC-MODULE-7009'));
      const current = pending.then(async () => {
        if (failed) throw firstFailure;
        await fenceBoundAuthorities(client, participant, [scope.authority]);
        assertModuleLifecycleObservationUnchanged(
          expectedDigest,
          await observeModuleLifecycleReferences(client, scope, request, verify),
        );
      });
      // Retain failure even if the callback catches it; serialize borrowed reads
      // and settle them before rollback/disposal, including unawaited callbacks.
      pending = current.then(
        () => undefined,
        (error: unknown) => {
          if (!failed) {
            failed = true;
            firstFailure = error;
          }
        },
      );
      return current;
    };
    await inspect(observation, revalidate);
    await revalidate();
    open = false;
    await client.query('commit');
    return observation;
  } catch (error) {
    open = false;
    await pending;
    await client.query('rollback').catch(() => undefined);
    if (error instanceof AuthorityFenceError) throw new ContractError('PC-POLICY-2004');
    throw error;
  } finally {
    open = false;
    client.release(true);
  }
}
