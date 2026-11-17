import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { businessTransitionProfileForOperation } from '@openpc/security-kernel';
import {
  transitionStatePreimage,
  type CborValue,
} from '@openpc/security-kernel/business-transition/state';

import { ConfigurationRepositoryError } from '../../../control-api/src/configuration/persistence/types.js';
import { sha256 as configurationDigest } from '../../../control-api/src/configuration/digest.js';
import {
  AuthorityFenceError,
  fenceBoundAuthorities,
} from '../../../identity-service/src/db/authority-fence.js';
import { canonicalJson } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';
import { publicModuleSchema, type PublicModule } from '../public-module-list-pagination.js';
import { assertActionIntent, type PublicApprovalScope } from './public-approval-store.js';
// The committed export remains stable when M2 moves its implementation to a leaf.
import { readVerifiedModuleLifecycleSnapshot } from './module-lifecycle-store.js';
import { dependencyClosure, type ModuleReleaseVerifier } from './module-release-store.js';
// @ts-expect-error The existing migration declaration is JavaScript-only.
import { moduleLifecycleGuardSql } from './module-lifecycle-guards.mjs';

type Snapshot = Awaited<ReturnType<typeof readVerifiedModuleLifecycleSnapshot>>;
const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const hex = (value: Buffer) => `sha256:${value.toString('hex')}`;
const bytesDigest = (value: Buffer) => hex(createHash('sha256').update(value).digest());
const hash = (value: unknown) => hex(createHash('sha256').update(canonicalJson(value)).digest());
const unavailable = (): never => {
  throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
};
const revision = publicModuleSchema.shape.revision.refine((value) => value !== '0');
const inventorySchema = z.strictObject({
  id: uuid,
  versionId: uuid,
  state: z.enum(['ADMITTED', 'INSTALLED_DISABLED', 'ENABLED']),
  revision,
  moduleId: publicModuleSchema.shape.name,
  semanticVersion: publicModuleSchema.shape.semanticVersion,
  manifest: digest,
  manifestBytes: digest,
  signer: digest,
  releasePayload: digest,
  releaseSignature: digest,
  desired: digest,
  dependency: digest,
  activeManifest: digest.nullable(),
  configurationId: uuid,
  generation: z.literal('1'),
  active: z.boolean(),
  configuration: digest,
  configurationBytes: digest,
  operation: uuid.nullable(),
  evaluation: digest.nullable(),
  signedRelease: z.literal(true),
  createdAt: publicModuleSchema.shape.createdAt,
  updatedAt: publicModuleSchema.shape.updatedAt,
});
type Inventory = z.infer<typeof inventorySchema>;
const maxModules = 33;

/** R1 supports one exact configuration per admitted module. The inventory is
 * deliberately unfiltered: unsupported state, absent payload or broken joins
 * cannot disappear behind the verified snapshot's serving-state predicate. */
async function inventory(client: PoolClient, scope: PublicApprovalScope): Promise<Inventory[]> {
  const result = await client.query<{ value: unknown }>(
    `select jsonb_build_object(
    'id',i.module_installation_id,'versionId',i.module_version_id,'state',i.state,'revision',i.aggregate_version::text,
    'moduleId',v.module_id,'semanticVersion',v.semantic_version,
    'manifest','sha256:'||encode(v.manifest_digest,'hex'),'manifestBytes','sha256:'||encode(sha256(v.manifest_cbor),'hex'),
    'signer','sha256:'||encode(v.release_signer_key_digest,'hex'),
    'releasePayload','sha256:'||encode(sha256(v.release_payload_cbor),'hex'),
    'releaseSignature','sha256:'||encode(sha256(v.cose_sign1),'hex'),
    'desired','sha256:'||encode(i.desired_manifest_digest,'hex'),
    'dependency','sha256:'||encode(i.admission_dependency_digest,'hex'),
    'activeManifest','sha256:'||encode(i.active_manifest_digest,'hex'),
    'configurationId',c.generation_id,'generation',c.generation::text,'active',c.active,
    'configuration','sha256:'||encode(c.configuration_digest,'hex'),
    'configurationBytes','sha256:'||encode(sha256(c.configuration_cbor),'hex'),
    'operation',i.lifecycle_operation_id,'evaluation','sha256:'||encode(i.lifecycle_evaluation_digest,'hex'),
    'signedRelease',v.release_payload_cbor is not null,
    'createdAt',to_char(i.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'updatedAt',to_char(i.updated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) value
    from control.module_installation i left join control.module_version v using(module_version_id)
    left join control.module_configuration_generation c on c.module_installation_id=i.module_installation_id
      and c.participant_id=i.participant_id and c.privacy_domain_id=i.privacy_domain_id
    where i.participant_id=$1 and i.privacy_domain_id=$2
    order by i.module_installation_id,c.generation_id limit $3`,
    [scope.participantId, scope.privacyDomainId, maxModules + 1],
  );
  const parsed = z
    .array(inventorySchema)
    .max(maxModules)
    .safeParse(result.rows.map((row) => row.value));
  if (
    !parsed.success ||
    new Set(parsed.data.map((row) => row.id)).size !== parsed.data.length ||
    new Set(parsed.data.map((row) => row.moduleId)).size !== parsed.data.length
  )
    return unavailable();
  return parsed.data;
}

/** Compare actual scope inventory with the existing verified owner, before
 * filtering/pagination. Exported for malformed-input regressions, not admission. */
export function assertModuleListCoverage(raw: unknown, snapshot: Snapshot): readonly Inventory[] {
  const parsed = z.array(inventorySchema).max(maxModules).safeParse(raw);
  if (
    !parsed.success ||
    parsed.data.length !== snapshot.length ||
    new Set(parsed.data.map((row) => row.id)).size !== parsed.data.length ||
    new Set(parsed.data.map((row) => row.moduleId)).size !== parsed.data.length ||
    new Set(snapshot.map((row) => row.stored.moduleInstallationId)).size !== snapshot.length
  )
    return unavailable();
  for (const row of parsed.data) {
    const match = snapshot.find((item) => item.stored.moduleInstallationId === row.id);
    if (!match) return unavailable();
    const { stored, release, configuration } = match;
    if (
      stored.moduleVersionId !== row.versionId ||
      stored.state !== row.state ||
      stored.revision !== row.revision ||
      stored.lifecycleOperationId !== row.operation ||
      release.manifest.metadata.id !== row.moduleId ||
      release.manifest.metadata.version !== row.semanticVersion ||
      row.manifest !== hex(release.manifestDigest) ||
      row.manifestBytes !== row.manifest ||
      row.desired !== row.manifest ||
      row.signer !== hex(release.signerKeyDigest) ||
      row.releasePayload !== bytesDigest(release.payloadCbor) ||
      row.releaseSignature !== bytesDigest(release.coseSign1) ||
      !stored.admissionDependencyDigest ||
      row.dependency !== hex(stored.admissionDependencyDigest) ||
      row.configuration !== hex(release.configurationDigest) ||
      row.configurationBytes !== row.configuration ||
      configuration.id !== row.id ||
      row.configurationId !== configuration.configurationId ||
      row.configuration !== hex(configuration.digest) ||
      configuration.generation !== row.generation ||
      configuration.active !== row.active ||
      configuration.operationId !== row.operation ||
      (configuration.evaluationDigest ? hex(configuration.evaluationDigest) : null) !==
        row.evaluation ||
      (configuration.activeManifest ? hex(configuration.activeManifest) : null) !==
        row.activeManifest ||
      (row.state === 'ENABLED'
        ? !row.active || row.activeManifest !== row.manifest
        : row.active || row.activeManifest !== null) ||
      (row.state === 'ADMITTED'
        ? row.revision !== '1' || row.operation !== null || row.evaluation !== null
        : row.revision === '1' || row.operation === null || row.evaluation === null)
    )
      return unavailable();
  }
  return parsed.data;
}

const fencedTables = [
  'module_installation',
  'module_configuration_generation',
  'module_version',
  'module_dependency',
  'module_capability',
] as const;
/** The SQL body comes from the existing migration owner, not a copied guard.
 * Pre-M2 source or missing/drifted installation intentionally cannot serve this reader. */
export function moduleListFenceDeclaration(sql: unknown): string | undefined {
  if (typeof sql !== 'string') return undefined;
  const start =
    'CREATE OR REPLACE FUNCTION openpc.guard_module_reference_write_fence()\nRETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$';
  const parts = sql.split(start);
  if (parts.length !== 2) return undefined;
  const end = parts[1]!.indexOf('$$;');
  if (end <= 0) return undefined;
  for (const table of fencedTables) {
    const declaration = `CREATE TRIGGER a_module_reference_fence_${table} BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON control.${table}\n FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_module_reference_write_fence();`;
    if (sql.split(declaration).length !== 2) return undefined;
  }
  return parts[1]!.slice(0, end);
}

async function requireFences(client: PoolClient) {
  const body = moduleListFenceDeclaration(moduleLifecycleGuardSql);
  if (!body) return unavailable();
  const result = await client.query<{ valid: boolean }>(
    `select count(*)=$3 and bool_and(
    n.nspname='control' and o.rolname='openpc_control_owner' and c.relkind='r'
    and not c.relispartition and not exists(select 1 from pg_catalog.pg_inherits i where i.inhparent=c.oid or i.inhrelid=c.oid)
    and c.relrowsecurity=(c.relname in ('module_installation','module_configuration_generation'))
    and c.relforcerowsecurity=c.relrowsecurity
    and t.tgtype=62 and t.tgenabled in ('O','A') and not t.tgisinternal and t.tgconstraint=0 and t.tgparentid=0
    and not t.tgdeferrable and not t.tginitdeferred and t.tgnargs=0 and octet_length(t.tgargs)=0
    and t.tgattr::text='' and t.tgqual is null and t.tgoldtable is null and t.tgnewtable is null
    and fn.nspname='openpc' and fo.rolname='openpc_control_owner' and p.proname='guard_module_reference_write_fence'
    and l.lanname='plpgsql' and p.prokind='f' and p.provolatile='v' and not p.prosecdef and not p.proisstrict
    and not p.proleakproof and p.proparallel='u' and not p.proretset and p.prosupport=0
    and p.prorettype='pg_catalog.trigger'::regtype and p.pronargs=0 and p.pronargdefaults=0 and p.provariadic=0
    and p.proargmodes is null and p.proconfig=array['search_path=pg_catalog']::text[] and p.prosrc=$2
  ) valid from pg_catalog.pg_trigger t join pg_catalog.pg_class c on c.oid=t.tgrelid
    join pg_catalog.pg_namespace n on n.oid=c.relnamespace join pg_catalog.pg_roles o on o.oid=c.relowner
    join pg_catalog.pg_proc p on p.oid=t.tgfoid join pg_catalog.pg_namespace fn on fn.oid=p.pronamespace
    join pg_catalog.pg_roles fo on fo.oid=p.proowner join pg_catalog.pg_language l on l.oid=p.prolang
    where n.nspname='control' and c.relname=any($1::text[]) and t.tgname='a_module_reference_fence_'||c.relname`,
    [fencedTables, body, fencedTables.length],
  );
  if (result.rows[0]?.valid !== true) return unavailable();
}

async function catalogueProjection(client: PoolClient, snapshot: Snapshot) {
  const result = await client.query<{ id: string; dependencies: unknown; capabilities: unknown }>(
    `select v.module_version_id::text id,
      coalesce((select jsonb_agg(d.value order by d.value::text) from
        (select jsonb_build_object('edgeId',edge_id,'providerModuleId',provider_module_id,
          'capabilityId',capability_id,'version',semantic_version,
          'manifestDigest','sha256:'||encode(provider_manifest_digest,'hex')) value
         from control.module_dependency where consumer_module_version_id=v.module_version_id
         order by edge_id limit 1025) d),'[]'::jsonb) dependencies,
      coalesce((select jsonb_agg(c.value order by c.value::text) from
        (select jsonb_build_object('capabilityId',capability_id,'contractDigest','sha256:'||encode(contract_digest,'hex')) value
         from control.module_capability where module_version_id=v.module_version_id
         order by capability_id limit 1025) c),'[]'::jsonb) capabilities
      from control.module_version v where v.module_version_id=any($1::uuid[]) order by v.module_version_id`,
    [snapshot.map((item) => item.stored.moduleVersionId)],
  );
  if (result.rows.length !== snapshot.length) return unavailable();
  const ordered = (value: unknown) => {
    if (!Array.isArray(value) || value.length > 1024) return unavailable();
    return value.map((item: unknown) => canonicalJson(item)).sort();
  };
  for (const row of result.rows) {
    const item = snapshot.find((value) => value.stored.moduleVersionId === row.id);
    if (!item) return unavailable();
    const expectedDependencies = item.release.manifest.dependencies.map((edge) => ({
      edgeId: edge.edgeId,
      providerModuleId: edge.providerModuleId,
      capabilityId: edge.capabilityId,
      version: edge.version,
      manifestDigest: edge.manifestDigest,
    }));
    const expectedCapabilities = item.release.manifest.capabilities.provided.map((capability) => ({
      capabilityId: capability.capabilityId,
      contractDigest: configurationDigest(capability),
    }));
    if (
      canonicalJson(ordered(row.dependencies)) !== canonicalJson(ordered(expectedDependencies)) ||
      canonicalJson(ordered(row.capabilities)) !== canonicalJson(ordered(expectedCapabilities))
    )
      return unavailable();
  }
  return result.rows.map((row) => ({
    id: row.id,
    dependencies: ordered(row.dependencies),
    capabilities: ordered(row.capabilities),
  }));
}

type Provenance = {
  id: string;
  operation: string;
  operationId: string;
  profileDigest: Buffer;
  afterPreimage: Buffer;
  receiptDigest: Buffer;
};
async function provenance(
  client: PoolClient,
  scope: PublicApprovalScope,
  rows: readonly Inventory[],
) {
  const result = await client.query<Provenance>(
    `select a.aggregate_id::text id,a.catalog_operation_id operation,
    a.operation_id::text as "operationId",a.profile_digest as "profileDigest",
    a.after_state_preimage as "afterPreimage",a.receipt_digest as "receiptDigest"
    from control.module_installation i join control.audit_occurrence a
      on a.participant_id=i.participant_id and a.privacy_domain_id=i.privacy_domain_id
      and a.aggregate_type='module-registration' and a.aggregate_id=i.module_installation_id and a.after_revision=i.aggregate_version
    join control.evidence_record e on e.participant_id=a.participant_id
      and e.privacy_domain_id=a.privacy_domain_id and e.receipt_id=a.receipt_id
    where i.participant_id=$1 and i.privacy_domain_id=$2 and a.after_existence=1
      and a.receipt_digest=sha256(a.receipt_cbor) and e.receipt_digest=a.receipt_digest
      and e.recorded_at_ns=a.recorded_at_ns
      and a.after_state_digest=sha256(a.after_state_preimage)
      and openpc.business_cbor(a.receipt_cbor)->'4'=openpc.business_bytes(a.profile_digest)
      and openpc.business_cbor(a.receipt_cbor)->'6'=openpc.business_uuid(a.participant_id)
      and openpc.business_cbor(a.receipt_cbor)->'7'=openpc.business_uuid(a.privacy_domain_id)
      and openpc.business_cbor(a.receipt_cbor)->'8'=openpc.business_uuid(a.operation_id)
      and openpc.business_cbor(a.receipt_cbor)->>'10'=a.catalog_operation_id
      and openpc.business_cbor(a.receipt_cbor)->>'11'=a.aggregate_type
      and openpc.business_cbor(a.receipt_cbor)->'12'=openpc.business_uuid(a.aggregate_id)
      and openpc.business_cbor(a.receipt_cbor)->'19'=jsonb_build_object('0',1,'1',a.after_revision,'2',openpc.business_bytes(a.after_state_digest))
      and exists(select 1 from control.outbox_event event where event.participant_id=a.participant_id
        and event.privacy_domain_id=a.privacy_domain_id and event.receipt_id=a.receipt_id
        and event.aggregate_type=a.aggregate_type and event.aggregate_id=a.aggregate_id
        and event.proof_kind='BUSINESS_RECEIPT_REFERENCE' and event.event_type='io.openpc.control.command.committed.v1'
        and event.payload_digest=sha256(event.payload_cbor))
      and (i.state='ADMITTED' and a.catalog_operation_id='MOD-OP-REGISTER' or
        i.lifecycle_operation_id=a.operation_id and a.catalog_operation_id in ('MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE'))
      and (i.state='ADMITTED' or exists(select 1 from control.module_lifecycle_evaluation evaluation
        where evaluation.participant_id=i.participant_id and evaluation.privacy_domain_id=i.privacy_domain_id
          and evaluation.module_installation_id=i.module_installation_id and evaluation.operation_id=i.lifecycle_operation_id
          and evaluation.revision=i.aggregate_version and evaluation.result_digest=i.lifecycle_evaluation_digest
          and evaluation.result_digest=sha256(evaluation.result_cbor)))
      and exists(select 1 from control.idempotency_record idempotency where idempotency.participant_id=a.participant_id
        and idempotency.privacy_domain_id=a.privacy_domain_id and idempotency.operation_id=a.operation_id
        and idempotency.terminal_state='COMMITTED' and idempotency.result_digest is not null and idempotency.result_payload is not null)
    order by a.aggregate_id,a.receipt_id limit $3`,
    [scope.participantId, scope.privacyDomainId, maxModules + 1],
  );
  if (
    result.rows.length !== rows.length ||
    new Set(result.rows.map((row) => row.id)).size !== rows.length
  )
    return unavailable();
  return result.rows;
}

function stateProjection(
  row: Inventory,
  proof: Provenance,
  scope: PublicApprovalScope,
): PublicModule['state'] {
  const expected =
    row.state === 'ADMITTED'
      ? ['MOD-OP-REGISTER']
      : row.state === 'ENABLED'
        ? ['MOD-OP-ENABLE']
        : ['MOD-OP-INSTALL', 'MOD-OP-DISABLE'];
  const profile = businessTransitionProfileForOperation(proof.operation);
  if (
    !profile ||
    !expected.includes(proof.operation) ||
    profile.aggregateType !== 'module-registration' ||
    !Buffer.isBuffer(proof.profileDigest) ||
    hex(proof.profileDigest) !== profile.profileDigest ||
    !Buffer.isBuffer(proof.afterPreimage) ||
    !Buffer.isBuffer(proof.receiptDigest) ||
    proof.receiptDigest.length !== 32 ||
    (row.state !== 'ADMITTED' && proof.operationId !== row.operation)
  )
    return unavailable();
  const projection = new Map<number, CborValue>([
    [0, row.moduleId],
    [1, row.semanticVersion],
    [2, Buffer.from(row.manifest.slice(7), 'hex')],
    [3, Buffer.from(row.dependency.slice(7), 'hex')],
    [4, Buffer.from(row.configuration.slice(7), 'hex')],
    [5, row.state],
    [6, row.activeManifest === null ? 0n : 1n],
    [7, BigInt(row.generation)],
    [8, row.active ? 1n : 0n],
  ]);
  if (row.evaluation) projection.set(9, Buffer.from(row.evaluation.slice(7), 'hex'));
  if (row.activeManifest) projection.set(10, Buffer.from(row.activeManifest.slice(7), 'hex'));
  const bytes = transitionStatePreimage(
    {
      profileDigest: proof.profileDigest,
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      aggregateType: 'module-registration',
      aggregateId: row.id,
    },
    1,
    BigInt(row.revision),
    projection,
  );
  if (!bytes.equals(proof.afterPreimage)) return unavailable();
  return proof.operation === 'MOD-OP-REGISTER'
    ? 'REGISTERED'
    : proof.operation === 'MOD-OP-ENABLE'
      ? 'ACTIVE'
      : proof.operation === 'MOD-OP-DISABLE'
        ? 'DISABLED'
        : 'INSTALLED';
}

export interface CurrentPublicModules {
  readonly items: readonly PublicModule[];
  /** Private current source fingerprint; never sent as a public generation. */
  readonly snapshotDigest: string;
  readonly authorityDigest: string;
}
export function moduleListAuthorityDigest(scope: PublicApprovalScope): string {
  return hash({
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    authority: scope.authority,
  });
}

/** No writes, signing, synthetic readiness or cross-store observation. A fresh
 * connection and READ COMMITTED reads avoid inheriting a pre-fence MVCC snapshot. */
export async function readCurrentPublicModules(
  pool: Pool,
  inputScope: PublicApprovalScope,
  verify: ModuleReleaseVerifier,
): Promise<CurrentPublicModules> {
  const scope = { ...inputScope, authority: { ...inputScope.authority } };
  if (
    scope.actionIntentId !== 'ACT-MODULES_READ_COLLECTION-V1' ||
    scope.authority.actionIntentId !== scope.actionIntentId ||
    !['*', scope.participantId].includes(scope.authority.resourceId) ||
    scope.authority.privacyDomainId !== scope.privacyDomainId ||
    scope.authority.principalId !== scope.principalId ||
    !uuid.safeParse(scope.participantId).success ||
    !uuid.safeParse(scope.privacyDomainId).success
  )
    throw new AuthorityFenceError();
  const started = performance.now();
  const assertTime = () => {
    if (performance.now() - started > 30_000) return unavailable();
  };
  // The hosting Pool must also have its existing finite connection timeout. A
  // late checkout is released; timeout does not leak a subsequently granted client.
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const checkout = pool.connect().then((value) => {
    if (timedOut) {
      value.release();
      return unavailable();
    }
    return value;
  });
  const client = await Promise.race([
    checkout,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        reject(new ConfigurationRepositoryError('PC-INTEGRATION-5001'));
      }, 5000);
    }),
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
  let open = false;
  try {
    await client.query('begin isolation level read committed');
    open = true;
    await client.query("set local statement_timeout='3s'");
    await client.query("set local lock_timeout='1s'");
    await client.query("set local idle_in_transaction_session_timeout='35s'");
    await client.query('set local row_security=on');
    const identity = await client.query<{
      safe: boolean;
    }>(`select current_database()='openpc_control'
      and not rolsuper and not rolbypassrls and current_user<>'openpc_control_owner'
      and (pg_has_role(current_user,'openpc_control_runtime','MEMBER') or pg_has_role(current_user,'openpc_control_reader','MEMBER')) safe
      from pg_catalog.pg_roles where rolname=current_user`);
    if (identity.rows[0]?.safe !== true) return unavailable();
    await client.query(
      `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
      [scope.participantId, scope.privacyDomainId, scope.operationId, scope.actionIntentId],
    );
    await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
    await assertActionIntent(client, scope, 'READ', ['modules']);
    for (const key of [
      'module-release-catalog',
      `module-admission:${scope.participantId}:${scope.privacyDomainId}`,
    ]) {
      const locked = await client.query<{ acquired: boolean }>(
        'select pg_try_advisory_xact_lock_shared(hashtextextended($1,0)) acquired',
        [key],
      );
      if (locked.rows[0]?.acquired !== true) return unavailable();
    }
    assertTime();
    await requireFences(client);
    const before = await inventory(client, scope);
    const snapshot = await readVerifiedModuleLifecycleSnapshot(
      client,
      scope.participantId,
      scope.privacyDomainId,
      verify,
    );
    const rows = assertModuleListCoverage(before, snapshot);
    const catalogue = await catalogueProjection(client, snapshot);
    const proofs = await provenance(client, scope, rows);
    const retained = new Map(
      snapshot.map(({ release }) => [
        `${release.manifest.metadata.id}@${release.manifest.metadata.version}:${hex(release.manifestDigest)}`,
        release,
      ]),
    );
    const items: PublicModule[] = [];
    for (const row of rows) {
      assertTime();
      const item = snapshot.find((value) => value.stored.moduleInstallationId === row.id)!;
      const proof = proofs.find((value) => value.id === row.id);
      if (!proof) return unavailable();
      const closure = await dependencyClosure(
        client,
        scope,
        item.release,
        verify,
        Date.now(),
        retained,
      );
      if (`sha256:${closure.closureDigest}` !== row.dependency) return unavailable();
      const state = stateProjection(row, proof, scope);
      items.push(
        publicModuleSchema.parse({
          moduleId: `urn:openpc:resource:${row.id}`,
          name: row.moduleId,
          semanticVersion: row.semanticVersion,
          manifestDigest: row.manifest,
          supportProfile: 'R1',
          state,
          revision: row.revision,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
        }),
      );
    }
    // Recheck trust at response release, not just at the first graph read.
    for (const item of snapshot) {
      assertTime();
      verify(item.stored, Date.now());
    }
    await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
    if (hash(await inventory(client, scope)) !== hash(before)) return unavailable();
    if (hash(await catalogueProjection(client, snapshot)) !== hash(catalogue)) return unavailable();
    assertTime();
    const result = {
      items,
      snapshotDigest: hash({
        inventory: before,
        catalogue,
        items,
        proofs: proofs.map((proof) => ({
          id: proof.id,
          operation: proof.operation,
          operationId: proof.operationId,
          receipt: hex(proof.receiptDigest),
        })),
      }),
      authorityDigest: moduleListAuthorityDigest(scope),
    };
    await client.query('commit');
    open = false;
    return result;
  } catch (error) {
    if (error instanceof AuthorityFenceError || error instanceof ConfigurationRepositoryError)
      throw error;
    if (error instanceof ContractError && ['PC-POLICY-2004', 'PC-POLICY-2005'].includes(error.code))
      throw error;
    // Invalid internal state, unavailable trust, parse and DB errors never look empty.
    return unavailable();
  } finally {
    let destroyed = false;
    if (open) {
      try {
        await client.query('rollback');
      } catch {
        client.release(true);
        destroyed = true;
      }
    }
    if (!destroyed) client.release();
  }
}
