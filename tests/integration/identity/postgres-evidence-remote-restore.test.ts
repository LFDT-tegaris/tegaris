import { execFile } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';
import Fastify from 'fastify';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import type { InstalledFactConsumerProfile } from '../../../packages/security-kernel/src/index.js';
import { requireFactConsumerProfile } from '../../../services/control-api/src/fact-consumers/profile-store.js';
import { installInitialFleetConsumerProfile } from '../local-runtime/fact-consumer-bootstrap.js';
import { installInitialFleetFailureSigner } from '../local-runtime/fact-failure-bootstrap.js';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { ProtectedRemoteArchiveCustody } from '../../../services/control-api/src/evidence/protected-remote-custody.js';
import { PostgresRemoteArchiveAttemptOwner } from '../../../services/control-api/src/evidence/remote-archive-owner.js';
import { RemoteEvidenceArchive } from '../../../services/control-api/src/evidence/remote-archive.js';
import {
  remoteArchiveIntent,
  remoteArchiveReceipt,
  retentionMicros,
  type RemoteArchiveProfile,
} from '../../../services/control-api/src/evidence/remote-archive-contracts.js';
import type { S3ArchiveCredentials } from '../../../services/control-api/src/evidence/remote-archive-s3.js';
import { openRemoteArchiveRuntime } from '../../../services/control-api/src/evidence/remote-archive-runtime.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { registerConfigurationRoutes } from '../../../services/control-api/src/configuration/http.js';
import { createLocalConfigurationAuthorizer } from '../../../services/control-api/src/configuration/local-authorizer.js';
import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import {
  buildLocalIdentityRuntime,
  readLocalIdentityRuntimeConfig,
} from '../../../services/identity-service/src/local-runtime.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { controlDatabaseRecoveryFixture } from './control-database-recovery-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';
import { evidenceArchiveAuthorityFixture } from './evidence-archive-authority-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && workerUrl && runtimeUrl ? it : it.skip;
const execute = promisify(execFile);
const time = (offset: number) =>
  new Date(Date.now() + offset).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
type Scope = { participantId: string; privacyDomainId: string; streamId: string };
type Governance = Awaited<ReturnType<typeof contractAdministrationFixture>>;
type ArchiveTrust = Awaited<ReturnType<typeof evidenceArchiveAuthorityFixture>>;
type MountedArchive = NonNullable<ArchiveTrust['runtimeConfiguration']>;
interface ExternalObject {
  key: string;
  versionId: string;
  bytes: string;
  retention: string;
  initialHold: 'ON' | 'OFF';
  deleteMarker?: boolean;
  metadata: Record<string, string>;
}
interface ExternalArchive {
  endpoint: string;
  faults: {
    dropPutResponse: boolean;
    dropHoldResponse: boolean;
    wrongVersion: boolean;
    corruptRead: boolean;
    forceHold: 'ON' | 'OFF' | null;
  };
  counts: { puts: number; holds: number; gets: number; lists: number };
  objects(): Promise<ExternalObject[]>;
  rewriteVersion(original: ExternalObject, patch: Partial<ExternalObject>): Promise<void>;
  close(): Promise<void>;
}
const fleetGuardUrl = new URL(
  '../../../services/control-api/src/configuration/fleet-fact-guards.mjs',
  import.meta.url,
);
const { fleetFactGuardsSql } = (await import(fleetGuardUrl.href)) as { fleetFactGuardsSql: string };
expect(typeof fleetFactGuardsSql).toBe('string');
const profileGuardUrl = new URL(
  '../../../services/control-api/src/fact-consumers/profile-guards.mjs',
  import.meta.url,
);
const { factConsumerProfileGuardsSql } = (await import(profileGuardUrl.href)) as {
  factConsumerProfileGuardsSql: string;
};
const deliveryGuardUrl = new URL(
  '../../../services/control-api/src/fact-consumers/fleet-delivery-guards.mjs',
  import.meta.url,
);
const { fleetDeliveryGuardsSql } = (await import(deliveryGuardUrl.href)) as {
  fleetDeliveryGuardsSql: string;
};
const failureGuardUrl = new URL(
  '../../../services/control-api/src/fact-consumers/failure-guards.mjs',
  import.meta.url,
);
const { factConsumerFailureGuardsSql } = (await import(failureGuardUrl.href)) as {
  factConsumerFailureGuardsSql: string;
};
const fixtureUrl = new URL('../local-runtime/evidence-remote-archive-fixture.mjs', import.meta.url);
const { startRemoteArchiveFixture } = (await import(fixtureUrl.href)) as {
  startRemoteArchiveFixture(options: {
    root: string;
    bucket: string;
    expectedOwner: string;
    region: string;
    credentials: S3ArchiveCredentials;
  }): Promise<ExternalArchive>;
};

const fleetDeliveryTables = [
  'fleet_fact_delivery',
  'fleet_fact_delivery_attempt',
  'fact_consumer_failure_signer',
  'fleet_fact_quarantine',
  'fleet_fact_failure_outbox',
] as const;
const fleetScopedTables = [
  'fleet_fact_admission_inbox',
  'fleet_fact_admission_cursor',
  ...fleetDeliveryTables.filter((name) => name !== 'fact_consumer_failure_signer'),
] as const;
const fleetTables = [
  ...fleetScopedTables,
  'fleet_fact_admission_key',
  'fact_consumer_profile',
  'fact_consumer_failure_signer',
] as const;
const tables = [
  'participant',
  'privacy_domain',
  'principal',
  'credential',
  'session',
  'authority_envelope',
  'assignment',
  'authentication_occurrence',
  'mutation_evidence',
  'audit_occurrence',
  'outbox_event',
  'evidence_stream',
  'evidence_catalogue',
  'evidence_segment',
  'evidence_segment_payload',
  'evidence_checkpoint',
  'protected_proof_object',
  'protected_proof_payload',
  'protected_proof_checkpoint',
  'retention_hold',
  'evidence_hold_coverage',
  'retention_policy',
  'deletion_job',
  'evidence_deletion_item',
  'evidence_remote_archive_intent',
  'evidence_remote_archive_attempt',
  'evidence_archive_trust',
  'evidence_archive_profile',
  'evidence_archive_receipt',
  'evidence_archive_outbox',
  'evidence_archive_commit_nonce',
  ...fleetScopedTables,
] as const;
// Installed authority bindings stay outside the generic row snapshot: only
// server-computed fingerprints of their material leave PostgreSQL.
const securityTables = [
  ...tables,
  'fleet_fact_admission_key',
  'fact_consumer_profile',
  'fact_consumer_failure_signer',
  'work_item',
] as const;
type CatalogueGrant = {
  grantor: string;
  grantee: string;
  privilege: string;
  grantable: boolean;
};
type CataloguePolicy = {
  name: string;
  roles: string[];
  command: string;
  permissive: boolean;
  using: string | null;
  check: string | null;
};
type CatalogueConstraint = {
  name: string;
  kind: string;
  validated: boolean;
  enforced: boolean;
  definition: string;
  deferrable: boolean;
  deferred: boolean;
  columns: string[] | null;
  referenced_schema: string | null;
  referenced_table: string | null;
  referenced_columns: string[] | null;
  update_action: string;
  delete_action: string;
  match_type: string;
  no_inherit: boolean;
  nulls_not_distinct: boolean | null;
};
type SecurityRow = {
  relname: string;
  relkind: string;
  owner: string;
  relrowsecurity: boolean;
  relforcerowsecurity: boolean;
  grants: CatalogueGrant[];
  column_grants: (CatalogueGrant & { column: string })[];
  constraints: CatalogueConstraint[] | null;
  policies: CataloguePolicy[] | null;
};
async function snapshot(admin: Pool, participantId: string) {
  const result: Record<string, unknown[]> = {};
  for (const table of tables)
    result[table] = (
      await admin.query(
        `select to_jsonb(t) value from control.${table} t where participant_id=$1 order by to_jsonb(t)::text`,
        [participantId],
      )
    ).rows.map((row: { value: unknown }) => row.value);
  // Authenticate restored host commit material without putting a secret into
  // assertion diagnostics. Runtime still admits the original mounted key.
  result.commit_keys = (
    await admin.query(
      `select environment_id,sink_id,encode(sha256(verifier_secret),'hex') digest
    from control.evidence_archive_commit_key where participant_id=$1 order by environment_id,sink_id`,
      [participantId],
    )
  ).rows;
  // Installed signer/profile material is optional. Preserve absence and exact
  // bindings without exposing key bytes or admission references in diffs.
  for (const table of ['fact_consumer_profile', 'fact_consumer_failure_signer']) {
    result[table] = (
      await admin.query(
        `select encode(sha256(convert_to(to_jsonb(s)::text,'UTF8')),'hex') fingerprint
         from control.${table} s where participant_id=$1 order by fingerprint`,
        [participantId],
      )
    ).rows;
  }
  result.migrations = (
    await admin.query(
      'select path,sha256,applied_at::text from openpc_local.migration order by path',
    )
  ).rows;
  return result;
}
async function databaseSecurity(admin: Pool) {
  const database = (
    await admin.query(`select pg_get_userbyid(datdba) owner
      from pg_database where datname=current_database()`)
  ).rows;
  const schemas = (
    await admin.query(`select n.nspname,pg_get_userbyid(n.nspowner) owner,
      has_schema_privilege('openpc_control_owner',n.oid,'USAGE') owner_usage,
      has_schema_privilege('openpc_control_owner',n.oid,'CREATE') owner_create,
      (select jsonb_agg(jsonb_build_object(
        'grantor',pg_get_userbyid(a.grantor),
        'grantee',case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,
        'privilege',a.privilege_type,'grantable',a.is_grantable)
        order by a.grantor,a.grantee,a.privilege_type,a.is_grantable)
        from aclexplode(n.nspacl) a) grants
      from pg_namespace n where n.nspname in ('public','openpc','control') order by n.nspname`)
  ).rows;
  expect(database).toEqual([{ owner: 'openpc_control_owner' }]);
  expect(schemas).toHaveLength(3);
  expect(schemas.find((schema) => schema.nspname === 'public')).toMatchObject({
    owner: 'pg_database_owner',
    owner_usage: true,
  });
  return { database, schemas };
}

// Role membership is a set; dump/restore may reorder role OIDs. PostgreSQL's
// CHECK expressions are reparsed by PostgreSQL against identical temporary
// column types. This models pg_restore normalization (including array casts),
// without deleting predicates or editing any source/restored product relation.
async function security(admin: Pool) {
  const rows = (
    await admin.query<SecurityRow>(
      `select c.relname,c.relkind,pg_get_userbyid(c.relowner) owner,c.relrowsecurity,c.relforcerowsecurity,
    coalesce((select jsonb_agg(jsonb_build_object('grantor',pg_get_userbyid(a.grantor),
      'grantee',case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,
      'privilege',a.privilege_type,'grantable',a.is_grantable)
      order by pg_get_userbyid(a.grantor),case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,a.privilege_type,a.is_grantable)
      from aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a),'[]'::jsonb) grants,
    coalesce((select jsonb_agg(jsonb_build_object('column',v.attname,'grantor',pg_get_userbyid(a.grantor),
      'grantee',case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,
      'privilege',a.privilege_type,'grantable',a.is_grantable)
      order by v.attname,pg_get_userbyid(a.grantor),case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,a.privilege_type,a.is_grantable)
      from pg_attribute v cross join lateral aclexplode(v.attacl) a
      where v.attrelid=c.oid and v.attnum>0 and not v.attisdropped),'[]'::jsonb) column_grants,
    (select jsonb_agg(jsonb_build_object('name',v.conname,'kind',v.contype,'validated',v.convalidated,'enforced',v.conenforced,'definition',pg_get_constraintdef(v.oid,true),
      'deferrable',v.condeferrable,'deferred',v.condeferred,
      'columns',(select jsonb_agg(a.attname order by k.ordinality) from unnest(v.conkey) with ordinality k(attnum,ordinality)
        join pg_attribute a on a.attrelid=v.conrelid and a.attnum=k.attnum),
      'referenced_schema',(select n.nspname from pg_class r join pg_namespace n on n.oid=r.relnamespace where r.oid=v.confrelid),
      'referenced_table',(select r.relname from pg_class r where r.oid=v.confrelid),
      'referenced_columns',(select jsonb_agg(a.attname order by k.ordinality) from unnest(v.confkey) with ordinality k(attnum,ordinality)
        join pg_attribute a on a.attrelid=v.confrelid and a.attnum=k.attnum),
      'update_action',v.confupdtype,'delete_action',v.confdeltype,'match_type',v.confmatchtype,'no_inherit',v.connoinherit,
      'nulls_not_distinct',(select i.indnullsnotdistinct from pg_index i where i.indexrelid=v.conindid))
      order by v.conname) from pg_constraint v where v.conrelid=c.oid) constraints,
    (select jsonb_agg(jsonb_build_object('name',p.polname,'roles',(select jsonb_agg(case when role=0 then 'PUBLIC' else pg_get_userbyid(role) end order by case when role=0 then 'PUBLIC' else pg_get_userbyid(role) end) from unnest(p.polroles) role),'command',p.polcmd,'permissive',p.polpermissive,
      'using',pg_get_expr(p.polqual,p.polrelid),'check',pg_get_expr(p.polwithcheck,p.polrelid)) order by p.polname)
      from pg_policy p where p.polrelid=c.oid) policies
    from pg_class c where c.relnamespace='control'::regnamespace and c.relname=any($1::text[]) order by c.relname`,
      [securityTables],
    )
  ).rows;
  expect(rows.map((row) => row.relname).sort()).toEqual([...securityTables].sort());
  const client = await admin.connect();
  const identifier = (name: string) => '"' + name.replaceAll('"', '""') + '"';
  try {
    await client.query('begin');
    for (const row of rows) {
      expect(securityTables).toContain(row.relname);
      await client.query(
        `create temporary table openpc_restore_security (like control.${identifier(row.relname)}) on commit drop`,
      );
      for (const constraint of row.constraints ?? []) {
        if (constraint.kind !== 'c') continue;
        // Definition comes only from the server catalogue above. Parse the
        // complete original expression; do not normalize it with text erasure.
        await client.query(
          `alter table pg_temp.openpc_restore_security add constraint ${identifier(constraint.name)} ${constraint.definition}`,
        );
      }
      const canonical = await client.query<{ name: string; definition: string }>(
        "select conname name,pg_get_constraintdef(oid,true) definition from pg_constraint where conrelid='pg_temp.openpc_restore_security'::regclass and contype='c'",
      );
      for (const constraint of row.constraints ?? []) {
        if (constraint.kind !== 'c') continue;
        const parsed = canonical.rows.find((entry) => entry.name === constraint.name);
        expect(parsed).toBeDefined();
        constraint.definition = parsed!.definition;
      }
      await client.query('drop table pg_temp.openpc_restore_security');
    }
    return rows;
  } finally {
    await client.query('rollback');
    client.release();
  }
}

type FleetSchemaTable = {
  columns: Record<string, { name: string; notNull: boolean }>;
  compositePrimaryKeys: Record<string, { name: string; columns: string[] }>;
  uniqueConstraints: Record<string, { name: string; columns: string[]; nullsNotDistinct: boolean }>;
  foreignKeys: Record<
    string,
    {
      name: string;
      columnsFrom: string[];
      tableTo: string;
      schemaTo: string;
      columnsTo: string[];
      onUpdate: string;
      onDelete: string;
    }
  >;
  checkConstraints: Record<string, { name: string; value: string }>;
  policies: Record<
    string,
    {
      name: string;
      as: string;
      for: string;
      to: string[];
      using: string;
      withCheck: string;
    }
  >;
  indexes: Record<
    string,
    {
      name: string;
      columns: { expression: string; isExpression: boolean; asc: boolean; nulls: string }[];
      isUnique: boolean;
      method: string;
      where: string;
    }
  >;
};
type FleetSchemaExpectation = {
  constraints: Partial<CatalogueConstraint>[];
  notNull: string[];
  policies: CataloguePolicy[];
};
type FleetIndex = {
  name: string;
  method: string;
  unique: boolean;
  valid: boolean;
  ready: boolean;
  nulls_not_distinct: boolean;
  columns: string[];
  predicate: string;
};
type FleetSchemaExpectations = {
  relations: Record<string, FleetSchemaExpectation>;
  signerIndex: FleetIndex;
  workItemPolicies: CataloguePolicy[];
};

// Independent expectations come from the committed Drizzle snapshot and guard
// producers, not the observed source DB. Parse complete source predicates on
// temporary LIKE tables; never seed delivery, quarantine or work-item effects.
async function fleetSchemaExpectations(admin: Pool): Promise<FleetSchemaExpectations> {
  const source = JSON.parse(
    await readFile(
      new URL('../../../migrations/postgres/control-api/meta/0098_snapshot.json', import.meta.url),
      'utf8',
    ),
  ) as { tables: Record<string, FleetSchemaTable> };
  const relations: FleetSchemaExpectations['relations'] = {};
  let signerIndex: FleetIndex | undefined;
  let workItemPolicies: CataloguePolicy[] = [];
  const identifier = (name: string) => '"' + name.replaceAll('"', '""') + '"';
  const client = await admin.connect();
  try {
    await client.query('begin');
    for (const table of [...fleetDeliveryTables, 'work_item']) {
      const schema = source.tables[`control.${table}`];
      // Work items are Identity-owned; only their added Fleet policy is checked here.
      if (table !== 'work_item') expect(schema).toBeDefined();
      const unqualify = (sql: string) => sql.replaceAll(`"control"."${table}".`, '');
      await client.query(
        `create temporary table openpc_restore_fleet_expected (like control.${identifier(table)}) on commit drop`,
      );
      const constraints: Partial<CatalogueConstraint>[] = [];
      if (table !== 'work_item') {
        for (const constraint of Object.values(schema!.checkConstraints)) {
          await client.query(
            `alter table pg_temp.openpc_restore_fleet_expected add constraint ${identifier(constraint.name)} check (${unqualify(constraint.value)})`,
          );
        }
        const checks = await client.query<{ name: string; definition: string }>(
          "select conname name,pg_get_constraintdef(oid,true) definition from pg_constraint where conrelid='pg_temp.openpc_restore_fleet_expected'::regclass and contype='c'",
        );
        // Apply the same PostgreSQL reparse as security(), including array casts.
        for (const check of checks.rows) {
          await client.query(
            `alter table pg_temp.openpc_restore_fleet_expected drop constraint ${identifier(check.name)}`,
          );
          await client.query(
            `alter table pg_temp.openpc_restore_fleet_expected add constraint ${identifier(check.name)} ${check.definition}`,
          );
        }
        constraints.push(
          ...(
            await client.query<Partial<CatalogueConstraint>>(
              `select conname name,contype kind,convalidated validated,conenforced enforced,condeferrable as "deferrable",condeferred as "deferred",connoinherit no_inherit,pg_get_constraintdef(oid,true) definition from pg_constraint where conrelid='pg_temp.openpc_restore_fleet_expected'::regclass and contype='c'`,
            )
          ).rows,
        );
        for (const [kind, entries] of [
          ['p', Object.values(schema!.compositePrimaryKeys)],
          ['u', Object.values(schema!.uniqueConstraints)],
        ] as const) {
          for (const key of entries)
            constraints.push({
              name: key.name.slice(0, 63),
              kind,
              columns: key.columns,
              validated: true,
              enforced: true,
              deferrable: false,
              deferred: false,
              nulls_not_distinct: schema!.uniqueConstraints[key.name]?.nullsNotDistinct ?? false,
            });
        }
        for (const fk of Object.values(schema!.foreignKeys)) {
          // These scoped references deliberately restrict deletion; do not
          // silently map an unknown migration action to the expected default.
          expect(fk.onUpdate).toBe('no action');
          expect(fk.onDelete).toBe('restrict');
          constraints.push({
            name: fk.name.slice(0, 63),
            kind: 'f',
            columns: fk.columnsFrom,
            referenced_schema: fk.schemaTo,
            referenced_table: fk.tableTo,
            referenced_columns: fk.columnsTo,
            update_action: 'a',
            delete_action: 'r',
            match_type: 's',
            validated: true,
            enforced: true,
            deferrable: false,
            deferred: false,
          });
        }
        if (table === 'fleet_fact_quarantine')
          constraints.push({
            name: 'fleet_quarantine_atomic',
            kind: 't',
            validated: true,
            enforced: true,
            deferrable: true,
            deferred: true,
          });
        for (const policy of Object.values(schema!.policies)) {
          expect(['PERMISSIVE', 'RESTRICTIVE']).toContain(policy.as);
          expect(policy.for).toBe('ALL');
          await client.query(`create policy ${identifier(policy.name)} on pg_temp.openpc_restore_fleet_expected as ${policy.as} for all to ${policy.to.map(identifier).join(',')}
            using (${unqualify(policy.using)}) with check (${unqualify(policy.withCheck)})`);
        }
      }
      // These are the complete CREATE POLICY statements from the two owners;
      // only the target relation is redirected to the disposable parser table.
      const policyTarget = new RegExp(` ON control\\.${table}(?=\\s)`, 'u');
      const policies = [
        ...`${fleetDeliveryGuardsSql}\n${factConsumerFailureGuardsSql}`.matchAll(
          /CREATE POLICY [^;]+;/gu,
        ),
      ]
        .map(([sql]) => sql)
        .filter((sql) => policyTarget.test(sql));
      expect(policies).toHaveLength(1);
      for (const policy of policies)
        await client.query(
          policy.replace(policyTarget, ' ON pg_temp.openpc_restore_fleet_expected'),
        );
      const parsedPolicies = (
        await client.query<CataloguePolicy>(
          `select p.polname name,(select jsonb_agg(case when role=0 then 'PUBLIC' else pg_get_userbyid(role) end order by case when role=0 then 'PUBLIC' else pg_get_userbyid(role) end) from unnest(p.polroles) role) roles,
          p.polcmd command,p.polpermissive permissive,pg_get_expr(p.polqual,p.polrelid) as "using",pg_get_expr(p.polwithcheck,p.polrelid) as "check"
         from pg_policy p where p.polrelid='pg_temp.openpc_restore_fleet_expected'::regclass order by p.polname`,
        )
      ).rows;
      if (table === 'work_item') workItemPolicies = parsedPolicies;
      else
        relations[table] = {
          constraints,
          policies: parsedPolicies,
          notNull: Object.values(schema!.columns)
            .filter((column) => column.notNull)
            .map((column) => column.name)
            .sort(),
        };
      if (table === 'fact_consumer_failure_signer') {
        const index = schema!.indexes.fact_failure_active_signer_uq;
        expect(index).toMatchObject({ isUnique: true, method: 'btree' });
        for (const column of index!.columns)
          expect(column).toMatchObject({ isExpression: false, asc: true, nulls: 'last' });
        await client.query(
          `create unique index openpc_restore_fleet_expected_idx on pg_temp.openpc_restore_fleet_expected using btree (${index!.columns.map((column) => identifier(column.expression)).join(',')}) where ${unqualify(index!.where)}`,
        );
        const predicate = (
          await client.query<{ predicate: string }>(
            "select pg_get_expr(indpred,indrelid) predicate from pg_index where indexrelid='pg_temp.openpc_restore_fleet_expected_idx'::regclass",
          )
        ).rows[0]!.predicate;
        signerIndex = {
          name: index!.name,
          method: index!.method,
          unique: index!.isUnique,
          valid: true,
          ready: true,
          nulls_not_distinct: false,
          columns: index!.columns.map((column) => column.expression),
          predicate,
        };
      }
      await client.query('drop table pg_temp.openpc_restore_fleet_expected');
    }
    expect(signerIndex).toBeDefined();
    return { relations, signerIndex: signerIndex!, workItemPolicies };
  } finally {
    await client.query('rollback');
    client.release();
  }
}

type FleetAuthority = {
  relations: SecurityRow[];
  workItem: SecurityRow;
  signerIndexes: FleetIndex[];
  triggers: {
    table: string;
    name: string;
    routine_schema: string;
    routine: string;
    routine_arguments: string;
    enabled: string;
    type: number;
    arguments: number;
    argument_bytes: string;
    columns: string;
    condition: string | null;
    deferrable: boolean;
    deferred: boolean;
    constraint: string | null;
  }[];
  keys: {
    database_role: string;
    fingerprint: string;
    key_bytes: number;
    login: boolean | null;
    superuser: boolean | null;
    bypass_rls: boolean | null;
    create_role: boolean | null;
    worker_member: boolean | null;
    key_readable: boolean | null;
    commit_allowed: boolean | null;
  }[];
  routines: {
    name: string;
    arguments: string;
    result: string;
    owner: string;
    language: string;
    definer: boolean;
    volatility: string;
    configuration: string[];
    grants: CatalogueGrant[];
    body: string;
    definition: string;
  }[];
};

const fleetRoutines = [
  [
    'commit_fleet_fact_admission',
    'bytea, bytea, bytea',
    'material bytea,nonce bytea,mac bytea',
    'boolean',
    fleetFactGuardsSql,
    'worker',
  ],
  [
    'commit_fleet_fact_admission_v2',
    'bytea, bytea, bytea, text',
    'material bytea,nonce bytea,mac bytea,wanted_profile text',
    'boolean',
    fleetFactGuardsSql,
    'worker',
  ],
  [
    'require_fact_consumer_profile',
    'text',
    'wanted_consumer text',
    'control.fact_consumer_profile',
    factConsumerProfileGuardsSql,
    'worker',
  ],
  [
    'verify_fleet_delivery_capability',
    'bytea, bytea, bytea, text, text',
    'material bytea,nonce bytea,mac bytea,profile_digest text,purpose text',
    'jsonb',
    fleetDeliveryGuardsSql,
    'private',
  ],
  [
    'fleet_delivery_retry_delay',
    'integer, integer, integer',
    'failures integer,initial_ms integer,maximum_ms integer',
    'bigint',
    fleetDeliveryGuardsSql,
    'immutable',
  ],
  [
    'close_fleet_delivery_lease',
    'uuid, uuid, text, text',
    'wanted_event uuid,wanted_lease uuid,result text,problem text',
    'text',
    fleetDeliveryGuardsSql,
    'private',
  ],
  [
    'begin_fleet_fact_delivery',
    'bytea, bytea, bytea, text',
    'material bytea,nonce bytea,mac bytea,wanted_profile text',
    'jsonb',
    fleetDeliveryGuardsSql,
    'worker',
  ],
  [
    'fail_fleet_fact_delivery',
    'bytea, bytea, bytea, text',
    'material bytea,nonce bytea,mac bytea,wanted_profile text',
    'text',
    fleetDeliveryGuardsSql,
    'worker',
  ],
  ['guard_fleet_delivery_history', '', '', 'trigger', fleetDeliveryGuardsSql, 'trigger'],
  ['guard_fact_failure_signer', '', '', 'trigger', factConsumerFailureGuardsSql, 'trigger'],
  [
    'require_fact_failure_signer',
    'control.fact_consumer_profile, text',
    'p control.fact_consumer_profile,wanted_signer text',
    'control.fact_consumer_failure_signer',
    factConsumerFailureGuardsSql,
    'private',
  ],
  [
    'prepare_fleet_fact_quarantine',
    'bytea, bytea, bytea, text',
    'material bytea,nonce bytea,mac bytea,wanted_profile text',
    'jsonb',
    factConsumerFailureGuardsSql,
    'worker',
  ],
  [
    'commit_fleet_fact_quarantine',
    'bytea, bytea, bytea, text',
    'material bytea,nonce bytea,mac bytea,wanted_profile text',
    'uuid',
    factConsumerFailureGuardsSql,
    'worker',
  ],
  ['guard_fleet_quarantine_history', '', '', 'trigger', factConsumerFailureGuardsSql, 'trigger'],
  ['assert_fleet_quarantine_atomic', '', '', 'trigger', factConsumerFailureGuardsSql, 'private'],
] as const;
const fleetTriggers = [
  ['fleet_fact_delivery', 'fleet_delivery_history', 'guard_fleet_delivery_history', 27],
  ['fleet_fact_delivery_attempt', 'fleet_delivery_history', 'guard_fleet_delivery_history', 27],
  [
    'fact_consumer_failure_signer',
    'fact_failure_signer_installation',
    'guard_fact_failure_signer',
    31,
  ],
  ['fleet_fact_quarantine', 'fleet_failure_history', 'guard_fleet_quarantine_history', 27],
  ['fleet_fact_failure_outbox', 'fleet_failure_history', 'guard_fleet_quarantine_history', 27],
  ['fleet_fact_quarantine', 'fleet_quarantine_atomic', 'assert_fleet_quarantine_atomic', 21],
] as const;

function assertFleetAuthority(value: FleetAuthority, expected: FleetSchemaExpectations) {
  expect(value.relations.map((row) => row.relname).sort()).toEqual([...fleetTables].sort());
  for (const relation of value.relations) {
    const key = relation.relname === 'fleet_fact_admission_key';
    const profile = relation.relname === 'fact_consumer_profile';
    const signer = relation.relname === 'fact_consumer_failure_signer';
    expect(relation).toMatchObject({
      relkind: 'r',
      owner: 'openpc_control_owner',
      relrowsecurity: !key,
      relforcerowsecurity: !key,
      column_grants: [],
    });
    if (key) expect(relation.policies).toBeNull();
    else if (expected.relations[relation.relname]) {
      const schema = expected.relations[relation.relname]!;
      expect(relation.policies).toEqual(schema.policies);
      const constraints = relation.constraints ?? [];
      expect(
        constraints
          .filter((constraint) => constraint.kind !== 'n')
          .map((constraint) => constraint.name)
          .sort(),
      ).toEqual(schema.constraints.map((constraint) => constraint.name).sort());
      for (const constraint of schema.constraints)
        expect(constraints.find((entry) => entry.name === constraint.name)).toMatchObject(
          constraint,
        );
      const notNull = constraints.filter((constraint) => constraint.kind === 'n');
      expect(notNull.map((constraint) => constraint.columns).sort()).toEqual(
        schema.notNull.map((column) => [column]).sort(),
      );
      for (const constraint of notNull)
        expect(constraint).toMatchObject({
          validated: true,
          enforced: true,
          deferrable: false,
          deferred: false,
        });
    } else expect(relation.policies).toHaveLength(3);
    expect(relation.grants.filter((grant) => grant.grantee !== relation.owner)).toEqual(
      key
        ? []
        : signer
          ? [
              ['openpc_control_key_governor', 'INSERT'],
              ['openpc_control_key_governor', 'SELECT'],
              ['openpc_control_key_governor', 'UPDATE'],
              ['openpc_control_worker', 'SELECT'],
            ].map(([grantee, privilege]) => ({
              grantor: 'openpc_control_owner',
              grantee,
              privilege,
              grantable: false,
            }))
          : profile
            ? [
                ['openpc_control_key_governor', 'INSERT'],
                ['openpc_control_key_governor', 'SELECT'],
                ['openpc_control_worker', 'SELECT'],
              ].map(([grantee, privilege]) => ({
                grantor: 'openpc_control_owner',
                grantee,
                privilege,
                grantable: false,
              }))
            : ['openpc_control_reader', 'openpc_control_worker'].map((grantee) => ({
                grantor: 'openpc_control_owner',
                grantee,
                privilege: 'SELECT',
                grantable: false,
              })),
    );
  }
  // The ordinary Control-only runner does not provision the optional Fleet key.
  // Preserve every installed binding if present; empty metadata is not evidence
  // of a populated Fleet admission or cross-store acknowledgement restoration.
  for (const key of value.keys) {
    expect(key).toMatchObject({
      database_role: 'openpc_local_control_worker',
      key_bytes: 32,
      login: true,
      superuser: false,
      bypass_rls: false,
      create_role: false,
      worker_member: true,
      key_readable: false,
      commit_allowed: true,
    });
    expect(key.fingerprint).toMatch(/^[0-9a-f]{64}$/u);
  }
  expect(value.signerIndexes).toEqual([expected.signerIndex]);
  expect(value.workItem).toMatchObject({
    owner: 'openpc_control_owner',
    relkind: 'r',
    relrowsecurity: true,
    relforcerowsecurity: true,
  });
  expect(
    value.workItem.policies?.filter((policy) => policy.name === 'fleet_failure_work_item'),
  ).toEqual(expected.workItemPolicies);
  for (const privilege of ['SELECT', 'INSERT'])
    expect(value.workItem.grants).toContainEqual({
      grantor: 'openpc_control_owner',
      grantee: 'openpc_control_owner',
      privilege,
      grantable: false,
    });
  expect(value.triggers).toHaveLength(fleetTriggers.length);
  // PostgreSQL trigger bits: ROW=1, BEFORE=2, INSERT=4, DELETE=8, UPDATE=16.
  for (const [table, name, routine, type] of fleetTriggers) {
    const atomic = name === 'fleet_quarantine_atomic';
    expect(
      value.triggers.find((trigger) => trigger.table === table && trigger.name === name),
    ).toEqual({
      table,
      name,
      routine_schema: 'openpc',
      routine,
      routine_arguments: '',
      enabled: 'O',
      type,
      arguments: 0,
      argument_bytes: '',
      columns: '',
      condition: null,
      deferrable: atomic,
      deferred: atomic,
      constraint: atomic ? name : null,
    });
  }
  expect(value.routines).toHaveLength(fleetRoutines.length);
  for (const [name, argumentsText, parameters, result, sql, mode] of fleetRoutines) {
    const prefix = `CREATE OR REPLACE FUNCTION openpc.${name}(${parameters})`;
    expect(sql!.indexOf(prefix)).toBeGreaterThanOrEqual(0);
    const source = sql!.slice(sql!.indexOf(prefix));
    const body = source.match(/ AS \$\$([\s\S]*?)\$\$;/u)?.[1];
    expect(body).toBeDefined();
    const routine = value.routines.find((entry) => entry.name === name);
    expect(routine).toMatchObject({
      name,
      arguments: argumentsText,
      result,
      owner: 'openpc_control_owner',
      language: mode === 'immutable' ? 'sql' : 'plpgsql',
      definer: mode === 'worker' || mode === 'private',
      volatility: mode === 'immutable' ? 'i' : 'v',
      configuration:
        name === 'require_fact_consumer_profile'
          ? ['search_path=pg_catalog', 'row_security=on']
          : ['search_path=pg_catalog'],
      body,
    });
    // Trigger functions and the pure retry calculator retain PostgreSQL's
    // PUBLIC default; all callable admission/private definers explicitly revoke it.
    expect(
      routine!.grants.filter((grant) => grant.grantee !== 'openpc_control_owner'),
      name,
    ).toEqual(
      mode === 'worker'
        ? [
            {
              grantor: 'openpc_control_owner',
              grantee: 'openpc_control_worker',
              privilege: 'EXECUTE',
              grantable: false,
            },
          ]
        : mode === 'trigger' || mode === 'immutable'
          ? [
              {
                grantor: 'openpc_control_owner',
                grantee: 'PUBLIC',
                privilege: 'EXECUTE',
                grantable: false,
              },
            ]
          : [],
    );
  }
}

async function fleetAuthority(
  admin: Pool,
  rows: SecurityRow[],
  expected: FleetSchemaExpectations,
): Promise<FleetAuthority> {
  const workItem = rows.find((row) => row.relname === 'work_item');
  expect(workItem).toBeDefined();
  const value: FleetAuthority = {
    relations: rows.filter((row) => fleetTables.some((name) => name === row.relname)),
    workItem: workItem!,
    signerIndexes: (
      await admin.query<FleetIndex>(
        `select c.relname name,m.amname method,i.indisunique as "unique",i.indisvalid valid,i.indisready ready,
        i.indnullsnotdistinct nulls_not_distinct,
        (select jsonb_agg(pg_get_indexdef(i.indexrelid,n,true) order by n) from generate_series(1,i.indnatts) n) columns,
        pg_get_expr(i.indpred,i.indrelid) predicate
       from pg_index i join pg_class c on c.oid=i.indexrelid join pg_am m on m.oid=c.relam
       where i.indrelid='control.fact_consumer_failure_signer'::regclass and c.relname='fact_failure_active_signer_uq'`,
      )
    ).rows,
    triggers: (
      await admin.query<FleetAuthority['triggers'][number]>(
        `select c.relname as "table",t.tgname name,n.nspname routine_schema,p.proname routine,
        oidvectortypes(p.proargtypes) routine_arguments,t.tgenabled enabled,t.tgtype type,t.tgnargs arguments,
        encode(t.tgargs,'hex') argument_bytes,t.tgattr::text columns,pg_get_expr(t.tgqual,t.tgrelid) condition,
        t.tgdeferrable as "deferrable",t.tginitdeferred as "deferred",v.conname as "constraint"
       from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_proc p on p.oid=t.tgfoid
        join pg_namespace n on n.oid=p.pronamespace left join pg_constraint v on v.oid=t.tgconstraint
       where c.relnamespace='control'::regnamespace and c.relname=any($1::text[]) and not t.tgisinternal
       order by c.relname,t.tgname`,
        [fleetDeliveryTables],
      )
    ).rows,
    keys: (
      await admin.query<FleetAuthority['keys'][number]>(`select k.database_role,
        encode(sha256(k.verifier_secret),'hex') fingerprint,octet_length(k.verifier_secret) key_bytes,
        r.rolcanlogin login,r.rolsuper superuser,r.rolbypassrls bypass_rls,r.rolcreaterole create_role,
        pg_has_role(r.oid,'openpc_control_worker','USAGE') worker_member,
        has_table_privilege(r.oid,'control.fleet_fact_admission_key','SELECT') key_readable,
        has_function_privilege(r.oid,'openpc.commit_fleet_fact_admission(bytea,bytea,bytea)','EXECUTE') commit_allowed
        from control.fleet_fact_admission_key k left join pg_roles r on r.rolname=k.database_role
        order by k.database_role`)
    ).rows,
    routines: (
      await admin.query<FleetAuthority['routines'][number]>(
        `select p.proname name,
        oidvectortypes(p.proargtypes) arguments,pg_get_function_result(p.oid) result,
        pg_get_userbyid(p.proowner) owner,l.lanname language,p.prosecdef definer,
        p.provolatile volatility,p.proconfig configuration,p.prosrc body,pg_get_functiondef(p.oid) definition,
        (select jsonb_agg(jsonb_build_object('grantor',pg_get_userbyid(a.grantor),
          'grantee',case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,
          'privilege',a.privilege_type,'grantable',a.is_grantable)
          order by pg_get_userbyid(a.grantor),case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,a.privilege_type,a.is_grantable)
          from aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a) grants
        from pg_proc p join pg_language l on l.oid=p.prolang
        where p.oid in (select to_regprocedure(signature) from unnest($1::text[]) signature) order by p.proname`,
        [fleetRoutines.map(([name, argumentsText]) => `openpc.${name}(${argumentsText})`)],
      )
    ).rows,
  };
  assertFleetAuthority(value, expected);
  return value;
}

/** Reopen only real readback owners against the recovered DB, retaining the
 * original Identity signing/trust files and original sessions. No fixture
 * bootstrap, login, new approval or business replay runs after restoration. */
async function restoredReadback(
  databaseUrl: string,
  directory: string,
  scope: Scope,
  makerId: string,
  checkerId: string,
) {
  const database = new URL(databaseUrl);
  const file = (name: string) => join(directory, name);
  const config = await readLocalIdentityRuntimeConfig({
    OPENPC_LOCAL_RUNTIME: '1',
    IDENTITY_DATABASE_HOST: database.hostname,
    IDENTITY_DATABASE_PORT: database.port,
    IDENTITY_DATABASE_NAME: database.pathname.slice(1),
    IDENTITY_DATABASE_USER: decodeURIComponent(database.username),
    IDENTITY_DATABASE_PASSWORD_FILE: file('database'),
    IDENTITY_INTERNAL_TOKEN_FILE: file('internal'),
    IDENTITY_RUNTIME_SIGNING_PRIVATE_KEY_FILE: file('private.der'),
    IDENTITY_RUNTIME_SIGNING_PUBLIC_KEY_FILE: file('public.der'),
    IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES: file('public.der'),
    IDENTITY_LOCAL_OPERATOR_CREDENTIAL_FILE: file('internal'),
    IDENTITY_LOCAL_VIEWER_CREDENTIAL_FILE: file('internal'),
    IDENTITY_LOCAL_OPERATOR_PRINCIPAL_ID: makerId,
    IDENTITY_LOCAL_VIEWER_PRINCIPAL_ID: checkerId,
    IDENTITY_LOCAL_PARTICIPANT_ID: scope.participantId,
    IDENTITY_LOCAL_PRIVACY_DOMAIN_ID: scope.privacyDomainId,
    IDENTITY_OIDC_ISSUER: 'http://127.0.0.1:1',
    IDENTITY_OIDC_CLIENT_ID: 'isolated-readback',
    IDENTITY_OIDC_REDIRECT_URI: 'http://127.0.0.1:1/callback',
    IDENTITY_MTLS_CA_FILE: file('tls.crt'),
    IDENTITY_WORKLOAD_ISSUER_URL: 'http://127.0.0.1:1',
    IDENTITY_WORKLOAD_ISSUER_TOKEN_FILE: file('internal'),
    IDENTITY_MTLS_SERVER_CERT_FILE: file('tls.crt'),
    IDENTITY_MTLS_SERVER_KEY_FILE: file('tls.key'),
    IDENTITY_MTLS_LISTEN: '127.0.0.1:1',
    IDENTITY_LISTEN: '127.0.0.1:1',
  });
  const identity = await buildLocalIdentityRuntime(config);
  const pool = new Pool({ connectionString: databaseUrl, max: 1 });
  const app = Fastify({ logger: { level: 'warn' } });
  try {
    const identityUrl = await identity.app.listen({ host: '127.0.0.1', port: 0 });
    registerConfigurationRoutes(app, {
      pool,
      authorizer: createLocalConfigurationAuthorizer(
        identityUrl,
        (await readFile(file('internal'), 'utf8')).trim(),
        scope.privacyDomainId,
      ),
      identityRuntimeVerifier: createLocalIdentityRuntimeVerifier([
        await readFile(file('public.der')),
      ]),
    });
    const url = await app.listen({ host: '127.0.0.1', port: 0 });
    return {
      async read(
        path: string,
        token: string,
        context: Pick<Scope, 'participantId' | 'privacyDomainId'> = scope,
      ) {
        const response = await fetch(`${url}/api/v1/${path}`, {
          headers: {
            'Cookie': `__Host-openpc_session=${token}`,
            'OpenPC-Participant-ID': `urn:openpc:participant:${context.participantId}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${context.privacyDomainId}`,
            'OpenPC-API-Version': '1',
            'X-Request-ID': id(),
            'X-Correlation-ID': id(),
          },
          signal: AbortSignal.timeout(10000),
        });
        return {
          status: response.status,
          body: await response.json(),
          cache: response.headers.get('cache-control'),
        };
      },
      async close() {
        await app.close();
        await identity.app.close();
        await Promise.all([pool.end(), identity.pool.end()]);
      },
    };
  } catch (error) {
    await app.close();
    await identity.app.close();
    await Promise.all([pool.end(), identity.pool.end()]);
    throw error;
  }
}

async function isolated(
  worker: Pool,
  context: Pick<Scope, 'participantId' | 'privacyDomainId'>,
  owner: string,
) {
  const client = await worker.connect();
  try {
    await client.query('begin');
    await client.query('set local row_security=on');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true),openpc.assert_request_context(true)",
      [context.participantId, context.privacyDomainId, id()],
    );
    return (
      await client.query(
        `select
      (select count(*)::int from control.protected_proof_object where participant_id=$1) proofs,
      (select count(*)::int from control.protected_proof_payload where participant_id=$1) payloads,
      (select count(*)::int from control.evidence_remote_archive_intent where participant_id=$1) intents,
      (select count(*)::int from control.evidence_archive_receipt where participant_id=$1) receipts,
      (select count(*)::int from control.evidence_archive_outbox where participant_id=$1) events`,
        [owner],
      )
    ).rows[0];
  } finally {
    await client.query('rollback');
    client.release();
  }
}

type InstalledFleetTrust = {
  installed: InstalledFactConsumerProfile;
  payload: Buffer;
  cose: Buffer;
  profileFingerprint: string;
  signerId: string;
  signerState: 'ACTIVE' | 'REVOKED';
  signerFingerprint: string;
};

// Initial local trust only. The explicit workload comes from the existing
// scoped archive fixture, not the Compose bootstrap's fixed credential ID.
// This is database installation/readback coverage, not mTLS or Fleet effects.
async function installFleetRestoreTrust(
  admin: Pool,
  secretRoot: string,
  scope: Pick<Scope, 'participantId' | 'privacyDomainId'>,
  workloadCredentialId: string,
  revoked: boolean,
): Promise<InstalledFleetTrust> {
  await mkdir(secretRoot, { mode: 0o700 });
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const keyBytes = Buffer.from(key.privateKey.export({ format: 'jwk' }).d!, 'base64url');
  try {
    await writeFile(
      join(secretRoot, 'fleet_fact_failure_signing_key.txt'),
      keyBytes.toString('hex'),
      {
        mode: 0o600,
        flag: 'wx',
      },
    );
  } finally {
    keyBytes.fill(0);
  }
  const client = await admin.connect();
  try {
    await client.query('begin');
    const credential = await client.query<{ epoch: string }>(
      `select credential_epoch::text epoch from control.credential
       where participant_id=$1 and credential_id=$2 and state='ACTIVE'`,
      [scope.participantId, workloadCredentialId],
    );
    expect(credential.rowCount).toBe(1);
    const digest = await installInitialFleetConsumerProfile(
      client,
      scope.participantId,
      scope.privacyDomainId,
      workloadCredentialId,
    );
    const profile = await client.query<{
      payload: Buffer;
      cose: Buffer;
      issuer_spki: Buffer;
      fingerprint: string;
    }>(
      `select payload,cose,issuer_spki,
        encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex') fingerprint
       from control.fact_consumer_profile p where participant_id=$1 and privacy_domain_id=$2
         and consumer_id='LS-FLEET-CONTROL'`,
      [scope.participantId, scope.privacyDomainId],
    );
    expect(profile.rowCount).toBe(1);
    const original = profile.rows[0]!;
    const installed: InstalledFactConsumerProfile = {
      ...scope,
      environmentId: 'openpc-local-runtime',
      profileId: 'fleet-fact-admission',
      revision: '1',
      consumerId: 'LS-FLEET-CONTROL',
      subscriptionId: 'SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1',
      workloadCredentialId,
      workloadCredentialEpoch: credential.rows[0]!.epoch,
      databaseRole: 'openpc_local_control_worker',
      issuerSpkiDer: original.issuer_spki,
      signedProfileDigest: digest,
    };
    const signerId = await installInitialFleetFailureSigner(
      client,
      secretRoot,
      scope.participantId,
      scope.privacyDomainId,
    );
    const signerFingerprint = async () => {
      const result = await client.query<{ fingerprint: string }>(
        `select encode(sha256(convert_to(to_jsonb(s)::text,'UTF8')),'hex') fingerprint
         from control.fact_consumer_failure_signer s where participant_id=$1 and privacy_domain_id=$2
           and consumer_id='LS-FLEET-CONTROL' and signer_key_id=$3`,
        [scope.participantId, scope.privacyDomainId, signerId],
      );
      expect(result.rowCount).toBe(1);
      return result.rows[0]!.fingerprint;
    };
    const initialSignerFingerprint = await signerFingerprint();
    expect(
      await installInitialFleetConsumerProfile(
        client,
        scope.participantId,
        scope.privacyDomainId,
        workloadCredentialId,
      ),
    ).toBe(digest);
    expect(
      await installInitialFleetFailureSigner(
        client,
        secretRoot,
        scope.participantId,
        scope.privacyDomainId,
      ),
    ).toBe(signerId);
    expect(await signerFingerprint()).toBe(initialSignerFingerprint);
    const retained = await client.query<{ unchanged: boolean }>(
      `select payload=$3 and cose=$4 and issuer_spki=$5 and profile_digest=$6
        and encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex')=$7 unchanged
       from control.fact_consumer_profile p where participant_id=$1 and privacy_domain_id=$2
         and consumer_id='LS-FLEET-CONTROL'`,
      [
        scope.participantId,
        scope.privacyDomainId,
        original.payload,
        original.cose,
        installed.issuerSpkiDer,
        digest,
        original.fingerprint,
      ],
    );
    expect(retained.rows).toEqual([{ unchanged: true }]);
    if (revoked) {
      const changed = await client.query(
        `update control.fact_consumer_failure_signer set state='REVOKED'
         where participant_id=$1 and privacy_domain_id=$2 and signer_key_id=$3 and state='ACTIVE'`,
        [scope.participantId, scope.privacyDomainId, signerId],
      );
      expect(changed.rowCount).toBe(1);
      const revokedFingerprint = await signerFingerprint();
      // The initial installer must refuse retained revoked trust, not renew it.
      await expect(
        installInitialFleetFailureSigner(
          client,
          secretRoot,
          scope.participantId,
          scope.privacyDomainId,
        ),
      ).rejects.toMatchObject({ code: 'ERR_ASSERTION' });
      expect(await signerFingerprint()).toBe(revokedFingerprint);
    }
    const trust: InstalledFleetTrust = {
      installed,
      payload: original.payload,
      cose: original.cose,
      profileFingerprint: original.fingerprint,
      signerId,
      signerState: revoked ? 'REVOKED' : 'ACTIVE',
      signerFingerprint: await signerFingerprint(),
    };
    await client.query('commit');
    return trust;
  } catch (error) {
    await client.query('rollback');
    throw error;
  } finally {
    client.release();
  }
}

async function withFleetRestoreContext<T>(
  pool: Pool,
  scope: Pick<Scope, 'participantId' | 'privacyDomainId'>,
  read: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('set local row_security=on');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-OPERATIONS_READ_OPERATION-V1',true),openpc.assert_request_context(true)",
      [scope.participantId, scope.privacyDomainId, id()],
    );
    return await read(client);
  } finally {
    await client.query('rollback');
    client.release();
  }
}

async function assertFleetRestoreBindings(client: Pool | PoolClient, trust: InstalledFleetTrust) {
  const { installed } = trust;
  const result = await client.query<{
    original_payload: boolean;
    original_cose: boolean;
    original_issuer: boolean;
    profile_digest: string;
    profile_fingerprint: string;
    signer_id: string;
    signer_state: string;
    signer_fingerprint: string;
  }>(
    `select p.payload=$3 original_payload,p.cose=$4 original_cose,p.issuer_spki=$5 original_issuer,
      p.profile_digest,encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex') profile_fingerprint,
      s.signer_key_id signer_id,s.state signer_state,
      encode(sha256(convert_to(to_jsonb(s)::text,'UTF8')),'hex') signer_fingerprint
     from control.fact_consumer_profile p join control.fact_consumer_failure_signer s
       using(participant_id,privacy_domain_id,consumer_id)
     where p.participant_id=$1 and p.privacy_domain_id=$2 and p.consumer_id='LS-FLEET-CONTROL'`,
    [
      installed.participantId,
      installed.privacyDomainId,
      trust.payload,
      trust.cose,
      installed.issuerSpkiDer,
    ],
  );
  expect(result.rows).toEqual([
    {
      original_payload: true,
      original_cose: true,
      original_issuer: true,
      profile_digest: installed.signedProfileDigest,
      profile_fingerprint: trust.profileFingerprint,
      signer_id: trust.signerId,
      signer_state: trust.signerState,
      signer_fingerprint: trust.signerFingerprint,
    },
  ]);
}

async function assertNoFleetRestoreEffects(admin: Pool, participantId: string) {
  for (const table of fleetScopedTables) {
    const result = await admin.query<{ count: number }>(
      `select count(*)::int count from control.${table} where participant_id=$1`,
      [participantId],
    );
    expect(result.rows, `Trust installation must not create ${table}`).toEqual([{ count: 0 }]);
  }
  expect(
    (
      await admin.query(
        "select count(*)::int count from control.work_item where participant_id=$1 and kind='FLEET_FAILURE'",
        [participantId],
      )
    ).rows,
  ).toEqual([{ count: 0 }]);
}

async function assertFleetRestoreAuthority(
  admin: Pool,
  worker: Pool,
  deniedDatabaseUrl: string,
  trusts: readonly InstalledFleetTrust[],
  foreignScope: Pick<Scope, 'participantId' | 'privacyDomainId'>,
) {
  const denied = new Pool({ connectionString: deniedDatabaseUrl, max: 1 });
  try {
    for (const trust of trusts) {
      const { installed } = trust;
      await assertFleetRestoreBindings(admin, trust);
      // The failure signer can be revoked while its profile remains current.
      // Its effect admission needs genuine exhausted delivery and is untested here.
      await withFleetRestoreContext(worker, installed, async (client) => {
        const profile = await requireFactConsumerProfile(client, installed);
        expect(profile).toMatchObject({
          participantId: installed.participantId,
          privacyDomainId: installed.privacyDomainId,
          workloadCredentialId: installed.workloadCredentialId,
          workloadCredentialEpoch: installed.workloadCredentialEpoch,
          revision: installed.revision,
          databaseRole: installed.databaseRole,
        });
        await assertFleetRestoreBindings(client, trust);
      });
      const otherScope = trusts.find((other) => other !== trust)!.installed;
      for (const scope of [foreignScope, otherScope]) {
        const hidden = await withFleetRestoreContext(worker, scope, (client) =>
          client.query(
            `select
            (select count(*)::int from control.fact_consumer_profile where participant_id=$1 and privacy_domain_id=$2) profiles,
            (select count(*)::int from control.fact_consumer_failure_signer where participant_id=$1 and privacy_domain_id=$2) signers`,
            [installed.participantId, installed.privacyDomainId],
          ),
        );
        expect(hidden.rows).toEqual([{ profiles: 0, signers: 0 }]);
      }
      await expect(
        withFleetRestoreContext(worker, foreignScope, (client) =>
          requireFactConsumerProfile(client, installed),
        ),
      ).rejects.toMatchObject({ code: 'P0002' });
      await expect(
        withFleetRestoreContext(worker, otherScope, (client) =>
          requireFactConsumerProfile(client, installed),
        ),
      ).rejects.toThrow('Installed Fact consumer profile rejected');
      await expect(
        withFleetRestoreContext(denied, installed, (client) =>
          requireFactConsumerProfile(client, installed),
        ),
      ).rejects.toMatchObject({ code: '42501' });
      const changedIssuer = Buffer.from(installed.issuerSpkiDer);
      changedIssuer[changedIssuer.length - 1] = changedIssuer[changedIssuer.length - 1]! ^ 1;
      for (const changed of [
        { ...installed, signedProfileDigest: `sha256:${'00'.repeat(32)}` },
        { ...installed, issuerSpkiDer: changedIssuer },
        {
          ...installed,
          workloadCredentialEpoch: (BigInt(installed.workloadCredentialEpoch) + 1n).toString(),
        },
      ]) {
        await expect(
          withFleetRestoreContext(worker, installed, (client) =>
            requireFactConsumerProfile(client, changed),
          ),
        ).rejects.toThrow('Installed Fact consumer profile rejected');
      }
      for (const table of ['fact_consumer_profile', 'fact_consumer_failure_signer']) {
        // Exercise the real worker ACL with a statement that cannot insert even
        // if the grant regresses. An unexpected success still fails the test.
        await expect(
          withFleetRestoreContext(worker, installed, (client) =>
            client.query(`insert into control.${table} select * from control.${table} where false`),
          ),
        ).rejects.toMatchObject({ code: '42501' });
      }
      await expect(
        withFleetRestoreContext(worker, installed, (client) =>
          client.query(
            `update control.fact_consumer_failure_signer set state='REVOKED'
         where participant_id=$1 and privacy_domain_id=$2 and signer_key_id=$3`,
            [installed.participantId, installed.privacyDomainId, trust.signerId],
          ),
        ),
      ).rejects.toMatchObject({ code: '42501' });
      await assertFleetRestoreBindings(admin, trust);
    }
    await assertNoFleetRestoreEffects(admin, trusts[0]!.installed.participantId);
  } finally {
    await denied.end();
  }
}

// SEM-052–061, 138/139 / DATA MIGRATION_RETENTION_RECOVERY: actual current-schema
// logical backup/restore of real governed custody. External S3 is the sole mock.
// This does not qualify WORM, remote destruction, key lifecycle or older remote
// migrations. Existing runner registration/ordinary CI belongs to the integrator.
integration(
  'restores signed remote custody, pending attempts and retired local copies without replaying effects',
  async () => {
    let admin: Pool | undefined = new Pool({ connectionString: adminUrl, max: 2 });
    let worker: Pool | undefined = new Pool({ connectionString: workerUrl, max: 1 });
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'remote-restore-'));
    const scope: Scope = {
      participantId: id(),
      privacyDomainId: id(),
      streamId: 'restore-authentication',
    };
    const participantId = `urn:openpc:participant:${scope.participantId}`;
    const foreignPrivacy = id();
    const foreignScope = { participantId: id(), privacyDomainId: id(), streamId: scope.streamId };
    const sourceKey = randomBytes(32),
      proofKey = randomBytes(32);
    const credentials = {
      accessKeyId: `RESTORE${randomBytes(10).toString('hex')}`,
      secretAccessKey: randomBytes(32).toString('base64'),
    };
    const signers: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>>[] = [];
    const trusts: ArchiveTrust[] = [];
    const externals: ExternalArchive[] = [];
    let governance: Governance | undefined;
    let foreign: Governance | undefined;
    let readback: Awaited<ReturnType<typeof restoredReadback>> | undefined;
    let passed = false;
    try {
      const fleetExpected = await fleetSchemaExpectations(admin);
      await fleetAuthority(admin, await security(admin), fleetExpected);
      const recovery = await controlDatabaseRecoveryFixture();
      const executable = join(root, 'evidence-worker.mjs');
      // Existing packaged-owner build, prepared before short-lived host authority.
      await execute(
        'pnpm',
        [
          '--dir',
          'services/control-api',
          'exec',
          'esbuild',
          'src/evidence/runtime.ts',
          '--bundle',
          '--platform=node',
          '--format=esm',
          '--banner:js=import { createRequire } from "node:module"; const require = createRequire(import.meta.url);',
          `--outfile=${executable}`,
        ],
        { timeout: 20000, maxBuffer: 16384 },
      );
      governance = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        scope.participantId,
        scope.privacyDomainId,
        {
          protectedProofKeys: {
            activeKeyId: 'restore-proof',
            keys: new Map([['restore-proof', proofKey]]),
          },
        },
      );
      foreign = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        foreignScope.participantId,
        foreignScope.privacyDomainId,
      );
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
      values($1,$2,'Restore foreign privacy','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [foreignPrivacy, scope.participantId],
      );
      for (const family of ['retention-policy', 'evidence-deletion', 'evidence-hold'] as const)
        signers.push(
          await evidenceGovernanceSigningFixture(
            admin,
            scope.participantId,
            scope.privacyDomainId,
            family,
          ),
        );
      const [policySigner, deletionSigner, holdSigner] = signers;
      const mounted: MountedArchive[] = [];
      const profiles: RemoteArchiveProfile[] = [];
      for (const sourceKind of ['SEGMENT', 'PROTECTED_PROOF'] as const) {
        const directory = join(root, sourceKind);
        await mkdir(directory, { mode: 0o700 });
        const bucket = sourceKind === 'SEGMENT' ? 'restore-segments' : 'restore-proofs';
        const external = await startRemoteArchiveFixture({
          root: join(directory, 'external'),
          credentials,
          bucket,
          expectedOwner: '123456789012',
          region: 'local-1',
        });
        externals.push(external);
        const profile: RemoteArchiveProfile = {
          profileId: bucket,
          sinkId: bucket,
          endpoint: external.endpoint,
          transport: 'LOOPBACK_TEST',
          bucket,
          region: 'local-1',
          expectedBucketOwner: '123456789012',
          prefix: 'evidence',
          lockMode: 'COMPLIANCE',
          requestTimeoutMs: 10000,
          maxVersionPages: 4,
        };
        const trust = await evidenceArchiveAuthorityFixture(
          admin,
          worker,
          scope,
          [scope.streamId],
          profile,
          { directory, credentials },
          sourceKind,
        );
        trusts.push(trust);
        profiles.push(profile);
        mounted.push(trust.runtimeConfiguration!);
      }
      const [segmentExternal, proofExternal] = externals;
      const proofTrust = trusts[1]!,
        proofProfile = profiles[1]!;
      const installedFleetTrusts = [
        await installFleetRestoreTrust(
          admin,
          join(root, 'FLEET-ACTIVE'),
          scope,
          proofTrust.workloadCredentialId,
          false,
        ),
        await installFleetRestoreTrust(
          admin,
          join(root, 'FLEET-REVOKED'),
          { participantId: scope.participantId, privacyDomainId: foreignPrivacy },
          proofTrust.workloadCredentialId,
          true,
        ),
      ];
      await assertFleetRestoreAuthority(
        admin,
        worker,
        runtimeUrl!,
        installedFleetTrusts,
        foreignScope,
      );
      const proofOwner = () =>
        new PostgresRemoteArchiveAttemptOwner(worker!, scope, proofTrust.authority);
      const proofCustody = () =>
        new ProtectedRemoteArchiveCustody(
          proofOwner(),
          proofTrust.authority,
          async () => credentials,
        );
      const passwordFile = join(root, 'worker-password'),
        keyFile = join(root, 'source.key');
      await writeFile(passwordFile, decodeURIComponent(new URL(workerUrl!).password), {
        mode: 0o600,
      });
      await writeFile(keyFile, sourceKey, { mode: 0o600 });
      const runWorker = async (databaseUrl: string, archives: MountedArchive[] = mounted) => {
        const database = new URL(databaseUrl),
          configFile = join(root, 'worker.json');
        await writeFile(
          configFile,
          JSON.stringify({
            database: {
              host: database.hostname,
              port: Number(database.port),
              database: database.pathname.slice(1),
              user: decodeURIComponent(database.username),
              passwordFile,
            },
            vaultDirectory: join(root, 'local-vault'),
            sinkId: 'restore-local',
            remoteArchives: archives,
            protectedScopes: [
              { participantId: scope.participantId, privacyDomainId: scope.privacyDomainId },
            ],
            scopes: [
              {
                ...scope,
                source: 'AUTHENTICATION',
                activeKeyId: 'restore-source',
                keys: [{ keyId: 'restore-source', keyFile }],
                retentionSeconds: 172800,
                capacityBytes: 1048576,
              },
            ],
          }),
          { mode: 0o600 },
        );
        return execute(process.execPath, [executable, '--once'], {
          env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configFile },
          timeout: 30000,
          maxBuffer: 16384,
        });
      };
      await governance.governance.client.stepUp(
        governance.governance.maker,
        'ACT-POLICY_SETS_CREATE_RESOURCE-V1',
        id(),
        sha256({ purpose: 'restore source' }),
      );
      await new EvidenceCustody(worker).ingestAuthentication(
        scope,
        { keyId: 'restore-source', key: sourceKey },
        time(172800000),
        1048576,
      );
      const sourceId = (
        await admin.query(
          `select c.evidence_id::text id from control.evidence_catalogue c join control.authentication_occurrence a
      on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id and a.occurrence_id::text=c.record_id
      where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and a.method='WEBAUTHN_ASSERTION' order by c.sequence desc limit 1`,
          [scope.participantId, scope.privacyDomainId, scope.streamId],
        )
      ).rows[0].id;
      const discovery = await governance.read(
        `evidence-records/urn:openpc:resource:${sourceId}/protected-proof-source`,
      );
      expect(discovery.status).toBe(200);
      const retain = async (reference: string, retainUntil: string) =>
        String(
          (
            await governance!.create(
              'protected-proofs',
              'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1',
              {
                participantId,
                source: discovery.body,
                purpose: 'Original custody through database recovery',
                caseReference: reference,
                retainUntil,
              },
            )
          ).body.resourceRef,
        );
      const retiredDeadline = time(12000);
      const retiredRef = await retain('retired-local-copy-before-backup', retiredDeadline);
      expect(await proofCustody().exportNext()).toMatchObject({ result: 'CHECKPOINT' });
      await governance.restartConfiguration(policySigner!.evidence);
      await governance.create('retention-policies', 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1', {
        participantId,
        predecessorPolicyId: null,
        policy: {
          dataClass: 'RAW_SOURCE_BODY',
          policyVersion: '1.0.0',
          retentionPeriodMs: '0',
          localGraceMs: '0',
          sinkQuorum: 1,
          deletionMode: 'ROW_DELETE',
          makerCheckerRequired: true,
        },
      });
      await delay(Math.max(0, Date.parse(retiredDeadline) - Date.now() + 25));
      const deletionPlan = await governance.read(`protected-proofs/${retiredRef}/deletion-plan`);
      expect(deletionPlan).toMatchObject({ status: 200, body: { eligible: true, blockers: [] } });
      await governance.restartConfiguration(deletionSigner!.evidence);
      const deleted = await governance.create(
        'evidence-deletions/raw-batches',
        'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1',
        {
          participantId,
          selection: deletionPlan.body.selection,
          beforeDigest: deletionPlan.body.beforeDigest,
        },
      );
      await governance.restartConfiguration(holdSigner!.evidence);
      const held = await governance.create(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1',
        { participantId, holdKind: 'LEGAL', selector: { type: 'PARTICIPANT' } },
      );
      const holdRef = String(held.body.resourceRef);
      expect(await proofCustody().reconcileHolds()).toMatchObject({ result: 'PROTECTION' });
      const pendingDeadline = time(3600000);
      const pendingRef = await retain('pending-original-upload-at-backup', pendingDeadline);
      const pendingView = (await governance.read(`protected-proofs/${pendingRef}`)).body;
      const maker = { ...governance.governance.maker },
        checker = { ...governance.governance.checker };
      const logoutAction = 'ACT-IDENTITY_DELETE_SESSION-V1',
        reason = 'Retain revocation through database restore';
      const revision = (
        await admin.query('select row_version::text from control.session where session_id=$1', [
          checker.sessionId,
        ])
      ).rows[0].row_version;
      const client = governance.governance.client;
      expect(
        (
          await client.request(
            `${governance.service.identityUrl}/api/v1/session/logout`,
            checker,
            {
              targetRef: `urn:openpc:resource:${checker.sessionId}`,
              actionIntentId: logoutAction,
              actionIntentDigest: client.actionDigests.get(logoutAction),
              inputDigest: sha256({ sessionId: checker.sessionId, reason }),
              expectedRevision: revision,
              reason,
            },
            {
              'OpenPC-API-Version': '1',
              'OpenPC-Participant-ID': participantId,
              'X-Request-ID': id(),
              'X-Correlation-ID': id(),
              'Idempotency-Key': `logout-${id()}`,
              'OpenPC-Action-Intent-Digest': client.actionDigests.get(logoutAction)!,
              'If-Match': `"${sha256({ resourceType: 'session', sessionId: checker.sessionId, revision })}"`,
              'X-CSRF-Token': await client.csrf(
                checker,
                logoutAction,
                governance.service.identityUrl,
              ),
            },
          )
        ).status,
      ).toBe(202);
      const identityFiles = join(root, 'identity-recovery');
      await cp(governance.service.directory, identityFiles, {
        recursive: true,
        errorOnExist: true,
        force: false,
      });
      const revoked = (
        await admin.query('select to_jsonb(s) value from control.session s where session_id=$1', [
          checker.sessionId,
        ])
      ).rows[0].value;
      // Drain this known source before backup, with protected dispatch excluded
      // until its one deliberately ambiguous upload has been committed below.
      let caughtUp = false;
      for (let pass = 0; pass < 8; pass++) {
        await runWorker(workerUrl!, [mounted[0]!]);
        const pendingSegments = (
          await admin.query(
            `select count(*)::int n from control.evidence_segment s where s.participant_id=$1
        and (not openpc.remote_archive_covers(s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id,$2))`,
            [scope.participantId, profiles[0]!.sinkId],
          )
        ).rows[0].n;
        if (pendingSegments === 0) {
          caughtUp = true;
          break;
        }
      }
      expect(caughtUp, 'Source custody must be stable before backup').toBe(true);
      proofExternal!.faults.dropPutResponse = true;
      await expect(proofCustody().exportNext()).rejects.toMatchObject({ code: 'AMBIGUOUS' });
      expect(proofExternal!.counts.puts).toBe(2);
      const attemptQuery = `select i.intent,a.attempt_id::text,a.binding,a.state,a.observation from control.evidence_remote_archive_intent i
      join control.evidence_remote_archive_attempt a using(participant_id,privacy_domain_id,intent_id)
      where i.participant_id=$1 and i.protected_object_id=$2 and a.action='PUT'`;
      const pending = (
        await admin.query(attemptQuery, [scope.participantId, pendingRef.slice(-36)])
      ).rows;
      expect(pending).toHaveLength(1);
      expect(pending[0].state).toBe('AMBIGUOUS');
      const originalIntent = remoteArchiveIntent.parse(pending[0].intent);
      expect(originalIntent.source.kind).toBe('PROTECTED_PROOF');
      const proofObjects = await proofExternal!.objects(),
        segmentObjects = await segmentExternal!.objects();
      expect(proofObjects).toHaveLength(2);
      expect(segmentObjects.length).toBeGreaterThan(0);
      const pendingObject = proofObjects.find(
        (object) => object.metadata['x-amz-meta-openpc-intent'] === sha256(originalIntent),
      );
      expect(pendingObject).toBeDefined();
      expect(pendingObject!.initialHold).toBe('ON');
      expect(pendingObject!.retention).toBe(pendingDeadline);
      const immutableBefore = await snapshot(admin, scope.participantId),
        databaseSecurityBefore = await databaseSecurity(admin),
        securityBefore = await security(admin),
        fleetBefore = await fleetAuthority(admin, securityBefore, fleetExpected);
      // Exercise the oracle against copies of the actual installed catalogue.
      // These corruptions never mutate product relations, roles or routines.
      for (const name of fleetTables) {
        const missing = structuredClone(fleetBefore);
        missing.relations = missing.relations.filter((row) => row.relname !== name);
        expect(() => assertFleetAuthority(missing, fleetExpected), `missing ${name}`).toThrow();
      }
      for (const [name] of fleetRoutines) {
        const missing = structuredClone(fleetBefore);
        missing.routines = missing.routines.filter((row) => row.name !== name);
        expect(() => assertFleetAuthority(missing, fleetExpected), `missing ${name}`).toThrow();
      }
      for (const [table, name] of fleetTriggers) {
        const missing = structuredClone(fleetBefore);
        missing.triggers = missing.triggers.filter(
          (row) => row.table !== table || row.name !== name,
        );
        expect(
          () => assertFleetAuthority(missing, fleetExpected),
          `missing ${table}.${name}`,
        ).toThrow();
      }
      const corruptions: Record<string, (value: FleetAuthority) => void> = {
        'changed commit body': (value) => {
          value.routines.find((row) => row.name === 'commit_fleet_fact_admission')!.body =
            '\nBEGIN RETURN true; END ';
        },
        'public commit execution': (value) => {
          value.routines
            .find((row) => row.name === 'commit_fleet_fact_admission')!
            .grants.push({
              grantor: 'openpc_control_owner',
              grantee: 'PUBLIC',
              privilege: 'EXECUTE',
              grantable: false,
            });
        },
        'worker key disclosure': (value) => {
          value.relations
            .find((row) => row.relname === 'fleet_fact_admission_key')!
            .grants.push({
              grantor: 'openpc_control_owner',
              grantee: 'openpc_control_worker',
              privilege: 'SELECT',
              grantable: false,
            });
        },
        'unforced inbox isolation': (value) => {
          value.relations.find(
            (row) => row.relname === 'fleet_fact_admission_inbox',
          )!.relforcerowsecurity = false;
        },
        'missing quarantine worker grant': (value) => {
          value.routines.find((row) => row.name === 'commit_fleet_fact_quarantine')!.grants = [];
        },
        'worker can bypass delivery admission': (value) => {
          value.routines
            .find((row) => row.name === 'close_fleet_delivery_lease')!
            .grants.push({
              grantor: 'openpc_control_owner',
              grantee: 'openpc_control_worker',
              privilege: 'EXECUTE',
              grantable: false,
            });
        },
        'changed quarantine admission': (value) => {
          value.routines.find((row) => row.name === 'prepare_fleet_fact_quarantine')!.body =
            '\nBEGIN RETURN NULL; END ';
        },
        'changed signer validation': (value) => {
          value.routines.find((row) => row.name === 'require_fact_failure_signer')!.body =
            '\nBEGIN RETURN NULL; END ';
        },
        'changed atomicity body': (value) => {
          value.routines.find((row) => row.name === 'assert_fleet_quarantine_atomic')!.body =
            '\nBEGIN RETURN NULL; END ';
        },
        'missing signer revocation grant': (value) => {
          const signer = value.relations.find(
            (row) => row.relname === 'fact_consumer_failure_signer',
          )!;
          signer.grants = signer.grants.filter(
            (grant) =>
              grant.grantee !== 'openpc_control_key_governor' || grant.privilege !== 'UPDATE',
          );
        },
        'worker can install failure signer': (value) => {
          value.relations
            .find((row) => row.relname === 'fact_consumer_failure_signer')!
            .grants.push({
              grantor: 'openpc_control_owner',
              grantee: 'openpc_control_worker',
              privilege: 'INSERT',
              grantable: false,
            });
        },
        'permissive quarantine privacy policy': (value) => {
          value.relations
            .find((row) => row.relname === 'fleet_fact_quarantine')!
            .policies!.find((policy) => policy.name === 'privacy_domain_isolation')!.permissive =
            true;
        },
        'unscoped delivery owner policy': (value) => {
          value.relations
            .find((row) => row.relname === 'fleet_fact_delivery')!
            .policies!.find((policy) => policy.name === 'fleet_delivery_owner')!.check = 'true';
        },
        'unscoped attempt profile reference': (value) => {
          value.relations
            .find((row) => row.relname === 'fleet_fact_delivery_attempt')!
            .constraints!.find(
              (constraint) => constraint.name === 'fleet_delivery_attempt_profile_fk',
            )!.referenced_columns = ['profile_digest'];
        },
        'unenforced failure outbox reference': (value) => {
          value.relations
            .find((row) => row.relname === 'fleet_fact_failure_outbox')!
            .constraints!.find(
              (constraint) => constraint.name === 'fleet_failure_outbox_receipt_fk',
            )!.enforced = false;
        },
        'weakened quarantine state constraint': (value) => {
          value.relations
            .find((row) => row.relname === 'fleet_fact_quarantine')!
            .constraints!.find(
              (constraint) => constraint.name === 'fleet_quarantine_state_ck',
            )!.definition = 'CHECK (true)';
        },
        'missing retry budget constraint': (value) => {
          const delivery = value.relations.find((row) => row.relname === 'fleet_fact_delivery')!;
          delivery.constraints = delivery.constraints!.filter(
            (constraint) => constraint.name !== 'fleet_delivery_budget_ck',
          );
        },
        'weakened active signer uniqueness': (value) => {
          value.signerIndexes[0]!.predicate = "(state = 'REVOKED'::text)";
        },
        'invalid active signer index': (value) => {
          value.signerIndexes[0]!.valid = false;
        },
        'disabled delivery history guard': (value) => {
          value.triggers.find(
            (trigger) => trigger.table === 'fleet_fact_delivery_attempt',
          )!.enabled = 'D';
        },
        'retargeted signer installation guard': (value) => {
          value.triggers.find(
            (trigger) => trigger.name === 'fact_failure_signer_installation',
          )!.routine = 'guard_fleet_quarantine_history';
        },
        'atomicity trigger not initially deferred': (value) => {
          value.triggers.find((trigger) => trigger.name === 'fleet_quarantine_atomic')!.deferred =
            false;
        },
        'atomicity trigger not a constraint': (value) => {
          value.triggers.find((trigger) => trigger.name === 'fleet_quarantine_atomic')!.constraint =
            null;
        },
        'atomicity constraint not deferrable': (value) => {
          value.relations
            .find((row) => row.relname === 'fleet_fact_quarantine')!
            .constraints!.find(
              (constraint) => constraint.name === 'fleet_quarantine_atomic',
            )!.deferrable = false;
        },
        'work-item kind/action fence removed': (value) => {
          value.workItem.policies!.find(
            (policy) => policy.name === 'fleet_failure_work_item',
          )!.check = 'true';
        },
        'missing work-item insert grant': (value) => {
          value.workItem.grants = value.workItem.grants.filter(
            (grant) => grant.grantee !== 'openpc_control_owner' || grant.privilege !== 'INSERT',
          );
        },
      };
      for (const [name, corrupt] of Object.entries(corruptions)) {
        const altered = structuredClone(fleetBefore);
        corrupt(altered);
        expect(() => assertFleetAuthority(altered, fleetExpected), name).toThrow();
      }
      for (const row of securityBefore.filter((row) =>
        /^(evidence_|protected_proof_)/u.test(row.relname),
      )) {
        expect(row).toMatchObject({
          relrowsecurity: true,
          relforcerowsecurity: true,
          owner: 'openpc_control_owner',
        });
      }
      const unchangedAttemptsQuery = `select to_jsonb(a) value from control.evidence_remote_archive_attempt a
        where participant_id=$1 and attempt_id<>$2 order by attempt_id`;
      const unchangedAttempts = (
        await admin.query(unchangedAttemptsQuery, [scope.participantId, pending[0].attempt_id])
      ).rows;
      const putsBefore = [segmentExternal!.counts.puts, proofExternal!.counts.puts];
      const holdsBefore = [segmentExternal!.counts.holds, proofExternal!.counts.holds];
      const noCheckpoint = async () =>
        expect(
          (
            await admin!.query(
              `select count(*)::int n from control.protected_proof_checkpoint
      where object_id=$1 and sink_id=$2`,
              [pendingRef.slice(-36), proofProfile.sinkId],
            )
          ).rows[0].n,
        ).toBe(0);
      await noCheckpoint();
      // No process can write either source scope while the backup is copied.
      await governance.close();
      governance = undefined;
      await foreign.close();
      foreign = undefined;
      await Promise.all([admin.end(), worker.end()]);
      admin = undefined;
      worker = undefined;
      await recovery.restore();
      admin = new Pool({ connectionString: recovery.adminUrl, max: 2 });
      worker = new Pool({ connectionString: recovery.workerUrl, max: 1 });
      expect(await snapshot(admin, scope.participantId)).toEqual(immutableBefore);
      expect(await databaseSecurity(admin)).toEqual(databaseSecurityBefore);
      const securityAfter = await security(admin);
      expect(securityAfter).toEqual(securityBefore);
      expect(await fleetAuthority(admin, securityAfter, fleetExpected)).toEqual(fleetBefore);
      // Reuse original installation pins; do not rerun either bootstrap after
      // restoration or create a fresh profile/signer in the recovered database.
      await assertFleetRestoreAuthority(
        admin,
        worker,
        recovery.runtimeUrl,
        installedFleetTrusts,
        foreignScope,
      );
      expect(
        (await admin.query(attemptQuery, [scope.participantId, pendingRef.slice(-36)])).rows,
      ).toEqual(pending);
      await noCheckpoint();
      const assertNoNewPut = () =>
        expect([segmentExternal!.counts.puts, proofExternal!.counts.puts]).toEqual(putsBefore);
      const refusedWorker = async (archives = mounted) => {
        await expect(runWorker(recovery.workerUrl, archives)).rejects.toMatchObject({
          code: 1,
          stderr: expect.stringContaining('UNAVAILABLE'),
        });
        assertNoNewPut();
        await noCheckpoint();
      };
      // Missing/mismatched mounted trust fails before any worker phase or I/O.
      const proofMount = mounted[1]!;
      for (const invalid of [
        { ...proofMount, signedProfileFile: join(root, 'missing-profile.json') },
        {
          ...proofMount,
          trust: { ...proofMount.trust, issuerSpkiHex: mounted[0]!.trust.issuerSpkiHex },
        },
      ]) {
        await refusedWorker([mounted[0]!, invalid]);
        expect(await snapshot(admin, scope.participantId)).toEqual(immutableBefore);
      }
      // External faults cannot promote the restored AMBIGUOUS journal to custody,
      // lose its original intent, substitute a version or authorize another PUT.
      await proofExternal!.rewriteVersion(pendingObject!, { deleteMarker: true });
      try {
        await refusedWorker();
      } finally {
        await proofExternal!.rewriteVersion(pendingObject!, {});
      }
      for (const fault of ['wrongVersion', 'corruptRead'] as const) {
        proofExternal!.faults[fault] = true;
        try {
          await refusedWorker();
        } finally {
          proofExternal!.faults[fault] = false;
        }
      }
      expect(
        (await admin.query(attemptQuery, [scope.participantId, pendingRef.slice(-36)])).rows[0],
      ).toMatchObject({
        attempt_id: pending[0].attempt_id,
        binding: pending[0].binding,
        state: 'AMBIGUOUS',
      });
      await runWorker(recovery.workerUrl);
      assertNoNewPut();
      const recovered = (
        await admin.query(attemptQuery, [scope.participantId, pendingRef.slice(-36)])
      ).rows;
      expect(recovered).toHaveLength(1);
      expect(recovered[0]).toMatchObject({
        attempt_id: pending[0].attempt_id,
        binding: pending[0].binding,
        state: 'OBSERVED',
      });
      const observation = remoteArchiveReceipt.parse(recovered[0].observation);
      expect(observation.locator.versionId).toBe(pendingObject!.versionId);
      expect(observation.observedRetention.retainUntil).toBe(pendingDeadline);
      expect(observation.observedLegalHold).toBe('ON');
      const transport = new RemoteEvidenceArchive(
        proofProfile,
        async () => credentials,
        proofOwner(),
      );
      const packet = await transport.readExact(originalIntent, observation.locator);
      expect(packet).toEqual(Buffer.from(pendingObject!.bytes, 'base64'));
      expect(sha256(packet)).toBe(originalIntent.payloadDigest);
      expect(originalIntent.payloadBytes).toBe(packet.length);
      const sealed = (
        await admin.query(
          `select r.payload,r.cose,r.receipt_digest,c.checkpoint_digest,o.event,o.event_digest
      from control.evidence_archive_receipt r join control.evidence_archive_outbox o using(participant_id,privacy_domain_id,receipt_id)
      join control.protected_proof_checkpoint c using(participant_id,privacy_domain_id,receipt_digest)
      where r.participant_id=$1 and r.attempt_id=$2`,
          [scope.participantId, pending[0].attempt_id],
        )
      ).rows;
      expect(sealed).toHaveLength(1);
      const signed = proofTrust.authority.verifyProtected(sealed[0].payload, sealed[0].cose);
      expect(signed.receiptDigest).toBe(sealed[0].receipt_digest);
      expect(signed.claims).toMatchObject({
        intentId: originalIntent.intentId,
        attemptId: pending[0].attempt_id,
        objectId: pendingRef.slice(-36),
        payloadDigest: originalIntent.payloadDigest,
        locatorDigest: sha256(observation.locator),
        proofRetainUntilMicros: retentionMicros(pendingDeadline).toString(),
      });
      expect(sealed[0].event_digest).toBe(sha256(sealed[0].event));
      // Read original signed history for every remote object, including the
      // expired proof whose local ciphertext was deleted before this backup.
      const histories = (
        await admin.query(
          `select i.intent,a.observation,r.payload,r.cose,r.receipt_digest from control.evidence_archive_receipt r
      join control.evidence_remote_archive_attempt a on a.participant_id=r.participant_id
       and a.privacy_domain_id=r.privacy_domain_id and a.attempt_id=r.attempt_id and a.intent_id=r.intent_id
      join control.evidence_remote_archive_intent i on i.participant_id=a.participant_id
       and i.privacy_domain_id=a.privacy_domain_id and i.intent_id=a.intent_id
      where r.participant_id=$1 order by r.receipt_id`,
          [scope.participantId],
        )
      ).rows;
      const latest = new Map<string, (typeof histories)[number]>();
      for (const history of histories) {
        const intent = remoteArchiveIntent.parse(history.intent);
        const index = intent.source.kind === 'SEGMENT' ? 0 : 1,
          trust = trusts[index]!;
        const verified =
          index === 0
            ? trust.authority.verify(history.payload, history.cose)
            : trust.authority.verifyProtected(history.payload, history.cose);
        expect(verified.receiptDigest).toBe(history.receipt_digest);
        latest.set(intent.intentId, history);
      }
      for (const history of latest.values()) {
        const intent = remoteArchiveIntent.parse(history.intent),
          observed = remoteArchiveReceipt.parse(history.observation);
        const index = intent.source.kind === 'SEGMENT' ? 0 : 1,
          trust = trusts[index]!;
        const owner = new PostgresRemoteArchiveAttemptOwner(worker, scope, trust.authority);
        const archive = new RemoteEvidenceArchive(profiles[index]!, async () => credentials, owner);
        expect(sha256(await archive.readExact(intent, observed.locator))).toBe(
          intent.payloadDigest,
        );
        const current = await archive.verifyExact(
          intent,
          observed.locator,
          await owner.currentProtection(intent),
        );
        expect(current.observedLegalHold).toBe('ON');
        if (intent.source.kind === 'PROTECTED_PROOF') {
          expect(intent.source.object.retainUntil).toBe(
            intent.source.object.objectRef === retiredRef ? retiredDeadline : pendingDeadline,
          );
        } else {
          expect(retentionMicros(intent.source.object.retentionUntil)).toBeGreaterThan(
            retentionMicros(pendingDeadline),
          );
        }
      }
      await runWorker(recovery.workerUrl);
      assertNoNewPut();
      expect(
        (await admin.query(attemptQuery, [scope.participantId, pendingRef.slice(-36)])).rows,
      ).toEqual(recovered);
      expect(
        (await admin.query(unchangedAttemptsQuery, [scope.participantId, pending[0].attempt_id]))
          .rows,
      ).toEqual(unchangedAttempts);
      expect(await proofExternal!.objects()).toEqual(proofObjects);
      expect(await segmentExternal!.objects()).toEqual(segmentObjects);
      const empty = { proofs: 0, payloads: 0, intents: 0, receipts: 0, events: 0 };
      expect(await isolated(worker, foreignScope, scope.participantId)).toEqual(empty);
      expect(
        await isolated(worker, { ...scope, privacyDomainId: foreignPrivacy }, scope.participantId),
      ).toEqual(empty);
      expect((await isolated(worker, scope, scope.participantId)).proofs).toBe(2);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.protected_proof_payload where object_id=$1',
            [retiredRef.slice(-36)],
          )
        ).rows[0].n,
      ).toBe(0);
      expect(
        (
          await admin.query('select to_jsonb(s) value from control.session s where session_id=$1', [
            checker.sessionId,
          ])
        ).rows[0].value,
      ).toEqual(revoked);
      const after = await snapshot(admin, scope.participantId);
      for (const table of tables.filter((table) => table !== 'evidence_remote_archive_attempt'))
        expect(after[table], `Original ${table} survives restore and reconciliation`).toEqual(
          expect.arrayContaining(immutableBefore[table]!),
        );
      for (const table of ['fact_consumer_profile', 'fact_consumer_failure_signer'])
        expect(after[table], `Installed ${table} bindings survive reconciliation`).toEqual(
          immutableBefore[table],
        );
      readback = await restoredReadback(
        recovery.runtimeUrl,
        identityFiles,
        scope,
        maker.principalId,
        checker.principalId,
      );
      const proofView = await readback.read(`protected-proofs/${pendingRef}`, maker.sessionToken);
      expect(proofView).toMatchObject({ status: 200, body: pendingView, cache: 'no-store' });
      expect(JSON.stringify(proofView.body)).not.toMatch(
        /ciphertext|nonce|assertionBase64|privateKey/u,
      );
      expect(
        await readback.read(`protected-proofs/${retiredRef}/deletion-plan`, maker.sessionToken),
      ).toMatchObject({
        status: 200,
        body: { localPayload: 'DELETED', blockers: ['ALREADY_DELETED'] },
      });
      expect(await readback.read(`evidence-holds/${holdRef}`, maker.sessionToken)).toMatchObject({
        status: 200,
        body: { state: 'ACTIVE', revision: '1', coverage: 'VERIFIED' },
      });
      expect(
        (await readback.read(`evidence-deletions/${deleted.body.resourceRef}`, maker.sessionToken))
          .status,
      ).toBe(200);
      expect([401, 403]).toContain(
        (await readback.read(`protected-proofs/${pendingRef}`, checker.sessionToken)).status,
      );
      expect([403, 404]).toContain(
        (await readback.read(`protected-proofs/${pendingRef}`, maker.sessionToken, foreignScope))
          .status,
      );
      expect([403, 404]).toContain(
        (
          await readback.read(`protected-proofs/${pendingRef}`, maker.sessionToken, {
            ...scope,
            privacyDomainId: foreignPrivacy,
          })
        ).status,
      );
      // Opening the mounted owner again proves restored host trust/roles admit the
      // original signed profile. This performs no extra effect or business replay.
      const reopened = await openRemoteArchiveRuntime(worker, proofMount, [scope]);
      try {
        expect(await reopened.forScope(scope).exportNext()).toBeNull();
        expect(await reopened.forScope(scope).reconcileHolds()).toBeNull();
      } finally {
        reopened.close();
      }
      assertNoNewPut();
      expect([segmentExternal!.counts.holds, proofExternal!.counts.holds]).toEqual(holdsBefore);
      // This fixture workload also owns protected archive trust. Revoke it only
      // after every existing archive recovery/readback obligation has completed.
      const revokedWorkload = await admin.query<{ epoch: string }>(
        `update control.credential set state='REVOKED',credential_epoch=credential_epoch+1
         where participant_id=$1 and credential_id=$2 and credential_epoch=$3 and state='ACTIVE'
         returning credential_epoch::text epoch`,
        [
          scope.participantId,
          proofTrust.workloadCredentialId,
          installedFleetTrusts[0]!.installed.workloadCredentialEpoch,
        ],
      );
      expect(revokedWorkload.rows).toEqual([
        {
          epoch: (
            BigInt(installedFleetTrusts[0]!.installed.workloadCredentialEpoch) + 1n
          ).toString(),
        },
      ]);
      // A new connection must still deny new profile use with the original
      // signed pins. Retained historical trust is never renewed or reactivated.
      await worker.end();
      worker = new Pool({ connectionString: recovery.workerUrl, max: 1 });
      for (const trust of installedFleetTrusts) {
        await expect(
          withFleetRestoreContext(worker, trust.installed, (client) =>
            requireFactConsumerProfile(client, trust.installed),
          ),
        ).rejects.toThrow('PC-AUTH-0005');
        await assertFleetRestoreBindings(admin, trust);
      }
      await assertNoFleetRestoreEffects(admin, scope.participantId);
      assertNoNewPut();
      passed = true;
    } finally {
      await readback?.close();
      await governance?.close();
      await foreign?.close();
      for (const trust of trusts) trust.close();
      for (const external of externals) await external.close();
      for (const signer of signers) await signer.close();
      await Promise.all([admin?.end(), worker?.end()]);
      sourceKey.fill(0);
      proofKey.fill(0);
      // Remove mounted private keys even on failure. The actual database backup
      // includes synthetic host trust and stays private under the runner root.
      for (const directory of ['identity-recovery', 'SEGMENT', 'PROTECTED_PROOF']) {
        if (directory === 'identity-recovery')
          await rm(join(root, directory), { recursive: true, force: true });
        else
          for (const name of [
            'archive-signer.der',
            'archive-commit.key',
            'archive-credentials.json',
          ])
            await rm(join(root, directory, name), { force: true });
      }
      await rm(join(root, 'worker-password'), { force: true });
      await rm(join(root, 'source.key'), { force: true });
      for (const directory of ['FLEET-ACTIVE', 'FLEET-REVOKED'])
        await rm(join(root, directory, 'fleet_fact_failure_signing_key.txt'), { force: true });
      if (passed) await rm(root, { recursive: true, force: true });
    }
  },
  240000,
);
