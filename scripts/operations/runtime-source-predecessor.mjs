// Prospective local installation custody. Cluster globals are deliberately
// outside supported per-database restores. This never installs a source root.
import { createHash } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { open, lstat, realpath, mkdtemp, mkdir, copyFile, chmod, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isIP } from 'node:net';
import { promisify } from 'node:util';
import { Client, Pool } from 'pg';
import { z } from 'zod';
import { runtimeSourceLogin } from '../../packages/security-kernel/src/runtime-source-identity.ts';
import { canonicalJson } from '../../services/control-api/src/configuration/digest.ts';
import { parseStrictJsonBytes } from '../../services/control-api/src/privacy-explorer/strict-json.ts';

export const predecessorRevision = '5baddf3d4ed503f0b9a7112c34521048671409a7';
const purpose = 'openpc:runtime-source-predecessor:v1';
const execute = promisify(execFile);
const builtArtifacts = new WeakMap();
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hex = z.string().regex(/^[0-9a-f]{64}$/u);
const role = z.string().regex(/^[a-z][a-z0-9_]{0,62}$/u);
const enrollmentSchema = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  installationId: z.uuidv7(),
  legacyRole: role,
  sourceRevision: z.literal(predecessorRevision),
  executableDigest: hex,
  clusterIdentifier: z.string().regex(/^[0-9]{1,20}$/u),
  databaseOid: z.number().int().positive(),
  databaseName: z.string().min(1).max(63),
});
const profileSchema = z.strictObject({
  purpose: z.literal(purpose),
  enrollment: enrollmentSchema,
  state: z.enum([
    'ENROLLED',
    'RUNNING',
    'STOPPED',
    'QUIESCING',
    'CAPTURING',
    'CAPTURED',
    'CONSUMED',
  ]),
  runId: z.uuidv7().nullable(),
  captureDigest: hex.nullable(),
  successorSchemaDigest: hex.nullable(),
  successorMigrationPaths: z.array(z.string().min(1).max(512)).max(2048),
  priorConnectionLimit: z.number().int().min(-1),
});
const rejectionStages = Object.freeze({
  artifact_untrusted: 'enrollment',
  protected_scope: 'installation',
  profile_scope_mismatch: 'installation',
  cluster_mismatch: 'installation',
  database_mismatch: 'installation',
  run_state_rejected: 'run',
  executable_mismatch: 'run',
  endpoint_mismatch: 'run',
  active_sessions: 'quiesce',
  capture_state_rejected: 'capture',
  reconcile_state_rejected: 'reconcile',
  reconcile_bytes_mismatch: 'reconcile',
  consume_state_rejected: 'consume',
  consume_bytes_mismatch: 'consume',
});
class PredecessorRejection extends Error {
  constructor(reason) {
    super('RUNTIME_SOURCE_PREDECESSOR_REJECTED');
    this.reason = reason;
  }
}
const fail = (reason) => {
  if (Object.hasOwn(rejectionStages, reason)) throw new PredecessorRejection(reason);
  throw new Error('RUNTIME_SOURCE_PREDECESSOR_REJECTED');
};
export const isRuntimePredecessorRejection = (error, reason) =>
  Object.hasOwn(rejectionStages, reason) &&
  error instanceof PredecessorRejection &&
  error.reason === reason;

/** Only a rejection issued at its actual owning predicate is attributable.
 * Config, resource, transport, SQL and unexpected failures remain unavailable. */
export function runtimePredecessorHostFailure(error) {
  return isRuntimePredecessorRejection(error, error?.reason)
    ? {
        event: 'runtime_source_predecessor_rejected',
        stage: rejectionStages[error.reason],
        reason: error.reason,
      }
    : { event: 'runtime_source_predecessor_unavailable', stage: 'host', reason: 'unavailable' };
}
export function isRuntimePredecessorHostRejection(error, reason) {
  if (
    !Object.hasOwn(rejectionStages, reason) ||
    error?.code !== 1 ||
    (error.signal !== null && error.signal !== undefined) ||
    error.killed === true ||
    (error.stdout ?? '') !== '' ||
    typeof error.stderr !== 'string' ||
    error.stderr.length > 512
  )
    return false;
  try {
    const actual = parseStrictJsonBytes(Buffer.from(error.stderr), { maximumDepth: 2 });
    return (
      Object.keys(actual).length === 3 &&
      actual.event === 'runtime_source_predecessor_rejected' &&
      actual.stage === rejectionStages[reason] &&
      actual.reason === reason
    );
  } catch {
    return false;
  }
}
export const predecessorMarker = (participant, privacy) =>
  runtimeSourceLogin(participant, privacy).replace('openpc_rs_login_', 'openpc_rs_pre_');

/** The local supported predecessor is built from the exact preserved commit,
 * never from a caller's version string or a binary with a self-authored pin.
 * This is an admitted build phase; it creates no installation or business state. */
export async function buildRuntimePredecessor(repository) {
  const canonical = await realpath(repository);
  const { stdout } = await execute('git', ['rev-parse', '--show-toplevel'], { cwd: canonical });
  if (stdout.trim() !== canonical) fail();
  const revision = await execute(
    'git',
    ['rev-parse', '--verify', `${predecessorRevision}^{commit}`],
    { cwd: canonical },
  );
  if (revision.stdout.trim() !== predecessorRevision) fail();
  await execute(
    'bash',
    [
      join(canonical, 'scripts/maintenance/run-bounded.sh'),
      '--profile',
      'focused',
      '--memory-gib',
      '8',
      '--peak-disk-gib',
      '40',
      '--reuse',
      '--',
      'true',
    ],
    { cwd: canonical },
  );
  const scratch = process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT;
  if (!scratch || !scratch.startsWith('/')) fail();
  const root = await mkdtemp(join(scratch, 'runtime-source-predecessor.'));
  const source = join(root, 'source');
  await mkdir(source, { mode: 0o700 });
  const archive = join(root, 'predecessor.tar');
  await execute('git', ['archive', '--format=tar', '--output', archive, predecessorRevision], {
    cwd: canonical,
  });
  await execute('tar', ['--extract', '--file', archive, '--directory', source]);
  // Reuse the canonical compiler cache through Cargo's ordinary input tracking.
  // The separately copied result remains fixed if the current tree is built later.
  const target = process.env.CARGO_TARGET_DIR ?? join(canonical, 'target');
  await new Promise((resolve, reject) => {
    const child = spawn(
      'cargo',
      [
        'build',
        '--package',
        'openpc-fleet-controller',
        '--bin',
        'local_runtime_worker',
        '--locked',
        '--offline',
      ],
      {
        cwd: source,
        env: { ...process.env, CARGO_TARGET_DIR: target },
        stdio: ['ignore', 'inherit', 'inherit'],
      },
    );
    child.once('error', reject);
    child.once('close', (code) =>
      code === 0 ? resolve() : reject(new Error('RUNTIME_SOURCE_PREDECESSOR_BUILD_FAILED')),
    );
  });
  const executable = join(root, 'openpc-control-worker-predecessor');
  await copyFile(join(target, 'debug/local_runtime_worker'), executable, constants.COPYFILE_EXCL);
  await chmod(executable, 0o500);
  const artifact = Object.freeze({
    sourceRevision: predecessorRevision,
    executable,
    executableDigest: await fileDigest(executable, true),
    source,
  });
  builtArtifacts.set(artifact, artifact.executableDigest);
  return artifact;
}

async function fileDigest(path, executable = false) {
  if (typeof path !== 'string' || !path.startsWith('/') || (await realpath(path)) !== path) fail();
  const metadata = await lstat(path);
  if (
    !metadata.isFile() ||
    (metadata.mode & 0o022) !== 0 ||
    metadata.size > (executable ? 1024 : 256) * 1024 * 1024
  )
    fail();
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const actual = await file.stat();
    if (actual.dev !== metadata.dev || actual.ino !== metadata.ino) fail();
    if (executable) {
      const magic = Buffer.alloc(4);
      await file.read(magic, 0, 4, 0);
      if ((actual.mode & 0o111) === 0 || !magic.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])))
        fail();
    }
    const hash = createHash('sha256');
    for await (const chunk of file.createReadStream({ start: 0, autoClose: false }))
      hash.update(chunk);
    const after = await file.stat();
    if (
      after.size !== actual.size ||
      after.mtimeMs !== actual.mtimeMs ||
      after.ctimeMs !== actual.ctimeMs
    )
      fail();
    return hash.digest('hex');
  } finally {
    await file.close();
  }
}

async function statement(client, template, first, second = '') {
  const result = await client.query('select pg_catalog.format($1,$2::text,$3::text) statement', [
    template,
    first,
    second,
  ]);
  await client.query(result.rows[0].statement);
}
async function identity(client) {
  const { rows } = await client.query(`select s.system_identifier::text as "clusterIdentifier",
    d.oid::integer as "databaseOid",d.datname as "databaseName",d.datconnlimit as "connectionLimit",
    current_user=session_user and r.rolsuper privileged
    from pg_control_system() s,pg_database d,pg_roles r
    where d.datname=current_database() and r.rolname=session_user`);
  if (rows.length !== 1 || rows[0].privileged !== true) fail();
  return rows[0];
}
async function schemaDigest(client) {
  const { rows } = await client.query(`select encode(sha256(convert_to(
    jsonb_agg(jsonb_build_array(path,sha256) order by path)::text,'UTF8')),'hex') digest
    from openpc_local.migration`);
  return hex.parse(rows[0]?.digest);
}
async function successorSchema(client) {
  const { rows } = await client.query('select path from openpc_local.migration order by path');
  if (
    !rows.length ||
    rows.length > 2048 ||
    !['0171_runtime_artifact_source_custody.sql', '0173_scoped_fact_consumer_role.sql'].every(
      (name) => rows.some((row) => row.path === `/migrations/postgres/control-api/${name}`),
    )
  )
    fail();
  return {
    successorSchemaDigest: await schemaDigest(client),
    successorMigrationPaths: rows.map((row) => row.path),
  };
}
async function safeLogin(client, name, canLogin) {
  const { rows } = await client.query(
    `select r.rolcanlogin=$2 and not r.rolsuper and not r.rolbypassrls
    and not r.rolcreaterole and not r.rolcreatedb and not r.rolreplication
    and pg_has_role(r.oid,'openpc_control_worker','USAGE')
    and not exists(select 1 from pg_auth_members m join pg_roles p on p.oid=m.roleid
      join pg_roles g on g.oid=m.grantor where m.member=r.oid
      and (p.rolname<>'openpc_control_worker' or m.admin_option or not g.rolsuper))
    and not exists(select 1 from pg_shdepend d where d.refclassid='pg_authid'::regclass
      and d.refobjid=r.oid and d.deptype in ('a','o','r','i')) safe
    from pg_roles r where r.rolname=$1`,
    [name, canLogin],
  );
  if (rows.length !== 1 || rows[0].safe !== true) fail();
}
async function readProfile(client, marker) {
  const { rows } = await client.query(
    `select shobj_description(r.oid,'pg_authid') profile,
    not r.rolcanlogin and not r.rolsuper and not r.rolbypassrls and not r.rolcreaterole
    and not r.rolcreatedb and not r.rolreplication
    and not exists(select 1 from pg_auth_members m where m.member=r.oid)
    and not exists(select 1 from pg_shdepend d where d.refclassid='pg_authid'::regclass
      and d.refobjid=r.oid and d.deptype in ('a','o','r','i')) safe
    from pg_roles r where r.rolname=$1`,
    [marker],
  );
  if (rows.length !== 1 || rows[0].safe !== true) fail();
  const profile = profileSchema.parse(JSON.parse(rows[0].profile));
  const actual = await identity(client);
  const e = profile.enrollment;
  if (predecessorMarker(e.participantId, e.privacyDomainId) !== marker)
    fail('profile_scope_mismatch');
  if (actual.clusterIdentifier !== e.clusterIdentifier) fail('cluster_mismatch');
  if (actual.databaseOid !== e.databaseOid || actual.databaseName !== e.databaseName)
    fail('database_mismatch');
  const rooted = await client.query('select 1 from pg_roles where rolname=$1', [
    runtimeSourceLogin(e.participantId, e.privacyDomainId),
  ]);
  if (rooted.rowCount !== 0) fail('protected_scope');
  return profile;
}
const save = (client, marker, profile) =>
  statement(
    client,
    'COMMENT ON ROLE %I IS %L',
    marker,
    canonicalJson(profileSchema.parse(profile)),
  );

async function owned(pool, scope, action) {
  const marker = predecessorMarker(scope.participantId, scope.privacyDomainId);
  const client = await pool.connect();
  let locked = false;
  try {
    await identity(client);
    const result = await client.query(
      "select pg_try_advisory_lock(hashtextextended('runtime-source-predecessor:'||$1,0)) acquired",
      [marker],
    );
    if (result.rows[0].acquired !== true) fail();
    locked = true;
    return await action(client, marker);
  } finally {
    if (locked)
      await client.query(
        "select pg_advisory_unlock(hashtextextended('runtime-source-predecessor:'||$1,0))",
        [marker],
      );
    client.release();
  }
}
async function transaction(client, action) {
  await client.query('begin');
  try {
    const result = await action();
    await client.query('commit');
    return result;
  } catch (error) {
    await client.query('rollback');
    throw error;
  }
}

/** Initial host trust before old first use. New role and scope INSERTs make
 * retrospective enrollment impossible; no unknown existing login is granted. */
export async function enrollRuntimePredecessor(pool, input) {
  return owned(pool, input, async (client, marker) =>
    transaction(client, async () => {
      const artifact = input.artifact;
      if (
        !artifact ||
        !builtArtifacts.has(artifact) ||
        (await fileDigest(artifact.executable, true)) !== builtArtifacts.get(artifact)
      )
        fail('artifact_untrusted');
      const actual = await identity(client);
      const rooted = await client.query('select 1 from pg_roles where rolname=$1', [
        runtimeSourceLogin(input.participantId, input.privacyDomainId),
      ]);
      if (rooted.rowCount !== 0) fail('protected_scope');
      const enrollment = enrollmentSchema.parse({
        participantId: input.participantId,
        privacyDomainId: input.privacyDomainId,
        installationId: input.installationId,
        legacyRole: input.legacyRole,
        sourceRevision: artifact.sourceRevision,
        executableDigest: artifact.executableDigest,
        clusterIdentifier: actual.clusterIdentifier,
        databaseOid: actual.databaseOid,
        databaseName: actual.databaseName,
      });
      if (!/^[A-Za-z0-9]{32,256}$/u.test(input.password)) fail();
      if (input.legacyRole.startsWith('openpc_rs_')) fail();
      for (const value of [input.displayName, input.domainName, input.residencyProfile]) {
        if (
          typeof value !== 'string' ||
          !value.trim() ||
          value.length > 160 ||
          /\p{Cc}/u.test(value)
        )
          fail();
      }
      await statement(
        client,
        'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
        marker,
      );
      await statement(
        client,
        'CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
        enrollment.legacyRole,
        input.password,
      );
      await statement(client, 'GRANT openpc_control_worker TO %I', enrollment.legacyRole);
      await client.query(
        'GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO openpc_control_worker',
      );
      await client.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,$2,'ACTIVE',1)",
        [input.participantId, input.displayName],
      );
      await client.query(
        "insert into control.privacy_domain(participant_id,privacy_domain_id,domain_name,placement_profile,residency_profile,state) values($1,$2,$3,'PARTICIPANT_LOCAL',$4,'ACTIVE')",
        [input.participantId, input.privacyDomainId, input.domainName, input.residencyProfile],
      );
      await client.query(
        'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
        [input.participantId, input.privacyDomainId],
      );
      await save(client, marker, {
        purpose,
        enrollment,
        state: 'ENROLLED',
        runId: null,
        captureDigest: null,
        successorSchemaDigest: null,
        successorMigrationPaths: [],
        priorConnectionLimit: actual.connectionLimit,
      });
      return enrollment;
    }),
  );
}

/** This owner observes the actual pinned predecessor child. A crashed owner
 * leaves RUNNING in independent cluster custody, which cannot be captured. */
export async function runRuntimePredecessor(pool, scope, input) {
  return owned(pool, scope, async (client, marker) => {
    const profile = await readProfile(client, marker);
    if (!['ENROLLED', 'STOPPED'].includes(profile.state)) fail('run_state_rejected');
    if (
      !Array.isArray(input.arguments) ||
      !(
        input.arguments.length === 0 ||
        (input.arguments.length === 1 && input.arguments[0] === 'fact-admission-once')
      )
    )
      fail();
    await safeLogin(client, profile.enrollment.legacyRole, true);
    const endpoint = await predecessorEndpoint(client, profile, input);
    if ((await fileDigest(input.executable, true)) !== profile.enrollment.executableDigest)
      fail('executable_mismatch');
    profile.state = 'RUNNING';
    profile.runId = z.uuidv7().parse(input.runId);
    await save(client, marker, profile);
    const output = input.logFile
      ? await open(
          input.logFile,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
          0o600,
        )
      : undefined;
    const child = spawn(input.executable, input.arguments, {
      env: {
        ...input.environment,
        OPENPC_LOCAL_RUNTIME: '1',
        CONTROL_WORKER_DATABASE_HOST: endpoint.host,
        CONTROL_WORKER_DATABASE_PORT: String(endpoint.port),
        CONTROL_WORKER_DATABASE_NAME: profile.enrollment.databaseName,
        CONTROL_WORKER_PARTICIPANT_ID: profile.enrollment.participantId,
        CONTROL_WORKER_PRIVACY_DOMAIN_ID: profile.enrollment.privacyDomainId,
        CONTROL_WORKER_DATABASE_USER: profile.enrollment.legacyRole,
        CONTROL_WORKER_DATABASE_PASSWORD_FILE: input.passwordFile,
      },
      stdio: ['ignore', output?.fd ?? 'inherit', output?.fd ?? 'inherit'],
    });
    // No argv or environment is logged. The caller may stop its exact child;
    // only this parent's actual exit observation can advance the durable state.
    if (child.pid) process.stderr.write(`OPENPC_PREDECESSOR_PROCESS|pid=${child.pid}\n`);
    const stop = () => child.kill('SIGTERM');
    input.signal?.addEventListener('abort', stop, { once: true });
    if (input.signal?.aborted) stop();
    const result = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    await output?.close();
    input.signal?.removeEventListener('abort', stop);
    if (result.code !== 0 && !['SIGTERM', 'SIGINT'].includes(result.signal)) fail();
    profile.state = 'STOPPED';
    await save(client, marker, profile);
    return { state: 'STOPPED', runId: profile.runId };
  });
}

async function predecessorEndpoint(client, profile, input) {
  const e = profile.enrollment;
  const configured = client.connectionParameters;
  const socket = client.connection.stream;
  if (
    !configured ||
    !isIP(socket.remoteAddress) ||
    !Number.isInteger(socket.remotePort) ||
    input.environment.CONTROL_WORKER_DATABASE_HOST !== configured.host ||
    input.environment.CONTROL_WORKER_DATABASE_PORT !== String(configured.port) ||
    input.environment.CONTROL_WORKER_DATABASE_NAME !== e.databaseName
  )
    fail('endpoint_mismatch');
  // The child receives the authenticated socket's numeric peer, not a second
  // DNS lookup or caller-chosen server. Verify its actual credential first.
  const endpoint = { host: socket.remoteAddress, port: socket.remotePort };
  const password = (await readFile(input.passwordFile, 'utf8')).trim();
  if (!/^[A-Za-z0-9]{32,256}$/u.test(password)) fail();
  const legacy = new Client({
    ...endpoint,
    database: e.databaseName,
    user: e.legacyRole,
    password,
  });
  try {
    await legacy.connect();
    const { rows } = await legacy.query(
      `select s.system_identifier::text cluster,d.oid::integer oid,
      d.datname name,current_user=session_user and session_user=$1 actual
      from pg_control_system() s,pg_database d where d.datname=current_database()`,
      [e.legacyRole],
    );
    if (
      rows.length !== 1 ||
      rows[0].cluster !== e.clusterIdentifier ||
      rows[0].oid !== e.databaseOid ||
      rows[0].name !== e.databaseName ||
      rows[0].actual !== true
    )
      fail();
  } finally {
    await legacy.end();
  }
  return endpoint;
}

/** Reconcile only the original durable capture after a lost completion. A
 * missing/changed artifact remains blocked; this path never resnapshots. */
export async function reconcileRuntimePredecessorCapture(pool, scope, captureFile) {
  return owned(pool, scope, async (client, marker) => {
    const profile = await readProfile(client, marker);
    if (!['CAPTURING', 'CAPTURED'].includes(profile.state)) fail('reconcile_state_rejected');
    if ((await fileDigest(captureFile)) !== profile.captureDigest) fail('reconcile_bytes_mismatch');
    await safeLogin(client, profile.enrollment.legacyRole, false);
    const actual = await identity(client);
    if (actual.connectionLimit !== 0) fail();
    const active = await client.query(
      'select 1 from pg_stat_activity where datid=$1 and pid<>pg_backend_pid()',
      [profile.enrollment.databaseOid],
    );
    if (active.rowCount !== 0) fail();
    profile.state = 'CAPTURED';
    await save(client, marker, profile);
    return { state: 'CAPTURED', captureDigest: profile.captureDigest };
  });
}

export async function readRuntimePredecessor(pool, scope) {
  return owned(pool, scope, async (client, marker) => {
    const profile = await readProfile(client, marker);
    return {
      state: profile.state,
      installationId: profile.enrollment.installationId,
      runId: profile.runId,
      captureDigest: profile.captureDigest,
      priorConsumption: 'UNPROVEN',
    };
  });
}

/** Freeze admission before observing idle sessions. A failed idle check keeps
 * the fence; it never reopens the old writer to manufacture a clean capture. */
export async function quiesceRuntimePredecessor(pool, scope) {
  return owned(pool, scope, async (client, marker) => {
    const profile = await readProfile(client, marker);
    if (!['STOPPED', 'QUIESCING'].includes(profile.state)) fail();
    if (profile.state === 'STOPPED')
      await transaction(client, async () => {
        await safeLogin(client, profile.enrollment.legacyRole, true);
        await statement(client, 'ALTER ROLE %I NOLOGIN', profile.enrollment.legacyRole);
        await statement(
          client,
          'ALTER DATABASE %I CONNECTION LIMIT 0',
          profile.enrollment.databaseName,
        );
        profile.state = 'QUIESCING';
        await save(client, marker, profile);
      });
    await safeLogin(client, profile.enrollment.legacyRole, false);
    if ((await identity(client)).connectionLimit !== 0) fail();
    const active = await client.query(
      'select 1 from pg_stat_activity where datid=$1 and pid<>pg_backend_pid()',
      [profile.enrollment.databaseOid],
    );
    if (active.rowCount !== 0) fail('active_sessions');
    return { state: 'QUIESCING', enrollment: profile.enrollment };
  });
}

/** The existing host backup owner supplies its stopped database backup and
 * native inventory. Exact artifact bytes are bound here; this grants no claim
 * that an arbitrary caller-provided backup is complete or restorable. */
export async function captureRuntimePredecessor(pool, scope, input) {
  return owned(pool, scope, async (client, marker) => {
    const profile = await readProfile(client, marker);
    if (profile.state !== 'QUIESCING' || !profile.runId) fail('capture_state_rejected');
    await safeLogin(client, profile.enrollment.legacyRole, false);
    if ((await identity(client)).connectionLimit !== 0) fail();
    const active = await client.query(
      'select 1 from pg_stat_activity where datid=$1 and pid<>pg_backend_pid()',
      [profile.enrollment.databaseOid],
    );
    if (active.rowCount !== 0) fail();
    if (!Array.isArray(input.nativeFiles) || input.nativeFiles.length > 4096) fail();
    const paths = [...new Set(input.nativeFiles)].sort();
    if (paths.length !== input.nativeFiles.length) fail();
    const nativeFiles = [];
    for (const path of paths)
      nativeFiles.push({ pathDigest: digest(path), digest: await fileDigest(path) });
    const cohort = await client.query(
      `select jsonb_build_object('participantId',p.participant_id::text,
      'privacyDomainId',d.privacy_domain_id::text,'participantEpoch',p.authority_epoch::text,
      'participantState',p.state,'privacyState',d.state) cohort
      from control.participant p join control.privacy_domain d using(participant_id)
      where p.participant_id=$1 and d.privacy_domain_id=$2`,
      [scope.participantId, scope.privacyDomainId],
    );
    if (cohort.rows.length !== 1) fail();
    const capture = {
      version: 1,
      enrollment: profile.enrollment,
      runId: profile.runId,
      cohort: cohort.rows[0].cohort,
      predecessorSchemaDigest: await schemaDigest(client),
      backupDigest: await fileDigest(input.backupFile),
      nativeFiles,
      priorConsumption: 'UNPROVEN',
    };
    const bytes = Buffer.from(canonicalJson(capture));
    if (bytes.length > 1024 * 1024) fail();
    profile.captureDigest = digest(bytes);
    profile.state = 'CAPTURING';
    await save(client, marker, profile);
    const file = await open(
      input.captureFile,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      await file.writeFile(bytes);
      await file.sync();
    } finally {
      await file.close();
    }
    const parent = await open(dirname(input.captureFile), constants.O_RDONLY);
    try {
      await parent.sync();
    } finally {
      await parent.close();
    }
    profile.state = 'CAPTURED';
    await save(client, marker, profile);
    return { captureDigest: profile.captureDigest, priorConsumption: 'UNPROVEN' };
  });
}

/** Supported post-migration compatibility. This does not install a source or
 * grant global LEGACY membership; the existing login receives one scoped pin. */
export async function consumeRuntimePredecessor(pool, scope, captureFile) {
  return owned(pool, scope, async (client, marker) =>
    transaction(client, async () => {
      const profile = await readProfile(client, marker);
      if (profile.state !== 'CAPTURED') fail('consume_state_rejected');
      if ((await fileDigest(captureFile)) !== profile.captureDigest) fail('consume_bytes_mismatch');
      await safeLogin(client, profile.enrollment.legacyRole, false);
      if ((await identity(client)).connectionLimit !== 0) fail();
      const active = await client.query(
        'select 1 from pg_stat_activity where datid=$1 and pid<>pg_backend_pid()',
        [profile.enrollment.databaseOid],
      );
      if (active.rowCount !== 0) fail();
      const installed = await client.query(
        'select 1 from control.runtime_artifact_source where participant_id=$1 and privacy_domain_id=$2',
        [scope.participantId, scope.privacyDomainId],
      );
      if (installed.rowCount !== 0) fail();
      Object.assign(profile, await successorSchema(client));
      profile.state = 'CONSUMED';
      await statement(
        client,
        'GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET FALSE',
        marker,
        profile.enrollment.legacyRole,
      );
      await save(client, marker, profile);
      await statement(client, 'ALTER ROLE %I LOGIN', profile.enrollment.legacyRole);
      await statement(
        client,
        'ALTER DATABASE %I CONNECTION LIMIT %s',
        profile.enrollment.databaseName,
        String(profile.priorConnectionLimit),
      );
      return { state: 'CONSUMED', priorConsumption: 'UNPROVEN', sourceAuthority: 'NONE' };
    }),
  );
}

const hostActions = ['enroll', 'run', 'quiesce', 'capture', 'reconcile', 'consume', 'status'];
const absolute = z
  .string()
  .min(1)
  .max(4096)
  .refine((value) => value.startsWith('/') && resolve(value) === value);
const hostBase = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  database: z.strictObject({
    host: z.enum(['127.0.0.1', '::1']),
    port: z.number().int().min(1).max(65535),
    name: z.string().min(1).max(63),
    user: role,
    passwordFile: absolute,
  }),
});
const hostSchemas = {
  enroll: hostBase.extend({
    repository: absolute,
    installationId: z.uuidv7(),
    legacyRole: role,
    workerPasswordFile: absolute,
    displayName: z.string().min(1).max(160),
    domainName: z.string().min(1).max(160),
    residencyProfile: z.literal('LOCAL_DEVELOPMENT'),
  }),
  run: hostBase.extend({
    executable: absolute,
    passwordFile: absolute,
    environmentFile: absolute,
    runId: z.uuidv7(),
    logFile: absolute,
  }),
  quiesce: hostBase,
  capture: hostBase.extend({
    backupFile: absolute,
    captureFile: absolute,
    nativeFiles: z.array(absolute).max(4096),
  }),
  reconcile: hostBase.extend({ captureFile: absolute }),
  consume: hostBase.extend({ captureFile: absolute }),
  status: hostBase,
};
export function parseRuntimePredecessorHostArguments(args) {
  if (
    args.length !== 4 ||
    args[0] !== '--action' ||
    !hostActions.includes(args[1]) ||
    args[2] !== '--config'
  )
    fail();
  return { action: args[1], config: absolute.parse(args[3]) };
}
async function hostPrivateInput(path, limit) {
  if ((await realpath(path)) !== path) fail();
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat();
    if (
      !before.isFile() ||
      before.uid !== process.getuid() ||
      (before.mode & 0o077) !== 0 ||
      before.size > limit ||
      before.size === 0
    )
      fail();
    const bytes = await file.readFile();
    const after = await file.stat();
    if (
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    )
      fail();
    return bytes;
  } finally {
    await file.close();
  }
}

/** Supported local host caller. The optional pool is the existing integration
 * seam for real-PostgreSQL response-loss tests; the executable always owns its
 * authenticated connection. No supplied state/readiness or version is accepted. */
export async function runRuntimePredecessorHost(args, providedPool) {
  const { action, config } = parseRuntimePredecessorHostArguments(args);
  if (process.env.OPENPC_LOCAL_RUNTIME !== '1') fail();
  const input = hostSchemas[action].parse(
    parseStrictJsonBytes(await hostPrivateInput(config, 65536), { maximumDepth: 8 }),
  );
  const repository = resolve(import.meta.dirname, '../..');
  if (action === 'enroll' && input.repository !== repository) fail();
  await execute(
    'bash',
    [
      join(repository, 'scripts/maintenance/run-bounded.sh'),
      '--profile',
      'database',
      '--memory-gib',
      action === 'enroll' ? '8' : '3',
      '--peak-disk-gib',
      '40',
      '--reuse',
      '--',
      'true',
    ],
    { cwd: repository },
  );
  const password = (await hostPrivateInput(input.database.passwordFile, 8192))
    .toString('utf8')
    .trim();
  if (!password || password.includes('\0')) fail();
  const pool =
    providedPool ??
    new Pool({
      host: input.database.host,
      port: input.database.port,
      database: input.database.name,
      user: input.database.user,
      password,
      max: 1,
      connectionTimeoutMillis: 5000,
    });
  try {
    switch (action) {
      case 'enroll': {
        const artifact = await buildRuntimePredecessor(input.repository);
        const password = (await hostPrivateInput(input.workerPasswordFile, 8192))
          .toString('utf8')
          .trim();
        const enrollment = await enrollRuntimePredecessor(pool, { ...input, artifact, password });
        return {
          state: 'ENROLLED',
          enrollment,
          executable: artifact.executable,
          source: artifact.source,
          priorConsumption: 'UNPROVEN',
        };
      }
      case 'run': {
        const environment = z
          .record(z.string().regex(/^CONTROL_WORKER_[A-Z0-9_]+$/u), z.string().max(4096))
          .parse(
            parseStrictJsonBytes(await hostPrivateInput(input.environmentFile, 65536), {
              maximumDepth: 2,
            }),
          );
        if (Object.keys(environment).some((key) => /(?:PASSWORD|SECRET|TOKEN)$/u.test(key))) fail();
        const stop = new AbortController();
        const abort = () => stop.abort();
        process.once('SIGTERM', abort);
        process.once('SIGINT', abort);
        try {
          return await runRuntimePredecessor(pool, input, {
            ...input,
            arguments: [],
            environment: { ...process.env, ...environment },
            signal: stop.signal,
          });
        } finally {
          process.off('SIGTERM', abort);
          process.off('SIGINT', abort);
        }
      }
      case 'quiesce':
        return await quiesceRuntimePredecessor(pool, input);
      case 'capture':
        return await captureRuntimePredecessor(pool, input, input);
      case 'reconcile':
        return await reconcileRuntimePredecessorCapture(pool, input, input.captureFile);
      case 'consume':
        return await consumeRuntimePredecessor(pool, input, input.captureFile);
      case 'status':
        return await readRuntimePredecessor(pool, input);
      default:
        fail();
    }
  } finally {
    if (!providedPool) await pool.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    process.stdout.write(
      `${JSON.stringify(await runRuntimePredecessorHost(process.argv.slice(2)))}\n`,
    );
  } catch (error) {
    process.stderr.write(`${JSON.stringify(runtimePredecessorHostFailure(error))}\n`);
    process.exitCode = 1;
  }
}
