import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath, type FileHandle } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';

// Shared mechanics only. Each store retains its closed schemas, security profile,
// business assertions and original artifact format.
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, item]) => [key, canonical(item)]),
    );
  return value;
}
export const recoveryBytes = (value: unknown) => Buffer.from(JSON.stringify(canonical(value)));
export const recoveryHash = (value: Buffer) => createHash('sha256').update(value).digest('hex');

export function recoveryPrivateFiles(fail: () => Error) {
  const metadataLimit = 4 * 1024 * 1024;
  async function privateDirectory(directory: string) {
    const stat = await lstat(directory);
    if (
      !isAbsolute(directory) ||
      (await realpath(directory)) !== directory ||
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      stat.uid !== process.getuid?.() ||
      (stat.mode & 0o7777) !== 0o700
    )
      throw fail();
    return stat;
  }
  async function unchangedDirectory(
    directory: string,
    before: Awaited<ReturnType<typeof privateDirectory>>,
  ) {
    const after = await privateDirectory(directory);
    if (before.dev !== after.dev || before.ino !== after.ino) throw fail();
  }
  async function syncDirectory(directory: string) {
    const handle = await open(
      directory,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  }
  async function privateFile(directory: string, name: string, limit: number, write = false) {
    const parent = await privateDirectory(directory);
    const file = join(directory, name);
    const handle = await open(
      file,
      (write ? constants.O_RDWR : constants.O_RDONLY) | constants.O_NOFOLLOW,
    );
    try {
      const stat = await handle.stat();
      const entry = await lstat(file);
      if (
        !stat.isFile() ||
        stat.nlink !== 1 ||
        stat.uid !== process.getuid?.() ||
        (stat.mode & 0o7777) !== 0o600 ||
        stat.size < 1 ||
        stat.size > limit ||
        entry.isSymbolicLink() ||
        entry.dev !== stat.dev ||
        entry.ino !== stat.ino
      )
        throw fail();
      await unchangedDirectory(directory, parent);
      return { handle, stat, parent, file };
    } catch (error) {
      await handle.close();
      throw error;
    }
  }
  async function verifyFileEnd(directory: string, file: Awaited<ReturnType<typeof privateFile>>) {
    const after = await file.handle.stat();
    const entry = await lstat(file.file);
    if (
      after.size !== file.stat.size ||
      after.mtimeMs !== file.stat.mtimeMs ||
      after.ctimeMs !== file.stat.ctimeMs ||
      after.nlink !== 1 ||
      entry.dev !== after.dev ||
      entry.ino !== after.ino
    )
      throw fail();
    await unchangedDirectory(directory, file.parent);
  }
  async function readMetadata(directory: string, name: string) {
    const file = await privateFile(directory, name, metadataLimit);
    try {
      const value = await file.handle.readFile();
      await verifyFileEnd(directory, file);
      return value;
    } finally {
      await file.handle.close();
    }
  }
  function decode<T>(data: Buffer, schema: z.ZodType<T>): T {
    try {
      const value = schema.parse(JSON.parse(data.toString('utf8')));
      // Reject duplicate keys, invalid UTF-8, trailing data and noncanonical edits.
      if (!recoveryBytes(value).equals(data)) throw fail();
      return value;
    } catch {
      throw fail();
    }
  }
  async function writeImmutable(directory: string, name: string, value: unknown) {
    const parent = await privateDirectory(directory);
    const data = recoveryBytes(value);
    if (data.length > metadataLimit) throw fail();
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        join(directory, name),
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      await handle.writeFile(data);
      await handle.sync();
      const stat = await handle.stat();
      const entry = await lstat(join(directory, name));
      if (
        stat.nlink !== 1 ||
        (stat.mode & 0o7777) !== 0o600 ||
        entry.dev !== stat.dev ||
        entry.ino !== stat.ino
      )
        throw fail();
      await unchangedDirectory(directory, parent);
      await syncDirectory(directory);
    } finally {
      await handle?.close();
    }
    // A failed write/fsync is retained, never removed or overwritten for retry.
  }

  async function readBytes(directory: string, name: string, limit: number) {
    const file = await privateFile(directory, name, limit);
    try {
      const value = await file.handle.readFile();
      await verifyFileEnd(directory, file);
      return value;
    } finally {
      await file.handle.close();
    }
  }
  async function writeBytes(directory: string, name: string, data: Buffer, limit: number) {
    const parent = await privateDirectory(directory);
    if (!/^[a-z0-9][a-z0-9.-]*$/u.test(name) || !data.length || data.length > limit) throw fail();
    const handle = await open(
      join(directory, name),
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      await handle.writeFile(data);
      await handle.sync();
      const stat = await handle.stat(),
        entry = await lstat(join(directory, name));
      if (
        stat.nlink !== 1 ||
        stat.uid !== process.getuid?.() ||
        (stat.mode & 0o7777) !== 0o600 ||
        stat.dev !== entry.dev ||
        stat.ino !== entry.ino
      )
        throw fail();
      await unchangedDirectory(directory, parent);
      await syncDirectory(directory);
    } finally {
      await handle.close();
    }
  }
  return {
    privateDirectory,
    privateFile,
    verifyFileEnd,
    syncDirectory,
    readMetadata,
    decode,
    writeImmutable,
    readBytes,
    writeBytes,
  };
}

export async function observeRecovery<T>(
  pool: Pool,
  borrowed: PoolClient | undefined,
  observe: (client: PoolClient) => Promise<T>,
  message = 'UNKNOWN: PostgreSQL recovery observation or cleanup failed',
): Promise<T> {
  if (borrowed) return observe(borrowed);
  const client = await pool.connect();
  let hasFailure = false;
  let primary: unknown;
  let result: T | undefined;
  const remember = (error: unknown) => {
    if (!hasFailure) {
      hasFailure = true;
      primary = error;
    }
  };
  try {
    result = await observe(client);
  } catch (error) {
    remember(error);
  }
  try {
    await client.query('rollback');
  } catch (error) {
    remember(error);
  }
  try {
    client.release(true);
  } catch (error) {
    remember(error);
  }
  if (hasFailure)
    throw new Error(message, {
      cause: primary,
    });
  return result as T;
}

export type RecoverySourceStep =
  | 'prepare'
  | 'rollbackSnapshot'
  | 'releaseSnapshot'
  | 'endSourcePool'
  | 'fenceSource'
  | 'verifySourceFence';
export type RecoverySourceAction = () => unknown | Promise<unknown>;

export async function finishRecoverySourcePhase(
  actions: {
    prepare: RecoverySourceAction;
    rollbackSnapshot?: RecoverySourceAction;
    releaseSnapshot?: RecoverySourceAction;
    endSourcePool?: RecoverySourceAction;
    fenceSource: RecoverySourceAction;
    verifySourceFence: RecoverySourceAction;
  },
  failure: (primary: unknown, steps: RecoverySourceStep[]) => Error,
) {
  let hasFailure = false;
  let primary: unknown;
  const failedSteps: RecoverySourceStep[] = [];
  for (const step of [
    'prepare',
    'rollbackSnapshot',
    'releaseSnapshot',
    'fenceSource',
    // Fence before pool shutdown: a rejected or unresolved shutdown must not
    // leave privileged source admission open. Readback still follows shutdown.
    'endSourcePool',
    'verifySourceFence',
  ] as const) {
    try {
      await actions[step]?.();
    } catch (error) {
      if (!hasFailure) {
        hasFailure = true;
        primary = error;
      }
      failedSteps.push(step);
    }
  }
  if (hasFailure) throw failure(primary, failedSteps);
}

export const recoveryQuote = (value: string) => `"${value.replaceAll('"', '""')}"`;

export const recoveryAcl = (
  expression: string,
  defaultAcl?: string,
) => `(select jsonb_agg(jsonb_build_array(
  pg_get_userbyid(a.grantor),case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,
  a.privilege_type,a.is_grantable) order by pg_get_userbyid(a.grantor),
  case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,a.privilege_type,a.is_grantable)
  from aclexplode(${defaultAcl ? `coalesce(${expression},${defaultAcl})` : expression}) a)`;

export async function readRecoverySecurity(
  client: PoolClient,
  schema: 'candidate' | 'facts',
  roleState: unknown,
) {
  const relations = (
    await client.query(
      `select n.nspname schema,c.relname name,c.relkind,pg_get_userbyid(c.relowner) owner,
       c.relrowsecurity rls,c.relforcerowsecurity forced,c.reloptions,${recoveryAcl('c.relacl', "acldefault(case when c.relkind='S' then 's'::\"char\" else 'r'::\"char\" end,c.relowner)")} grants,
       case when c.relkind='v' then pg_get_viewdef(c.oid,false) end view_definition,
       (select jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,
         a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid),${recoveryAcl('a.attacl')}) order by a.attnum)
        from pg_attribute a left join pg_attrdef d on d.adrelid=a.attrelid and d.adnum=a.attnum
        where a.attrelid=c.oid and a.attnum>0 and not a.attisdropped) columns
       from pg_class c join pg_namespace n on n.oid=c.relnamespace
       where n.nspname in ('${schema}','openpc','openpc_local') and c.relkind in ('r','p','v','S')
       order by schema,name`,
    )
  ).rows;
  const policies = (
    await client.query(
      `select n.nspname schema,c.relname relation,p.polname name,p.polcmd,p.polpermissive,
       (select jsonb_agg(name order by name) from
         (select case when r=0 then 'PUBLIC' else pg_get_userbyid(r) end name from unnest(p.polroles) r) roles) roles,
       pg_get_expr(p.polqual,p.polrelid) "using",pg_get_expr(p.polwithcheck,p.polrelid) "check"
       from pg_policy p join pg_class c on c.oid=p.polrelid join pg_namespace n on n.oid=c.relnamespace
       where n.nspname in ('${schema}','openpc') order by schema,relation,name`,
    )
  ).rows;
  const functions = (
    await client.query(
      `select n.nspname schema,p.proname name,pg_get_function_identity_arguments(p.oid) arguments,
       pg_get_userbyid(p.proowner) owner,p.prosecdef definer,p.proconfig configuration,
       pg_get_functiondef(p.oid) definition,${recoveryAcl('p.proacl', "acldefault('f',p.proowner)")} grants
       from pg_proc p join pg_namespace n on n.oid=p.pronamespace
       where n.nspname in ('${schema}','openpc') and p.prokind in ('f','p') order by schema,name,arguments`,
    )
  ).rows;
  const triggers = (
    await client.query(
      `select n.nspname schema,c.relname relation,t.tgname name,t.tgenabled enabled,
       pg_get_triggerdef(t.oid,false) definition from pg_trigger t join pg_class c on c.oid=t.tgrelid
       join pg_namespace n on n.oid=c.relnamespace where n.nspname in ('${schema}','openpc')
       and not t.tgisinternal order by schema,relation,name`,
    )
  ).rows;
  const constraints = (
    await client.query<{
      schema: string;
      relation: string;
      name: string;
      type: string;
      definition: string;
    }>(
      `select n.nspname schema,c.relname relation,x.conname name,x.contype type,x.convalidated,x.conenforced,
       x.condeferrable,x.condeferred,pg_get_constraintdef(x.oid) definition
       from pg_constraint x join pg_class c on c.oid=x.conrelid join pg_namespace n on n.oid=c.relnamespace
       where n.nspname in ('${schema}','openpc','openpc_local') order by schema,relation,name`,
    )
  ).rows;
  // pg_dump re-parses CHECK expressions and can add implicit casts. Parse both
  // sides once through the same real PG grammar; never erase predicates.
  let index = 0;
  for (const row of constraints.filter((row) => row.type === 'c')) {
    const temp = `recovery_constraint_${index++}`;
    await client.query(
      `create temporary table ${recoveryQuote(temp)} (like ${recoveryQuote(row.schema)}.${recoveryQuote(row.relation)}) on commit drop`,
    );
    await client.query(
      `alter table ${recoveryQuote(temp)} add constraint checked ${row.definition}`,
    );
    row.definition = (
      await client.query(
        `select pg_get_constraintdef(oid) definition from pg_constraint where conrelid=$1::regclass and conname='checked'`,
        [temp],
      )
    ).rows[0].definition;
  }
  const schemas = (
    await client.query(
      `select nspname,pg_get_userbyid(nspowner) owner,${recoveryAcl('nspacl', "acldefault('n',nspowner)")} grants from pg_namespace
       where nspname in ('${schema}','openpc','openpc_local','public') order by nspname`,
    )
  ).rows;
  const defaults = (
    await client.query(
      `select pg_get_userbyid(d.defaclrole) role,n.nspname schema,d.defaclobjtype type,${recoveryAcl('d.defaclacl')} grants
       from pg_default_acl d left join pg_namespace n on n.oid=d.defaclnamespace order by role,schema,type`,
    )
  ).rows;
  const databases = (
    await client.query(
      `select datname,pg_get_userbyid(datdba) owner,encoding,datlocprovider,datcollate,datctype,
       datlocale,datcollversion,datconnlimit,${recoveryAcl('datacl', "acldefault('d',datdba)")} grants
       from pg_database where datname=current_database()`,
    )
  ).rows;
  const settings = (
    await client.query(
      `select case when s.setrole=0 then 'ALL' else pg_get_userbyid(s.setrole) end role,s.setconfig
       from pg_db_role_setting s join pg_database d on d.oid=s.setdatabase
       where d.datname=current_database() order by role`,
    )
  ).rows;
  return {
    relations,
    policies,
    functions,
    triggers,
    constraints,
    schemas,
    defaults,
    roles: roleState,
    databases,
    settings,
  };
}

export function recoveryTargetPort(
  input: {
    source: { port: number };
    target: { containerId: string; dataDirectory: string };
    control: { port: number };
  },
  root: string,
  imageId: string,
  inspection: unknown,
  image: string,
  targetRole: 'candidate-target' | 'fact-target',
  fail: () => Error,
) {
  const info = z
    .object({
      Id: z.literal(input.target.containerId),
      Image: z.literal(imageId),
      State: z.object({ Running: z.boolean(), OOMKilled: z.literal(false) }),
      Config: z.object({
        Image: z.literal(image),
        Labels: z.record(z.string(), z.string()),
      }),
      HostConfig: z.object({
        Privileged: z.literal(false),
        NetworkMode: z.string().refine((v) => v !== 'host'),
        Memory: z.literal(1073741824),
        MemorySwap: z.literal(1073741824),
        NanoCpus: z.literal(750_000_000),
        PidsLimit: z.number().int().positive().max(256),
        SecurityOpt: z.array(z.string()).refine((v) => v.includes('no-new-privileges:true')),
      }),
      Mounts: z.array(
        z.object({
          Destination: z.string(),
          Source: z.string(),
          Type: z.string(),
          RW: z.boolean(),
        }),
      ),
      NetworkSettings: z.object({
        Ports: z.record(
          z.string(),
          z.array(z.object({ HostIp: z.string(), HostPort: z.string() })).nullable(),
        ),
      }),
    })
    .parse(inspection);
  if (
    info.Config.Labels['io.openpc.test-owner'] !== root ||
    info.Config.Labels['io.openpc.recovery-role'] !== targetRole
  )
    throw fail();
  const mounts = info.Mounts.filter((m) => m.Destination === '/var/lib/postgresql');
  if (
    mounts.length !== 1 ||
    mounts[0]!.Type !== 'bind' ||
    !mounts[0]!.RW ||
    mounts[0]!.Source !== input.target.dataDirectory
  )
    throw fail();
  if (!info.State.Running) return undefined;
  const ports = info.NetworkSettings.Ports['5432/tcp'];
  if (ports?.length !== 1 || ports[0]!.HostIp !== '127.0.0.1') throw fail();
  const port = z.number().int().min(1024).max(65535).parse(Number(ports[0]!.HostPort));
  if (String(port) !== ports[0]!.HostPort || [input.source.port, input.control.port].includes(port))
    throw fail();
  return port;
}
