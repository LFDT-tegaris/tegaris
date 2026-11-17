import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import {
  readFile,
  writeFile,
  mkdir,
  open,
  copyFile,
  chmod,
  lstat,
  realpath,
} from 'node:fs/promises';
import { constants } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { isSourceStartupRejection } from './runtime-source-import-journey.mjs';
import { installInitialAuthenticatorTrust } from './deployment-intent-actors.mjs';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { canonicalJson } from '../../../services/control-api/src/configuration/digest.ts';

const execute = promisify(execFile);
const sha = (value) => createHash('sha256').update(value).digest();

export async function predecessorCheckpoint(root, name, value) {
  assert.match(name, /^[a-z0-9-]+\.json$/u);
  const directory = join(root, 'evidence/runtime-bootstrap');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const bytes = JSON.stringify(value);
  const path = join(directory, name);
  try {
    const prior = await readFile(path, 'utf8');
    assert.deepEqual(JSON.parse(prior), value, 'Original checkpoint cannot be replaced');
    return;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const file = await open(path, 'wx', 0o600);
  try {
    await file.writeFile(bytes);
    await file.sync();
  } finally {
    await file.close();
  }
  const parent = await open(directory, 'r');
  try {
    await parent.sync();
  } finally {
    await parent.close();
  }
}

async function digestCurrentInput(path, executable = false) {
  assert.equal(await realpath(path), path);
  const meta = await lstat(path);
  assert(meta.isFile());
  if (executable) assert((meta.mode & 0o022) === 0);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat();
    assert.equal(before.ino, meta.ino);
    assert.equal(before.dev, meta.dev);
    if (executable) {
      const magic = Buffer.alloc(4);
      await file.read(magic, 0, 4, 0);
      assert(magic.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])));
      assert((before.mode & 0o111) !== 0);
    }
    const hash = createHash('sha256');
    for await (const chunk of file.createReadStream({ start: 0, autoClose: false }))
      hash.update(chunk);
    const after = await file.stat();
    assert.equal(after.size, before.size);
    assert.equal(after.mtimeMs, before.mtimeMs);
    assert.equal(after.ctimeMs, before.ctimeMs);
    return hash.digest('hex');
  } finally {
    await file.close();
  }
}

export async function verifyRetainedCurrentWorker(root, record, binding) {
  assert.equal(record.binding, binding);
  assert.equal(record.producer, 'cargo-build-locked-offline-local-runtime-worker');
  assert.match(record.name, /^current-worker-[0-9a-f-]{36}$/u);
  const executable = join(root, record.name);
  assert.equal(await digestCurrentInput(executable, true), record.executableDigest);
  for (const [path, digest] of record.compilerInputs) {
    assert.equal(
      await digestCurrentInput(path),
      digest,
      'Compiler input changed; refresh required',
    );
  }
  return executable;
}

// Freeze the result of the actual admitted build before another producer can
// replace Cargo's shared output. Existing checkpoints and binaries are immutable.
export async function currentRuntimeArtifact(repository, root, refresh) {
  const cargoArgs = [
    'build',
    '-p',
    'openpc-fleet-controller',
    '--bin',
    'local_runtime_worker',
    '--locked',
    '--offline',
  ];
  const sourceBinding = async () => {
    const { stdout } = await execute(
      'git',
      ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
      { cwd: repository },
    );
    const paths = [
      ...new Set(
        stdout
          .split('\0')
          .filter(
            (path) =>
              path &&
              (/\.(?:rs|proto)$/u.test(path) ||
                /(?:^|\/)Cargo\.(?:toml|lock)$/u.test(path) ||
                path.startsWith('.cargo/') ||
                path.startsWith('rust-toolchain')),
          ),
      ),
    ].sort();
    const hash = createHash('sha256');
    for (const path of paths) {
      hash.update(JSON.stringify([path, await digestCurrentInput(join(repository, path))]));
    }
    for (const program of ['cargo', 'rustc']) {
      hash.update((await execute(program, ['--version', '--verbose'], { cwd: repository })).stdout);
    }
    // Bind compilation settings without persisting environment values/secrets.
    hash.update(
      JSON.stringify(
        Object.entries(process.env)
          .filter(([key]) =>
            /^(?:RUST|CARGO_(?:BUILD|PROFILE|TARGET|ENCODED_RUSTFLAGS))/u.test(key),
          )
          .sort(),
      ),
    );
    return hash.digest('hex');
  };
  const binding = await sourceBinding();
  const checkpoint = `predecessor-current-build-${binding}.json`;
  let prior;
  try {
    prior = JSON.parse(
      await readFile(join(root, 'evidence/runtime-bootstrap', checkpoint), 'utf8'),
    );
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    assert(refresh, 'No compatible retained current build; explicit refresh required');
  }
  if (prior) return await verifyRetainedCurrentWorker(root, prior, binding);
  await execute('cargo', cargoArgs, { cwd: repository, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(await sourceBinding(), binding, 'Source changed during build');
  const target = process.env.CARGO_TARGET_DIR ?? join(repository, 'target');
  const built = join(target, 'debug/local_runtime_worker');
  const depfile = await readFile(`${built}.d`, 'utf8');
  const line = depfile.split('\n')[0];
  assert(line.startsWith(`${built}: `));
  const inputs = [
    ...new Set(
      await Promise.all(
        line
          .slice(built.length + 2)
          .split(/(?<!\\) /u)
          .filter(Boolean)
          .map((path) => realpath(resolve(repository, path.replace(/\\ /gu, ' ')))),
      ),
    ),
  ].sort();
  const compilerInputs = [];
  for (const path of inputs) compilerInputs.push([path, await digestCurrentInput(path)]);
  const name = `current-worker-${id()}`;
  const copied = join(root, name);
  const executableDigest = await digestCurrentInput(built);
  await copyFile(built, copied, constants.COPYFILE_EXCL);
  await chmod(copied, 0o500);
  const file = await open(copied, 'r');
  try {
    await file.sync();
  } finally {
    await file.close();
  }
  assert.equal(await digestCurrentInput(copied, true), executableDigest);
  const directory = await open(root, 'r');
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
  const record = {
    producer: 'cargo-build-locked-offline-local-runtime-worker',
    binding,
    name,
    executableDigest,
    compilerInputs,
    cargoArgs,
  };
  await predecessorCheckpoint(root, checkpoint, record);
  return await verifyRetainedCurrentWorker(root, record, binding);
}

// Exercise the real migration adapter in rollback-only transactions before
// admitting a restored database. Poisoned CHECKs never persist in the fixture.
export async function testRestoredControlChecks(repository, root, container, pool, command) {
  const source = await readFile(join(repository, 'deploy/compose/local/migrate.sh'), 'utf8');
  const boundary = source.indexOf('\ncase "$mode" in\n');
  assert(boundary > 0);
  const name = `restore-check-emitter-${id()}.sh`;
  await writeFile(join(root, name), source.slice(0, boundary) + '\nemit_control_check_restore\n', {
    mode: 0o600,
    flag: 'wx',
  });
  const adapter = await command('docker', [
    'exec',
    '-e',
    'PGHOST=127.0.0.1',
    '-e',
    'PGUSER=openpc_control',
    '-e',
    'PGDATABASE=openpc_control',
    container,
    'sh',
    `/capture/${name}`,
    'control-schema',
  ]);
  const start = adapter.indexOf(' FROM STDIN;\n') + ' FROM STDIN;\n'.length;
  assert(start > 20);
  const rows = adapter
    .slice(start, adapter.indexOf('\n\\.\n', start))
    .split('\n')
    .map((line) => line.split('\t'));
  assert.equal(rows.length, 8);
  assert(rows.every((row) => row.length === 6));
  const declarations = new Map(rows.map((row) => [row[1], row]));
  const replaceCheck = (name, transform, suffix = '') => {
    const [table, , declaration] = declarations.get(name);
    return `ALTER TABLE control.${table} DROP CONSTRAINT ${name}; ALTER TABLE control.${table} ADD CONSTRAINT ${name} CHECK ${transform(declaration)} ${suffix};`;
  };
  const metadata = async () =>
    (
      await pool.query(
        `select c.oid::text, c.conname, pg_get_expr(c.conbin,c.conrelid) expression, c.convalidated, c.conenforced, r.relowner::text from pg_constraint c join pg_class r on r.oid=c.conrelid where c.conname=any($1::text[]) order by c.conname`,
        [rows.map((row) => row[1])],
      )
    ).rows;
  const before = await metadata();
  const cases = [
    [
      'bound',
      replaceCheck('completion_attempt_bytes_ck', (value) =>
        value.replace('between 1 and 4096', 'between 0 and 4096'),
      ),
      'EXPRESSION',
    ],
    [
      'digest',
      replaceCheck('completion_source_bytes_ck', (value) =>
        value.replace("'sha256:'", "'sha512:'"),
      ),
      'EXPRESSION',
    ],
    [
      'operator',
      replaceCheck('completion_attempt_bytes_ck', (value) =>
        value.replace(' and "control"', ' or "control"'),
      ),
      'EXPRESSION',
    ],
    [
      'or',
      replaceCheck('notification_cursor_position_ck', (value) => value.replace(' or ', ' and ')),
      'EXPRESSION',
    ],
    [
      'missing',
      'ALTER TABLE control.notification_completion_source DROP CONSTRAINT completion_source_bytes_ck;',
      'IDENTITY',
    ],
    [
      'not-valid',
      replaceCheck('completion_source_bytes_ck', (value) => value, 'NOT VALID'),
      'IDENTITY',
    ],
    [
      'owner',
      'ALTER TABLE control.notification_completion_source OWNER TO openpc_control;',
      'TABLE',
    ],
    [
      'column',
      'ALTER TABLE control.notification_completion_attempt ALTER COLUMN attempt_digest TYPE varchar(80);',
      'COLUMN',
    ],
    [
      'source',
      "UPDATE openpc_local.migration SET sha256=repeat('0',64) WHERE path='/migrations/postgres/control-api/0123_curved_firelord.sql';",
      'SOURCE',
    ],
    ['null', replaceCheck('completion_attempt_bytes_ck', () => '(NULL::boolean)'), 'EXPRESSION'],
    [
      'reordered',
      replaceCheck(
        'completion_attempt_bytes_ck',
        () =>
          "(attempt_digest='sha256:'||encode(sha256(attempt_bytes),'hex') and octet_length(attempt_bytes) between 1 and 4096)",
      ),
      'EXPRESSION',
    ],
    [
      'not-enforced',
      replaceCheck('completion_source_bytes_ck', (value) => value, 'NOT ENFORCED'),
      'IDENTITY',
    ],
    [
      'collation',
      'ALTER TABLE control.notification_completion_attempt ALTER COLUMN attempt_digest TYPE text COLLATE "C";',
      'COLUMN',
    ],
    [
      'repeated-restore',
      `DO $$ DECLARE c record; BEGIN FOR c IN SELECT conname,conrelid::regclass relation,pg_get_expr(conbin,conrelid) expression FROM pg_constraint WHERE conname=ANY(ARRAY[${rows.map((row) => "'" + row[1] + "'").join(',')}]) ORDER BY conname LOOP EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.relation,c.conname); EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I CHECK ',c.relation,c.conname)||c.expression; END LOOP; END $$;`,
      'TEST-INTERRUPTION',
    ],
    ['interruption', '', 'TEST-INTERRUPTION'],
  ];
  for (const [label, poison, reason] of cases) {
    const sql = `${poison}\n${adapter}\nSELECT openpc.assert_notification_completion_disposition_shared_owner();\nDO $$ BEGIN RAISE EXCEPTION 'CONTROL-RESTORE-CHECK-TEST-INTERRUPTION'; END $$;`;
    const input = `restore-check-${label}-${id()}.sql`;
    await writeFile(join(root, input), sql, { mode: 0o600, flag: 'wx' });
    await assert.rejects(
      command('docker', [
        'exec',
        container,
        'psql',
        '-X',
        '-q',
        '-v',
        'ON_ERROR_STOP=1',
        '--single-transaction',
        '-U',
        'openpc_control',
        '-d',
        'openpc_control',
        '-f',
        `/capture/${input}`,
      ]),
      (error) =>
        error.code === 3 && error.stderr.includes(`ERROR:  CONTROL-RESTORE-CHECK-${reason}`),
      label,
    );
    assert.deepEqual(
      await metadata(),
      before,
      `Failed ${label} transaction must preserve original constraints`,
    );
    process.stdout.write(`OPENPC_PREDECESSOR_CHECK_RESTORE|PASS|${label}|atomic-original\n`);
  }
}

async function initialAuthenticator(admin, root, participantId, principalId) {
  const path = join(root, 'evidence/runtime-bootstrap/predecessor-authenticator.json');
  let device;
  try {
    device = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const privateKeyPath = join(root, 'secrets/predecessor-authenticator.pk8');
    const file = await open(privateKeyPath, 'wx', 0o400);
    try {
      await file.writeFile(pair.privateKey.export({ format: 'der', type: 'pkcs8' }));
      await file.sync();
    } finally {
      await file.close();
    }
    device = {
      participantId,
      principalId,
      credentialId: id(),
      privateKeyPath,
      establishedAt: new Date().toISOString(),
    };
    await predecessorCheckpoint(root, 'predecessor-authenticator.json', device);
  }
  assert.equal(device.participantId, participantId);
  assert.equal(device.principalId, principalId);
  assert.equal(device.privateKeyPath, join(root, 'secrets/predecessor-authenticator.pk8'));
  const privateKey = createPrivateKey({
    key: await readFile(device.privateKeyPath),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const client = await admin.connect();
  try {
    await installInitialAuthenticatorTrust(client, { ...device, publicKey });
  } finally {
    client.release();
  }
  return { ...device, privateKey };
}

async function assertOriginalSession(admin, root, origin, initial, scope, headers) {
  const device = await initialAuthenticator(admin, root, scope.participantId, initial.principalId);
  const intent = 'ACT-IDENTITY_CREATE_SESSION-V1';
  const csrfResponse = await fetch(`${origin}/api/v1/session/csrf`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ actionIntentId: intent }),
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(csrfResponse.status, 200);
  const csrf = (await csrfResponse.json()).csrfToken;
  const binding = {
    actionIntentId: intent,
    resourceId: scope.privacyDomainId,
    resourceDigest: `sha256:${sha(canonicalJson(scope)).toString('hex')}`,
    rpIdHash: `sha256:${sha(new URL(origin).hostname).toString('hex')}`,
  };
  const challengeResponse = await fetch(`${origin}/v1/identity/webauthn/assertion/challenge`, {
    method: 'POST',
    headers: { ...headers, 'x-csrf-token': csrf },
    body: JSON.stringify(binding),
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(challengeResponse.status, 200);
  const challenge = await challengeResponse.json();
  assert(challenge.credentialIds.includes(device.credentialId));
  const row = (
    await admin.query(
      'select s.row_version::text, c.authenticator_sign_count from control.session s join control.credential c on c.participant_id=s.participant_id and c.principal_id=s.principal_id where s.session_id=$1 and c.credential_id=$2',
      [initial.sessionId, device.credentialId],
    )
  ).rows[0];
  const clientData = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge: challenge.challenge, origin }),
  );
  const authData = Buffer.alloc(37);
  sha(new URL(origin).hostname).copy(authData);
  authData[32] = 5;
  authData.writeUInt32BE(Number(row.authenticator_sign_count) + 1, 33);
  const signature = sign('sha256', Buffer.concat([authData, sha(clientData)]), device.privateKey);
  const action = (
    await admin.query(
      "select 'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent where action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'",
    )
  ).rows[0].digest;
  const response = await fetch(`${origin}/v1/identity/webauthn/assertion/verify`, {
    method: 'POST',
    headers: {
      ...headers,
      'x-csrf-token': csrf,
      'Idempotency-Key': `predecessor-step-up-${id()}`,
      'X-OpenPC-Aggregate-Version': row.row_version,
      'OpenPC-Action-Intent-Digest': action,
    },
    body: JSON.stringify({
      ...binding,
      challenge: challenge.challenge,
      assertion: JSON.stringify({
        credentialId: device.credentialId,
        authenticatorData: authData.toString('base64url'),
        clientDataJson: clientData.toString('base64url'),
        signature: signature.toString('base64url'),
      }),
    }),
    signal: AbortSignal.timeout(5000),
  });
  const outcome = await response.json();
  await predecessorCheckpoint(root, `predecessor-assertion-${id()}.json`, {
    status: response.status,
    body: outcome,
  });
  assert.equal(response.status, 200);
}

/** All product imports come from the actual archived tree. Only locked external
 * dependencies resolve from the canonical installation. No old file is edited. */
export async function preparePredecessorHttp(source, repository, root) {
  const { build } = createRequire(join(repository, 'services/identity-service/package.json'))(
    'esbuild',
  );
  const outfile = join(root, 'predecessor-identity.mjs');
  await build({
    entryPoints: [join(source, 'services/identity-service/src/local-runtime.ts')],
    outfile,
    bundle: true,
    platform: 'node',
    format: 'esm',
    nodePaths: [
      join(repository, 'services/identity-service/node_modules'),
      join(repository, 'packages/security-kernel/node_modules'),
      join(repository, 'node_modules'),
    ],
    banner: {
      js: 'import { createRequire } from "node:module"; const require = createRequire(import.meta.url);',
    },
    alias: { '@openpc/security-kernel': join(source, 'packages/security-kernel/src/index.ts') },
    logLevel: 'silent',
  });
  return import(pathToFileURL(outfile).href);
}

export async function prepareWorkerTls(root, environment, resume = false) {
  const key = join(root, 'runtime-tls.key'),
    cert = join(root, 'runtime-tls.crt');
  if (!resume)
    await execute('openssl', [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      key,
      '-out',
      cert,
      '-days',
      '2',
      '-subj',
      '/CN=OpenPC predecessor acceptance',
      '-addext',
      'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ]);
  Object.assign(environment, {
    CONTROL_WORKER_ADS_LISTEN: '127.0.0.1:0',
    CONTROL_WORKER_ADS_SERVER_CERT_FILE: cert,
    CONTROL_WORKER_ADS_SERVER_KEY_FILE: key,
    CONTROL_WORKER_ADS_CLIENT_CA_FILE: cert,
    CONTROL_WORKER_TARGET_CLIENT_CERT_FILE: join(root, 'no-target-enrolled.pem'),
    CONTROL_WORKER_PROTECTED_BIND: '127.0.0.1',
    CONTROL_WORKER_PROTECTED_PORT: '10443',
    CONTROL_WORKER_PDS_SOCKET: join(root, 'pds.sock'),
    CONTROL_WORKER_BROKER_SOCKET: join(root, 'broker.sock'),
    CONTROL_WORKER_PROTECTED_CERT_FILE: cert,
    CONTROL_WORKER_PROTECTED_KEY_FILE: key,
    CONTROL_WORKER_WORKLOAD_CA_FILE: cert,
    CONTROL_WORKER_SIGNING_PROVIDER_URL: 'https://127.0.0.1:1/',
    CONTROL_WORKER_SIGNING_PROVIDER_CA_FILE: cert,
    CONTROL_WORKER_SIGNING_PROVIDER_CERT_FILE: cert,
    CONTROL_WORKER_SIGNING_PROVIDER_KEY_FILE: key,
    CONTROL_WORKER_SIGNING_CREDENTIAL_ID: '018f0000-0000-7000-8000-000000000901',
  });
  return { cert, key };
}

export async function waitForWorkerIdle(logFile, stopped) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const output = await readFile(logFile, 'utf8').catch((error) => {
      if (error.code !== 'ENOENT') throw error;
      return '';
    });
    const events = output.split('\n').flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
    assert(
      !events.some((event) => event.level === 'error' || event.event === 'control_worker_stopped'),
    );
    if (events.some((event) => event.event === 'control_worker_idle_poll')) return;
    assert(!stopped(), 'Worker exited before completing its normal loop');
    await delay(100);
  }
  throw new Error('PREDECESSOR_NORMAL_STARTUP_TIMEOUT');
}

export async function currentWorkerStartup(binary, environment, logFile) {
  const child = spawn(binary, [], { env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '',
    stopped = false;
  for (const stream of [child.stdout, child.stderr])
    stream.on('data', (chunk) => {
      output += chunk;
    });
  const completion = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => {
      stopped = true;
      resolve({ code, signal });
    });
  });
  try {
    const deadline = Date.now() + 30000;
    while (!output.includes('"event":"control_worker_idle_poll"')) {
      assert(!stopped && Date.now() < deadline, 'Current worker failed normal startup');
      await delay(100);
    }
    assert(!output.includes('"level":"error"'));
  } finally {
    if (!stopped) child.kill('SIGTERM');
    const result = await completion;
    await writeFile(logFile, output, { mode: 0o600, flag: 'wx' });
    assert.equal(result.signal, 'SIGTERM');
  }
}

export async function rejectPredecessorStartup(binary, environment, reason) {
  await assert.rejects(
    execute(binary, ['fact-admission-once'], { env: environment, timeout: 30000, maxBuffer: 8192 }),
    (error) => isSourceStartupRejection(error, { stage: 'installation', reason }),
  );
}

export async function currentBusinessReadback(business, scope) {
  const current = await import('../../../services/identity-service/src/local-runtime.ts');
  const service = await current.buildLocalIdentityRuntime(business.config);
  try {
    const origin = await service.app.listen({ host: '127.0.0.1', port: 0 });
    const response = await fetch(`${origin}/api/v1/session`, {
      headers: { cookie: `__Host-openpc_session=${business.sessionToken}` },
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, 200);
    const observed = await response.json();
    for (const [field, value] of Object.entries({
      ...scope,
      sessionId: business.sessionId,
      principalId: business.principalId,
      contextMode: 'PARTICIPANT',
    }))
      assert.equal(observed[field], value);
    return observed;
  } finally {
    await service.app.close();
    await service.pool.end();
  }
}

/** Real old HTTP session issuance followed by public context selection. Initial
 * trust is supplied by the old installer; the durable transition is not seeded. */
export async function predecessorBusiness(
  old,
  root,
  environment,
  tls,
  scope,
  credential,
  admin,
  resume = false,
) {
  const signing = generateKeyPairSync('ed25519');
  const privateFile = join(root, 'identity-private.der'),
    publicFile = join(root, 'identity-public.der');
  if (!resume)
    await writeFile(privateFile, signing.privateKey.export({ type: 'pkcs8', format: 'der' }), {
      mode: 0o600,
      flag: 'wx',
    });
  if (!resume)
    await writeFile(publicFile, signing.publicKey.export({ type: 'spki', format: 'der' }), {
      mode: 0o600,
      flag: 'wx',
    });
  const secretFile = environment.CONTROL_WORKER_DATABASE_PASSWORD_FILE;
  const config = await old.readLocalIdentityRuntimeConfig({
    OPENPC_LOCAL_RUNTIME: '1',
    IDENTITY_DATABASE_HOST: environment.CONTROL_WORKER_DATABASE_HOST,
    IDENTITY_DATABASE_PORT: environment.CONTROL_WORKER_DATABASE_PORT,
    IDENTITY_DATABASE_NAME: environment.CONTROL_WORKER_DATABASE_NAME,
    IDENTITY_DATABASE_USER: 'openpc_identity_runtime',
    IDENTITY_DATABASE_PASSWORD_FILE: secretFile,
    IDENTITY_INTERNAL_TOKEN_FILE: secretFile,
    IDENTITY_LOCAL_OPERATOR_CREDENTIAL_FILE: secretFile,
    IDENTITY_LOCAL_VIEWER_CREDENTIAL_FILE: secretFile,
    IDENTITY_RUNTIME_SIGNING_PRIVATE_KEY_FILE: privateFile,
    IDENTITY_RUNTIME_SIGNING_PUBLIC_KEY_FILE: publicFile,
    IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES: publicFile,
    IDENTITY_LOCAL_OPERATOR_PRINCIPAL_ID: '018f0000-0000-7000-8000-000000000111',
    IDENTITY_LOCAL_VIEWER_PRINCIPAL_ID: '018f0000-0000-7000-8000-000000000112',
    IDENTITY_LOCAL_PARTICIPANT_ID: scope.participantId,
    IDENTITY_LOCAL_PRIVACY_DOMAIN_ID: scope.privacyDomainId,
    IDENTITY_OIDC_ISSUER: 'http://127.0.0.1:1',
    IDENTITY_OIDC_CLIENT_ID: 'predecessor',
    IDENTITY_OIDC_REDIRECT_URI: 'http://127.0.0.1:1/callback',
    IDENTITY_MTLS_CA_FILE: tls.cert,
    IDENTITY_WORKLOAD_ISSUER_URL: 'http://127.0.0.1:1',
    IDENTITY_WORKLOAD_ISSUER_TOKEN_FILE: secretFile,
    IDENTITY_MTLS_SERVER_CERT_FILE: tls.cert,
    IDENTITY_MTLS_SERVER_KEY_FILE: tls.key,
    IDENTITY_MTLS_LISTEN: '127.0.0.1:1',
    IDENTITY_LISTEN: '127.0.0.1:1',
  });
  if (resume) {
    let response;
    try {
      response = JSON.parse(
        await readFile(
          join(root, 'evidence/runtime-bootstrap/predecessor-context-response.json'),
          'utf8',
        ),
      );
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (response) {
      assert.equal(response.status, 201, 'A retained denied response needs classification');
      const initial = JSON.parse(
        await readFile(
          join(root, 'evidence/runtime-bootstrap/predecessor-original-session.json'),
          'utf8',
        ),
      );
      const result = response.body;
      assert.equal(result.participantId, scope.participantId);
      assert.equal(result.privacyDomainId, scope.privacyDomainId);
      assert.equal(result.principalId, initial.principalId);
      assert.notEqual(result.sessionId, initial.sessionId);
      return {
        config,
        initialSessionId: initial.sessionId,
        principalId: initial.principalId,
        sessionId: result.sessionId,
        sessionToken: result.sessionToken,
      };
    }
  }
  const service = await old.buildLocalIdentityRuntime(config);
  try {
    const origin = await service.app.listen({ host: '127.0.0.1', port: 0 });
    let initial;
    if (resume) {
      const original = await admin.query(
        "select session_id,participant_id,principal_id from control.session where participant_id=$1 and principal_id='018f0000-0000-7000-8000-000000000111' and state='ACTIVE'",
        [scope.participantId],
      );
      assert.equal(original.rowCount, 1);
      assert.equal(
        (
          await admin.query(
            "select count(*)::integer n from control.outbox_event where event_type='openpc.identity.session.context-selected.v1'",
          )
        ).rows[0].n,
        0,
      );
      const row = original.rows[0];
      initial = {
        sessionId: row.session_id,
        participantId: row.participant_id,
        principalId: row.principal_id,
        sessionToken: `${row.participant_id}.${row.session_id}`,
        origin: 'original-authoritative-readback',
      };
    } else {
      const login = await fetch(`${origin}/internal/v1/local/session/login`, {
        method: 'POST',
        headers: { 'authorization': `Bearer ${credential}`, 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'operator', credential }),
        signal: AbortSignal.timeout(5000),
      });
      assert.equal(login.status, 201);
      initial = await login.json();
    }
    await predecessorCheckpoint(root, 'predecessor-original-session.json', initial);
    const headers = {
      'content-type': 'application/json',
      origin,
      'cookie': `__Host-openpc_session=${initial.sessionToken}`,
    };
    const readback = await fetch(`${origin}/api/v1/session`, {
      headers,
      signal: AbortSignal.timeout(5000),
    });
    const observed = await readback.json();
    await predecessorCheckpoint(root, `predecessor-session-readback-${id()}.json`, {
      status: readback.status,
      body: observed,
    });
    assert.equal(readback.status, 200, 'Preserved original session must still authenticate');
    await assertOriginalSession(admin, root, origin, initial, scope, headers);
    const csrf = await fetch(`${origin}/api/v1/session/csrf`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' }),
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(csrf.status, 200);
    const selected = await fetch(`${origin}/api/v1/session/context`, {
      method: 'POST',
      headers: { ...headers, 'x-csrf-token': (await csrf.json()).csrfToken },
      body: JSON.stringify(scope),
      signal: AbortSignal.timeout(5000),
    });
    const result = await selected.json();
    await predecessorCheckpoint(root, 'predecessor-context-response.json', {
      status: selected.status,
      body: result,
    });
    assert.equal(selected.status, 201);
    assert.equal(result.participantId, scope.participantId);
    assert.equal(result.privacyDomainId, scope.privacyDomainId);
    assert.equal(result.contextMode, 'PARTICIPANT');
    assert.notEqual(result.sessionId, initial.sessionId);
    return {
      config,
      initialSessionId: initial.sessionId,
      principalId: initial.principalId,
      sessionId: result.sessionId,
      sessionToken: result.sessionToken,
    };
  } finally {
    await service.app.close();
    await service.pool.end();
  }
}
