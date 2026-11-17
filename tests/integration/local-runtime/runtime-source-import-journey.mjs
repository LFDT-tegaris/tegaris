import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, writeFile, rename, lstat, mkdir, mkdtemp } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { startSourceImportCommitFault } from './runtime-source-import-fault.mjs';
import { sourceScope, verifyInstalledRuntimeSource } from './runtime-source-bootstrap.mjs';

const execute = promisify(execFile);
const json = async (path) => JSON.parse(await readFile(path, 'utf8'));
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const newFile = (path, bytes) => writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
const nativePath = '/runtime-source-journal/owner/runtime-artifact-source.json';
const retainedPath = '/runtime-source-retained/owner/runtime-artifact-source-root.json';

function observations(native) {
  const state = JSON.parse(native.toString());
  assert.ok(Array.isArray(state.history?.originals));
  return state.history.originals.map((wire) => {
    const value = JSON.parse(Buffer.from(wire).toString());
    assert.equal(value.purpose, 'openpc:runtime-artifact-source-history:v1');
    return { wire, observation: value.claims.observation };
  });
}

export function verifyOriginalSourceJournal(native, original, committedRequired) {
  const records = observations(native);
  const pending = records.filter((record) => record.observation.ImportPending);
  const committed = records.filter((record) => record.observation.ImportCommitted);
  assert.equal(pending.length, 1);
  assert.deepEqual(pending[0].wire, original.pending);
  assert.deepEqual(pending[0].observation.ImportPending, original.identity);
  if (committedRequired) assert.equal(committed.length, 1);
  else assert.ok(committed.length <= 1);
  for (const record of committed)
    assert.deepEqual(record.observation.ImportCommitted, original.identity);
}

// A generic exit, SQL/I/O/lock failure or later tick never proves the attack.
export function isSourceStartupRejection(error, expected) {
  if (error?.code !== 1 || error.killed || error.signal) return false;
  const events = (error.stderr ?? '').split('\n').flatMap((line) => {
    try {
      return [JSON.parse(line)];
    } catch {
      return [];
    }
  });
  const rejections = events.filter((event) => event.event === 'runtime_source_startup_rejected');
  return (
    rejections.length === 1 &&
    rejections[0].phase === 'startup' &&
    rejections[0].stage === expected.stage &&
    rejections[0].reason === expected.reason &&
    events.some(
      (event) =>
        event.event === 'control_worker_stopped' && event.phase === 'runtime_source_custody',
    )
  );
}

export async function writeSourceImportProxyOverride(evidence, host, port) {
  // Transport setup may fail before the fault is armed. Keep every attempt's
  // endpoint separate so recovery cannot overwrite the first failure evidence.
  const directory = await mkdtemp(join(evidence, 'source-import-transport-'));
  const path = join(directory, 'compose.json');
  await newFile(
    path,
    JSON.stringify({
      services: {
        'control-worker': {
          environment: {
            CONTROL_WORKER_DATABASE_HOST: host,
            CONTROL_WORKER_DATABASE_PORT: String(port),
          },
        },
      },
    }),
  );
  return path;
}

export async function importOriginalSource(options) {
  return sourceImportJourney(options, false);
}

export async function resumeOriginalSource(options) {
  return sourceImportJourney(options, true);
}

async function sourceImportJourney({ root, compose, gateway }, resume) {
  assert.equal(root, resolve(root));
  assert.ok(Array.isArray(compose) && compose[0] === 'docker' && compose[1] === 'compose');
  const secretRoot = join(root, 'secrets'),
    evidence = join(root, 'evidence/runtime-bootstrap');
  const owner = (await readFile(join(root, '.openpc-local-runtime-owner'), 'utf8'))
    .trim()
    .split(':');
  const run = async (args, command = compose) =>
    execute(command[0], [...command.slice(1), ...args], {
      timeout: 45000,
      maxBuffer: 20 * 1024 * 1024,
    });
  const container = async (command = compose) =>
    (await run(['ps', '-q', 'control-worker'], command)).stdout.trim();
  const native = async (id, path = nativePath) =>
    Buffer.from(
      (await execute('docker', ['exec', id, 'cat', path], { maxBuffer: 20 * 1024 * 1024 })).stdout,
    );
  const input = await json(join(evidence, 'source-configuration.json'));
  const prior = await json(join(evidence, 'source-preflight.json'));
  for (const field of [
    'providerArtifactDigest',
    'indexerArtifactDigest',
    'projectionArtifactDigest',
  ])
    assert.equal(input[field], prior[field]);
  const bytes = Buffer.from(input.configurationCborHex, 'hex'),
    digest = hash(bytes);
  const path = join(
    root,
    'data/runtime-bootstrap/provider-probe-source/runtime-configuration.cbor',
  );
  if (resume) assert.deepEqual(await readFile(path), bytes);
  else await assert.rejects(lstat(path), { code: 'ENOENT' });
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    max: 1,
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    statement_timeout: 3000,
    query_timeout: 4000,
    connectionTimeoutMillis: 3000,
  });
  const row = async () => {
    const result = await pool.query(
      `select runtime_configuration_input_id::text as input_id,
      module_installation_id::text,module_configuration_generation_id::text,
      encode(configuration_digest,'hex') as configuration_digest,configuration_cbor,selected
      from control.runtime_configuration_input where participant_id=$1 and privacy_domain_id=$2`,
      [sourceScope.participant, sourceScope.privacy],
    );
    assert.equal(result.rows.length, 1);
    assert.deepEqual(result.rows[0].configuration_cbor, bytes);
    assert.equal(result.rows[0].selected, true);
    return Object.fromEntries(
      [
        'input_id',
        'module_installation_id',
        'module_configuration_generation_id',
        'configuration_digest',
      ].map((field) => [field, result.rows[0][field]]),
    );
  };
  let proxy,
    proxied,
    original,
    before,
    workerStopped = false;
  try {
    await verifyInstalledRuntimeSource(
      pool,
      secretRoot,
      sourceScope.participant,
      sourceScope.privacy,
    );
    if (resume) {
      // Reconcile only the preserved consumed intent. No resource submission,
      // input installation, proxy arming or new pending signature is reachable.
      original = await json(join(evidence, 'source-import-original.json'));
      assert.deepEqual(await row(), original.identity);
      const existing = await run([
        'run',
        '--rm',
        '--no-deps',
        '-T',
        '--entrypoint',
        '/bin/cat',
        'control-worker',
        nativePath,
      ]);
      verifyOriginalSourceJournal(Buffer.from(existing.stdout), original, false);
      workerStopped = true;
    } else {
      assert.equal(
        (
          await pool.query(
            'select count(*)::int n from control.runtime_configuration_input where participant_id=$1 and privacy_domain_id=$2',
            [sourceScope.participant, sourceScope.privacy],
          )
        ).rows[0].n,
        0,
      );
      const worker = await container();
      const [actual] = JSON.parse((await execute('docker', ['inspect', worker])).stdout);
      assert.equal(actual.Config.Labels['com.docker.compose.project'], owner[1]);
      assert.equal(actual.Config.Labels['com.docker.compose.service'], 'control-worker');
      assert.ok(
        Object.values(actual.NetworkSettings.Networks).some(
          (network) => network.Gateway === gateway,
        ),
      );
      await run(['stop', 'control-worker']);
      workerStopped = true;
      proxy = await startSourceImportCommitFault({
        host: gateway,
        ...sourceScope,
        configurationDigest: digest,
        observeCommitted: async (fault) => {
          const { count, ...identity } = fault;
          assert.equal(count, 1);
          assert.deepEqual(await row(), identity);
          before = await native(await container(proxied));
          const records = observations(before);
          const pending = records.filter((record) => record.observation.ImportPending);
          assert.equal(pending.length, 1);
          assert.deepEqual(pending[0].observation.ImportPending, identity);
          assert.equal(records.filter((record) => record.observation.ImportCommitted).length, 0);
          original = { identity, pending: pending[0].wire };
          // Preserve the actual signed bytes before the caller observes EOF.
          await newFile(join(evidence, 'source-import-original.json'), JSON.stringify(original));
        },
      });
      const override = await writeSourceImportProxyOverride(evidence, gateway, proxy.port);
      proxied = [...compose, '-f', override];
      await run(
        ['up', '-d', '--wait', '--no-deps', '--no-build', '--pull', 'never', 'control-worker'],
        proxied,
      );
      workerStopped = false;
      proxy.arm();
      await writeFile(`${path}.next`, bytes, { flag: 'wx', mode: 0o444 });
      await rename(`${path}.next`, path);
      const deadline = Date.now() + 45000;
      while (!proxy.status()) {
        assert.ok(Date.now() < deadline, 'Exact import COMMIT not observed');
        await delay(200);
      }
      assert.ok(original && before);
      await run(['stop', 'control-worker'], proxied);
      workerStopped = true;
      await proxy.close();
      proxy = undefined;
    }
    // Normal startup reconciles the preserved original; it must not create a
    // new input, sign another pending original or publish a business outcome.
    await run([
      'up',
      '-d',
      '--wait',
      '--no-deps',
      '--no-build',
      '--pull',
      'never',
      'control-worker',
    ]);
    workerStopped = false;
    let current = await container();
    const recovered = await native(current),
      retained = await native(current, retainedPath);
    verifyOriginalSourceJournal(recovered, original, true);
    assert.deepEqual(await row(), original.identity);
    assert.deepEqual(await readFile(path), bytes);
    await run(['stop', 'control-worker']);
    workerStopped = true;
    const config = await json(join(root, 'data/runtime-source-config/configuration.json'));
    const swapped = structuredClone(config);
    swapped.retained_root.binding.generation_id = '018f0000-0000-7000-8000-000000008903';
    const substituted = join(root, 'data/runtime-source-config/substituted.json');
    try {
      assert.deepEqual(await readFile(substituted), Buffer.from(JSON.stringify(swapped)));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await writeFile(substituted, JSON.stringify(swapped), { flag: 'wx', mode: 0o444 });
    }
    const missingRoot = join(root, 'data/runtime-source-missing-root');
    await mkdir(missingRoot, { mode: 0o755, recursive: true });
    const missingRootStat = await lstat(missingRoot);
    assert.ok(missingRootStat.isDirectory() && !missingRootStat.isSymbolicLink());
    for (const [name, expected, args] of [
      [
        'missing-config',
        { stage: 'configuration', reason: 'configuration_missing' },
        ['-e', 'OPENPC_RUNTIME_ARTIFACT_SOURCE_FILE=/runtime-source-config/absent.json'],
      ],
      [
        'substituted-generation',
        { stage: 'retained_root', reason: 'root_binding_mismatch' },
        ['-e', 'OPENPC_RUNTIME_ARTIFACT_SOURCE_FILE=/runtime-source-config/substituted.json'],
      ],
      [
        'legacy-login',
        { stage: 'installation', reason: 'protected_scope_login' },
        [
          '-e',
          'CONTROL_WORKER_DATABASE_USER=openpc_local_control_worker',
          '-e',
          'CONTROL_WORKER_DATABASE_PASSWORD_FILE=/run/secrets/control_worker_runtime_db_password',
        ],
      ],
      [
        'missing-root',
        { stage: 'retained_root', reason: 'root_missing' },
        ['-v', `${missingRoot}:/runtime-source-retained:ro`],
      ],
    ]) {
      let denied = false;
      try {
        await run([
          'run',
          '--rm',
          '--no-deps',
          '-T',
          '--name',
          `${owner[1]}-source-${name}`,
          ...args,
          'control-worker',
        ]);
      } catch (error) {
        // A timeout, transport/lock error, or later business failure is not the
        // intended startup denial. Preserve the first failure and stop here.
        denied = isSourceStartupRejection(error, expected);
      }
      const remaining = (
        await execute('docker', ['ps', '-aq', '--filter', `name=^/${owner[1]}-source-${name}$`])
      ).stdout.trim();
      if (remaining) {
        const [unexpected] = JSON.parse((await execute('docker', ['inspect', remaining])).stdout);
        assert.equal(unexpected.Config.Labels['com.docker.compose.project'], owner[1]);
        assert.equal(unexpected.Name, `/${owner[1]}-source-${name}`);
        if (unexpected.State.Running)
          await execute('docker', ['stop', remaining], { timeout: 20000 });
        // An uncertain one-shot is retained for diagnosis, never counted as a
        // denial merely because its client timed out or was terminated.
        denied = false;
      }
      assert.equal(denied, true, `Installed source must reject ${name} before runtime startup`);
      // Check each attack before the next one. The packaged unprivileged reader
      // starts no worker and grants no custody or business authority.
      const unchanged = await run([
        'run',
        '--rm',
        '--no-deps',
        '-T',
        '--entrypoint',
        '/bin/cat',
        'control-worker',
        nativePath,
        retainedPath,
      ]);
      assert.deepEqual(Buffer.from(unchanged.stdout), Buffer.concat([recovered, retained]));
      assert.deepEqual(await row(), original.identity);
      assert.deepEqual(await readFile(path), bytes);
      process.stdout.write(
        `OPENPC_RUNTIME_SOURCE_STARTUP_DENIAL|PASS|case=${name}|stage=${expected.stage}|reason=${expected.reason}|no_effect=verified\n`,
      );
    }
    await run([
      'up',
      '-d',
      '--wait',
      '--no-deps',
      '--no-build',
      '--pull',
      'never',
      'control-worker',
    ]);
    workerStopped = false;
    current = await container();
    assert.deepEqual(await native(current), recovered);
    assert.deepEqual(await native(current, retainedPath), retained);
    assert.deepEqual(await row(), original.identity);
    assert.deepEqual(await readFile(path), bytes);
    process.stdout.write(
      resume
        ? 'OPENPC_RUNTIME_SOURCE_RESUME|PASS|original-reconciliation|restart|installed-startup-denials|consumer-closure=UNPROVEN\n'
        : 'OPENPC_RUNTIME_SOURCE_IMPORT|PASS|public-resources|actual-COMMIT-response-loss|original-reconciliation|restart|installed-startup-denials|consumer-closure=UNPROVEN\n',
    );
  } catch (error) {
    if (!workerStopped) await run(['stop', 'control-worker'], proxied ?? compose).catch(() => {});
    throw error;
  } finally {
    await proxy?.close();
    await pool.end();
  }
}
