// Initial host trust for the ordinary first-policy journey. No module, input,
// approval, operation, activation or effect is created by this fixture.
import assert from 'node:assert/strict';
import { createECDH, randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, open, readFile, readdir, rename } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

export const sourceScope = Object.freeze({
  participant: '018f0000-0000-7000-8000-000000000101',
  privacy: '018f0000-0000-7000-8000-000000007201',
});
export const qaSourceScope = Object.freeze({
  participant: '018f0000-0000-7000-8000-000000000101',
  privacy: '018f0000-0000-7000-8000-000000000201',
});

function selectedScope(participant, privacy) {
  const scope = [sourceScope, qaSourceScope].find(
    (value) => value.participant === participant && value.privacy === privacy,
  );
  assert.ok(scope, 'Unknown initial runtime source scope');
  return scope;
}

async function preparedScope(root) {
  const input = await readJson(join(root, 'data/runtime-source-config/input.json'));
  return selectedScope(input.participant_id, input.privacy_domain_id);
}
const readJson = async (path) => JSON.parse(await readFile(path, 'utf8'));
const writeNew = async (path, value, mode = 0o444) => {
  const file = await open(path, 'wx', mode);
  try {
    await file.writeFile(value);
    // The runner's private umask must not make declared container inputs unreadable.
    // Apply the exact mode to this newly created inode, never an existing path.
    await file.chmod(mode);
  } finally {
    await file.close();
  }
};
export const runtimeArchiveConfiguration = Object.freeze({
  stream_id: 'runtime-source-archive',
  database_password_file: '/runtime-source-archive/owner/database.password',
  keys: { 'runtime-source-archive-key': '/runtime-source-archive/owner/archive.key' },
});

// Provision only initial local test trust, as the exact packaged consumer uid.
// The host caller never reads or loosens the private archive key permissions.
async function prepareArchiveKeys(directory) {
  assert.equal(process.getuid(), 65532);
  assert.equal(process.getgid(), 65532);
  assert.equal(directory, '/runtime-source-archive');
  const metadata = await lstat(directory);
  assert.equal(metadata.isDirectory(), true);
  assert.deepEqual(await readdir(directory), []);
  await mkdir(join(directory, 'owner'), { mode: 0o700 });
  await writeNew(
    runtimeArchiveConfiguration.database_password_file,
    randomBytes(32).toString('hex'),
    0o600,
  );
  await writeNew(
    runtimeArchiveConfiguration.keys['runtime-source-archive-key'],
    randomBytes(32),
    0o600,
  );
  for (const file of [
    runtimeArchiveConfiguration.database_password_file,
    ...Object.values(runtimeArchiveConfiguration.keys),
  ]) {
    const actual = await lstat(file);
    assert.equal(actual.isFile(), true);
    assert.equal(actual.mode & 0o777, 0o600);
    assert.equal(actual.uid, 65532);
    assert.equal(actual.gid, 65532);
  }
}

export function sourceOverlay(root, config, scope = sourceScope) {
  selectedScope(scope.participant, scope.privacy);
  assert.equal(config.installation.participant_id, scope.participant);
  assert.equal(config.installation.privacy_domain_id, scope.privacy);
  assert.match(config.database_role, /^openpc_rs_login_[A-Za-z0-9_-]{43}$/u);
  assert.equal(config.source_file, '/provider-sources/runtime-configuration.cbor');
  assert.equal(config.journal_directory, '/runtime-source-journal/owner');
  assert.equal(config.retained_root.directory, '/runtime-source-retained/owner');
  assert.equal(config.signing_key_file, '/run/secrets/runtime_source_signing_key');
  assert.equal(config.commit_key_file, '/run/secrets/runtime_source_commit_key');
  assert.equal(config.database_password_file, '/run/secrets/runtime_source_database_password');
  const secretNames = [
    'runtime_source_signing_key',
    'runtime_source_commit_key',
    'runtime_source_database_password',
  ];
  const overlay = {
    services: {
      'control-migrate': {
        environment: { OPENPC_CONTROL_WORKER_TRUST_ROLE: config.database_role },
      },
      'control-worker': {
        environment: {
          CONTROL_WORKER_PARTICIPANT_ID: scope.participant,
          CONTROL_WORKER_PRIVACY_DOMAIN_ID: scope.privacy,
          CONTROL_WORKER_DATABASE_USER: config.database_role,
          CONTROL_WORKER_DATABASE_PASSWORD_FILE: config.database_password_file,
          OPENPC_RUNTIME_ARTIFACT_SOURCE_FILE: '/runtime-source-config/configuration.json',
        },
        secrets: secretNames,
        volumes: [
          `${root}/data/runtime-source-config:/runtime-source-config:ro`,
          `${root}/data/runtime-source-journal:/runtime-source-journal`,
          // Separate from data/, runtime/, and every supported source backup.
          `${root}/retained-runtime-source:/runtime-source-retained`,
        ],
      },
    },
    secrets: Object.fromEntries(
      secretNames.map((name) => [name, { file: `${root}/secrets/${name}` }]),
    ),
  };
  if (
    config.retained_root.binding?.consumer_profile === 'openpc:local-runtime-source-consumers:v2'
  ) {
    const endpoint = '/run/openpc-runtime-source';
    const mount = `${root}/data/runtime-source-ipc:${endpoint}`;
    overlay.services['control-worker'].environment.OPENPC_RUNTIME_ARTIFACT_SOURCE_SOCKET_DIRECTORY =
      endpoint;
    overlay.services['control-worker'].volumes.push(mount);
    for (const reader of ['control-api', 'policy-service', 'fact-service', 'runtime-target']) {
      overlay.services[reader] = {
        environment: { OPENPC_RUNTIME_ARTIFACT_SOURCE_SOCKET_DIRECTORY: endpoint },
        volumes: [`${mount}:ro`],
      };
    }
  }
  if (config.archive_custody !== undefined && config.archive_custody !== null) {
    assert.equal(
      config.retained_root.binding.consumer_profile,
      'openpc:local-runtime-source-consumers:v2',
    );
    assert.deepEqual(config.archive_custody, runtimeArchiveConfiguration);
    overlay.services['control-worker'].volumes.push(
      `${root}/runtime-source-archive:/runtime-source-archive:ro`,
    );
  }
  return overlay;
}

export async function verifyInstalledRuntimeSource(client, secretRoot, participant, privacy) {
  const config = await readJson(
    join(secretRoot, '../data/runtime-source-config/configuration.json'),
  );
  sourceOverlay(resolve(secretRoot, '..'), config, selectedScope(participant, privacy));
  assert.equal(participant, config.installation.participant_id);
  assert.equal(privacy, config.installation.privacy_domain_id);
  const sourceKey = createECDH('prime256v1');
  sourceKey.setPrivateKey(await readFile(join(secretRoot, 'runtime_source_signing_key')));
  const commitKey = await readFile(join(secretRoot, 'runtime_source_commit_key'));
  const { rows } = await client.query(
    `select p.root_privacy_domain_id,p.state as participant_state,d.state as privacy_state,
      d.domain_name,d.placement_profile,d.residency_profile,s.source_owner_id,
      encode(s.source_file_binding,'hex') as source_file_binding,s.source_public_key,
      s.database_role,s.custody_root,s.installation_reference,
      s.archive_custody,
      k.verifier_secret=$3::bytea as commit_key_matches
     from control.participant p join control.privacy_domain d using(participant_id)
     join control.runtime_artifact_source s using(participant_id,privacy_domain_id)
     join control.runtime_artifact_source_verifier_key k using(participant_id,privacy_domain_id,source_owner_id)
     where p.participant_id=$1 and d.privacy_domain_id=$2`,
    [participant, privacy, commitKey],
  );
  assert.equal(rows.length, 1, 'Exactly one installed source is required');
  const row = rows[0];
  assert.equal(row.root_privacy_domain_id, privacy);
  assert.equal(row.participant_state, 'ACTIVE');
  assert.equal(row.privacy_state, 'ACTIVE');
  assert.equal(row.domain_name, config.fresh_scope.privacy_domain_name);
  assert.equal(row.placement_profile, 'PARTICIPANT_LOCAL');
  assert.equal(row.residency_profile, config.fresh_scope.residency_profile);
  for (const field of ['source_owner_id', 'source_file_binding']) {
    assert.equal(row[field], config.installation[field]);
  }
  assert.deepEqual(row.source_public_key, sourceKey.getPublicKey(undefined, 'compressed'));
  assert.equal(row.database_role, config.database_role);
  assert.deepEqual(row.custody_root, config.retained_root.binding);
  assert.equal(
    row.installation_reference,
    `native-source-root:${config.retained_root.binding.generation_id}`,
  );
  assert.equal(row.commit_key_matches, true);
  if (config.archive_custody) {
    assert.equal(
      row.archive_custody.database_role,
      config.database_role.replace('openpc_rs_login_', 'openpc_ra_login_'),
    );
    assert.equal(row.archive_custody.stream_id, runtimeArchiveConfiguration.stream_id);
    assert.deepEqual(
      Object.keys(row.archive_custody.keys),
      Object.keys(runtimeArchiveConfiguration.keys),
    );
    for (const digest of Object.values(row.archive_custody.keys))
      assert.match(digest, /^[0-9a-f]{64}$/u);
  } else assert.equal(row.archive_custody, null);
  // Validate both connected native admissions before a worker starts. Source
  // installation alone cannot prove its existing Fact/disposition bridge trust.
  const bridgeKeys = [];
  for (const [table, file] of [
    ['fleet_fact_admission_key', 'fleet_fact_admission_key.txt'],
    ['runtime_target_disposition_key', 'runtime_target_disposition_key.txt'],
  ]) {
    const encoded = (await readFile(join(secretRoot, file), 'utf8')).trim();
    assert.match(encoded, /^[0-9a-f]{64}$/u);
    const key = Buffer.from(encoded, 'hex');
    const result = await client.query(
      `select verifier_secret=$2::bytea as matches from control.${table} where database_role=$1`,
      [config.database_role, key],
    );
    assert.deepEqual(result.rows, [{ matches: true }], 'Exact installed consumer bridge trust');
    bridgeKeys.push(key);
  }
  assert.notDeepEqual(bridgeKeys[0], bridgeKeys[1]);
  assert.notDeepEqual(bridgeKeys[0], commitKey);
  assert.notDeepEqual(bridgeKeys[1], commitKey);
  for (const key of [...bridgeKeys, commitKey]) key.fill(0);
  return config;
}

class SourceBootstrapError extends Error {
  constructor(stage) {
    super('Runtime source bootstrap failed');
    this.stage = stage;
  }
}
async function checked(stage, action) {
  try {
    return await action();
  } catch {
    throw new SourceBootstrapError(stage);
  }
}

export function verifyRuntimeSourceContainer(container, { root, project, config }) {
  const secretRoot = join(root, 'secrets');
  assert.equal(container.Config.Labels['com.docker.compose.project'], project);
  assert.equal(container.Config.Labels['com.docker.compose.service'], 'control-worker');
  assert.equal(container.Config.User, '65532:65532');
  assert.equal(container.State.Running, true);
  assert.equal(container.State.Health.Status, 'healthy');
  const environment = Object.fromEntries(
    container.Config.Env.map((item) => {
      const split = item.indexOf('=');
      return [item.slice(0, split), item.slice(split + 1)];
    }),
  );
  assert.equal(environment.CONTROL_WORKER_DATABASE_USER, config.database_role);
  assert.equal(environment.CONTROL_WORKER_DATABASE_PASSWORD_FILE, config.database_password_file);
  if (
    config.retained_root?.binding?.consumer_profile === 'openpc:local-runtime-source-consumers:v2'
  ) {
    assert.equal(
      environment.OPENPC_RUNTIME_ARTIFACT_SOURCE_SOCKET_DIRECTORY,
      '/run/openpc-runtime-source',
    );
    const mounts = container.Mounts.filter(
      (mount) => mount.Destination === '/run/openpc-runtime-source',
    );
    assert.equal(mounts.length, 1);
    assert.equal(mounts[0].Source, join(root, 'data/runtime-source-ipc'));
    assert.equal(mounts[0].RW, true);
  }
  if (config.archive_custody) {
    const mounts = container.Mounts.filter(
      (mount) => mount.Destination === '/runtime-source-archive',
    );
    assert.equal(mounts.length, 1);
    assert.equal(mounts[0].Source, join(root, 'runtime-source-archive'));
    assert.equal(mounts[0].RW, false);
  }
  for (const mount of container.Mounts) {
    assert.notEqual(mount.Source, join(secretRoot, 'control_pg_password.txt'));
    assert.notEqual(mount.Source, secretRoot);
    assert.notEqual(mount.Destination, '/run/secrets/installer_database_password');
  }
  for (const [destination, source] of [
    ['/runtime-source-journal', join(root, 'data/runtime-source-journal')],
    ['/runtime-source-retained', join(root, 'retained-runtime-source')],
  ]) {
    const mounts = container.Mounts.filter((mount) => mount.Destination === destination);
    assert.equal(mounts.length, 1);
    assert.equal(mounts[0].Source, source);
    assert.equal(mounts[0].RW, true);
  }
  const addresses = Object.values(container.NetworkSettings.Networks).map(
    (network) => network.IPAddress,
  );

  assert.ok(
    addresses.length > 0 &&
      addresses.every((address) => typeof address === 'string' && address.length > 0),
  );
  return addresses;
}

async function main([mode, root, containerId]) {
  assert.equal(root, resolve(root));
  if (mode === 'archive-keys') return prepareArchiveKeys(root);
  const secretRoot = join(root, 'secrets');
  const configRoot = join(root, 'data/runtime-source-config');
  if (mode === 'prepare') {
    assert.ok(containerId === undefined || containerId === 'qa-primary');
    if (containerId === 'qa-primary') {
      assert.equal(process.env.OPENPC_LOCAL_RUNTIME, '1');
      assert.equal(process.env.OPENPC_LOCAL_RUNTIME_QA_FIXTURE, '1');
      assert.equal(process.env.OPENPC_LOCAL_QA_ROOTED_SOURCE, '1');
    }
    const scope = containerId === 'qa-primary' ? qaSourceScope : sourceScope;
    await mkdir(configRoot, { mode: 0o755 });
    await chmod(configRoot, 0o755);
    // Only the packaged uid creates the inner locked 0700 owner directories.
    // The run root is private and remains under the runner's exclusive lock.
    for (const directory of [
      'data/runtime-source-journal',
      'retained-runtime-source',
      'runtime-source-archive',
    ]) {
      await mkdir(join(root, directory), { mode: 0o777 });
      await chmod(join(root, directory), 0o777);
    }
    const signing = createECDH('prime256v1');
    signing.generateKeys();
    await writeNew(join(secretRoot, 'runtime_source_signing_key'), signing.getPrivateKey());
    await writeNew(join(secretRoot, 'runtime_source_commit_key'), randomBytes(32));
    await writeNew(
      join(secretRoot, 'runtime_source_database_password'),
      randomBytes(32).toString('hex'),
    );
    await writeNew(
      join(configRoot, 'input.json'),
      JSON.stringify({
        participant_id: scope.participant,
        privacy_domain_id: scope.privacy,
        source_owner_id: '018f0000-0000-7000-8000-000000008901',
        generation_id: '018f0000-0000-7000-8000-000000008902',
        source_file: '/provider-sources/runtime-configuration.cbor',
        journal_directory: '/runtime-source-journal/owner',
        retained_root_directory: '/runtime-source-retained/owner',
        signing_key_file: '/run/secrets/runtime_source_signing_key',
        commit_key_file: '/run/secrets/runtime_source_commit_key',
        database_password_file: '/run/secrets/runtime_source_database_password',
        fresh_scope: {
          participant_display_name: 'Local participant',
          privacy_domain_name: 'Isolated runtime bootstrap',
          residency_profile: 'LOCAL_DEVELOPMENT',
        },
      }),
    );
  } else if (mode === 'materialization-database') {
    // Finalize a genuinely new installation before its first native/SQL
    // enrollment. Never relabel a retained V1 root, even an apparently empty one.
    const input = await readJson(join(configRoot, 'input.json'));
    const scope = selectedScope(input.participant_id, input.privacy_domain_id);
    const draft = await readJson(join(configRoot, 'configuration.json'));
    assert.equal(input.materialization_database, undefined);
    assert.equal(
      draft.retained_root.binding.consumer_profile,
      'openpc:local-runtime-source-consumers:v1',
    );
    for (const path of ['data/runtime-source-journal', 'retained-runtime-source']) {
      assert.equal((await lstat(join(root, path))).isDirectory(), true);
      assert.deepEqual(await readdir(join(root, path)), []);
    }
    const { default: pg } = await import('pg');
    const client = new pg.Client({
      host: '127.0.0.1',
      port: 55432,
      database: 'openpc_control',
      user: 'openpc_control',
      password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    });
    await client.connect();
    try {
      const existing = await client.query(
        `select exists(select 1 from control.participant where participant_id=$1) participant,
        exists(select 1 from pg_roles where rolname=$2) installed`,
        [scope.participant, draft.database_role],
      );
      assert.deepEqual(existing.rows, [{ participant: false, installed: false }]);
      const database = await client.query(
        'select openpc.runtime_artifact_database_identity() identity',
      );
      assert.equal(database.rowCount, 1);
      for (const key of ['system_identifier', 'database_oid'])
        assert.match(database.rows[0].identity[key], /^[1-9][0-9]*$/u);
      for (const file of ['input.json', 'configuration.json', 'compose.json']) {
        const preserved = join(configRoot, `${file}.pre-enrollment`);
        await assert.rejects(lstat(preserved), { code: 'ENOENT' });
        await rename(join(configRoot, file), preserved);
      }
      await writeNew(
        join(configRoot, 'input.json'),
        JSON.stringify({
          ...input,
          materialization_database: database.rows[0].identity,
          archive_custody: runtimeArchiveConfiguration,
        }),
      );
      const endpoint = join(root, 'data/runtime-source-ipc');
      await mkdir(endpoint, { mode: 0o1777 });
      await chmod(endpoint, 0o1777);
    } finally {
      await client.end();
    }
  } else if (mode === 'overlay') {
    const config = await readJson(join(configRoot, 'configuration.json'));
    await writeNew(
      join(configRoot, 'compose.json'),
      JSON.stringify(sourceOverlay(root, config, await preparedScope(root))),
    );
  } else if (mode === 'verify' || mode === 'verify-runtime') {
    const scope = await preparedScope(root);
    const { default: pg } = await import('pg');
    const client = new pg.Client({
      host: '127.0.0.1',
      port: 55432,
      database: 'openpc_control',
      user: 'openpc_control',
      password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    });
    await client.connect();
    try {
      const config = await checked('installed_source_readback', () =>
        verifyInstalledRuntimeSource(client, secretRoot, scope.participant, scope.privacy),
      );
      if (mode === 'verify-runtime') {
        assert.match(containerId, /^[0-9a-f]{64}$/u);
        const { stdout } = await checked('container_inspect', () =>
          promisify(execFile)('docker', ['inspect', containerId]),
        );
        const [container] = JSON.parse(stdout);
        const owner = (await readFile(join(root, '.openpc-local-runtime-owner'), 'utf8'))
          .trim()
          .split(':');
        const addresses = await checked('container_readback', () =>
          verifyRuntimeSourceContainer(container, { root, project: owner[1], config }),
        );
        await checked('database_session_readback', async () => {
          const sessions = await client.query(
            `select count(*)::int as count from pg_catalog.pg_stat_activity
             where usename=$1 and host(client_addr)=any($2::text[]) and backend_type='client backend'`,
            [config.database_role, addresses],
          );
          assert.ok(sessions.rows[0].count > 0, 'Actual worker must use its dedicated login');
        });
      }
      const runtime = new pg.Client({
        host: '127.0.0.1',
        port: 55432,
        database: 'openpc_control',
        user: config.database_role,
        password: await readFile(join(secretRoot, 'runtime_source_database_password'), 'utf8'),
      });
      await runtime.connect();
      try {
        const {
          rows: [identity],
        } = await runtime.query('select session_user,current_user');
        assert.deepEqual(identity, {
          session_user: config.database_role,
          current_user: config.database_role,
        });
      } finally {
        await runtime.end();
      }
      process.stdout.write(
        'OPENPC_RUNTIME_SOURCE_BOOTSTRAP|PASS|installed-scope-and-keys|dedicated-login|coverage=UNPROVEN\n',
      );
    } finally {
      await client.end();
    }
  } else {
    throw new Error('Unknown source bootstrap mode');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  // Assertions can contain key bytes. This fixture reports only its failed phase.
  main(process.argv.slice(2)).catch((error) => {
    const stage =
      error instanceof SourceBootstrapError ? error.stage : 'bootstrap_input_or_connection';
    process.stderr.write(`OPENPC_RUNTIME_SOURCE_BOOTSTRAP|FAIL|stage=${stage}\n`);
    process.exitCode = 1;
  });
}
