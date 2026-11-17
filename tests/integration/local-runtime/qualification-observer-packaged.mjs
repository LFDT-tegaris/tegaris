/** Consumes a freshly prepared, exclusively owned existing local-runtime slice.
 * The canonical runner owns build/initial trust/DB/created containers and final
 * removal. This driver starts the NORMAL Identity program and the built host
 * executable; no in-process native observer or substitute workload program. */
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFile, lstat, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { z } from 'zod';
import { readInstallationQualificationInputs } from '../../../scripts/operations/installation-qualification-inputs.mjs';
import {
  qualificationObserverClientInputSchema,
  readQualificationObserverFile,
} from '../../../services/identity-service/src/domain/qualification-observer-client.ts';
import {
  installationProcessIsolationSchema,
  readInstallationProcessIsolation,
} from '../../../scripts/operations/installation-process-observation.mjs';
import {
  qualificationDeploymentPinsSchema,
  parseQualificationDeploymentPins,
  readQualificationPublicArtifactArchive,
  qualificationDeploymentDigest,
} from '../../../scripts/operations/qualification-deployment-observation.mjs';
import { installInitialQualificationDeployment } from '../../../services/control-api/src/configuration/operations/qualification-deployment-observation.ts';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.ts';

export const qualificationObserverPackagedCases = Object.freeze([
  'positive-root-restart',
  'committed-host-crash',
  'lost-reply-subject-restart',
  'copied-credential',
  'current-identity-denial',
  'wrong-server-spki',
  'wrong-role',
  'wrong-original',
  'bounded-drain',
]);
const path = z
  .string()
  .min(2)
  .max(512)
  .refine((v) => v.startsWith('/'));
const hash = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const container = z.string().regex(/^[0-9a-f]{64}$/u);
const derived = new Set([
  'containerId',
  'imageId',
  'containerStartedAt',
  'installedProcess',
  'networkId',
  'address',
  'artifacts',
]);
// Reuse the actual native input fields; only the installer fills native fields
// from the real started subject. Full refinements still run before installation.
const template = z.strictObject(
  Object.fromEntries(
    Object.entries(qualificationDeploymentPinsSchema.shape).filter(([key]) => !derived.has(key)),
  ),
);
export const qualificationObserverPackagedInputSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    caseName: z.enum(qualificationObserverPackagedCases),
    root: path,
    ownerToken: z.string().regex(/^[0-9a-f]{64}$/u),
    project: z.string().regex(/^openpc-local-e2e-[0-9a-f]{12}$/u),
    hostBundle: path,
    hostInputFile: path,
    adminConnectionFile: path,
    actors: z
      .array(
        z.strictObject({
          containerId: container,
          imageId: hash,
          initialPins: template,
          clientInputFile: path,
          clientCertificateFile: path,
          clientPrivateKeyFile: path,
        }),
      )
      .length(2),
  })
  .superRefine((v, c) => {
    const files = v.actors.flatMap((a) => [
      a.clientInputFile,
      a.clientCertificateFile,
      a.clientPrivateKeyFile,
    ]);
    if (
      v.ownerToken.slice(0, 12) !== v.project.slice('openpc-local-e2e-'.length) ||
      v.actors[0].containerId === v.actors[1].containerId ||
      v.actors[0].initialPins.installationId === v.actors[1].initialPins.installationId ||
      new Set(files).size !== files.length ||
      v.actors.some((a, i) => {
        const other = v.actors[1 - i].initialPins,
          p = a.initialPins;
        return (
          p.executable !== '/usr/local/bin/node' ||
          p.argv.length !== 1 ||
          p.argv[0] !== '/app/server.mjs' ||
          p.memoryBytes > 268435456 ||
          p.nanoCpus > 500000000 ||
          p.pidsLimit > 64 ||
          p.participantId !== other.participantId ||
          p.privacyDomainId !== other.privacyDomainId ||
          p.environmentId !== other.environmentId ||
          p.daemonId !== other.daemonId ||
          p.peer.credentialId === other.peer.credentialId ||
          p.peer.principalId === other.peer.principalId ||
          p.separatedFrom.length !== 1 ||
          p.separatedFrom[0] !== other.installationId
        );
      })
    )
      c.addIssue({ code: 'custom', message: 'Packaged input ownership rejected' });
  });
const execute = promisify(execFile);
const nap = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(check, milliseconds = 30000) {
  const end = Date.now() + milliseconds;
  while (Date.now() < end) {
    const value = await check();
    if (value) return value;
    await nap(20);
  }
  throw new Error('QUALIFICATION_PACKAGED_PHASE_TIMEOUT');
}
export async function verifyQualificationObserverFiles(value) {
  const input = qualificationObserverPackagedInputSchema.parse(value);
  assert.equal(await realpath(input.root), input.root);
  const rootInfo = await lstat(input.root);
  assert.ok(
    rootInfo.isDirectory() &&
      rootInfo.uid === process.getuid() &&
      (rootInfo.mode & 0o777) === 0o700,
  );
  const sentinel = (
    await readQualificationObserverFile(join(input.root, '.openpc-local-runtime-owner'), 256)
  ).toString('utf8');
  assert.equal(sentinel, `openpc-local-runtime:${input.project}:${input.ownerToken}\n`);
  const privateFiles = [
    input.hostInputFile,
    input.adminConnectionFile,
    ...input.actors.flatMap((a) => [
      a.clientInputFile,
      a.clientCertificateFile,
      a.clientPrivateKeyFile,
    ]),
  ];
  for (const file of [input.hostBundle, ...privateFiles]) {
    assert.ok(file.startsWith(input.root + '/'));
    assert.equal(await realpath(file), file);
    const stat = await lstat(file);
    assert.ok(
      stat.isFile() &&
        stat.nlink === 1 &&
        !(stat.mode & 0o022) &&
        [0, process.getuid()].includes(stat.uid),
    );
    if (privateFiles.includes(file)) assert.equal(stat.mode & 0o077, 0);
  }
  return input;
}
export async function runQualificationObserverPackagedCase(value) {
  const input = await verifyQualificationObserverFiles(value);
  const host = await readInstallationQualificationInputs(input.hostInputFile);
  assert.ok(
    host.resources.externalMemoryGiB >= 1.75,
    'DB plus two capped actual Identity programs must be admitted',
  );
  await execute(
    'bash',
    [
      join(host.repositoryRoot, 'scripts/maintenance/run-bounded.sh'),
      '--memory-gib',
      String(host.resources.memoryGiB),
      '--external-memory-gib',
      String(host.resources.externalMemoryGiB),
      '--peak-disk-gib',
      String(host.resources.peakDiskGiB),
      '--reuse',
      '--',
      'true',
    ],
    { cwd: host.repositoryRoot, timeout: 10000, maxBuffer: 16384 },
  );
  const docker = async (...args) =>
    (
      await execute('docker', ['--host', 'unix:///var/run/docker.sock', ...args], {
        timeout: args[0] === 'stop' || args[0] === 'restart' ? 55000 : 10000,
        maxBuffer: 20 * 1024 * 1024,
        encoding: 'buffer',
      })
    ).stdout;
  const selectedEnvironment = (name) => {
    const prefix = name + '=';
    return (
      '[{{range .Config.Env}}{{if and (ge (len .) ' +
      prefix.length +
      ') (eq (slice . 0 ' +
      prefix.length +
      ') ' +
      JSON.stringify(prefix) +
      ')}}{{json .}},{{end}}{{end}}null]'
    );
  };
  const inspect = async (actor) =>
    JSON.parse(
      (
        await docker(
          'inspect',
          '--format',
          '{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},"path":{{json .Path}},"args":{{json .Args}},"memory":{{json .HostConfig.Memory}},"nanocpus":{{json .HostConfig.NanoCpus}},"pids":{{json .HostConfig.PidsLimit}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"mounts":{{json .Mounts}},"networks":{{json .NetworkSettings.Networks}},"owner":{{json (index .Config.Labels "io.openpc.fixture.owner")}},"observerInput":' +
            selectedEnvironment('IDENTITY_QUALIFICATION_OBSERVER_FILE') +
            ',"httpListen":' +
            selectedEnvironment('IDENTITY_LISTEN') +
            '}',
          actor.containerId,
        )
      ).toString('utf8'),
    );
  const adminBytes = await readQualificationObserverFile(input.adminConnectionFile, 8192);
  const admin = new Pool({
    connectionString: adminBytes.toString('utf8').trim(),
    max: 2,
    connectionTimeoutMillis: 2000,
    query_timeout: 5000,
  });
  adminBytes.fill(0);
  const primary = input.actors[0],
    secondary = input.actors[1],
    intent = host.deployment.intent;
  assert.equal(host.deployment.selection.installationId, primary.initialPins.installationId);
  const clients = [];
  const children = [];
  const started = new Set();
  let hostProcess;
  let firstFailure;
  const startHost = () => {
    const child = spawn(process.execPath, [input.hostBundle, '--serve', input.hostInputFile], {
      cwd: host.repositoryRoot,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const record = { child, pid: child.pid, text: '', code: undefined, signal: undefined };
    children.push(record);
    const output = (chunk) => {
      record.text += chunk.toString('utf8');
      if (record.text.length > 65536) {
        child.kill('SIGKILL');
        record.text = 'QUALIFICATION_PACKAGED_OUTPUT_OVERFLOW';
      }
    };
    child.stdout.on('data', output);
    child.stderr.on('data', output);
    record.done = new Promise((resolve) => {
      child.once('error', () => {
        record.code = 127;
        resolve();
      });
      child.once('exit', (code, signal) => {
        record.code = code;
        record.signal = signal;
        resolve();
      });
    });
    hostProcess = record;
    return record;
  };
  const stopHost = async (signal = 'SIGTERM') => {
    if (!hostProcess) return;
    const target = hostProcess;
    target.child.kill(signal);
    await until(
      () => target.code !== undefined || target.signal !== undefined,
      host.drainTimeoutMs + 5000,
    );
    if (signal === 'SIGTERM') assert.equal(target.code, 0, 'Real root must finish bounded drain');
  };
  const original = async () => {
    const r = await admin.query(
      `select a.request_bytes,a.request_digest,o.observation_bytes,o.observation_digest,o.observation
      from control.qualification_deployment_attempt a left join control.qualification_deployment_observation o using(observation_id)
      where a.observation_id=$1 and a.installation_id=$2 and a.participant_id=$3 and a.privacy_domain_id=$4`,
      [
        intent.observationId,
        primary.initialPins.installationId,
        primary.initialPins.participantId,
        primary.initialPins.privacyDomainId,
      ],
    );
    assert.ok(r.rowCount <= 1);
    return r.rows[0];
  };
  const localRead = async () =>
    JSON.parse(
      (
        await execute(
          process.execPath,
          [input.hostBundle, '--read-deployment-original', input.hostInputFile],
          { cwd: host.repositoryRoot, env: process.env, timeout: 20000, maxBuffer: 1024 * 1024 },
        )
      ).stdout,
    );
  const bootstrap = async (pins) => {
    const c = await admin.connect();
    try {
      await c.query('begin isolation level read committed');
      await c.query('set local role openpc_operations_qualification_bootstrap');
      await c.query('set local row_security=on');
      await c.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        [pins.participantId, pins.privacyDomainId, id()],
      );
      await installInitialQualificationDeployment(c, pins);
      await c.query('commit');
    } catch (error) {
      await c.query('rollback');
      throw error;
    } finally {
      c.release();
    }
  };
  try {
    for (const imageId of new Set(input.actors.map((a) => a.imageId))) {
      const image = JSON.parse(
        (
          await docker(
            'image',
            'inspect',
            '--format',
            '{"id":{{json .Id}},"owner":{{json (index .Config.Labels "io.openpc.image.owner")}},"service":{{json (index .Config.Labels "io.openpc.image.service")}}',
            imageId,
          )
        ).toString('utf8'),
      );
      assert.equal(image.id, imageId);
      assert.equal(image.owner, 'openpc-r1-local-runtime-v1');
      assert.equal(image.service, 'identity-service');
    }
    const roots = await admin.query(
      'select installation_id from control.qualification_deployment_installation where installation_id=any($1::uuid[])',
      [input.actors.map((a) => a.initialPins.installationId)],
    );
    assert.equal(roots.rowCount, 0, 'Fresh initial trust only; do not replay a retained case');
    for (const actor of input.actors) {
      const actual = await inspect(actor);
      assert.equal(actual.owner, input.ownerToken);
      assert.equal(actual.id, actor.containerId);
      assert.equal(actual.image, actor.imageId);
      assert.equal(actual.state.Status, 'created');
      assert.equal(actual.memory, actor.initialPins.memoryBytes);
      assert.equal(actual.nanocpus, actor.initialPins.nanoCpus);
      assert.equal(actual.pids, actor.initialPins.pidsLimit);
      assert.equal(actual.readonly, true);
      assert.equal(actual.privileged, false);
      assert.equal(actual.path, '/usr/local/bin/node');
      assert.deepEqual(actual.args, ['/app/server.mjs']);
      const mountedSource = (target) => {
        const matches = actual.mounts.filter(
          (m) =>
            m.Type === 'bind' &&
            !m.RW &&
            (target === m.Destination || target.startsWith(m.Destination + '/')),
        );
        assert.equal(
          matches.length,
          1,
          'Client input must resolve through one read-only installed mount',
        );
        return matches[0].Source + target.slice(matches[0].Destination.length);
      };
      assert.equal(
        actual.observerInput.length,
        2,
        'One explicit optional client input is required',
      );
      assert.equal(
        mountedSource(
          actual.observerInput[0].slice('IDENTITY_QUALIFICATION_OBSERVER_FILE='.length),
        ),
        actor.clientInputFile,
      );
      assert.equal(actual.httpListen.length, 2);
      const listen = /^IDENTITY_LISTEN=0[.]0[.]0[.]0:([1-9][0-9]{0,4})$/u.exec(
        actual.httpListen[0],
      );
      assert.ok(
        listen && Number(listen[1]) <= 65535,
        'Normal Identity must bind its prepared HTTP port',
      );
      actor.httpPort = Number(listen[1]);
      const config = qualificationObserverClientInputSchema.parse(
        JSON.parse(
          (await readQualificationObserverFile(actor.clientInputFile, 16384)).toString('utf8'),
        ),
      );
      assert.equal(config.origin, `https://${host.listen.address}:${host.listen.port}`);
      assert.equal(mountedSource(config.certificateFile), actor.clientCertificateFile);
      assert.equal(mountedSource(config.privateKeyFile), actor.clientPrivateKeyFile);
      clients.push(config);
    }
    assert.equal(clients[0].observationId, intent.observationId);
    assert.equal(clients[0].operationId, intent.operationId);
    // Finalize scenario inputs BEFORE either actual service starts. Each case
    // uses fresh identities/containers; a denial is never repaired into a pass.
    if (input.caseName === 'wrong-server-spki' || input.caseName === 'copied-credential')
      clients[0].serverSpkiDigest = 'sha256:' + 'f'.repeat(64);
    if (input.caseName === 'wrong-original') clients[0].operationId = id();
    if (input.caseName === 'copied-credential') {
      clients[1].observationId = intent.observationId;
      clients[1].operationId = intent.operationId;
      clients[1].clientCertificateDigest = clients[0].clientCertificateDigest;
      const key = await readQualificationObserverFile(primary.clientPrivateKeyFile, 16384);
      try {
        await writeFile(secondary.clientPrivateKeyFile, key, { mode: 0o600 });
      } finally {
        key.fill(0);
      }
      await writeFile(
        secondary.clientCertificateFile,
        await readQualificationObserverFile(primary.clientCertificateFile, 16384),
        { mode: 0o600 },
      );
    } else clients[1].serverSpkiDigest = 'sha256:' + 'e'.repeat(64); // independent sibling emits no accepted native intent
    for (let i = 0; i < 2; i++)
      await writeFile(input.actors[i].clientInputFile, JSON.stringify(clients[i]), { mode: 0o600 });
    for (const actor of input.actors) {
      started.add(actor.containerId);
      await docker('start', actor.containerId);
    }
    for (const actor of input.actors) {
      const actual = await inspect(actor);
      assert.equal(actual.state.Running, true);
      const networks = Object.values(actual.networks);
      assert.equal(networks.length, 1);
      await until(async () => {
        let response;
        try {
          response = await fetch(`http://${networks[0].IPAddress}:${actor.httpPort}/healthz`, {
            signal: AbortSignal.timeout(2000),
            redirect: 'error',
          });
        } catch {
          return false;
        }
        assert.equal(response.status, 200, 'Normal Identity health route must start');
        assert.deepEqual(await response.json(), { status: 'ok' });
        return true;
      }, 15000);
      const process = installationProcessIsolationSchema.parse(
        await readInstallationProcessIsolation(actual.state.Pid),
      );
      const artifact = readQualificationPublicArtifactArchive(
        await docker('cp', actor.containerId + ':/app/server.mjs', '-'),
        '/app/server.mjs',
        16 * 1024 * 1024,
      );
      const pins = parseQualificationDeploymentPins({
        ...actor.initialPins,
        containerId: actor.containerId,
        imageId: actor.imageId,
        containerStartedAt: actual.state.StartedAt,
        installedProcess: process,
        networkId: networks[0].NetworkID,
        address: networks[0].IPAddress,
        artifacts: [
          { path: '/app/server.mjs', digest: artifact.digest, maximumBytes: 16 * 1024 * 1024 },
        ],
      });
      await bootstrap(pins);
      actor.pins = pins;
    }
    // Actual source is installed before the root accepts traffic. Client bounded
    // pre-handshake recovery spans this startup ordering, without fake readiness.
    if (input.caseName === 'wrong-role') {
      await writeFile(
        host.ownerConnectionFile,
        await readQualificationObserverFile(host.identityConnectionFile, 8192),
        { mode: 0o600 },
      );
    }
    let launched = startHost();
    if (input.caseName === 'wrong-role') {
      await until(() => launched.code !== undefined, 20000);
      assert.notEqual(launched.code, 0);
      assert.ok(!launched.text.includes('|LISTENING|'));
      assert.equal(await original(), undefined);
    } else {
      await until(() => {
        assert.equal(launched.code, undefined, 'host startup failed');
        return launched.text.includes('QUALIFICATION_OBSERVER|LISTENING|OBSERVATION_ONLY');
      }, 20000);
      if (['wrong-server-spki', 'wrong-original', 'copied-credential'].includes(input.caseName)) {
        await until(
          async () =>
            (
              await docker(
                'logs',
                input.caseName === 'copied-credential'
                  ? secondary.containerId
                  : primary.containerId,
              )
            )
              .toString()
              .includes('IDENTITY_QUALIFICATION_OBSERVER|UNKNOWN|HISTORICAL_ONLY'),
          90000,
        );
        assert.equal(await original(), undefined);
      } else if (input.caseName === 'committed-host-crash') {
        const reserved = await until(original);
        assert.equal(
          reserved.observation_bytes,
          null,
          'Crash must occur after reservation and before result retention',
        );
        await stopHost('SIGKILL');
        const afterCrash = await original();
        assert.deepEqual(afterCrash.request_bytes, reserved.request_bytes);
        assert.equal(
          afterCrash.observation_bytes,
          null,
          'An already completed observation does not prove the uncertain crash phase',
        );
        const oldPid = launched.pid;
        launched = startHost();
        assert.notEqual(launched.pid, oldPid);
        await until(() => launched.text.includes('|LISTENING|'), 20000);
        const read = await localRead();
        assert.equal(read.readback, 'HISTORICAL_ONLY');
        assert.equal(qualificationDeploymentDigest(read.request), afterCrash.request_digest);
        await until(
          async () =>
            (await docker('logs', primary.containerId))
              .toString()
              .includes('IDENTITY_QUALIFICATION_OBSERVER|ORIGINAL_PENDING|HISTORICAL_ONLY'),
          90000,
        );
        const later = await original();
        assert.deepEqual(later.request_bytes, afterCrash.request_bytes);
        assert.deepEqual(later.observation_bytes, afterCrash.observation_bytes);
      } else if (input.caseName === 'lost-reply-subject-restart') {
        const reserved = await until(original);
        assert.equal(
          reserved.observation_bytes,
          null,
          'Subject interruption must precede retained response',
        );
        await docker('kill', '--signal', 'KILL', primary.containerId);
        await until(async () => (await original())?.observation_bytes, 35000);
        const stored = await original();
        await docker('start', primary.containerId);
        await until(
          async () =>
            (await docker('logs', primary.containerId))
              .toString()
              .includes('IDENTITY_QUALIFICATION_OBSERVER|ORIGINAL_RETAINED|HISTORICAL_ONLY'),
          90000,
        );
        assert.deepEqual((await original()).observation_bytes, stored.observation_bytes);
        assert.equal((await localRead()).readback, 'HISTORICAL_ONLY');
      } else if (input.caseName === 'bounded-drain') {
        await until(original);
        launched.child.kill('SIGTERM');
        launched.child.kill('SIGINT');
        await until(() => launched.code !== undefined, host.drainTimeoutMs + 5000);
        assert.equal(launched.code, 0);
        const stored = await original();
        const read = await localRead();
        assert.equal(qualificationDeploymentDigest(read.request), stored.request_digest);
      } else {
        const stored = await until(async () => {
          const r = await original();
          return r?.observation_bytes ? r : undefined;
        }, 35000);
        {
          assert.equal(stored.observation.state, 'OBSERVED');
          assert.equal(stored.observation.measurement.instance.containerId, primary.containerId);
          assert.equal(stored.observation.measurement.qualification, 'UNESTABLISHED');
          if (input.caseName === 'positive-root-restart') {
            const before = await localRead(),
              oldPid = launched.pid;
            await stopHost();
            launched = startHost();
            assert.notEqual(launched.pid, oldPid);
            await until(() => launched.text.includes('|LISTENING|'), 20000);
            assert.deepEqual(await localRead(), before);
          } else {
            await admin.query(
              "update control.credential set state='REVOKED',credential_epoch=credential_epoch+1 where credential_id=$1",
              [primary.initialPins.peer.credentialId],
            );
            const initialLogs = (await docker('logs', primary.containerId)).toString();
            await docker('restart', primary.containerId);
            await until(async () => {
              const text = (await docker('logs', primary.containerId)).toString();
              return (
                text.length > initialLogs.length &&
                text
                  .slice(initialLogs.length)
                  .includes('IDENTITY_QUALIFICATION_OBSERVER|UNKNOWN|HISTORICAL_ONLY')
              );
            }, 90000);
            assert.deepEqual((await original()).observation_bytes, stored.observation_bytes);
            assert.equal((await localRead()).readback, 'HISTORICAL_ONLY');
          }
        }
      }
    }
    const count = (
      await admin.query(
        'select count(*)::int n from control.qualification_deployment_attempt where observation_id=$1',
        [intent.observationId],
      )
    ).rows[0].n;
    assert.ok(count <= 1);
    assert.equal(
      (
        await admin.query(
          'select count(*)::int n from control.operations_provider_retry_qualification where environment_id=$1',
          [primary.initialPins.environmentId],
        )
      ).rows[0].n,
      0,
    );
  } catch (error) {
    firstFailure = error;
  }
  const cleanup = [];
  for (const record of children) {
    if (record.code === undefined && record.signal === undefined) {
      record.child.kill('SIGTERM');
      try {
        await until(
          () => record.code !== undefined || record.signal !== undefined,
          host.drainTimeoutMs + 5000,
        );
      } catch (error) {
        record.child.kill('SIGKILL');
        cleanup.push(error);
      }
    }
  }
  for (const actor of input.actors) {
    if (!started.has(actor.containerId)) continue;
    try {
      const actual = await inspect(actor);
      assert.equal(actual.owner, input.ownerToken);
      if (actual.state.Running) await docker('stop', '--time', '45', actor.containerId);
    } catch (error) {
      cleanup.push(error);
    }
  }
  try {
    await admin.end();
  } catch (error) {
    cleanup.push(error);
  }
  if (firstFailure || cleanup.length)
    throw new AggregateError(
      [...(firstFailure ? [firstFailure] : []), ...cleanup],
      'QUALIFICATION_PACKAGED_CASE_FAILED',
    );
  return { caseName: input.caseName, result: 'PASS', claim: 'PACKAGED_NATIVE_OBSERVATION_ONLY' };
}
