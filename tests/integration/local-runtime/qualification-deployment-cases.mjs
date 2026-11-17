import { tmpdir } from 'node:os';
/** Cases for the existing canonical bounded PG/local-runtime dispatch. No
 * standalone daemon/build/runner: two owned finite clients, real host product
 * observer and actual Identity/Control stores. Never run against retained data. */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { generateKeyPairSync } from 'node:crypto';
import { channel } from 'node:diagnostics_channel';
import { mkdtemp, mkdir, readFile, writeFile, rename, rm, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Pool } from 'pg';
import { runtimeSnapshotTlsFixture } from '../identity/runtime-snapshot-tls-fixture.ts';
import {
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../../services/identity-service/src/domain/identity-kernel.ts';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.ts';
import { createQualificationDeploymentPeer } from '../../../services/identity-service/src/domain/qualification-deployment-peer.ts';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { withAuthenticatedWorkloadPeer } from '../../../services/identity-service/src/domain/workload-peer.ts';
import {
  installInitialQualificationDeployment,
  withdrawQualificationDeployment,
  readQualificationDeployment,
  reserveQualificationDeployment,
} from '../../../services/control-api/src/configuration/operations/qualification-deployment-observation.ts';
import { readInstallationProcessIsolation } from '../../../scripts/operations/installation-process-observation.mjs';
import {
  parseQualificationDeploymentPins,
  readQualificationPublicArtifactArchive,
  qualificationDeploymentDigest,
  readCollectedQualificationDeployment,
} from '../../../scripts/operations/qualification-deployment-observation.mjs';
import {
  qualificationDigest as hash,
  qualificationCanonicalJson as canonical,
} from '../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.ts';
import { readPublicOperationsSources } from '../../../scripts/operations/read-public-installation-sources.mjs';
import { installInitialOperationsEnvironment } from '../../../scripts/operations/installation-generation-store.mjs';

const repository = fileURLToPath(new URL('../../../', import.meta.url));
const execute = promisify(execFile);
const clientCode = `const f=require('fs'),h=require('https');let last='',busy=false;setInterval(()=>{if(busy)return;let s;try{s=f.readFileSync('/run/client/command','utf8')}catch{return}if(s===last)return;last=s;busy=true;let c=JSON.parse(s);let q=h.request({...c.options,ca:f.readFileSync('/run/client/ca'),cert:f.readFileSync('/run/client/cert'),key:f.readFileSync('/run/client/key')},r=>{let b='';r.on('data',x=>b+=x);r.on('end',()=>{console.log(JSON.stringify({seq:c.seq,status:r.statusCode,body:JSON.parse(b)}));busy=false})});q.on('error',()=>{console.log(JSON.stringify({seq:c.seq,status:0}));busy=false});q.end(JSON.stringify(c.body))},20)`;
export const qualificationDeploymentClientArguments = Object.freeze(['-e', clientCode]);
export const qualificationDeploymentCaseNames = Object.freeze([
  'native-original-restart',
  'isolation-and-artifact-denial',
  'copied-peer-and-epoch',
  'withdrawal-and-role',
  'reservation-gap-and-readback',
  'substitution-and-promotion',
]);
function fail() {
  throw new Error('QUALIFICATION_DEPLOYMENT_NATIVE_CASE_FAILED');
}
async function fixture() {
  assert.ok(qualificationDeploymentClientArguments.every((v) => v.length <= 2048));
  assert.match(
    process.env.OPENPC_QUALIFICATION_DEPLOYMENT_IMAGE_ID ?? '',
    /^sha256:[0-9a-f]{64}$/u,
  );
  assert.ok(
    process.env.OPENPC_I02_ADMIN_DATABASE_URL && process.env.OPENPC_I02_RUNTIME_DATABASE_URL,
  );
  // Validate actual inherited lock, cgroup caps, live headroom and disk through
  // the canonical guard. 1.25 GiB DB + two 128 MiB clients = 1.5 GiB external.
  await execute(
    'bash',
    [
      join(repository, 'scripts/maintenance/run-bounded.sh'),
      '--memory-gib',
      '1',
      '--external-memory-gib',
      '1.5',
      '--peak-disk-gib',
      '10',
      '--reuse',
      '--',
      'true',
    ],
    { cwd: repository, timeout: 10000, maxBuffer: 8192 },
  );
  const docker = async (...args) =>
    (
      await execute('docker', ['--host', 'unix:///var/run/docker.sock', ...args], {
        timeout: 10000,
        maxBuffer: 20 * 1024 * 1024,
        encoding: 'buffer',
      })
    ).stdout;
  const json = async (...args) => JSON.parse((await docker(...args)).toString('utf8'));
  const imageId = process.env.OPENPC_QUALIFICATION_DEPLOYMENT_IMAGE_ID;
  const images = await json('image', 'inspect', imageId);
  assert.equal(images.length, 1);
  assert.equal(images[0].Id, imageId);
  assert.equal(images[0].Os, 'linux');
  assert.equal(images[0].Architecture, 'amd64');
  assert.equal(images[0].Config.Labels?.['io.openpc.image.owner'], 'openpc-r1-local-runtime-v1');
  assert.equal(images[0].Config.Labels?.['io.openpc.image.service'], 'identity-service');
  const daemonId = (await docker('info', '--format', '{{.ID}}')).toString().trim();
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'qualification-deployment-'),
  );
  assert.ok(!(await realpath(root)).startsWith(resolve(repository) + '/'));
  const token = 'qualification-deployment-' + id(),
    containers = [],
    networks = [],
    actors = [];
  const admin = new Pool({ connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL, max: 2 });
  const runtime = new Pool({
    connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL,
    max: 2,
  });
  const owner = new Pool({
    connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL,
    options: '-c role=openpc_operations_qualification_owner',
    max: 2,
  });
  const participantId = id(),
    privacyDomainId = id(),
    environmentId = 'dep-' + id().slice(-12);
  let app,
    port,
    adapter,
    sequence = 0;
  const tx = async (role, fn, commit = false) => {
    assert.ok(
      [
        'openpc_control_owner',
        'openpc_operations_qualification_bootstrap',
        'openpc_operations_qualification_owner',
        'openpc_identity_runtime',
      ].includes(role),
    );
    const c = await admin.connect();
    await c.query('begin isolation level read committed');
    try {
      await c.query(`set local role ${role}`);
      await c.query('set local row_security=on');
      await c.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        [participantId, privacyDomainId, id()],
      );
      const result = await fn(c);
      await c.query(commit ? 'commit' : 'rollback');
      return result;
    } catch (e) {
      await c.query('rollback');
      throw e;
    } finally {
      c.release();
    }
  };
  const close = async () => {
    const failures = [];
    try {
      await app?.close();
    } catch (e) {
      failures.push(e);
    }
    for (const container of containers.reverse())
      try {
        const actual = await json(
          'inspect',
          '--format',
          '{"owner":{{json (index .Config.Labels "io.openpc.fixture.owner")}}}',
          container,
        );
        assert.equal(actual.owner, token);
        await docker('rm', '--force', container);
      } catch (e) {
        failures.push(e);
      }
    for (const network of networks.reverse())
      try {
        await docker('network', 'rm', network);
      } catch (e) {
        failures.push(e);
      }
    for (const result of await Promise.allSettled([
      admin.end(),
      runtime.end(),
      owner.end(),
      ...actors.map((actor) => actor.tls.close()),
    ]))
      if (result.status === 'rejected') failures.push(result.reason);
    if (failures.length)
      throw new AggregateError(failures, 'QUALIFICATION_DEPLOYMENT_CLEANUP_UNKNOWN');
    await rm(root, { recursive: true, force: true });
  };
  try {
    await admin.query(
      "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Deployment initial trust','ACTIVE',1)",
      [participantId],
    );
    await admin.query(
      "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Deployment initial trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
      [privacyDomainId, participantId],
    );
    for (let n = 0; n < 2; n++) {
      const principalId = id(),
        credentialId = id(),
        workloadId = 'urn:openpc:workload:' + id(),
        uri = `urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`;
      const tls = await runtimeSnapshotTlsFixture(uri, 'deployment-observer');
      const actor = { tls, directory: join(root, 'client-' + n), installationId: id() };
      actors.push(actor);
      const spki = tls.parsed.publicKey.export({ type: 'spki', format: 'der' });
      const peer = {
        principalId,
        credentialId,
        participantEpoch: '1',
        principalEpoch: '1',
        credentialEpoch: '1',
        workloadId,
        keyDigest: hash(spki),
        certificateDigest: hash(tls.parsed.raw),
      };
      actor.peer = peer;
      await admin.query(
        "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD',$3,'ACTIVE',1)",
        [principalId, participantId, 'Deployment ' + n],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until) values($1,$2,$3,'WORKLOAD_MTLS','deployment-local-test',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          credentialId,
          participantId,
          principalId,
          uri,
          workloadId,
          Buffer.from(peer.keyDigest.slice(7), 'hex'),
          spki,
          Buffer.from(peer.certificateDigest.slice(7), 'hex'),
          new Date(tls.parsed.validFrom),
          new Date(tls.parsed.validTo),
        ],
      );
      await mkdir(actor.directory, { mode: 0o700 });
    }
    const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
        format: 'der',
        type: 'spki',
      }),
      at = Date.now();
    const schemaBytes = await readFile(
        join(repository, 'config/schema/effective-configuration.schema.json'),
      ),
      profileBytes = await readFile(join(repository, 'config/profiles/local.yaml'));
    const sourceAuthentication = (
      await readPublicOperationsSources({
        sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
        profile: 'local',
      })
    ).custody;
    await installInitialOperationsEnvironment(
      admin,
      { participantId, privacyDomainId },
      {
        pins: {
          environmentId,
          profile: 'local',
          issuerSpkiHex: key.toString('hex'),
          issuerEpoch: '1',
          issuerValidFromMs: at - 1000,
          issuerValidUntilMs: at + 600000,
          configurationSchemaDigest: hash(schemaBytes),
          namedProfileDigest: hash(profileBytes),
        },
        initialBaseGenerationId: id(),
        schemaBytes,
        profileBytes,
        sourceAuthentication,
      },
    );
    const installationDigest = (
      await admin.query(
        'select installation_digest from control.operations_installation where environment_id=$1',
        [environmentId],
      )
    ).rows[0].installation_digest;
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    adapter = createQualificationDeploymentPeer({ ownerPool: owner, kernel });
    app = buildLocalWorkloadMtlsService(runtime, kernel, {
      ...actors[0].tls.server,
      ca: Buffer.concat(actors.map((v) => v.tls.server.ca)),
    });
    app.post('/test/deployment-observation', async (request, reply) => {
      try {
        const { selection, intent, reserveOnly, dropReply } = request.body;
        if (reserveOnly) {
          // Real committed native reservation, then intentional simulated host
          // stop BEFORE any inspection. This is the exact absent-result phase,
          // not a seeded success or a fake native collector.
          await withAuthenticatedWorkloadPeer(
            owner,
            kernel,
            request.raw.socket,
            async (c, identity, confirm) => {
              const actor = actors.find((v) => v.peer.principalId === identity.principalId);
              assert.ok(actor);
              await confirm();
              await reserveQualificationDeployment(c, selection, actor.peer, intent);
              await confirm();
            },
            selection,
          );
          return { reserved: true };
        }
        const result = await adapter.observe(request.raw.socket, selection, intent);
        if (dropReply) {
          reply.raw.destroy();
          return reply;
        }
        return result;
      } catch {
        return reply.code(403).send({ code: 'QUALIFICATION_DEPLOYMENT_REJECTED' });
      }
    });
    await app.listen({ host: '0.0.0.0', port: 0 });
    port = app.server.address().port;
    for (const [n, actor] of actors.entries()) {
      const network = (
        await docker(
          'network',
          'create',
          '--internal',
          '--label',
          'io.openpc.fixture.owner=' + token,
          token + '-' + n,
        )
      )
        .toString()
        .trim();
      networks.push(network);
      const net = (await json('network', 'inspect', network))[0];
      actor.gateway = net.IPAM.Config[0].Gateway;
      await writeFile(join(actor.directory, 'ca'), actors[0].tls.server.ca, { mode: 0o600 });
      await writeFile(join(actor.directory, 'cert'), actor.tls.certificate, { mode: 0o600 });
      await writeFile(join(actor.directory, 'key'), actor.tls.privateKey, { mode: 0o600 });
      const uid = process.getuid();
      assert.ok(uid > 0, 'Native fixture must run as the admitted non-root host owner');
      const container = (
        await docker(
          'create',
          '--label',
          'io.openpc.fixture.owner=' + token,
          '--network',
          network,
          '--read-only',
          '--cap-drop',
          'ALL',
          '--security-opt',
          'no-new-privileges:true',
          '--ipc',
          'private',
          '--cgroupns',
          'private',
          '--memory',
          '134217728',
          '--memory-swap',
          '134217728',
          '--cpus',
          '0.5',
          '--pids-limit',
          '32',
          '--user',
          String(uid) + ':' + String(process.getgid()),
          '--mount',
          `type=bind,src=${actor.directory},dst=/run/client,readonly,bind-propagation=rprivate`,
          '--entrypoint',
          '/usr/local/bin/node',
          imageId,
          ...qualificationDeploymentClientArguments,
        )
      )
        .toString()
        .trim();
      containers.push(container);
      actor.container = container;
      await docker('start', container);
      const current = (await json('inspect', container))[0],
        networkState = Object.values(current.NetworkSettings.Networks)[0];
      const artifact = readQualificationPublicArtifactArchive(
        await docker('cp', container + ':/app/server.mjs', '-'),
        '/app/server.mjs',
        16 * 1024 * 1024,
      );
      actor.pins = parseQualificationDeploymentPins({
        schemaVersion: 1,
        installationId: actor.installationId,
        participantId,
        privacyDomainId,
        environmentId,
        operationsInstallationDigest: installationDigest,
        peer: actor.peer,
        daemonId,
        engineEndpoint: 'unix:///var/run/docker.sock',
        containerId: container,
        imageId,
        containerStartedAt: current.State.StartedAt,
        installedProcess: await readInstallationProcessIsolation(current.State.Pid),
        expectedUid: uid,
        executable: '/usr/local/bin/node',
        argv: [...qualificationDeploymentClientArguments],
        networkId: network,
        address: networkState.IPAddress,
        memoryBytes: 134217728,
        nanoCpus: 500000000,
        pidsLimit: 32,
        mounts: [
          { source: actor.directory, target: '/run/client', kind: 'CREDENTIAL', readOnly: true },
        ],
        tmpfsTargets: [],
        artifacts: [
          { path: '/app/server.mjs', digest: artifact.digest, maximumBytes: 16 * 1024 * 1024 },
        ],
        separatedFrom: [actors[1 - n].installationId],
      });
    }
    for (const actor of actors)
      await tx(
        'openpc_operations_qualification_bootstrap',
        (c) => installInitialQualificationDeployment(c, actor.pins),
        true,
      );
    const selection = (actor) => ({
      participantId,
      privacyDomainId,
      installationId: actor.installationId,
    });
    const observe = async (
      actor = actors[0],
      intent = { observationId: id(), operationId: id() },
      extra = {},
    ) => {
      const seq = ++sequence,
        command = {
          seq,
          options: {
            host: actor.gateway,
            port,
            servername: 'deployment-observer',
            path: '/test/deployment-observation',
            method: 'POST',
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',
            headers: { 'content-type': 'application/json' },
          },
          body: { selection: selection(actor), intent, ...extra },
        };
      await writeFile(join(actor.directory, 'next'), JSON.stringify(command), { mode: 0o600 });
      await rename(join(actor.directory, 'next'), join(actor.directory, 'command'));
      const deadline = Date.now() + 35000;
      while (Date.now() < deadline) {
        const logs = (await docker('logs', actor.container)).toString('utf8');
        for (const line of logs.trim().split('\n'))
          if (line.startsWith('{')) {
            const result = JSON.parse(line);
            if (result.seq === seq) return { ...result, intent };
          }
        await new Promise((r) => setTimeout(r, 50));
      }
      return fail();
    };
    const waitReserved = async (intent) => {
      const deadline = Date.now() + 10000;
      while (Date.now() < deadline) {
        const row = (
          await admin.query(
            'select request from control.qualification_deployment_attempt where observation_id=$1 and participant_id=$2 and privacy_domain_id=$3',
            [intent.observationId, participantId, privacyDomainId],
          )
        ).rows[0];
        if (row) return row.request;
        await new Promise((r) => setTimeout(r, 5));
      }
      throw new Error('Deployment reservation barrier was not reached');
    };
    return {
      root,
      actors,
      admin,
      owner,
      selection,
      tx,
      observe,
      waitReserved,
      docker,
      json,
      close,
      get adapter() {
        return adapter;
      },
      restartAdapter() {
        adapter = createQualificationDeploymentPeer({ ownerPool: owner, kernel });
      },
    };
  } catch (e) {
    try {
      await close();
    } catch (cleanupError) {
      throw new AggregateError([e, cleanupError], 'Deployment setup and cleanup failed');
    }
    throw e;
  }
}

/** Each name owns fresh scope, two clients, keys, network and business IDs.
 * Internal identity, SQL and observation owners remain real. */
export async function runQualificationDeploymentCase(name) {
  assert.ok(qualificationDeploymentCaseNames.includes(name));
  const f = await fixture();
  const diagnostics = channel('openpc.qualification.deployment-observation');
  const recordFailure = (value) => {
    // This native collector channel contains codes only. Fail closed on an
    // unexpected diagnostic shape; never stringify an exception or inspect data.
    const stage =
      /^(?:PIN_SET|HOST_PROCESS|DAEMON_BEFORE|SEPARATION|NETWORK_BEFORE|ARTIFACT_METADATA_BEFORE|ARTIFACT_ARCHIVE|ARTIFACT_METADATA_AFTER|SUBJECT_STABILITY|PEER_STABILITY|NETWORK_AFTER|DAEMON_AFTER|MEASUREMENT|(?:SUBJECT|PEER)_(?:BEFORE|AFTER)_(?:INSPECT|INSPECT_JSON|PROCFS|PROFILE|MOUNTS))$/u;
    const code =
      /^(?:REJECTED|INVALID_SHAPE|IO_DENIED|IO_ABSENT|TIMEOUT|OUTPUT_LIMIT|PROCESS_KILLED|TEMPLATE_TMPFS|TEMPLATE_UTS_MODE|TEMPLATE_REJECTED|PROCESS_EXIT|JSON_INVALID|NATIVE_ERROR|DOCKER_STDERR|DAEMON_SOCKET|DAEMON_PROFILE|DAEMON_IDENTITY|CONTAINER_IDENTITY|PROCESS_IDENTITY|PROCESS_SECURITY|NATIVE_LIMITS|CGROUP_IDENTITY|DECLARED_ISOLATION|NAMESPACE_ISOLATION|NETWORK_BINDING|ARTIFACT_DIGEST|ARTIFACT_SIZE)$/u;
    if (
      value &&
      typeof value.stage === 'string' &&
      typeof value.code === 'string' &&
      stage.test(value.stage) &&
      code.test(value.code)
    )
      process.stderr.write(
        'OPENPC_QUALIFICATION_DEPLOYMENT_FAILURE|stage=' +
          value.stage +
          '|code=' +
          value.code +
          '\n',
      );
    else
      process.stderr.write(
        'OPENPC_QUALIFICATION_DEPLOYMENT_FAILURE|stage=DIAGNOSTIC|code=REJECTED\n',
      );
  };
  diagnostics.subscribe(recordFailure);
  let firstFailure;
  try {
    const a = f.actors[0],
      s = f.selection(a);
    if (name === 'native-original-restart') {
      const lost = await f.observe(
        a,
        { observationId: id(), operationId: id() },
        { dropReply: true },
      );
      assert.equal(lost.status, 0);
      const first = {
        intent: lost.intent,
        body: await f.adapter.readOriginal(s, lost.intent.observationId),
      };
      assert.equal(first.body.observation.state, 'OBSERVED');
      assert.equal(first.body.readback, 'HISTORICAL_ONLY');
      assert.equal(first.body.observation.measurement.scope, 'CONTAINER_WORKLOAD');
      assert.equal(first.body.observation.measurement.changeAuthorship, 'UNESTABLISHED');
      assert.equal(first.body.observation.measurement.sourceBuildLink, 'UNESTABLISHED');
      f.restartAdapter();
      const replay = await f.observe(a, first.intent);
      assert.deepEqual(replay.body, first.body);
      // The disposable client runs as PID 1. Bound its stop grace below the
      // native-command deadline so a real restart can finish and be observed.
      await f.docker('restart', '--timeout', '1', a.container);
      const denied = await f.observe(a);
      assert.equal(denied.status, 200);
      assert.equal(denied.body.observation.state, 'UNKNOWN');
      assert.deepEqual(await f.adapter.readOriginal(s, first.intent.observationId), first.body);
    } else if (name === 'isolation-and-artifact-denial') {
      // A live resource change is native state, not a caller observation object.
      await f.docker('update', '--pids-limit', '64', a.container);
      const rejected = await f.observe();
      assert.equal(rejected.status, 200);
      assert.equal(rejected.body.observation.state, 'UNKNOWN');
      assert.equal(rejected.body.observation.measurement, null);
      await f.docker('update', '--pids-limit', '32', a.container);
      const wrong = {
        ...a.pins,
        installationId: id(),
        artifacts: [{ ...a.pins.artifacts[0], digest: 'sha256:' + 'f'.repeat(64) }],
      };
      await f.tx(
        'openpc_operations_qualification_bootstrap',
        (c) => installInitialQualificationDeployment(c, wrong),
        true,
      );
      const originalId = a.installationId;
      a.installationId = wrong.installationId;
      const artifact = await f.observe();
      a.installationId = originalId;
      assert.equal(artifact.status, 200);
      assert.equal(artifact.body.observation.state, 'UNKNOWN');
    } else if (name === 'copied-peer-and-epoch') {
      const first = await f.observe();
      assert.equal(first.body.observation.state, 'OBSERVED');
      const b = f.actors[1];
      await writeFile(join(b.directory, 'cert'), a.tls.certificate);
      await writeFile(join(b.directory, 'key'), a.tls.privateKey);
      const wrong = await f.observe(
        b,
        { observationId: id(), operationId: id() },
        { selection: s },
      );
      assert.equal(wrong.status, 200);
      assert.equal(wrong.body.observation.state, 'UNKNOWN');
      await f.admin.query(
        "update control.credential set state='REVOKED',credential_epoch=credential_epoch+1 where credential_id=$1",
        [a.peer.credentialId],
      );
      const denied = await f.observe();
      assert.equal(denied.status, 403);
      assert.deepEqual(await f.adapter.readOriginal(s, first.intent.observationId), first.body);
    } else if (name === 'withdrawal-and-role') {
      const first = await f.observe();
      assert.equal(first.body.observation.state, 'OBSERVED');
      const racingIntent = { observationId: id(), operationId: id() };
      const pending = f.observe(a, racingIntent);
      // Attach a rejection handler immediately; the original failure is still
      // awaited and propagated below, never converted into a passing sibling.
      pending.catch(() => undefined);
      const original = await f.waitReserved(racingIntent);
      const invalidatedAt = await f.tx(
        'openpc_operations_qualification_bootstrap',
        async (c) => {
          await withdrawQualificationDeployment(c, s);
          return Number(
            (await c.query('select floor(extract(epoch from clock_timestamp())*1000)::text ms'))
              .rows[0].ms,
          );
        },
        true,
      );
      const withdrawalCommittedAt = Date.now();
      const late = await pending;
      assert.equal(late.status, 200);
      assert.equal(late.body.observation.state, 'HISTORICAL');
      assert.ok(late.body.observation.measurement.startedAtMs <= invalidatedAt);
      assert.ok(invalidatedAt <= late.body.observation.measurement.completedAtMs);
      assert.ok(withdrawalCommittedAt <= late.body.observation.measurement.completedAtMs);
      assert.ok(late.body.observation.measurement.completedAtMs < original.deadlineAtMs);

      await assert.rejects(
        f.tx(
          'openpc_operations_qualification_bootstrap',
          (c) => installInitialQualificationDeployment(c, a.pins),
          true,
        ),
      );
      assert.equal((await f.observe()).status, 403);
      await assert.rejects(
        f.tx('openpc_identity_runtime', (c) =>
          readQualificationDeployment(c, s, first.intent.observationId),
        ),
      );
      assert.deepEqual(await f.adapter.readOriginal(s, first.intent.observationId), first.body);
      for (const sql of [
        'delete from control.qualification_deployment_observation',
        'truncate control.qualification_deployment_observation',
        'update control.qualification_deployment_attempt set operation_id=gen_random_uuid()',
      ])
        await assert.rejects(f.tx('openpc_control_owner', (c) => c.query(sql)));
    } else if (name === 'reservation-gap-and-readback') {
      const intent = { observationId: id(), operationId: id() };
      assert.equal((await f.observe(a, intent, { reserveOnly: true })).status, 200);
      f.restartAdapter();
      const replay = await f.observe(a, intent);
      assert.equal(replay.status, 200);
      assert.equal(replay.body.observation, null);
      assert.equal(replay.body.readback, 'HISTORICAL_ONLY');
      const stored = await f.tx('openpc_control_owner', (c) =>
        readQualificationDeployment(c, s, intent.observationId),
      );
      assert.deepEqual(stored, replay.body);
      assert.equal((await f.observe(a, { ...intent, operationId: id() })).status, 403);
      // Consume the actual original deadline without changing the clock, intent
      // or credentials. Expiry never grants another native inspection attempt.
      while (Date.now() <= stored.request.deadlineAtMs)
        await new Promise((resolve) =>
          setTimeout(resolve, Math.min(1000, stored.request.deadlineAtMs - Date.now() + 1)),
        );
      const expired = await f.observe(a, intent);
      assert.equal(expired.status, 200);
      assert.deepEqual(expired.body, stored);
    } else {
      const first = await f.observe();
      assert.equal(first.body.observation.state, 'OBSERVED');
      assert.throws(() => readCollectedQualificationDeployment(first.body.observation.measurement));
      await assert.rejects(
        f.tx('openpc_control_owner', (c) =>
          readQualificationDeployment(
            c,
            { ...s, privacyDomainId: id() },
            first.intent.observationId,
          ),
        ),
      );
      const stored = first.body.observation;
      for (const mutation of [{ separatedPins: [] }, { current: true }]) {
        const malformed = {
          ...first.body.request,
          observationId: id(),
          operationId: id(),
          ...mutation,
        };
        await assert.rejects(
          f.tx('openpc_operations_qualification_owner', (c) =>
            c.query(
              'insert into control.qualification_deployment_attempt(observation_id,installation_id,participant_id,privacy_domain_id,operation_id,request,request_bytes,request_digest) values($1,$2,$3,$4,$5,$6,$7,$8)',
              [
                malformed.observationId,
                a.installationId,
                s.participantId,
                s.privacyDomainId,
                malformed.operationId,
                malformed,
                Buffer.from(canonical(malformed)),
                qualificationDeploymentDigest(malformed),
              ],
            ),
          ),
          /QUALIFICATION_DEPLOYMENT_(REQUEST|SEPARATION)/u,
        );
      }
      const malformed = { ...stored, state: null };
      await assert.rejects(
        f.tx('openpc_operations_qualification_owner', (c) =>
          c.query(
            'insert into control.qualification_deployment_observation(observation_id,participant_id,privacy_domain_id,observation,observation_bytes,observation_digest) values($1,$2,$3,$4,$5,$6)',
            [
              first.intent.observationId,
              s.participantId,
              s.privacyDomainId,
              malformed,
              Buffer.from(canonical(malformed)),
              qualificationDeploymentDigest(malformed),
            ],
          ),
        ),
        /QUALIFICATION_DEPLOYMENT_RESULT/u,
      );
      await assert.rejects(
        f.tx('openpc_control_owner', (c) =>
          c.query(
            "update control.qualification_deployment_observation set observation=jsonb_set(observation,'{measurement,qualification}','\"ACTIVE\"') where observation_id=$1",
            [first.intent.observationId],
          ),
        ),
      );
      const count = (
        await f.admin.query(
          'select count(*)::int n from control.qualification_deployment_attempt where installation_id=$1',
          [a.installationId],
        )
      ).rows[0].n;
      assert.equal(count, 1);
      assert.equal(stored.measurement.qualification, 'UNESTABLISHED');
      assert.equal(
        (
          await f.admin.query(
            'select count(*)::int n from control.operations_provider_retry_qualification where environment_id=$1',
            [a.pins.environmentId],
          )
        ).rows[0].n,
        0,
      );
      assert.equal(
        qualificationDeploymentDigest(
          (await f.adapter.readOriginal(s, first.intent.observationId)).observation,
        ),
        qualificationDeploymentDigest(stored),
      );
    }
  } catch (error) {
    firstFailure = error;
  } finally {
    diagnostics.unsubscribe(recordFailure);
  }
  try {
    await f.close();
  } catch (cleanupError) {
    if (firstFailure)
      throw new AggregateError([firstFailure, cleanupError], 'Deployment case and cleanup failed');
    throw cleanupError;
  }
  if (firstFailure) throw firstFailure;
  return { name, result: 'PASS', claim: 'NATIVE_OBSERVATION_ONLY' };
}
