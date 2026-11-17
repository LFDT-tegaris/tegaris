import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { channel } from 'node:diagnostics_channel';
import { readFile } from 'node:fs/promises';
import {
  parseQualificationDeploymentPins,
  readQualificationPublicArtifactArchive,
  validateQualificationContainerSnapshot,
  readCollectedQualificationDeployment,
  validateQualificationArtifactMetadata,
  collectQualificationDeployment,
} from './qualification-deployment-observation.mjs';
const uuid = (n) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = (v) => 'sha256:' + v.repeat(64);
test('failed collection publishes only fixed codes and cannot emit observation authority', async () => {
  const diagnostics = channel('openpc.qualification.deployment-observation');
  const events = [];
  const receive = (value) => events.push(value);
  diagnostics.subscribe(receive);
  try {
    const pins = fixture().pins;
    pins.argv = ['private-value-must-not-appear'];
    pins.separatedFrom = [uuid(9)];
    await assert.rejects(
      collectQualificationDeployment(
        pins,
        [],
        { remoteAddress: 'secret', localAddress: 'secret' },
        {
          observationId: uuid(8),
          requestDigest: h('a'),
        },
      ),
      { message: 'QUALIFICATION_DEPLOYMENT_OBSERVATION_UNKNOWN' },
    );
    assert.deepEqual(events, [{ stage: 'PIN_SET', code: 'REJECTED' }]);
    assert.ok(Object.isFrozen(events[0]));
    assert.throws(() => readCollectedQualificationDeployment(events[0]));
  } finally {
    diagnostics.unsubscribe(receive);
  }
});
function fixture() {
  const namespaces = (n) =>
    Object.fromEntries(
      ['mnt', 'pid', 'net', 'ipc', 'uts', 'user', 'cgroup'].map((name) => [name, `${name}:[${n}]`]),
    );
  const process = {
    process: {
      pid: 10,
      startTicks: '1',
      bootId: '00000000-0000-4000-8000-000000000001',
      startedAtMs: 10,
      executable: '/app/runtime',
      uid: 65532,
    },
    namespaces: namespaces(2),
    cgroup: '0::/system.slice/docker-' + 'a'.repeat(64) + '.scope\n',
    executableDevice: '1',
    executableInode: '2',
    security: {
      noNewPrivileges: 1,
      seccomp: 2,
      capabilities: Array(5).fill('0000000000000000'),
      rootMountId: '10',
      rootDevice: '0:10',
      rootReadOnly: true,
    },
    limits: { memoryBytes: '67108864', cpuQuota: '50000', cpuPeriod: '100000', pids: '32' },
  };
  const pins = {
    schemaVersion: 1,
    installationId: uuid(1),
    participantId: uuid(2),
    privacyDomainId: uuid(3),
    environmentId: 'test-deployment',
    operationsInstallationDigest: h('1'),
    peer: {
      principalId: uuid(4),
      credentialId: uuid(5),
      participantEpoch: '1',
      principalEpoch: '1',
      credentialEpoch: '1',
      workloadId: 'urn:openpc:workload:' + uuid(4),
      keyDigest: h('2'),
      certificateDigest: h('3'),
    },
    daemonId: 'test-engine',
    engineEndpoint: 'unix:///var/run/docker.sock',
    containerId: 'a'.repeat(64),
    imageId: h('4'),
    containerStartedAt: '2026-09-26T00:00:00Z',
    installedProcess: process,
    expectedUid: 65532,
    executable: '/app/runtime',
    argv: [],
    networkId: 'b'.repeat(64),
    address: '172.20.0.2',
    memoryBytes: 67108864,
    nanoCpus: 500000000,
    pidsLimit: 32,
    mounts: [],
    tmpfsTargets: [],
    artifacts: [{ path: '/app/runtime', digest: h('5'), maximumBytes: 1024 }],
    separatedFrom: [],
  };
  const actual = {
    id: pins.containerId,
    image: pins.imageId,
    pid: 10,
    started: pins.containerStartedAt,
    running: true,
    paused: false,
    restarting: false,
    dead: false,
    oom: false,
    path: pins.executable,
    args: [],
    readonly: true,
    privileged: false,
    devices: [],
    deviceRequests: [],
    capadd: [],
    capdrop: ['ALL'],
    security: ['no-new-privileges:true'],
    pidmode: '',
    ipcmode: 'private',
    utsmode: '',
    cgmode: 'private',
    networkmode: 'owned',
    memory: pins.memoryBytes,
    nanocpus: pins.nanoCpus,
    pids: pins.pidsLimit,
    mounts: [],
    networks: {
      owned: { NetworkID: pins.networkId, IPAddress: pins.address, EndpointID: 'c'.repeat(64) },
    },
  };
  const host = {
    ...process,
    process: { ...process.process, pid: 11, executable: '/usr/local/bin/node', uid: 1000 },
    namespaces: namespaces(1),
    cgroup: '0::/user.slice\n',
  };
  return { pins, actual, process, host };
}
test('installed observations keep every provenance/authority promotion absent', () => {
  const { pins, actual, process, host } = fixture();
  assert.ok(Object.isFrozen(parseQualificationDeploymentPins(pins).peer));
  assert.ok(validateQualificationContainerSnapshot(pins, actual, process, host));
  assert.throws(() => readCollectedQualificationDeployment({}));
  assert.throws(() =>
    readCollectedQualificationDeployment({ measurement: { ...actual, current: true } }),
  );
});
test('inspect projection admits Docker JSON with omitted Tmpfs and still requires UTSMode', async () => {
  // Wire-contract preflight for Docker CLI's raw JSON fallback, which treats
  // dot-path missing keys as errors. This does not execute Docker or emit a
  // native observation; the real one-case dispatch remains required.
  const source = await readFile(
    new URL('./qualification-deployment-observation.mjs', import.meta.url),
    'utf8',
  );
  const format = /const format =\s*'([^']+)';/u.exec(source)?.[1];
  assert.ok(format);
  const f = fixture(),
    a = f.actual;
  const wire = {
    Id: a.id,
    Image: a.image,
    Path: a.path,
    Args: a.args,
    State: {
      Pid: a.pid,
      StartedAt: a.started,
      Running: a.running,
      Paused: a.paused,
      Restarting: a.restarting,
      Dead: a.dead,
      OOMKilled: a.oom,
    },
    HostConfig: {
      ReadonlyRootfs: a.readonly,
      Privileged: a.privileged,
      Devices: a.devices,
      DeviceRequests: a.deviceRequests,
      CapAdd: a.capadd,
      CapDrop: a.capdrop,
      SecurityOpt: a.security,
      PidMode: a.pidmode,
      IpcMode: a.ipcmode,
      NetworkMode: a.networkmode,
      UTSMode: a.utsmode,
      CgroupnsMode: a.cgmode,
      Memory: a.memory,
      NanoCpus: a.nanocpus,
      PidsLimit: a.pids,
    },
    Mounts: a.mounts,
    NetworkSettings: { Networks: a.networks },
  };
  const project = (wire) =>
    JSON.parse(
      format
        .replace(/\{\{json (\.[A-Za-z.]+)\}\}/gu, (_match, path) => {
          let value = wire;
          for (const key of path.slice(1).split('.')) {
            assert.ok(Object.hasOwn(value, key), 'Required Docker JSON field missing');
            value = value[key];
          }
          return JSON.stringify(value);
        })
        .replace(/\{\{json \(index \.HostConfig "Tmpfs"\)\}\}/gu, () =>
          JSON.stringify(wire.HostConfig.Tmpfs ?? null),
        ),
    );
  const absent = project(wire);
  assert.equal(absent.tmpfs, null);
  assert.ok(validateQualificationContainerSnapshot(f.pins, absent, f.process, f.host));
  const withTmpfs = {
    ...wire,
    HostConfig: { ...wire.HostConfig, Tmpfs: { '/tmp': 'size=1m,nodev,noexec,nosuid' } },
  };
  assert.deepEqual(project(withTmpfs).tmpfs, withTmpfs.HostConfig.Tmpfs);
  delete wire.HostConfig.UTSMode;
  assert.throws(() => project(wire), /Required Docker JSON field missing/u);
});
const pinMutations = {
  remoteDaemon: { engineEndpoint: 'tcp://example:2375' },
  mutableImage: { imageId: 'node:latest' },
  rootUid: { expectedUid: 0 },
  extraCurrent: { current: true },
  authorship: { changeAuthor: 'alice' },
  relativeArtifact: { artifacts: [{ path: '../secret', digest: h('5'), maximumBytes: 10 }] },
  secretArtifact: { artifacts: [{ path: '/run/secrets/key', digest: h('5'), maximumBytes: 10 }] },
  mountedArtifact: {
    mounts: [{ source: '/tmp/code', target: '/app', kind: 'SCRATCH', readOnly: true }],
  },
  writableCredential: {
    mounts: [{ source: '/tmp/cert', target: '/run/client', kind: 'CREDENTIAL', readOnly: false }],
  },
  dockerSocket: {
    mounts: [
      { source: '/var/run/docker.sock', target: '/daemon', kind: 'SCRATCH', readOnly: true },
    ],
  },
  dockerSocketParent: {
    mounts: [{ source: '/run', target: '/daemon', kind: 'SCRATCH', readOnly: true }],
  },
  hostDeviceTree: {
    mounts: [{ source: '/dev', target: '/devices', kind: 'SCRATCH', readOnly: true }],
  },
  duplicateSeparation: { separatedFrom: [uuid(9), uuid(9)] },
  selfSeparation: { separatedFrom: [uuid(1)] },
  hugeArtifact: { artifacts: [{ path: '/app/runtime', digest: h('5'), maximumBytes: Infinity }] },
  randomUuid: { installationId: randomUUID() },
};
for (const [name, mutation] of Object.entries(pinMutations))
  test('pins reject ' + name, () =>
    assert.throws(() => parseQualificationDeploymentPins({ ...fixture().pins, ...mutation })),
  );
const nativeMutations = {
  image: { image: h('f') },
  pid: { pid: 99 },
  restart: { started: '2026-09-26T00:01:00Z' },
  stopped: { running: false },
  paused: { paused: true },
  oom: { oom: true },
  executable: { path: '/app/other' },
  argv: { args: ['--alternate'] },
  writableRoot: { readonly: false },
  privileged: { privileged: true },
  device: { devices: [{ PathOnHost: '/dev/kvm' }] },
  deviceRequest: { deviceRequests: [{ Driver: 'nvidia', Count: -1 }] },
  capability: { capadd: ['SYS_ADMIN'] },
  capDrop: { capdrop: [] },
  nnp: { security: [] },
  hostPid: { pidmode: 'host' },
  sharedPid: { pidmode: 'container:other' },
  sharedIpc: { ipcmode: 'shareable' },
  hostNet: { networkmode: 'host' },
  sharedNet: { networkmode: 'container:other' },
  hostCgroup: { cgmode: 'host' },
  memory: { memory: 0 },
  cpu: { nanocpus: 0 },
  pids: { pids: 0 },
  wrongNetwork: { networks: { owned: { NetworkID: 'f'.repeat(64) } } },
};
for (const [name, mutation] of Object.entries(nativeMutations))
  test('native consistency rejects ' + name, () => {
    const f = fixture();
    assert.throws(() =>
      validateQualificationContainerSnapshot(
        f.pins,
        { ...f.actual, ...mutation },
        f.process,
        f.host,
      ),
    );
  });
for (const name of ['mnt', 'pid', 'net', 'ipc', 'uts', 'cgroup'])
  test('actual shared ' + name + ' namespace rejects', () => {
    const f = fixture(),
      process = {
        ...f.process,
        namespaces: { ...f.process.namespaces, [name]: f.host.namespaces[name] },
      };
    assert.throws(() =>
      validateQualificationContainerSnapshot(
        { ...f.pins, installedProcess: process },
        f.actual,
        process,
        f.host,
      ),
    );
  });
test('Config.User cannot substitute for actual process uid or cgroup ownership', () => {
  const f = fixture();
  for (const process of [
    { ...f.process, process: { ...f.process.process, uid: 0 } },
    { ...f.process, cgroup: '0::/unrelated\n' },
    { ...f.process, process: { ...f.process.process, startTicks: '2' } },
    { ...f.process, process: { ...f.process.process, bootId: randomUUID() } },
  ])
    assert.throws(() =>
      validateQualificationContainerSnapshot(
        f.pins,
        { ...f.actual, user: '65532:65532' },
        process,
        f.host,
      ),
    );
});
for (const [name, mutation] of Object.entries({
  privilegeEscalation: { security: { noNewPrivileges: 0 } },
  unsandboxed: { security: { seccomp: 0 } },
  kernelCapabilities: { security: { capabilities: Array(5).fill('0000000000000001') } },
  writableRoot: { security: { rootReadOnly: false } },
  unlimitedMemory: { limits: { memoryBytes: 'max' } },
  unlimitedCpu: { limits: { cpuQuota: 'max' } },
  wrongCpuRatio: { limits: { cpuQuota: '100000' } },
  zeroCpuPeriod: { limits: { cpuPeriod: '0' } },
  unlimitedPids: { limits: { pids: 'max' } },
  absentController: { limits: { cpuQuota: null, cpuPeriod: null } },
}))
  test('actual kernel state overrides declared isolation: ' + name, () => {
    const f = fixture();
    const process = {
      ...f.process,
      security: { ...f.process.security, ...mutation.security },
      limits: { ...f.process.limits, ...mutation.limits },
    };
    assert.throws(() =>
      validateQualificationContainerSnapshot(
        { ...f.pins, installedProcess: process },
        f.actual,
        process,
        f.host,
      ),
    );
  });
const artifactMetadata = {
  mode: 0o100644,
  links: '1',
  size: 12,
  device: '1',
  inode: '2',
  modifiedNs: '3',
  changedNs: '4',
};
test('public artifact metadata permits only a directory ancestry and bounded regular file', () => {
  assert.deepEqual(
    validateQualificationArtifactMetadata(artifactMetadata, false, 12),
    artifactMetadata,
  );
  assert.ok(
    validateQualificationArtifactMetadata(
      { ...artifactMetadata, mode: 0o040755, links: '2' },
      true,
      12,
    ),
  );
});
for (const [name, mutation, directory] of [
  ['ancestor symlink', { mode: 0o120777 }, true],
  ['final symlink', { mode: 0o120777 }, false],
  ['hard link', { links: '2' }, false],
  ['device', { mode: 0o020600 }, false],
  ['socket', { mode: 0o140600 }, false],
  ['fifo', { mode: 0o010600 }, false],
  ['oversize', { size: 13 }, false],
  ['empty', { size: 0 }, false],
])
  test('public artifact metadata rejects ' + name, () =>
    assert.throws(() =>
      validateQualificationArtifactMetadata({ ...artifactMetadata, ...mutation }, directory, 12),
    ),
  );
function tar(payload, options = {}) {
  const header = Buffer.alloc(512),
    data = Buffer.from(payload);
  header.write(options.name ?? 'runtime', 0);
  header.write('0000644\0', 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  header.write('00000000000\0', 136);
  header.fill(32, 148, 156);
  header[156] = (options.type ?? '0').charCodeAt(0);
  header.write(options.link ?? '', 157);
  header.write('ustar\0', 257);
  header.write('00', 263);
  const sum = header.reduce((n, v) => n + v, 0);
  header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return Buffer.concat([
    header,
    data,
    Buffer.alloc(Math.ceil(data.length / 512) * 512 - data.length + 1024),
  ]);
}
test('archive reader measures exact regular member bytes without extracting', () => {
  const payload = Buffer.from('native artifact bytes');
  assert.deepEqual(readQualificationPublicArtifactArchive(tar(payload), '/app/runtime', 1024), {
    digest: 'sha256:' + createHash('sha256').update(payload).digest('hex'),
    bytes: payload.length,
  });
});
for (const [name, options] of Object.entries({
  symlink: { type: '2', link: '/run/secrets/key' },
  hardlink: { type: '1', link: 'runtime' },
  pax: { type: 'x' },
  directory: { type: '5' },
  traversal: { name: '../runtime' },
  wrongName: { name: 'elsewhere' },
}))
  test('archive rejects ' + name, () =>
    assert.throws(() =>
      readQualificationPublicArtifactArchive(tar('bytes', options), '/app/runtime', 1024),
    ),
  );
test('archive rejects checksum, size, trailing member and truncated frame', () => {
  const original = tar('bytes');
  const corrupt = Buffer.from(original);
  corrupt[1] ^= 1;
  const second = Buffer.from(original);
  second[1024] = 1;
  for (const value of [corrupt, second, original.subarray(0, 1024), Buffer.alloc(1536)])
    assert.throws(() => readQualificationPublicArtifactArchive(value, '/app/runtime', 1024));
  assert.throws(() => readQualificationPublicArtifactArchive(original, '/app/runtime', 1));
});
test('accessors never become installed measurements', () => {
  let read = false;
  const pins = fixture().pins;
  Object.defineProperty(pins, 'current', {
    enumerable: true,
    get() {
      read = true;
      return true;
    },
  });
  assert.throws(() => parseQualificationDeploymentPins(pins));
  assert.equal(read, false);
});
