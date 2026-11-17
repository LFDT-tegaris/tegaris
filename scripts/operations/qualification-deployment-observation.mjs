import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lstat, realpath } from 'node:fs/promises';
import { basename, posix } from 'node:path';
import { channel } from 'node:diagnostics_channel';
import { z } from 'zod';
import {
  qualificationCanonicalJson as canonical,
  qualificationDigest as hash,
} from '../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.ts';
import {
  readInstallationProcessIsolation,
  installationProcessIsolationSchema,
} from './installation-process-observation.mjs';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const id = z.uuidv7(),
  containerId = z.string().regex(/^[0-9a-f]{64}$/u);
const ms = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const uint = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/u)
  .max(20);
const absolute = z
  .string()
  .min(2)
  .max(512)
  .refine(
    (p) =>
      p.startsWith('/') &&
      posix.normalize(p) === p &&
      ![...p].some((c) => c.charCodeAt(0) <= 32 || c.charCodeAt(0) === 127 || c === '\\'),
  );
const publicPath = absolute.refine(
  (p) =>
    p.split('/').length <= 17 &&
    !['/proc', '/sys', '/dev', '/run', '/var/run', '/etc', '/root', '/home'].some(
      (r) => p === r || p.startsWith(r + '/'),
    ),
);
export const qualificationDeploymentPeerSchema = z.strictObject({
  principalId: id,
  credentialId: id,
  participantEpoch: uint,
  principalEpoch: uint,
  credentialEpoch: uint,
  workloadId: z.string().min(1).max(256),
  keyDigest: digest,
  certificateDigest: digest,
});
export const qualificationDeploymentSelectionSchema = z.strictObject({
  participantId: id,
  privacyDomainId: id,
  installationId: id,
});
export const qualificationDeploymentIntentSchema = z.strictObject({
  observationId: id,
  operationId: id,
});
const mount = z
  .strictObject({
    source: absolute,
    target: absolute,
    kind: z.enum(['CREDENTIAL', 'SCRATCH']),
    readOnly: z.boolean(),
  })
  .refine((v) => v.kind !== 'CREDENTIAL' || v.readOnly);
export const qualificationDeploymentPinsSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    installationId: id,
    participantId: id,
    privacyDomainId: id,
    environmentId: z.string().regex(/^[a-z][a-z0-9-]{2,31}$/u),
    operationsInstallationDigest: digest,
    peer: qualificationDeploymentPeerSchema,
    daemonId: z.string().regex(/^[A-Za-z0-9:_-]{1,128}$/u),
    engineEndpoint: z.literal('unix:///var/run/docker.sock'),
    containerId,
    imageId: digest,
    containerStartedAt: z.string().min(1).max(64),
    installedProcess: installationProcessIsolationSchema,
    expectedUid: z.number().int().min(1).max(2147483647),
    executable: absolute,
    argv: z
      .array(
        z
          .string()
          .max(2048)
          .refine((s) => ![...s].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)),
      )
      .max(16),
    networkId: containerId,
    address: z.ipv4(),
    memoryBytes: z.number().int().min(16777216).max(8589934592),
    nanoCpus: z.number().int().min(10000000).max(2000000000),
    pidsLimit: z.number().int().min(1).max(512),
    mounts: z.array(mount).max(16),
    tmpfsTargets: z.array(absolute).max(4),
    artifacts: z
      .array(
        z.strictObject({
          path: publicPath,
          digest,
          maximumBytes: z.number().int().min(1).max(67108864),
        }),
      )
      .min(1)
      .max(4),
    separatedFrom: z.array(id).max(8),
  })
  .superRefine((p, c) => {
    const targets = [...p.mounts.map((m) => m.target), ...p.tmpfsTargets];
    if (
      p.installedProcess.process.uid !== p.expectedUid ||
      p.installedProcess.process.executable !== p.executable ||
      new Set(targets).size !== targets.length ||
      new Set(p.artifacts.map((a) => a.path)).size !== p.artifacts.length ||
      new Set(p.separatedFrom).size !== p.separatedFrom.length ||
      p.separatedFrom.includes(p.installationId) ||
      p.artifacts.reduce((n, a) => n + a.maximumBytes, 0) > 134217728 ||
      p.artifacts.some((a) => targets.some((t) => contains(t, a.path))) ||
      p.mounts.some((m) => m.source.includes('docker.sock') || m.target.includes('docker.sock')) ||
      p.mounts.some((m) =>
        ['/proc', '/sys', '/dev', '/run', '/var/run', '/var/lib/docker'].some(
          (root) => contains(root, m.source) || contains(m.source, root),
        ),
      )
    )
      c.addIssue({ code: 'custom', message: 'Deployment pins rejected' });
  });
const daemonSchema = z.strictObject({
  id: z.string(),
  socketDevice: uint,
  socketInode: uint,
  hostBootId: z.uuid(),
});
const mountObservation = z.strictObject({
  target: absolute,
  kind: z.enum(['CREDENTIAL', 'SCRATCH', 'TMPFS']),
  readOnly: z.boolean(),
  device: uint.nullable(),
  inode: uint.nullable(),
});
const instanceSchema = z.strictObject({
  installationId: id,
  containerId,
  imageId: digest,
  startedAt: z.string().min(1).max(64),
  process: installationProcessIsolationSchema,
  networkId: containerId,
  address: z.ipv4(),
  endpointId: containerId,
  memoryBytes: ms,
  nanoCpus: ms,
  pidsLimit: ms,
  mounts: z.array(mountObservation).max(20),
});
export const qualificationDeploymentMeasurementSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    observationId: id,
    requestDigest: digest,
    installationDigest: digest,
    startedAtMs: ms,
    completedAtMs: ms,
    scope: z.literal('CONTAINER_WORKLOAD'),
    daemon: daemonSchema,
    instance: instanceSchema,
    separatedInstances: z.array(instanceSchema).max(8),
    artifacts: z
      .array(z.strictObject({ path: publicPath, digest, bytes: ms }))
      .min(1)
      .max(4),
    sourceBuildLink: z.literal('UNESTABLISHED'),
    changeAuthorship: z.literal('UNESTABLISHED'),
    exactSocketProcess: z.literal('UNESTABLISHED'),
    qualification: z.literal('UNESTABLISHED'),
  })
  .refine((v) => v.completedAtMs >= v.startedAtMs && v.completedAtMs - v.startedAtMs <= 30000);
const issued = new WeakMap();
export function deploymentCopy(value) {
  const copy = JSON.parse(canonical(value));
  function freeze(v) {
    if (v && typeof v === 'object') {
      Object.values(v).forEach(freeze);
      Object.freeze(v);
    }
    return v;
  }
  return freeze(copy);
}
export function parseQualificationDeploymentPins(value) {
  return deploymentCopy(qualificationDeploymentPinsSchema.parse(deploymentCopy(value)));
}
export function qualificationDeploymentDigest(value) {
  return hash(Buffer.from(canonical(value)));
}
const diagnostics = channel('openpc.qualification.deployment-observation');
const rejectionCodes = new WeakMap();
function fail(code = 'REJECTED') {
  const error = new Error('QUALIFICATION_DEPLOYMENT_OBSERVATION_UNKNOWN');
  rejectionCodes.set(error, code);
  throw error;
}
function failureCode(error) {
  // Never retain or publish messages, stacks, commands, paths or native values.
  // Process observation wraps native errors; inspect only bounded own data fields.
  for (let i = 0; i < 4 && error instanceof Error; i++) {
    if (rejectionCodes.has(error)) return rejectionCodes.get(error);
    if (error instanceof z.ZodError) return 'INVALID_SHAPE';
    const code = Object.getOwnPropertyDescriptor(error, 'code')?.value;
    if (code === 'EACCES' || code === 'EPERM') return 'IO_DENIED';
    if (code === 'ENOENT' || code === 'ESRCH') return 'IO_ABSENT';
    if (code === 'ETIMEDOUT' || code === 'ABORT_ERR') return 'TIMEOUT';
    if (code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') return 'OUTPUT_LIMIT';
    if (Object.getOwnPropertyDescriptor(error, 'killed')?.value === true) return 'PROCESS_KILLED';
    const stderr = Object.getOwnPropertyDescriptor(error, 'stderr')?.value;
    if (Buffer.isBuffer(stderr)) {
      // Inspect only known static error signatures. Never return any bytes or
      // field name from the native error, including unknown template fields.
      if (stderr.includes('template parsing error:')) {
        if (stderr.includes('map has no entry for key "Tmpfs"')) return 'TEMPLATE_TMPFS';
        if (stderr.includes('map has no entry for key "UTSMode"')) return 'TEMPLATE_UTS_MODE';
        return 'TEMPLATE_REJECTED';
      }
    }
    if (typeof code === 'number') return 'PROCESS_EXIT';
    if (error instanceof SyntaxError) return 'JSON_INVALID';
    error = Object.getOwnPropertyDescriptor(error, 'cause')?.value;
  }
  return 'NATIVE_ERROR';
}
function contains(parent, child) {
  return parent === child || child.startsWith(parent + '/');
}
function same(a, b) {
  if (canonical(a) !== canonical(b)) fail();
}

/** Only native proc-root metadata reaches the collector. This pure validator
 * emits no observation authority and never reads file contents. */
export function validateQualificationArtifactMetadata(value, directory, maximumBytes) {
  const v = z
    .strictObject({
      mode: z.number().int().nonnegative(),
      links: uint,
      size: ms,
      device: uint,
      inode: uint,
      modifiedNs: uint,
      changedNs: uint,
    })
    .parse(deploymentCopy(value));
  const kind = v.mode & 0o170000;
  if (
    directory
      ? kind !== 0o040000
      : kind !== 0o100000 || v.links !== '1' || v.size < 1 || v.size > maximumBytes
  )
    fail();
  return v;
}
async function artifactPathMetadata(p, artifact) {
  const parts = artifact.path.slice(1).split('/'),
    observed = [];
  for (let i = 0; i < parts.length; i++) {
    // Inspect each ancestor before following it. The already checked actual
    // read-only root, no mounts over this path and zero native capabilities
    // prevent workload substitutions during the subsequent bounded archive read.
    const info = await lstat(
      `/proc/${p.installedProcess.process.pid}/root/${parts.slice(0, i + 1).join('/')}`,
      { bigint: true },
    );
    observed.push(
      validateQualificationArtifactMetadata(
        {
          mode: Number(info.mode),
          links: String(info.nlink),
          size: Number(info.size),
          device: String(info.dev),
          inode: String(info.ino),
          modifiedNs: String(info.mtimeNs),
          changedNs: String(info.ctimeNs),
        },
        i < parts.length - 1,
        artifact.maximumBytes,
      ),
    );
  }
  return observed;
}

/** Bounded Docker archive framing only. No extraction, extension headers,
 * links, sparse files, alternate names or filesystem writes are accepted. */
export function readQualificationPublicArtifactArchive(bytes, path, maximumBytes) {
  publicPath.parse(path);
  if (
    !Buffer.isBuffer(bytes) ||
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > 67108864 ||
    bytes.length < 1536 ||
    bytes.length > maximumBytes + 4096 ||
    bytes.length % 512
  )
    fail();
  const header = bytes.subarray(0, 512);
  const text = (start, length) => {
    const part = header.subarray(start, start + length),
      zero = part.indexOf(0);
    if (zero >= 0 && part.subarray(zero).some((b) => b !== 0)) fail();
    const value = part.subarray(0, zero < 0 ? part.length : zero).toString('utf8');
    if (!Buffer.from(value).equals(part.subarray(0, zero < 0 ? part.length : zero))) fail();
    return value;
  };
  const octal = (start, length) => {
    const v = header.subarray(start, start + length).toString('ascii');
    if (!/^[0-7]+[\0 ]*$/u.test(v)) fail();
    return Number.parseInt(v, 8);
  };
  const checksum = octal(148, 8),
    size = octal(124, 12);
  const total = header.reduce((n, b, i) => n + (i >= 148 && i < 156 ? 32 : b), 0);
  if (
    checksum !== total ||
    text(0, 100) !== basename(path) ||
    text(345, 155) !== '' ||
    text(157, 100) !== '' ||
    ![0, 48].includes(header[156]) ||
    text(257, 6) !== 'ustar' ||
    size < 1 ||
    size > maximumBytes ||
    !Number.isSafeInteger(size)
  )
    fail();
  const end = 512 + Math.ceil(size / 512) * 512;
  if (bytes.length < end + 1024 || bytes.subarray(512 + size).some((b) => b !== 0)) fail();
  return { digest: hash(bytes.subarray(512, 512 + size)), bytes: size };
}

// Docker's typed ID is ID, but its JSON key is Id, so the public .Id template
// selects the raw-JSON fallback. That parser uses missingkey=error. Tmpfs is
// explicitly omitempty in the HostConfig API; index preserves its documented
// absence as null. Required isolation fields, including UTSMode, stay required.
const format =
  '{"id":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},"started":{{json .State.StartedAt}},"running":{{json .State.Running}},"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},"dead":{{json .State.Dead}},"oom":{{json .State.OOMKilled}},"path":{{json .Path}},"args":{{json .Args}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"devices":{{json .HostConfig.Devices}},"deviceRequests":{{json .HostConfig.DeviceRequests}},"capadd":{{json .HostConfig.CapAdd}},"capdrop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"pidmode":{{json .HostConfig.PidMode}},"ipcmode":{{json .HostConfig.IpcMode}},"networkmode":{{json .HostConfig.NetworkMode}},"utsmode":{{json .HostConfig.UTSMode}},"cgmode":{{json .HostConfig.CgroupnsMode}},"memory":{{json .HostConfig.Memory}},"nanocpus":{{json .HostConfig.NanoCpus}},"pids":{{json .HostConfig.PidsLimit}},"mounts":{{json .Mounts}},"tmpfs":{{json (index .HostConfig "Tmpfs")}},"networks":{{json .NetworkSettings.Networks}}}';
async function docker(args, signal, maximum = 65536) {
  const r = await promisify(execFile)(
    'docker',
    ['--host', 'unix:///var/run/docker.sock', ...args],
    { timeout: 3000, maxBuffer: maximum, encoding: 'buffer', signal },
  );
  if (r.stderr.length) fail('DOCKER_STDERR');
  return r.stdout;
}
async function daemon(signal, host) {
  const sock = await lstat('/var/run/docker.sock', { bigint: true });
  if (!sock.isSocket() || sock.uid !== 0n || (sock.mode & 7n) !== 0n) fail('DAEMON_SOCKET');
  const info = JSON.parse(
    (
      await docker(['info', '--format', '{"id":{{json .ID}},"os":{{json .OSType}}}'], signal)
    ).toString('utf8'),
  );
  if (info.os !== 'linux' || typeof info.id !== 'string') fail('DAEMON_PROFILE');
  return daemonSchema.parse({
    id: info.id,
    socketDevice: String(sock.dev),
    socketInode: String(sock.ino),
    hostBootId: host.process.bootId,
  });
}

/** A pure consistency check is useful for malformed input tests, but is never
 * accepted as native evidence; only collectQualificationDeployment emits handles. */
export function validateQualificationContainerSnapshot(pins, actual, process, host) {
  const p = parseQualificationDeploymentPins(pins);
  installationProcessIsolationSchema.parse(process);
  installationProcessIsolationSchema.parse(host);
  if (
    actual.id !== p.containerId ||
    actual.image !== p.imageId ||
    actual.pid !== process.process.pid ||
    actual.started !== p.containerStartedAt ||
    actual.running !== true ||
    actual.paused !== false ||
    actual.restarting !== false ||
    actual.dead !== false ||
    actual.oom !== false ||
    actual.path !== p.executable ||
    canonical(actual.args) !== canonical(p.argv)
  )
    fail('CONTAINER_IDENTITY');
  if (
    canonical(process) !== canonical(p.installedProcess) ||
    process.process.executable !== p.executable ||
    process.process.uid !== p.expectedUid ||
    process.process.bootId !== host.process.bootId
  )
    fail('PROCESS_IDENTITY');
  if (
    process.security.noNewPrivileges !== 1 ||
    process.security.seccomp !== 2 ||
    process.security.capabilities.some((v) => v !== '0000000000000000') ||
    process.security.rootReadOnly !== true
  )
    fail('PROCESS_SECURITY');
  if (
    process.limits.memoryBytes !== String(p.memoryBytes) ||
    process.limits.pids !== String(p.pidsLimit) ||
    process.limits.cpuQuota === 'max' ||
    process.limits.cpuQuota === null ||
    process.limits.cpuPeriod === null ||
    BigInt(process.limits.cpuPeriod) === 0n ||
    BigInt(process.limits.cpuQuota) * 1000000000n !==
      BigInt(p.nanoCpus) * BigInt(process.limits.cpuPeriod)
  )
    fail('NATIVE_LIMITS');
  if (
    !new RegExp('(?:^|/)(?:docker-)?' + p.containerId + '(?:\\.scope)?(?:/|$)', 'mu').test(
      process.cgroup,
    )
  )
    fail('CGROUP_IDENTITY');
  if (
    actual.readonly !== true ||
    actual.privileged !== false ||
    (actual.devices !== null && (!Array.isArray(actual.devices) || actual.devices.length !== 0)) ||
    (actual.deviceRequests !== null &&
      (!Array.isArray(actual.deviceRequests) || actual.deviceRequests.length !== 0)) ||
    (actual.capadd?.length ?? 0) !== 0 ||
    canonical(actual.capdrop) !== '["ALL"]' ||
    !Array.isArray(actual.security) ||
    !actual.security.some((s) => s === 'no-new-privileges' || s === 'no-new-privileges:true') ||
    actual.pidmode !== '' ||
    !['private', ''].includes(actual.ipcmode) ||
    !['private', ''].includes(actual.cgmode) ||
    actual.utsmode !== '' ||
    actual.networkmode === 'host' ||
    actual.networkmode?.startsWith('container:') ||
    actual.memory !== p.memoryBytes ||
    actual.nanocpus !== p.nanoCpus ||
    actual.pids !== p.pidsLimit
  )
    fail('DECLARED_ISOLATION');
  for (const name of ['mnt', 'pid', 'net', 'ipc', 'uts', 'cgroup'])
    if (
      process.namespaces[name] === host.namespaces[name] ||
      !process.namespaces[name].startsWith(name + ':[')
    )
      fail('NAMESPACE_ISOLATION');
  const nets = Object.values(actual.networks ?? {});
  if (
    nets.length !== 1 ||
    nets[0].NetworkID !== p.networkId ||
    nets[0].IPAddress !== p.address ||
    !containerId.safeParse(nets[0].EndpointID).success ||
    !Array.isArray(actual.mounts)
  )
    fail('NETWORK_BINDING');
  return nets[0];
}
async function instance(p, host, signal, mark) {
  mark('INSPECT');
  const raw = await docker(
    ['inspect', '--type', 'container', '--format', format, p.containerId],
    signal,
  );
  mark('INSPECT_JSON');
  const a = JSON.parse(raw.toString('utf8'));
  mark('PROCFS');
  const process = await readInstallationProcessIsolation(a.pid);
  mark('PROFILE');
  const network = validateQualificationContainerSnapshot(p, a, process, host);
  mark('MOUNTS');
  const mounts = [],
    sources = [];
  for (const m of a.mounts) {
    if (m.Type === 'tmpfs' && p.tmpfsTargets.includes(m.Destination)) continue;
    const expected = p.mounts.find((e) => e.target === m.Destination);
    if (
      !expected ||
      m.Type !== 'bind' ||
      m.Source !== expected.source ||
      m.RW !== !expected.readOnly ||
      !['rprivate', 'private'].includes(m.Propagation)
    )
      fail();
    const file = await lstat(m.Source, { bigint: true });
    if (
      file.isSymbolicLink() ||
      file.isSocket() ||
      !(file.isFile() || file.isDirectory()) ||
      (await realpath(m.Source)) !== m.Source
    )
      fail();
    mounts.push({
      target: m.Destination,
      kind: expected.kind,
      readOnly: expected.readOnly,
      device: String(file.dev),
      inode: String(file.ino),
    });
    sources.push({
      path: m.Source,
      device: String(file.dev),
      inode: String(file.ino),
      kind: expected.kind,
      readOnly: expected.readOnly,
    });
  }
  if (mounts.length !== p.mounts.length) fail();
  same(Object.keys(a.tmpfs ?? {}).sort(), [...p.tmpfsTargets].sort());
  for (const target of p.tmpfsTargets) {
    if (!['/tmp', '/var/tmp'].includes(target)) fail();
    const options = String(a.tmpfs[target]).split(',');
    if (
      !['noexec', 'nosuid', 'nodev'].every((v) => options.includes(v)) ||
      !options.some((v) => /^size=[1-9][0-9]*[kmg]?$/u.test(v))
    )
      fail();
    mounts.push({ target, kind: 'TMPFS', readOnly: false, device: null, inode: null });
  }
  mounts.sort((x, y) => x.target.localeCompare(y.target));
  return {
    value: instanceSchema.parse({
      installationId: p.installationId,
      containerId: p.containerId,
      imageId: p.imageId,
      startedAt: a.started,
      process,
      networkId: p.networkId,
      address: p.address,
      endpointId: network.EndpointID,
      memoryBytes: a.memory,
      nanoCpus: a.nanocpus,
      pidsLimit: a.pids,
      mounts,
    }),
    sources,
  };
}
function separate(left, right) {
  if (left.value.containerId === right.value.containerId) fail();
  for (const name of ['mnt', 'pid', 'net', 'ipc', 'uts'])
    if (left.value.process.namespaces[name] === right.value.process.namespaces[name]) fail();
  for (const a of left.sources)
    for (const b of right.sources)
      if (
        (a.kind === 'CREDENTIAL' || b.kind === 'CREDENTIAL' || !a.readOnly || !b.readOnly) &&
        ((a.device === b.device && a.inode === b.inode) ||
          contains(a.path, b.path) ||
          contains(b.path, a.path))
      )
        fail();
}

/** Host-root only. Inputs are installed pins plus actual TLS socket metadata
 * derived by the native peer adapter. No native reader can be injected. */
export async function collectQualificationDeployment(pins, otherPins, connection, attempt) {
  const p = parseQualificationDeploymentPins(pins),
    others = otherPins.map(parseQualificationDeploymentPins);
  attempt = deploymentCopy(
    z.strictObject({ observationId: id, requestDigest: digest }).parse(attempt),
  );
  const startedAtMs = Date.now(),
    signal = AbortSignal.timeout(25000);
  let stage = 'PIN_SET';
  const markInstance = (phase) => (part) => {
    stage = phase + '_' + part;
  };
  try {
    same(others.map((v) => v.installationId).sort(), [...p.separatedFrom].sort());
    if (
      others.some(
        (v) =>
          v.daemonId !== p.daemonId ||
          v.environmentId !== p.environmentId ||
          v.participantId !== p.participantId ||
          v.privacyDomainId !== p.privacyDomainId ||
          v.engineEndpoint !== p.engineEndpoint,
      )
    )
      fail();
    stage = 'HOST_PROCESS';
    const host = await readInstallationProcessIsolation(process.pid);
    stage = 'DAEMON_BEFORE';
    const engine = await daemon(signal, host);
    if (engine.id !== p.daemonId) fail('DAEMON_IDENTITY');
    const before = await instance(p, host, signal, markInstance('SUBJECT_BEFORE')),
      peers = [];
    for (const other of others) {
      const observed = await instance(other, host, signal, markInstance('PEER_BEFORE'));
      stage = 'SEPARATION';
      separate(before, observed);
      peers.push(observed);
    }
    stage = 'SEPARATION';
    for (let i = 0; i < peers.length; i++)
      for (let j = i + 1; j < peers.length; j++) separate(peers[i], peers[j]);
    const readNetwork = async () => {
      const network = JSON.parse(
        (
          await docker(
            [
              'network',
              'inspect',
              '--format',
              '{"id":{{json .Id}},"driver":{{json .Driver}},"scope":{{json .Scope}},"internal":{{json .Internal}},"ipam":{{json .IPAM.Config}},"containers":{{json .Containers}}}',
              p.networkId,
            ],
            signal,
          )
        ).toString('utf8'),
      );
      const address = (v) => (typeof v === 'string' ? v.replace(/^::ffff:/u, '') : null);
      const entry = network.containers?.[p.containerId];
      const allowed = new Set(
        [p, ...others].filter((v) => v.networkId === p.networkId).map((v) => v.containerId),
      );
      if (
        network.id !== p.networkId ||
        network.driver !== 'bridge' ||
        network.scope !== 'local' ||
        network.internal !== true ||
        !entry ||
        entry.EndpointID !== before.value.endpointId ||
        entry.IPv4Address?.split('/')[0] !== p.address ||
        address(connection.remoteAddress) !== p.address ||
        !Array.isArray(network.ipam) ||
        !network.ipam.some((v) => v.Gateway === address(connection.localAddress)) ||
        Object.keys(network.containers).some((v) => !allowed.has(v))
      )
        fail();
      return network;
    };
    stage = 'NETWORK_BEFORE';
    const network = await readNetwork();
    const artifacts = [];
    for (const artifact of p.artifacts) {
      stage = 'ARTIFACT_METADATA_BEFORE';
      const pathBefore = await artifactPathMetadata(p, artifact);
      stage = 'ARTIFACT_ARCHIVE';
      const raw = await docker(
        ['cp', p.containerId + ':' + artifact.path, '-'],
        signal,
        artifact.maximumBytes + 4096,
      );
      const observed = readQualificationPublicArtifactArchive(
        raw,
        artifact.path,
        artifact.maximumBytes,
      );
      if (observed.digest !== artifact.digest) fail('ARTIFACT_DIGEST');
      if (observed.bytes !== pathBefore.at(-1).size) fail('ARTIFACT_SIZE');
      stage = 'ARTIFACT_METADATA_AFTER';
      same(pathBefore, await artifactPathMetadata(p, artifact));
      artifacts.push({ path: artifact.path, ...observed });
    }
    const after = await instance(p, host, signal, markInstance('SUBJECT_AFTER'));
    stage = 'SUBJECT_STABILITY';
    same(before, after);
    for (let i = 0; i < others.length; i++) {
      const peerAfter = await instance(others[i], host, signal, markInstance('PEER_AFTER'));
      stage = 'PEER_STABILITY';
      same(peers[i], peerAfter);
    }
    stage = 'NETWORK_AFTER';
    same(network, await readNetwork());
    stage = 'DAEMON_AFTER';
    same(engine, await daemon(signal, await readInstallationProcessIsolation(process.pid)));
    stage = 'MEASUREMENT';
    const measurement = deploymentCopy(
      qualificationDeploymentMeasurementSchema.parse({
        schemaVersion: 1,
        ...attempt,
        installationDigest: qualificationDeploymentDigest(p),
        startedAtMs,
        completedAtMs: Date.now(),
        scope: 'CONTAINER_WORKLOAD',
        daemon: engine,
        instance: before.value,
        separatedInstances: peers.map((v) => v.value),
        artifacts,
        sourceBuildLink: 'UNESTABLISHED',
        changeAuthorship: 'UNESTABLISHED',
        exactSocketProcess: 'UNESTABLISHED',
        qualification: 'UNESTABLISHED',
      }),
    );
    const handle = Object.freeze({});
    issued.set(handle, measurement);
    return handle;
  } catch (error) {
    diagnostics.publish(Object.freeze({ stage, code: failureCode(error) }));
    return fail();
  }
}
/** Original native handle only. JSON, structural clones and historical rows
 * cannot create a new observation or authorize any later effect. */
export function readCollectedQualificationDeployment(handle) {
  const value = issued.get(handle);
  if (!value) fail();
  return deploymentCopy(value);
}
