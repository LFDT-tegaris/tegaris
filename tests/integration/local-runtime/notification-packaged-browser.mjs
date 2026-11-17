import { isDeepStrictEqual } from 'node:util';
import { execFile } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { constants, fstatSync, fsyncSync } from 'node:fs';
import { lstat, open, realpath, stat } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, normalize, resolve } from 'node:path';
import { z } from 'zod';
import { immutableJsonCopy } from '../../../services/control-api/src/privacy-explorer/immutable.ts';
import {
  prepareNotificationPackagedInputs,
  validateNotificationPackagedInputRequest,
} from './notification-packaged-inputs.mjs';
import { validateStoredBinding } from '../../../scripts/maintenance/local-runtime-network.mjs';
import { parseNotificationPackagedNetworkJson } from './notification-packaged-runtime.mjs';
import { parseStrictJsonBytes } from '../../../services/control-api/src/privacy-explorer/strict-json.ts';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

const blocked = (boundary) => new Error(`BLOCKED_NOTIFICATION_PACKAGED_BROWSER_${boundary}`);
/** Closed diagnostic vocabulary only; never interpolate an arbitrary error. */
export function notificationPackagedFailureBoundary(error) {
  if (error instanceof AggregateError) {
    for (const item of error.errors.slice(0, 8)) {
      const input = /^BLOCKED_NOTIFICATION_INPUTS_([A-Z_]{1,48})$/u.exec(
        item instanceof Error ? item.message : '',
      );
      if (
        input &&
        [
          'ROOT',
          'DATABASE_ROLE',
          'ACTIVE_SCOPE',
          'FRESH_OWNER',
          'TLS_GENERATION',
          'LIFETIME',
          'PROFILES',
          'INITIAL_WORKLOAD',
          'CURRENT_WORKLOAD',
          'CURRENT_INSTALLATION',
          'NETWORK_CHANGED',
          'CLEANUP_UNKNOWN',
        ].includes(input[1])
      )
        return `INPUTS_${input[1]}`;
    }
  }
  const match = /^BLOCKED_NOTIFICATION_PACKAGED_BROWSER_([A-Z_]{1,48})$/u.exec(
    error instanceof Error ? error.message : '',
  );
  return match &&
    [
      'ROOT',
      'LOG',
      'CLI_ARGUMENTS',
      'COMPOSE_OPTIONS',
      'ENVIRONMENT',
      'COMMAND',
      'NETWORK_COMMAND',
      'RETAINED_NETWORK',
      'FRESH_ROOT',
      'DATABASE_MAPPING',
      'PRIVATE_INPUT',
      'HANDOFF',
      'CHILD_STILL_LIVE',
    ].includes(match[1])
    ? match[1]
    : 'UNCLASSIFIED';
}
/** Existing strict JSON owner with explicit finite profile for root/runtime I/O. */
export function parseNotificationPackagedJson(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > 4 * 1024 * 1024) throw blocked('JSON');
  return parseStrictJsonBytes(bytes, { maximumDepth: 64 });
}

const absolute = z
  .string()
  .min(2)
  .max(4096)
  .refine((v) => isAbsolute(v) && normalize(v) === v && !/[\0\r\n]/u.test(v));
const argument = z
  .string()
  .min(1)
  .max(4096)
  .refine((v) => !/[\0\r\n]/u.test(v));
function plain(value) {
  return (
    value &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0 &&
    Object.values(Object.getOwnPropertyDescriptors(value)).every((p) => !p.get && !p.set)
  );
}
const requestSchema = z.strictObject({
  inputs: z.unknown(),
  composeArgv: z.array(argument).min(6).max(22),
});

/** Closed request only. Parsing executable arguments never grants network,
 * image, database, browser, signer or provider authority. */
export function validateNotificationPackagedBrowserRequest(value) {
  if (!plain(value)) throw blocked('REQUEST');
  const parsed = requestSchema.safeParse(value);
  if (!parsed.success) throw blocked('REQUEST');
  const inputs = validateNotificationPackagedInputRequest(parsed.data.inputs);
  if (inputs.channels.length !== 2) throw blocked('DESTINATIONS');
  return { inputs, composeArgv: Object.freeze([...parsed.data.composeArgv]) };
}

/** Inspect the actual bare handoff. This validates options only; each lifecycle
 * invocation must also authenticate inherited admission and the live network. */
export function notificationPackagedComposeOptions(value) {
  const parsed = z
    .strictObject({
      argv: z.array(argument).min(6).max(24),
      runRoot: absolute,
      repository: absolute,
      project: z.string().regex(/^openpc-local-e2e-[0-9a-f]{12}$/u),
    })
    .safeParse(value);
  if (!parsed.success) throw blocked('COMPOSE_OPTIONS');
  const { argv, runRoot, repository, project } = parsed.data;
  if (argv[0] !== 'docker' || argv[1] !== 'compose' || argv.length % 2)
    throw blocked('COMPOSE_OPTIONS');
  const projects = [],
    files = [];
  for (let index = 2; index < argv.length; index += 2) {
    const [flag, selected] = argv.slice(index, index + 2);
    if (['-p', '--project-name'].includes(flag)) projects.push(selected);
    else if (['-f', '--file'].includes(flag)) files.push(selected);
    else throw blocked('COMPOSE_OPTIONS');
  }
  const base = join(repository, 'deploy/compose/local/compose.yaml');
  if (
    !isDeepStrictEqual(projects, [project]) ||
    files[0] !== base ||
    new Set(files).size !== files.length ||
    files.some(
      (file) =>
        !absolute.safeParse(file).success || (file !== base && !file.startsWith(`${runRoot}/`)),
    )
  )
    throw blocked('COMPOSE_OPTIONS');
  return immutableJsonCopy({ project, files });
}

const port = z.number().int().min(1).max(65535);
const mount = z.strictObject({
  type: z.literal('bind'),
  source: absolute,
  target: absolute,
  read_only: z.literal(true),
});
const descriptor = z.strictObject({
  configurationFile: absolute,
  mounts: z.array(mount).min(7).max(28),
  environment: z.strictObject({ CONTROL_API_NOTIFICATION_VERIFICATION_FILE: absolute }),
  port: z.strictObject({
    target: port,
    published: port,
    host_ip: z.literal('127.0.0.1'),
    protocol: z.literal('tcp'),
  }),
});

/** Transport projection from the real FOUR-file runtime. This pure function
 * accepts no provider/secret bytes, service image, readiness flag or extra service. */
export function notificationPackagedBrowserOverlay(value) {
  const parsed = z
    .strictObject({ runRoot: absolute, containerRoot: absolute, runtime: descriptor })
    .safeParse(value);
  if (!parsed.success) throw blocked('OVERLAY');
  const { runRoot, containerRoot, runtime } = parsed.data;
  const directory = join(runRoot, 'data/notification-packaged');
  const config = join(containerRoot, 'configuration.json');
  if (
    runtime.configurationFile !== config ||
    runtime.environment.CONTROL_API_NOTIFICATION_VERIFICATION_FILE !== config ||
    runtime.port.target < 1024 ||
    new Set(runtime.mounts.map((m) => m.target)).size !== runtime.mounts.length ||
    new Set(runtime.mounts.map((m) => m.source)).size !== runtime.mounts.length
  )
    throw blocked('OVERLAY');
  const count = (runtime.mounts.length - 4) / 3;
  if (!Number.isInteger(count) || count < 1 || count > 8) throw blocked('OVERLAY');
  const names = [
    'configuration.json',
    ...['control', ...Array.from({ length: count }, (_, i) => `workload-${i}`)].flatMap((prefix) =>
      ['ca', 'certificate', 'key'].map((kind) => `${prefix}-${kind}.pem`),
    ),
  ].sort();
  if (
    !isDeepStrictEqual(runtime.mounts.map((m) => basename(m.source)).sort(), names) ||
    runtime.mounts.some(
      (m) =>
        m.source !== join(directory, basename(m.source)) ||
        m.target !== join(containerRoot, basename(m.source)),
    )
  )
    throw blocked('OVERLAY');
  return immutableJsonCopy({
    services: {
      'control-api': {
        environment: runtime.environment,
        volumes: runtime.mounts,
        ports: [runtime.port],
      },
    },
  });
}

/** Private Compose input only, written after the actual FOUR runtime creates its
 * owned directory. No service command, credential bytes, cleanup permission or
 * authority is produced here. Existing/partial files are never replaced. */
export async function writeNotificationPackagedBrowserOverlay(value) {
  const overlay = notificationPackagedBrowserOverlay(value);
  const directory = join(value.runRoot, 'data/notification-packaged');
  const path = join(directory, 'compose.json');
  let handle, first;
  try {
    for (const owned of [value.runRoot, directory]) {
      const info = await stat(owned);
      if (
        (await realpath(owned)) !== owned ||
        !info.isDirectory() ||
        info.uid !== process.getuid() ||
        info.mode & 0o077
      )
        throw blocked('OVERLAY_DIRECTORY');
    }
    handle = await open(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(`${JSON.stringify(overlay)}\n`);
    await handle.sync();
  } catch {
    first = new NotificationPackagedBrowserFailure('OVERLAY');
  }
  try {
    await handle?.close();
  } catch {
    throw new NotificationPackagedBrowserFailure('OVERLAY', true);
  }
  if (first) throw first;
  let parent,
    durabilityUnknown = false;
  try {
    parent = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
    await parent.sync();
  } catch {
    durabilityUnknown = true;
  } finally {
    try {
      await parent?.close();
    } catch {
      durabilityUnknown = true;
    }
  }
  if (durabilityUnknown) throw new NotificationPackagedBrowserFailure('OVERLAY', true);
  return path;
}

function inspectable(value) {
  if (!plain(value) || !plain(value.services) || !plain(value.services['control-api']))
    throw blocked('TOPOLOGY');
  return structuredClone(value);
}
function expectedPort(value) {
  if (
    !plain(value) ||
    value.protocol !== 'tcp' ||
    value.mode !== 'ingress' ||
    value.host_ip !== '127.0.0.1' ||
    !['target', 'published', 'host_ip', 'protocol', 'mode'].every((key) =>
      Object.hasOwn(value, key),
    ) ||
    Object.keys(value).length !== 5 ||
    !port.safeParse(Number(value.target)).success ||
    !port.safeParse(Number(value.published)).success
  )
    throw blocked('TOPOLOGY');
  return {
    target: Number(value.target),
    published: Number(value.published),
    host_ip: value.host_ip,
    protocol: value.protocol,
  };
}

/** Compare actual Compose renders. Only the exact control-api transport overlay
 * may differ. The caller still authenticates current image/container/network
 * ownership through the canonical guarded execution owner before startup. */
export function assertNotificationPackagedBrowserTopology({ before, after, overlay }) {
  const prior = inspectable(before),
    next = inspectable(after);
  if (
    !plain(overlay) ||
    !isDeepStrictEqual(Object.keys(overlay), ['services']) ||
    !plain(overlay.services) ||
    !isDeepStrictEqual(Object.keys(overlay.services), ['control-api'])
  )
    throw blocked('TOPOLOGY');
  const added = overlay.services['control-api'];
  if (
    !plain(added) ||
    !isDeepStrictEqual(Object.keys(added).sort(), ['environment', 'ports', 'volumes']) ||
    !Array.isArray(added.ports) ||
    added.ports.length !== 1 ||
    !Array.isArray(added.volumes) ||
    !plain(added.environment) ||
    !isDeepStrictEqual(Object.keys(added.environment), [
      'CONTROL_API_NOTIFICATION_VERIFICATION_FILE',
    ]) ||
    added.volumes.some((v) => !mount.safeParse(v).success) ||
    !descriptor.shape.port.safeParse(added.ports[0]).success
  )
    throw blocked('TOPOLOGY');
  const source = prior.services['control-api'],
    actual = next.services['control-api'];
  if (
    !plain(source.environment) ||
    !plain(actual.environment) ||
    Object.hasOwn(source.environment, 'CONTROL_API_NOTIFICATION_VERIFICATION_FILE') ||
    !Array.isArray(source.volumes) ||
    !Array.isArray(source.ports) ||
    !Array.isArray(actual.volumes) ||
    !Array.isArray(actual.ports)
  )
    throw blocked('TOPOLOGY');
  const targets = added.volumes.map((v) => v.target),
    containerRoot = dirnameOfConfig(added.environment.CONTROL_API_NOTIFICATION_VERIFICATION_FILE);
  if (
    source.volumes.some(
      (v) =>
        targets.some((target) => v.target === target || target.startsWith(`${v.target}/`)) ||
        v.target.startsWith(`${containerRoot}/`),
    ) ||
    source.ports.some(
      (p) =>
        Number(p.target) === added.ports[0].target ||
        (p.host_ip === added.ports[0].host_ip && Number(p.published) === added.ports[0].published),
    )
  )
    throw blocked('TOPOLOGY_COLLISION');
  if (!isDeepStrictEqual(actual.environment, { ...source.environment, ...added.environment }))
    throw blocked('TOPOLOGY');
  const newVolumes = actual.volumes.filter((v) => targets.includes(v.target));
  if (
    newVolumes.length !== added.volumes.length ||
    newVolumes.some((v) => {
      const expected = added.volumes.find((m) => m.target === v.target);
      // Compose may emit its default bind.create_host_path setting. It must not
      // add propagation, SELinux or any other writable/alternate mount behavior.
      const { bind, ...plainMount } = v;
      return (
        !isDeepStrictEqual(plainMount, expected) ||
        (bind !== undefined && !isDeepStrictEqual(bind, { create_host_path: true }))
      );
    })
  )
    throw blocked('TOPOLOGY_MOUNTS');
  const newPorts = actual.ports.filter((p) => Number(p.target) === added.ports[0].target);
  if (newPorts.length !== 1 || !isDeepStrictEqual(expectedPort(newPorts[0]), added.ports[0]))
    throw blocked('TOPOLOGY_PORT');
  actual.environment = source.environment;
  actual.volumes = actual.volumes.filter((v) => !targets.includes(v.target));
  actual.ports = actual.ports.filter((p) => Number(p.target) !== added.ports[0].target);
  if (!isDeepStrictEqual(prior, next)) throw blocked('TOPOLOGY_DRIFT');
}
function dirnameOfConfig(config) {
  if (!absolute.safeParse(config).success || basename(config) !== 'configuration.json')
    throw blocked('TOPOLOGY');
  return config.slice(0, -'/configuration.json'.length);
}

/** Safe root-facing failure. UNKNOWN/partial setup never authorizes generic
 * destructive cleanup. Actual driver/owner evidence retains business identity;
 * arbitrary diagnostics, Compose output and database URLs are not serialized. */
export class NotificationPackagedBrowserFailure extends AggregateError {
  constructor(phase, cleanupUnknown = false) {
    const allowed = [
      'REQUEST',
      'ADMISSION',
      'NETWORK',
      'PREPARATION',
      'OVERLAY',
      'STARTUP',
      'BROWSER',
      'CLEANUP',
    ];
    if (!allowed.includes(phase)) throw blocked('FAILURE');
    super(
      [blocked(phase), ...(cleanupUnknown ? [blocked('CLEANUP_UNKNOWN')] : [])],
      `BLOCKED_NOTIFICATION_PACKAGED_BROWSER_${phase}`,
    );
    this.disposition = Object.freeze({
      phase,
      state: ['REQUEST', 'ADMISSION'].includes(phase) ? 'NOT_STARTED' : 'UNKNOWN_RETAIN_ALL',
      genericCleanupAllowed: false,
      filesRetained: true,
      exitCode: cleanupUnknown ? 99 : 96,
    });
  }
}

// Commands are fixed by this feature owner. There is no callback, arbitrary
// command, shell wrapper or caller-produced readiness/cleanup authority.
export function notificationPackagedLifecycleArguments(operation) {
  if (operation === 'START_CONTROL_API')
    return Object.freeze([
      'up',
      '--detach',
      '--no-deps',
      '--no-build',
      '--pull',
      'never',
      '--wait',
      '--wait-timeout',
      '120',
      'control-api',
    ]);
  if (operation === 'RESTART_BROWSER_SERVICES')
    return Object.freeze(['restart', '--no-deps', 'control-api', 'admin-web']);
  throw blocked('LIFECYCLE_OPERATION');
}

// Never attach raw exec errors (they can contain rendered credentials). Keep
// the canonical network owner's bounded, deliberately safe denial marker.
function command(file, argv, { input = '', timeout = 15000, network = false } = {}) {
  return new Promise((accept, reject) => {
    let inputError;
    const child = execFile(
      file,
      argv,
      {
        cwd: repository,
        timeout,
        maxBuffer: 4 * 1024 * 1024,
      },
      (error, stdout, stderr) => {
        if (network) {
          for (const line of stderr.split('\n'))
            if (
              /^OPENPC_NETWORK\|(?:PASS\|mode=(?:before|verify)\|subnet=[0-9./]{1,18}|BLOCKED\|[a-z0-9-]{1,160})$/u.test(
                line,
              )
            )
              process.stderr.write(`${line}\n`);
        }
        if (error || inputError) {
          const marker =
            network &&
            stderr
              .split('\n')
              .find((line) => /^OPENPC_NETWORK\|BLOCKED\|[a-z0-9-]{1,160}$/u.test(line));
          reject(marker ? new Error(marker) : blocked(network ? 'NETWORK_COMMAND' : 'COMMAND'));
        } else accept(stdout);
      },
    );
    child.stdin.on('error', (error) => {
      inputError = error;
    });
    child.stdin.end(input);
  });
}
async function ownedFile(file, maximum) {
  if ((await realpath(file)) !== file) throw blocked('ROOT');
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const bytes = Buffer.alloc(maximum + 1);
  try {
    const info = await handle.stat();
    if (
      !info.isFile() ||
      info.uid !== process.getuid() ||
      info.mode & 0o022 ||
      info.size < 1 ||
      info.size > maximum
    )
      throw blocked('ROOT');
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    if (bytesRead !== info.size || bytesRead > maximum) throw blocked('ROOT');
    return Buffer.from(bytes.subarray(0, bytesRead));
  } finally {
    bytes.fill(0);
    await handle.close();
  }
}
/** Cheap source prerequisite before images/services. Rechecked by composeOwner
 * at actual use; this check alone grants no runtime or cleanup authority. */
export async function notificationPackagedSourcePreflight(
  file = join(repository, 'deploy/compose/local/compose.yaml'),
) {
  if (!absolute.safeParse(file).success) throw blocked('ROOT');
  await ownedFile(file, 4 * 1024 * 1024);
}
async function composeOwner(runRoot, composeArgv) {
  if (!absolute.safeParse(runRoot).success) throw blocked('ROOT');
  for (const directory of [runRoot, join(runRoot, 'data')]) {
    const info = await stat(directory);
    if (
      (await realpath(directory)) !== directory ||
      !info.isDirectory() ||
      info.uid !== process.getuid() ||
      info.mode & 0o077
    )
      throw blocked('ROOT');
  }
  const sentinel = (await ownedFile(join(runRoot, '.openpc-local-runtime-owner'), 256)).toString();
  const match = /^openpc-local-runtime:(openpc-local-e2e-[0-9a-f]{12}):([0-9a-f]{64})\n$/u.exec(
    sentinel,
  );
  if (!match || match[1] !== `openpc-local-e2e-${match[2].slice(0, 12)}`) throw blocked('ROOT');
  const identity = { root: runRoot, project: match[1], token: match[2] };
  const binding = validateStoredBinding(
    parseNotificationPackagedNetworkJson(
      await ownedFile(join(runRoot, 'data/local-runtime-network.json'), 262144),
    ),
    identity,
  );
  const options = notificationPackagedComposeOptions({
    argv: composeArgv,
    runRoot,
    repository,
    project: identity.project,
  });
  for (const file of options.files) await ownedFile(file, 4 * 1024 * 1024);
  await command('bash', [
    join(repository, 'scripts/maintenance/run-bounded.sh'),
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  const owner = { identity, binding, composeArgv };
  // Authenticate the real FD8/FD9 ancestors before rendering. This alone is
  // not lifecycle validation: before/verify below consume real rendered stdin.
  await networkCheck(owner, 'compose-overlay');
  return owner;
}
function networkCheck(owner, mode, rendered = '') {
  const { identity, binding } = owner;
  return command(
    process.execPath,
    [
      join(repository, 'scripts/maintenance/local-runtime-network.mjs'),
      mode,
      identity.root,
      identity.project,
      identity.token,
      binding.subnet,
      binding.gateway,
      'retained',
    ],
    { input: rendered, network: true },
  );
}
async function checkedRender(owner, mode) {
  const rendered = await command(owner.composeArgv[0], [
    ...owner.composeArgv.slice(1),
    '--profile',
    'astra05',
    'config',
    '--format',
    'json',
  ]);
  const parsed = parseNotificationPackagedJson(Buffer.from(rendered));
  if ((await networkCheck(owner, mode, rendered)) !== 'existing\n')
    throw blocked('RETAINED_NETWORK');
  return parsed;
}

/** Match real Docker inspection to the actual rendered service and private
 * transport projection. This pure comparison is not an ownership receipt. */
export function assertNotificationPackagedBrowserContainer({
  container,
  project,
  service,
  overlay,
}) {
  const expected = overlay.services['control-api'];
  const environment = container?.Config?.Env;
  const labels = container?.Config?.Labels;
  const mounts = container?.Mounts;
  const selectedPort = expected.ports[0];
  const containerRoot = dirnameOfConfig(
    expected.environment.CONTROL_API_NOTIFICATION_VERIFICATION_FILE,
  );
  if (
    !container?.State?.Running ||
    labels?.['com.docker.compose.project'] !== project ||
    labels?.['com.docker.compose.service'] !== 'control-api' ||
    container?.Config?.Image !== service.image ||
    !Array.isArray(environment) ||
    !isDeepStrictEqual(
      environment.filter((entry) =>
        entry.startsWith('CONTROL_API_NOTIFICATION_VERIFICATION_FILE='),
      ),
      [
        `CONTROL_API_NOTIFICATION_VERIFICATION_FILE=${expected.environment.CONTROL_API_NOTIFICATION_VERIFICATION_FILE}`,
      ],
    ) ||
    !Array.isArray(mounts) ||
    expected.volumes.some((volume) => {
      const selected = mounts.filter((entry) => entry.Destination === volume.target);
      return (
        selected.length !== 1 ||
        selected[0].Type !== 'bind' ||
        selected[0].Source !== volume.source ||
        selected[0].RW !== false
      );
    }) ||
    mounts.some(
      (entry) =>
        (entry.Destination === containerRoot ||
          containerRoot.startsWith(`${entry.Destination}/`) ||
          entry.Destination.startsWith(`${containerRoot}/`)) &&
        !expected.volumes.some((volume) => volume.target === entry.Destination),
    ) ||
    !isDeepStrictEqual(container?.NetworkSettings?.Ports?.[`${selectedPort.target}/tcp`], [
      { HostIp: selectedPort.host_ip, HostPort: String(selectedPort.published) },
    ])
  )
    throw blocked('CONTAINER_TRANSPORT');
}
async function transportOverlay(owner) {
  const path = join(owner.identity.root, 'data/notification-packaged/compose.json');
  const options = notificationPackagedComposeOptions({
    argv: owner.composeArgv,
    runRoot: owner.identity.root,
    project: owner.identity.project,
    repository,
  });
  if (options.files.at(-1) !== path) throw blocked('OVERLAY_ORDER');
  const overlay = parseNotificationPackagedJson(await ownedFile(path, 65536));
  const service = overlay.services?.['control-api'];
  const config = service?.environment?.CONTROL_API_NOTIFICATION_VERIFICATION_FILE;
  const validated = notificationPackagedBrowserOverlay({
    runRoot: owner.identity.root,
    containerRoot: dirnameOfConfig(config),
    runtime: {
      configurationFile: config,
      mounts: service.volumes,
      environment: service.environment,
      port: service.ports?.[0],
    },
  });
  if (!isDeepStrictEqual(overlay, validated)) throw blocked('OVERLAY');
  return validated;
}
async function inspectControl(owner, rendered, overlay) {
  const id = (
    await command(owner.composeArgv[0], [
      ...owner.composeArgv.slice(1),
      'ps',
      '--all',
      '--quiet',
      'control-api',
    ])
  ).trim();
  if (!/^[a-f0-9]{64}$/u.test(id)) throw blocked('CONTAINER');
  const inspected = parseNotificationPackagedJson(
    Buffer.from(await command('docker', ['inspect', id])),
  );
  if (!Array.isArray(inspected) || inspected.length !== 1 || inspected[0].Id !== id)
    throw blocked('CONTAINER');
  assertNotificationPackagedBrowserContainer({
    container: inspected[0],
    project: owner.identity.project,
    service: rendered.services['control-api'],
    overlay,
  });
}

let lifecycleRunning = false;
/** The existing driver's packaged restarts call this same executor. It never
 * allocates anchors, starts dependencies, refreshes images or changes caps. */
export async function runNotificationPackagedCompose(value) {
  const parsed = z
    .strictObject({
      runRoot: absolute,
      composeArgv: z.array(argument).min(6).max(24),
      operation: z.enum(['START_CONTROL_API', 'RESTART_BROWSER_SERVICES']),
    })
    .safeParse(value);
  if (!parsed.success || lifecycleRunning) throw blocked('LIFECYCLE_REQUEST');
  lifecycleRunning = true;
  try {
    const { runRoot, composeArgv, operation } = parsed.data;
    const owner = await composeOwner(runRoot, composeArgv);
    const overlay = await transportOverlay(owner);
    const before = await checkedRender(owner, 'before');
    let first;
    try {
      await command(
        composeArgv[0],
        [...composeArgv.slice(1), ...notificationPackagedLifecycleArguments(operation)],
        { timeout: operation === 'START_CONTROL_API' ? 150000 : 90000 },
      );
    } catch (error) {
      first = error;
    }
    try {
      const after = await checkedRender(owner, 'verify');
      if (!isDeepStrictEqual(before, after)) throw blocked('LIFECYCLE_TOPOLOGY_CHANGED');
      if (!isDeepStrictEqual(overlay, await transportOverlay(owner)))
        throw blocked('LIFECYCLE_OVERLAY_CHANGED');
      await inspectControl(owner, after, overlay);
    } catch (error) {
      first ??= error;
    }
    if (first) throw first;
  } finally {
    lifecycleRunning = false;
  }
}

const browserFlags = {
  OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_BROWSER: '1',
  OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UPDATE_BROWSER: '1',
  OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UNKNOWN_BROWSER: '0',
};
const browserSelections = [
  'OPENPC_NOTIFICATION_ENDPOINT_REF',
  'OPENPC_NOTIFICATION_ENDPOINT_DESTINATION_REF',
  'OPENPC_NOTIFICATION_ENDPOINT_CHANNEL',
  'OPENPC_NOTIFICATION_ENDPOINT_REPLACEMENT_DESTINATION_REF',
  'OPENPC_NOTIFICATION_ENDPOINT_REPLACEMENT_DIGEST',
  'OPENPC_NOTIFICATION_ENDPOINT_UNKNOWN_REF',
];
/** Existing endpoint identities cannot be turned into fresh setup by changing
 * keys. The supported browser CREATE/UPDATE owns all business transitions. */
export function validateNotificationPackagedBrowserEnvironment(environment) {
  if (
    !plain(environment) ||
    browserSelections.some((name) => environment[name] !== undefined) ||
    Object.entries(browserFlags).some(
      ([name, value]) => environment[name] !== undefined && environment[name] !== value,
    )
  )
    throw blocked('ENVIRONMENT');
}
function selectBrowserDestinations(destinations) {
  const selected = {
    ...browserFlags,
    OPENPC_NOTIFICATION_ENDPOINT_CHANNEL: destinations[0].channel,
    OPENPC_NOTIFICATION_ENDPOINT_DESTINATION_REF: destinations[0].destinationRef,
    OPENPC_NOTIFICATION_ENDPOINT_REPLACEMENT_DESTINATION_REF: destinations[1].destinationRef,
  };
  const previous = Object.fromEntries(
    Object.keys(selected).map((name) => [name, process.env[name]]),
  );
  for (const [name, value] of Object.entries(selected)) process.env[name] = value;
  return () => {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  };
}

let browserRunning = false;
/** Same-process input/provider/runtime/browser ownership. No successful result
 * is returned before awaited browser completion and actual provider drain. */
export async function runNotificationPackagedBrowser(value) {
  let request;
  try {
    request = validateNotificationPackagedBrowserRequest(value);
    validateNotificationPackagedBrowserEnvironment({ ...process.env });
    if (browserRunning) throw blocked('CONCURRENT_BROWSER');
  } catch {
    throw new NotificationPackagedBrowserFailure('REQUEST');
  }
  browserRunning = true;
  let prepared,
    runtime,
    restoreEnvironment,
    first,
    cleanupUnknown = false,
    phase = 'ADMISSION';
  try {
    const { inputs, composeArgv } = request;
    const owner = await composeOwner(inputs.runRoot, composeArgv);
    phase = 'NETWORK';
    const before = await checkedRender(owner, 'before');
    phase = 'PREPARATION';
    prepared = await prepareNotificationPackagedInputs(inputs);
    runtime = await prepared.prepareRuntime();
    phase = 'OVERLAY';
    const transport = {
      runRoot: inputs.runRoot,
      containerRoot: inputs.containerRoot,
      runtime: {
        configurationFile: runtime.configurationFile,
        mounts: runtime.mounts,
        environment: runtime.environment,
        port: runtime.port,
      },
    };
    const overlay = notificationPackagedBrowserOverlay(transport);
    const file = await writeNotificationPackagedBrowserOverlay(transport);
    const withOverlay = [...composeArgv, '-f', file];
    const configured = await composeOwner(inputs.runRoot, withOverlay);
    const after = await checkedRender(configured, 'before');
    assertNotificationPackagedBrowserTopology({ before, after, overlay });
    phase = 'STARTUP';
    await runNotificationPackagedCompose({
      runRoot: inputs.runRoot,
      composeArgv: withOverlay,
      operation: 'START_CONTROL_API',
    });
    await prepared.assertCurrent();
    phase = 'BROWSER';
    restoreEnvironment = selectBrowserDestinations(prepared.destinations);
    await runtime.runBrowser({
      argv: [
        join(inputs.runRoot, 'secrets'),
        join(inputs.runRoot, 'evidence'),
        inputs.participantId,
        inputs.privacyDomainId,
        JSON.stringify(withOverlay),
      ],
    });
  } catch (error) {
    first = new NotificationPackagedBrowserFailure(phase);
    // Include only safe typed owner markers, never raw child output or URLs.
    if (
      /^(?:BLOCKED_NOTIFICATION_[A-Z_]+|OPENPC_NETWORK\|BLOCKED\|[a-z0-9-]{1,160})$/u.test(
        error?.message ?? '',
      )
    )
      first.errors.push(new Error(error.message));
    if (error instanceof AggregateError || /CLEANUP_UNKNOWN/u.test(error?.message ?? ''))
      cleanupUnknown = true;
  } finally {
    restoreEnvironment?.();
    try {
      if (runtime) {
        const result = await runtime.close();
        if (result?.providerDrain !== 'DRAINED' || result?.filesRetained !== true)
          cleanupUnknown = true;
      }
    } catch {
      cleanupUnknown = true;
    }
    try {
      await prepared?.close();
    } catch {
      cleanupUnknown = true;
    }
    browserRunning = false;
  }
  if (first || cleanupUnknown) {
    if (cleanupUnknown) {
      const failure = new NotificationPackagedBrowserFailure(
        first?.disposition.phase ?? 'CLEANUP',
        true,
      );
      if (first) failure.errors.splice(0, 1, ...first.errors);
      throw failure;
    }
    throw first;
  }
  return Object.freeze({
    status: 'PASS',
    scope: 'CREATE_UPDATE_VERIFY_BROWSER',
    fullNotificationAcceptance: 'OPEN',
    visualInspection: 'PENDING',
    providerDrain: 'DRAINED',
    filesRetained: true,
    genericCleanupAllowed: false,
    exitCode: 0,
  });
}

const rootLog = (runRoot) => join(runRoot, 'evidence/notification-browser/packaged-runtime.log');
const resultPrefix = 'OPENPC_NOTIFICATION_PACKAGED_RESULT|';
const terminalSchema = z.strictObject({
  schema: z.literal('openpc-notification-packaged-process-v1'),
  root: absolute,
  project: z.string().regex(/^openpc-local-e2e-[0-9a-f]{12}$/u),
  pid: z.number().int().positive(),
  result: z.strictObject({
    status: z.literal('PASS'),
    scope: z.literal('CREATE_UPDATE_VERIFY_BROWSER'),
    fullNotificationAcceptance: z.literal('OPEN'),
    visualInspection: z.literal('PENDING'),
    providerDrain: z.literal('DRAINED'),
    filesRetained: z.literal(true),
    genericCleanupAllowed: z.literal(false),
    exitCode: z.literal(0),
  }),
});

/** Compare actual Docker state with the root's rendered PostgreSQL mapping.
 * A caller-supplied DSN or a role guessed from a credential is never accepted. */
export function notificationPackagedDatabaseEndpoint({ container, rendered, runRoot, project }) {
  const service = rendered?.services?.['control-pg'];
  const ports = service?.ports?.filter((p) => Number(p.target) === 5432);
  const mappings = container?.NetworkSettings?.Ports?.['5432/tcp'];
  const mounts = container?.Mounts?.filter((m) => m.Destination === '/var/lib/postgresql');
  const environment = container?.Config?.Env;
  if (
    !absolute.safeParse(runRoot).success ||
    !container?.State?.Running ||
    container?.Config?.Labels?.['com.docker.compose.project'] !== project ||
    container?.Config?.Labels?.['com.docker.compose.service'] !== 'control-pg' ||
    container?.Config?.Image !== service?.image ||
    !Array.isArray(environment) ||
    [
      'POSTGRES_DB=openpc_control',
      'POSTGRES_USER=openpc_control',
      'POSTGRES_PASSWORD_FILE=/run/secrets/control_pg_password',
    ].some(
      (expected) =>
        !isDeepStrictEqual(
          environment.filter((entry) => entry.startsWith(`${expected.split('=')[0]}=`)),
          [expected],
        ),
    ) ||
    ports?.length !== 1 ||
    ports[0].protocol !== 'tcp' ||
    ports[0].host_ip !== '127.0.0.1' ||
    !port.safeParse(Number(ports[0].published)).success ||
    Number(ports[0].published) < 1024 ||
    !isDeepStrictEqual(mappings, [{ HostIp: '127.0.0.1', HostPort: String(ports[0].published) }]) ||
    mounts?.length !== 1 ||
    mounts[0].Type !== 'bind' ||
    mounts[0].RW !== true ||
    mounts[0].Source !== join(runRoot, 'data/control-pg')
  )
    throw blocked('DATABASE_MAPPING');
  return Object.freeze({ host: '127.0.0.1', port: Number(ports[0].published) });
}
async function privateDirectory(path) {
  const info = await lstat(path);
  if (
    (await realpath(path)) !== path ||
    !info.isDirectory() ||
    info.uid !== process.getuid() ||
    info.mode & 0o077
  )
    throw blocked('PRIVATE_INPUT');
}
/** File parsing only. The CLI first authenticates its real root/network and
 * observes the running database; SQL role/tenant checks remain with TWO. */
export async function readNotificationPackagedDatabaseInputs({ runRoot, endpoint }) {
  if (
    !absolute.safeParse(runRoot).success ||
    !z
      .strictObject({
        host: z.literal('127.0.0.1'),
        port: z.number().int().min(1024).max(65535),
      })
      .safeParse(endpoint).success
  )
    throw blocked('PRIVATE_INPUT');
  await privateDirectory(runRoot);
  await privateDirectory(join(runRoot, 'secrets'));
  const result = {};
  for (const [field, user, name] of [
    ['installationUrl', 'openpc_control', 'control_pg_password.txt'],
    ['runtimeUrl', 'openpc_configuration_runtime', 'control_api_runtime_db_password.txt'],
  ]) {
    const path = join(runRoot, 'secrets', name);
    const info = await lstat(path);
    if (info.nlink !== 1) throw blocked('PRIVATE_INPUT');
    const bytes = await ownedFile(path, 65);
    try {
      if (!/^[0-9a-f]{64}\n$/u.test(bytes.toString())) throw blocked('PRIVATE_INPUT');
      const url = new URL(`postgresql://${endpoint.host}:${endpoint.port}/openpc_control`);
      url.username = user;
      url.password = bytes.subarray(0, 64).toString();
      result[field] = url.href;
    } finally {
      bytes.fill(0);
    }
  }
  return result;
}
async function databaseInputs(owner, rendered) {
  const id = (
    await command(owner.composeArgv[0], [
      ...owner.composeArgv.slice(1),
      'ps',
      '--all',
      '--quiet',
      'control-pg',
    ])
  ).trim();
  if (!/^[0-9a-f]{64}$/u.test(id)) throw blocked('DATABASE_MAPPING');
  const records = parseNotificationPackagedJson(
    Buffer.from(await command('docker', ['inspect', id])),
  );
  if (!Array.isArray(records) || records.length !== 1 || records[0].Id !== id)
    throw blocked('DATABASE_MAPPING');
  const endpoint = notificationPackagedDatabaseEndpoint({
    container: records[0],
    rendered,
    runRoot: owner.identity.root,
    project: owner.identity.project,
  });
  return readNotificationPackagedDatabaseInputs({ runRoot: owner.identity.root, endpoint });
}

/** Strict command parsing occurs before filesystem, child commands or secrets. */
export function notificationPackagedBrowserCliArguments(argv) {
  if (!Array.isArray(argv) || !argv.every((v) => argument.safeParse(v).success))
    throw blocked('CLI_ARGUMENTS');
  if (argv.length === 1 && argv[0] === 'preflight-source') return { mode: 'preflight-source' };
  if (argv[0] === 'run' && argv.length === 5) {
    const [, runRoot, participantId, privacyDomainId, encoded] = argv;
    const uuid = z
      .string()
      .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
    if (
      !absolute.safeParse(runRoot).success ||
      !uuid.safeParse(participantId).success ||
      !uuid.safeParse(privacyDomainId).success
    )
      throw blocked('CLI_ARGUMENTS');
    const composeArgv = z.array(argument).min(6).max(22).parse(JSON.parse(encoded));
    if (composeArgv[0] !== 'docker' || composeArgv[1] !== 'compose') throw blocked('CLI_ARGUMENTS');
    return { mode: 'run', runRoot, participantId, privacyDomainId, composeArgv };
  }
  if (argv[0] === 'inspect-result' && argv.length === 6) {
    const [, runRoot, project, pid, exitCode, encoded] = argv;
    if (
      !absolute.safeParse(runRoot).success ||
      !/^openpc-local-e2e-[0-9a-f]{12}$/u.test(project) ||
      !/^[1-9][0-9]{0,9}$/u.test(pid) ||
      exitCode !== '0'
    )
      throw blocked('CLI_ARGUMENTS');
    const composeArgv = z.array(argument).min(6).max(24).parse(JSON.parse(encoded));
    if (composeArgv[0] !== 'docker' || composeArgv[1] !== 'compose') throw blocked('CLI_ARGUMENTS');
    return { mode: 'inspect-result', runRoot, project, pid: Number(pid), composeArgv };
  }
  throw blocked('CLI_ARGUMENTS');
}

/** This is only a private process-completion record. It never grants generic
 * cleanup or business authority and is accepted only after live root checks. */
export function notificationPackagedBrowserTerminalResult({ log, runRoot, project, pid }) {
  if (typeof log !== 'string' || !log.endsWith('\n')) throw blocked('HANDOFF');
  const lines = log.slice(0, -1).split('\n');
  const selected = lines.filter((line) => line.startsWith(resultPrefix));
  if (selected.length !== 1 || selected[0] !== lines.at(-1)) throw blocked('HANDOFF');
  const value = terminalSchema.parse(
    parseNotificationPackagedJson(Buffer.from(selected[0].slice(resultPrefix.length))),
  );
  if (value.root !== runRoot || value.project !== project || value.pid !== pid)
    throw blocked('HANDOFF');
  return 'DRAINED_RETAINED';
}
async function checkedLog(runRoot, writing = false) {
  await privateDirectory(runRoot);
  await privateDirectory(join(runRoot, 'evidence'));
  await privateDirectory(join(runRoot, 'evidence/notification-browser'));
  const path = rootLog(runRoot);
  const info = await lstat(path);
  if (
    !info.isFile() ||
    info.nlink !== 1 ||
    info.uid !== process.getuid() ||
    info.mode & 0o077 ||
    (await realpath(path)) !== path
  )
    throw blocked('LOG');
  if (writing) {
    const stdout = fstatSync(1),
      stderr = fstatSync(2);
    if (
      info.size !== 0 ||
      !stdout.isFile() ||
      stdout.dev !== info.dev ||
      stdout.ino !== info.ino ||
      stderr.dev !== info.dev ||
      stderr.ino !== info.ino
    )
      throw blocked('LOG');
  }
  return path;
}
async function writeTerminal(runRoot, line) {
  await new Promise((accept, reject) =>
    process.stdout.write(`${line}\n`, (error) => (error ? reject(error) : accept())),
  );
  fsyncSync(1);
  const directory = await open(
    dirname(rootLog(runRoot)),
    constants.O_RDONLY | constants.O_DIRECTORY,
  );
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

export async function runNotificationPackagedBrowserCli(argv = process.argv.slice(2)) {
  let input,
    owner,
    logging = false;
  try {
    input = notificationPackagedBrowserCliArguments(argv);
    if (input.mode === 'preflight-source') {
      await notificationPackagedSourcePreflight();
      process.stderr.write('OPENPC_NOTIFICATION_PACKAGED_SOURCE|PASS|owned-nonwritable-source\n');
      return 0;
    }
    if (input.mode === 'run') {
      validateNotificationPackagedBrowserEnvironment({ ...process.env });
      await checkedLog(input.runRoot, true);
      logging = true;
    }
    owner = await composeOwner(input.runRoot, input.composeArgv);
    const rendered = await checkedRender(owner, input.mode === 'run' ? 'before' : 'verify');
    if (input.mode === 'inspect-result') {
      if (owner.identity.project !== input.project) throw blocked('HANDOFF');
      // A live child cannot be treated as drained merely because it wrote output.
      try {
        process.kill(input.pid, 0);
        throw blocked('CHILD_STILL_LIVE');
      } catch (error) {
        if (error.code !== 'ESRCH') throw error;
      }
      const path = await checkedLog(input.runRoot);
      const log = (await ownedFile(path, 4 * 1024 * 1024)).toString();
      const outcome = notificationPackagedBrowserTerminalResult({
        log,
        runRoot: input.runRoot,
        project: input.project,
        pid: input.pid,
      });
      process.stdout.write(`${outcome}\n`);
      return 0;
    }
    // A retained provider/input root is never reopened by this fresh-only CLI.
    for (const name of ['notification-inputs', 'notification-packaged']) {
      try {
        await lstat(join(input.runRoot, 'data', name));
        throw blocked('FRESH_ROOT');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
    const database = await databaseInputs(owner, rendered);
    const request = validateNotificationPackagedBrowserRequest({
      inputs: {
        runRoot: input.runRoot,
        participantId: input.participantId,
        privacyDomainId: input.privacyDomainId,
        database,
        channels: ['WEBHOOK', 'WEBHOOK'],
        validityMs: 3600000,
        minimumRemainingMs: 120000,
        controlListenPort: 3448,
      },
      composeArgv: input.composeArgv,
    });
    const result = await runNotificationPackagedBrowser(request);
    const record = terminalSchema.parse({
      schema: 'openpc-notification-packaged-process-v1',
      root: owner.identity.root,
      project: owner.identity.project,
      pid: process.pid,
      result,
    });
    await writeTerminal(input.runRoot, resultPrefix + JSON.stringify(record));
    return 0;
  } catch (error) {
    const exitCode =
      error instanceof NotificationPackagedBrowserFailure ? error.disposition.exitCode : 99;
    // No exec errors, URLs, passwords or raw assertions enter the root handoff.
    const phase =
      error instanceof NotificationPackagedBrowserFailure ? error.disposition.phase : 'CLI';
    const marker = `OPENPC_NOTIFICATION_PACKAGED_CLI|UNKNOWN_RETAIN_ALL|phase=${phase}|exit=${exitCode}|boundary=${notificationPackagedFailureBoundary(error)}`;
    if (logging) {
      try {
        await writeTerminal(input.runRoot, marker);
      } catch {
        process.stderr.write(
          'OPENPC_NOTIFICATION_PACKAGED_CLI|UNKNOWN_RETAIN_ALL|log-sync-failed\n',
        );
      }
    } else process.stderr.write(`${marker}\n`);
    return exitCode;
  }
}

// The browser's restart owner dynamically imports this module. Awaiting the
// entire journey at module scope would keep that import pending on itself.
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  void runNotificationPackagedBrowserCli().then(
    (code) => {
      process.exitCode = code;
    },
    () => {
      process.stderr.write(
        'OPENPC_NOTIFICATION_PACKAGED_CLI|UNKNOWN_RETAIN_ALL|entrypoint-failed\n',
      );
      process.exitCode = 99;
    },
  );
