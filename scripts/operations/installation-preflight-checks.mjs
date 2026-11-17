import { posix } from 'node:path';
import { canonicalJson } from '../../services/control-api/src/configuration/digest.ts';
import { InstallationConfigError } from './installation-config-inputs.mjs';

const digest = /^sha256:[0-9a-f]{64}$/u;
const identifier = /^[a-z][a-z0-9-]{0,95}$/u;
const imageOwner = 'openpc-r1-local-runtime-v1';
const localImageServices = new Set([
  'control-worker',
  'fact-service',
  'policy-service',
  'identity-service',
  'participant-service',
  'control-api',
  'admin-web',
]);

export function rejectPreflight(reason) {
  throw new InstallationConfigError(reason);
}

export function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function absolutePath(value) {
  if (
    typeof value !== 'string' ||
    value.length > 4096 ||
    !value.startsWith('/') ||
    value === '/' ||
    posix.normalize(value) !== value ||
    [...value].some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127 || character === '\\',
    )
  )
    rejectPreflight('PREFLIGHT_PATH_INVALID');
  return value;
}

function positiveInteger(value) {
  if (
    (typeof value !== 'number' && (typeof value !== 'string' || !/^[1-9][0-9]*$/u.test(value))) ||
    !Number.isSafeInteger(Number(value)) ||
    Number(value) <= 0
  )
    rejectPreflight('PREFLIGHT_RESOURCE_UNBOUNDED');
  return Number(value);
}

function boundedCpu(value) {
  if (
    typeof value !== 'number' &&
    (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u.test(value))
  )
    rejectPreflight('PREFLIGHT_RESOURCE_UNBOUNDED');
  const cpus = Number(value);
  if (!Number.isFinite(cpus) || cpus <= 0 || cpus > 2)
    rejectPreflight('PREFLIGHT_RESOURCE_UNBOUNDED');
  return cpus;
}

function environment(value) {
  if (!object(value)) rejectPreflight('PREFLIGHT_ENVIRONMENT_INVALID');
  for (const [name, item] of Object.entries(value)) {
    if (
      !/^[A-Z][A-Z0-9_]*$/u.test(name) ||
      typeof item !== 'string' ||
      item.includes('${') ||
      ['\0', '\r', '\n'].some((character) => item.includes(character))
    )
      rejectPreflight('PREFLIGHT_ENVIRONMENT_INVALID');
    // Actual local entrypoints consume credentials by file. Never print a rejected value.
    if (
      /(?:PASSWORD|TOKEN|PRIVATE_KEY|SECRET)$/u.test(name) ||
      /-----BEGIN .*PRIVATE KEY-----/u.test(item)
    )
      rejectPreflight('PREFLIGHT_INLINE_SECRET');
  }
  return value;
}

/** Normalized docker compose config --format json; no YAML or interpolation here. */
export function checkRenderedCompose(rendered, selectedServices) {
  if (
    !object(rendered) ||
    !identifier.test(rendered.name) ||
    !object(rendered.services) ||
    !object(rendered.networks) ||
    !Array.isArray(selectedServices) ||
    selectedServices.length === 0 ||
    selectedServices.length > 64 ||
    new Set(selectedServices).size !== selectedServices.length
  )
    rejectPreflight('PREFLIGHT_COMPOSE_INVALID');
  let memoryBytes = 0;
  for (const name of selectedServices) {
    if (typeof name !== 'string' || !identifier.test(name) || !object(rendered.services[name]))
      rejectPreflight('PREFLIGHT_SERVICE_MISSING');
    const service = rendered.services[name];
    environment(service.environment ?? {});
    if (
      service.platform !== 'linux/amd64' ||
      service.privileged === true ||
      service.network_mode ||
      service.pid === 'host' ||
      service.ipc === 'host' ||
      service.volumes_from
    )
      rejectPreflight('PREFLIGHT_SERVICE_ISOLATION');
    if (typeof service.image !== 'string' || service.image.includes('${'))
      rejectPreflight('PREFLIGHT_IMAGE_UNBOUND');
    if ((service.build || name === 'runtime-target') && service.read_only !== true)
      rejectPreflight('PREFLIGHT_SERVICE_ISOLATION');
    if (service.env_file?.length) rejectPreflight('PREFLIGHT_ENV_FILE_UNRESOLVED');
    const memory = positiveInteger(service.mem_limit);
    boundedCpu(service.cpus);
    positiveInteger(service.pids_limit);
    memoryBytes += memory;
    if (!Number.isSafeInteger(memoryBytes)) rejectPreflight('PREFLIGHT_RESOURCE_UNBOUNDED');
    if (!object(service.networks) || Object.keys(service.networks).length === 0)
      rejectPreflight('PREFLIGHT_NETWORK_UNBOUND');
    for (const network of Object.keys(service.networks)) {
      const definition = rendered.networks[network];
      if (
        !object(definition) ||
        definition.external === true ||
        definition.name !== `${rendered.name}_${network}` ||
        !identifier.test(network)
      )
        rejectPreflight('PREFLIGHT_NETWORK_OWNERSHIP');
    }
    for (const [dependency, rule] of Object.entries(service.depends_on ?? {})) {
      if (!object(rendered.services[dependency])) rejectPreflight('PREFLIGHT_DEPENDENCY_MISSING');
      if (
        !object(rule) ||
        rule.required === false ||
        !['service_started', 'service_healthy', 'service_completed_successfully'].includes(
          rule.condition,
        )
      )
        rejectPreflight('PREFLIGHT_DEPENDENCY_INVALID');
      if (dependency.endsWith('-migrate') && rule.condition !== 'service_completed_successfully')
        rejectPreflight('PREFLIGHT_MIGRATION_BINDING');
    }
    renderedMounts(rendered, name);
  }
  return memoryBytes;
}

/** Native mount identities only; this never reads or resolves any secret file. */
export function renderedMounts(rendered, name) {
  const service = rendered.services[name];
  const mounts = new Map();
  const add = (target, item) => {
    absolutePath(target);
    if (mounts.has(target)) rejectPreflight('PREFLIGHT_MOUNT_DUPLICATE');
    mounts.set(target, item);
  };
  for (const mount of service.volumes ?? []) {
    if (!object(mount) || !['bind', 'volume', 'tmpfs'].includes(mount.type))
      rejectPreflight('PREFLIGHT_MOUNT_INVALID');
    if (mount.type === 'bind') {
      add(mount.target, {
        type: 'bind',
        source: absolutePath(mount.source),
        readOnly: mount.read_only === true,
      });
    } else if (mount.type === 'volume') {
      const volume = rendered.volumes?.[mount.source];
      if (
        !object(volume) ||
        volume.external === true ||
        !identifier.test(mount.source) ||
        volume.name !== `${rendered.name}_${mount.source}`
      )
        rejectPreflight('PREFLIGHT_VOLUME_OWNERSHIP');
      add(mount.target, {
        type: 'volume',
        source: volume.name,
        readOnly: mount.read_only === true,
      });
    } else add(mount.target, { type: 'tmpfs', source: null, readOnly: mount.read_only === true });
  }
  for (const [section, prefix] of [
    ['secrets', '/run/secrets/'],
    ['configs', '/'],
  ]) {
    for (const mount of service[section] ?? []) {
      if (!object(mount) || typeof mount.source !== 'string')
        rejectPreflight('PREFLIGHT_MOUNT_INVALID');
      const definition = rendered[section]?.[mount.source];
      if (
        !object(definition) ||
        definition.external === true ||
        !definition.file ||
        definition.environment !== undefined ||
        definition.content !== undefined
      )
        rejectPreflight('PREFLIGHT_FILE_BINDING_MISSING');
      const target = mount.target ?? mount.source;
      if (typeof target !== 'string') rejectPreflight('PREFLIGHT_MOUNT_INVALID');
      add(target.startsWith('/') ? target : `${prefix}${target}`, {
        type: 'bind',
        source: absolutePath(definition.file),
        readOnly: true,
      });
    }
  }
  for (const [key, value] of Object.entries(service.environment ?? {})) {
    if (!/_FILES?$/u.test(key)) continue;
    const paths = key.endsWith('_FILES') ? value.split(',') : [value];
    for (const path of paths) {
      absolutePath(path);
      // Longest containing directory binds generated runtime files too. Their existence,
      // inode identity and custody still require the original owner at runtime.
      const containing = [...mounts.keys()].filter(
        (target) => path === target || path.startsWith(`${target}/`),
      );
      if (containing.length === 0) rejectPreflight('PREFLIGHT_CONSUMED_FILE_UNMOUNTED');
      if (path.startsWith('/run/secrets/') && mounts.get(path)?.readOnly !== true)
        rejectPreflight('PREFLIGHT_SECRET_MOUNT_WRITABLE');
    }
  }
  return mounts;
}

function repositoryDigest(reference) {
  if (typeof reference !== 'string' || !/^[A-Za-z0-9._/:+-]+@sha256:[0-9a-f]{64}$/u.test(reference))
    return null;
  const [tagged, hash] = reference.split('@');
  const repository =
    tagged.lastIndexOf(':') > tagged.lastIndexOf('/')
      ? tagged.slice(0, tagged.lastIndexOf(':'))
      : tagged;
  return `${repository.replace(/^docker\.io\//u, '').replace(/^library\//u, '')}@${hash}`;
}

export function checkImageBindings(rendered, selectedServices, inspected) {
  if (!Array.isArray(inspected) || inspected.length === 0 || inspected.length > 128)
    rejectPreflight('PREFLIGHT_IMAGE_INSPECTION_MISSING');
  const result = {};
  const ids = new Set();
  for (const image of inspected) {
    if (!object(image) || !digest.test(image.Id) || ids.has(image.Id))
      rejectPreflight('PREFLIGHT_IMAGE_INSPECTION_INVALID');
    ids.add(image.Id);
  }
  for (const name of selectedServices) {
    const service = rendered.services[name];
    const stable = /^openpc-r1-dev\/([a-z][a-z0-9-]+):local$/u.exec(service.image);
    const pinned = repositoryDigest(service.image);
    if (!stable && !pinned) rejectPreflight('PREFLIGHT_FLOATING_IMAGE');
    if (stable && !localImageServices.has(stable[1])) rejectPreflight('PREFLIGHT_IMAGE_OWNERSHIP');
    const matches = inspected.filter((image) =>
      stable
        ? image.RepoTags?.includes(service.image)
        : image.RepoDigests?.some((reference) => repositoryDigest(reference) === pinned),
    );
    if (matches.length !== 1) rejectPreflight('PREFLIGHT_IMAGE_UNBOUND');
    const image = matches[0];
    if (image.Os !== 'linux' || image.Architecture !== 'amd64')
      rejectPreflight('PREFLIGHT_IMAGE_PLATFORM');
    if (
      stable &&
      (image.Config?.Labels?.['io.openpc.image.owner'] !== imageOwner ||
        image.Config?.Labels?.['io.openpc.image.service'] !== stable[1])
    )
      rejectPreflight('PREFLIGHT_IMAGE_OWNERSHIP');
    if (
      service.build &&
      (service.build.labels?.['io.openpc.image.owner'] !== imageOwner ||
        service.build.labels?.['io.openpc.image.service'] !== stable?.[1])
    )
      rejectPreflight('PREFLIGHT_BUILD_OWNERSHIP');
    result[name] = image.Id;
  }
  return result;
}

/** Detect changed final renders; selection/order belongs to the existing runner. */
export function compareRenderedBindings(prepared, current, services) {
  if (prepared.name !== current.name) rejectPreflight('PREFLIGHT_PROJECT_CHANGED');
  for (const name of services) {
    if (canonicalJson(prepared.services[name]) !== canonicalJson(current.services[name]))
      rejectPreflight('PREFLIGHT_SERVICE_CONFIGURATION_CHANGED');
    if (
      canonicalJson([...renderedMounts(prepared, name)]) !==
      canonicalJson([...renderedMounts(current, name)])
    )
      rejectPreflight('PREFLIGHT_MOUNT_CHANGED');
    for (const network of Object.keys(prepared.services[name].networks))
      if (canonicalJson(prepared.networks[network]) !== canonicalJson(current.networks[network]))
        rejectPreflight('PREFLIGHT_NETWORK_CHANGED');
  }
}

/** Docker inspection consistency is supporting evidence, never signed/live readiness. */
export function checkContainerBindings(rendered, services, images, containers, inspectedImages) {
  if (!Array.isArray(containers) || containers.length > 128)
    rejectPreflight('PREFLIGHT_CONTAINER_OBSERVATION_INVALID');
  const selected = new Map();
  for (const container of containers) {
    const labels = container.Config?.Labels;
    const name = labels?.['com.docker.compose.service'];
    if (
      labels?.['com.docker.compose.project'] !== rendered.name ||
      !services.includes(name) ||
      selected.has(name) ||
      !/^[0-9a-f]{64}$/u.test(container.Id)
    )
      rejectPreflight('PREFLIGHT_CONTAINER_OWNERSHIP');
    selected.set(name, container);
  }
  for (const name of services) {
    const container = selected.get(name);
    if (!container) rejectPreflight('PREFLIGHT_CONTAINER_OBSERVATION_MISSING');
    const expected = rendered.services[name];
    if (container.Image !== images[name]) rejectPreflight('PREFLIGHT_STALE_IMAGE_OBSERVATION');
    const imageConfig = inspectedImages.find((image) => image.Id === container.Image)?.Config;
    if (!object(imageConfig)) rejectPreflight('PREFLIGHT_IMAGE_INSPECTION_INVALID');
    if (!Array.isArray(container.Config.Env)) rejectPreflight('PREFLIGHT_CONTAINER_ENVIRONMENT');
    const actualEnvironment = {};
    for (const entry of container.Config.Env) {
      const index = typeof entry === 'string' ? entry.indexOf('=') : -1;
      if (index <= 0 || Object.hasOwn(actualEnvironment, entry.slice(0, index)))
        rejectPreflight('PREFLIGHT_CONTAINER_ENVIRONMENT');
      actualEnvironment[entry.slice(0, index)] = entry.slice(index + 1);
    }
    const effectiveEnvironment = {};
    for (const entry of imageConfig.Env ?? []) {
      const index = typeof entry === 'string' ? entry.indexOf('=') : -1;
      if (index <= 0 || Object.hasOwn(effectiveEnvironment, entry.slice(0, index)))
        rejectPreflight('PREFLIGHT_IMAGE_ENVIRONMENT');
      effectiveEnvironment[entry.slice(0, index)] = entry.slice(index + 1);
    }
    Object.assign(effectiveEnvironment, expected.environment ?? {});
    environment(effectiveEnvironment);
    if (canonicalJson(actualEnvironment) !== canonicalJson(effectiveEnvironment))
      rejectPreflight('PREFLIGHT_STALE_CONFIGURATION_OBSERVATION');
    if (
      canonicalJson(container.Config.Cmd ?? null) !==
        canonicalJson(expected.command ?? imageConfig.Cmd ?? null) ||
      canonicalJson(container.Config.Entrypoint ?? null) !==
        canonicalJson(expected.entrypoint ?? imageConfig.Entrypoint ?? null) ||
      (container.Config.User ?? '') !== (expected.user ?? imageConfig.User ?? '')
    )
      rejectPreflight('PREFLIGHT_CONTAINER_ENTRYPOINT');
    const host = container.HostConfig;
    if (
      !object(host) ||
      host.Privileged === true ||
      host.NetworkMode === 'host' ||
      host.PidMode === 'host' ||
      host.IpcMode === 'host' ||
      host.Memory !== Number(expected.mem_limit) ||
      host.PidsLimit !== Number(expected.pids_limit) ||
      host.ReadonlyRootfs !== (expected.read_only === true) ||
      (host.NanoCpus || (host.CpuQuota / host.CpuPeriod) * 1e9) !== Number(expected.cpus) * 1e9
    )
      rejectPreflight('PREFLIGHT_CONTAINER_RESOURCE');
    if (
      canonicalJson([...(host.CapAdd ?? [])].sort()) !==
        canonicalJson([...(expected.cap_add ?? [])].sort()) ||
      (expected.security_opt ?? []).some(
        (option) =>
          option.startsWith('no-new-privileges') &&
          !(host.SecurityOpt ?? []).some(
            (actual) => actual === 'no-new-privileges' || actual === 'no-new-privileges:true',
          ),
      )
    )
      rejectPreflight('PREFLIGHT_CONTAINER_ISOLATION');
    const expectedNetworks = Object.keys(expected.networks)
      .map((key) => rendered.networks[key].name)
      .sort();
    if (
      canonicalJson(Object.keys(container.NetworkSettings?.Networks ?? {}).sort()) !==
      canonicalJson(expectedNetworks)
    )
      rejectPreflight('PREFLIGHT_CONTAINER_NETWORK');
    const mounts = renderedMounts(rendered, name);
    const actualMounts = new Map();
    for (const mount of container.Mounts ?? []) {
      if (!object(mount) || actualMounts.has(mount.Destination))
        rejectPreflight('PREFLIGHT_CONTAINER_MOUNT');
      actualMounts.set(mount.Destination, mount);
    }
    for (const [target, mount] of mounts) {
      const actual = actualMounts.get(target);
      if (
        !actual ||
        actual.Type !== mount.type ||
        actual.RW !== !mount.readOnly ||
        (mount.type === 'bind' && actual.Source !== mount.source) ||
        (mount.type === 'volume' && actual.Name !== mount.source)
      )
        rejectPreflight('PREFLIGHT_STALE_MOUNT_OBSERVATION');
    }
    for (const [target, mount] of actualMounts) {
      if (mounts.has(target)) continue;
      if (
        mount.Type !== 'tmpfs' ||
        !(expected.tmpfs ?? []).some((entry) => entry.split(':')[0] === target)
      )
        rejectPreflight('PREFLIGHT_UNDECLARED_CONTAINER_MOUNT');
    }
  }
}

/** Compare only fields used by existing consumers; unconnected adapters remain unqualified. */
export function checkConsumedConfiguration(rendered, services, configuration) {
  const projections = [
    ['identity-service', 'IDENTITY_OIDC_ISSUER', configuration.identity.oidcIssuer],
    ['identity-service', 'IDENTITY_OIDC_CLIENT_ID', configuration.identity.clientId],
    ['control-api', 'CONTROL_API_EVIDENCE_ENVIRONMENT_ID', configuration.environmentId],
    [
      'control-worker',
      'CONTROL_WORKER_ARTIFACT_CAPACITY_BYTES',
      String(configuration.settings['runtime.local_artifact_capacity']),
    ],
  ];
  let compared = 0;
  for (const [service, key, value] of projections) {
    if (!services.includes(service)) continue;
    if (rendered.services[service].environment?.[key] !== value)
      rejectPreflight('PREFLIGHT_CONSUMED_CONFIGURATION_MISMATCH');
    compared += 1;
  }
  // Presence is structural only. Database grants/migrations and trust validity need real owners.
  const primaryRoles = {
    'identity-service': 'IDENTITY_DATABASE_USER',
    'participant-service': 'PARTICIPANT_DATABASE_USER',
    'policy-service': 'POLICY_DATABASE_USER',
    'control-api': 'CONTROL_API_DATABASE_USER',
    'control-worker': 'CONTROL_WORKER_DATABASE_USER',
    'fact-service': 'OPENPC_FACT_DATABASE_USER',
  };
  for (const name of services) {
    const env = rendered.services[name].environment ?? {};
    const roles = Object.keys(env).filter((key) => key.endsWith('_DATABASE_USER'));
    if (Object.hasOwn(primaryRoles, name)) {
      if (!env[primaryRoles[name]]) rejectPreflight('PREFLIGHT_ROLE_BINDING_MISSING');
      if (
        !Object.keys(rendered.services[name].depends_on ?? {}).some((dependency) =>
          dependency.endsWith('-migrate'),
        )
      )
        rejectPreflight('PREFLIGHT_MIGRATION_BINDING');
      if (
        !Object.keys(env).some((key) =>
          /(?:SIGNING|VERIFY|TRUST|PUBLIC_KEY|CAPABILITY).*_FILES?$/u.test(key),
        )
      )
        rejectPreflight('PREFLIGHT_TRUST_BINDING_MISSING');
    }
    for (const key of roles)
      if (!/^[a-z][a-z0-9_]{0,62}$/u.test(env[key]))
        rejectPreflight('PREFLIGHT_ROLE_BINDING_INVALID');
  }
  return compared;
}
