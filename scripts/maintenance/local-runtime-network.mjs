import { execFileSync } from 'node:child_process';
import { createHash, randomUUID, X509Certificate } from 'node:crypto';
import {
  constants,
  openSync,
  closeSync,
  readFileSync,
  writeFileSync,
  fsyncSync,
  realpathSync,
  readlinkSync,
  fstatSync,
  existsSync,
  renameSync,
  readdirSync,
} from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';

const ownerLabel = 'io.openpc.network.owner';
const rootLabel = 'io.openpc.network.root';
const schema = 'openpc-local-network-v1';
const recoveredSchema = 'openpc-local-network-binding-v2';
const newTopologySchema = 'openpc-local-network-binding-v3';
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const fail = (reason) => {
  throw new Error(`OPENPC_NETWORK|BLOCKED|${reason}`);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const array = (value) => {
  if (!Array.isArray(value)) fail('malformed-inventory');
  return value;
};
const ip = (value) => {
  if (typeof value !== 'string' || isIP(value) !== 4) fail('invalid-ipv4');
  return value.split('.').reduce((n, part) => n * 256 + Number(part), 0);
};
const address = (value) =>
  [24, 16, 8, 0].map((shift) => Math.floor(value / 2 ** shift) % 256).join('.');
export function range(value) {
  if (typeof value !== 'string' || !/^[0-9.]+\/(?:0|[1-9][0-9]?)$/u.test(value))
    fail('invalid-cidr');
  const [host, bits] = value.split('/');
  const prefix = Number(bits);
  if (prefix > 32) fail('invalid-cidr');
  const size = 2 ** (32 - prefix),
    start = Math.floor(ip(host) / size) * size;
  return { start, end: start + size - 1, cidr: `${address(start)}/${prefix}` };
}
export const overlaps = (left, right) => left.start <= right.end && right.start <= left.end;
const contained = (inner, outer) => inner.start >= outer.start && inner.end <= outer.end;
export function validateInspectedIds(ids, records) {
  if (
    !Array.isArray(ids) ||
    ids.some((id) => typeof id !== 'string' || !/^[0-9a-f]{64}$/u.test(id)) ||
    new Set(ids).size !== ids.length ||
    !Array.isArray(records) ||
    records.length !== ids.length ||
    records.some((record) => !object(record) || !ids.includes(record.Id)) ||
    new Set(records.map((record) => record.Id)).size !== ids.length
  )
    fail('incomplete-inspection');
  return records;
}
export function validateDockerEndpoint(endpoint, hostOverride) {
  if (
    hostOverride !== undefined ||
    !object(endpoint) ||
    typeof endpoint.Host !== 'string' ||
    !/^unix:\/\/\/[^\s\0]+$/u.test(endpoint.Host)
  )
    fail('nonlocal-or-overridden-docker-endpoint');
}
function validOtherFamily(value) {
  if (typeof value !== 'string') fail('invalid-ipv6');
  const [host, prefix, extra] = value.split('/');
  if (
    extra !== undefined ||
    isIP(host) !== 6 ||
    (prefix !== undefined && (!/^\d{1,3}$/u.test(prefix) || Number(prefix) > 128))
  )
    fail('invalid-ipv6');
}

/** Pure topology parsing. Only the CLI below reads authority and performs effects. */
export function exclusions(snapshot, own) {
  if (!object(snapshot)) fail('missing-topology');
  const result = [],
    interfaces = array(snapshot.addresses),
    routes = array(snapshot.routes);
  const networks = array(snapshot.networks);
  if (!interfaces.length || !routes.length || !networks.length) fail('empty-topology');
  let meaningfulAddress = false,
    meaningfulRoute = false;
  const bridge = own
    ? own.Options?.['com.docker.network.bridge.name'] || `br-${own.Id.slice(0, 12)}`
    : undefined;
  const ownRange = own ? range(own.IPAM.Config[0].Subnet) : undefined;
  const add = (cidr, device) => {
    const parsed = range(cidr);
    if (device === bridge && ownRange && contained(parsed, ownRange)) return;
    result.push(parsed);
  };
  for (const item of interfaces) {
    if (!object(item) || typeof item.ifname !== 'string' || !item.ifname)
      fail('malformed-interface');
    for (const entry of array(item.addr_info)) {
      if (!object(entry) || !Number.isInteger(entry.prefixlen)) fail('malformed-address');
      if (entry.family === 'inet') {
        add(`${entry.local}/${entry.prefixlen}`, item.ifname);
        if (item.ifname !== 'lo') meaningfulAddress = true;
      } else if (entry.family === 'inet6') validOtherFamily(`${entry.local}/${entry.prefixlen}`);
      else fail('unknown-address-family');
    }
  }
  for (const entry of routes) {
    if (!object(entry) || typeof entry.dst !== 'string') fail('malformed-route');
    if (entry.dst !== 'default' && entry.dst !== '0.0.0.0/0') {
      add(entry.dst.includes('/') ? entry.dst : `${entry.dst}/32`, entry.dev);
      if (entry.dev !== 'lo') meaningfulRoute = true;
    }
    // A default route forwards traffic; it does not reserve all IPv4 space.
    // Its actual gateway address must nevertheless remain reachable.
    if (entry.gateway !== undefined) add(`${entry.gateway}/32`, entry.dev);
    if (entry.multipath !== undefined)
      for (const hop of array(entry.multipath)) {
        if (!object(hop) || typeof hop.dev !== 'string') fail('malformed-route');
        if (hop.gateway !== undefined) add(`${hop.gateway}/32`, hop.dev);
      }
  }
  const ids = new Set();
  for (const network of networks) {
    if (
      !object(network) ||
      !/^[0-9a-f]{64}$/u.test(network.Id) ||
      typeof network.Name !== 'string' ||
      ids.has(network.Id) ||
      !object(network.IPAM)
    )
      fail('malformed-docker-network');
    ids.add(network.Id);
    const config = network.IPAM.Config;
    if (network.Driver === 'host' || network.Driver === 'null') {
      if (config !== null && (!Array.isArray(config) || config.length))
        fail('malformed-docker-network');
      continue;
    }
    if (!array(config).length) fail('missing-docker-ipam');
    for (const item of config) {
      if (!object(item) || typeof item.Subnet !== 'string') fail('missing-docker-ipam');
      if (item.Subnet.includes(':')) {
        validOtherFamily(item.Subnet);
        continue;
      }
      const parsed = range(item.Subnet);
      if (item.Gateway !== undefined && !contained(range(`${item.Gateway}/32`), parsed))
        fail('invalid-docker-gateway');
      if (network.Id !== own?.Id) result.push(parsed);
    }
  }
  if (!meaningfulAddress || !meaningfulRoute) fail('incomplete-host-topology');
  return result;
}

// Finite candidates, never an assumption that any of these ranges is safe.
export function selectSubnet(snapshot, requiredAddresses = []) {
  const occupied = exclusions(snapshot);
  if (!Array.isArray(requiredAddresses)) fail('incomplete-endpoint-inventory');
  if (requiredAddresses.length) {
    const required = requiredAddresses.map(ip);
    const candidate = range(`${requiredAddresses[0]}/24`);
    if (
      new Set(required).size !== required.length ||
      required.some((value) => value <= candidate.start || value >= candidate.end) ||
      !['172.16.0.0/12', '10.0.0.0/8', '192.168.0.0/16'].some((pool) =>
        contained(candidate, range(pool)),
      )
    )
      fail('fixed-endpoints-outside-bounded-candidate');
    if (occupied.some((other) => overlaps(candidate, other))) fail('route-overlap');
    for (let gateway = candidate.start + 1; gateway < candidate.end; gateway++)
      if (!required.includes(gateway)) return { subnet: candidate.cidr, gateway: address(gateway) };
    fail('no-unclaimed-gateway');
  }
  for (const pool of ['172.16.0.0/12', '10.0.0.0/8', '192.168.0.0/16']) {
    const span = range(pool);
    for (let start = span.start; start <= span.end; start += 256) {
      const candidate = range(`${address(start)}/24`);
      if (!occupied.some((other) => overlaps(candidate, other)))
        return { subnet: candidate.cidr, gateway: address(start + 1) };
    }
  }
  fail('no-nonoverlapping-private-subnet');
}
export function validateSelection(snapshot, binding, own) {
  if (!object(binding)) fail('missing-binding');
  const subnet = range(binding.subnet);
  if (
    subnet.cidr !== binding.subnet ||
    Number(binding.subnet.split('/')[1]) > 30 ||
    !['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].some((pool) =>
      contained(subnet, range(pool)),
    ) ||
    ip(binding.gateway) <= subnet.start ||
    ip(binding.gateway) >= subnet.end
  )
    fail('invalid-binding');
  if (exclusions(snapshot, own).some((other) => overlaps(subnet, other))) fail('route-overlap');
  return binding;
}
export function validateNetwork(network, binding, identity) {
  if (
    !object(network) ||
    network.Name !== `${identity.project}_openpc-local` ||
    !/^[0-9a-f]{64}$/u.test(network.Id) ||
    (binding.networkId && network.Id !== binding.networkId) ||
    network.Driver !== 'bridge' ||
    network.Scope !== 'local' ||
    network.Internal !== false ||
    network.EnableIPv6 !== false ||
    network.Labels?.['com.docker.compose.project'] !== identity.project ||
    network.Labels?.['com.docker.compose.network'] !== 'openpc-local' ||
    network.Labels?.[ownerLabel] !== identity.token ||
    network.Labels?.[rootLabel] !== identity.root ||
    network.Labels?.['io.openpc.network.schema'] !== schema ||
    network.IPAM?.Driver !== 'default' ||
    !Array.isArray(network.IPAM.Config) ||
    network.IPAM.Config.length !== 1 ||
    !object(network.IPAM.Config[0]) ||
    network.IPAM.Config[0].Subnet !== binding.subnet ||
    network.IPAM.Config[0].Gateway !== binding.gateway ||
    // Docker may report an unset allocation range as an empty string.
    (network.IPAM.Config[0].IPRange !== undefined && network.IPAM.Config[0].IPRange !== '') ||
    Object.keys(network.IPAM.Config[0]).some(
      (key) => !['Subnet', 'Gateway', 'IPRange'].includes(key),
    ) ||
    !object(network.Containers) ||
    !object(network.Options) ||
    Object.keys(network.Options).length ||
    (network.IPAM.Options !== null &&
      network.IPAM.Options !== undefined &&
      (!object(network.IPAM.Options) || Object.keys(network.IPAM.Options).length))
  )
    fail('network-identity-or-ipam-changed');
  return network;
}
export function validateCompose(rendered, binding, identity) {
  const network = rendered?.networks?.['openpc-local'];
  const ipam = network?.ipam?.config;
  if (
    !object(rendered?.networks) ||
    Object.keys(rendered.networks).length !== 1 ||
    !network ||
    network.name !== `${identity.project}_openpc-local` ||
    network.external === true ||
    network.driver !== 'bridge' ||
    network.internal === true ||
    network.enable_ipv4 === false ||
    network.enable_ipv6 === true ||
    network.ipam?.driver !== 'default' ||
    (network.ipam.options && Object.keys(network.ipam.options).length) ||
    !Array.isArray(ipam) ||
    ipam.length !== 1 ||
    !object(ipam[0]) ||
    Object.keys(ipam[0]).sort().join(',') !== 'gateway,subnet' ||
    ipam[0].subnet !== binding.subnet ||
    ipam[0].gateway !== binding.gateway ||
    network.labels?.[ownerLabel] !== identity.token ||
    network.labels?.[rootLabel] !== identity.root ||
    network.labels?.['io.openpc.network.schema'] !== schema ||
    (network.driver_opts && Object.keys(network.driver_opts).length)
  )
    fail('compose-network-override');
  if (!object(rendered.services) || !rendered.services['control-pg'])
    fail('missing-network-anchor');
  for (const service of Object.values(rendered.services)) {
    if (
      !object(service) ||
      service.network_mode !== undefined ||
      !object(service.networks) ||
      Object.keys(service.networks).length !== 1 ||
      !Object.hasOwn(service.networks, 'openpc-local')
    )
      fail('compose-network-bypass');
    const attachment = service.networks['openpc-local'];
    if (
      attachment?.ipv6_address !== undefined ||
      (attachment?.ipv4_address !== undefined &&
        !contained(range(`${attachment.ipv4_address}/32`), range(binding.subnet)))
    )
      fail('compose-network-bypass');
  }
  if (
    binding.recovery &&
    JSON.stringify(staticAddresses(rendered)) !== JSON.stringify(binding.recovery.staticAddresses)
  )
    fail('original-static-bindings-changed');
}

function staticAddresses(configuration) {
  if (!object(configuration?.services)) fail('missing-original-service-bindings');
  const entries = [];
  for (const [name, service] of Object.entries(configuration.services)) {
    if (!object(service) || service.network_mode !== undefined)
      fail('unsupported-original-service-network');
    const attachment = service.networks?.['openpc-local'];
    if (attachment?.ipv6_address !== undefined) fail('unsupported-original-service-network');
    if (attachment?.ipv4_address !== undefined) {
      ip(attachment.ipv4_address);
      entries.push([name, attachment.ipv4_address]);
    }
  }
  return Object.fromEntries(entries.sort(([a], [b]) => a.localeCompare(b)));
}

function endpointMounts(service) {
  const volumes = service.volumes ?? [];
  if (!Array.isArray(volumes) || volumes.some((volume) => !object(volume)))
    fail('incomplete-endpoint-mounts');
  const resolveMount = (target) => {
    if (typeof target !== 'string' || !target.startsWith('/')) fail('invalid-endpoint-input');
    const matches = volumes.filter(
      (volume) =>
        typeof volume.target === 'string' &&
        (target === volume.target || target.startsWith(`${volume.target}/`)),
    );
    if (
      matches.length !== 1 ||
      matches[0].type !== 'bind' ||
      typeof matches[0].source !== 'string' ||
      !matches[0].source.startsWith('/')
    )
      fail('ambiguous-endpoint-mount');
    return resolve(matches[0].source, `.${target.slice(matches[0].target.length)}`);
  };
  return {
    providerDirectory: volumes.some((volume) => volume.target === '/provider-sources')
      ? resolveMount('/provider-sources')
      : null,
    identityConfiguration:
      service.environment?.OPENPC_FACT_BRIDGE_CONFIGURATION_FILE === undefined
        ? null
        : resolveMount(service.environment.OPENPC_FACT_BRIDGE_CONFIGURATION_FILE),
  };
}

function consumerAttachments(rendered) {
  if (!object(rendered?.services) || !Object.keys(rendered.services).length)
    fail('incomplete-consumer-inventory');
  const consumers = {};
  for (const [name, service] of Object.entries(rendered.services).sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    if (
      !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/u.test(name) ||
      !object(service) ||
      service.network_mode !== undefined ||
      !object(service.networks) ||
      Object.keys(service.networks).join(',') !== 'openpc-local' ||
      [
        'extra_hosts',
        'external_links',
        'links',
        'dns',
        'dns_search',
        'hostname',
        'domainname',
        'container_name',
      ].some((key) => service[key] !== undefined)
    )
      fail('unsupported-consumer-network');
    const attachment = service.networks['openpc-local'];
    if (
      attachment !== null &&
      (!object(attachment) ||
        Object.keys(attachment).some((key) => !['aliases', 'ipv4_address'].includes(key)))
    )
      fail('unsupported-consumer-attachment');
    const aliases = attachment?.aliases ?? [];
    if (
      !Array.isArray(aliases) ||
      aliases.some(
        (alias) => typeof alias !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/u.test(alias),
      )
    )
      fail('invalid-consumer-alias');
    const fixed = attachment?.ipv4_address ?? null;
    if (fixed !== null) ip(fixed);
    consumers[name] = {
      aliases: [...new Set([name, ...aliases])].sort(),
      address: fixed,
      ...endpointMounts(service),
    };
  }
  return consumers;
}

/** A compatibility inventory, never authentication or business readiness. */
export function endpointInventory(configuration, rendered, inputs) {
  const consumers = consumerAttachments(rendered),
    originalPins = staticAddresses(configuration),
    pins = { ...originalPins };
  if (!Array.isArray(inputs) || !inputs.length) fail('incomplete-endpoint-inventory');
  const files = {},
    descriptors = [],
    profiles = [];
  const certificates = inputs.filter((input) => input?.kind === 'identity-certificate');
  let identitySources = 0;
  const constrain = (endpoint, addresses, allowed, privateRanges, certificate) => {
    if (
      !object(endpoint) ||
      typeof endpoint.normalized_uri !== 'string' ||
      typeof endpoint.reference_identity !== 'string' ||
      !Array.isArray(addresses) ||
      addresses.length !== 1 ||
      !Array.isArray(allowed) ||
      !Array.isArray(privateRanges)
    )
      fail('incomplete-endpoint-inventory');
    let uri;
    try {
      uri = new URL(endpoint.normalized_uri);
    } catch {
      fail('unsupported-endpoint-binding');
    }
    if (
      uri.protocol !== 'https:' ||
      uri.username ||
      uri.password ||
      uri.search ||
      uri.hash ||
      uri.hostname !== endpoint.reference_identity ||
      Number(uri.port || 443) !== endpoint.port ||
      uri.pathname !== endpoint.path
    )
      fail('unsupported-endpoint-binding');
    const fixed = addresses[0];
    ip(fixed);
    if (
      JSON.stringify(allowed) !== JSON.stringify([`${fixed}/32`]) ||
      JSON.stringify(privateRanges) !== JSON.stringify(allowed)
    )
      fail('unsupported-endpoint-ranges');
    let owners = Object.entries(consumers).filter(([, value]) =>
      value.aliases.includes(endpoint.reference_identity),
    );
    if (certificate) {
      // FactBridge connects to its admitted IP and uses this name for TLS SNI;
      // the reference identity need not be a Docker DNS alias.
      if (
        certificate.service !== 'identity-service' ||
        certificate.referenceIdentity !== endpoint.reference_identity ||
        certificate.port !== endpoint.port ||
        !consumers[certificate.service] ||
        rendered.services[certificate.service].environment?.IDENTITY_MTLS_LISTEN !==
          `0.0.0.0:${endpoint.port}` ||
        owners.some(([name]) => name !== certificate.service)
      )
        fail('unresolved-identity-consumer');
      owners = [[certificate.service, consumers[certificate.service]]];
    }
    if (owners.length !== 1) fail('unresolved-endpoint-consumer');
    const [service] = owners[0];
    if (
      (pins[service] && pins[service] !== fixed) ||
      (consumers[service].address && consumers[service].address !== fixed)
    )
      fail('changed-fixed-endpoint');
    pins[service] = fixed;
  };
  for (const input of inputs) {
    if (
      !object(input) ||
      typeof input.path !== 'string' ||
      !(
        input.kind === 'identity-certificate'
          ? /^secrets\/identity_mtls_server_cert\.pem$/u
          : /^data\/[a-zA-Z0-9_./-]+$/u
      ).test(input.path) ||
      input.path.split('/').includes('..') ||
      !/^sha256:[0-9a-f]{64}$/u.test(input.digest) ||
      Object.hasOwn(files, input.path) ||
      !object(input.value)
    )
      fail('invalid-endpoint-input');
    files[input.path] = input.digest;
    const value = input.value;
    if (input.kind === 'provider') {
      if (value.version !== 1 || value.allow_ip_endpoint !== false)
        fail('unsupported-provider-endpoint');
      constrain(
        value.endpoint,
        value.addresses,
        value.allowed_ranges,
        value.private_network_ranges,
      );
      descriptors.push(input.digest);
    } else if (input.kind === 'identity') {
      if (
        value.version !== 1 ||
        value.allow_ip_endpoint !== false ||
        value.provider_directory !== '/provider-sources' ||
        certificates.length !== 1 ||
        !/^[0-9a-f]{64}$/u.test(value.server_certificate_digest) ||
        certificates[0].value?.certificateDigest !== value.server_certificate_digest
      )
        fail('unsupported-identity-endpoint');
      constrain(
        value.identity_endpoint,
        value.identity_addresses,
        value.allowed_ranges,
        value.private_network_ranges,
        certificates[0].value,
      );
      identitySources++;
    } else if (input.kind === 'profile') profiles.push(value.configuration_digest);
    else if (!['auxiliary', 'identity-certificate'].includes(input.kind))
      fail('unknown-endpoint-input');
  }
  if (
    !descriptors.length ||
    identitySources !== 1 ||
    profiles.length !== 1 ||
    !descriptors.includes(profiles[0])
  )
    fail('incomplete-endpoint-inventory');
  for (const [name, value] of Object.entries(consumers)) {
    if (value.address && value.address !== pins[name]) fail('unexplained-static-attachment');
    if (pins[name]) value.address = pins[name];
    const service = rendered.services[name];
    for (const value of [
      service.environment,
      service.command,
      service.entrypoint,
      service.healthcheck,
    ])
      for (const match of JSON.stringify(value ?? null).matchAll(
        /(?<![0-9a-fA-F.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9a-fA-F.])/gu,
      )) {
        const host = match[0];
        ip(host);
        if (host !== '0.0.0.0' && !host.startsWith('127.') && !Object.values(pins).includes(host))
          fail('unexplained-environment-endpoint');
      }
  }
  if (
    Object.keys(pins).some((name) => !consumers[name]) ||
    !Object.keys(pins).length ||
    new Set(Object.values(pins)).size !== Object.keys(pins).length
  )
    fail('incomplete-endpoint-inventory');
  return {
    staticAddresses: Object.fromEntries(
      Object.entries(pins).sort(([a], [b]) => a.localeCompare(b)),
    ),
    consumers,
    inputs: Object.fromEntries(Object.entries(files).sort(([a], [b]) => a.localeCompare(b))),
  };
}

export function newTopology(snapshot, configuration, rendered, inputs, configurationDigest) {
  if (!/^sha256:[0-9a-f]{64}$/u.test(configurationDigest))
    fail('invalid-original-configuration-identity');
  if (configuration.networks?.['openpc-local']?.ipam)
    fail('historical-ipam-present-use-exact-recovery');
  const manifest = endpointInventory(configuration, rendered, inputs);
  const selected = selectSubnet(snapshot, Object.values(manifest.staticAddresses));
  return {
    ...selected,
    networkId: null,
    schema: newTopologySchema,
    recovery: {
      state: 'PENDING',
      admission: 'NEW_TOPOLOGY',
      originalTopology: 'UNKNOWN',
      originalNetworkId: null,
      originalConfiguration: 'data/runtime-bootstrap/compose.json',
      configurationDigest,
      ...manifest,
    },
  };
}

function attachmentOverride(pins) {
  return {
    services: Object.fromEntries(
      Object.entries(pins).map(([name, fixed]) => [
        name,
        { networks: { 'openpc-local': { ipv4_address: fixed } } },
      ]),
    ),
  };
}

export function bindingDocument(binding, identity) {
  const record = { ...identity, schema, ...binding };
  return binding.schema === newTopologySchema
    ? { 'x-openpc-network': record, ...attachmentOverride(binding.recovery.staticAddresses) }
    : record;
}

/** Exact retained inputs only: an endpoint alone never implies its prefix. */
export function originalTopology(configuration, previous, identity) {
  const network = configuration?.networks?.['openpc-local'];
  let subnet = previous?.subnet,
    gateway = previous?.gateway;
  if (network !== undefined) {
    if (
      !object(network) ||
      (network.name !== undefined && network.name !== `${identity.project}_openpc-local`) ||
      (network.driver !== undefined && network.driver !== 'bridge') ||
      network.external ||
      network.internal ||
      network.enable_ipv6 ||
      !Array.isArray(network.ipam?.config) ||
      network.ipam.config.length !== 1 ||
      !object(network.ipam.config[0]) ||
      Object.keys(network.ipam.config[0]).sort().join(',') !== 'gateway,subnet' ||
      (network.ipam.driver !== undefined && network.ipam.driver !== 'default') ||
      network.ipam.options ||
      network.driver_opts
    )
      fail('unsupported-original-ipam');
    const original = network.ipam.config[0];
    if (previous && (subnet !== original.subnet || gateway !== original.gateway))
      fail('conflicting-original-ipam');
    subnet = original.subnet;
    gateway = original.gateway;
  }
  if (typeof subnet !== 'string' || typeof gateway !== 'string')
    fail('original-subnet-and-gateway-evidence-required');
  const span = range(subnet),
    pins = staticAddresses(configuration);
  if (
    span.cidr !== subnet ||
    Number(subnet.split('/')[1]) > 30 ||
    ip(gateway) <= span.start ||
    ip(gateway) >= span.end
  )
    fail('unsupported-original-ipam');
  const values = Object.values(pins);
  if (
    new Set(values).size !== values.length ||
    values.some((value) => ip(value) <= span.start || ip(value) >= span.end || value === gateway)
  )
    fail('invalid-original-static-binding');
  return {
    subnet,
    gateway,
    networkId: null,
    recovery: {
      state: 'PENDING',
      originalNetworkId: previous?.networkId ?? null,
      staticAddresses: pins,
      originalConfiguration: 'data/runtime-bootstrap/compose.json',
    },
  };
}

export function assertRecoveryVacant(snapshot, containers, binding, identity) {
  validateSelection(snapshot, binding);
  if (
    snapshot.networks.some(
      (network) =>
        network.Name === `${identity.project}_openpc-local` ||
        network.Id === binding.recovery.originalNetworkId ||
        network.Labels?.['com.docker.compose.project'] === identity.project,
    )
  )
    fail('original-network-still-present');
  const all = array(containers);
  validateInspectedIds(
    all.map((container) => container?.Id),
    all,
  );
  for (const container of all) {
    if (
      !object(container.NetworkSettings?.Networks) ||
      !object(container.Config) ||
      (container.Config.Labels !== null && !object(container.Config.Labels)) ||
      typeof container.HostConfig?.NetworkMode !== 'string'
    )
      fail('incomplete-container-inspection');
    if (
      container.Config.Labels?.['com.docker.compose.project'] === identity.project ||
      Object.entries(container.NetworkSettings.Networks).some(
        ([name, attachment]) =>
          name === `${identity.project}_openpc-local` ||
          (binding.recovery.originalNetworkId &&
            attachment?.NetworkID === binding.recovery.originalNetworkId),
      ) ||
      container.HostConfig.NetworkMode === `${identity.project}_openpc-local` ||
      (binding.recovery.originalNetworkId &&
        container.HostConfig.NetworkMode === binding.recovery.originalNetworkId)
    )
      fail('original-network-has-consumers');
  }
  assertCompleteSharedNamespaces(all);
}

export function validateRecoveryAnchor(containers, network, rendered, identity) {
  const owned = containers.filter(
    (container) => container.Config?.Labels?.['com.docker.compose.project'] === identity.project,
  );
  if (
    owned.length !== 1 ||
    owned[0].Config.Labels['com.docker.compose.service'] !== 'control-pg' ||
    owned[0].State?.Running !== false ||
    owned[0].Config.Image !== rendered.services['control-pg'].image
  )
    fail('recovery-anchor-not-exclusively-stopped');
  for (const container of containers) {
    if (
      !object(container.NetworkSettings?.Networks) ||
      typeof container.HostConfig?.NetworkMode !== 'string'
    )
      fail('incomplete-container-inspection');
    if (
      container.Id !== owned[0].Id &&
      (container.HostConfig.NetworkMode === network.Name ||
        container.HostConfig.NetworkMode === network.Id ||
        Object.entries(container.NetworkSettings.Networks).some(
          ([name, value]) => name === network.Name || value?.NetworkID === network.Id,
        ))
    )
      fail('recovery-network-has-foreign-consumer');
  }
  if (Object.keys(network.Containers).some((id) => id !== owned[0].Id))
    fail('recovery-network-has-foreign-consumer');
  assertCompleteSharedNamespaces(containers);
}
export function assertRemovable(network, binding, identity, containers, disposition) {
  validateNetwork(network, binding, identity);
  if (
    !object(disposition) ||
    disposition.retained !== false ||
    disposition.unknown !== false ||
    disposition.originalTopologyRequired !== false
  )
    fail('topology-retained-or-unknown');
  if (Object.keys(network.Containers).length) fail('network-has-consumers');
  const all = array(containers);
  validateInspectedIds(
    all.map((container) => container?.Id),
    all,
  );
  for (const container of all) {
    if (
      !object(container.NetworkSettings?.Networks) ||
      typeof container.HostConfig?.NetworkMode !== 'string'
    )
      fail('incomplete-container-inspection');
    if (
      Object.entries(container.NetworkSettings.Networks).some(
        ([name, attachment]) => name === network.Name || attachment?.NetworkID === network.Id,
      ) ||
      container.HostConfig.NetworkMode === network.Name ||
      container.HostConfig.NetworkMode === network.Id
    )
      fail('network-has-consumers-or-shared-namespace');
  }
  assertCompleteSharedNamespaces(all);
}
function assertCompleteSharedNamespaces(all) {
  // A container sharing another network namespace can lack its own attachment
  // map. Resolve that actual chain; an unrelated complete chain is harmless.
  const visit = (container, seen = new Set()) => {
    if (seen.has(container)) fail('ambiguous-shared-namespace');
    seen.add(container);
    const mode = container.HostConfig.NetworkMode;
    if (!mode.startsWith('container:')) return;
    const target = mode.slice(10);
    const matches = all.filter(
      (item) =>
        item.Id === target ||
        item.Name === `/${target}` ||
        (/^[0-9a-f]{12,64}$/u.test(target) &&
          typeof item.Id === 'string' &&
          item.Id.startsWith(target)),
    );
    if (matches.length !== 1) fail('ambiguous-shared-namespace');
    visit(matches[0], seen);
  };
  for (const container of all) visit(container);
}

function command(program, args, options = {}) {
  try {
    return execFileSync(program, args, {
      encoding: 'utf8',
      timeout: 15000,
      maxBuffer: 8 * 1024 * 1024,
      ...options,
    });
  } catch {
    fail('inspection-or-command-failed');
  }
}
function json(program, args, options) {
  try {
    return JSON.parse(command(program, args, options));
  } catch {
    fail('inspection-or-json-failed');
  }
}
function inventory() {
  // Host routes describe only this machine; a remote daemon cannot consume
  // this admission. Explicit Docker host overrides are unsupported.
  validateDockerEndpoint(
    json('docker', ['context', 'inspect', '--format', '{{json .Endpoints.docker}}']),
    process.env.DOCKER_HOST,
  );
  const ids = command('docker', ['network', 'ls', '--no-trunc', '--format', '{{.ID}}'])
    .trim()
    .split('\n');
  if (
    !ids.length ||
    ids.length > 256 ||
    ids.some((id) => !/^[0-9a-f]{64}$/u.test(id)) ||
    new Set(ids).size !== ids.length
  )
    fail('invalid-network-inventory');
  const networks = validateInspectedIds(ids, json('docker', ['network', 'inspect', ...ids]));
  return {
    addresses: json('ip', ['-j', 'address', 'show']),
    routes: json('ip', ['-j', '-4', 'route', 'show', 'table', 'all']),
    networks,
  };
}
function readOwned(file, maximum = 65536) {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.uid !== process.getuid() || info.nlink !== 1 || info.size > maximum)
      fail('invalid-owner-file');
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}

function ownedConfiguration(file, identity) {
  if (!file.startsWith(`${identity.root}/data/`) || realpathSync(file) !== file)
    fail('foreign-endpoint-configuration');
  const bytes = readOwned(file, 4 * 1024 * 1024);
  return {
    path: file.slice(identity.root.length + 1),
    digest: digest(bytes),
    value: JSON.parse(bytes),
  };
}

function identityCertificateInput(rendered, identity, configuration) {
  const endpoint = configuration.identity_endpoint;
  const service = rendered.services['identity-service'];
  const certificateTarget = service?.environment?.IDENTITY_MTLS_SERVER_CERT_FILE;
  if (
    !object(endpoint) ||
    !Number.isInteger(endpoint.port) ||
    certificateTarget !== '/run/secrets/identity_mtls_server_cert' ||
    service.environment.IDENTITY_MTLS_LISTEN !== `0.0.0.0:${endpoint.port}` ||
    !Array.isArray(service.secrets)
  )
    fail('unresolved-identity-certificate');
  const matching = service.secrets.filter(
    (secret) =>
      object(secret) &&
      (secret.target?.startsWith('/')
        ? secret.target
        : `/run/secrets/${secret.target ?? secret.source}`) === certificateTarget,
  );
  if (
    matching.length !== 1 ||
    matching[0].source !== 'identity_mtls_server_cert' ||
    (service.volumes ?? []).some(
      (volume) =>
        certificateTarget === volume.target || certificateTarget.startsWith(`${volume.target}/`),
    )
  )
    fail('unresolved-identity-certificate');
  const source = rendered.secrets?.[matching[0].source];
  const file = join(identity.root, 'secrets/identity_mtls_server_cert.pem');
  if (
    !object(source) ||
    source.file !== file ||
    source.external ||
    source.environment ||
    realpathSync(file) !== file
  )
    fail('foreign-identity-certificate');
  // This is only the public server certificate, never a private key or token.
  const bytes = readOwned(file);
  const certificate = new X509Certificate(bytes);
  if (!certificate.checkHost(endpoint.reference_identity, { subject: 'never', wildcards: false }))
    fail('identity-certificate-name-mismatch');
  return {
    kind: 'identity-certificate',
    path: 'secrets/identity_mtls_server_cert.pem',
    digest: digest(bytes),
    value: {
      service: 'identity-service',
      referenceIdentity: endpoint.reference_identity,
      port: endpoint.port,
      certificateDigest: digest(certificate.raw).slice(7),
    },
  };
}

export function readEndpointInputs(rendered, identity) {
  const directories = new Set(),
    identityFiles = new Set();
  for (const service of Object.values(rendered.services)) {
    const mounts = endpointMounts(service);
    for (const mounted of Object.values(mounts)) {
      if (mounted === null) continue;
      if (!mounted.startsWith(`${identity.root}/data/`) || realpathSync(mounted) !== mounted)
        fail('foreign-endpoint-mount');
    }
    if (mounts.providerDirectory) directories.add(mounts.providerDirectory);
    if (mounts.identityConfiguration) identityFiles.add(mounts.identityConfiguration);
  }
  if (directories.size !== 1 || identityFiles.size !== 1) fail('incomplete-endpoint-mounts');
  const inputs = [];
  for (const directory of directories) {
    const names = readdirSync(directory)
      .filter((name) => name.endsWith('.json'))
      .sort();
    if (names.length > 64) fail('unsupported-endpoint-directory');
    for (const name of names) {
      let kind;
      if (/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json$/u.test(name)) kind = 'provider';
      else if (name === 'profile.json') kind = 'profile';
      else if (
        ['acquisition.json', 'rpc-fact-acquisition.json', 'rpc-fact-binding.json'].includes(name)
      )
        kind = 'auxiliary';
      else fail('unrecognized-endpoint-configuration');
      inputs.push({ ...ownedConfiguration(join(directory, name), identity), kind });
    }
  }
  for (const file of identityFiles) {
    const input = { ...ownedConfiguration(file, identity), kind: 'identity' };
    inputs.push(input, identityCertificateInput(rendered, identity, input.value));
  }
  return inputs;
}
function originalConfiguration(identity) {
  return ownedConfiguration(join(identity.root, 'data/runtime-bootstrap/compose.json'), identity);
}
export function newTopologyInputsUnchanged(binding, identity, rendered) {
  const original = originalConfiguration(identity);
  const manifest = endpointInventory(
    original.value,
    rendered,
    readEndpointInputs(rendered, identity),
  );
  const saved = binding.recovery;
  if (
    original.digest !== saved.configurationDigest ||
    JSON.stringify(manifest.inputs) !== JSON.stringify(saved.inputs) ||
    JSON.stringify(manifest.consumers) !== JSON.stringify(saved.consumers) ||
    JSON.stringify(manifest.staticAddresses) !== JSON.stringify(saved.staticAddresses)
  )
    fail('new-topology-inputs-changed');
}
function ancestor(pid) {
  let current = process.pid;
  while (current > 1) {
    if (current === pid) return true;
    const match = /^PPid:\s+(\d+)$/mu.exec(readFileSync(`/proc/${current}/status`, 'utf8'));
    if (!match) return false;
    current = Number(match[1]);
  }
  return false;
}
function held(file, pid, fd) {
  if (
    !Number.isSafeInteger(pid) ||
    !ancestor(pid) ||
    readlinkSync(`/proc/${pid}/fd/${fd}`) !== file
  )
    fail('missing-serialized-owner');
  try {
    execFileSync('flock', ['-E', '73', '-n', file, 'true'], { stdio: 'ignore', timeout: 5000 });
  } catch (error) {
    if (error.status === 73) return;
    fail('lock-inspection-failed');
  }
  fail('missing-serialized-owner');
}
function identityFrom(root, project, token) {
  if (
    !/^openpc-local-e2e-[0-9a-f]{12}$/u.test(project) ||
    !/^[0-9a-f]{64}$/u.test(token) ||
    project !== `openpc-local-e2e-${token.slice(0, 12)}` ||
    realpathSync(root) !== root ||
    realpathSync(join(root, 'data')) !== join(root, 'data')
  )
    fail('invalid-run-owner');
  const sentinel = join(root, '.openpc-local-runtime-owner');
  if (readOwned(sentinel) !== `openpc-local-runtime:${project}:${token}\n`)
    fail('invalid-run-owner');
  held(sentinel, Number(process.env.OPENPC_RUNTIME_OWNER_PID), 8);
  const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  const common = command('git', [
    '-C',
    repository,
    'rev-parse',
    '--path-format=absolute',
    '--git-common-dir',
  ]).trim();
  held(join(common, 'openpc-heavy.lock'), Number(process.env.OPENPC_HEAVY_LOCK_OWNER_PID), 9);
  return { root, project, token };
}
function readBinding(file, identity) {
  let value;
  try {
    value = JSON.parse(readOwned(file));
  } catch {
    fail('missing-or-invalid-retained-binding');
  }
  return validateStoredBinding(value, identity);
}
export function validateStoredBinding(value, identity) {
  if (object(value) && Object.hasOwn(value, 'x-openpc-network')) {
    if (
      Object.keys(value).sort().join(',') !== 'services,x-openpc-network' ||
      value['x-openpc-network']?.schema !== newTopologySchema ||
      !object(value['x-openpc-network'].recovery?.staticAddresses) ||
      JSON.stringify(value.services) !==
        JSON.stringify(
          attachmentOverride(value['x-openpc-network'].recovery.staticAddresses).services,
        )
    )
      fail('invalid-new-topology-overlay');
    value = value['x-openpc-network'];
  } else if (value?.schema === newTopologySchema) fail('missing-new-topology-overlay');
  if (
    !object(value) ||
    Object.keys(value).sort().join(',') !==
      ([recoveredSchema, newTopologySchema].includes(value.schema)
        ? 'gateway,networkId,project,recovery,root,schema,subnet,token'
        : 'gateway,networkId,project,root,schema,subnet,token') ||
    ![schema, recoveredSchema, newTopologySchema].includes(value.schema) ||
    value.root !== identity.root ||
    value.project !== identity.project ||
    value.token !== identity.token ||
    (value.networkId !== null && !/^[0-9a-f]{64}$/u.test(value.networkId))
  )
    fail('invalid-retained-binding');
  if ([recoveredSchema, newTopologySchema].includes(value.schema)) {
    const recovery = value.recovery;
    if (
      !object(recovery) ||
      Object.keys(recovery).sort().join(',') !==
        (value.schema === newTopologySchema
          ? 'admission,attempt,configurationDigest,consumers,inputs,originalConfiguration,originalNetworkId,originalTopology,state,staticAddresses'
          : 'attempt,originalConfiguration,originalNetworkId,state,staticAddresses') ||
      !['PENDING', 'BOUND'].includes(recovery.state) ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        recovery.attempt,
      ) ||
      recovery.originalConfiguration !== 'data/runtime-bootstrap/compose.json' ||
      (recovery.originalNetworkId !== null &&
        !/^[0-9a-f]{64}$/u.test(recovery.originalNetworkId)) ||
      !object(recovery.staticAddresses)
    )
      fail('invalid-retained-binding');
    if (value.schema === newTopologySchema) {
      if (
        recovery.admission !== 'NEW_TOPOLOGY' ||
        recovery.originalTopology !== 'UNKNOWN' ||
        recovery.originalNetworkId !== null ||
        !/^sha256:[0-9a-f]{64}$/u.test(recovery.configurationDigest) ||
        !object(recovery.consumers) ||
        !Object.keys(recovery.consumers).length ||
        !object(recovery.inputs) ||
        Object.keys(recovery.inputs).length < 4 ||
        !Object.hasOwn(recovery.inputs, 'secrets/identity_mtls_server_cert.pem') ||
        Object.keys(recovery.staticAddresses).some(
          (name) => !Object.hasOwn(recovery.consumers, name),
        ) ||
        Object.entries(recovery.inputs).some(
          ([path, hash]) =>
            !/^(?:data\/[a-zA-Z0-9_./-]+|secrets\/identity_mtls_server_cert\.pem)$/u.test(path) ||
            path.split('/').includes('..') ||
            !/^sha256:[0-9a-f]{64}$/u.test(hash),
        )
      )
        fail('invalid-new-topology-intent');
      for (const [name, consumer] of Object.entries(recovery.consumers)) {
        if (
          !object(consumer) ||
          Object.keys(consumer).sort().join(',') !==
            'address,aliases,identityConfiguration,providerDirectory' ||
          !Array.isArray(consumer.aliases) ||
          !consumer.aliases.includes(name) ||
          consumer.aliases.some((alias) => typeof alias !== 'string') ||
          consumer.address !== (recovery.staticAddresses[name] ?? null) ||
          [consumer.providerDirectory, consumer.identityConfiguration].some(
            (path) =>
              path !== null &&
              (typeof path !== 'string' ||
                !path.startsWith(`${identity.root}/data/`) ||
                resolve(path) !== path),
          )
        )
          fail('invalid-new-topology-consumers');
      }
    }
    if (recovery.state === 'PENDING') fail('recovery-outcome-unknown');
    if (!value.networkId) fail('invalid-retained-binding');
    const span = range(value.subnet),
      pins = Object.values(recovery.staticAddresses);
    if (
      new Set(pins).size !== pins.length ||
      pins.some((pin) => ip(pin) <= span.start || ip(pin) >= span.end || pin === value.gateway)
    )
      fail('invalid-retained-binding');
  } else if (!value.networkId) fail('invalid-retained-binding');
  return value;
}
function storeBinding(file, binding, identity) {
  const fd = openSync(
    file,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeFileSync(fd, JSON.stringify(bindingDocument(binding, identity)) + '\n');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  const directory = openSync(dirname(file), constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(directory);
  } finally {
    closeSync(directory);
  }
}
function replaceBinding(file, binding, identity) {
  const temporary = `${file}.${binding.recovery.attempt}.tmp`;
  storeBinding(temporary, binding, identity);
  renameSync(temporary, file);
  const fd = openSync(dirname(file), constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
function containerInventory() {
  const output = command('docker', ['ps', '-aq', '--no-trunc']).trim();
  const ids = output ? output.split('\n') : [];
  if (ids.length > 4096) fail('invalid-container-inventory');
  validateInspectedIds(
    ids,
    ids.map((Id) => ({ Id })),
  );
  return validateInspectedIds(ids, ids.length ? json('docker', ['inspect', ...ids]) : []);
}
function composeForRetained(identity) {
  const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  return [
    'compose',
    '-p',
    identity.project,
    '--profile',
    'astra05',
    '-f',
    join(repository, 'deploy/compose/local/compose.yaml'),
    '-f',
    join(identity.root, 'data/runtime-bootstrap/compose.json'),
  ];
}
function networkEnvironment(identity, selection) {
  return {
    ...process.env,
    OPENPC_LOCAL_SECRET_ROOT: join(identity.root, 'secrets'),
    OPENPC_LOCAL_DATA_ROOT: join(identity.root, 'data'),
    OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET: selection.subnet,
    OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY: selection.gateway,
    OPENPC_LOCAL_RUNTIME_NETWORK_OWNER: identity.token,
    OPENPC_LOCAL_RUNTIME_NETWORK_ROOT: identity.root,
  };
}
function admitNewTopology(mode, file, previous, identity, snapshot, subnet, gateway) {
  if (previous) fail('existing-topology-intent-requires-reconciliation');
  const original = originalConfiguration(identity),
    compose = composeForRetained(identity);
  // A preliminary new range permits rendering the known static attachments.
  // It is not historical IPAM or admission: the complete mounted-input and
  // consumer manifest below must select and validate the final new range.
  const renderOnly = networkEnvironment(
    identity,
    selectSubnet(snapshot, Object.values(staticAddresses(original.value))),
  );
  const raw = json('docker', [...compose, 'config', '--format', 'json'], { env: renderOnly });
  const inputs = readEndpointInputs(raw, identity),
    manifest = endpointInventory(original.value, raw, inputs);
  const override = JSON.stringify(attachmentOverride(manifest.staticAddresses));
  const pinned = json('docker', [...compose, '-f', '-', 'config', '--format', 'json'], {
    env: renderOnly,
    input: override,
  });
  const binding = newTopology(snapshot, original.value, pinned, inputs, original.digest);
  assertRecoveryVacant(snapshot, containerInventory(), binding, identity);
  const environment = networkEnvironment(identity, binding);
  const rendered = json('docker', [...compose, '-f', '-', 'config', '--format', 'json'], {
    env: environment,
    input: override,
  });
  validateCompose(rendered, binding, identity);
  newTopologyInputsUnchanged(binding, identity, rendered);
  if (mode === 'new-topology-plan') {
    process.stderr.write(
      `OPENPC_NETWORK|NEW_TOPOLOGY_PLAN|${JSON.stringify({ originalTopology: 'UNKNOWN', subnet: binding.subnet, gateway: binding.gateway, staticAddresses: binding.recovery.staticAddresses, consumers: binding.recovery.consumers, configurationDigest: original.digest, inputs: binding.recovery.inputs })}\n`,
    );
    process.stdout.write(`${binding.subnet} ${binding.gateway}\n`);
    return;
  }
  if (
    subnet !== binding.subnet ||
    gateway !== binding.gateway ||
    process.env.OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET !== subnet ||
    process.env.OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY !== gateway ||
    process.env.OPENPC_LOCAL_RUNTIME_NETWORK_OWNER !== identity.token ||
    process.env.OPENPC_LOCAL_RUNTIME_NETWORK_ROOT !== identity.root
  )
    fail('binding-override');
  binding.recovery.attempt = randomUUID();
  storeBinding(file, binding, identity);
  // The one execution input is also the Compose attachment override. Original
  // configuration and governed endpoint bytes are never rewritten.
  const admitted = [...compose, '-f', file];
  const checked = json('docker', [...admitted, 'config', '--format', 'json'], { env: environment });
  validateCompose(checked, binding, identity);
  newTopologyInputsUnchanged(binding, identity, checked);
  assertRecoveryVacant(inventory(), containerInventory(), binding, identity);
  command('docker', [...admitted, 'create', '--no-build', '--pull', 'never', 'control-pg'], {
    env: environment,
  });
  const actual = inventory(),
    matches = actual.networks.filter(
      (network) => network.Name === `${identity.project}_openpc-local`,
    );
  if (matches.length !== 1) fail('new-topology-not-uniquely-created');
  const network = validateNetwork(matches[0], binding, identity);
  validateSelection(actual, binding, network);
  validateRecoveryAnchor(containerInventory(), network, checked, identity);
  const finalRendered = json('docker', [...admitted, 'config', '--format', 'json'], {
    env: environment,
  });
  validateCompose(finalRendered, binding, identity);
  newTopologyInputsUnchanged(binding, identity, finalRendered);
  binding.networkId = network.Id;
  binding.recovery.state = 'BOUND';
  replaceBinding(file, binding, identity);
  process.stderr.write(
    'OPENPC_NETWORK|PASS|mode=admit-new-topology|admission=NEW_TOPOLOGY|original-topology=UNKNOWN|services-stopped\n',
  );
}
function recover(mode, file, previous, identity, snapshot, subnet, gateway) {
  if (previous?.recovery) fail('repeated-topology-recovery-needs-reconciliation');
  const original = join(identity.root, 'data/runtime-bootstrap/compose.json');
  if (!existsSync(original)) fail('original-subnet-and-gateway-evidence-required');
  if (realpathSync(original) !== original) fail('invalid-original-configuration');
  const configuration = JSON.parse(readOwned(original, 4 * 1024 * 1024));
  const binding = originalTopology(configuration, previous, identity);
  assertRecoveryVacant(snapshot, containerInventory(), binding, identity);
  if (mode === 'recovery-plan') {
    process.stdout.write(`${binding.subnet} ${binding.gateway}\n`);
    return;
  }
  if (
    subnet !== binding.subnet ||
    gateway !== binding.gateway ||
    process.env.OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET !== subnet ||
    process.env.OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY !== gateway ||
    process.env.OPENPC_LOCAL_RUNTIME_NETWORK_OWNER !== identity.token ||
    process.env.OPENPC_LOCAL_RUNTIME_NETWORK_ROOT !== identity.root
  )
    fail('binding-override');
  const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  const compose = [
    'compose',
    '-p',
    identity.project,
    '-f',
    join(repository, 'deploy/compose/local/compose.yaml'),
    '-f',
    original,
  ];
  const rendered = json('docker', [...compose, 'config', '--format', 'json']);
  validateCompose(rendered, binding, identity);
  binding.schema = recoveredSchema;
  binding.recovery.attempt = randomUUID();
  // Commit intent before allocation. A crash or ambiguous daemon reply leaves
  // PENDING, which every later entrypoint refuses. There is no blind retry.
  if (previous) replaceBinding(file, binding, identity);
  else storeBinding(file, binding, identity);
  assertRecoveryVacant(inventory(), containerInventory(), binding, identity);
  command('docker', [...compose, 'create', '--no-build', '--pull', 'never', 'control-pg']);
  const actual = inventory(),
    matches = actual.networks.filter(
      (network) => network.Name === `${identity.project}_openpc-local`,
    );
  if (matches.length !== 1) fail('recovery-network-not-uniquely-created');
  const network = validateNetwork(matches[0], binding, identity);
  validateSelection(actual, binding, network);
  validateRecoveryAnchor(containerInventory(), network, rendered, identity);
  binding.networkId = network.Id;
  binding.recovery.state = 'BOUND';
  replaceBinding(file, binding, identity);
  process.stderr.write(
    'OPENPC_NETWORK|PASS|mode=recover|original-topology-restored|services-stopped\n',
  );
}
function main(args) {
  const [mode, root, project, token, subnet, gateway, phase, ...extra] = args;
  if (
    ![
      'plan',
      'before',
      'verify',
      'cleanup',
      'recovery-plan',
      'recover',
      'new-topology-plan',
      'admit-new-topology',
      'compose-overlay',
    ].includes(mode) ||
    extra.length ||
    !['fresh', 'retained'].includes(phase)
  )
    fail('invalid-command');
  const identity = identityFrom(root, project, token),
    file = join(root, 'data', 'local-runtime-network.json');
  const retained = existsSync(file) ? readBinding(file, identity) : undefined;
  if (mode === 'compose-overlay') {
    if (retained?.schema === newTopologySchema) process.stdout.write(`${file}\n`);
    return;
  }
  if (mode === 'new-topology-plan' || mode === 'admit-new-topology') {
    if (phase !== 'retained') fail('new-topology-requires-retained-owner');
    admitNewTopology(mode, file, retained, identity, inventory(), subnet, gateway);
    return;
  }
  if (mode === 'recovery-plan' || mode === 'recover') {
    if (phase !== 'retained') fail('recovery-requires-retained-owner');
    recover(mode, file, retained, identity, inventory(), subnet, gateway);
    return;
  }
  if (phase === 'retained' && !retained) fail('missing-retained-network-binding');
  if (mode === 'plan' && phase === 'fresh' && retained) fail('unexpected-existing-binding');
  const snapshot = inventory(),
    found = snapshot.networks.filter((network) => network.Name === `${project}_openpc-local`);
  if (found.length > 1) fail('ambiguous-network-owner');
  const own = found[0];
  const binding = retained ?? (mode === 'plan' ? selectSubnet(snapshot) : { subnet, gateway });
  if (mode !== 'plan' && (binding.subnet !== subnet || binding.gateway !== gateway))
    fail('binding-override');
  if (own) validateNetwork(own, binding, identity);
  if (retained && !own) fail('retained-network-missing');
  if (!retained && own && mode !== 'verify' && mode !== 'cleanup') fail('unrecorded-network');
  if (mode === 'cleanup') {
    const flags = [
      'OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT',
      'OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE',
      'OPENPC_NETWORK_UNKNOWN',
      'OPENPC_NETWORK_ORIGINAL_TOPOLOGY_REQUIRED',
    ];
    const values = flags.map((name) => process.env[name] ?? '0');
    if (values.some((value) => !['0', '1'].includes(value))) fail('unknown-retention-disposition');
    if (values.some((value) => value === '1')) fail('topology-retained-or-unknown');
    if (!own) return;
    const containers = containerInventory();
    assertRemovable(own, binding, identity, containers, {
      retained: values[0] === '1' || values[1] === '1',
      unknown: values[2] === '1',
      originalTopologyRequired: values[3] === '1',
    });
    // Delete by immutable ID only. Docker also refuses a concurrent attachment.
    command('docker', ['network', 'rm', own.Id]);
    process.stderr.write('OPENPC_NETWORK|PASS|mode=cleanup|owned-empty-network-removed\n');
    return;
  }
  validateSelection(snapshot, binding, own);
  if (mode === 'plan') {
    process.stdout.write(`${binding.subnet} ${binding.gateway}\n`);
    return;
  }
  const rendered = JSON.parse(readFileSync(0, 'utf8'));
  validateCompose(rendered, binding, identity);
  if (binding.schema === newTopologySchema) newTopologyInputsUnchanged(binding, identity, rendered);
  if (mode === 'verify') {
    if (!own) fail('network-not-created');
    if (!retained) storeBinding(file, { ...binding, networkId: own.Id }, identity);
  }
  process.stderr.write(`OPENPC_NETWORK|PASS|mode=${mode}|subnet=${binding.subnet}\n`);
  process.stdout.write(own ? 'existing\n' : 'absent\n');
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(
      error instanceof Error && error.message.startsWith('OPENPC_NETWORK|')
        ? `${error.message}\n`
        : 'OPENPC_NETWORK|BLOCKED|owner-or-inspection-failed\n',
    );
    process.exitCode = 96;
  }
}
