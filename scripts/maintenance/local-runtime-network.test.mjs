import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { createHash, generateKeyPairSync, sign, X509Certificate } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  range,
  overlaps,
  selectSubnet,
  validateSelection,
  validateNetwork,
  validateCompose,
  assertRemovable,
  validateInspectedIds,
  validateDockerEndpoint,
  originalTopology,
  assertRecoveryVacant,
  validateRecoveryAnchor,
  validateStoredBinding,
  endpointInventory,
  newTopology,
  bindingDocument,
  readEndpointInputs,
  newTopologyInputsUnchanged,
} from './local-runtime-network.mjs';

const identity = {
  root: '/owned/local-runtime.example',
  project: 'openpc-local-e2e-aaaaaaaaaaaa',
  token: 'a'.repeat(64),
};
const binding = { subnet: '172.18.0.0/24', gateway: '172.18.0.1', networkId: 'b'.repeat(64) };
function network(id = 'c'.repeat(64), subnet = '172.17.0.0/16', gateway = '172.17.0.1') {
  return {
    Id: id,
    Name: 'bridge',
    Driver: 'bridge',
    Scope: 'local',
    Internal: false,
    EnableIPv6: false,
    Options: {},
    Containers: {},
    Labels: {},
    IPAM: { Driver: 'default', Config: [{ Subnet: subnet, Gateway: gateway }] },
  };
}
function own() {
  return {
    ...network(binding.networkId, binding.subnet, binding.gateway),
    Name: `${identity.project}_openpc-local`,
    Labels: {
      'com.docker.compose.project': identity.project,
      'com.docker.compose.network': 'openpc-local',
      'io.openpc.network.owner': identity.token,
      'io.openpc.network.root': identity.root,
      'io.openpc.network.schema': 'openpc-local-network-v1',
    },
  };
}
function snapshot() {
  return {
    addresses: [
      { ifname: 'lo', addr_info: [{ family: 'inet', local: '127.0.0.1', prefixlen: 8 }] },
      {
        ifname: 'wlo1',
        addr_info: [
          { family: 'inet', local: '192.168.0.20', prefixlen: 24 },
          { family: 'inet6', local: 'fe80::1', prefixlen: 64 },
        ],
      },
    ],
    routes: [
      { dst: 'default', gateway: '192.168.0.1', dev: 'wlo1' },
      { dst: '192.168.0.0/24', dev: 'wlo1' },
      { dst: '127.0.0.0/8', dev: 'lo', table: 'local' },
      { dst: '172.17.0.0/16', dev: 'docker0' },
    ],
    networks: [network()],
  };
}
function rendered() {
  return {
    services: { 'control-pg': { networks: { 'openpc-local': {} } } },
    networks: {
      'openpc-local': {
        name: `${identity.project}_openpc-local`,
        driver: 'bridge',
        enable_ipv6: false,
        ipam: { driver: 'default', config: [{ subnet: binding.subnet, gateway: binding.gateway }] },
        labels: {
          'io.openpc.network.owner': identity.token,
          'io.openpc.network.root': identity.root,
          'io.openpc.network.schema': 'openpc-local-network-v1',
        },
      },
    },
  };
}
const blocked = (fn) => assert.throws(fn, /OPENPC_NETWORK\|BLOCKED/u);

const inputDigest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
function publicCertificateFixture() {
  const der = (tag, ...parts) => {
    const bytes = Buffer.concat(parts.map((part) => Buffer.from(part)));
    const length =
      bytes.length < 128
        ? [bytes.length]
        : bytes.length < 256
          ? [0x81, bytes.length]
          : [0x82, bytes.length >> 8, bytes.length & 255];
    return Buffer.concat([Buffer.from([tag, ...length]), bytes]);
  };
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const algorithm = der(0x30, Buffer.from('06032b6570', 'hex'));
  const name = der(
    0x30,
    der(0x31, der(0x30, Buffer.from('0603550403', 'hex'), der(0x0c, 'identity.openpc.test'))),
  );
  const san = der(
    0xa3,
    der(
      0x30,
      der(
        0x30,
        Buffer.from('0603551d11', 'hex'),
        der(0x04, der(0x30, der(0x82, 'identity.openpc.test'))),
      ),
    ),
  );
  const tbs = der(
    0x30,
    der(0xa0, der(0x02, [2])),
    der(0x02, [1]),
    algorithm,
    name,
    der(0x30, der(0x17, '200101000000Z'), der(0x17, '491231235959Z')),
    name,
    publicKey.export({ type: 'spki', format: 'der' }),
    san,
  );
  const raw = der(0x30, tbs, algorithm, der(0x03, [0], sign(null, tbs, privateKey)));
  return { pem: new X509Certificate(raw).toString(), digest: inputDigest(raw).slice(7) };
}
const certificate = publicCertificateFixture();
function endpointFixture() {
  const configuration = {
    services: {
      'rpc-provider': { networks: { 'openpc-local': { ipv4_address: '192.168.48.13' } } },
    },
  };
  const consumers = rendered();
  consumers.services['rpc-provider'] = {
    networks: {
      'openpc-local': { aliases: ['rpc-provider.openpc.test'], ipv4_address: '192.168.48.13' },
    },
  };
  consumers.services['identity-service'] = {
    networks: { 'openpc-local': {} },
    environment: {
      IDENTITY_MTLS_LISTEN: '0.0.0.0:3443',
      IDENTITY_MTLS_SERVER_CERT_FILE: '/run/secrets/identity_mtls_server_cert',
    },
    secrets: [{ source: 'identity_mtls_server_cert', target: 'identity_mtls_server_cert' }],
  };
  consumers.secrets = {
    identity_mtls_server_cert: {
      file: join(identity.root, 'secrets/identity_mtls_server_cert.pem'),
    },
  };
  const endpoint = (host, port, path) => ({
    normalized_uri: `https://${host}:${port}${path}`,
    reference_identity: host,
    port,
    path,
  });
  const provider = {
    version: 1,
    endpoint: endpoint('rpc-provider.openpc.test', 3008, '/rpc'),
    addresses: ['192.168.48.13'],
    allowed_ranges: ['192.168.48.13/32'],
    private_network_ranges: ['192.168.48.13/32'],
    allow_ip_endpoint: false,
  };
  const providerDigest = inputDigest(JSON.stringify(provider));
  const profile = { configuration_digest: providerDigest };
  const fact = {
    version: 1,
    identity_endpoint: endpoint('identity.openpc.test', 3443, '/internal'),
    identity_addresses: ['192.168.48.7'],
    allowed_ranges: ['192.168.48.7/32'],
    private_network_ranges: ['192.168.48.7/32'],
    allow_ip_endpoint: false,
    provider_directory: '/provider-sources',
    server_certificate_digest: certificate.digest,
  };
  const input = (kind, path, value) => ({
    kind,
    path,
    value,
    digest: inputDigest(JSON.stringify(value)),
  });
  const inputs = [
    input(
      'provider',
      'data/runtime-bootstrap/provider-probe-source/018f0000-0000-7000-8000-000000000930.json',
      provider,
    ),
    input('profile', 'data/runtime-bootstrap/provider-probe-source/profile.json', profile),
    input('identity', 'data/runtime-bootstrap/fact-bridge/config/deployment.json', fact),
    {
      kind: 'identity-certificate',
      path: 'secrets/identity_mtls_server_cert.pem',
      digest: inputDigest(certificate.pem),
      value: {
        service: 'identity-service',
        referenceIdentity: 'identity.openpc.test',
        port: 3443,
        certificateDigest: certificate.digest,
      },
    },
  ];
  return {
    configuration,
    consumers,
    inputs,
    configurationDigest: inputDigest(JSON.stringify(configuration)),
  };
}

test('NEW_TOPOLOGY preserves real-profile RPC and FactBridge Identity constraints without historical IPAM', () => {
  const fixture = endpointFixture();
  const manifest = endpointInventory(fixture.configuration, fixture.consumers, fixture.inputs);
  assert.deepEqual(manifest.staticAddresses, {
    'identity-service': '192.168.48.7',
    'rpc-provider': '192.168.48.13',
  });
  assert.equal(manifest.consumers['identity-service'].address, '192.168.48.7');
  const selected = newTopology(
    snapshot(),
    fixture.configuration,
    fixture.consumers,
    fixture.inputs,
    fixture.configurationDigest,
  );
  assert.equal(selected.subnet, '192.168.48.0/24');
  assert.equal(selected.gateway, '192.168.48.1');
  assert.equal(selected.recovery.admission, 'NEW_TOPOLOGY');
  assert.equal(selected.recovery.originalTopology, 'UNKNOWN');
  assert.equal(selected.recovery.originalNetworkId, null);
  assert.equal(Object.hasOwn(fixture.configuration, 'networks'), false);
  blocked(() => originalTopology(fixture.configuration, undefined, identity));
});

test('NEW_TOPOLOGY rejects incomplete endpoint inventory, contradictory pins and ambiguous consumers', () => {
  for (const alter of [
    (value) => value.inputs.pop(),
    (value) => value.inputs.splice(2, 1),
    (value) => value.inputs.splice(1, 1),
    (value) => (value.inputs[1].value.configuration_digest = 'sha256:' + '0'.repeat(64)),
    (value) => (value.inputs[0].value.addresses = ['192.168.48.14']),
    (value) =>
      (value.inputs[2].value.identity_endpoint.reference_identity = 'unmapped.openpc.test'),
    (value) =>
      (value.consumers.services['control-pg'].networks['openpc-local'].aliases = [
        'identity.openpc.test',
      ]),
    (value) =>
      (value.consumers.services['rpc-provider'].networks['openpc-local'].ipv4_address =
        '192.168.48.14'),
    (value) => (value.consumers.services['control-pg'].network_mode = 'host'),
    (value) =>
      (value.consumers.services['control-pg'].extra_hosts = {
        'identity.openpc.test': '192.168.48.8',
      }),
    (value) =>
      (value.consumers.services['control-pg'].environment = {
        UNRECONCILED_ENDPOINT: 'https://192.168.49.9:3000',
      }),
    (value) => (value.consumers.services['control-pg'].command = ['connect', '192.168.49.9']),
    (value) => (value.consumers.services['control-pg'].volumes = [null]),
    (value) => (value.inputs[0].value.endpoint.normalized_uri += '?unknown=true'),
    (value) => (value.inputs[2].value.server_certificate_digest = '0'.repeat(64)),
    (value) =>
      (value.consumers.services['identity-service'].environment.IDENTITY_MTLS_LISTEN =
        '0.0.0.0:3444'),
  ]) {
    const value = endpointFixture();
    alter(value);
    blocked(() => endpointInventory(value.configuration, value.consumers, value.inputs));
  }
});

test('NEW_TOPOLOGY retains LAN/VPN denial, requires every pin in its bounded range, and avoids pinned gateways', () => {
  assert.equal(selectSubnet(snapshot(), ['192.168.48.1', '192.168.48.7']).gateway, '192.168.48.2');
  for (const pins of [
    ['192.168.0.13'],
    ['192.168.48.13', '192.168.49.7'],
    ['192.168.48.0'],
    ['192.168.48.255'],
    ['8.8.8.8'],
  ])
    blocked(() => selectSubnet(snapshot(), pins));
  const vpn = snapshot();
  vpn.routes.push({ dst: '192.168.48.0/24', dev: 'tun0', table: 150 });
  blocked(() => selectSubnet(vpn, ['192.168.48.13']));
  blocked(() =>
    selectSubnet(
      snapshot(),
      Array.from({ length: 254 }, (_, i) => `192.168.48.${i + 1}`),
    ),
  );
});

test('NEW_TOPOLOGY execution input is its exact Compose overlay and crash intent never becomes historical proof', () => {
  const fixture = endpointFixture(),
    selected = newTopology(
      snapshot(),
      fixture.configuration,
      fixture.consumers,
      fixture.inputs,
      fixture.configurationDigest,
    );
  selected.recovery.attempt = '01234567-1234-4567-8123-0123456789ab';
  const pending = bindingDocument(selected, identity);
  assert.throws(() => validateStoredBinding(pending, identity), /recovery-outcome-unknown/u);
  selected.networkId = 'e'.repeat(64);
  selected.recovery.state = 'BOUND';
  const doc = bindingDocument(selected, identity),
    admitted = validateStoredBinding(doc, identity);
  assert.equal(
    doc.services['identity-service'].networks['openpc-local'].ipv4_address,
    '192.168.48.7',
  );
  assert.equal(admitted.recovery.originalTopology, 'UNKNOWN');
  for (const alter of [
    (value) => (value['x-openpc-network'].recovery.originalTopology = 'RESTORED'),
    (value) => (value['x-openpc-network'].recovery.admission = 'ORIGINAL'),
    (value) => (value['x-openpc-network'].gateway = '192.168.48.7'),
    (value) =>
      (value.services['identity-service'].networks['openpc-local'].ipv4_address = '192.168.48.8'),
    (value) =>
      (value['x-openpc-network'].recovery.consumers['identity-service'].address = '192.168.48.8'),
  ]) {
    const changed = structuredClone(doc);
    alter(changed);
    blocked(() => validateStoredBinding(changed, identity));
  }
  blocked(() => validateStoredBinding(doc['x-openpc-network'], identity));
});

test('NEW_TOPOLOGY never permits an existing original project network or consumer', () => {
  const fixture = endpointFixture(),
    selected = newTopology(
      snapshot(),
      fixture.configuration,
      fixture.consumers,
      fixture.inputs,
      fixture.configurationDigest,
    );
  assertRecoveryVacant(snapshot(), [], selected, identity);
  const source = snapshot();
  source.networks.push({
    ...network('e'.repeat(64), '10.1.0.0/24', '10.1.0.1'),
    Name: `${identity.project}_openpc-local`,
  });
  blocked(() => assertRecoveryVacant(source, [], selected, identity));
  const consumer = {
    Id: 'e'.repeat(64),
    Config: { Labels: { 'com.docker.compose.project': identity.project } },
    NetworkSettings: { Networks: {} },
    HostConfig: { NetworkMode: 'none' },
  };
  blocked(() => assertRecoveryVacant(snapshot(), [consumer], selected, identity));
});

test('owned mounted endpoint files produce the complete manifest and reject missing or redirected inputs', (t) => {
  const root = mkdtempSync(
    join(process.env.OPENPC_PNC_TMP_ROOT ?? tmpdir(), 'openpc-network-inputs-'),
  );
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = endpointFixture(),
    owner = { ...identity, root };
  const providers = join(root, 'data/runtime-bootstrap/provider-probe-source'),
    fact = join(root, 'data/runtime-bootstrap/fact-bridge/config');
  mkdirSync(providers, { recursive: true });
  mkdirSync(fact, { recursive: true });
  mkdirSync(join(root, 'secrets'), { recursive: true });
  fixture.consumers.secrets.identity_mtls_server_cert.file = join(
    root,
    'secrets/identity_mtls_server_cert.pem',
  );
  for (const input of fixture.inputs)
    writeFileSync(
      join(root, input.path),
      input.kind === 'identity-certificate' ? certificate.pem : JSON.stringify(input.value),
      { mode: 0o600 },
    );
  fixture.consumers.services['control-worker'] = {
    networks: { 'openpc-local': {} },
    volumes: [{ type: 'bind', source: providers, target: '/provider-sources' }],
  };
  fixture.consumers.services['fact-service'] = {
    networks: { 'openpc-local': {} },
    volumes: [
      { type: 'bind', source: providers, target: '/provider-sources' },
      { type: 'bind', source: fact, target: '/fact-bridge' },
    ],
    environment: { OPENPC_FACT_BRIDGE_CONFIGURATION_FILE: '/fact-bridge/deployment.json' },
  };
  assert.deepEqual(
    endpointInventory(
      fixture.configuration,
      fixture.consumers,
      readEndpointInputs(fixture.consumers, owner),
    ).staticAddresses,
    { 'identity-service': '192.168.48.7', 'rpc-provider': '192.168.48.13' },
  );
  const originalFile = join(root, 'data/runtime-bootstrap/compose.json');
  const originalBytes = JSON.stringify(fixture.configuration);
  writeFileSync(originalFile, originalBytes, { mode: 0o600 });
  const selected = newTopology(
    snapshot(),
    fixture.configuration,
    fixture.consumers,
    readEndpointInputs(fixture.consumers, owner),
    inputDigest(originalBytes),
  );
  fixture.consumers.services['identity-service'].networks['openpc-local'].ipv4_address =
    '192.168.48.7';
  fixture.consumers.networks['openpc-local'].ipam.config = [
    { subnet: selected.subnet, gateway: selected.gateway },
  ];
  fixture.consumers.networks['openpc-local'].labels['io.openpc.network.root'] = root;
  validateCompose(fixture.consumers, selected, owner);
  newTopologyInputsUnchanged(selected, owner, fixture.consumers);
  writeFileSync(originalFile, originalBytes + '\n');
  blocked(() => newTopologyInputsUnchanged(selected, owner, fixture.consumers));
  writeFileSync(originalFile, originalBytes);
  for (const alter of [
    (value) =>
      (value.services['identity-service'].networks['openpc-local'].aliases = ['changed-alias']),
    (value) => (value.services['control-worker'].volumes = []),
    (value) => (value.services['extra-consumer'] = { networks: { 'openpc-local': {} } }),
    (value) =>
      (value.services['identity-service'].networks['openpc-local'].ipv4_address = '192.168.48.8'),
    (value) =>
      value.services['fact-service'].volumes.push({
        type: 'volume',
        source: 'shadow',
        target: '/fact-bridge/deployment.json',
      }),
    (value) => (value.secrets.identity_mtls_server_cert.file = '/foreign/server.pem'),
    (value) =>
      value.services['identity-service'].secrets.push({
        source: 'shadow',
        target: 'identity_mtls_server_cert',
      }),
    (value) =>
      (value.services['identity-service'].environment.IDENTITY_MTLS_LISTEN = '0.0.0.0:3444'),
  ]) {
    const changed = structuredClone(fixture.consumers);
    alter(changed);
    blocked(() => newTopologyInputsUnchanged(selected, owner, changed));
  }
  const identityFile = join(fact, 'deployment.json');
  const certificateFile = join(root, 'secrets/identity_mtls_server_cert.pem');
  writeFileSync(certificateFile, publicCertificateFixture().pem);
  blocked(() => newTopologyInputsUnchanged(selected, owner, fixture.consumers));
  writeFileSync(certificateFile, certificate.pem);
  const identityBytes = readFileSync(identityFile, 'utf8');
  const changedIdentity = JSON.parse(identityBytes);
  changedIdentity.identity_addresses = ['192.168.48.8'];
  changedIdentity.allowed_ranges = changedIdentity.private_network_ranges = ['192.168.48.8/32'];
  writeFileSync(identityFile, JSON.stringify(changedIdentity));
  blocked(() => newTopologyInputsUnchanged(selected, owner, fixture.consumers));
  writeFileSync(identityFile, identityBytes);
  const unknown = join(providers, 'unexpected-endpoint.json');
  writeFileSync(unknown, '{}');
  blocked(() => readEndpointInputs(fixture.consumers, owner));
  rmSync(unknown);
  const profile = join(providers, 'profile.json');
  rmSync(profile);
  blocked(() =>
    endpointInventory(
      fixture.configuration,
      fixture.consumers,
      readEndpointInputs(fixture.consumers, owner),
    ),
  );
  symlinkSync(join(fact, 'deployment.json'), profile);
  blocked(() => readEndpointInputs(fixture.consumers, owner));
});

function originalConfiguration() {
  return {
    services: {
      'rpc-provider': { networks: { 'openpc-local': { ipv4_address: '192.168.48.13' } } },
    },
    networks: {
      'openpc-local': {
        ipam: { config: [{ subnet: '192.168.48.0/20', gateway: '192.168.48.1' }] },
      },
    },
  };
}

test('retained recovery derives exact original IPAM and never guesses a prefix from the static endpoint', () => {
  const configuration = originalConfiguration();
  const original = originalTopology(configuration, undefined, identity);
  assert.equal(original.subnet, '192.168.48.0/20');
  assert.deepEqual(original.recovery.staticAddresses, { 'rpc-provider': '192.168.48.13' });
  validateSelection(snapshot(), original);
  const withoutIpam = { services: configuration.services };
  assert.throws(
    () => originalTopology(withoutIpam, undefined, identity),
    /original-subnet-and-gateway-evidence-required/u,
  );
  const previous = {
    subnet: original.subnet,
    gateway: original.gateway,
    networkId: binding.networkId,
  };
  assert.equal(
    originalTopology(withoutIpam, previous, identity).recovery.originalNetworkId,
    binding.networkId,
  );
  for (const alter of [
    (value) => (value.networks['openpc-local'].ipam.config[0].gateway = undefined),
    (value) => (value.networks['openpc-local'].ipam.config[0].subnet = '192.168.48.13/20'),
    (value) =>
      value.networks['openpc-local'].ipam.config.push({
        subnet: '10.0.0.0/8',
        gateway: '10.0.0.1',
      }),
    (value) => (value.networks['openpc-local'].name = 'foreign'),
    (value) =>
      (value.services['rpc-provider'].networks['openpc-local'].ipv4_address = '192.168.0.13'),
  ]) {
    const value = originalConfiguration();
    alter(value);
    blocked(() => originalTopology(value, undefined, identity));
  }
  blocked(() => originalTopology(configuration, binding, identity));
});

test('retained recovery rejects collisions, original networks and stopped or foreign consumers', () => {
  const original = originalTopology(originalConfiguration(), undefined, identity);
  assertRecoveryVacant(snapshot(), [], original, identity);
  for (const alter of [
    (value) => value.routes.push({ dst: '192.168.48.0/24', dev: 'tun0' }),
    (value) =>
      value.networks.push({
        ...network('e'.repeat(64), '10.1.0.0/24', '10.1.0.1'),
        Name: `${identity.project}_openpc-local`,
      }),
    (value) =>
      value.networks.push({
        ...network('e'.repeat(64), '10.1.0.0/24', '10.1.0.1'),
        Labels: { 'com.docker.compose.project': identity.project },
      }),
  ]) {
    const value = snapshot();
    alter(value);
    blocked(() => assertRecoveryVacant(value, [], original, identity));
  }
  const stopped = {
    Id: 'e'.repeat(64),
    Config: { Labels: {} },
    State: { Running: false },
    NetworkSettings: { Networks: {} },
    HostConfig: { NetworkMode: 'none' },
  };
  assertRecoveryVacant(snapshot(), [stopped], original, identity);
  for (const consumer of [
    { ...stopped, Config: { Labels: { 'com.docker.compose.project': identity.project } } },
    { ...stopped, HostConfig: { NetworkMode: `${identity.project}_openpc-local` } },
    { ...stopped, NetworkSettings: { Networks: { [`${identity.project}_openpc-local`]: {} } } },
    { ...stopped, HostConfig: { NetworkMode: 'container:missing' } },
  ])
    blocked(() => assertRecoveryVacant(snapshot(), [consumer], original, identity));
});

test('a recovery intent or malformed persisted result remains fenced after a crash', () => {
  const original = originalTopology(originalConfiguration(), undefined, identity);
  const record = {
    ...identity,
    ...original,
    schema: 'openpc-local-network-binding-v2',
    recovery: { ...original.recovery, attempt: '01234567-1234-4567-8123-0123456789ab' },
  };
  assert.throws(() => validateStoredBinding(record, identity), /recovery-outcome-unknown/u);
  const completed = {
    ...record,
    networkId: 'e'.repeat(64),
    recovery: { ...record.recovery, state: 'BOUND' },
  };
  assert.equal(validateStoredBinding(completed, identity).networkId, 'e'.repeat(64));
  for (const changed of [
    { ...completed, token: 'foreign' },
    { ...completed, networkId: null },
    { ...completed, recovery: { ...completed.recovery, state: 'RETRY' } },
    { ...completed, recovery: { ...completed.recovery, attempt: '-'.repeat(36) } },
    {
      ...completed,
      recovery: { ...completed.recovery, staticAddresses: { 'rpc-provider': '192.168.0.13' } },
    },
    { ...completed, recovery: { ...completed.recovery, unexpected: true } },
  ])
    blocked(() => validateStoredBinding(changed, identity));
});

test('recovered allocation requires only a stopped anchor and unchanged original static bindings', () => {
  const original = originalTopology(originalConfiguration(), undefined, identity);
  const configuration = rendered();
  configuration.networks['openpc-local'].ipam.config = [
    { subnet: original.subnet, gateway: original.gateway },
  ];
  configuration.services['rpc-provider'] = originalConfiguration().services['rpc-provider'];
  configuration.services['control-pg'].image = 'pinned-postgres';
  validateCompose(configuration, original, identity);
  const anchor = {
    Id: 'e'.repeat(64),
    Config: {
      Image: 'pinned-postgres',
      Labels: {
        'com.docker.compose.project': identity.project,
        'com.docker.compose.service': 'control-pg',
      },
    },
    State: { Running: false },
    NetworkSettings: { Networks: {} },
    HostConfig: { NetworkMode: own().Name },
  };
  validateRecoveryAnchor([anchor], own(), configuration, identity);
  blocked(() =>
    validateRecoveryAnchor(
      [{ ...anchor, State: { Running: true } }],
      own(),
      configuration,
      identity,
    ),
  );
  const foreign = { ...anchor, Id: 'f'.repeat(64), Config: { Labels: {} } };
  blocked(() => validateRecoveryAnchor([anchor, foreign], own(), configuration, identity));
  blocked(() =>
    validateRecoveryAnchor(
      [anchor],
      { ...own(), Containers: { foreign: {} } },
      configuration,
      identity,
    ),
  );
  configuration.services['rpc-provider'].networks['openpc-local'].ipv4_address = '192.168.48.14';
  blocked(() => validateCompose(configuration, original, identity));
});

test('CIDR overlap covers containment in both directions and rejects malformed addresses', () => {
  for (const [a, b] of [
    ['192.168.0.0/24', '192.168.0.1/32'],
    ['10.0.0.0/8', '10.77.4.0/24'],
    ['172.17.0.0/16', '172.17.99.0/24'],
  ]) {
    assert.equal(overlaps(range(a), range(b)), true);
    assert.equal(overlaps(range(b), range(a)), true);
  }
  assert.equal(overlaps(range('192.168.0.0/24'), range('192.168.1.0/24')), false);
  for (const value of [
    '192.168.0.0/33',
    '172.017.0.1/24',
    '1.2.3/24',
    '0.0.0.0/-1',
    '10.0.0.0/08',
    '10.0.0.0/24\n',
  ])
    blocked(() => range(value));
});
test('selection excludes actual LAN and Docker ranges without treating default as all space', () => {
  const source = snapshot(),
    selected = selectSubnet(source);
  assert.equal(selected.subnet, '172.16.0.0/24');
  assert.doesNotThrow(() => validateSelection(source, selected));
  for (const subnet of ['192.168.0.0/24', '172.17.100.0/24'])
    blocked(() => validateSelection(source, { subnet, gateway: subnet.replace('0/24', '1') }));
});
test('an original 192.168.48.13 endpoint is distinct from a 192.168.0.0/24 LAN', () => {
  const original = { ...binding, subnet: '192.168.48.0/24', gateway: '192.168.48.1' };
  const configuration = rendered();
  configuration.networks['openpc-local'].ipam.config = [
    { subnet: original.subnet, gateway: original.gateway },
  ];
  configuration.services['rpc-provider'] = {
    networks: { 'openpc-local': { ipv4_address: '192.168.48.13' } },
  };
  validateSelection(snapshot(), original);
  validateCompose(configuration, original, identity);
  const vpn = snapshot();
  vpn.routes.push({ dst: '192.168.48.0/20', dev: 'tun0', table: 100 });
  blocked(() => validateSelection(vpn, original));
  // Choosing a new subnet must never silently rewrite a governed endpoint.
  blocked(() => validateCompose(configuration, binding, identity));
});
test('specific VPN routes, policy-routing tables, gateway hosts and interface prefixes all exclude', () => {
  for (const addition of [
    (source) => source.routes.push({ dst: '172.16.0.0/12', dev: 'tun0', table: 100 }),
    (source) =>
      source.addresses.push({
        ifname: 'tun0',
        addr_info: [{ family: 'inet', local: '172.16.0.5', prefixlen: 12 }],
      }),
    (source) => source.routes.push({ dst: '172.16.0.12', dev: 'tun0' }),
    (source) =>
      source.routes.push({ dst: 'default', multipath: [{ dev: 'tun0', gateway: '172.16.0.8' }] }),
  ]) {
    const source = snapshot();
    addition(source);
    assert.notEqual(selectSubnet(source).subnet, '172.16.0.0/24');
  }
});
test('malformed, empty and incomplete inspection cannot authorize allocation', () => {
  const cases = [
    null,
    {},
    { ...snapshot(), routes: [] },
    { ...snapshot(), addresses: [] },
    { ...snapshot(), networks: [] },
    { ...snapshot(), routes: [{}] },
    { ...snapshot(), networks: [{ Id: 'bad' }] },
    { ...snapshot(), networks: [{ ...network(), IPAM: { Config: [] } }] },
    { ...snapshot(), addresses: [{ ifname: 'wlo1', addr_info: null }] },
    { ...snapshot(), routes: [{ dst: 'default', gateway: 'invalid' }] },
    { ...snapshot(), networks: [network(), network()] },
  ];
  for (const source of cases) blocked(() => selectSubnet(source));
});
test('exhausted private candidates fail closed, including broad VPN split-default routes', () => {
  const source = snapshot();
  source.routes.push({ dst: '0.0.0.0/1', dev: 'tun0' }, { dst: '128.0.0.0/1', dev: 'tun0' });
  blocked(() => selectSubnet(source));
});
test('sequential allocations inspect the first allocation and never reuse a stale private choice', () => {
  const source = snapshot(),
    first = selectSubnet(source);
  source.networks.push(network('d'.repeat(64), first.subnet, first.gateway));
  const second = selectSubnet(source);
  assert.notEqual(first.subnet, second.subnet);
  blocked(() => validateSelection(source, first));
  assert.doesNotThrow(() => validateSelection(source, second));
});
test('reuse admits only the original ID, labels and exact IPAM with its own bridge routes excluded', () => {
  const source = snapshot(),
    original = own(),
    device = `br-${original.Id.slice(0, 12)}`;
  source.networks.push(original);
  source.routes.push(
    { dst: binding.subnet, dev: device },
    { dst: binding.gateway, dev: device, table: 'local' },
  );
  source.addresses.push({
    ifname: device,
    addr_info: [{ family: 'inet', local: binding.gateway, prefixlen: 24 }],
  });
  validateNetwork(original, binding, identity);
  const emptyRange = structuredClone(original);
  emptyRange.IPAM.Config[0].IPRange = '';
  validateNetwork(emptyRange, binding, identity);
  for (const range of ['172.18.0.0/25', ' ', null, 0]) {
    const changed = structuredClone(original);
    changed.IPAM.Config[0].IPRange = range;
    blocked(() => validateNetwork(changed, binding, identity));
  }
  const unknownIpam = structuredClone(original);
  unknownIpam.IPAM.Config[0].Unknown = '';
  blocked(() => validateNetwork(unknownIpam, binding, identity));
  validateSelection(source, binding, original);
  source.routes.push({ dst: '172.18.0.0/16', dev: 'tun0' });
  blocked(() => validateSelection(source, binding, original));
  for (const changed of [
    { ...original, Id: 'e'.repeat(64) },
    { ...original, Labels: {} },
    {
      ...original,
      IPAM: { Driver: 'default', Config: [{ Subnet: '172.19.0.0/24', Gateway: '172.19.0.1' }] },
    },
    { ...original, EnableIPv6: true },
    { ...original, Name: 'unrelated' },
    { ...original, Options: { 'com.docker.network.bridge.name': 'wlo1' } },
    { ...original, IPAM: { ...original.IPAM, Options: { override: 'yes' } } },
  ])
    blocked(() => validateNetwork(changed, binding, identity));
});
test('explicit Compose overrides and host/network bypasses are denied', () => {
  validateCompose(rendered(), binding, identity);
  const reordered = rendered();
  reordered.networks['openpc-local'].ipam.config = [
    { gateway: binding.gateway, subnet: binding.subnet },
  ];
  validateCompose(reordered, binding, identity);
  const changes = [
    (value) => (value.networks['openpc-local'].ipam.config[0].subnet = '192.168.0.0/24'),
    (value) => (value.networks['openpc-local'].external = true),
    (value) => (value.networks.other = {}),
    (value) => (value.networks['openpc-local'].labels['io.openpc.network.owner'] = 'other'),
    (value) => (value.services['control-pg'].network_mode = 'host'),
    (value) => (value.services['control-pg'].networks = { default: {} }),
    (value) => (value.networks['openpc-local'].driver_opts = { bridge: 'wlo1' }),
    (value) =>
      (value.services['control-pg'].networks['openpc-local'] = { ipv4_address: '192.168.0.10' }),
    (value) =>
      (value.services['control-pg'].networks['openpc-local'] = { ipv6_address: 'fd00::1' }),
  ];
  for (const change of changes) {
    const value = rendered();
    change(value);
    blocked(() => validateCompose(value, binding, identity));
  }
});
test('only positively owned empty networks without retention or UNKNOWN obligations are removable', () => {
  const clear = { retained: false, unknown: false, originalTopologyRequired: false };
  assertRemovable(own(), binding, identity, [], clear);
  for (const field of Object.keys(clear))
    blocked(() => assertRemovable(own(), binding, identity, [], { ...clear, [field]: true }));
  blocked(() => assertRemovable(network(), binding, identity, [], clear));
  blocked(() =>
    assertRemovable({ ...own(), Containers: { active: {} } }, binding, identity, [], clear),
  );
  for (const consumer of [
    {
      Id: 'd'.repeat(64),
      State: { Running: false },
      NetworkSettings: { Networks: { [own().Name]: { NetworkID: binding.networkId } } },
      HostConfig: { NetworkMode: 'default' },
    },
    {
      Id: 'd'.repeat(64),
      State: { Running: true },
      NetworkSettings: { Networks: {} },
      HostConfig: { NetworkMode: own().Name },
    },
    {
      Id: 'd'.repeat(64),
      NetworkSettings: { Networks: {} },
      HostConfig: { NetworkMode: 'container:other' },
    },
    {},
  ])
    blocked(() => assertRemovable(own(), binding, identity, [consumer], clear));
});
test('complete unrelated shared namespaces are safe while missing, cyclic and ambiguous chains block cleanup', () => {
  const clear = { retained: false, unknown: false, originalTopologyRequired: false };
  const base = {
    Id: 'd'.repeat(64),
    Name: '/unrelated',
    NetworkSettings: { Networks: {} },
    HostConfig: { NetworkMode: 'none' },
  };
  const shared = {
    Id: 'e'.repeat(64),
    Name: '/shared',
    NetworkSettings: { Networks: {} },
    HostConfig: { NetworkMode: 'container:unrelated' },
  };
  assertRemovable(own(), binding, identity, [base, shared], clear);
  assertRemovable(
    own(),
    binding,
    identity,
    [base, { ...shared, HostConfig: { NetworkMode: `container:${base.Id.slice(0, 12)}` } }],
    clear,
  );
  blocked(() => assertRemovable(own(), binding, identity, [shared], clear));
  blocked(() =>
    assertRemovable(
      own(),
      binding,
      identity,
      [{ ...base, HostConfig: { NetworkMode: 'container:shared' } }, shared],
      clear,
    ),
  );
  blocked(() =>
    assertRemovable(
      own(),
      binding,
      identity,
      [base, { ...base, Id: 'f'.repeat(64) }, shared],
      clear,
    ),
  );
  blocked(() => assertRemovable(own(), binding, identity, [base, base], clear));
});
test('inspection must return each requested ID exactly once and topology must use a local Docker endpoint', () => {
  const ids = ['c'.repeat(64), 'd'.repeat(64)];
  assert.deepEqual(
    validateInspectedIds(
      ids,
      ids.map((Id) => ({ Id })),
    ).map((item) => item.Id),
    ids,
  );
  for (const records of [
    null,
    [],
    [{ Id: ids[0] }],
    [{ Id: ids[0] }, { Id: ids[0] }],
    [{ Id: ids[0] }, { Id: 'f'.repeat(64) }],
  ])
    blocked(() => validateInspectedIds(ids, records));
  blocked(() => validateInspectedIds([ids[0], ids[0]], [{ Id: ids[0] }, { Id: ids[0] }]));
  validateDockerEndpoint({ Host: 'unix:///var/run/docker.sock' }, undefined);
  for (const host of ['tcp://localhost:2375', 'ssh://remote', '', null])
    blocked(() => validateDockerEndpoint({ Host: host }, undefined));
  blocked(() =>
    validateDockerEndpoint({ Host: 'unix:///var/run/docker.sock' }, 'unix:///other.sock'),
  );
});
test('the effect owner reads real topology and held ancestor locks, and never prunes resources', () => {
  const owner = readFileSync(new URL('./local-runtime-network.mjs', import.meta.url), 'utf8');
  assert.match(owner, /held\(sentinel,\s*Number\(process\.env\.OPENPC_RUNTIME_OWNER_PID\),\s*8\)/u);
  assert.match(owner, /openpc-heavy.lock/u);
  assert.match(owner, /'route',\s*'show',\s*'table',\s*'all'/u);
  assert.match(owner, /command\('docker',\s*\['network',\s*'rm',\s*own.Id\]\)/u);
  assert.doesNotMatch(
    owner,
    /\['(?:container|volume|image)',\s*'(?:rm|prune)'|\['network',\s*'prune'/u,
  );
});
