import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { relationshipSourceLogs, sourceBlockHeader } from './rpc-source-header-fixture.mjs';
const [mode, root, address, sourceKind] = process.argv.slice(2);
if (sourceKind !== undefined && sourceKind !== 'state-candidates')
  throw new Error('Unknown controlled source corpus');
if (!root || !['bootstrap', 'source'].includes(mode))
  throw new Error('Owned fixture root and mode required');
const scope = JSON.parse(
  process.env.OPENPC_LOCAL_FIXTURE_SCOPE ??
    '["018f0000-0000-7000-8000-000000000101","018f0000-0000-7000-8000-000000000201"]',
);
if (
  !Array.isArray(scope) ||
  scope.length !== 2 ||
  scope.some(
    (value) =>
      typeof value !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value),
  )
)
  throw new Error('Controlled provider scope rejected');
const provider = join(root, 'rpc-provider'),
  sources = join(root, 'provider-probe-source');
const hash = (v) => createHash('sha256').update(v).digest('hex');
const openssl = (args) => execFileSync('openssl', args, { cwd: provider, stdio: 'ignore' });
const replaceSource = async (name, bytes) => {
  const path = join(sources, name);
  await writeFile(`${path}.next`, bytes, { mode: 0o444 });
  await chmod(`${path}.next`, 0o444);
  await rename(`${path}.next`, path);
};
if (mode === 'bootstrap') {
  await mkdir(provider, { mode: 0o755 });
  await mkdir(sources, { mode: 0o755 });
  // The restricted worker must traverse its read-only input mount even when
  // the host setup process uses a private umask. Key files stay private.
  await chmod(sources, 0o755);
  // The service creates its private 0700 journal beneath this disposable mount.
  await mkdir(join(root, 'provider-probe-journal'), { mode: 0o777 });
  await chmod(join(root, 'provider-probe-journal'), 0o777);
  openssl([
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-keyout',
    'ca.key',
    '-out',
    'ca.pem',
    '-days',
    '1',
    '-subj',
    '/CN=controlled-rpc-provider-ca',
  ]);
  for (const [name, san, usage, serial] of [
    ['server', 'DNS:rpc-provider.openpc.test', 'serverAuth', '1'],
    ['client', 'URI:urn:openpc:local:provider-probe', 'clientAuth', '2'],
  ]) {
    openssl([
      'req',
      '-new',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      `${name}.key`,
      '-out',
      `${name}.csr`,
      '-subj',
      `/CN=${name}`,
    ]);
    await writeFile(
      join(provider, `${name}.ext`),
      `subjectAltName=${san}\nextendedKeyUsage=${usage}\nkeyUsage=digitalSignature\n`,
    );
    openssl([
      'x509',
      '-req',
      '-in',
      `${name}.csr`,
      '-CA',
      'ca.pem',
      '-CAkey',
      'ca.key',
      '-set_serial',
      serial,
      '-days',
      '1',
      '-extfile',
      `${name}.ext`,
      '-out',
      `${name}.pem`,
    ]);
    await rm(join(provider, `${name}.csr`));
    await rm(join(provider, `${name}.ext`));
  }
  await rm(join(provider, 'ca.key'));
} else {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/u.test(address ?? ''))
    throw new Error('Controlled provider address required');
  const cert = async (name) =>
    new X509Certificate(await readFile(join(provider, `${name}.pem`))).raw;
  const rootCert = await cert('ca'),
    client = await cert('client'),
    server = await cert('server');
  const credential = '018f0000-0000-7000-8000-000000000931';
  const probe = {
    corpus_digest: hash('controlled-hash-pinned-call-corpus/v1'),
    chain_id: 31337,
    genesis_hash: '11'.repeat(32),
    block_hash: '22'.repeat(32),
    block_number: 10,
    state_root: '33'.repeat(32),
    unknown_block_hash: '44'.repeat(32),
    noncanonical_block_hash: '55'.repeat(32),
    sender: Array(20).fill(0x66),
    target: Array(20).fill(0x77),
    calldata: [1, 2, 3, 4],
    expected_result_digest: hash(Buffer.from('1234', 'hex')),
    expected_client_version_digest: hash('controlled-provider/v1'),
    unknown_hash_error_code: -32000,
    noncanonical_hash_error_code: -32001,
    repeat_window: { secs: 5, nanos: 0 },
    per_request_timeout: { secs: 2, nanos: 0 },
  };
  if (sourceKind === 'state-candidates') {
    const header = sourceBlockHeader(10);
    probe.corpus_digest = hash('controlled-state-and-header-corpus/v1');
    probe.block_header = {
      expected_header_digest: hash(
        JSON.stringify(
          Object.fromEntries(
            Object.keys(header)
              .sort()
              .map((key) => [key, header[key]]),
          ),
        ),
      ),
      unknown_block_number: 99,
    };
    if (process.env.OPENPC_VISIBILITY_SOURCE_KIND === 'relationship') {
      const owned = JSON.parse(await readFile(join(provider, 'fact-inputs.json'), 'utf8'));
      const logs = relationshipSourceLogs(owned).filter(
        (log) => log.blockHash === `0x${probe.block_hash}`,
      );
      if (logs.length === 0) throw new Error('relationship qualification requires a known event');
      probe.corpus_digest = hash('controlled-relationship-and-header-corpus/v1');
      probe.target = [...Buffer.from(logs[0].address.slice(2), 'hex')];
      probe.event_log = {
        event_signature: logs[0].topics[0].slice(2),
        expected_logs_digest: hash(
          JSON.stringify(
            logs.map((log) =>
              Object.fromEntries(
                Object.keys(log)
                  .sort()
                  .map((key) => [key, log[key]]),
              ),
            ),
          ),
        ),
      };
    }
  }
  const source = {
    version: 1,
    participant_id: scope[0],
    privacy_domain_id: scope[1],
    endpoint: {
      endpoint_id: 'local-provider-endpoint',
      normalized_uri: 'https://rpc-provider.openpc.test:3008/rpc',
      reference_identity: 'rpc-provider.openpc.test',
      port: 3008,
      path: '/rpc',
      dns_policy_ref: 'local-exact-address-v1',
      tls_policy_ref: 'local-mtls-v1',
      credential_ref: `urn:openpc:secret:${credential}`,
      egress_policy_ref: 'local-exact-private-address-v1',
      endpoint_generation: 1,
    },
    allowed_ranges: [`${address}/32`],
    private_network_ranges: [`${address}/32`],
    allow_ip_endpoint: false,
    addresses: [address],
    connection_validity_ms: 3600000,
    roots_der: [[...rootCert]],
    client_chain_der: [[...client]],
    server_certificate_digest: hash(server),
    probe,
  };
  const bytes = JSON.stringify(source);
  await replaceSource('018f0000-0000-7000-8000-000000000930.json', bytes);
  const key = createPrivateKey(await readFile(join(provider, 'client.key'))).export({
    format: 'der',
    type: 'pkcs8',
  });
  await replaceSource(`${credential}.pk8`, key);
  const profile = {
    profile_id: 'local-provider-profile',
    profile_version: '1.0.0',
    profile_digest: hash('local-provider-profile'),
    provider_instance_id: 'local-provider-instance',
    provider_release_digest: hash('controlled-provider-release'),
    provider_build_digest: hash('controlled-provider-build'),
    configuration_digest: `sha256:${hash(bytes)}`,
    chain_id: '31337',
    genesis_hash: `sha256:${probe.genesis_hash}`,
    network_id: 'openpc-local',
    tls_credential_identity: source.endpoint.credential_ref,
    tls_credential_fingerprint: `sha256:${hash(client)}`,
    trust_epoch: 1,
    json_rpc_version: '2.0',
    method_data_classes: [{ method: 'eth_call', data_class: 'STATE_CALL' }],
    limits: { max_request_bytes: 65536, max_response_bytes: 65536, max_range: 1, max_batch: 1 },
    maximum_response_classification: 'participant-confidential',
    idempotency: 'IdempotentRead',
    route_plan: 'SingleExact',
    read_retry_budget: 0,
    timeout_budget_millis: 2000,
    corpus_digest: `sha256:${probe.corpus_digest}`,
    lifecycle: 'Qualified',
    evidence_refs: [hash('controlled-external-corpus-source')],
  };
  if (sourceKind === 'state-candidates')
    profile.method_data_classes.push(
      { method: 'eth_getBlockByNumber(false)', data_class: 'BLOCK_HEADER' },
      // FactBridge checks code independently. The indexer profile still exposes
      // only its authored state call and bounded header reads.
      { method: 'eth_getCode', data_class: 'STATE_CALL' },
      // The same controlled endpoint serves the visibility response families.
      // Declaring these inputs does not qualify them; public governance does.
      { method: 'eth_getTransactionByHash', data_class: 'TRANSACTION' },
      { method: 'eth_getTransactionReceipt', data_class: 'RECEIPT' },
      { method: 'eth_getLogs', data_class: 'EVENT_LOG' },
    );
  for (const field of [
    'request_schema_digest',
    'privacy_behavior_digest',
    'failure_behavior_digest',
    'rate_limit_contract_digest',
    'capability_profile_digest',
    'conformance_receipt_digest',
  ])
    profile[field] = hash(`local-${field}`);
  profile.response_schema_digest =
    'sha256:20aaa63d00ada53380a4a64ac15bae6ee849148d6d7a7386a4f2fb6cff43c3c1';
  profile.normalization_rule_digest =
    'sha256:619eba3715fdd2bfec698c78a2e823747a18257652ae5ceecec67ace22d8e2e5';
  if (
    process.env.OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY === '1' ||
    process.env.OPENPC_LOCAL_RUNTIME_CIGL_ONLY === '1'
  ) {
    profile.idempotency = 'GovernedWrite';
    profile.timeout_budget_millis = 5000;
    profile.method_data_classes.push(
      ...[
        ['eth_sendRawTransaction', 'transaction'],
        ['eth_chainId', 'CHAIN_METADATA'],
        ['eth_getBlockByNumber', 'BLOCK_HEADER'],
        ['eth_getTransactionByHash', 'TRANSACTION'],
        ['eth_getTransactionReceipt', 'RECEIPT'],
        ['eth_getCode', 'STATE_CALL'],
        ['eth_getBalance', 'STATE_CALL'],
        ['eth_getTransactionCount', 'STATE_CALL'],
        ['debug_traceCall', 'STATE_CALL'],
        ['debug_traceTransaction', 'TRANSACTION'],
      ].map(([method, data_class]) => ({ method, data_class })),
    );
  }
  profile.method_data_classes.sort((a, b) =>
    a.method < b.method
      ? -1
      : a.method > b.method
        ? 1
        : a.data_class < b.data_class
          ? -1
          : a.data_class > b.data_class
            ? 1
            : 0,
  );
  await replaceSource('profile.json', JSON.stringify(profile));
}
