import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  X509Certificate,
} from 'node:crypto';
import { chmod, lstat, mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { evidenceKeyId } from '../../../packages/security-kernel/src/business-transition/cose.ts';
import { signSecretRecipientProfile } from '../../../packages/security-kernel/src/secret-recipient/profile.ts';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { installInitialSecretRecipient } from '../../../services/identity-service/src/domain/secret-recipient.ts';
import {
  assertEmptyFactCandidateSlice,
  createFactSecretConsumerJourney,
  startFactSecretConsumerPublisher,
} from './fact-secret-consumer-journey.mjs';
import {
  prepareFactSecretOperations,
  parseFactSecretResolutionDescriptor,
  parseFactSecretPublisherCommand,
  createFactSecretPublisherInput,
} from './fact-secret-operations.mjs';

// TEST installer only. No stores, migrations, images or shared services start
// here. The existing runner supplies its real exclusive root and live admitted
// slice. The normal consumer path proves native container startup/restart;
// consumerLifecycle:'process' preserves the separate exec-process proof.
export const factSecretInstallation = Object.freeze({
  image:
    'docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43',
  containerMemoryBytes: 256 * 1024 ** 2,
  publicationMemoryBytes: 64 * 1024 ** 2,
  // Three concurrent capped namespaces, plus the separately mounted tmpfs.
  additionalExternalMemoryBytes: (3 * 256 + 64) * 1024 ** 2,
});
const ownerLabel = 'io.openpc.fixture.owner';
const publicationRoot = '/publication';
const bundleTarget = '/fixture/publisher.mjs';
const reference = 'secret://test-memory-resolver/fact/candidate-reader#v1';
const endpointPath = '/internal/v1/secrets/fact-candidate';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const runCommand = promisify(execFile);
const sha = (bytes) => createHash('sha256').update(bytes).digest();
const digest = (bytes) => `sha256:${sha(bytes).toString('hex')}`;
const failure = () => new Error('Packaged Fact installation failed; private diagnostics withheld');
const privateCauses = new WeakMap();
const poolFailures = new WeakMap();
function emit(status, phase) {
  try {
    process.stdout.write(`FACT_SECRET_INSTALLATION|${status}|${phase}\n`);
  } catch {
    /* Preserve outcome. */
  }
}
function capture(error) {
  const safe = failure();
  privateCauses.set(safe, error);
  return safe;
}
async function bounded(promise, milliseconds = 15000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(failure()), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
async function command(executable, args, options = {}) {
  const result = await runCommand(executable, args, {
    timeout: 30000,
    maxBuffer: 2 * 1024 ** 2,
    ...options,
  });
  return result.stdout.trim();
}
const docker = (...args) => command('docker', args);
const jsonDocker = async (...args) => JSON.parse(await docker(...args));
async function canonical(path, kind = 'file') {
  assert.equal(resolve(path), path);
  assert.equal(await realpath(path), path);
  const stat = await lstat(path);
  assert.ok(kind === 'directory' ? stat.isDirectory() : stat.isFile());
  return stat;
}
async function readSecret(path) {
  const stat = await canonical(path);
  assert.ok(stat.size > 0 && stat.size <= 65536 && (stat.mode & 0o022) === 0);
  return readFile(path);
}
async function newFile(path, contents, mode = 0o444) {
  await writeFile(path, contents, { flag: 'wx', mode });
}
function pool(options) {
  const result = new Pool({
    ...options,
    max: 3,
    connectionTimeoutMillis: 3000,
    query_timeout: 10000,
  });
  // Retain an idle socket failure even if pg subsequently reconnects. It must
  // fail cleanup/acceptance without printing its connection string.
  result.on('error', (error) => {
    if (!poolFailures.has(result)) poolFailures.set(result, error);
  });
  return result;
}
async function endPool(value) {
  await bounded(value.end());
  if (poolFailures.has(value)) throw poolFailures.get(value);
}

function candidateScope(input) {
  assert.deepEqual(Object.keys(input).sort(), ['participantId', 'privacyDomainId']);
  const { participantId, privacyDomainId } = input;
  assert.match(participantId, uuid);
  assert.match(privacyDomainId, uuid);
  return Object.freeze({ participantId, privacyDomainId });
}

// One concrete owner for ordinary installation and test inspection. Connection
// options always come from the admitted topology and its protected secret files.
// Opening this owner proves neither an empty store nor recipient/LOGIN authority.
async function candidateFixture(context, input) {
  const scope = candidateScope(input);
  const live = await topology(context);
  const database = await databaseOptions(context, live.addresses);
  const candidate = pool(database.candidate);
  return { live, database, candidate, ...factSecretCandidatePoolLifetime(candidate, scope) };
}

/** Transport/callback lifetime only, exported for connection-fault regressions.
 * This grants no fixture admission: candidateFixture always checks the actual
 * installer context/topology/credentials first, and runCase still requires the
 * real empty-store preflight. Tests may fault pg connections here without faking
 * any ownership, authorization, grant, business row or successful SQL result.
 */
export function factSecretCandidatePoolLifetime(candidate, input) {
  const scope = candidateScope(input);
  assert.ok(candidate instanceof Pool);
  assert.ok(
    candidate.options.connectionTimeoutMillis > 0 &&
      candidate.options.connectionTimeoutMillis <= 5000,
  );
  assert.ok(candidate.options.query_timeout > 0 && candidate.options.query_timeout <= 10000);
  let closing;
  let uncertain = false;
  let uncertaintyCause;
  const markUncertain = (error) => {
    if (!uncertain) {
      uncertain = true;
      uncertaintyCause = error;
    }
  };
  const close = () => {
    closing ??= (async () => {
      try {
        await endPool(candidate);
      } catch (error) {
        markUncertain(error);
        emit('UNKNOWN', 'candidate-fixture-pool');
        throw uncertaintyCause;
      }
      if (uncertain) throw uncertaintyCause;
    })();
    return closing;
  };
  const assertEmpty = async () => {
    assert.ok(!closing && !uncertain);
    if (poolFailures.has(candidate)) throw poolFailures.get(candidate);
    await assertEmptyFactCandidateSlice(candidate, scope);
    if (poolFailures.has(candidate)) throw poolFailures.get(candidate);
  };
  const read = async (inspect) => {
    assert.ok(!closing && !uncertain && typeof inspect === 'function');
    if (poolFailures.has(candidate)) throw poolFailures.get(candidate);
    const client = await candidate.connect();
    let first,
      result,
      failed = false,
      connectionFailed = false;
    const fail = (error) => {
      if (!failed) {
        failed = true;
        first = error;
      }
    };
    client.on('error', (error) => {
      connectionFailed = true;
      fail(error);
    });
    const query = async (...args) => {
      if (failed) throw first;
      const result = await client.query(...args);
      if (failed) throw first;
      return result;
    };
    try {
      await query('begin isolation level repeatable read read only');
      await query("set local statement_timeout='5s'");
      await query("set local lock_timeout='2s'");
      assert.deepEqual((await query('select current_database() name,current_user role')).rows, [
        { name: 'openpc_candidate_index', role: 'openpc_candidate_index' },
      ]);
      await query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',true)",
        [scope.participantId, scope.privacyDomainId, id()],
      );
      await query('select openpc.assert_request_context(true)');
      if (failed) throw first;
      result = await inspect(client, scope);
      if (poolFailures.has(candidate)) fail(poolFailures.get(candidate));
    } catch (error) {
      fail(error);
    } finally {
      try {
        await client.query('rollback');
        if (connectionFailed) {
          fail(failure());
          markUncertain(first);
          emit('UNKNOWN', 'candidate-fixture-rollback');
        }
      } catch (error) {
        fail(error);
        markUncertain(first);
        emit('UNKNOWN', 'candidate-fixture-rollback');
      }
      try {
        const previouslyFailed = connectionFailed;
        client.release(true);
        if (!previouslyFailed && connectionFailed) {
          fail(failure());
          markUncertain(first);
          emit('UNKNOWN', 'candidate-fixture-release');
        }
      } catch (error) {
        fail(error);
        markUncertain(first);
        emit('UNKNOWN', 'candidate-fixture-release');
      }
    }
    if (failed) throw first;
    return result;
  };
  const borrowed = Object.freeze({ candidatePool: candidate, scope, assertEmpty, read });
  const run = async (inspect) => {
    let first,
      failed = false;
    const fail = (error) => {
      if (!failed) {
        failed = true;
        first = error;
      }
    };
    try {
      assert.ok(!closing && !uncertain && typeof inspect === 'function');
      await inspect(borrowed);
    } catch (error) {
      fail(error);
    } finally {
      try {
        await close();
      } catch (error) {
        emit('UNKNOWN', 'candidate-fixture-cleanup');
        fail(error);
      }
    }
    if (failed) throw first;
  };
  return Object.freeze({ scope, assertEmpty, read, close, run });
}

/** Trusted executable TEST-owner callback, never a product API or DSN input.
 * Pass the ordinary installer's four concrete options and original exact scope.
 * The callback borrows the actual candidate pool only for the existing preflight;
 * use read() for rollback-only inspection, including an original occupied slice.
 * No empty-store gate is skipped by runCase: assertEmpty() remains mandatory there.
 * No LOGIN lease, initial trust, publication, container or business state is made
 * here. Pool lifetime ends with this callback; results/credentials are not returned.
 */
export async function withFactSecretCandidateFixture(options, input, inspect) {
  const scope = candidateScope(input);
  assert.equal(typeof inspect, 'function');
  try {
    const context = await contextFor(options);
    const owner = await candidateFixture(context, scope);
    await owner.run(inspect);
  } catch (error) {
    throw capture(error);
  }
}
const lines = (text) => (text ? text.split('\n') : []);

async function contextFor({
  runRoot,
  compose,
  factImageId,
  publisherBundle,
  consumerLifecycle = 'container',
  operationsOnly = false,
}) {
  assert.ok(['container', 'process'].includes(consumerLifecycle));
  assert.equal(typeof operationsOnly, 'boolean');
  assert.ok(!operationsOnly || consumerLifecycle === 'container');
  const repository = fileURLToPath(new URL('../../../', import.meta.url));
  await canonical(runRoot, 'directory');
  for (const name of ['data', 'secrets', 'evidence'])
    await canonical(join(runRoot, name), 'directory');
  const sentinel = join(runRoot, '.openpc-local-runtime-owner');
  await canonical(sentinel);
  const match = /^openpc-local-runtime:(openpc-local-e2e-[0-9a-f]{12}):([0-9a-f]{64})\n$/u.exec(
    await readFile(sentinel, 'utf8'),
  );
  assert.ok(match && match[1] === `openpc-local-e2e-${match[2].slice(0, 12)}`);
  assert.ok(Array.isArray(compose));
  assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
  const projects = [],
    files = [];
  for (let n = 2; n < compose.length; n += 2) {
    const [flag, value] = compose.slice(n, n + 2);
    assert.ok(typeof value === 'string' && !/[\n\r\0]/u.test(value));
    if (['-p', '--project-name'].includes(flag)) projects.push(value);
    else {
      assert.ok(['-f', '--file'].includes(flag));
      await canonical(value);
      assert.ok(
        value === join(repository, 'deploy/compose/local/compose.yaml') ||
          value.startsWith(`${runRoot}/data/`),
      );
      files.push(value);
    }
  }
  assert.deepEqual(projects, [match[1]]);
  assert.ok(files.includes(join(repository, 'deploy/compose/local/compose.yaml')));
  assert.equal(files.length, new Set(files).size);
  assert.match(factImageId, /^sha256:[0-9a-f]{64}$/u);
  await canonical(publisherBundle);
  assert.ok(
    publisherBundle.startsWith(`${runRoot}/data/fact-secret-bundle.`) &&
      publisherBundle.endsWith('/publisher.mjs'),
  );
  const context = {
    repository,
    runRoot,
    compose,
    factImageId,
    publisherBundle,
    consumerLifecycle,
    operationsOnly,
    project: match[1],
    token: match[2],
  };
  context.shell = join(
    repository,
    'tests/integration/local-runtime/fact-secret-consumer-installation.sh',
  );
  await command('bash', [context.shell, 'guard', runRoot], { cwd: repository });
  const [factImage] = await jsonDocker('image', 'inspect', factImageId);
  assert.equal(factImage.Id, factImageId);
  assert.equal(factImage.Config.Labels?.['io.openpc.image.owner'], 'openpc-r1-local-runtime-v1');
  assert.equal(factImage.Config.Labels?.['io.openpc.image.service'], 'fact-service');
  if (consumerLifecycle === 'container') {
    // Cheap actual image contract check before topology/initial trust/fresh authority.
    assert.deepEqual(factImage.Config.Entrypoint, ['/usr/local/bin/openpc-fact-local-runtime']);
    assert.deepEqual(factImage.Config.Cmd ?? [], []);
  }
  const [nodeImage] = await jsonDocker('image', 'inspect', factSecretInstallation.image);
  assert.match(nodeImage.Id, /^sha256:[0-9a-f]{64}$/u);
  context.nodeImageId = nodeImage.Id;
  // A partially attempted installation must be reconciled, never replayed with
  // new UUIDs in the same root. These are actual fixture inputs, not a ledger.
  assert.ok(
    !(await readdir(join(runRoot, 'data'))).some((name) => /^fact-secret-[0-9a-f]{8}-/u.test(name)),
  );
  assert.equal(
    await docker(
      'ps',
      '-aq',
      '--filter',
      'label=io.openpc.fixture=fact-secret-consumer',
      '--filter',
      `label=${ownerLabel}=${context.token}`,
    ),
    '',
  );
  assert.equal(
    await docker(
      'volume',
      'ls',
      '-q',
      '--filter',
      'label=io.openpc.fixture=fact-secret-consumer',
      '--filter',
      `label=${ownerLabel}=${context.token}`,
    ),
    '',
  );
  return context;
}

async function topology(context) {
  await command('bash', [context.shell, 'guard', context.runRoot], { cwd: context.repository });
  const ids = lines(
    await docker(
      'ps',
      '-q',
      '--no-trunc',
      '--filter',
      `label=com.docker.compose.project=${context.project}`,
    ),
  );
  assert.ok(ids.length > 0);
  const containers = await jsonDocker('inspect', ...ids);
  let bytes = factSecretInstallation.additionalExternalMemoryBytes;
  const byService = new Map();
  for (const container of containers) {
    assert.equal(container.Config.Labels?.['com.docker.compose.project'], context.project);
    const service = container.Config.Labels['com.docker.compose.service'];
    assert.ok(
      [
        'control-pg',
        'fact-pg',
        'candidate-index-pg',
        'identity-service',
        'oidc-emulator',
        'workload-issuer',
      ].includes(service),
      'The isolated secret-consumer slice must not contain business writers',
    );
    assert.ok(!byService.has(service));
    byService.set(service, container);
    assert.ok(container.State.Running && !container.State.OOMKilled);
    assert.ok(Number.isSafeInteger(container.HostConfig.Memory) && container.HostConfig.Memory > 0);
    bytes += container.HostConfig.Memory;
  }
  assert.ok(!byService.has('fact-service'), 'Ordinary Fact must not compete for the reader lease');
  const cap = Number(process.env.OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB) * 1024;
  assert.ok(Number.isSafeInteger(cap) && cap >= 9 * 1024 ** 3 && bytes <= cap);
  for (const service of ['control-pg', 'fact-pg', 'candidate-index-pg', 'identity-service']) {
    const value = byService.get(service);
    assert.ok(value && value.State.Health?.Status === 'healthy');
    assert.equal(Object.keys(value.NetworkSettings.Networks).length, 1);
  }
  const network = Object.keys(byService.get('identity-service').NetworkSettings.Networks)[0];
  const [description] = await jsonDocker('network', 'inspect', network);
  assert.equal(description.Labels?.['com.docker.compose.project'], context.project);
  // A container from another project on this network would escape the Compose
  // service allowlist. Prove the actual dedicated slice before opening its pools.
  assert.deepEqual(
    Object.keys(description.Containers ?? {}).sort(),
    containers.map((container) => container.Id).sort(),
  );
  const addresses = {};
  for (const service of ['control-pg', 'fact-pg', 'candidate-index-pg', 'identity-service']) {
    addresses[service] = byService.get(service).NetworkSettings.Networks[network]?.IPAddress;
    assert.equal(isIP(addresses[service]), 4);
  }
  emit('OBSERVED', `resource-peak-${bytes}-bytes`);
  const gateways = (description.IPAM?.Config ?? [])
    .map((v) => v.Gateway)
    .filter((v) => isIP(v) === 4);
  return {
    network,
    networkId: description.Id,
    // The host-observer path requires one concrete gateway. Keep this optional
    // for the original C1 path; its own network contract is unchanged.
    gateway: gateways.length === 1 ? gateways[0] : undefined,
    addresses,
    identity: byService.get('identity-service'),
  };
}

async function databaseOptions(context, addresses) {
  const credentials = {};
  for (const name of [
    'control_pg',
    'candidate_index_pg',
    'identity_runtime_db',
    'fact_runtime_db',
    'fact_bridge_reader_db',
  ]) {
    const bytes = await readSecret(join(context.runRoot, 'secrets', `${name}_password.txt`));
    try {
      const value = bytes.toString().trim();
      assert.match(value, /^[0-9a-f]{64}$/u);
      credentials[name] = value;
    } finally {
      bytes.fill(0);
    }
  }
  const connection = (host, database, user, password) => ({
    host,
    port: 5432,
    database,
    user,
    password,
  });
  return {
    control: connection(
      addresses['control-pg'],
      'openpc_control',
      'openpc_control',
      credentials.control_pg,
    ),
    candidate: connection(
      addresses['candidate-index-pg'],
      'openpc_candidate_index',
      'openpc_candidate_index',
      credentials.candidate_index_pg,
    ),
    facts: connection(
      addresses['fact-pg'],
      'openpc_facts',
      'openpc_fact_runtime',
      credentials.fact_runtime_db,
    ),
    identity: connection(
      addresses['control-pg'],
      'openpc_control',
      'openpc_identity_runtime',
      credentials.identity_runtime_db,
    ),
    readerPassword: credentials.fact_bridge_reader_db,
  };
}

async function certificates(context, state, live) {
  const secrets = join(context.runRoot, 'secrets');
  const caPath = join(secrets, 'identity_mtls_ca.pem');
  const caKeyPath = join(secrets, 'identity_mtls_ca_key.pem');
  const ca = await readSecret(caPath),
    caKey = await readSecret(caKeyPath);
  const parsedCa = new X509Certificate(ca);
  try {
    assert.ok(parsedCa.ca && parsedCa.checkPrivateKey(createPrivateKey(caKey)));
  } finally {
    caKey.fill(0);
  }
  // Compare real mounted trust/public material, not a caller's ready flag.
  for (const [host, mounted] of [
    ['identity_mtls_ca.pem', '/run/secrets/identity_mtls_ca'],
    ['identity_mtls_server_cert.pem', '/run/secrets/identity_mtls_server_cert'],
  ]) {
    const actual = new X509Certificate(await docker('exec', live.identity.Id, 'cat', mounted));
    assert.deepEqual(actual.raw, new X509Certificate(await readSecret(join(secrets, host))).raw);
  }
  const identityKey = await readSecret(join(secrets, 'identity_runtime_signing_public_key.der'));
  const mountedKey = await runCommand(
    'docker',
    ['exec', live.identity.Id, 'cat', '/run/secrets/identity_runtime_signing_public_key'],
    { encoding: 'buffer', timeout: 10000, maxBuffer: 65536 },
  );
  assert.deepEqual(mountedKey.stdout, identityKey);
  const uriSan = `urn:openpc:participant:${state.participantId}:workload:${state.workloadId}`;
  const serverName = `secret-${state.caseId}.openpc.test`;
  for (const [name, usage, san] of [
    ['client', 'clientAuth', `URI:${uriSan}`],
    ['server', 'serverAuth', `DNS:${serverName}`],
    ...(state.operationsCause
      ? [['observer', 'serverAuth', `DNS:observer-${state.caseId}.openpc.test`]]
      : []),
  ]) {
    const key = join(state.secretRoot, `${name}.key`),
      csr = join(state.secretRoot, `${name}.csr`);
    const extensions = join(state.secretRoot, `${name}.ext`);
    await newFile(
      extensions,
      `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=${usage}\nsubjectAltName=${san}\n`,
      0o400,
    );
    await command('openssl', [
      'req',
      '-new',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-subj',
      `/CN=${name === 'server' ? serverName : 'OpenPC local Fact workload'}`,
      '-keyout',
      key,
      '-out',
      csr,
    ]);
    await chmod(key, 0o400);
    await command('openssl', [
      'x509',
      '-req',
      '-in',
      csr,
      '-CA',
      caPath,
      '-CAkey',
      caKeyPath,
      '-set_serial',
      `0x${randomBytes(16).toString('hex')}`,
      '-days',
      '1',
      '-extfile',
      extensions,
      '-out',
      join(state.secretRoot, `${name}.pem`),
    ]);
    await chmod(join(state.secretRoot, `${name}.pem`), 0o400);
  }
  const certificate = await readSecret(join(state.secretRoot, 'client.pem'));
  const privateKey = await readSecret(join(state.secretRoot, 'client.key'));
  const serverCertificate = await readSecret(join(state.secretRoot, 'server.pem'));
  const serverKey = await readSecret(join(state.secretRoot, 'server.key'));
  const parsed = new X509Certificate(certificate),
    server = new X509Certificate(serverCertificate);
  assert.ok(parsed.verify(parsedCa.publicKey) && server.verify(parsedCa.publicKey));
  assert.ok(
    parsed.checkPrivateKey(createPrivateKey(privateKey)) &&
      server.checkPrivateKey(createPrivateKey(serverKey)),
  );
  assert.equal(server.checkHost(serverName), serverName);
  assert.ok(parsed.subjectAltName.includes(`URI:${uriSan}`));
  state.tls = {
    ca,
    certificate,
    privateKey,
    serverCertificate,
    serverKey,
    parsed,
    parsedCa,
    server,
  };
  if (state.operationsCause) {
    state.tls.observerCertificate = await readSecret(join(state.secretRoot, 'observer.pem'));
    state.tls.observerKey = await readSecret(join(state.secretRoot, 'observer.key'));
    const observer = new X509Certificate(state.tls.observerCertificate);
    assert.ok(
      observer.verify(parsedCa.publicKey) &&
        observer.checkPrivateKey(createPrivateKey(state.tls.observerKey)),
    );
    assert.equal(
      observer.checkHost(`observer-${state.caseId}.openpc.test`),
      `observer-${state.caseId}.openpc.test`,
    );
  }
  state.uriSan = uriSan;
  state.serverName = serverName;
}

async function initialWorkload(admin, state) {
  const client = await admin.connect();
  try {
    await client.query('begin');
    // The established initial-trust fixture only: no decisions, activation,
    // authorization result, publication or intermediate business state.
    await client.query(
      "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Packaged Fact initial trust','ACTIVE',1)",
      [state.participantId],
    );
    await client.query(
      "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Packaged Fact initial trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
      [state.privacyDomainId, state.participantId],
    );
    await client.query(
      'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
      [state.participantId, state.privacyDomainId],
    );
    await client.query(
      "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Packaged Fact initial trust','ACTIVE',1)",
      [state.principalId, state.participantId],
    );
    const spki = state.tls.parsed.publicKey.export({ format: 'der', type: 'spki' });
    await client.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS','local-evidence-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
      [
        state.credentialId,
        state.participantId,
        state.principalId,
        state.uriSan,
        `urn:openpc:workload:${state.workloadId}`,
        sha(spki),
        spki,
        sha(state.tls.parsed.raw),
        new Date(state.tls.parsed.validFrom),
        new Date(state.tls.parsed.validTo),
      ],
    );
    await client.query('commit');
  } catch (error) {
    await client.query('rollback').catch(() => {
      state.uncertain = true;
      emit('UNKNOWN', 'initial-trust-rollback');
    });
    throw error;
  } finally {
    client.release();
  }
}

function labels(context, state) {
  return {
    'io.openpc.fixture': 'fact-secret-consumer',
    [ownerLabel]: context.token,
    'io.openpc.fixture.project': context.project,
    'io.openpc.fixture.case': state.caseId,
  };
}
function assertLabels(actual, context, state) {
  for (const [key, value] of Object.entries(labels(context, state)))
    assert.equal(actual?.[key], value);
  assertFactSecretContainerLabelIsolation(actual);
}

const composeImageLabels = [
  'com.docker.compose.project',
  'com.docker.compose.service',
  'com.docker.compose.version',
];
/** Docker inherits image labels. Explicit empty overrides keep these separately
 * owned namespaces outside every project/service selector used by Compose. */
export function factSecretContainerLabelOverrides() {
  return composeImageLabels.flatMap((name) => ['--label', `${name}=`]);
}
export function assertFactSecretContainerLabelIsolation(actual) {
  for (const name of composeImageLabels)
    assert.ok(actual?.[name] === undefined || actual[name] === '');
}

/** All containers must be checked for file-bind users, including stopped and
 * foreign containers. Batch bounded metadata only; never collect their env or
 * command secrets into one unbounded inspect response. A partial read is UNKNOWN. */
export async function inspectFactSecretContainerMounts(run = docker) {
  const ids = lines(await run('ps', '-aq', '--no-trunc'));
  assert.equal(new Set(ids).size, ids.length);
  for (const id of ids) assert.match(id, /^[0-9a-f]{64}$/u);
  const result = [];
  const format =
    '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"Mounts":{{json .Mounts}},"Config":{"Labels":{{json .Config.Labels}}}}';
  for (let offset = 0; offset < ids.length; offset += 32) {
    const batch = ids.slice(offset, offset + 32);
    const rows = lines(await run('inspect', '--format', format, ...batch)).map((row) =>
      JSON.parse(row),
    );
    assert.deepEqual(rows.map((row) => row.Id).sort(), [...batch].sort());
    for (const row of rows) {
      assert.equal(typeof row.Name, 'string');
      assert.match(row.Image, /^sha256:[0-9a-f]{64}$/u);
      assert.ok(Array.isArray(row.Mounts));
      result.push(row);
    }
  }
  return result;
}
const mount = (source, target, readOnly = true, propagation = 'rprivate') => {
  assert.ok(['rprivate', 'rslave'].includes(propagation));
  assert.ok(!/[\n\r\0,]/u.test(source + target));
  return [
    '--mount',
    `type=bind,src=${source},dst=${target},bind-propagation=${propagation}${readOnly ? ',readonly' : ''}`,
  ];
};
export { mount as factSecretBindMount };
const configNames = [
  'deployment.json',
  'secret-recipient.json',
  'root.der',
  'client.der',
  'client.pk8',
  'identity.der',
  'control-url',
];
const factSecretNames = [
  'fact_runtime_db_password',
  'fact_capability_secret',
  'fact_signing_secret',
  'fact_internal_token',
];

async function namespace(context, state, kind, bind) {
  const name = `openpc-fact-secret-${state.caseId}-${kind}`;
  const record = {
    name,
    kind,
    imageId: kind === 'publisher' ? context.nodeImageId : context.factImageId,
  };
  state.containers.push(record); // Intent survives a lost create/start reply.
  const args = [
    'create',
    '--name',
    name,
    '--platform',
    'linux/amd64',
    '--network',
    state.live.network,
    '--user',
    '65532:65532',
    '--read-only',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--memory',
    '256m',
    '--memory-swap',
    '256m',
    '--cpus',
    '1',
    '--pids-limit',
    '128',
    '--shm-size',
    '16m',
    '--restart',
    'no',
    '--tmpfs',
    '/tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700',
  ];
  for (const [key, value] of Object.entries(labels(context, state)))
    args.push('--label', `${key}=${value}`);
  args.push(...factSecretContainerLabelOverrides());
  const config = join(state.dataRoot, 'fact-bridge/config');
  if (kind === 'consumer') {
    for (const filename of configNames)
      args.push(...mount(join(config, filename), `/fact-bridge/${filename}`));
    assert.deepEqual(Object.keys(bind).sort(), ['readOnly', 'source', 'target', 'type']);
    assert.equal(bind.type, 'bind');
    assert.equal(bind.readOnly, true);
    assert.equal(bind.target, '/fact-bridge/candidate-url');
    // Docker requires slave propagation for a file beneath its volume root.
    // This exact read-only regular-file bind cannot propagate mounts to the host.
    args.push(...mount(bind.source, bind.target, true, 'rslave'));
  } else args.push(...mount(config, '/fact-bridge'));
  if (kind === 'publisher') {
    args.push(
      '--mount',
      `type=volume,src=${state.volumeName},dst=${publicationRoot},volume-nocopy`,
      ...mount(context.publisherBundle, bundleTarget),
      '--entrypoint',
      'node',
      factSecretInstallation.image,
      '-e',
      'if(process.getuid()!==65532||process.getgid()!==65532)process.exit(96);setInterval(()=>{},1000)',
    );
  } else {
    const env = {
      OPENPC_LOCAL_RUNTIME: '1',
      OPENPC_FACT_BRIDGE_CONFIGURATION_FILE: '/fact-bridge/deployment.json',
      OPENPC_LOCAL_RUNTIME_FACT_SECRET_RECIPIENT_CONFIG: '/fact-bridge/secret-recipient.json',
      OPENPC_FACT_DATABASE_HOST: 'fact-pg',
      OPENPC_FACT_DATABASE_PORT: '5432',
      OPENPC_FACT_DATABASE_NAME: 'openpc_facts',
      OPENPC_FACT_DATABASE_USER: 'openpc_fact_runtime',
      OPENPC_FACT_DATABASE_PASSWORD_FILE: '/run/secrets/fact_runtime_db_password',
      OPENPC_FACT_CAPABILITY_SECRET_FILE: '/run/secrets/fact_capability_secret',
      OPENPC_FACT_SIGNING_SECRET_FILE: '/run/secrets/fact_signing_secret',
      OPENPC_FACT_INTERNAL_TOKEN_FILE: '/run/secrets/fact_internal_token',
      OPENPC_FACT_LISTEN: '0.0.0.0:8081',
    };
    for (const [key, value] of Object.entries(env)) args.push('-e', `${key}=${value}`);
    for (const name of factSecretNames) {
      const source = join(context.runRoot, 'secrets', `${name}.txt`);
      const stat = await canonical(source);
      assert.ok(
        (stat.mode & 0o004) !== 0 && (stat.mode & 0o022) === 0,
        'Installed secret must be readable by workload UID without changing its owner',
      );
      args.push(...mount(source, `/run/secrets/${name}`));
    }
    args.push(
      ...mount(join(state.dataRoot, 'fact-bridge/connections'), '/fact-connections', false),
      ...mount(join(state.dataRoot, 'fact-bridge/artifacts'), '/fact-artifacts', false),
      ...mount(join(state.dataRoot, 'provider-sources'), '/provider-sources'),
    );
    if (kind === 'consumer' && context.consumerLifecycle === 'container')
      args.push(context.factImageId);
    else args.push('--entrypoint', '/bin/sleep', context.factImageId, 'infinity');
  }
  record.id = await docker(...args);
  assert.match(record.id, /^[0-9a-f]{64}$/u);
  if (kind === 'consumer' && context.consumerLifecycle === 'container') {
    // The observer verifies the complete CREATED topology, then owns actual
    // start/restart/denied-start. No server runs through docker exec in this mode.
    const [created] = await jsonDocker('inspect', record.id);
    assertLabels(created.Config.Labels, context, state);
    assert.equal(created.Image, record.imageId);
    assert.equal(created.State.Status, 'created');
    assert.equal(created.State.Running, false);
    assert.deepEqual(created.Config.Entrypoint, ['/usr/local/bin/openpc-fact-local-runtime']);
    assert.deepEqual(created.Config.Cmd ?? [], []);
    return record;
  }
  await docker('start', record.id);
  const [current] = await jsonDocker('inspect', record.id);
  assertLabels(current.Config.Labels, context, state);
  assert.equal(current.Image, record.imageId);
  assert.ok(current.State.Running && !current.State.OOMKilled);
  record.startedAt = current.State.StartedAt;
  record.address = current.NetworkSettings.Networks[state.live.network]?.IPAddress;
  assert.equal(isIP(record.address), 4);
  return record;
}

async function allocate(context, state) {
  state.volumeName = `openpc-fact-secret-${state.caseId}`;
  state.volumeAttempted = true;
  const args = ['volume', 'create', '--driver', 'local'];
  for (const [key, value] of Object.entries(labels(context, state)))
    args.push('--label', `${key}=${value}`);
  args.push(
    '--opt',
    'type=tmpfs',
    '--opt',
    'device=tmpfs',
    '--opt',
    'o=size=64m,nosuid,nodev,noexec,uid=65532,gid=65532,mode=0700',
    state.volumeName,
  );
  assert.equal(await docker(...args), state.volumeName);
  state.publisher = await namespace(context, state, 'publisher');
  state.preparer = await namespace(context, state, 'preparer');
}

async function installBinding(context, state, admin) {
  const current = (
    await admin.query(
      `select credential_epoch::text epoch,valid_from,valid_until,
    floor(extract(epoch from clock_timestamp())*1000)::text now
    from control.credential where credential_id=$1 and participant_id=$2 and principal_id=$3
    and kind='WORKLOAD_MTLS' and state='ACTIVE' and public_key_digest=$4 and secret_fingerprint=$5`,
      [
        state.credentialId,
        state.participantId,
        state.principalId,
        sha(state.tls.parsed.publicKey.export({ format: 'der', type: 'spki' })),
        sha(state.tls.parsed.raw),
      ],
    )
  ).rows;
  assert.equal(current.length, 1);
  const now = Number(current[0].now);
  assert.ok(Number.isSafeInteger(now) && Math.abs(now - Date.now()) < 1000);
  assert.ok(current[0].valid_from.getTime() <= now);
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = issuer.publicKey.export({ format: 'der', type: 'spki' });
  const privateKey = issuer.privateKey.export({ format: 'der', type: 'pkcs8' });
  // Fresh packaged fixtures only. Revocation retains the established ten-minute
  // fixture ceiling; the independent expiry case uses one minute (driver ceiling
  // two minutes). No existing grant/certificate or component timer is extended.
  const validUntilMs = Math.min(
    now + (state.mode === 'consumer-expiry' ? 60000 : 600000),
    current[0].valid_until.getTime(),
    Date.parse(state.tls.parsedCa.validTo),
    Date.parse(state.tls.server.validTo),
  );
  assert.ok(validUntilMs - now >= 15000);
  const profile = {
    participantId: state.participantId,
    privacyDomainId: state.privacyDomainId,
    principalId: state.principalId,
    workloadCredentialId: state.credentialId,
    workloadCredentialEpoch: current[0].epoch,
    environmentId: state.operations?.environmentId ?? 'local-test',
    installationDigest: digest(Buffer.from(`${context.project}:${state.caseId}`)),
    generation: '1',
    consumerId: 'LS-FACT-BRIDGE',
    secretClass: 'SECRET-DB-CREDENTIAL',
    purpose: 'POSTGRES_CONNECT',
    store: 'STORE-CANDIDATE-INDEX-PG',
    reference,
    version: 'v1',
    validFromMs: now,
    validUntilMs,
    issuerKeyId: evidenceKeyId(spki),
  };
  let signed;
  try {
    signed = signSecretRecipientProfile(privateKey, spki, profile);
  } finally {
    privateKey.fill(0);
  }
  const pins = {
    issuerSpkiDer: spki,
    signedBindingDigest: digest(signed.cose),
    installationDigest: profile.installationDigest,
    environmentId: profile.environmentId,
    generation: profile.generation,
    participantId: profile.participantId,
    privacyDomainId: profile.privacyDomainId,
    principalId: profile.principalId,
    workloadCredentialId: profile.workloadCredentialId,
    workloadCredentialEpoch: profile.workloadCredentialEpoch,
  };
  const client = await admin.connect();
  try {
    await client.query('begin');
    await installInitialSecretRecipient(
      client,
      pins,
      signed.payload,
      signed.cose,
      'local-packaged-fact-initial-trust',
    );
    await client.query('commit');
  } catch (error) {
    await client.query('rollback').catch(() => {
      state.uncertain = true;
      emit('UNKNOWN', 'recipient-install-rollback');
    });
    throw error;
  } finally {
    client.release();
  }
  const address = state.publisher.address;
  const recipient = {
    endpoint: {
      endpoint_id: 'fact-candidate-secret',
      normalized_uri: `https://${state.serverName}:3443${endpointPath}`,
      reference_identity: state.serverName,
      port: 3443,
      path: endpointPath,
      dns_policy_ref: 'local-exact-address-v1',
      tls_policy_ref: 'local-mtls-v1',
      credential_ref: `urn:openpc:workload:${state.workloadId}`,
      egress_policy_ref: 'local-exact-private-address-v1',
      endpoint_generation: 1,
    },
    addresses: [address],
    allowed_ranges: [`${address}/32`],
    private_network_ranges: [`${address}/32`],
    server_certificate_digest: sha(state.tls.server.raw).toString('hex'),
    ...(state.operations ? { operations_observer: state.operations.native } : {}),
    signed_binding_digest: pins.signedBindingDigest,
    installation_digest: pins.installationDigest,
    generation: pins.generation,
    workload_credential_id: pins.workloadCredentialId,
    workload_credential_epoch: pins.workloadCredentialEpoch,
    reference,
    version: 'v1',
  };
  await newFile(join(state.dataRoot, 'recipient.json'), JSON.stringify(recipient));
  await command(
    'bash',
    [
      context.shell,
      'render',
      context.runRoot,
      state.dataRoot,
      state.workloadId,
      state.participantId,
      state.privacyDomainId,
      join(state.secretRoot, 'client.pem'),
      join(state.secretRoot, 'client.key'),
      join(state.dataRoot, 'recipient.json'),
      JSON.stringify(context.compose),
    ],
    { cwd: context.repository },
  );
  assert.ok(validUntilMs - Date.now() >= 15000);
  const reader = new URL(
    `postgresql://openpc_fact_bridge_reader@${state.live.addresses['candidate-index-pg']}:5432/openpc_candidate_index`,
  );
  reader.password = state.database.readerPassword;
  const material = new URL(reader);
  material.hostname = 'candidate-index-pg';
  return {
    mode: state.mode,
    ...(state.operations ? { operations: state.operations.native } : {}),
    pins: { ...pins, issuerSpkiDer: spki.toString('base64') },
    reference,
    validUntilMs,
    candidateUrl: reader.href,
    material: Buffer.from(material.href).toString('base64'),
    tls: {
      certificate: state.tls.certificate.toString('base64'),
      privateKey: state.tls.privateKey.toString('base64'),
      server: {
        ca: state.tls.ca.toString('base64'),
        certificate: state.tls.serverCertificate.toString('base64'),
        privateKey: state.tls.serverKey.toString('base64'),
      },
    },
  };
}

async function publisherProcess(context, state, input) {
  // Import the bundle as a library: esbuild gives imported modules the bundle's
  // import.meta.url too. Clearing argv[1] prevents their standalone CLI guards
  // (including the staged driver's deliberate BLOCKED guard) from dispatching.
  const child = spawn(
    'docker',
    [
      'exec',
      '-i',
      '--user',
      '65532:65532',
      state.publisher.id,
      'node',
      '--input-type=module',
      '-e',
      `process.argv[1]=undefined;const m=await import('file://${bundleTarget}');await m.runFactSecretConsumerInstallationPublisher();`,
    ],
    { stdio: ['pipe', 'pipe', 'pipe'] },
  );
  const record = { child, output: '', invalid: false, result: undefined };
  state.publisherProcess = record;
  record.done = new Promise((resolveDone) => {
    child.once('error', () => {
      record.result = { code: null };
      resolveDone(record.result);
    });
    child.once('close', (code, signal) => {
      record.result = { code, signal };
      resolveDone(record.result);
    });
  });
  child.stdin.on('error', () => {
    record.invalid = true;
  });
  child.stderr.on('data', () => {
    record.invalid = true;
  }); // Never forward raw child diagnostics.
  child.stdout.on('data', (bytes) => {
    if (record.output.length + bytes.length > 16384) record.invalid = true;
    else record.output += bytes.toString();
  });
  child.stdin.write(
    `${JSON.stringify({ input, publicationRoot, runtime: state.database.identity, candidate: state.database.candidate })}\n`,
  );
  const end = performance.now() + 10000;
  while (!record.output.includes('FACT_SECRET_PUBLISHER|LISTENING\n')) {
    assert.ok(!record.invalid && record.result === undefined && performance.now() < end);
    await delay(25);
  }
  const match = /^FACT_SECRET_PUBLISHER\|PID\|([1-9][0-9]*)\|([1-9][0-9]*)\n/u.exec(record.output);
  assert.ok(match && Number(match[1]) > 1);
  record.pid = match[1];
  record.start = match[2];
  if (state.operations) {
    const descriptor = /^FACT_SECRET_PUBLISHER\|DESCRIPTOR\|([^\n]+)\n/mu.exec(record.output);
    assert.ok(descriptor);
    await state.operations.attachPublisher(
      parseFactSecretResolutionDescriptor(JSON.parse(descriptor[1]), reference),
    );
  }
  // LISTENING is only process coordination. The driver still executes real
  // denied requests and authenticated prepare; no startup authority is inferred.
}

async function publisherCommand(state, operation) {
  assert.ok(state.operations && ['arm', 'release', 'abort'].includes(operation));
  const record = state.publisherProcess,
    associationId = state.operations.associationId;
  assert.ok(record && !record.invalid && record.result === undefined);
  record.child.stdin.write(`${operation} ${associationId}\n`);
  const expected = `FACT_SECRET_PUBLISHER|GATE|${operation}|${associationId}\n`;
  const end = performance.now() + 2000;
  while (!record.output.includes(expected)) {
    assert.ok(!record.invalid && record.result === undefined && performance.now() < end);
    await delay(10);
  }
}

async function closePublisher(state) {
  const record = state.publisherProcess;
  if (!record) return;
  if (record.result === undefined) record.child.stdin.end('close\n');
  const result = await bounded(record.done);
  assert.equal(result.code, 0);
  assert.equal(record.invalid, false);
  assert.match(
    record.output,
    /^FACT_SECRET_PUBLISHER\|PID\|[1-9][0-9]*\|[1-9][0-9]*\n(?:FACT_SECRET_PUBLISHER\|DESCRIPTOR\|[^\n]+\n)?FACT_SECRET_PUBLISHER\|LISTENING\n(?:FACT_SECRET_PUBLISHER\|GATE\|(?:arm|release|abort)\|[0-9a-f-]+\n)*FACT_SECRET_PUBLISHER\|CLOSED\n$/u,
  );
  // Closing the Docker client is not proof of stopping its remote process.
  const observed = await docker(
    'exec',
    state.publisher.id,
    'node',
    '-e',
    'const f=require("node:fs");try{const s=f.readFileSync(`/proc/${process.argv[1]}/stat`,"utf8").split(") ")[1].split(" ");if(s[19]===process.argv[2]&&s[0]!=="Z")process.exit(96)}catch(e){if(e.code!=="ENOENT")throw e}',
    record.pid,
    record.start,
  );
  assert.equal(observed, '');
}

async function removeNamespaces(context, state) {
  let safe = true;
  if (state.volumeAttempted) {
    try {
      const [volume] = await jsonDocker('volume', 'inspect', state.volumeName);
      assertLabels(volume.Labels, context, state);
      const all = await inspectFactSecretContainerMounts();
      for (const container of all) {
        if (
          !container.Mounts.some(
            (m) =>
              m.Name === state.volumeName ||
              m.Source === volume.Mountpoint ||
              m.Source?.startsWith(`${volume.Mountpoint}/`),
          )
        )
          continue;
        const owned = state.containers.find((record) => container.Name === `/${record.name}`);
        assert.ok(owned);
        assertLabels(container.Config.Labels, context, state);
        assert.equal(container.Image, owned.imageId);
        if (owned.id) assert.equal(container.Id, owned.id);
      }
    } catch {
      emit('UNKNOWN', 'retained-volume-consumers');
      return false;
    }
  }
  for (const record of [...state.containers].reverse()) {
    try {
      // Even an ambiguous create reply is reconciled by its unique exact name,
      // labels and image before removal; inspection failure means retain.
      const [current] = await jsonDocker('inspect', record.id ?? record.name);
      assert.equal(current.Name, `/${record.name}`);
      assertLabels(current.Config.Labels, context, state);
      assert.equal(current.Image, record.imageId);
      if (record.id) assert.equal(current.Id, record.id);
      if (record.startedAt) assert.equal(current.State.StartedAt, record.startedAt);
      if (current.State.Running) await docker('stop', '--time', '5', current.Id);
      await docker('rm', current.Id);
    } catch {
      safe = false;
      emit('UNKNOWN', `cleanup-${record.kind}`);
    }
  }
  if (state.volumeAttempted && safe) {
    try {
      const [volume] = await jsonDocker('volume', 'inspect', state.volumeName);
      assertLabels(volume.Labels, context, state);
      assert.equal(volume.Name, state.volumeName);
      assert.equal(volume.Driver, 'local');
      assert.deepEqual(volume.Options, {
        type: 'tmpfs',
        device: 'tmpfs',
        o: 'size=64m,nosuid,nodev,noexec,uid=65532,gid=65532,mode=0700',
      });
      // File-level bind users need not appear in Docker's named-volume filter.
      const users = await inspectFactSecretContainerMounts();
      assert.ok(
        users.every((container) =>
          container.Mounts.every(
            (m) =>
              m.Name !== state.volumeName &&
              m.Source !== volume.Mountpoint &&
              !m.Source?.startsWith(`${volume.Mountpoint}/`),
          ),
        ),
      );
      await docker('volume', 'rm', state.volumeName);
    } catch {
      safe = false;
      emit('UNKNOWN', 'cleanup-volume');
    }
  } else if (state.volumeAttempted) emit('UNKNOWN', 'retained-volume');
  return safe;
}

async function runCase(context, mode, operationsCause) {
  const caseId = id();
  const state = {
    caseId,
    mode,
    operationsCause,
    participantId: id(),
    privacyDomainId: id(),
    principalId: id(),
    credentialId: id(),
    workloadId: id(),
    dataRoot: join(context.runRoot, 'data', `fact-secret-${caseId}`),
    secretRoot: join(context.runRoot, 'secrets', `fact-secret-${caseId}`),
    containers: [],
    pools: [],
  };
  let phase = 'prepare-installation';
  let first,
    failed = false,
    cleanupKnown = true,
    journey,
    input,
    candidateOwner;
  const fail = (error) => {
    if (!failed) {
      failed = true;
      first = capture(error);
    }
  };
  try {
    for (const value of [
      caseId,
      state.participantId,
      state.privacyDomainId,
      state.principalId,
      state.credentialId,
      state.workloadId,
    ])
      assert.match(value, uuid);
    candidateOwner = await candidateFixture(context, {
      participantId: state.participantId,
      privacyDomainId: state.privacyDomainId,
    });
    state.live = candidateOwner.live;
    state.database = candidateOwner.database;
    const admin = pool(state.database.control),
      candidate = candidateOwner.candidate,
      facts = pool(state.database.facts);
    state.pools.push(admin, facts);
    assert.deepEqual((await admin.query('select current_database() name,current_user role')).rows, [
      { name: 'openpc_control', role: 'openpc_control' },
    ]);
    await candidateOwner.assertEmpty();
    assert.deepEqual((await facts.query('select current_database() name,current_user role')).rows, [
      { name: 'openpc_facts', role: 'openpc_fact_runtime' },
    ]);
    await mkdir(state.dataRoot, { mode: 0o755 });
    await mkdir(state.secretRoot, { mode: 0o700 });
    await mkdir(join(state.dataRoot, 'fact-bridge'), { mode: 0o755 });
    for (const [path, permissions] of [
      ['fact-bridge/config', 0o755],
      ['fact-bridge/connections', 0o777],
      ['fact-bridge/artifacts', 0o777],
      ['provider-sources', 0o755],
    ]) {
      const target = join(state.dataRoot, path);
      await mkdir(target, { mode: permissions });
      await chmod(target, permissions);
    }
    await certificates(context, state, state.live);
    phase = 'initial-workload';
    await initialWorkload(admin, state);
    if (operationsCause) {
      assert.equal(context.consumerLifecycle, 'container');
      const runtime = pool(state.database.identity);
      state.pools.push(runtime);
      state.operations = await prepareFactSecretOperations({
        repository: context.repository,
        scope: { participantId: state.participantId, privacyDomainId: state.privacyDomainId },
        reference,
        controlPool: admin,
        runtimePool: runtime,
        candidateAdminPool: candidate,
        workloadId: state.workloadId,
        gateway: state.live.gateway,
        networkId: state.live.networkId,
        imageId: context.factImageId,
        ownerToken: context.token,
        tls: {
          ca: state.tls.ca,
          certificate: state.tls.observerCertificate,
          privateKey: state.tls.observerKey,
        },
        serverName: `observer-${state.caseId}.openpc.test`,
      });
    }
    phase = 'allocate-namespaces';
    await allocate(context, state);
    const started = performance.now();
    phase = 'install-recipient';
    input = await installBinding(context, state, admin);
    phase = 'start-publisher';
    await publisherProcess(context, state, input);
    phase = 'construct-journey';
    state.journeyAttempted = true;
    journey = await createFactSecretConsumerJourney(input, {
      controlAdminPool: admin,
      candidateAdminPool: candidate,
      factPool: facts,
      owner: { label: ownerLabel, value: context.token },
      publisher: { containerId: state.publisher.id, imageId: context.nodeImageId, publicationRoot },
      preparer: { containerId: state.preparer.id, imageId: context.factImageId },
      consumerLifecycle: context.consumerLifecycle,
      ...(state.operations
        ? {
            operations: state.operations,
            releaseOperationsGate: () => publisherCommand(state, 'release'),
          }
        : {}),
    });
    phase = 'publish-secret';
    const bind = await journey.prepare();
    if (state.operations) await publisherCommand(state, 'arm');
    phase = 'create-consumer';
    const consumer = await namespace(context, state, 'consumer', bind);
    const observed = (result) => {
      if (context.consumerLifecycle === 'process') {
        assert.equal(result, undefined);
        return;
      }
      // Refresh removal identity only from the driver's native verified lifecycle
      // result. A failed/ambiguous stage throws and leaves cleanup in UNKNOWN.
      assert.equal(result.containerId, consumer.id);
      assert.ok(Number.isFinite(Date.parse(result.startedAt)) && Date.parse(result.startedAt) > 0);
      consumer.startedAt = result.startedAt;
    };
    phase = 'consume';
    observed(await journey.consume(consumer.id));
    if (state.operations) {
      phase = `operations-${operationsCause}`;
      observed(await journey.observeOperationsInvalidation(operationsCause));
    } else {
      phase = 'restart';
      observed(await journey.restart());
      phase = 'invalidate';
      observed(await journey.invalidate());
    }
    emit('OBSERVED', `${mode}-authority-phase-${Math.ceil(performance.now() - started)}ms`);
  } catch (error) {
    fail(error);
    emit('FAIL', `${mode}-${phase}`);
  }
  if (state.uncertain || (state.journeyAttempted && !journey)) {
    cleanupKnown = false;
    emit('UNKNOWN', 'construction-or-transaction');
  }
  if (state.operations && state.publisherProcess && state.publisherProcess.result === undefined) {
    try {
      await publisherCommand(state, 'abort');
    } catch (error) {
      cleanupKnown = false;
      fail(error);
      emit('UNKNOWN', 'cleanup-gate');
    }
  }
  // Independently attempt every release owner. A failed driver/publisher close
  // prevents namespace destruction, but does not skip the other close or pools.
  for (const [name, close] of [
    ['journey', () => journey?.close()],
    ['operations', () => state.operations?.close()],
    ['publisher', () => closePublisher(state)],
  ]) {
    try {
      await bounded(Promise.resolve().then(close), 30000);
    } catch (error) {
      cleanupKnown = false;
      fail(error);
      emit('UNKNOWN', `cleanup-${name}`);
    }
  }
  const poolResults = await Promise.allSettled([
    ...state.pools.map(endPool),
    candidateOwner?.close(),
  ]);
  if (poolResults.some((result) => result.status === 'rejected')) {
    cleanupKnown = false;
    fail(poolResults.find((result) => result.status === 'rejected').reason);
    emit('UNKNOWN', 'cleanup-pools');
  }
  if (cleanupKnown) {
    cleanupKnown = await removeNamespaces(context, state);
    if (!cleanupKnown) fail(failure());
  } else emit('UNKNOWN', 'retained-namespaces');
  for (const value of Object.values(state.tls ?? {})) if (Buffer.isBuffer(value)) value.fill(0);
  if (input) {
    input.material = '';
    input.candidateUrl = '';
    input.tls = undefined;
  }
  state.database = undefined;
  if (!failed)
    emit(
      'PASS',
      operationsCause
        ? `operations-${operationsCause}-cleanup`
        : `${mode}-${context.consumerLifecycle}-restart-cleanup`,
    );
  return { failed, error: first, cleanupKnown };
}

/** One fresh installation root, sequential independent scopes, no replay API.
 * All four required fields are concrete runner inputs; there are no ready callbacks.
 * consumerLifecycle defaults to 'container'. Explicit 'process' retains the
 * earlier sleep-namespace/docker-exec acceptance as a distinct selectable proof.
 * The caller retains image/build/migration/admission and ordinary CI ownership.
 */
export async function runFactSecretConsumerInstallation(options) {
  const context = await contextFor(options);
  let first;
  for (const mode of context.operationsOnly ? [] : ['consumer-revocation', 'consumer-expiry']) {
    const result = await runCase(context, mode);
    if (result.failed && !first) first = result.error;
    if (result.failed && result.cleanupKnown) {
      // A shared setup/contract failure is not a fresh scenario merely because
      // its mode changes. Classify/correct it before another installation.
      if (mode === 'consumer-revocation') emit('BLOCKED', 'consumer-expiry-shared-prerequisite');
      break;
    }
    if (!result.cleanupKnown) {
      if (mode === 'consumer-revocation')
        emit('BLOCKED', 'consumer-expiry-uncertain-predecessor-cleanup');
      break;
    }
  }
  if (first) throw first;
  if (context.consumerLifecycle === 'container') {
    for (const cause of ['backend-close', 'exit', 'stale-restart', 'revocation', 'expiry']) {
      const result = await runCase(context, 'consumer-revocation', cause);
      if (result.failed) throw result.error;
      assert.equal(result.cleanupKnown, true);
    }
    emit('PASS', 'sequential-operations-source-invalidation');
  }
  emit(
    'PASS',
    context.operationsOnly
      ? 'operations-only-no-base-lifecycle-acceptance'
      : context.consumerLifecycle === 'container'
        ? 'sequential-installation-container-restart'
        : 'sequential-installation-process-restart-only',
  );
}

async function publisherMain() {
  assert.equal(process.geteuid(), 65532);
  assert.equal(process.getegid(), 65532);
  const framedInput = createFactSecretPublisherInput();
  const inputLines = createInterface({ input: framedInput, crlfDelay: Infinity });
  const iterator = inputLines[Symbol.asyncIterator]();
  let app,
    pools = [],
    failed = false;
  // Signal/EOF triggers the same awaited real factory close. PID1 is the keeper,
  // so killing only the docker-exec client is never a cleanup implementation.
  const terminate = () => inputLines.close();
  const rejectInput = () => {
    failed = true;
    inputLines.close();
  };
  framedInput.once('error', rejectInput);
  inputLines.once('error', rejectInput);
  process.stdin.pipe(framedInput);
  process.once('SIGTERM', terminate);
  process.once('SIGINT', terminate);
  try {
    const stat = (await readFile('/proc/self/stat', 'utf8')).split(') ')[1].split(' ');
    assert.match(stat[19], /^[1-9][0-9]*$/u);
    process.stdout.write(`FACT_SECRET_PUBLISHER|PID|${process.pid}|${stat[19]}\n`);
    const first = await bounded(iterator.next());
    assert.ok(!first.done && first.value.length <= 65536);
    const request = JSON.parse(first.value);
    assert.deepEqual(Object.keys(request).sort(), [
      'candidate',
      'input',
      'publicationRoot',
      'runtime',
    ]);
    assert.equal(request.publicationRoot, publicationRoot);
    assert.equal(request.runtime.user, 'openpc_identity_runtime');
    assert.equal(request.runtime.database, 'openpc_control');
    assert.equal(request.candidate.user, 'openpc_candidate_index');
    assert.equal(request.candidate.database, 'openpc_candidate_index');
    pools = [pool(request.runtime), pool(request.candidate)];
    app = await startFactSecretConsumerPublisher(request.input, {
      publicationRoot,
      runtimePool: pools[0],
      candidateAdminPool: pools[1],
    });
    request.input.material = '';
    request.input.tls = undefined;
    if (app.descriptor)
      process.stdout.write(`FACT_SECRET_PUBLISHER|DESCRIPTOR|${JSON.stringify(app.descriptor)}\n`);
    process.stdout.write('FACT_SECRET_PUBLISHER|LISTENING\n');
    while (true) {
      const next = await iterator.next();
      assert.ok(!next.done);
      const command = parseFactSecretPublisherCommand(next.value);
      if (command.operation === 'close') break;
      assert.ok(app.descriptor);
      assert.equal(command.associationId, request.input.operations.association_id);
      if (command.operation === 'arm') app.arm(command.associationId);
      else if (command.operation === 'release') app.release(command.associationId);
      else app.abort();
      process.stdout.write(
        `FACT_SECRET_PUBLISHER|GATE|${command.operation}|${command.associationId}\n`,
      );
    }
  } catch {
    failed = true;
  }
  try {
    await bounded(Promise.resolve().then(() => app?.close()));
  } catch {
    failed = true;
  }
  const results = await Promise.allSettled(pools.map(endPool));
  if (results.some((result) => result.status === 'rejected')) failed = true;
  inputLines.close();
  process.stdin.unpipe(framedInput);
  framedInput.destroy();
  process.removeListener('SIGTERM', terminate);
  process.removeListener('SIGINT', terminate);
  if (failed) throw failure();
  process.stdout.write('FACT_SECRET_PUBLISHER|CLOSED\n');
}

export async function runFactSecretConsumerInstallationPublisher() {
  try {
    await publisherMain();
  } catch {
    emit('FAIL', 'publisher-private-diagnostics-withheld');
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [action, runRoot, composeJson, factImageId, publisherBundle] = process.argv.slice(2);
    if (action === 'publisher') {
      assert.equal(process.argv.length, 3);
      await runFactSecretConsumerInstallationPublisher();
    } else {
      assert.equal(action, 'run');
      assert.equal(process.argv.length, 7);
      const phase = process.env.OPENPC_LOCAL_RUNTIME_FACT_SECRET_OPERATIONS_ONLY ?? '0';
      assert.ok(['0', '1'].includes(phase));
      await runFactSecretConsumerInstallation({
        operationsOnly: phase === '1',
        runRoot,
        compose: JSON.parse(composeJson),
        factImageId,
        publisherBundle,
      });
    }
  } catch {
    // Raw assertions, subprocess exceptions and pg errors may include secrets.
    emit('FAIL', 'entrypoint-private-diagnostics-withheld');
    process.exitCode = 1;
  }
}
