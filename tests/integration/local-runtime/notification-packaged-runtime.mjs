import { execFile } from 'node:child_process';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, isAbsolute, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { currentNotificationChannel } from '../../../services/control-api/src/notifications/endpoint-admission.ts';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.ts';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { validateStoredBinding } from '../../../scripts/maintenance/local-runtime-network.mjs';
import { parseStrictJsonBytes } from '../../../services/control-api/src/privacy-explorer/strict-json.ts';
import { createNotificationCredentialProviderFixture } from './notification-credential-provider-fixture.mjs';
import {
  prepareNotificationRuntimeFixtures,
  validateNotificationRuntimeEntries,
} from './notification-runtime-bootstrap.mjs';

const exec = promisify(execFile);
const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const fail = (reason = 'INPUTS') => new Error(`BLOCKED_NOTIFICATION_PACKAGED_${reason}`);
/** Shared finite parser profile for the actual retained network input. The
 * network owner still validates identity/topology and live ownership separately. */
export function parseNotificationPackagedNetworkJson(value) {
  if (!(value instanceof Uint8Array) || value.length > 262144) throw fail('NETWORK_JSON');
  return parseStrictJsonBytes(value, { maximumDepth: 16 });
}
const absolute = z
  .string()
  .min(1)
  .max(4096)
  .refine((p) => isAbsolute(p) && normalize(p) === p && !p.includes('\0'));
const ip = z.string().refine((v) => isIP(v) !== 0);
const port = z.number().int().min(1).max(65535);
const bytes = z.custom((v) => Buffer.isBuffer(v) && v.length > 0 && v.length <= 65536);
const tls = z.strictObject({ ca: bytes, certificate: bytes, privateKey: bytes });
const name = z.string().regex(/^[a-zA-Z0-9.:-]{1,253}$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const inputSchema = z.strictObject({
  runRoot: absolute,
  containerRoot: absolute,
  installationPool: z.custom((v) => v instanceof Pool),
  runtimePool: z.custom((v) => v instanceof Pool),
  entries: z
    .array(z.strictObject({ fixture: z.unknown(), workloadTls: tls }))
    .min(1)
    .max(8),
  provider: z.strictObject({
    tls,
    port: port.optional(),
    leaseMs: z.number().int().min(100).max(30000),
    network: z.strictObject({
      advertisedAddress: ip,
      listenHost: z.enum(['127.0.0.1', '0.0.0.0']),
      serverName: name,
      serverSpkiDigest: digest,
    }),
  }),
  control: z.strictObject({
    tls,
    listen: z.strictObject({ host: ip, port }),
    peer: z.strictObject({ host: ip, port, serverName: name, serverSpkiDigest: digest }),
    connectionLifetimeMs: z.number().int().min(1000).max(300000).default(300000),
  }),
  timeoutMs: z.number().int().min(100).max(30000).default(10000),
});
const claimedProviders = new WeakSet();
const claimedRoots = new Set();
function certificate(input, usage, endpoint) {
  const cert = new X509Certificate(input.certificate);
  const ca = new X509Certificate(input.ca);
  if (
    !ca.ca ||
    cert.ca ||
    !cert.verify(ca.publicKey) ||
    Date.parse(ca.validFrom) > Date.now() ||
    Date.parse(ca.validTo) <= Date.now() ||
    !cert.checkPrivateKey(createPrivateKey(input.privateKey)) ||
    !cert.keyUsage?.includes(usage) ||
    Date.parse(cert.validFrom) > Date.now() ||
    Date.parse(cert.validTo) <= Date.now()
  )
    throw fail('TLS');
  if (
    endpoint &&
    (!(isIP(endpoint.serverName)
      ? cert.checkIP(endpoint.serverName)
      : cert.checkHost(endpoint.serverName)) ||
      sha256(cert.publicKey.export({ type: 'spki', format: 'der' })) !== endpoint.serverSpkiDigest)
  )
    throw fail('TLS_PIN');
  return cert;
}

/** Pure validation only. Signed profiles and real TLS inputs are checked here;
 * this is not a provider constructor, installation, readiness grant or effect. */
export function validateNotificationPackagedInputs(value) {
  let input;
  try {
    input = inputSchema.parse(value);
  } catch {
    throw fail();
  }
  for (const pool of [input.installationPool, input.runtimePool]) {
    if (
      pool.options.max !== 1 ||
      ![
        'connectionTimeoutMillis',
        'statement_timeout',
        'idle_in_transaction_session_timeout',
      ].every(
        (key) =>
          Number.isInteger(pool.options[key]) &&
          pool.options[key] > 0 &&
          pool.options[key] <= 30000,
      )
    )
      throw fail('POOL');
  }
  if (
    input.runtimePool === input.installationPool ||
    input.containerRoot === '/' ||
    input.provider.leaseMs > input.timeoutMs
  )
    throw fail();
  const prepared = validateNotificationRuntimeEntries(input.entries.map((entry) => entry.fixture));
  const scope = prepared[0].credential;
  const identities = new Map();
  for (let index = 0; index < prepared.length; index++) {
    const entry = prepared[index],
      cert = certificate(input.entries[index].workloadTls, '1.3.6.1.5.5.7.3.2');
    const key = `${entry.credential.participantId}:${entry.installation.workloadId}`;
    const binding = canonicalJson([
      entry.installation.principalId,
      entry.installation.workloadCredentialId,
      entry.installation.workloadEpoch,
      sha256(cert.raw),
    ]);
    if (
      entry.credential.participantId !== scope.participantId ||
      entry.credential.privacyDomainId !== scope.privacyDomainId ||
      cert.subjectAltName !==
        `URI:urn:openpc:participant:${scope.participantId}:workload:${entry.installation.workloadId.slice(-36)}` ||
      (identities.has(key) && identities.get(key) !== binding) ||
      typeof entry.provider?.revoke !== 'function' ||
      typeof entry.provider?.close !== 'function' ||
      !input.entries[index].fixture.network ||
      dirname(entry.gatewayOptions.journalPath) !==
        join(input.runRoot, 'evidence/notification-browser')
    )
      throw fail('BINDING');
    if (
      [input.entries[index].workloadTls, input.control.tls, input.provider.tls].some(
        (material) =>
          sha256(
            new X509Certificate(material.certificate).publicKey.export({
              type: 'spki',
              format: 'der',
            }),
          ) === input.entries[index].fixture.clientSpkiDigest,
      )
    )
      throw fail('CHANNEL_KEY_FILE');
    // The supplied workload transport leaf must be issued by both listener CAs.
    for (const ca of [input.control.tls.ca, input.provider.tls.ca])
      if (!cert.verify(new X509Certificate(ca).publicKey)) throw fail('TLS_ISSUER');
    identities.set(key, binding);
  }
  // The committed runtime has four live peer slots; several destinations may
  // share one actual installed workload, but distinct peers cannot exceed it.
  if (identities.size > 4) throw fail('PEER_LIMIT');
  certificate(input.control.tls, '1.3.6.1.5.5.7.3.1', input.control.peer);
  certificate(input.provider.tls, '1.3.6.1.5.5.7.3.1', input.provider.network);
  return { input, prepared };
}

/** Exact 437e7120 loader contract. providerPort is the actually bound external
 * listener's port at preparation; this pure builder establishes no authority. */
export function notificationPackagedConfiguration(value, providerPort) {
  const { input, prepared } = validateNotificationPackagedInputs(value);
  port.parse(providerPort);
  const paths = (prefix) => ({
    caFile: join(input.containerRoot, `${prefix}-ca.pem`),
    certificateFile: join(input.containerRoot, `${prefix}-certificate.pem`),
    privateKeyFile: join(input.containerRoot, `${prefix}-key.pem`),
  });
  return {
    version: 1,
    listen: input.control.listen,
    tls: paths('control'),
    providers: prepared.map((entry, index) => ({
      credential: entry.credential,
      address: input.provider.network.advertisedAddress,
      port: providerPort,
      serverName: input.provider.network.serverName,
      serverSpkiDigest: input.provider.network.serverSpkiDigest,
      tls: paths(`workload-${index}`),
    })),
    timeoutMs: input.timeoutMs,
    connectionLifetimeMs: input.control.connectionLifetimeMs,
  };
}

/** Publish a read-only file for a differently numbered container user. The
 * private host parent keeps other host users out; each container gets only the
 * explicit read-only file mounts. Set mode on the owned descriptor so a private
 * caller umask cannot make the installed file unreadable by its actual consumer. */
export async function writeNotificationPackagedMountFile(directory, name, data) {
  const parent = await lstat(directory);
  if (
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    parent.uid !== process.getuid() ||
    (parent.mode & 0o777) !== 0o700 ||
    (await realpath(directory)) !== directory ||
    !/^(?:configuration\.json|(?:control|workload-[0-7])-(?:ca|certificate|key)\.pem)$/u.test(
      name,
    ) ||
    !(data instanceof Uint8Array) ||
    data.length < 1 ||
    data.length > 262144
  )
    throw fail('FILE');
  const path = join(directory, name);
  const file = await open(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o400,
  );
  try {
    await file.writeFile(data);
    await file.chmod(0o444);
    await file.sync();
  } finally {
    await file.close();
  }
  return path;
}

async function readOwned(path, maximum = 262144) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const buffer = Buffer.alloc(maximum + 1);
  try {
    const info = await file.stat();
    if (
      !info.isFile() ||
      info.uid !== process.getuid() ||
      info.size < 1 ||
      info.size > maximum ||
      info.mode & 0o022
    )
      throw fail('FILE');
    let used = 0;
    while (used < buffer.length) {
      const next = await file.read(buffer, used, buffer.length - used, used);
      if (!next.bytesRead) break;
      used += next.bytesRead;
    }
    if (!used || used > maximum) throw fail('FILE');
    return Buffer.from(buffer.subarray(0, used));
  } finally {
    buffer.fill(0);
    await file.close();
  }
}

async function ownedExecution(input) {
  try {
    return await inspectOwnedExecution(input);
  } catch {
    // Subprocess errors include argv, including the root ownership token.
    // The caller needs the closed ownership failure, never that command/cause.
    throw fail('OWNERSHIP');
  }
}

async function inspectOwnedExecution(input) {
  // Existing guarded reuse only: no allocation, service command or hidden runner.
  await exec(
    'bash',
    [
      join(repository, 'scripts/maintenance/run-bounded.sh'),
      '--profile',
      'runtime-target',
      '--reuse',
      '--',
      'true',
    ],
    { cwd: repository, timeout: 15000, maxBuffer: 16384 },
  );
  const rootInfo = await stat(input.runRoot);
  if (
    (await realpath(input.runRoot)) !== input.runRoot ||
    !rootInfo.isDirectory() ||
    rootInfo.uid !== process.getuid() ||
    rootInfo.mode & 0o077
  )
    throw fail('ROOT');
  const sentinel = await readOwned(join(input.runRoot, '.openpc-local-runtime-owner'), 256);
  const owner = /^openpc-local-runtime:(openpc-local-e2e-[0-9a-f]{12}):([0-9a-f]{64})\n$/u.exec(
    sentinel.toString(),
  );
  if (!owner || owner[1] !== `openpc-local-e2e-${owner[2].slice(0, 12)}`) throw fail('OWNER');
  const identity = { root: input.runRoot, project: owner[1], token: owner[2] };
  const binding = validateStoredBinding(
    parseNotificationPackagedNetworkJson(
      await readOwned(join(input.runRoot, 'data/local-runtime-network.json')),
    ),
    identity,
  );
  // This existing read-only entrypoint also checks the live ancestor's FD8/FD9
  // locks. No caller boolean or newly introduced ownership protocol is accepted.
  await exec(
    process.execPath,
    [
      join(repository, 'scripts/maintenance/local-runtime-network.mjs'),
      'compose-overlay',
      input.runRoot,
      identity.project,
      identity.token,
      binding.subnet,
      binding.gateway,
      'retained',
    ],
    { cwd: repository, timeout: 15000, maxBuffer: 16384 },
  );
  if (
    input.provider.network.advertisedAddress !== binding.gateway ||
    input.provider.network.listenHost !== '0.0.0.0' ||
    input.entries.some(
      ({ fixture }) =>
        canonicalJson(fixture.network.addresses) !== canonicalJson([binding.gateway]) ||
        fixture.network.listenHost !== '0.0.0.0',
    )
  )
    throw fail('NETWORK');
  return identity;
}

/** Borrows the caller's two bounded real pools; owns created transport/gateway
 * listeners and consumes the supplied external providers' terminal lifecycle.
 * The caller owns installation trust/TLS generation, Compose startup, image
 * provenance, inherited admission and the final retained-root disposition. */
export async function prepareNotificationPackagedRuntime(value) {
  const { input, prepared } = validateNotificationPackagedInputs(value);
  const identity = await ownedExecution(input);
  const directory = join(input.runRoot, 'data/notification-packaged');
  if (claimedRoots.has(directory) || prepared.some((entry) => claimedProviders.has(entry.provider)))
    throw fail('DUPLICATE_OWNER');
  const providers = [...new Set(prepared.map((entry) => entry.provider))];
  let fixture,
    transport,
    closing,
    closed = false,
    running = false,
    peerFailure;
  const peers = new Map(),
    peerAttempts = new Map(),
    files = new Map(),
    reconnecting = new Set();
  const stopping = new AbortController();
  const scope = prepared[0].credential;
  async function databasePreflight(installed) {
    for (let index = 0; index < prepared.length; index++) {
      const entry = prepared[index],
        certificate = new X509Certificate(input.entries[index].workloadTls.certificate);
      await runScopedTransaction(
        input.runtimePool,
        {
          participantId: scope.participantId,
          privacyDomainId: scope.privacyDomainId,
          actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        },
        localOperationId,
        async (client) => {
          const row = await client.query(
            `select c.subject,c.audience,c.public_key_spki_der,c.secret_fingerprint
          from control.credential c join control.principal p on p.participant_id=c.participant_id and p.principal_id=c.principal_id
          where c.participant_id=$1 and c.principal_id=$2 and c.credential_id=$3 and c.credential_epoch=$4
          and c.kind='WORKLOAD_MTLS' and c.state='ACTIVE' and p.kind='WORKLOAD' and p.state='ACTIVE'
          and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()`,
            [
              scope.participantId,
              entry.installation.principalId,
              entry.installation.workloadCredentialId,
              entry.installation.workloadEpoch,
            ],
          );
          if (
            row.rowCount !== 1 ||
            row.rows[0].subject !== certificate.subjectAltName.slice(4) ||
            row.rows[0].audience !== entry.installation.workloadId ||
            !row.rows[0].public_key_spki_der.equals(
              certificate.publicKey.export({ type: 'spki', format: 'der' }),
            ) ||
            row.rows[0].secret_fingerprint.toString('hex') !== sha256(certificate.raw).slice(7)
          )
            throw fail('CURRENT_IDENTITY');
          if (
            installed &&
            canonicalJson(
              (await currentNotificationChannel(client, scope, entry.credential.credentialRef))
                .installation,
            ) !== canonicalJson(entry.installation)
          )
            throw fail('CURRENT_INSTALLATION');
        },
      );
    }
  }
  async function closeOwned() {
    closed = true;
    stopping.abort();
    for (const peer of peers.values()) peer.close();
    await Promise.allSettled([...reconnecting]);
    let failed = false;
    try {
      await fixture?.close();
    } catch {
      failed = true;
    }
    try {
      await transport?.close();
    } catch {
      failed = true;
    }
    for (const provider of providers) {
      try {
        await provider.close();
      } catch {
        failed = true;
      }
    }
    for (const contents of files.values()) contents.fill(0);
    if (failed) throw fail('CLEANUP_UNKNOWN');
    // Even DRAINED does not resolve an UNKNOWN business effect or grant deletion.
    return Object.freeze({ providerDrain: 'DRAINED', filesRetained: true });
  }
  const close = () => {
    // The unchanged browser owns its requests. A caller must await that owner
    // before teardown; concurrent cleanup cannot manufacture completed drain.
    if (running) return Promise.reject(fail('BROWSER_ACTIVE_CLEANUP_UNKNOWN'));
    closing ??= closeOwned();
    return closing;
  };
  async function assertFiles() {
    for (const [path, expected] of files) {
      const actual = await readOwned(path);
      try {
        if (!actual.equals(expected)) throw fail('FILE_SUBSTITUTION');
      } finally {
        actual.fill(0);
      }
    }
  }
  async function connectPeer(index) {
    if (closed) throw fail('CLOSED');
    const key = `${prepared[index].credential.participantId}:${prepared[index].installation.workloadId}`;
    if (peers.has(key)) return;
    const attempts = (peerAttempts.get(key) ?? 0) + 1;
    if (attempts > 8) throw fail('PEER_RECONNECT_LIMIT');
    await databasePreflight(true);
    const peer = await fixture.connectWorkload({
      ...input.control.peer,
      ...input.entries[index].workloadTls,
    });
    peerAttempts.set(key, attempts);
    if (closed) {
      peer.close();
      throw fail('CLOSED');
    }
    peers.set(key, peer);
    void peer.closed.then(() => {
      if (peers.get(key) !== peer) return;
      peers.delete(key);
      if (!running || closed) return;
      // Connection recovery only; this never repeats a business request or
      // constructs a provider. Current installation/Identity is reread each time.
      const task = (async () => {
        const deadline = Date.now() + 30000;
        for (let attempt = 0; attempt < 30 && running && !closed; attempt++) {
          await delay(Math.min(1000, 100 * (attempt + 1)), undefined, { signal: stopping.signal });
          if (!running || closed) return;
          try {
            await connectPeer(index);
            return;
          } catch (error) {
            if (error.code !== 'ECONNREFUSED' || Date.now() >= deadline) throw error;
          }
        }
        if (running && !closed) throw fail('PEER_RECONNECT');
      })().catch(() => {
        if (!closed) peerFailure = fail('PEER_RECONNECT');
      });
      reconnecting.add(task);
      void task.finally(() => reconnecting.delete(task));
    });
  }
  try {
    await databasePreflight(false);
    const role = await input.installationPool.query(
      "select pg_has_role(current_user,'openpc_control_owner','USAGE') allowed",
    );
    if (role.rows.length !== 1 || role.rows[0].allowed !== true) throw fail('INSTALLATION_ROLE');
    if ((await realpath(join(input.runRoot, 'data'))) !== join(input.runRoot, 'data'))
      throw fail('ROOT');
    await mkdir(directory, { mode: 0o700 }); // Exclusive durable claim; never overwrite/reopen.
    if (prepared.some((entry) => claimedProviders.has(entry.provider)))
      throw fail('DUPLICATE_OWNER');
    claimedRoots.add(directory);
    for (const provider of providers) claimedProviders.add(provider);
    const evidence = join(input.runRoot, 'evidence');
    if ((await realpath(evidence)) !== evidence) throw fail('JOURNAL_ROOT');
    const journals = join(evidence, 'notification-browser');
    await mkdir(journals, { mode: 0o700 }).catch((error) => {
      if (error.code !== 'EEXIST') throw error;
    });
    const journalRoot = await lstat(journals);
    if (
      !journalRoot.isDirectory() ||
      journalRoot.uid !== process.getuid() ||
      journalRoot.mode & 0o077
    )
      throw fail('JOURNAL_ROOT');
    for (const entry of prepared) {
      const journal = await lstat(entry.gatewayOptions.journalPath).catch((error) => {
        if (error.code !== 'ENOENT') throw error;
      });
      if (
        journal &&
        (!journal.isFile() || journal.uid !== process.getuid() || journal.mode & 0o077)
      )
        throw fail('JOURNAL_FILE');
    }
    transport = await createNotificationCredentialProviderFixture({
      ...input.provider,
      entries: prepared.map((entry, index) => ({
        installation: entry.installation,
        provider: entry.provider,
        clientCertificate: input.entries[index].workloadTls.certificate,
      })),
    });
    fixture = await prepareNotificationRuntimeFixtures({
      installationPool: input.installationPool,
      entries: input.entries.map((entry) => entry.fixture),
    });
    const config = notificationPackagedConfiguration(input, transport.port);
    async function save(name, contents) {
      const path = join(directory, name),
        data = Buffer.from(contents);
      try {
        await writeNotificationPackagedMountFile(directory, name, data);
        files.set(path, data);
      } catch (error) {
        data.fill(0);
        throw error;
      }
    }
    for (const [prefix, material] of [
      ['control', input.control.tls],
      ...input.entries.map((entry, index) => [`workload-${index}`, entry.workloadTls]),
    ]) {
      for (const [suffix, field] of [
        ['ca', 'ca'],
        ['certificate', 'certificate'],
        ['key', 'privateKey'],
      ])
        await save(`${prefix}-${suffix}.pem`, material[field]);
    }
    await save('configuration.json', canonicalJson(config));
    const dir = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
    try {
      await dir.sync();
    } finally {
      await dir.close();
    }
    const mounts = Object.freeze(
      [...files.keys()].map((source) =>
        Object.freeze({
          type: 'bind',
          source,
          target: join(input.containerRoot, source.slice(directory.length + 1)),
          read_only: true,
        }),
      ),
    );
    const configurationFile = join(input.containerRoot, 'configuration.json');
    return Object.freeze({
      configurationFile,
      mounts,
      environment: Object.freeze({ CONTROL_API_NOTIFICATION_VERIFICATION_FILE: configurationFile }),
      port: Object.freeze({
        target: input.control.listen.port,
        published: input.control.peer.port,
        host_ip: input.control.peer.host,
        protocol: 'tcp',
      }),
      async runBrowser({ argv }) {
        if (
          closed ||
          running ||
          peerFailure ||
          !Array.isArray(argv) ||
          argv.length !== 5 ||
          argv.some((v) => typeof v !== 'string') ||
          argv[0] !== join(input.runRoot, 'secrets') ||
          argv[1] !== join(input.runRoot, 'evidence') ||
          argv[2] !== scope.participantId ||
          argv[3] !== scope.privacyDomainId
        )
          throw fail('BROWSER_INPUT');
        running = true;
        try {
          const compose = JSON.parse(argv[4]);
          if (
            !Array.isArray(compose) ||
            compose[0] !== 'docker' ||
            compose[1] !== 'compose' ||
            compose.length > 24 ||
            !compose.every((v) => typeof v === 'string' && !v.includes('\0') && !v.includes('\n'))
          )
            throw fail('COMPOSE');
          const projects = [],
            paths = [];
          for (let index = 2; index < compose.length; index += 2) {
            if (['-p', '--project-name'].includes(compose[index]))
              projects.push(compose[index + 1]);
            else if (['-f', '--file'].includes(compose[index])) paths.push(compose[index + 1]);
            else throw fail('COMPOSE');
          }
          if (
            canonicalJson(projects) !== canonicalJson([identity.project]) ||
            paths.some(
              (p) =>
                !isAbsolute(p) ||
                !(
                  p.startsWith(`${input.runRoot}/`) ||
                  p === join(repository, 'deploy/compose/local/compose.yaml')
                ),
            )
          )
            throw fail('COMPOSE');
          await ownedExecution(input);
          await assertFiles();
          const rendered = JSON.parse(
            (
              await exec(compose[0], [...compose.slice(1), 'config', '--format', 'json'], {
                cwd: repository,
                timeout: 15000,
                maxBuffer: 4 * 1024 * 1024,
              })
            ).stdout,
          );
          const service = rendered.services?.['control-api'];
          if (
            service?.ports?.filter(
              (p) =>
                Number(p.target) === input.control.listen.port &&
                Number(p.published) === input.control.peer.port &&
                p.host_ip === input.control.peer.host &&
                p.protocol === 'tcp',
            ).length !== 1
          )
            throw fail('PEER_PORT');
          if (
            service?.environment?.CONTROL_API_NOTIFICATION_VERIFICATION_FILE !==
              configurationFile ||
            mounts.some(
              (mount) =>
                service.volumes?.filter((v) => v.target === mount.target).length !== 1 ||
                service.volumes?.filter(
                  (v) =>
                    v.source === mount.source &&
                    v.target === mount.target &&
                    v.type === 'bind' &&
                    v.read_only === true,
                ).length !== 1,
            ) ||
            service.volumes?.some(
              (v) =>
                v.target.startsWith(`${input.containerRoot}/`) &&
                !mounts.some((m) => m.target === v.target),
            )
          )
            throw fail('MOUNT_SUBSTITUTION');
          peerAttempts.clear();
          for (let index = 0; index < prepared.length; index++) await connectPeer(index);
          // These are real transport and current-SQL preflights, not a claimed
          // server-side runtime.preflight. Real public VERIFY still authenticates
          // the peer/recipient/provider; its result is required for N3 acceptance.
          const { runNotificationBrowser } = await import('./notification-browser.mjs');
          await runNotificationBrowser({ argv, notificationRuntime: fixture });
          await Promise.allSettled([...reconnecting]);
          if (peerFailure) throw peerFailure;
        } finally {
          running = false;
        }
      },
      close,
    });
  } catch (error) {
    const first = /^BLOCKED_NOTIFICATION_PACKAGED_[A-Z_]+$/u.test(error?.message ?? '')
      ? error
      : fail('PREPARATION');
    // Only consumed owners are closed. Rejected shape/ownership preflight never
    // revokes unrelated supplied providers. No cleanup path removes originals.
    try {
      if (claimedRoots.has(directory)) await close();
    } catch (cleanup) {
      throw new AggregateError(
        [first, cleanup],
        'BLOCKED_NOTIFICATION_PACKAGED_PREPARATION_AND_CLEANUP_UNKNOWN',
      );
    }
    throw first;
  }
}

/** Read already-prepared genuine transport files for the existing Control
 * container. This returns mount descriptors only; it installs no trust/profile,
 * consumes no source, and cannot qualify a native consumer or mark it CURRENT. */
export async function prepareNotificationPackagedDeliveryMount(value) {
  const input = z
    .strictObject({
      directory: absolute,
      containerRoot: absolute,
      participantId: z.uuidv7(),
      privacyDomainId: z.uuidv7(),
    })
    .parse(value);
  if (input.containerRoot === '/' || input.directory === '/') throw fail('DELIVERY_ROOT');
  const parent = await lstat(input.directory);
  if (
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    parent.uid !== process.getuid() ||
    parent.mode & 0o077 ||
    (await realpath(input.directory)) !== input.directory
  )
    throw fail('DELIVERY_ROOT');
  const read = async (name, maximum) => {
    const file = await open(
      join(input.directory, name),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const bytes = Buffer.alloc(maximum + 1);
    try {
      const info = await file.stat();
      if (
        !info.isFile() ||
        info.uid !== process.getuid() ||
        info.mode & 0o022 ||
        info.size < 1 ||
        info.size > maximum
      )
        throw fail('DELIVERY_FILE');
      let offset = 0;
      while (offset < bytes.length) {
        const result = await file.read(bytes, offset, bytes.length - offset, offset);
        if (!result.bytesRead) break;
        offset += result.bytesRead;
      }
      if (offset !== info.size || offset > maximum) throw fail('DELIVERY_FILE');
      return Buffer.from(bytes.subarray(0, offset));
    } finally {
      bytes.fill(0);
      await file.close();
    }
  };
  const { parseNotificationDeliveryServingConfiguration } =
    await import('../../../services/control-api/src/notifications/packaged-delivery-runtime.ts');
  const bytes = await read('delivery-configuration.json', 262144);
  let config;
  try {
    config = parseNotificationDeliveryServingConfiguration(
      parseStrictJsonBytes(bytes, { maximumDepth: 8 }),
    );
  } finally {
    bytes.fill(0);
  }
  if (
    config.worker.participantId !== input.participantId ||
    config.worker.privacyDomainId !== input.privacyDomainId
  )
    throw fail('DELIVERY_SCOPE');
  const paths = new Set(['delivery-configuration.json']);
  const name = (path) => {
    if (!path.startsWith(input.containerRoot + '/')) throw fail('DELIVERY_MOUNT');
    const relative = path.slice(input.containerRoot.length + 1);
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$/u.test(relative) || ['.', '..'].includes(relative))
      throw fail('DELIVERY_MOUNT');
    return relative;
  };
  for (const [files, server] of [
    [config.kmsTls, false],
    [config.signerTls, false],
    [config.consumer.listenerTls, true],
    [config.consumer.workerTls, false],
    [config.consumer.recipientTls, false],
    ...config.providers.map((p) => [p.tls, false]),
  ]) {
    const material = {};
    try {
      for (const [field, key] of [
        ['caFile', 'ca'],
        ['certificateFile', 'certificate'],
        ['privateKeyFile', 'privateKey'],
      ]) {
        const selected = name(files[field]);
        material[key] = await read(selected, 65536);
        paths.add(selected);
      }
      const actual = certificate(material, server ? '1.3.6.1.5.5.7.3.1' : '1.3.6.1.5.5.7.3.2');
      if (server) {
        if (
          !(isIP(config.consumer.serverName)
            ? actual.checkIP(config.consumer.serverName)
            : actual.checkHost(config.consumer.serverName))
        )
          throw fail('DELIVERY_TLS');
      } else {
        const sans = actual.subjectAltName?.split(', ').filter((s) => s.startsWith('URI:'));
        if (
          sans?.length !== 1 ||
          !new RegExp(
            `^URI:urn:openpc:participant:${input.participantId}:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
            'u',
          ).test(sans[0])
        )
          throw fail('DELIVERY_TLS');
      }
    } finally {
      for (const bytes of Object.values(material)) bytes.fill(0);
    }
  }
  const vault = name(config.vaultDirectory);
  if (paths.has(vault)) throw fail('DELIVERY_VAULT');
  const vaultRoot = join(input.directory, vault),
    info = await lstat(vaultRoot);
  if (
    !info.isDirectory() ||
    info.isSymbolicLink() ||
    info.mode & 0o077 ||
    (await realpath(vaultRoot)) !== vaultRoot
  )
    throw fail('DELIVERY_VAULT');
  // Decryption integrity/ownership remains in the actual payload/vault owner;
  // merely mounting a directory is not proof of a usable encrypted object.
  const configurationFile = join(input.containerRoot, 'delivery-configuration.json');
  return Object.freeze({
    configurationFile,
    mounts: Object.freeze(
      [...paths, vault].map((p) =>
        Object.freeze({
          type: 'bind',
          source: join(input.directory, p),
          target: join(input.containerRoot, p),
          read_only: true,
        }),
      ),
    ),
    environment: Object.freeze({ CONTROL_API_NOTIFICATION_DELIVERY_FILE: configurationFile }),
  });
}
