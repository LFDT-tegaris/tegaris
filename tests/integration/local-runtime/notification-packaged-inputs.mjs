import { execFile } from 'node:child_process';
import { createPrivateKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, realpath, stat } from 'node:fs/promises';
import { createServer } from 'node:net';
import { dirname, isAbsolute, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { z } from 'zod';
import {
  evidenceKeyId,
  signNotificationClaim,
} from '../../../packages/security-kernel/src/index.ts';
import { encodeCbor } from '../../../packages/security-kernel/src/canonical-cbor.ts';
import { createTestNotificationCredentialProvider } from '../../../scripts/operations/test-notification-credential-provider.ts';
import { validateStoredBinding } from '../../../scripts/maintenance/local-runtime-network.mjs';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidSchema } from '../../../services/control-api/src/configuration/resource-contracts.ts';
import { notificationChannel } from '../../../services/control-api/src/notifications/endpoint-binding.ts';
import {
  currentNotificationChannel,
  notificationDatabaseTime,
} from '../../../services/control-api/src/notifications/endpoint-admission.ts';
import { immutableJsonCopy } from '../../../services/control-api/src/privacy-explorer/immutable.ts';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.ts';
import { lockAuthorityFence } from '../../../services/identity-service/src/db/authority-fence.ts';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { notificationCredentialEncoding } from '../../../services/identity-service/src/domain/notification-credential-material.ts';
import { runtimeSnapshotTlsFixture } from '../identity/runtime-snapshot-tls-fixture.ts';
import {
  prepareNotificationPackagedRuntime,
  prepareNotificationPackagedDeliveryMount,
  validateNotificationPackagedInputs,
  parseNotificationPackagedNetworkJson,
} from './notification-packaged-runtime.mjs';

const exec = promisify(execFile);
const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const blocked = (boundary) => new Error(`BLOCKED_NOTIFICATION_INPUTS_${boundary}`);
const path = z
  .string()
  .min(2)
  .max(4096)
  .refine((v) => isAbsolute(v) && normalize(v) === v && !v.includes('\0'));
const databaseUrl = z
  .string()
  .max(4096)
  .refine((v) => {
    try {
      const url = new URL(v);
      return (
        ['postgres:', 'postgresql:'].includes(url.protocol) &&
        ['127.0.0.1', '[::1]'].includes(url.hostname) &&
        !!url.username &&
        !!url.password &&
        !!url.port &&
        Number(url.port) >= 1 &&
        Number(url.port) <= 65535 &&
        url.pathname === '/openpc_control' &&
        !url.search &&
        !url.hash
      );
    } catch {
      return false;
    }
  });
const requestSchema = z.strictObject({
  runRoot: path,
  containerRoot: path.default('/app/notification-packaged'),
  deliveryMountDirectory: path.optional(),
  participantId: uuidSchema,
  privacyDomainId: uuidSchema,
  environmentId: z
    .string()
    .regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u)
    .default('openpc-local-runtime'),
  database: z.strictObject({ installationUrl: databaseUrl, runtimeUrl: databaseUrl }),
  channels: z.array(notificationChannel).min(1).max(8).default(['WEBHOOK', 'WEBHOOK', 'WEBHOOK']),
  validityMs: z.number().int().min(1000).max(3600000).default(3600000),
  minimumRemainingMs: z.number().int().min(1000).max(3600000),
  controlListenPort: z.number().int().min(1024).max(65535).default(3448),
});
const boundedPool = Object.freeze({
  max: 1,
  connectionTimeoutMillis: 5000,
  statement_timeout: 5000,
  idle_in_transaction_session_timeout: 30000,
});
function plainRecord(value) {
  return (
    value &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0 &&
    Object.values(Object.getOwnPropertyDescriptors(value)).every((d) => !d.get && !d.set)
  );
}

/** Closed local-test request; no TLS, profiles, provider callbacks, ready flags,
 * installed grants, business candidates or channel-secret paths can be supplied. */
export function validateNotificationPackagedInputRequest(value) {
  if (!plainRecord(value) || !plainRecord(value.database)) throw blocked('REQUEST');
  const result = requestSchema.safeParse(value);
  if (!result.success) throw blocked('REQUEST');
  const input = result.data;
  if (
    input.deliveryMountDirectory &&
    !input.deliveryMountDirectory.startsWith(input.runRoot + '/data/')
  )
    throw blocked('DELIVERY_ROOT');
  const owner = new URL(input.database.installationUrl),
    runtime = new URL(input.database.runtimeUrl);
  if (
    input.minimumRemainingMs > input.validityMs ||
    owner.username === runtime.username ||
    runtime.username !== 'openpc_configuration_runtime' ||
    owner.host !== runtime.host ||
    owner.pathname !== runtime.pathname
  )
    throw blocked('REQUEST');
  return input;
}

/** Pure arithmetic over actual owner observations. Never a freshness grant;
 * preparation/current SQL and each actual recipient use recheck their owners. */
export function notificationPackagedValidity(value) {
  if (
    !plainRecord(value) ||
    !Array.isArray(value.certificates) ||
    !value.certificates.every(plainRecord)
  )
    throw blocked('LIFETIME');
  const parsed = z
    .strictObject({
      databaseNowMs: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
      validityMs: requestSchema.shape.validityMs,
      minimumRemainingMs: requestSchema.shape.minimumRemainingMs,
      certificates: z
        .array(
          z.strictObject({
            validFromMs: z.number().int().min(0),
            validUntilMs: z.number().int().min(0),
          }),
        )
        .min(1)
        .max(40),
    })
    .safeParse(value);
  if (!parsed.success) throw blocked('LIFETIME');
  const { databaseNowMs: now, validityMs, minimumRemainingMs, certificates } = parsed.data;
  const validUntilMs = Math.min(now + validityMs, ...certificates.map((c) => c.validUntilMs));
  if (
    certificates.some((c) => c.validFromMs > now || c.validUntilMs <= c.validFromMs) ||
    !Number.isSafeInteger(validUntilMs) ||
    validUntilMs - now < minimumRemainingMs
  )
    throw blocked('LIFETIME');
  return Object.freeze({ validFromMs: now, validUntilMs });
}

async function ownedFile(file, maximum) {
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
    if (!bytesRead || bytesRead > maximum || bytesRead !== info.size) throw blocked('ROOT');
    return Buffer.from(bytes.subarray(0, bytesRead));
  } finally {
    bytes.fill(0);
    await handle.close();
  }
}
async function ownedRoot(input) {
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
  const info = await stat(input.runRoot);
  if (
    (await realpath(input.runRoot)) !== input.runRoot ||
    !info.isDirectory() ||
    info.uid !== process.getuid() ||
    info.mode & 0o077
  )
    throw blocked('ROOT');
  const sentinel = await ownedFile(join(input.runRoot, '.openpc-local-runtime-owner'), 256);
  const owner = /^openpc-local-runtime:(openpc-local-e2e-[0-9a-f]{12}):([0-9a-f]{64})\n$/u.exec(
    sentinel.toString(),
  );
  if (!owner || owner[1] !== `openpc-local-e2e-${owner[2].slice(0, 12)}`) throw blocked('ROOT');
  const identity = { root: input.runRoot, project: owner[1], token: owner[2] };
  const binding = validateStoredBinding(
    parseNotificationPackagedNetworkJson(
      await ownedFile(join(input.runRoot, 'data/local-runtime-network.json'), 262144),
    ),
    identity,
  );
  // Existing read-only command authenticates the live ancestor/FD8/FD9 owner.
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
  if ((await realpath(join(input.runRoot, 'data'))) !== join(input.runRoot, 'data'))
    throw blocked('ROOT');
  return binding;
}
async function reservePort() {
  const server = createServer();
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '0.0.0.0', resolve);
    });
    return {
      port: server.address().port,
      close: () =>
        new Promise((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve())),
        ),
    };
  } catch (error) {
    server.close();
    throw error;
  }
}
async function settle(actions) {
  const failures = [];
  for (const action of actions) {
    try {
      await action();
    } catch {
      failures.push(blocked('CLEANUP_UNKNOWN'));
    }
  }
  if (failures.length)
    throw new AggregateError(failures, 'BLOCKED_NOTIFICATION_INPUTS_CLEANUP_UNKNOWN');
}

/** @typedef {Object} NotificationPackagedPreparation
 * @property {ReadonlyArray<{channel: string, destinationRef: string, credentialRef: string, channelProfileDigest: string}>} destinations
 * @property {number} validUntilMs
 * @property {() => Promise<void>} assertCurrent Read-only SQL, profile and root checks; no mTLS admission claim.
 * @property {() => ReturnType<typeof prepareNotificationPackagedRuntime>} prepareRuntime Exactly once, in this process.
 * @property {() => Promise<void>} close Await after runBrowser; preserves every journal, row and UNKNOWN outcome.
 */

/** Own fresh external TEST material and bounded pools for the FOUR-file caller.
 * Privileged initial workload trust uses the established local bootstrap's
 * principal/WORKLOAD_MTLS schema. It never seeds an actor grant, authentication
 * occurrence, channel verification, endpoint, approval or execution result.
 * Actual channel installation remains prepareNotificationRuntimeFixtures ->
 * installInitialNotificationChannel(client, installation). Physical exports
 * remain withNotificationSecretRecipient(real peer, current installed row).
 *
 * A durable exclusive directory prevents a second process from recreating a
 * provider after lost/revoked state. This owner has no retained-provider restore.
 * API restart reuses the same result/physical providers. Root owns shared
 * network, databases, browser grants/signers, Compose and retained disposition.
 * @returns {Promise<NotificationPackagedPreparation>}
 */
export async function prepareNotificationPackagedInputs(value) {
  const input = validateNotificationPackagedInputRequest(value);
  let stage = 'ROOT',
    runtime,
    runtimePromise,
    closing,
    closed = false;
  const buffers = new Set(),
    providers = [],
    temporaryTls = [],
    reservations = [];
  const installationPool = new Pool({
    ...boundedPool,
    connectionString: input.database.installationUrl,
  });
  const runtimePool = new Pool({ ...boundedPool, connectionString: input.database.runtimeUrl });
  const keep = (buffer) => {
    buffers.add(buffer);
    return buffer;
  };
  async function releaseReservations() {
    await settle(reservations.splice(0).map((r) => () => r.close()));
  }
  const cleanupInputs = async () => {
    closed = true;
    try {
      await settle([
        ...providers.map((provider) => () => provider.close()),
        releaseReservations,
        ...temporaryTls.splice(0).map((tls) => () => tls.close()),
        () => installationPool.end(),
        () => runtimePool.end(),
      ]);
    } finally {
      for (const bytes of buffers) bytes.fill(0);
    }
  };
  const close = () => {
    closing ??= (async () => {
      let first;
      // A post-construction current-state failure may reject the preparation
      // promise while leaving a real runtime to close. Always visit that owner.
      if (runtimePromise) {
        try {
          await runtimePromise;
        } catch {
          first = blocked('COMPOSITION');
        }
      }
      try {
        await runtime?.close();
      } catch (error) {
        // FOUR owns active requests. Do not erase their inputs behind its back.
        if (error.message === 'BLOCKED_NOTIFICATION_PACKAGED_BROWSER_ACTIVE_CLEANUP_UNKNOWN')
          throw error;
        first = blocked('COMPOSITION_CLEANUP_UNKNOWN');
      }
      try {
        await cleanupInputs();
      } catch (error) {
        if (first)
          throw new AggregateError([first, error], 'BLOCKED_NOTIFICATION_INPUTS_CLEANUP_UNKNOWN');
        throw error;
      }
      if (first) throw first;
    })();
    return closing.catch((error) => {
      if (error.message === 'BLOCKED_NOTIFICATION_PACKAGED_BROWSER_ACTIVE_CLEANUP_UNKNOWN')
        closing = undefined;
      throw error;
    });
  };
  try {
    const binding = await ownedRoot(input);
    stage = 'DATABASE_ROLE';
    const role = await installationPool.query(
      "select pg_has_role(current_user,'openpc_control_owner','USAGE') allowed",
    );
    const runtimeRole = await runtimePool.query(
      'select current_user name,rolsuper,rolbypassrls from pg_roles where rolname=current_user',
    );
    if (
      role.rows[0]?.allowed !== true ||
      runtimeRole.rowCount !== 1 ||
      runtimeRole.rows[0].name !== 'openpc_configuration_runtime' ||
      runtimeRole.rows[0].rolsuper ||
      runtimeRole.rows[0].rolbypassrls
    )
      throw blocked(stage);
    const scope = Object.freeze({
      participantId: input.participantId,
      privacyDomainId: input.privacyDomainId,
    });
    const scoped = (use) =>
      runScopedTransaction(
        runtimePool,
        { ...scope, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
        localOperationId,
        use,
      );
    stage = 'ACTIVE_SCOPE';
    await scoped(async (client) => {
      const row = await client.query(
        "select 1 from control.participant p join control.privacy_domain d using(participant_id) where p.participant_id=$1 and d.privacy_domain_id=$2 and p.state='ACTIVE' and d.state='ACTIVE'",
        [scope.participantId, scope.privacyDomainId],
      );
      if (row.rowCount !== 1) throw blocked('ACTIVE_SCOPE');
    });
    // No existing row/provider is reconstructed. Even a failed fresh attempt
    // retains this claim and its initial trust for the root's reconciliation.
    stage = 'FRESH_OWNER';
    await mkdir(join(input.runRoot, 'data/notification-inputs'), { mode: 0o700 });
    const workload = {
      principalId: localOperationId(),
      workloadCredentialId: localOperationId(),
      workloadId: `urn:openpc:workload:${localOperationId()}`,
      workloadEpoch: '1',
    };
    async function tlsFixture(san, serverName) {
      const tls = await runtimeSnapshotTlsFixture(san, serverName);
      temporaryTls.push(tls);
      for (const bytes of [tls.certificate, tls.privateKey, ...Object.values(tls.server)])
        keep(bytes);
      // Generation uses the existing helper's private temporary directory only.
      // Remove generation files before any provider exists; no material-file fallback.
      await tls.close();
      temporaryTls.splice(temporaryTls.indexOf(tls), 1);
      return tls;
    }
    stage = 'TLS_GENERATION';
    const peer = await tlsFixture(
      `urn:openpc:participant:${scope.participantId}:workload:${workload.workloadId.slice(-36)}`,
      'notification-transport',
    );
    const outbound = [];
    for (let index = 0; index < input.channels.length; index++)
      outbound.push(
        await tlsFixture(
          `urn:openpc:test:notification-gateway:${localOperationId()}`,
          `notification-gateway-${index}`,
        ),
      );
    stage = 'LIFETIME';
    const now = await scoped(notificationDatabaseTime);
    const lifetime = notificationPackagedValidity({
      databaseNowMs: now,
      validityMs: input.validityMs,
      minimumRemainingMs: input.minimumRemainingMs,
      certificates: [peer, ...outbound].flatMap((tls) =>
        [tls.certificate, tls.server.certificate, tls.server.ca].map((bytes) => {
          const cert = new X509Certificate(bytes);
          return {
            validFromMs: Date.parse(cert.validFrom),
            validUntilMs: Date.parse(cert.validTo),
          };
        }),
      ),
    });
    function signer() {
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      return {
        privateKey: keep(pair.privateKey.export({ format: 'der', type: 'pkcs8' })),
        spki: pair.publicKey.export({ format: 'der', type: 'spki' }),
      };
    }
    stage = 'PROFILES';
    const entries = [];
    for (let index = 0; index < outbound.length; index++) {
      const tls = outbound[index],
        issuer = signer(),
        gateway = signer(),
        verification = signer();
      const privateDer = createPrivateKey(tls.privateKey).export({ format: 'der', type: 'pkcs8' });
      let material;
      try {
        material = encodeCbor(
          new Map([
            [0, notificationCredentialEncoding],
            [1, privateDer],
            [2, [tls.parsed.raw, new X509Certificate(tls.server.ca).raw]],
            [3, [new X509Certificate(tls.server.ca).raw]],
          ]),
        );
      } finally {
        privateDer.fill(0);
        tls.privateKey.fill(0);
      }
      const credential = {
        ...scope,
        credentialRef: `urn:openpc:resource:${localOperationId()}`,
        destinationRef: `urn:openpc:resource:${localOperationId()}`,
        channel: input.channels[index],
        owner: 'LS-NOTIFICATION',
        secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
        reference: `secret://local/notification-packaged-${localOperationId()}#1`,
        version: '1',
        epoch: '1',
        fingerprint: sha256(material),
        ...lifetime,
        state: 'ACTIVE',
      };
      let provider;
      try {
        provider = createTestNotificationCredentialProvider(credential, material);
      } finally {
        material.fill(0);
      }
      providers.push(provider);
      const reservation = await reservePort();
      reservations.push(reservation);
      const transport = {
        protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
        channel: credential.channel,
        credentialRef: credential.credentialRef,
        destinationRef: credential.destinationRef,
        endpoint: `https://notification-gateway-${index}:${reservation.port}/`,
        addresses: [binding.gateway],
        serverSpkiDigest: sha256(
          new X509Certificate(tls.server.certificate).publicKey.export({
            format: 'der',
            type: 'spki',
          }),
        ),
        requestTimeoutMs: 10000,
        maxPayloadBytes: 65536,
      };
      const channel = signNotificationClaim(
        'NotificationChannelProfileV1',
        issuer.privateKey,
        issuer.spki,
        {
          ...scope,
          environmentId: input.environmentId,
          profileId: localOperationId(),
          revision: '1',
          ...lifetime,
          transportProfileDigest: sha256(transport),
          receiptSignerSpki: gateway.spki.toString('hex'),
          issuerKeyId: evidenceKeyId(issuer.spki),
        },
      );
      const trust = {
        ...scope,
        environmentId: input.environmentId,
        signedProfileDigest: sha256(channel.cose),
        issuerSpkiHex: issuer.spki.toString('hex'),
      };
      const proof = signNotificationClaim(
        'NotificationVerificationProfileV1',
        issuer.privateKey,
        issuer.spki,
        {
          ...scope,
          environmentId: input.environmentId,
          profileId: localOperationId(),
          revision: '1',
          ...lifetime,
          signedChannelProfileDigest: trust.signedProfileDigest,
          credentialBindingDigest: sha256(credential),
          verificationSignerSpki: verification.spki.toString('hex'),
          issuerKeyId: evidenceKeyId(issuer.spki),
        },
      );
      issuer.privateKey.fill(0);
      entries.push({
        fixture: {
          installation: {
            credential,
            ...workload,
            channelTrust: trust,
            channelSigned: {
              transport,
              payloadHex: channel.payload.toString('hex'),
              coseHex: channel.cose.toString('hex'),
            },
            verification: {
              trust: { ...trust, signedProfileDigest: sha256(proof.cose) },
              signed: {
                payloadHex: proof.payload.toString('hex'),
                coseHex: proof.cose.toString('hex'),
              },
            },
            admissionReference: 'OpenPC local initial notification packaged trust',
          },
          provider,
          journalPath: join(
            input.runRoot,
            'evidence/notification-browser',
            `gateway-${credential.credentialRef.slice(-36)}.jsonl`,
          ),
          gatewayTls: {
            ca: tls.server.ca,
            cert: tls.server.certificate,
            key: tls.server.privateKey,
          },
          gatewaySignerPrivateKey: gateway.privateKey,
          gatewaySignerSpki: gateway.spki,
          verificationSignerPrivateKey: verification.privateKey,
          verificationSignerSpki: verification.spki,
          clientSpkiDigest: sha256(tls.parsed.publicKey.export({ format: 'der', type: 'spki' })),
          network: {
            addresses: [binding.gateway],
            advertisedOrigin: transport.endpoint,
            listenHost: '0.0.0.0',
          },
        },
        workloadTls: {
          ca: peer.server.ca,
          certificate: peer.certificate,
          privateKey: peer.privateKey,
        },
      });
    }
    const peerPort = await reservePort();
    reservations.push(peerPort);
    const pin = sha256(
      new X509Certificate(peer.server.certificate).publicKey.export({
        format: 'der',
        type: 'spki',
      }),
    );
    const runtimeInput = {
      runRoot: input.runRoot,
      containerRoot: input.containerRoot,
      installationPool,
      runtimePool,
      entries,
      provider: {
        tls: peer.server,
        leaseMs: 10000,
        network: {
          advertisedAddress: binding.gateway,
          listenHost: '0.0.0.0',
          serverName: 'notification-transport',
          serverSpkiDigest: pin,
        },
      },
      control: {
        tls: peer.server,
        listen: { host: '0.0.0.0', port: input.controlListenPort },
        peer: {
          host: '127.0.0.1',
          port: peerPort.port,
          serverName: 'notification-transport',
          serverSpkiDigest: pin,
        },
        connectionLifetimeMs: 300000,
      },
      timeoutMs: 10000,
    };
    validateNotificationPackagedInputs(runtimeInput);
    stage = 'INITIAL_WORKLOAD';
    const client = await installationPool.connect();
    try {
      await client.query('begin');
      await lockAuthorityFence(client, scope.participantId, {
        participant: [{ id: scope.participantId }],
        privacy_domain: [{ id: scope.privacyDomainId }],
      });
      const active = await client.query(
        "select 1 from control.participant p join control.privacy_domain d using(participant_id) where p.participant_id=$1 and d.privacy_domain_id=$2 and p.state='ACTIVE' and d.state='ACTIVE'",
        [scope.participantId, scope.privacyDomainId],
      );
      if (active.rowCount !== 1) throw blocked('ACTIVE_SCOPE');
      // Same fresh initial trust as business-signing-bootstrap/fact installation;
      // never UPDATE, UPSERT, reactivate, grant policy or manufacture mTLS admission.
      await client.query(
        "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Local notification packaged initial trust','ACTIVE',1)",
        [workload.principalId, scope.participantId],
      );
      const spki = peer.parsed.publicKey.export({ format: 'der', type: 'spki' });
      await client.query(
        "insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until) values($1,$2,$3,'WORKLOAD_MTLS','local-evidence-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)",
        [
          workload.workloadCredentialId,
          scope.participantId,
          workload.principalId,
          peer.parsed.subjectAltName.slice(4),
          workload.workloadId,
          Buffer.from(sha256(spki).slice(7), 'hex'),
          spki,
          Buffer.from(sha256(peer.parsed.raw).slice(7), 'hex'),
          new Date(peer.parsed.validFrom),
          new Date(peer.parsed.validTo),
        ],
      );
      await client.query('commit');
    } catch {
      try {
        await client.query('rollback');
      } catch {
        throw new AggregateError(
          [blocked('INITIAL_WORKLOAD'), blocked('ROLLBACK_UNKNOWN')],
          'BLOCKED_NOTIFICATION_INPUTS_INITIAL_WORKLOAD_AND_ROLLBACK_UNKNOWN',
        );
      }
      throw blocked('INITIAL_WORKLOAD');
    } finally {
      client.release();
    }
    async function assertCurrent() {
      if (closed) throw blocked('CLOSED');
      const currentBinding = await ownedRoot(input);
      if (canonicalJson(currentBinding) !== canonicalJson(binding))
        throw blocked('NETWORK_CHANGED');
      validateNotificationPackagedInputs(runtimeInput);
      await scoped(async (connection) => {
        const current = await notificationDatabaseTime(connection);
        if (lifetime.validUntilMs - current < input.minimumRemainingMs) throw blocked('LIFETIME');
        const selected = await connection.query(
          `select c.subject,c.audience,c.public_key_spki_der,c.secret_fingerprint,floor(extract(epoch from c.valid_until)*1000)::text valid_until_ms from control.credential c join control.principal p using(participant_id,principal_id) join control.participant a using(participant_id) join control.privacy_domain d using(participant_id)
          where c.participant_id=$1 and d.privacy_domain_id=$2 and c.principal_id=$3 and c.credential_id=$4 and c.credential_epoch=1 and c.kind='WORKLOAD_MTLS' and p.kind='WORKLOAD' and c.state='ACTIVE' and p.state='ACTIVE' and a.state='ACTIVE' and d.state='ACTIVE' and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()`,
          [
            scope.participantId,
            scope.privacyDomainId,
            workload.principalId,
            workload.workloadCredentialId,
          ],
        );
        const row = selected.rows[0];
        if (
          selected.rowCount !== 1 ||
          Number(row.valid_until_ms) - current < input.minimumRemainingMs ||
          row.subject !== peer.parsed.subjectAltName.slice(4) ||
          row.audience !== workload.workloadId ||
          !row.public_key_spki_der.equals(
            peer.parsed.publicKey.export({ format: 'der', type: 'spki' }),
          ) ||
          !row.secret_fingerprint.equals(Buffer.from(sha256(peer.parsed.raw).slice(7), 'hex'))
        )
          throw blocked('CURRENT_WORKLOAD');
        if (runtime)
          for (const { fixture } of entries) {
            const actual = await currentNotificationChannel(
              connection,
              scope,
              fixture.installation.credential.credentialRef,
            );
            if (canonicalJson(actual.installation) !== canonicalJson(fixture.installation))
              throw blocked('CURRENT_INSTALLATION');
          }
      });
    }
    stage = 'CURRENT_WORKLOAD';
    await assertCurrent();
    return Object.freeze({
      destinations: immutableJsonCopy(
        entries.map(({ fixture }) => ({
          channel: fixture.installation.credential.channel,
          destinationRef: fixture.installation.credential.destinationRef,
          credentialRef: fixture.installation.credential.credentialRef,
          channelProfileDigest: fixture.installation.channelTrust.signedProfileDigest,
        })),
      ),
      validUntilMs: lifetime.validUntilMs,
      assertCurrent,
      prepareRuntime() {
        if (closed || closing) return Promise.reject(blocked('CLOSED'));
        runtimePromise ??= (async () => {
          await assertCurrent();
          await releaseReservations();
          const delivery = input.deliveryMountDirectory
            ? await prepareNotificationPackagedDeliveryMount({
                directory: input.deliveryMountDirectory,
                containerRoot: '/app/notification-delivery',
                participantId: input.participantId,
                privacyDomainId: input.privacyDomainId,
              })
            : undefined;
          runtime = await prepareNotificationPackagedRuntime(runtimeInput);
          await assertCurrent();
          return delivery
            ? Object.freeze({
                ...runtime,
                mounts: Object.freeze([...runtime.mounts, ...delivery.mounts]),
                environment: Object.freeze({ ...runtime.environment, ...delivery.environment }),
              })
            : runtime;
        })();
        return runtimePromise;
      },
      close,
    });
  } catch (error) {
    const first = error.message?.startsWith('BLOCKED_NOTIFICATION_INPUTS_')
      ? error
      : blocked(stage);
    try {
      await cleanupInputs();
    } catch (cleanup) {
      throw new AggregateError(
        [first, cleanup],
        'BLOCKED_NOTIFICATION_INPUTS_PREPARATION_AND_CLEANUP_UNKNOWN',
      );
    }
    throw first;
  }
}
