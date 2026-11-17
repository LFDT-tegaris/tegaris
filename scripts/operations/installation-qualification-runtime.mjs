import { createHash, X509Certificate, createPrivateKey } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { Pool } from 'pg';
import Fastify from 'fastify';
import {
  readInstallationQualificationInputs,
  parseInstallationQualificationArguments,
} from './installation-qualification-inputs.mjs';
import {
  readQualificationObserverFile,
  qualificationObserverCommandSchema,
  qualificationObserverResponseSchema,
  qualificationObserverPath,
} from '../../services/identity-service/src/domain/qualification-observer-client.ts';
import {
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../services/identity-service/src/domain/identity-kernel.ts';
import { createQualificationDeploymentPeer } from '../../services/identity-service/src/domain/qualification-deployment-peer.ts';
import { withAuthenticatedWorkloadPeer } from '../../services/identity-service/src/domain/workload-peer.ts';
import { runScopedTransaction } from '../../services/identity-service/src/db/scoped-transaction.ts';
import { localOperationId } from '../../services/identity-service/src/domain/local-operation-id.ts';
import { readQualificationDeployment } from '../../services/control-api/src/configuration/operations/qualification-deployment-observation.ts';
import { readQualificationKeyAttempt } from '../../services/control-api/src/configuration/operations/qualification-key-custody.ts';
import {
  qualificationDeploymentDigest,
  parseQualificationDeploymentPins,
} from './qualification-deployment-observation.mjs';

const unavailable = () => new Error('QUALIFICATION_OBSERVER_UNAVAILABLE');
/** One admitted operation; no queue and no business authority. */
export function createQualificationObservationAdmission() {
  let stopping = false,
    current;
  return Object.freeze({
    async use(work) {
      if (stopping || current) throw unavailable();
      current = Promise.resolve().then(work);
      try {
        return await current;
      } finally {
        current = undefined;
      }
    },
    async stop() {
      stopping = true;
      await current?.catch(() => undefined);
    },
  });
}
async function protectedPool(file, role) {
  const raw = await readQualificationObserverFile(file, 8192);
  let pool;
  try {
    const connectionString = raw.toString('utf8').trim(),
      url = new URL(connectionString);
    if (
      !['postgres:', 'postgresql:'].includes(url.protocol) ||
      !url.hostname ||
      !url.username ||
      !url.password
    )
      throw unavailable();
    pool = new Pool({
      connectionString,
      max: 2,
      connectionTimeoutMillis: 2000,
      query_timeout: 5000,
      statement_timeout: 5000,
      idle_in_transaction_session_timeout: 5000,
      idleTimeoutMillis: 10000,
      allowExitOnIdle: true,
    });
    pool.on('error', () => {
      process.stderr.write('QUALIFICATION_OBSERVER|POOL_UNAVAILABLE\n');
    });
    const actual = await pool.query('select current_user::text role');
    if (actual.rows.length !== 1 || actual.rows[0].role !== role) throw unavailable();
    return pool;
  } catch {
    await pool?.end();
    throw unavailable();
  } finally {
    raw.fill(0);
  }
}
function originalResponse(original) {
  return qualificationObserverResponseSchema.parse({
    schemaVersion: 1,
    observationId: original.request.observationId,
    readback: 'HISTORICAL_ONLY',
    state: original.observation === null ? 'ORIGINAL_PENDING' : 'ORIGINAL_RETAINED',
    observationDigest:
      original.observation === null ? null : qualificationDeploymentDigest(original.observation),
  });
}
async function resources(input) {
  // The caller already owns the heavy reservation. Validate the real inherited
  // lock/cgroup/headroom/disk through the canonical entrypoint, not env booleans.
  await promisify(execFile)(
    'bash',
    [
      join(input.repositoryRoot, 'scripts/maintenance/run-bounded.sh'),
      '--memory-gib',
      String(input.resources.memoryGiB),
      '--external-memory-gib',
      String(input.resources.externalMemoryGiB),
      '--peak-disk-gib',
      String(input.resources.peakDiskGiB),
      '--reuse',
      '--',
      'true',
    ],
    { cwd: input.repositoryRoot, timeout: 10000, maxBuffer: 16384 },
  );
}

/** Host installation executable. No provider TLS/client key, key dispatch,
 * qualification, public business route, migration, bootstrap or role elevation. */
export async function startInstallationQualificationRuntime(inputFile, mode = '--serve', signal) {
  const checkRunning = () => {
    if (signal?.aborted) throw unavailable();
  };
  checkRunning();
  if (!['--serve', '--read-deployment-original', '--read-key-original'].includes(mode))
    throw unavailable();
  const input = await readInstallationQualificationInputs(inputFile);
  checkRunning();
  await resources(input);
  checkRunning();
  let owner, identity, app, closing, serverKey;
  const sockets = new Set(),
    admission = createQualificationObservationAdmission();
  const close = () => {
    closing ??= (async () => {
      let timer;
      const deadline = new Promise((_resolve, reject) => {
        timer = setTimeout(() => {
          for (const socket of sockets) socket.destroy();
          reject(unavailable());
        }, input.drainTimeoutMs);
      });
      try {
        const stopped = admission.stop();
        const httpClosed = app?.close();
        const outcomes = await Promise.race([Promise.allSettled([stopped, httpClosed]), deadline]);
        for (const socket of sockets) socket.destroy();
        const pools = await Promise.race([
          Promise.allSettled([owner?.end(), identity?.end()]),
          deadline,
        ]);
        if ([...outcomes, ...pools].some((v) => v.status === 'rejected')) throw unavailable();
      } finally {
        clearTimeout(timer);
        serverKey?.fill(0);
      }
    })();
    return closing;
  };
  try {
    owner = await protectedPool(input.ownerConnectionFile, 'openpc_operations_qualification_owner');
    checkRunning();
    const scoped = (fn) =>
      runScopedTransaction(
        owner,
        { ...input.deployment.selection, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
        localOperationId,
        fn,
      );
    if (mode === '--read-key-original') {
      if (!input.keyOriginal) throw unavailable();
      const original = await scoped((c) =>
        readQualificationKeyAttempt(c, input.keyOriginal.selection, input.keyOriginal.attemptId),
      );
      await close();
      return { original: { ...original, readback: 'HISTORICAL_ONLY' } };
    }
    if (mode === '--read-deployment-original') {
      const original = await scoped((c) =>
        readQualificationDeployment(
          c,
          input.deployment.selection,
          input.deployment.intent.observationId,
        ),
      );
      await close();
      return { original };
    }
    // Verify the actual installed source and table shape. Source withdrawal is
    // not erased by startup: future observe denies; authenticated history remains.
    const installed = await scoped(async (c) => {
      const r = await c.query(
        'select pins,pins_digest from control.qualification_deployment_installation where installation_id=$1 and participant_id=$2 and privacy_domain_id=$3',
        [
          input.deployment.selection.installationId,
          input.deployment.selection.participantId,
          input.deployment.selection.privacyDomainId,
        ],
      );
      if (r.rowCount !== 1) throw unavailable();
      const pins = parseQualificationDeploymentPins(r.rows[0].pins);
      if (qualificationDeploymentDigest(pins) !== r.rows[0].pins_digest) throw unavailable();
      await c.query(
        'select observation_id,request_digest from control.qualification_deployment_attempt where false',
      );
      await c.query(
        'select observation_id,observation_digest from control.qualification_deployment_observation where false',
      );
      return pins;
    });
    identity = await protectedPool(input.identityConnectionFile, 'openpc_identity_runtime');
    checkRunning();
    const kernel = new IdentityKernel(new PostgresIdentityRepository(identity));
    const peer = createQualificationDeploymentPeer({ ownerPool: owner, kernel });
    const certificate = await readQualificationObserverFile(input.tls.certificateFile, 16384);
    serverKey = await readQualificationObserverFile(input.tls.privateKeyFile, 16384);
    const ca = await readQualificationObserverFile(input.tls.caFile, 32768);
    const cert = new X509Certificate(certificate);
    if (
      !cert.checkPrivateKey(createPrivateKey(serverKey)) ||
      Date.parse(cert.validFrom) > Date.now() ||
      Date.parse(cert.validTo) <= Date.now()
    )
      throw unavailable();
    app = Fastify({
      logger: false,
      trustProxy: false,
      bodyLimit: 1024,
      requestTimeout: 35000,
      connectionTimeout: 40000,
      keepAliveTimeout: 1000,
      maxRequestsPerSocket: 1,
      https: {
        cert: certificate,
        key: serverKey,
        ca,
        requestCert: true,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        handshakeTimeout: 3000,
      },
    });
    app.server.maxConnections = 2;
    app.server.on('connection', (socket) => {
      sockets.add(socket);
      socket.once('close', () => sockets.delete(socket));
    });
    app.setErrorHandler((_error, _request, reply) =>
      reply.code(400).send({ code: 'QUALIFICATION_OBSERVER_UNAVAILABLE' }),
    );
    app.post(qualificationObserverPath, async (request, reply) => {
      try {
        const command = qualificationObserverCommandSchema.parse(request.body);
        if (
          command.observationId !== input.deployment.intent.observationId ||
          command.operationId !== input.deployment.intent.operationId ||
          request.raw.socket.remoteAddress?.replace(/^::ffff:/u, '') !== installed.address ||
          request.raw.socket.localAddress?.replace(/^::ffff:/u, '') !== input.listen.address
        )
          throw unavailable();
        return await admission.use(async () => {
          if (command.mode === 'OBSERVE')
            return originalResponse(
              await peer.observe(
                request.raw.socket,
                input.deployment.selection,
                input.deployment.intent,
              ),
            );
          // History is never an anonymous or arbitrary-scope remote read. Actual
          // TLS/current Identity and exact original peer remain mandatory.
          return withAuthenticatedWorkloadPeer(
            owner,
            kernel,
            request.raw.socket,
            async (c, actor, confirm) => {
              await confirm();
              const original = await readQualificationDeployment(
                c,
                input.deployment.selection,
                command.observationId,
              );
              const p = original.request.pins.peer,
                raw = request.raw.socket.getPeerCertificate(true).raw;
              if (
                original.request.operationId !== command.operationId ||
                !raw ||
                p.principalId !== actor.principalId ||
                p.credentialId !== actor.credentialId ||
                p.participantEpoch !== actor.participantEpoch ||
                p.principalEpoch !== actor.principalEpoch ||
                p.credentialEpoch !== actor.workloadEpoch ||
                p.workloadId !== actor.workloadId ||
                p.keyDigest !== actor.keyId ||
                p.certificateDigest !==
                  'sha256:' + createHash('sha256').update(raw).digest('hex') ||
                original.request.installationDigest !== qualificationDeploymentDigest(installed) ||
                request.raw.socket.remoteAddress?.replace(/^::ffff:/u, '') !==
                  original.request.pins.address ||
                request.raw.socket.localAddress?.replace(/^::ffff:/u, '') !== input.listen.address
              )
                throw unavailable();
              await confirm();
              return originalResponse(original);
            },
            input.deployment.selection,
          );
        });
      } catch {
        return reply.code(403).send({ code: 'QUALIFICATION_OBSERVER_UNAVAILABLE' });
      }
    });
    checkRunning();
    await app.listen({ host: input.listen.address, port: input.listen.port });
    checkRunning();
    return Object.freeze({ close });
  } catch {
    await close().catch(() => undefined);
    throw unavailable();
  }
}
async function main() {
  const args = parseInstallationQualificationArguments(process.argv.slice(2));
  const abort = new AbortController();
  let runtime = null,
    pending;
  const stop = () => {
    abort.abort();
    if (runtime && 'close' in runtime)
      pending ??= runtime.close().catch(() => {
        process.stderr.write('QUALIFICATION_OBSERVER|CLEANUP_UNKNOWN\n');
        process.exit(1);
      });
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
  runtime = await startInstallationQualificationRuntime(args.inputFile, args.mode, abort.signal);
  if (abort.signal.aborted) {
    stop();
    await pending;
    return;
  }
  if ('original' in runtime) {
    process.stdout.write(JSON.stringify(runtime.original) + '\n');
    return;
  }
  process.stdout.write('QUALIFICATION_OBSERVER|LISTENING|OBSERVATION_ONLY\n');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch(() => {
    process.stderr.write('QUALIFICATION_OBSERVER|UNAVAILABLE\n');
    process.exit(1);
  });
