import { z } from 'zod';
import { createHash, randomBytes } from 'node:crypto';
import { buildLocalWorkloadMtlsService } from '../../services/identity-service/src/domain/local-workload-mtls.ts';
import {
  assertInstalledSecretRecipientNotRevoked,
  withInstalledSecretRecipient,
} from '../../services/identity-service/src/domain/secret-recipient.ts';
import { createTestFactSecretDelivery } from './test-fact-secret-delivery.mjs';
import { reserveTestFactDatabaseLease } from './test-fact-database-lease.mjs';
import {
  createOperationsSecretResolutionObserver,
  operationsSecretObservationPath,
} from '../../services/identity-service/src/domain/operations-secret-resolution.ts';

const requestSchema = z.strictObject({
  operation: z.enum(['PUBLISH', 'CHECK']),
  reference: z.string().min(1).max(512),
  version: z.string().min(1).max(128),
  expected: z.strictObject({
    signedBindingDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    installationDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    generation: z
      .string()
      .max(20)
      .regex(/^[1-9][0-9]*$/u),
    participantId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    workloadCredentialId: z.uuidv7(),
    workloadCredentialEpoch: z
      .string()
      .max(20)
      .regex(/^(0|[1-9][0-9]*)$/u),
  }),
});
export const testFactSecretConsumerPath = '/internal/v1/secrets/fact-candidate';
const unavailable = () => new Error('OPS_TEST_FACT_SECRET_CONSUMER_UNAVAILABLE');

/** Real TEST installation composition, not a readiness callback. The Rust Fact
 * entrypoint calls this mutually authenticated endpoint before reading its exact
 * tmpfs mount. The installer owns candidateAdminPool; the consumer never sees it.
 * Publication's existing startupAllowed:false is preserved: this separate owner
 * admits the exact reader login under current recipient fences and revokes it,
 * terminates its sessions and erases publication on failure, expiry or revocation.
 * Calls contain references only; responses contain no secret bytes or authority
 * booleans. Ordinary Fact business/action admission is still independently required.
 */
export async function createTestFactSecretConsumer(options) {
  const { pool, kernel, candidateAdminPool, tls, rootPath, reference, version, syntheticMaterial } =
    options;
  const installed = Object.freeze({
    ...options.installed,
    issuerSpkiDer: Buffer.from(options.installed.issuerSpkiDer),
  });
  // Validate real TLS material before reserving a database role or publication.
  let app;
  try {
    app = buildLocalWorkloadMtlsService(pool, kernel, tls);
  } catch (primary) {
    try {
      options.operationsObservation?.owner.release(true);
    } catch {
      process.stderr.write('OPS_TEST_FACT_SECRET_CONSUMER_CLEANUP|UNKNOWN|CONSTRUCTION\n');
    }
    throw primary;
  }
  let delivery, lease, observer, observerPending;
  try {
    lease = await reserveTestFactDatabaseLease(candidateAdminPool);
    delivery = createTestFactSecretDelivery({
      pool,
      kernel,
      installed,
      rootPath,
      reference,
      version,
      syntheticMaterial,
    });
    // Issued by this actual single-version TEST provider instance. This is
    // neither a material hash nor a hash of a caller's ref/version assertion.
    // A recreated provider issues a different opaque version identity. Exposed
    // only to trusted installer composition, never the secret HTTP response.
    const resolvedVersion = Object.freeze({
      referenceFingerprint: `sha256:${createHash('sha256').update(reference).digest('hex')}`,
      version,
      fingerprint: `sha256:${randomBytes(32).toString('hex')}`,
    });
    app.decorate('operationsSecretResolutionDescriptor', resolvedVersion);
    if (options.operationsObservation !== undefined) {
      // Distinct observation endpoint: secret PUBLISH/CHECK wire, publication,
      // lease admission and cleanup remain owned by the original C1 path. The
      // host installs the real consumer PID/start association during startup;
      // absence at first observation fails closed, never fabricates a process.
      app.decorate('startOperationsSecretResolution', async () => {
        if (closed) throw new Error('OPS_SECRET_OBSERVATION_REJECTED');
        observerPending ??= createOperationsSecretResolutionObserver({
          ...options.operationsObservation,
          pool,
          kernel,
          candidateAdminPool,
          resolvedVersion,
        });
        observer = await observerPending;
      });
      app.post(operationsSecretObservationPath, async (request, reply) => {
        try {
          if (!observer) throw new Error('OPS_SECRET_OBSERVATION_REJECTED');
          return await observer.request(request.raw.socket, request.body);
        } catch {
          return reply.code(403).send({ code: 'OPS_SECRET_OBSERVATION_REJECTED' });
        }
      });
      // Trusted installer composition only; no HTTP readiness/authority API.
      app.decorate('withCurrentOperationsSecretResolution', async (use) => {
        if (!observer) throw new Error('OPS_SECRET_OBSERVATION_REJECTED');
        return observer.withCurrent(use);
      });
    }
  } catch (primary) {
    const cleanup = await Promise.allSettled([
      app.close(),
      lease?.close(),
      observer?.close(),
      Promise.resolve().then(() => delivery?.dispose()),
      Promise.resolve().then(() => {
        if (!observerPending) options.operationsObservation?.owner.release(true);
      }),
    ]);
    if (cleanup.some((result) => result.status === 'rejected')) {
      // Preserve the original construction failure and separately retain the
      // unresolved database owner; never print the underlying SQL exception.
      try {
        process.stderr.write('OPS_TEST_FACT_SECRET_CONSUMER_CLEANUP|UNKNOWN|CONSTRUCTION\n');
      } catch {
        /* The primary construction failure remains authoritative. */
      }
    }
    throw primary;
  }
  let closed = false,
    published = false,
    timer,
    expiryTimer,
    monitorPending,
    cleanup;
  let queue = Promise.resolve();
  function serialized(run) {
    const next = queue.then(run);
    queue = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }
  async function stop() {
    closed = true;
    clearTimeout(timer);
    clearTimeout(expiryTimer);
    cleanup ??= (async () => {
      const results = await Promise.allSettled([
        lease.close(),
        Promise.resolve().then(() => delivery.dispose()),
        Promise.resolve().then(async () => {
          if (observerPending) await (await observerPending.catch(() => undefined))?.close();
          else options.operationsObservation?.owner.release(true);
        }),
      ]);
      if (results.some((result) => result.status === 'rejected'))
        throw new Error('OPS_TEST_FACT_SECRET_CONSUMER_CLEANUP_UNKNOWN');
    })();
    return cleanup;
  }
  function monitor() {
    if (closed) return;
    timer = setTimeout(() => {
      monitorPending = serialized(async () => {
        if (closed) return;
        try {
          await assertInstalledSecretRecipientNotRevoked(pool, installed);
          if (delivery.describe().publicationState !== 'PUBLISHED') throw unavailable();
        } catch {
          await stop();
        }
      }).finally(() => {
        if (!closed) monitor();
      });
      // A failure is retained by cleanup and makes close() fail; no raw error escapes.
      monitorPending.catch(() => undefined);
    }, 1000);
    timer.unref();
  }
  app.post(testFactSecretConsumerPath, async (request, reply) => {
    const parsed = requestSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ code: 'OPS_SECRET_UNRESOLVED' });
    // These are equality constraints, never caller-supplied authority. Check
    // before publication/LOGIN; reply validation would discover a wrong local
    // installation only after its externally observable effects.
    if (Object.entries(parsed.data.expected).some(([name, value]) => installed[name] !== value))
      return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
    const descriptor = { reference: parsed.data.reference, version: parsed.data.version };
    try {
      // An unrelated rejected peer cannot tear down the installed consumer.
      await withInstalledSecretRecipient(
        pool,
        kernel,
        request.raw.socket,
        installed,
        descriptor,
        async () => undefined,
      );
    } catch {
      return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
    }
    try {
      const response = await serialized(async () => {
        if (closed || (parsed.data.operation === 'CHECK' && !published)) throw unavailable();
        try {
          if (parsed.data.operation === 'PUBLISH')
            await delivery.publish(request.raw.socket, descriptor);
          const result = await withInstalledSecretRecipient(
            pool,
            kernel,
            request.raw.socket,
            installed,
            descriptor,
            async (profile) => {
              if (!expiryTimer) {
                const expire = () => {
                  const remaining = profile.validUntilMs - Date.now();
                  if (remaining <= 0) {
                    void stop().catch(() => undefined);
                    return;
                  }
                  expiryTimer = setTimeout(expire, Math.min(remaining, 2_147_483_647));
                  expiryTimer.unref();
                };
                expire();
              }
              if (parsed.data.operation === 'PUBLISH') await lease.activate(profile);
              else await lease.check(profile);
              return {
                version: 1,
                signedBindingDigest: installed.signedBindingDigest,
                installationDigest: installed.installationDigest,
                generation: installed.generation,
                participantId: installed.participantId,
                privacyDomainId: installed.privacyDomainId,
                workloadCredentialId: installed.workloadCredentialId,
                workloadCredentialEpoch: installed.workloadCredentialEpoch,
                validUntilMs: profile.validUntilMs,
              };
            },
          );
          if (closed || delivery.describe().publicationState !== 'PUBLISHED') throw unavailable();
          if (!published) {
            published = true;
            monitor();
          }
          return result;
        } catch {
          await stop();
          throw unavailable();
        }
      });
      return response;
    } catch {
      return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
    }
  });
  app.addHook('onClose', async () => {
    closed = true;
    clearTimeout(timer);
    clearTimeout(expiryTimer);
    await queue;
    await monitorPending?.catch(() => undefined);
    await stop();
  });
  return app;
}
