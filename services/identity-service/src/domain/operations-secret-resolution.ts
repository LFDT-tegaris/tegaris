import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import type { TLSSocket } from 'node:tls';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../../../control-api/src/configuration/digest.js';
import {
  encodeOperationsSecretResolution,
  signOperationsSecretResolution,
  verifyOperationsSecretResolution,
  operationsSecretObservationDigest,
  parseOperationsSecretResolutionClaims,
  type OperationsSecretResolutionClaims,
} from '../../../../packages/security-kernel/src/operations-configuration/secret-resolution.js';
import { verifyInstalledSecretRecipient } from '../../../../packages/security-kernel/src/secret-recipient/profile.js';
import { withInstalledSecretRecipient } from './secret-recipient.js';
import {
  buildLocalWorkloadMtlsService,
  type LocalWorkloadMtlsOptions,
} from './local-workload-mtls.js';
import type { IdentityKernel } from './identity-kernel.js';
import { localOperationId } from './local-operation-id.js';
// Installation-owned JavaScript; never supplied by an HTTP request.
// @ts-expect-error The released JavaScript owner has no declaration-generation seam yet.
import * as installation from '../../../../scripts/operations/installation-secret-binding.mjs';
// @ts-expect-error The released JavaScript owner has no declaration-generation seam yet.
import * as projection from '../../../../scripts/operations/installation-effective-projection.mjs';
const {
  loadOperationsSecretAssociation,
  operationsSecretRecipientPins,
  assertOperationsProcessIdentity,
} = installation;

export const operationsSecretObservationPath = '/internal/v1/operations/secret-resolution';
const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const common = {
  associationId: uuid,
  consumerInstanceId: uuid,
};
const requestSchema = z.discriminatedUnion('phase', [
  z.strictObject({ ...common, phase: z.literal('CHALLENGE') }),
  z.strictObject({
    ...common,
    phase: z.literal('OBSERVE'),
    challengeId: uuid,
    backendPid: z.number().int().positive(),
    backendStart: z.string().min(1).max(64),
  }),
]);
const rejected = (): never => {
  throw new Error('OPS_SECRET_OBSERVATION_REJECTED');
};
// Internal fixed-stage diagnostics only; never include peer, SQL, input or key data.
async function observed<T>(
  stage: 'process' | 'source' | 'peer' | 'probe',
  use: () => Promise<T>,
): Promise<T> {
  try {
    return await use();
  } catch (error) {
    process.stderr.write(`OPS_SECRET_OBSERVATION|FAIL|${stage}\n`);
    throw error;
  }
}
const maxAgeMs = 30000;
const safeMs = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const probeRequestSchema = z.strictObject({
  backendPid: z.number().int().positive().max(2147483647),
  backendStart: z.string().regex(/^[0-9]{1,12}(?:\.[0-9]{1,6})?$/u),
});
const challengeSchema = z.strictObject({
  challengeId: uuid,
  key1: z.number().int().min(0).max(2147483647),
  key2: z.number().int().min(0).max(2147483647),
  issuedAtMs: safeMs,
  validUntilMs: safeMs,
});

/** Pure transport boundary. No getter, extra success flag or caller-declared
 * process start can become an installed observation. */
export function parseOperationsSecretObservationRequest(input: unknown) {
  try {
    const value = requestSchema.parse(
      JSON.parse(projection.effectiveProjectionCanonicalJson(input)),
    );
    if (value.phase === 'OBSERVE')
      probeRequestSchema.parse({
        backendPid: value.backendPid,
        backendStart: value.backendStart,
      });
    return Object.freeze(value);
  } catch {
    return rejected();
  }
}
type Challenge = {
  challengeId: string;
  key1: number;
  key2: number;
  issuedAtMs: number;
  validUntilMs: number;
};
type ProbeRequest = { backendPid: number; backendStart: string };
type Probe = ProbeRequest & {
  clientAddress: string;
  databaseOid: string;
  roleOid: string;
  queryStart: string;
  query: string;
  key1: number;
  key2: number;
};

/** The query is independently constructed by BOTH producer and observer. A held
 * PostgreSQL transaction lock and idle-in-transaction query readback prove this
 * exact scoped read completed; caller return values and checked flags do not. */
export function operationsSecretProbeQuery(
  participantId: string,
  privacyDomainId: string,
  key1: number,
  key2: number,
): string {
  uuid.parse(participantId);
  uuid.parse(privacyDomainId);
  for (const key of [key1, key2])
    if (!Number.isInteger(key) || key < 0 || key > 2147483647) rejected();
  return `select pg_advisory_xact_lock(${key1},${key2}),exists(select 1 from candidate.fact_bridge_admission_v1 where participant_id='${participantId}'::uuid and privacy_domain_id='${privacyDomainId}'::uuid limit 1) from (select openpc.assert_request_context(true)) context where openpc.current_participant_id()='${participantId}'::uuid and openpc.current_privacy_domain_id()='${privacyDomainId}'::uuid and current_setting('transaction_read_only')='on' and current_setting('transaction_isolation')='repeatable read' and current_setting('row_security')='on' and current_user='openpc_fact_bridge_reader' and current_database()='openpc_candidate_index'`;
}

/** Privileged independent inspection of the candidate store. Does not connect
 * as the consumer, read secret bytes, set business state or manufacture a read. */
export async function inspectOperationsSecretProbe(
  pool: Pool,
  scope: { participantId: string; privacyDomainId: string; clientAddress: string },
  challenge: Challenge,
  request: ProbeRequest,
): Promise<Probe> {
  // Validate before touching PostgreSQL, including invalid JS numbers which
  // would otherwise make expiry comparisons silently evaluate false.
  challenge = challengeSchema.parse(challenge);
  z.ipv4().parse(scope.clientAddress);
  request = probeRequestSchema.parse({
    backendPid: request.backendPid,
    backendStart: request.backendStart,
  });
  if (
    challenge.validUntilMs <= challenge.issuedAtMs ||
    challenge.validUntilMs - challenge.issuedAtMs > maxAgeMs
  )
    rejected();
  const query = operationsSecretProbeQuery(
    scope.participantId,
    scope.privacyDomainId,
    challenge.key1,
    challenge.key2,
  );
  const result = await pool.query(
    `select a.pid,extract(epoch from a.backend_start)::text backend_start,extract(epoch from a.query_start)::text query_start,a.query,
    a.datid::text database_oid,a.usesysid::text role_oid,host(a.client_addr) client_address,
    floor(extract(epoch from a.backend_start)*1000)::text backend_ms,
    floor(extract(epoch from a.query_start)*1000)::text query_ms,
    floor(extract(epoch from clock_timestamp())*1000)::text now_ms
    from pg_stat_activity a join pg_roles r on r.oid=a.usesysid
    where a.pid=$1 and extract(epoch from a.backend_start)::text=$2 and a.datname='openpc_candidate_index'
    and a.client_addr=$6::inet
    and current_database()='openpc_candidate_index' and a.usename='openpc_fact_bridge_reader'
    and a.state='idle in transaction' and a.query=$3 and r.rolcanlogin
    and not(r.rolsuper or r.rolbypassrls or r.rolcreaterole or r.rolcreatedb or r.rolreplication)
    and r.rolvaliduntil>clock_timestamp() and not exists(select 1 from pg_auth_members where member=r.oid)
    and exists(select 1 from pg_locks l where l.pid=a.pid and l.database=a.datid and l.locktype='advisory'
      and l.classid=$4::oid and l.objid=$5::oid and l.objsubid=2 and l.mode='ExclusiveLock' and l.granted)`,
    [
      request.backendPid,
      request.backendStart,
      query,
      challenge.key1,
      challenge.key2,
      scope.clientAddress,
    ],
  );
  const row = result.rows[0];
  if (
    result.rowCount !== 1 ||
    !Number.isSafeInteger(Number(row.backend_ms)) ||
    !Number.isSafeInteger(Number(row.query_ms)) ||
    !Number.isSafeInteger(Number(row.now_ms)) ||
    Number(row.query_ms) < challenge.issuedAtMs ||
    Number(row.backend_ms) < challenge.issuedAtMs ||
    Number(row.backend_ms) > Number(row.query_ms) ||
    Number(row.query_ms) > Number(row.now_ms) ||
    Number(row.now_ms) >= challenge.validUntilMs
  )
    return rejected();
  return {
    backendPid: row.pid,
    backendStart: row.backend_start,
    clientAddress: row.client_address,
    databaseOid: row.database_oid,
    roleOid: row.role_oid,
    queryStart: row.query_start,
    query,
    key1: challenge.key1,
    key2: challenge.key2,
  };
}

export interface OperationsSecretObserverOptions {
  readonly owner: PoolClient;
  readonly pool: Pool;
  readonly candidateAdminPool: Pool;
  readonly kernel: IdentityKernel;
  readonly associationId: string;
  readonly installationScope: { readonly participantId: string; readonly privacyDomainId: string };
  readonly resolvedVersion: Readonly<{
    referenceFingerprint: string;
    version: string;
    fingerprint: string;
  }>;
  readonly issuerPrivateKey: Buffer;
}

/** The caller keeps this dedicated installed observer connection exclusively.
 * Lease loss is terminal. withCurrent revalidates actual process/DB proof and
 * cryptography around the caller's same-transaction generation operation.
 * The SQL framing function or saved receipt cannot replace this live owner.
 * No cross-database atomicity is claimed; both external observations bracket
 * the Control transaction, and any failure rolls back and fences the owner. */
export async function createOperationsSecretResolutionObserver(
  options: OperationsSecretObserverOptions,
) {
  const { owner, pool, candidateAdminPool, kernel } = options;
  let association;
  let key = Buffer.alloc(0);
  try {
    uuid.parse(options.associationId);
    uuid.parse(options.installationScope.participantId);
    uuid.parse(options.installationScope.privacyDomainId);
    if (!Buffer.isBuffer(options.issuerPrivateKey)) rejected();
    key = Buffer.from(options.issuerPrivateKey);
    await owner.query('begin isolation level read committed');
    await owner.query('set local role openpc_control_owner');
    await owner.query("set local statement_timeout='5s'");
    await owner.query("set local lock_timeout='2s'");
    await owner.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
      [
        options.installationScope.participantId,
        options.installationScope.privacyDomainId,
        localOperationId(),
      ],
    );
    association = await loadOperationsSecretAssociation(owner, options.associationId);
    await owner.query('commit');
  } catch {
    key.fill(0);
    await owner.query('rollback').catch(() => undefined);
    owner.release(true);
    return rejected();
  }
  const a = association as OperationsSecretResolutionClaims & {
    issuerSpkiHex: string;
    issuerValidUntilMs: number;
    recipientPayloadHex: string;
    recipientCoseHex: string;
    reference: string;
    consumerProcess: { container: { address: string } };
    observerProcess: { pid: number };
    observerBackendPid: number;
    observerBackendStart: string;
  };
  const pins = operationsSecretRecipientPins(association);
  const probeScope = {
    participantId: a.participantId,
    privacyDomainId: a.privacyDomainId,
    clientAddress: a.consumerProcess.container.address,
  };
  const spki = Buffer.from(a.issuerSpkiHex, 'hex');
  let closed = false;
  let cleanupFailure: { cause: unknown } | undefined;
  let closing: Promise<void> | undefined;
  let challenge: Challenge | undefined;
  let current:
    | {
        challenge: Challenge;
        probe: Probe;
        claims: Readonly<OperationsSecretResolutionClaims>;
        payload: Buffer;
        cose: Buffer;
      }
    | undefined;
  let queue: Promise<unknown> = Promise.resolve();
  const onError = () => {
    closed = true;
    key.fill(0);
  };
  owner.on('error', onError);
  owner.on('end', onError);
  try {
    if (
      a.referenceFingerprint !== options.resolvedVersion.referenceFingerprint ||
      a.version !== options.resolvedVersion.version ||
      a.fingerprint !== options.resolvedVersion.fingerprint ||
      a.observerProcess.pid !== process.pid ||
      !createPublicKey(createPrivateKey({ key, format: 'der', type: 'pkcs8' }))
        .export({ format: 'der', type: 'spki' })
        .equals(spki)
    )
      rejected();
    const identity = await owner.query(
      'select pg_backend_pid() pid,openpc.operations_observer_backend_start() started',
    );
    if (
      identity.rows[0]?.pid !== a.observerBackendPid ||
      identity.rows[0]?.started !== a.observerBackendStart
    )
      rejected();
    const lease = await owner.query(
      "select pg_try_advisory_lock(hashtextextended('operations-secret-observer:'||$1,0)) held",
      [a.associationId],
    );
    if (lease.rows[0]?.held !== true) rejected();
  } catch {
    onError();
    owner.off('error', onError);
    owner.off('end', onError);
    owner.release(true);
    rejected();
  }
  async function source() {
    if (closed) rejected();
    await observed('process', () =>
      Promise.all([
        assertOperationsProcessIdentity(a.consumerProcess),
        assertOperationsProcessIdentity(a.observerProcess),
      ]),
    );
    const selected = await owner.query(
      'select openpc.operations_secret_association_bound($1) bound,floor(extract(epoch from clock_timestamp())*1000)::text now',
      [a.associationId],
    );
    if (selected.rows[0]?.bound !== true) {
      process.stderr.write('OPS_SECRET_OBSERVATION|FAIL|source-binding\n');
      rejected();
    }
    const now = Number(selected.rows[0].now);
    if (!Number.isSafeInteger(now) || now < 0) rejected();
    const recipient = verifyInstalledSecretRecipient(
      pins,
      Buffer.from(a.recipientPayloadHex, 'hex'),
      Buffer.from(a.recipientCoseHex, 'hex'),
      now,
    );
    if (closed) rejected();
    return {
      now,
      validUntilMs: Math.min(recipient.validUntilMs, a.issuerValidUntilMs, now + maxAgeMs),
    };
  }
  async function transaction<T>(use: () => Promise<T>): Promise<T> {
    if (closed) return rejected();
    try {
      await owner.query('begin isolation level read committed');
      await owner.query('set local role openpc_control_owner');
      await owner.query("set local statement_timeout='5s'");
      await owner.query("set local lock_timeout='2s'");
      await owner.query("set local idle_in_transaction_session_timeout='30s'");
      await owner.query('set local row_security=on');
      await owner.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        [a.participantId, a.privacyDomainId, localOperationId()],
      );
      const lock = await owner.query(
        "select pg_try_advisory_xact_lock(hashtextextended('operations-generation:'||$1,0)) held",
        [a.environmentId],
      );
      if (lock.rows[0]?.held !== true) rejected();
      const result = await use();
      await source();
      await owner.query('commit');
      return result;
    } catch {
      // Loss/ambiguity of an admitted source is terminal for this observer.
      // A retry cannot turn the old signature or proof back into currentness.
      onError();
      challenge = undefined;
      current = undefined;
      await owner.query('rollback').catch(() => undefined);
      throw new Error('OPS_SECRET_OBSERVATION_REJECTED');
    }
  }
  function serialized<T>(use: () => Promise<T>): Promise<T> {
    const next = queue.then(use);
    queue = next.catch(() => undefined);
    return next;
  }
  async function checkCurrent() {
    const active = current;
    if (!active) return rejected();
    const { now } = await source();
    if (now >= active.claims.validUntilMs) rejected();
    const claims = verifyOperationsSecretResolution(spki, active.payload, active.cose);
    if (canonicalJson(claims) !== canonicalJson(active.claims)) rejected();
    const actual = await inspectOperationsSecretProbe(
      candidateAdminPool,
      probeScope,
      active.challenge,
      active.probe,
    );
    if (canonicalJson(actual) !== canonicalJson(active.probe)) rejected();
    const stored = await owner.query(
      `select payload,cose,state from control.operations_secret_observation where observation_id=$1 and association_id=$2 for share`,
      [claims.challengeId, a.associationId],
    );
    if (
      stored.rowCount !== 1 ||
      stored.rows[0].state !== 'OBSERVED' ||
      !stored.rows[0].payload.equals(active.payload) ||
      !stored.rows[0].cose.equals(active.cose)
    )
      rejected();
    return active;
  }
  return Object.freeze({
    async request(socket: TLSSocket, input: unknown) {
      const request = parseOperationsSecretObservationRequest(input);
      if (
        request.associationId !== a.associationId ||
        request.consumerInstanceId !== a.consumerInstanceId ||
        socket.remoteAddress?.replace(/^::ffff:/u, '') !== probeScope.clientAddress
      )
        return rejected();
      // An unrelated rejected peer cannot invalidate this observer's source.
      await observed('peer', () =>
        withInstalledSecretRecipient(
          pool,
          kernel,
          socket,
          pins,
          { reference: a.reference, version: a.version },
          async () => undefined,
        ),
      );
      return serialized(() =>
        transaction(async () => {
          // Environment lock is acquired first. Existing Identity/recipient fences
          // remain held during observation, with their own post-use revalidation.
          return withInstalledSecretRecipient(
            pool,
            kernel,
            socket,
            pins,
            { reference: a.reference, version: a.version },
            async () => {
              const timing = await observed('source', source);
              if (request.phase === 'CHALLENGE') {
                if (challenge && timing.now < challenge.validUntilMs) rejected();
                const entropy = randomBytes(8);
                challenge = {
                  challengeId: localOperationId(),
                  key1: entropy.readUInt32BE(0) & 0x7fffffff,
                  key2: entropy.readUInt32BE(4) & 0x7fffffff,
                  issuedAtMs: timing.now,
                  validUntilMs: timing.validUntilMs,
                };
                return { version: 1, ...challenge, consumerStartedAtMs: a.consumerStartedAtMs };
              }
              const pending = challenge;
              challenge = undefined;
              if (
                !pending ||
                pending.challengeId !== request.challengeId ||
                timing.now >= pending.validUntilMs
              )
                rejected();
              const admitted = pending!;
              const probe = await observed('probe', () =>
                inspectOperationsSecretProbe(candidateAdminPool, probeScope, admitted, request),
              );
              const names = [
                'environmentId',
                'participantId',
                'privacyDomainId',
                'associationId',
                'operationsInstallationDigest',
                'candidateDigest',
                'generationId',
                'recipientBindingDigest',
                'recipientInstallationDigest',
                'recipientGeneration',
                'field',
                'consumerId',
                'storeId',
                'referenceFingerprint',
                'version',
                'fingerprint',
                'principalId',
                'workloadCredentialId',
                'workloadCredentialEpoch',
                'consumerInstanceId',
                'consumerStartedAtMs',
                'observerInstanceId',
                'observerStartedAtMs',
                'issuerKeyId',
                'issuerEpoch',
              ] as const;
              const claims = parseOperationsSecretResolutionClaims({
                ...Object.fromEntries(names.map((name) => [name, a[name]])),
                challengeId: admitted.challengeId,
                probeDigest: sha256(probe),
                observedAtMs: timing.now,
                validUntilMs: Math.min(admitted.validUntilMs, timing.validUntilMs),
              });
              const payload = encodeOperationsSecretResolution(claims);
              const cose = signOperationsSecretResolution(key, spki, payload);
              verifyOperationsSecretResolution(spki, payload, cose);
              await owner.query(
                `insert into control.operations_secret_observation
            (observation_id,association_id,participant_id,privacy_domain_id,claims,probe,payload,cose,source_digest)
            values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
                [
                  claims.challengeId,
                  a.associationId,
                  a.participantId,
                  a.privacyDomainId,
                  claims,
                  probe,
                  payload,
                  cose,
                  operationsSecretObservationDigest(cose),
                ],
              );
              await inspectOperationsSecretProbe(candidateAdminPool, probeScope, admitted, probe);
              current = { challenge: admitted, probe, claims, payload, cose };
              return {
                version: 1,
                observationId: claims.challengeId,
                sourceDigest: operationsSecretObservationDigest(cose),
                validUntilMs: claims.validUntilMs,
              };
            },
          );
        }),
      );
    },
    async withCurrent<T>(
      use: (
        client: PoolClient,
        observation: Readonly<{
          associationId: string;
          observationId: string;
          sourceDigest: string;
        }>,
      ) => Promise<T>,
    ): Promise<T> {
      return serialized(() =>
        transaction(async () => {
          const active = await checkCurrent();
          const result = await use(
            owner,
            Object.freeze({
              associationId: a.associationId,
              observationId: active.claims.challengeId,
              sourceDigest: operationsSecretObservationDigest(active.cose),
            }),
          );
          await checkCurrent();
          return result;
        }),
      );
    },
    close() {
      closing ??= (async () => {
        closed = true;
        key.fill(0);
        challenge = undefined;
        current = undefined;
        await queue;
        try {
          await owner.query(
            "select pg_advisory_unlock(hashtextextended('operations-secret-observer:'||$1,0))",
            [a.associationId],
          );
        } catch (failure) {
          cleanupFailure ??= { cause: failure };
        } finally {
          owner.off('error', onError);
          owner.off('end', onError);
          try {
            owner.release(true);
          } catch (failure) {
            cleanupFailure ??= { cause: failure };
          }
        }
        if (cleanupFailure !== undefined) throw new Error('OPS_SECRET_OBSERVATION_CLEANUP_UNKNOWN');
      })();
      return closing;
    },
  });
}

/** Packaged deployments keep the independent observer in the existing host
 * installer, outside the publisher/consumer PID namespaces. Only that owner
 * can inspect the exact owned container; neither workload gets Docker access.
 * The launcher installs the measured process association before first use.
 * This service carries observations only, never secret bytes/PUBLISH/CHECK. */
export function buildOperationsSecretResolutionService(
  options: OperationsSecretObserverOptions & { readonly tls: LocalWorkloadMtlsOptions },
) {
  let app;
  try {
    app = buildLocalWorkloadMtlsService(options.pool, options.kernel, options.tls);
  } catch {
    options.owner.release(true);
    return rejected();
  }
  let pending: ReturnType<typeof createOperationsSecretResolutionObserver> | undefined;
  let observer: Awaited<ReturnType<typeof createOperationsSecretResolutionObserver>> | undefined;
  let stopped = false;
  // Trusted installer calls this only after installing measured PID/start and
  // before releasing the initial PUBLISH gate. HTTP callers cannot initialize
  // (or poison) the observer while its association does not yet exist.
  app.decorate('startOperationsSecretResolution', async () => {
    if (stopped) return rejected();
    pending ??= createOperationsSecretResolutionObserver(options);
    observer = await pending;
  });
  app.post(operationsSecretObservationPath, async (request, reply) => {
    try {
      if (!observer) return rejected();
      const result = await observer.request(request.raw.socket as TLSSocket, request.body);
      process.stderr.write(
        'challengeId' in result
          ? 'OPS_SECRET_OBSERVATION|OBSERVED|challenge-issued\n'
          : 'OPS_SECRET_OBSERVATION|OBSERVED|observation-persisted\n',
      );
      return result;
    } catch {
      process.stderr.write('OPS_SECRET_OBSERVATION|FAIL|request\n');
      return reply.code(403).send({ code: 'OPS_SECRET_OBSERVATION_REJECTED' });
    }
  });
  app.decorate(
    'withCurrentOperationsSecretResolution',
    async <T>(use: Parameters<NonNullable<typeof observer>['withCurrent']>[0]): Promise<T> => {
      if (!observer) return rejected();
      return (await observer.withCurrent(use)) as T;
    },
  );
  app.addHook('onClose', async () => {
    stopped = true;
    if (pending) await (await pending.catch(() => undefined))?.close();
    else options.owner.release(true);
  });
  return app;
}
