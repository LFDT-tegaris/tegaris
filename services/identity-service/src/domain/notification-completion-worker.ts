import type { verifyNotificationCompletionReceiptInTransaction } from './notification-completion-receipt.js';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { z } from 'zod';
import type { IdentityKernel } from './identity-kernel.js';
import { withAuthenticatedWorkloadPeer } from './workload-peer.js';
import { canonicalJson, sha256 } from '../../../control-api/src/configuration/digest.js';
import { immutableJsonCopy } from '../../../control-api/src/privacy-explorer/immutable.js';
import {
  notificationCompletionWorkerSelector,
  fenceNotificationCompletionWorkerInstallation,
  type NotificationCompletionWorkerSelector,
} from '../../../control-api/src/notifications/completion-worker-installation.js';
import { NotificationCompletionWorkerAdmissionError } from '../../../control-api/src/notifications/completion-worker-installation-contract.js';
export interface NotificationCompletionWorkerAdmission {
  readonly installation: Awaited<ReturnType<typeof fenceNotificationCompletionWorkerInstallation>>;
  readonly authorityDigest: string;
}
const active = new WeakMap<
  object,
  {
    client: PoolClient;
    selector: NotificationCompletionWorkerSelector;
    confirm: () => Promise<void>;
    admitPhase: (eventId: string, phase: NotificationCompletionDispositionPhase) => Promise<void>;
    admitReceipt: (
      eventId: string,
      phase: 'OBSERVE' | 'PUBLISH',
      observation: unknown,
    ) => Promise<void>;
  }
>();
const phaseSchema = z.enum([
  'SOURCE',
  'CLAIM',
  'LIMIT',
  'FINISH',
  'PREPARE',
  'SIGN_CLAIM',
  'OBSERVE',
  'PUBLISH',
]);
export type NotificationCompletionDispositionPhase = z.infer<typeof phaseSchema>;
const bridges = new WeakMap<Pool, Buffer>();
/** Trusted host composition only. This dedicated key is also installed for the
 * exact database login by its privileged installer, never read through SQL or
 * supplied by an event/request. Reinstallation cannot replace live trust. */
export function installNotificationCompletionSqlBridge(pool: Pool, secret: Uint8Array) {
  if (secret.length !== 32 || bridges.has(pool))
    throw new NotificationCompletionWorkerAdmissionError();
  bridges.set(pool, Buffer.from(secret));
}
/** Admit one exact event/phase only inside the actual authenticated callback.
 * The SQL owner independently checks the MAC, transaction and current bindings.
 * This authenticates the worker; each feature owner still admits its business effect. */
export async function admitNotificationCompletionDispositionPhase(
  admission: NotificationCompletionWorkerAdmission,
  client: PoolClient,
  selector: NotificationCompletionWorkerSelector,
  eventId: string,
  phase: NotificationCompletionDispositionPhase,
) {
  const event = z.uuidv7().parse(eventId),
    selectedPhase = phaseSchema.parse(phase);
  await assertNotificationCompletionWorkerCurrent(admission, client, selector);
  const entry = active.get(admission);
  if (!entry) throw new NotificationCompletionWorkerAdmissionError();
  await entry.admitPhase(event, selectedPhase);
  await assertNotificationCompletionWorkerCurrent(admission, client, selector);
}
/** Verify the actual original signed result, then attest its exact bytes in
 * this same live TLS transaction. No caller-provided receipt/trust digest grants authority. */
export async function admitNotificationCompletionDispositionReceipt(
  admission: NotificationCompletionWorkerAdmission,
  client: PoolClient,
  selector: NotificationCompletionWorkerSelector,
  eventId: string,
  phase: 'OBSERVE' | 'PUBLISH',
  observation: unknown,
) {
  const event = z.uuidv7().parse(eventId),
    selected = z.enum(['OBSERVE', 'PUBLISH']).parse(phase);
  await assertNotificationCompletionWorkerCurrent(admission, client, selector);
  const entry = active.get(admission);
  if (!entry) throw new NotificationCompletionWorkerAdmissionError();
  await entry.admitReceipt(event, selected, immutableJsonCopy(observation));
  await assertNotificationCompletionWorkerCurrent(admission, client, selector);
}
/** Exact same-client, still-live Identity and installation admission. A copied,
 * escaped, delivery-worker or caller-authored descriptor grants nothing. */
export async function assertNotificationCompletionWorkerCurrent(
  admission: NotificationCompletionWorkerAdmission,
  client: PoolClient,
  value: NotificationCompletionWorkerSelector,
) {
  const q = notificationCompletionWorkerSelector.parse(immutableJsonCopy(value));
  const entry = active.get(admission);
  if (!entry || entry.client !== client || canonicalJson(entry.selector) !== canonicalJson(q))
    throw new NotificationCompletionWorkerAdmissionError();
  await entry.confirm();
  if (active.get(admission) !== entry) throw new NotificationCompletionWorkerAdmissionError();
}
/** Current identity/installed purpose only. Callback must separately authorize
 * each source, disposition, inbox/cursor and quarantine/WorkItem effect. No I/O,
 * event ACK or detached authority is implied by a successful return. */
export async function withNotificationCompletionWorkerPeer<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  operation: (client: PoolClient, admission: NotificationCompletionWorkerAdmission) => Promise<T>,
): Promise<T> {
  const q = immutableJsonCopy(notificationCompletionWorkerSelector.parse(immutableJsonCopy(value)));
  return withAuthenticatedWorkloadPeer(
    pool,
    kernel,
    socket,
    async (client, peer, confirmPeer) => {
      if (peer.participantId !== q.participantId)
        throw new NotificationCompletionWorkerAdmissionError();
      const installation = await fenceNotificationCompletionWorkerInstallation(client, q),
        p = installation.profile,
        profileExpiresAtMs = p.validUntilMs;
      if (
        peer.principalId !== p.principalId ||
        peer.credentialId !== p.workloadCredentialId ||
        peer.workloadEpoch !== p.workloadEpoch ||
        peer.workloadId !== p.workloadId ||
        peer.keyId !== p.workloadKeyDigest ||
        p.serviceId !== 'LS-CONTROL-WORK' ||
        p.processRole !== 'ROLE-CONTROL-WORKER' ||
        p.subscriptionId !== 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'
      )
        throw new NotificationCompletionWorkerAdmissionError();
      const databaseBinding = await client.query<{ tx: string; backend: number; login: string }>(
        'select pg_current_xact_id()::text tx,pg_backend_pid() backend,session_user login',
      );
      const originalDatabase = databaseBinding.rows[0];
      if (databaseBinding.rowCount !== 1 || !originalDatabase)
        throw new NotificationCompletionWorkerAdmissionError();
      const admission = Object.freeze({
        installation,
        authorityDigest: sha256({
          schema: 'pc.notification-completion-worker.authority.v1',
          installationDigest: installation.installationDigest,
          participantId: peer.participantId,
          privacyDomainId: q.privacyDomainId,
          principalId: peer.principalId,
          credentialId: peer.credentialId,
          participantEpoch: peer.participantEpoch,
          principalEpoch: peer.principalEpoch,
          workloadEpoch: peer.workloadEpoch,
          workloadId: peer.workloadId,
          uriSan: peer.uriSan,
          keyId: peer.keyId,
          notBefore: peer.notBefore,
          notAfter: peer.notAfter,
        }),
      });
      const confirm = async () => {
        await confirmPeer();
        const current = await fenceNotificationCompletionWorkerInstallation(client, q);
        if (current.installationDigest !== installation.installationDigest)
          throw new NotificationCompletionWorkerAdmissionError();
      };
      const receipts = new Map<
        string,
        Awaited<ReturnType<typeof verifyNotificationCompletionReceiptInTransaction>>
      >();
      const admitPhase = async (eventId: string, phase: NotificationCompletionDispositionPhase) => {
        const key = bridges.get(pool);
        if (!key) throw new NotificationCompletionWorkerAdmissionError();
        await confirm();
        const binding = await client.query<{
          tx: string;
          backend: number;
          login: string;
          now: string;
        }>(
          `select pg_current_xact_id()::text tx,pg_backend_pid() backend,session_user login,
           floor(extract(epoch from clock_timestamp())*1000)::text now`,
        );
        const current = binding.rows[0];
        if (
          binding.rowCount !== 1 ||
          !current ||
          current.tx !== originalDatabase.tx ||
          current.backend !== originalDatabase.backend ||
          current.login !== originalDatabase.login
        )
          throw new NotificationCompletionWorkerAdmissionError();
        const now = Number(current.now);
        if (!Number.isSafeInteger(now)) throw new NotificationCompletionWorkerAdmissionError();
        const proof = {
          version: 2,
          receiptBinding: receipts.get(`${eventId}:${phase}`) ?? null,
          transactionId: originalDatabase.tx,
          backendPid: originalDatabase.backend,
          databaseRole: originalDatabase.login,
          participantId: q.participantId,
          privacyDomainId: q.privacyDomainId,
          eventId,
          phase,
          installationDigest: installation.installationDigest,
          authorityDigest: admission.authorityDigest,
          principalId: peer.principalId,
          credentialId: peer.credentialId,
          participantEpoch: peer.participantEpoch,
          principalEpoch: peer.principalEpoch,
          workloadEpoch: peer.workloadEpoch,
          workloadId: peer.workloadId,
          uriSan: peer.uriSan,
          keyId: peer.keyId,
          issuedAtMs: now,
          expiresAtMs: Math.min(now + 5000, profileExpiresAtMs, peer.notAfter.getTime()),
        };
        const wire = Buffer.from(canonicalJson(proof)),
          nonce = randomBytes(32);
        const mac = createHmac('sha256', key)
          .update('OPENPC_NOTIFICATION_COMPLETION_PHASE_ADMISSION_V1')
          .update(createHash('sha256').update(wire).digest())
          .update(nonce)
          .digest();
        await client.query('select openpc.admit_notification_completion_phase($1,$2,$3)', [
          wire,
          nonce,
          mac,
        ]);
        await confirm();
      };
      const admitReceipt = async (
        eventId: string,
        phase: 'OBSERVE' | 'PUBLISH',
        observation: unknown,
      ) => {
        await confirm();
        // Load the feature verifier only after the Identity/feature modules are
        // initialized; their existing ownership imports must not construct a
        // protocol schema with an uninitialized purpose during module loading.
        const { verifyNotificationCompletionReceiptInTransaction } =
          await import('./notification-completion-receipt.js');
        const verified = await verifyNotificationCompletionReceiptInTransaction(
          client,
          q,
          eventId,
          phase,
          observation,
        );
        if (
          verified.producerTrustDigest !== installation.profile.producerTrustDigest ||
          verified.environmentId !== installation.profile.environmentId
        )
          throw new NotificationCompletionWorkerAdmissionError();
        const id = `${eventId}:${phase}`,
          prior = receipts.get(id);
        if (prior && canonicalJson(prior) !== canonicalJson(verified))
          throw new NotificationCompletionWorkerAdmissionError();
        receipts.set(id, verified);
        await admitPhase(eventId, phase);
        await confirm();
      };
      active.set(admission, { client, selector: q, confirm, admitPhase, admitReceipt });
      try {
        await assertNotificationCompletionWorkerCurrent(admission, client, q);
        const result = await operation(client, admission);
        await assertNotificationCompletionWorkerCurrent(admission, client, q);
        // Admission rows exist only inside this transaction. Immediate effect
        // guards consume them; no detached capability remains after COMMIT.
        if (bridges.has(pool))
          await client.query('select openpc.clear_notification_completion_phases()');
        return result;
      } finally {
        active.delete(admission);
      }
    },
    q,
  );
}
