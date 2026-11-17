import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from './identity-kernel.js';
import { withAuthenticatedWorkloadPeer } from './workload-peer.js';
import { canonicalJson, sha256 } from '../../../control-api/src/configuration/digest.js';
import {
  notificationWorkerSelector,
  fenceNotificationWorkerInstallation,
  type NotificationWorkerSelector,
} from '../../../control-api/src/notifications/worker-installation.js';
import {
  NotificationWorkerAdmissionError,
  validateNotificationWorkerInstallation,
} from '../../../control-api/src/notifications/worker-installation-contract.js';
export interface NotificationWorkerAdmission {
  readonly installation: Awaited<ReturnType<typeof fenceNotificationWorkerInstallation>>;
  readonly authorityDigest: string;
}
const active = new WeakMap<object, { client: PoolClient; selector: NotificationWorkerSelector }>();
const deliveryCurrent = new WeakMap<object, () => Promise<void>>();
/** A live delivery worker fence, never a gateway claim or decrypted payload.
 * Local publisher/STARTED admissions, copied values and escaped handles fail. */
export async function assertNotificationDeliveryWorkerCurrent(
  admission: NotificationWorkerAdmission,
  client: PoolClient,
  selector: NotificationWorkerSelector,
): Promise<void> {
  assertNotificationDeliveryWorkerAdmission(admission, client, selector);
  const confirm = deliveryCurrent.get(admission);
  if (!confirm) throw new NotificationWorkerAdmissionError();
  await confirm();
}

/** A descriptor copied outside the live TLS/Identity transaction grants nothing. */
export function assertNotificationWorkerAdmission(
  admission: NotificationWorkerAdmission,
  client: PoolClient,
  selector: NotificationWorkerSelector,
) {
  const entry = active.get(admission);
  if (
    !entry ||
    entry.client !== client ||
    canonicalJson(entry.selector) !== canonicalJson(selector)
  )
    throw new NotificationWorkerAdmissionError();
}
/** Delivery-request consumption is a distinct installed subscription. Neither
 * of the Evidence-export publishers can borrow this live admission. This is
 * still only worker identity; source, STARTED, credential and I/O gates remain
 * independent. A retained/copied admission is rejected by the shared owner. */
export function assertNotificationDeliveryWorkerAdmission(
  admission: NotificationWorkerAdmission,
  client: PoolClient,
  selector: NotificationWorkerSelector,
) {
  assertNotificationWorkerAdmission(admission, client, selector);
  const profile = admission.installation.profile;
  if (
    profile.serviceId !== 'LS-NOTIFICATION' ||
    profile.processRole !== 'ROLE-NOTIFICATION-WORKER' ||
    profile.subscriptionId !== 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
  )
    throw new NotificationWorkerAdmissionError();
}
/** Context identity for the exact live delivery subscription. The credential ID
 * and epoch are the actual peer values already matched under Identity fences,
 * not a new session, caller label or profile revision. ACCESS-NOTIFICATION only
 * classifies this installed purpose; endpoint/configuration/STARTED/dispatch
 * admission remains mandatory and this detached descriptor is never a lease.
 */
export function notificationDeliveryWorkerContextIdentity(
  admission: NotificationWorkerAdmission,
  client: PoolClient,
  selector: NotificationWorkerSelector,
) {
  assertNotificationDeliveryWorkerAdmission(admission, client, selector);
  const profile = admission.installation.profile;
  const epoch = Number(profile.workloadEpoch);
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new NotificationWorkerAdmissionError();
  return Object.freeze({
    authorizationDigest: admission.authorityDigest,
    authorizationContextId: profile.workloadCredentialId,
    authorizationContextEpoch: epoch,
    accessClassIds: Object.freeze(['ACCESS-NOTIFICATION'] as const),
  });
}
/** Trusted local service composition. No external I/O belongs in this callback.
 * Source, route, custody, signer attempt and atomic business mutation are separate
 * required gates; authenticated workload/profile metadata cannot stand in for them. */
export async function withNotificationWorkerPeer<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  operation: (client: PoolClient, admission: NotificationWorkerAdmission) => Promise<T>,
): Promise<T> {
  return withWorkerPeer(pool, kernel, socket, value, operation, false);
}

/** Purpose-specific live worker admission for bounded delivery orchestration.
 * The root must separately retain configuration/source/route/cancellation fences,
 * commit its durable gateway claim and join current material before any send.
 * An external result remains ambiguous if the enclosing transaction fails. */
export async function withNotificationDeliveryWorkerPeer<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  operation: (client: PoolClient, admission: NotificationWorkerAdmission) => Promise<T>,
): Promise<T> {
  return withWorkerPeer(pool, kernel, socket, value, operation, true);
}

async function withWorkerPeer<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  operation: (client: PoolClient, admission: NotificationWorkerAdmission) => Promise<T>,
  delivery: boolean,
): Promise<T> {
  try {
    const selector = notificationWorkerSelector.parse(value);
    return await withAuthenticatedWorkloadPeer(
      pool,
      kernel,
      socket,
      async (client, peer, confirmPeer) => {
        if (peer.participantId !== selector.participantId)
          throw new NotificationWorkerAdmissionError();
        const installation = await fenceNotificationWorkerInstallation(client, selector),
          p = installation.profile;
        if (
          peer.principalId !== p.principalId ||
          peer.credentialId !== p.workloadCredentialId ||
          peer.workloadEpoch !== p.workloadEpoch ||
          peer.workloadId !== p.workloadId ||
          peer.keyId !== installation.input.pins.workloadKeyDigest
        )
          throw new NotificationWorkerAdmissionError();
        const authorityDigest = sha256({
          schema: 'pc.notification-worker.authority.v1',
          installationDigest: installation.installationDigest,
          participantId: peer.participantId,
          privacyDomainId: selector.privacyDomainId,
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
        });
        const admission = Object.freeze({ installation, authorityDigest });
        active.set(admission, { client, selector });
        try {
          if (delivery) {
            assertNotificationDeliveryWorkerAdmission(admission, client, selector);
            deliveryCurrent.set(admission, async () => {
              assertNotificationDeliveryWorkerAdmission(admission, client, selector);
              await confirmPeer();
              const clock = await client.query<{ now: string }>(
                'select floor(extract(epoch from clock_timestamp())*1000)::text now',
              );
              const checked = validateNotificationWorkerInstallation(
                installation.input,
                Number(clock.rows[0]?.now),
              );
              if (checked.installationDigest !== installation.installationDigest)
                throw new NotificationWorkerAdmissionError();
            });
            await assertNotificationDeliveryWorkerCurrent(admission, client, selector);
          }
          const result = await operation(client, admission);
          const current = await fenceNotificationWorkerInstallation(client, selector);
          if (current.installationDigest !== installation.installationDigest)
            throw new NotificationWorkerAdmissionError();
          return result;
        } finally {
          deliveryCurrent.delete(admission);
          active.delete(admission);
        }
      },
      selector,
    );
  } catch {
    throw new NotificationWorkerAdmissionError();
  }
}
