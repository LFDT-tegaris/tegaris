import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from './identity-kernel.js';
import { withAuthenticatedWorkloadPeer } from './workload-peer.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import { currentNotificationChannel } from '../../../control-api/src/notifications/endpoint-admission.js';
import type { NotificationChannelCredential } from '../../../control-api/src/notifications/endpoint-owner-contract.js';

import {
  notificationCredentialEncoding,
  notificationCredentialMaximumBytes,
  type NotificationCredentialProvider,
} from './notification-credential-material.js';

function reject(): never {
  throw new Error('OPS_SECRET_UNRESOLVED');
}
export interface NotificationSecretRequest {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly credentialRef: string;
  readonly reference: string;
  readonly version: string;
  readonly epoch: string;
}
// Compatibility name for existing composition callers; the canonical provider
// contract is the only material/export model.
export type { NotificationCredentialProvider as NotificationSecretProvider } from './notification-credential-material.js';
export interface NotificationCredentialLease {
  readonly credential: Readonly<NotificationChannelCredential>;
  /** Borrowed bounded bytes. Never retain, log or return them. Erased on every exit. */
  readonly bytes: Buffer;
  readonly signal: AbortSignal;
}
const active = new WeakMap<
  object,
  { deadline: number; transportDigest: string; assertCurrent(): void }
>();
export function assertNotificationCredentialLease(
  lease: NotificationCredentialLease,
  credential: NotificationChannelCredential,
  transportDigest?: string,
): number {
  const retained = lease ? active.get(lease) : undefined;
  if (!retained) reject();
  retained.assertCurrent();
  const deadline = retained.deadline;
  if (
    deadline === undefined ||
    deadline <= Date.now() ||
    !lease ||
    !active.has(lease) ||
    lease.signal.aborted ||
    (transportDigest !== undefined && transportDigest !== retained.transportDigest) ||
    lease.credential.participantId !== credential.participantId ||
    lease.credential.privacyDomainId !== credential.privacyDomainId ||
    lease.credential.credentialRef !== credential.credentialRef ||
    lease.credential.reference !== credential.reference ||
    lease.credential.version !== credential.version ||
    lease.credential.epoch !== credential.epoch ||
    lease.credential.fingerprint !== credential.fingerprint ||
    lease.credential.channel !== credential.channel ||
    lease.credential.destinationRef !== credential.destinationRef ||
    lease.credential.owner !== credential.owner ||
    lease.credential.secretClass !== credential.secretClass ||
    lease.credential.state !== 'ACTIVE' ||
    credential.state !== 'ACTIVE' ||
    lease.credential.validFromMs !== credential.validFromMs ||
    lease.credential.validUntilMs !== credential.validUntilMs ||
    lease.credential.validFromMs > Date.now() ||
    lease.credential.validUntilMs <= Date.now() ||
    `sha256:${createHash('sha256').update(lease.bytes).digest('hex')}` !== credential.fingerprint
  )
    reject();
  return deadline;
}
/** A distinct notification purpose. Does not broaden LS-FACT-BRIDGE or accept
 * an asserted identity, arbitrary consumer, unversioned reference or installed flag. */
export async function withNotificationSecretRecipient<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  request: NotificationSecretRequest,
  provider: NotificationCredentialProvider,
  use: (lease: NotificationCredentialLease) => Promise<T>,
): Promise<T> {
  if (
    !request ||
    Object.getPrototypeOf(request) !== Object.prototype ||
    Object.keys(request).sort().join(',') !==
      'credentialRef,epoch,participantId,privacyDomainId,reference,version'
  )
    reject();
  return withAuthenticatedWorkloadPeer(
    pool,
    kernel,
    socket,
    async (client, identity) => {
      if (identity.participantId !== request.participantId) reject();
      const current = await currentNotificationChannel(client, request, request.credentialRef),
        c = current.credential,
        i = current.installation;
      if (
        identity.workloadId !== i.workloadId ||
        identity.principalId !== i.principalId ||
        identity.credentialId !== i.workloadCredentialId ||
        identity.workloadEpoch !== i.workloadEpoch ||
        request.reference !== c.reference ||
        request.version !== c.version ||
        request.epoch !== c.epoch
      )
        reject();
      return provider.withExactVersion(
        { ...request, purpose: 'NOTIFICATION_GATEWAY_CREDENTIAL', consumer: 'LS-NOTIFICATION' },
        async (material) => {
          // Own and erase a copy even when the provider uses a borrowed cache buffer.
          if (
            !Buffer.isBuffer(material.bytes) ||
            material.bytes.length < 1 ||
            material.bytes.length > notificationCredentialMaximumBytes ||
            material.encoding !== notificationCredentialEncoding ||
            !(material.signal instanceof AbortSignal) ||
            material.signal.aborted ||
            typeof material.assertCurrent !== 'function' ||
            !Number.isSafeInteger(material.validUntilMs) ||
            material.validUntilMs <= Date.now() ||
            material.reference !== c.reference ||
            material.version !== c.version ||
            material.epoch !== c.epoch
          )
            reject();
          material.assertCurrent();
          const controller = new AbortController();
          const lease = Object.freeze({
            credential: c,
            bytes: Buffer.from(material.bytes),
            signal: controller.signal,
          });
          const deadline = Math.min(
            c.validUntilMs,
            current.channel.claims.validUntilMs,
            identity.notAfter.getTime(),
            material.validUntilMs,
          );
          let timer: ReturnType<typeof setTimeout> | undefined;
          const invalidate = () => {
            clearTimeout(timer);
            active.delete(lease);
            lease.bytes.fill(0);
            controller.abort();
          };
          const assertCurrent = () => {
            try {
              material.assertCurrent();
              if (material.signal.aborted || controller.signal.aborted || Date.now() >= deadline)
                reject();
            } catch {
              invalidate();
              reject();
            }
          };
          const expire = () => {
            if (Date.now() >= deadline) invalidate();
            else {
              timer = setTimeout(expire, Math.min(deadline - Date.now(), 2147483647));
              timer.unref();
            }
          };
          active.set(lease, {
            deadline,
            transportDigest: sha256(current.channel.transport),
            assertCurrent,
          });
          material.signal.addEventListener('abort', invalidate, { once: true });
          expire();
          let result: T;
          try {
            assertNotificationCredentialLease(lease, c);
            result = await use(lease);
            assertNotificationCredentialLease(lease, c);
          } finally {
            // The caller's borrowed authority ends at callback exit. Retaining
            // it during the asynchronous SQL recheck would let unawaited I/O
            // escape the callback window even though its eventual result fails.
            material.signal.removeEventListener('abort', invalidate);
            invalidate();
          }
          await currentNotificationChannel(client, request, request.credentialRef);
          return result;
        },
      );
    },
    { privacyDomainId: request.privacyDomainId },
  );
}
