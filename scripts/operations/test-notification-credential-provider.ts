import { createHash } from 'node:crypto';
import type { NotificationChannelCredential } from '../../services/control-api/src/notifications/endpoint-owner-contract.js';
import type { NotificationCredentialProvider } from '../../services/identity-service/src/domain/notification-credential-material.js';
import { notificationChannelCredential } from '../../services/control-api/src/notifications/endpoint-owner-contract.js';
import { immutableJsonCopy } from '../../services/control-api/src/privacy-explorer/immutable.js';
import {
  decodeNotificationCredentialMaterial,
  notificationCredentialEncoding,
} from '../../services/identity-service/src/domain/notification-credential-material.js';

const fail = () => new Error('OPS_SECRET_UNRESOLVED');
const digest = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

/** Concrete single-version external TEST provider, supplied only by trusted
 * local installation composition. Synthetic bytes stay in memory. The caller
 * owns/erases its input. This is not a public resolver, Identity substitute,
 * production provider qualification, or a persisted rotation/recovery owner.
 * Invoke only through withNotificationSecretRecipient with its real peer and
 * current SQL fences. A matching metadata request does not authenticate anyone.
 * Restart has no restored bytes/eligibility: the original runtime owner must
 * reconcile durable installation/provider state before creating another fixture.
 */
export function createTestNotificationCredentialProvider(
  credentialValue: unknown,
  syntheticBytes: Buffer,
): NotificationCredentialProvider & { revoke(): void; close(): void } {
  let credential: NotificationChannelCredential;
  let material: Buffer | undefined;
  let deadline: number;
  try {
    credential = notificationChannelCredential.parse(immutableJsonCopy(credentialValue));
    if (!Buffer.isBuffer(syntheticBytes)) throw fail();
    material = Buffer.from(syntheticBytes);
    const tls = decodeNotificationCredentialMaterial(material);
    if (
      credential.state !== 'ACTIVE' ||
      credential.validFromMs > Date.now() ||
      credential.fingerprint !== tls.fingerprint
    )
      throw fail();
    deadline = Math.min(credential.validUntilMs, tls.validUntilMs);
    if (deadline <= Date.now()) throw fail();
  } catch {
    material?.fill(0);
    throw fail();
  }
  const retained = material;
  const expected = Object.freeze({
    participantId: credential.participantId,
    privacyDomainId: credential.privacyDomainId,
    credentialRef: credential.credentialRef,
    reference: credential.reference,
    version: credential.version,
    epoch: credential.epoch,
    purpose: 'NOTIFICATION_GATEWAY_CREDENTIAL',
    consumer: 'LS-NOTIFICATION',
  });
  const controller = new AbortController();
  let terminal = false,
    busy = false;
  let borrowed: Buffer | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  function revoke() {
    if (terminal) return;
    terminal = true;
    clearTimeout(timer);
    retained.fill(0);
    borrowed?.fill(0);
    controller.abort(new Error('OPS_SECRET_REVOKED'));
  }
  function current() {
    if (terminal || Date.now() >= deadline) {
      revoke();
      throw fail();
    }
    if (digest(retained) !== credential.fingerprint) {
      revoke();
      throw fail();
    }
  }
  function expire() {
    if (Date.now() >= deadline) revoke();
    else {
      timer = setTimeout(expire, Math.min(deadline - Date.now(), 2147483647));
      timer.unref();
    }
  }
  expire();
  const provider: NotificationCredentialProvider & { revoke(): void; close(): void } = {
    async withExactVersion(request, use) {
      let entered = false;
      try {
        current();
        const snapshot = immutableJsonCopy(request);
        if (
          !snapshot ||
          Object.keys(snapshot).length !== Object.keys(expected).length ||
          Object.entries(expected).some(
            ([key, value]) => snapshot[key as keyof typeof snapshot] !== value,
          ) ||
          typeof use !== 'function' ||
          busy
        )
          throw fail();
        busy = true;
        entered = true;
        borrowed = Buffer.from(retained);
        const original = borrowed;
        const assertCurrent = () => {
          current();
          if (!busy || borrowed !== original || digest(original) !== credential.fingerprint)
            throw fail();
        };
        const result = await use(
          Object.freeze({
            encoding: notificationCredentialEncoding,
            bytes: borrowed,
            reference: credential.reference,
            version: credential.version,
            epoch: credential.epoch,
            signal: controller.signal,
            validUntilMs: deadline,
            assertCurrent,
          }),
        );
        assertCurrent();
        return result;
      } catch {
        // No arbitrary callback/provider diagnostic or secret-bearing cause escapes.
        throw fail();
      } finally {
        if (entered) {
          borrowed?.fill(0);
          borrowed = undefined;
          busy = false;
        }
      }
    },
    revoke,
    close: revoke,
  };
  return Object.freeze(provider);
}
