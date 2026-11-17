import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { EvidenceKmsError, evidenceKmsLimits } from '../evidence/kms-contracts.js';
import { EvidenceKmsRuntime, type EvidenceKmsTlsMaterial } from '../evidence/kms-runtime.js';
import { openVaultDirectory, readVaultFile } from '../evidence/immutable-vault.js';
import {
  inspectNotificationKeyCiphertext,
  notificationKeyFile,
} from '../evidence/notification-key-contracts.js';
import {
  notificationPayloadEncryptionProfile,
  openNotificationPayload,
} from '../evidence/notification-payload-crypto.js';
import {
  assertNotificationDeliveryMaterialContext,
  type NotificationDeliveryMaterialContext,
} from './delivery-material-context.js';
import {
  assertNotificationDeliveryMaterialStage,
  assertNotificationDeliveryPayloadReference,
} from './payload-reference.js';

export class NotificationDeliveryMaterialError extends Error {
  constructor(readonly code: 'UNAVAILABLE' | 'UNKNOWN') {
    super(`Notification delivery material ${code}`);
  }
}
/** Callback-local cancellation/time bounds only, never a dispatch capability. */
export interface NotificationDeliveryMaterialWindow {
  readonly signal: AbortSignal;
  readonly deadlineAtMs: number;
  readonly timeoutMs: number;
}
export type NotificationDeliveryMaterialConsumer = (
  plaintext: Buffer,
  window: NotificationDeliveryMaterialWindow,
) => void | Promise<void>;
type Bound = { readonly deadlineAtMs: number; readonly monotonicDeadlineMs: number };
// Match the context's one full-custody callback before issuing any native unwrap.
// A second/concurrent owner cannot start another exchange and block on that callback.
const consumedContexts = new WeakSet<NotificationDeliveryMaterialContext>();
const unavailable = (): never => {
  throw new NotificationDeliveryMaterialError('UNAVAILABLE');
};
const remaining = (bound: Bound) =>
  Math.min(bound.deadlineAtMs - Date.now(), bound.monotonicDeadlineMs - performance.now());
function assertBound(bound: Bound) {
  if (
    !Number.isSafeInteger(bound.deadlineAtMs) ||
    bound.deadlineAtMs < 0 ||
    !Number.isFinite(bound.monotonicDeadlineMs) ||
    remaining(bound) <= 0 ||
    remaining(bound) > evidenceKmsLimits.statusMaximumAgeMs
  )
    unavailable();
}
/** Local buffer lifetime mechanics only; no Identity/KMS/context success is
 * inferred here. The material owner calls this solely inside full live custody.
 * Takes ownership of bytes and erases them on every exit, abort and expiry.
 * Await consumer cleanup even on abort: never release live fences while an
 * unfinished consumer still owns the callback. Consumers must honor the signal.
 * JavaScript cannot erase deliberately retained copies, native buffers or OS snapshots. */
export async function consumeNotificationDeliveryBuffer(
  bytes: Buffer,
  signal: AbortSignal,
  input: Bound,
  use: NotificationDeliveryMaterialConsumer,
): Promise<void> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let entered = false;
  let bound: Bound = { deadlineAtMs: 0, monotonicDeadlineMs: 0 };
  const erase = () => {
    if (Buffer.isBuffer(bytes)) bytes.fill(0);
  };
  const invalidate = () => {
    erase();
    controller.abort();
  };
  const current = () => {
    if (signal.aborted || controller.signal.aborted || remaining(bound) <= 0) {
      invalidate();
      unavailable();
    }
  };
  const expire = () => {
    if (remaining(bound) <= 0) invalidate();
    else {
      timer = setTimeout(expire, Math.min(Math.ceil(remaining(bound)), 2147483647));
      timer.unref();
    }
  };
  try {
    if (
      !Buffer.isBuffer(bytes) ||
      !bytes.length ||
      bytes.length > notificationPayloadEncryptionProfile.maximumPlaintextBytes ||
      !(signal instanceof AbortSignal) ||
      typeof use !== 'function'
    )
      unavailable();
    bound = Object.freeze({
      deadlineAtMs: input.deadlineAtMs,
      monotonicDeadlineMs: input.monotonicDeadlineMs,
    });
    assertBound(bound);
    signal.addEventListener('abort', invalidate, { once: true });
    current();
    expire();
    const digest = sha256(bytes);
    const window: NotificationDeliveryMaterialWindow = Object.freeze({
      signal: controller.signal,
      deadlineAtMs: bound.deadlineAtMs,
      get timeoutMs() {
        return controller.signal.aborted ? 0 : Math.max(0, Math.floor(remaining(bound)));
      },
    });
    entered = true;
    const result: unknown = await use(bytes, window);
    if (result !== undefined) {
      if (Buffer.isBuffer(result)) result.fill(0);
      unavailable();
    }
    current();
    if (sha256(bytes) !== digest) unavailable();
  } catch {
    throw new NotificationDeliveryMaterialError(entered ? 'UNKNOWN' : 'UNAVAILABLE');
  } finally {
    clearTimeout(timer);
    if (signal instanceof AbortSignal) signal.removeEventListener('abort', invalidate);
    invalidate();
  }
}

/** Trusted root supplies real pool/kernel, native KMS TLS and owned vault.
 * Producer TLS is independent of the context's actual delivery worker TLS.
 * No injected successful unwrap callback, claim, gateway, retry or alternate key.
 * The context must be created by withNotificationDeliveryMaterialContext and
 * remain active around this entire call; this owner returns no plaintext/grant. */
export class NotificationDeliveryMaterial {
  private readonly kms: EvidenceKmsRuntime;
  constructor(
    pool: Pool,
    kernel: IdentityKernel,
    tls: EvidenceKmsTlsMaterial,
    private readonly vaultDirectory: string,
  ) {
    this.kms = new EvidenceKmsRuntime(pool, kernel, tls);
  }
  async consume(
    context: NotificationDeliveryMaterialContext,
    producerSocket: TLSSocket,
    signal: AbortSignal,
    use: NotificationDeliveryMaterialConsumer,
  ): Promise<void> {
    let plaintext: Buffer | undefined;
    let ciphertext: Buffer | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let borrowed = false;
    const controller = new AbortController();
    const invalidate = () => {
      plaintext?.fill(0);
      controller.abort();
    };
    try {
      // WeakSet/WeakMap admission precedes accessing any caller-shaped context,
      // callback, vault path, selector or KMS dependency.
      assertNotificationDeliveryMaterialContext(context);
      assertNotificationDeliveryMaterialStage(
        context.stage,
        context.client,
        context.selector.source,
      );
      if (!(signal instanceof AbortSignal) || signal.aborted || typeof use !== 'function')
        unavailable();
      if (consumedContexts.has(context)) unavailable();
      consumedContexts.add(context);
      const stage = context.stage,
        p = stage.preparation,
        original = context.original;
      if (
        canonicalJson(stage.deliverySource) !== canonicalJson(original.source) ||
        stage.reference.keyId !== original.source.keyId ||
        stage.reference.encryptedObjectDigest !== original.source.encryptedObjectDigest ||
        p.objectIntent.payloadDigest !== original.attempt.payloadDigest ||
        stage.custodyDigest !== original.source.custodyDigest
      )
        unavailable();
      const now = Date.now();
      // This local upper bound does not renew a KMS STATUS or DEK lease. The full
      // gate independently verifies the original current native receipts again.
      const deadlineAtMs = Math.min(
        original.attempt.deadlineAtMs,
        original.channel.claims.validUntilMs,
        p.kms.validUntilMs,
        context.admission.installation.profile.validUntilMs,
        now + evidenceKmsLimits.statusMaximumAgeMs,
      );
      const bound = Object.freeze({
        deadlineAtMs,
        monotonicDeadlineMs: performance.now() + deadlineAtMs - now,
      });
      assertBound(bound);
      const current = () => {
        if (signal.aborted || controller.signal.aborted || remaining(bound) <= 0) {
          invalidate();
          unavailable();
        }
      };
      const expire = () => {
        if (remaining(bound) <= 0) invalidate();
        else {
          timer = setTimeout(expire, Math.min(Math.ceil(remaining(bound)), 2147483647));
          timer.unref();
        }
      };
      signal.addEventListener('abort', invalidate, { once: true });
      current();
      expire();
      await context.assertCurrent();
      current();
      ciphertext = await readVaultFile(
        await openVaultDirectory(this.vaultDirectory),
        notificationKeyFile(p),
        131072,
      );
      const inspected = inspectNotificationKeyCiphertext(p, stage.reference.keyId, ciphertext);
      if (
        inspected.encryptedObjectDigest !== stage.reference.encryptedObjectDigest ||
        inspected.encryptionContextDigest !== stage.reference.encryptionContextDigest
      )
        unavailable();
      current();
      // The original-attempt lock is deliberately not held during native unwrap.
      // Existing KMS owns actual producer identity, DECRYPT permission, committed
      // dispatch, native response verification, recovery and receipt COMMIT.
      await this.kms.withObjectKey(
        producerSocket,
        {
          recipient: {
            participantId: p.input.scope.participantId,
            privacyDomainId: p.input.scope.privacyDomainId,
            producerTrustDigest: p.input.producerTrustDigest,
            installationDigest: p.input.kmsInstallationDigest,
          },
          attemptId: p.preparationId,
          keyId: stage.reference.keyId,
          use: 'DECRYPT',
        },
        controller.signal,
        (material) => {
          try {
            current();
            const keyDeadline = Math.min(
              bound.monotonicDeadlineMs,
              performance.now() + evidenceKmsLimits.leaseMaximumMs,
            );
            const sealed = ciphertext;
            if (!sealed || material.signal.aborted || material.keyId !== stage.reference.keyId)
              throw new NotificationDeliveryMaterialError('UNAVAILABLE');
            // Synchronous AEAD verifies exact original key, complete AAD, ciphertext
            // digest and minimized plaintext digest. No async continuation sees DEK.
            plaintext = openNotificationPayload(
              sealed,
              stage.reference.encryptedObjectDigest,
              { ...p.objectIntent, keyId: stage.reference.keyId },
              material,
            );
            current();
            if (material.signal.aborted || performance.now() >= keyDeadline) unavailable();
            return undefined;
          } finally {
            material.bytes.fill(0);
          }
        },
      );
      // The KMS promise includes COMMIT. Unknown receipt/COMMIT cannot reach use.
      current();
      await context.withCurrent(async (reference) => {
        assertNotificationDeliveryPayloadReference(
          reference,
          context.client,
          context.selector.source,
        );
        await context.assertCurrent();
        current();
        const owned = plaintext;
        if (
          !owned ||
          sha256(owned) !== original.attempt.payloadDigest ||
          reference.reference.keyId !== stage.reference.keyId ||
          reference.reference.encryptedObjectDigest !== stage.reference.encryptedObjectDigest ||
          reference.reference.encryptionContextDigest !== stage.reference.encryptionContextDigest
        )
          throw new NotificationDeliveryMaterialError('UNAVAILABLE');
        await consumeNotificationDeliveryBuffer(
          owned,
          controller.signal,
          bound,
          async (bytes, window) => {
            borrowed = true;
            // Keep the callback's runtime return value for escape rejection even
            // though the supported TypeScript consumer returns only void.
            return await use(bytes, window);
          },
        );
        await context.assertCurrent();
        current();
      });
      current();
    } catch (error) {
      throw new NotificationDeliveryMaterialError(
        borrowed || (error instanceof EvidenceKmsError && error.code === 'UNKNOWN')
          ? 'UNKNOWN'
          : 'UNAVAILABLE',
      );
    } finally {
      clearTimeout(timer);
      if (signal instanceof AbortSignal) signal.removeEventListener('abort', invalidate);
      invalidate();
      ciphertext?.fill(0);
    }
  }
}
