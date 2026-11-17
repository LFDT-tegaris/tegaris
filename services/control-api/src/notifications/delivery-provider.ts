import { performance } from 'node:perf_hooks';
import {
  assertNotificationCredentialLease,
  type NotificationCredentialLease,
} from '../../../identity-service/src/domain/notification-secret-recipient.js';
import { decodeNotificationCredentialMaterial } from '../../../identity-service/src/domain/notification-credential-material.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  notificationChannelCredential,
  type NotificationChannelCredential,
} from './endpoint-owner-contract.js';
import { validateNotificationDeliveryStartTransition } from './delivery-start-transition.js';
import { createNotificationGatewayAdapter } from './gateway-adapter.js';
import {
  assertNotificationDispatch,
  notificationGatewayTransport,
  verifyNotificationReceipt,
  NotificationGatewayError,
  type InstalledNotificationChannel,
  type NotificationGatewayWindow,
  type NotificationDeliveryReceiptV1,
} from './gateway-contracts.js';

export interface NotificationDeliveryProviderInput {
  /** Exact historical signed STARTED record, never a live dispatch capability. */
  readonly original: unknown;
  /** Supplied by the current installed-channel owner, not request data. */
  readonly current: InstalledNotificationChannel;
  readonly credential: NotificationChannelCredential;
  /** Genuine, active WeakMap-backed recipient lease. Copies are rejected. */
  readonly lease: NotificationCredentialLease;
  readonly window: NotificationGatewayWindow;
}

function observation(
  original: ReturnType<typeof validateNotificationDeliveryStartTransition>,
  value: unknown,
) {
  const supplied = immutableJsonCopy(value) as NotificationDeliveryReceiptV1;
  const checked = verifyNotificationReceipt(
    original.channel,
    original.attempt,
    original.context,
    supplied.signed,
  );
  if (canonicalJson(supplied) !== canonicalJson(checked))
    throw new NotificationGatewayError('CONTRACT');
  return checked;
}
/** Pure original-observation consistency, never dispatch or receipt-persistence
 * authority. Different valid signatures cannot replace the retained first one. */
export function validateNotificationDeliveryProviderObservation(
  originalValue: unknown,
  value: unknown,
  first?: unknown,
): NotificationDeliveryReceiptV1 {
  try {
    const original = validateNotificationDeliveryStartTransition(originalValue),
      checked = observation(original, value);
    if (
      first !== undefined &&
      canonicalJson(checked) !== canonicalJson(observation(original, first))
    )
      throw new NotificationGatewayError('AMBIGUOUS');
    return checked;
  } catch (error) {
    if (error instanceof NotificationGatewayError) throw error;
    throw new NotificationGatewayError('CONTRACT');
  }
}

/** Transport-only composition. The caller must first commit its exclusive
 * durable gateway claim and retain real delivery/cancellation/material fences.
 * Neither this input, signed STARTED, nor a credential lease grants that claim.
 * No dispatch store, plaintext reader, retry or public route is installed here. */
function admitted(input: NotificationDeliveryProviderInput, mode: 'INITIAL_SEND' | 'RECONCILE') {
  const enteredAt = performance.now(),
    enteredWall = Date.now();
  try {
    const original = validateNotificationDeliveryStartTransition(input.original);
    const current = immutableJsonCopy(input.current);
    const credential = notificationChannelCredential.parse(immutableJsonCopy(input.credential));
    const transport = notificationGatewayTransport.parse(current.transport);
    const transportDigest = sha256(transport);
    const lease = input.lease;
    const signal = input.window.signal;
    const timeout = input.window.timeoutMs;
    if (
      !(signal instanceof AbortSignal) ||
      !Number.isSafeInteger(timeout) ||
      timeout <= 0 ||
      current.claims.transportProfileDigest !== transportDigest ||
      credential.participantId !== original.receipt.participantId ||
      credential.privacyDomainId !== original.receipt.privacyDomainId ||
      credential.credentialRef !== transport.credentialRef ||
      credential.channel !== transport.channel ||
      credential.destinationRef !== transport.destinationRef
    )
      throw new Error();
    if (signal.aborted) throw new NotificationGatewayError('CANCELLED');
    const leaseDeadline = assertNotificationCredentialLease(lease, credential, transportDigest);
    const material = decodeNotificationCredentialMaterial(lease.bytes);
    if (material.fingerprint !== credential.fingerprint) throw new Error();
    const controller = new AbortController();
    const abort = () => controller.abort();
    const signals = [signal, lease.signal];
    const deadline = Math.min(leaseDeadline, material.validUntilMs, enteredWall + timeout);
    const expires = enteredAt + timeout;
    const check = () => {
      assertNotificationCredentialLease(lease, credential, transportDigest);
      if (
        signals.some((s) => s.aborted) ||
        controller.signal.aborted ||
        Date.now() >= deadline ||
        performance.now() >= expires
      )
        throw new NotificationGatewayError('AUTHORITY_EXPIRED');
    };
    check();
    const timeoutMs = assertNotificationDispatch(
      current,
      original.channel,
      original.attempt,
      original.context,
      mode,
      Date.now(),
      {
        signal: controller.signal,
        timeoutMs: Math.min(
          timeout - Math.ceil(performance.now() - enteredAt),
          deadline - Date.now(),
        ),
      },
    );
    // Material's only consumer is the established pinned gateway adapter. No
    // SecureContext or leased bytes escape from this bounded invocation.
    const adapter = createNotificationGatewayAdapter(
      original.channel,
      current,
      material.secureContext,
      { signal: controller.signal, timeoutMs },
      material.clientCertificateFingerprint,
    );
    for (const source of signals) source.addEventListener('abort', abort, { once: true });
    if (signals.some((s) => s.aborted)) abort();
    return {
      original,
      adapter,
      check,
      close() {
        for (const source of signals) source.removeEventListener('abort', abort);
        abort();
      },
    };
  } catch (error) {
    if (error instanceof NotificationGatewayError) throw error;
    throw new NotificationGatewayError('CONTRACT');
  }
}

/** Borrows the caller's plaintext without wiping or retaining it. Its own copy
 * and the adapter's wire copies are erased on all paths; JS strings/native TLS
 * copies are not claimed to be synchronously erasable. Return is an authenticated
 * observation only: the durable owner still must persist receipt/state/outbox. */
export async function deliverNotificationProvider(
  input: NotificationDeliveryProviderInput,
  plaintext: Buffer,
): Promise<NotificationDeliveryReceiptV1> {
  const active = admitted(input, 'INITIAL_SEND');
  let owned: Buffer | undefined;
  let entered = false;
  try {
    if (
      !Buffer.isBuffer(plaintext) ||
      plaintext.length !== active.original.attempt.payloadBytes ||
      plaintext.length > 65536 ||
      sha256(plaintext) !== active.original.attempt.payloadDigest
    )
      throw new NotificationGatewayError('CONTRACT');
    owned = Buffer.from(plaintext);
    active.check();
    entered = true;
    const result = await active.adapter.deliver(
      { attempt: active.original.attempt, payloadBase64: owned.toString('base64') },
      active.original.context,
    );
    active.check();
    return result;
  } catch (error) {
    // Any loss after entering external exchange is ambiguous, including a late
    // lease/currentness failure after a valid signed gateway response.
    if (entered) throw new NotificationGatewayError('AMBIGUOUS');
    if (error instanceof NotificationGatewayError) throw error;
    throw new NotificationGatewayError('CONTRACT');
  } finally {
    owned?.fill(0);
    active.close();
  }
}

/** Original readback only, including after original deadline/cancellation. The
 * owner supplies a new current credential window for lookup; it never supplies
 * payload, refreshes attempt/context, or converts ABSENT/transport loss into a
 * definitive no-effect result. A supplied first persisted receipt is reverified
 * and must remain byte-identical, including its signature. No fallback to deliver exists. */
export async function reconcileNotificationProvider(
  input: NotificationDeliveryProviderInput,
  first?: NotificationDeliveryReceiptV1,
): Promise<NotificationDeliveryReceiptV1> {
  const active = admitted(input, 'RECONCILE');
  try {
    const retained = first === undefined ? undefined : observation(active.original, first);
    active.check();
    const result = await active.adapter.reconcile(active.original.attempt, active.original.context);
    const checked = validateNotificationDeliveryProviderObservation(
      active.original,
      result,
      retained,
    );
    active.check();
    return checked;
  } catch {
    throw new NotificationGatewayError('AMBIGUOUS');
  } finally {
    active.close();
  }
}
