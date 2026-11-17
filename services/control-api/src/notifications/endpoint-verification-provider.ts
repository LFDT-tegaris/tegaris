import {
  assertNotificationCredentialLease,
  type NotificationCredentialLease,
} from '../../../identity-service/src/domain/notification-secret-recipient.js';
import { sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  notificationVerificationWire,
  verifyNotificationVerificationResponse,
  type InstalledNotificationVerification,
  type NotificationVerificationChallenge,
  type AuthenticatedNotificationVerification,
} from '../configuration/notification-verification-contract.js';
import {
  notificationGatewayTransport,
  NotificationGatewayError,
  type NotificationGatewayWindow,
} from './gateway-contracts.js';
import { exchangeNotificationEndpointTls } from './endpoint-tls-binding.js';

export interface NotificationVerificationResult {
  readonly responseBytes: Buffer;
  readonly authenticatedAtMs: number;
  readonly authenticated: AuthenticatedNotificationVerification;
}

/** Called after the durable attempt's DISPATCHED commit. The actual lease owns
 * TLS bytes and currentness; no constructor-supplied TLS context can substitute.
 * Transport failure never establishes a no-effect result or authorizes resend. */
export async function verifyNotificationEndpointProvider(
  installedValue: InstalledNotificationVerification,
  original: NotificationVerificationChallenge,
  lease: NotificationCredentialLease,
  window: NotificationGatewayWindow,
): Promise<NotificationVerificationResult> {
  const installed = immutableJsonCopy(installedValue);
  const transport = notificationGatewayTransport.parse(installed.channel.transport);
  if (
    sha256(transport) !== installed.channel.claims.transportProfileDigest ||
    !Number.isSafeInteger(window.timeoutMs) ||
    window.timeoutMs <= 0
  )
    throw new NotificationGatewayError('CONTRACT');
  if (window.signal.aborted) throw new NotificationGatewayError('CANCELLED');
  const deadline = assertNotificationCredentialLease(lease, original.credential);
  const bytes = notificationVerificationWire(installed, original, Date.now());
  const timeoutMs = Math.min(
    window.timeoutMs,
    transport.requestTimeoutMs,
    original.expiresAtMs - Date.now(),
    deadline - Date.now(),
  );
  if (timeoutMs <= 0) throw new NotificationGatewayError('AUTHORITY_EXPIRED');
  const response = await exchangeNotificationEndpointTls(
    lease,
    original.credential,
    transport,
    bytes,
    { ...window, timeoutMs },
  );
  try {
    assertNotificationCredentialLease(lease, original.credential);
    if (window.signal.aborted || Date.now() >= original.expiresAtMs) throw new Error();
    const authenticated = verifyNotificationVerificationResponse(
      installed,
      original,
      response.responseBytes,
      response.authenticatedAtMs,
    );
    assertNotificationCredentialLease(lease, original.credential);
    return { ...response, authenticated };
  } catch {
    throw new NotificationGatewayError('AMBIGUOUS');
  }
}
