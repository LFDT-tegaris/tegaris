import { expect, it } from 'vitest';
import type { NotificationCredentialLease } from '../../../identity-service/src/domain/notification-secret-recipient.js';
import type {
  InstalledNotificationVerification,
  NotificationVerificationChallenge,
} from '../configuration/notification-verification-contract.js';
import { sha256 } from '../configuration/digest.js';
import { verifyNotificationEndpointProvider } from './endpoint-verification-provider.js';

// Transport preflight negatives only. Real TLS/pinning/signatures/restart and
// zero-delivery assertions are in the existing external gateway fixture suite.
const transport = {
  protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
  channel: 'WEBHOOK',
  destinationRef: 'urn:openpc:resource:01900000-0000-7000-8000-000000000001',
  credentialRef: 'urn:openpc:resource:01900000-0000-7000-8000-000000000002',
  endpoint: 'https://gateway.invalid/',
  addresses: ['127.0.0.1'],
  serverSpkiDigest: `sha256:${'1'.repeat(64)}`,
  requestTimeoutMs: 1000,
  maxPayloadBytes: 1024,
};
const installed = {
  channel: { transport, claims: { transportProfileDigest: sha256(transport) } },
} as unknown as InstalledNotificationVerification;
it('cancelled admission performs no challenge parsing or socket allocation', async () => {
  const controller = new AbortController();
  controller.abort();
  await expect(
    verifyNotificationEndpointProvider(
      installed,
      {} as NotificationVerificationChallenge,
      {} as NotificationCredentialLease,
      { signal: controller.signal, timeoutMs: 1000 },
    ),
  ).rejects.toMatchObject({ reason: 'CANCELLED' });
});
it('rejects nonfinite, zero and fractional budgets before network allocation', async () => {
  for (const timeoutMs of [0, -1, NaN, Infinity, 0.5])
    await expect(
      verifyNotificationEndpointProvider(
        installed,
        {} as NotificationVerificationChallenge,
        {} as NotificationCredentialLease,
        { signal: new AbortController().signal, timeoutMs },
      ),
    ).rejects.toMatchObject({ reason: 'CONTRACT' });
});
it('rejects a transport substitution even if the endpoint URL remains the same', async () => {
  const changed = {
    ...installed,
    channel: {
      ...installed.channel,
      transport: { ...installed.channel.transport, addresses: ['127.0.0.2'] },
    },
  };
  await expect(
    verifyNotificationEndpointProvider(
      changed,
      {} as NotificationVerificationChallenge,
      {} as NotificationCredentialLease,
      { signal: new AbortController().signal, timeoutMs: 1000 },
    ),
  ).rejects.toMatchObject({ reason: 'CONTRACT' });
});

it('a fabricated lease fails before TLS even with a matching transport digest', async () => {
  await expect(
    verifyNotificationEndpointProvider(
      installed,
      {} as NotificationVerificationChallenge,
      {} as NotificationCredentialLease,
      { signal: new AbortController().signal, timeoutMs: 1000 },
    ),
  ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
});
