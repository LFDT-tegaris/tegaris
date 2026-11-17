import { expect, it } from 'vitest';
import { exchangeNotificationEndpointTls } from './endpoint-tls-binding.js';
import type { NotificationCredentialLease } from '../../../identity-service/src/domain/notification-secret-recipient.js';
import type { NotificationChannelCredential } from './endpoint-owner-contract.js';
import type { NotificationGatewayTransportV1 } from './gateway-contracts.js';

// Pure negative boundary checks only. Positive borrowed-key/TLS, currentness and
// cleanup coverage uses real Identity/PG in notification-gateway-fixture.test.mjs.
it('neither a TLS context nor copied credential bytes create an authenticated lease', async () => {
  for (const fabricated of [
    {},
    { bytes: Buffer.from('key'), signal: new AbortController().signal },
    { secureContext: {}, credential: { state: 'ACTIVE' } },
  ]) {
    await expect(
      exchangeNotificationEndpointTls(
        fabricated as unknown as NotificationCredentialLease,
        {} as NotificationChannelCredential,
        {} as NotificationGatewayTransportV1,
        Buffer.from('{}'),
        { signal: new AbortController().signal, timeoutMs: 1000 },
      ),
    ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
  }
});
