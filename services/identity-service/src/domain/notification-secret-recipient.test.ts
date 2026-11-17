import { expect, it, vi } from 'vitest';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from './identity-kernel.js';
import {
  assertNotificationCredentialLease,
  withNotificationSecretRecipient,
  type NotificationCredentialLease,
  type NotificationSecretRequest,
} from './notification-secret-recipient.js';

it('metadata or a copied lease cannot grant notification secret authority', () => {
  const bytes = Buffer.from('not-a-secret');
  const lease = {
    credential: { owner: 'LS-NOTIFICATION', secretClass: 'SECRET-NOTIFICATION-CREDENTIAL' },
    bytes,
  } as NotificationCredentialLease;
  expect(() => assertNotificationCredentialLease(lease, lease.credential)).toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
  expect(() => assertNotificationCredentialLease({ ...lease }, lease.credential)).toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
});
it('a caller cannot broaden the recipient with a purpose, consumer, installed flag or key bytes', async () => {
  const connect = vi.fn(),
    authenticateWorkload = vi.fn(),
    read = vi.fn(),
    use = vi.fn();
  const base = {
    participantId: 'p',
    privacyDomainId: 'd',
    credentialRef: 'ref',
    reference: 'secret://local/notification#1',
    version: '1',
    epoch: '1',
  };
  for (const change of [
    { consumer: 'LS-FACT-BRIDGE' },
    { purpose: 'POSTGRES_CONNECT' },
    { installed: true },
    { bytes: Buffer.from('data') },
  ]) {
    await expect(
      withNotificationSecretRecipient(
        { connect } as unknown as Pool,
        { authenticateWorkload } as unknown as IdentityKernel,
        {} as TLSSocket,
        { ...base, ...change } as NotificationSecretRequest,
        { withExactVersion: read },
        use,
      ),
    ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
  }
  expect(connect).not.toHaveBeenCalled();
  expect(authenticateWorkload).not.toHaveBeenCalled();
  expect(read).not.toHaveBeenCalled();
  expect(use).not.toHaveBeenCalled();
});

it('an externally aborted lookalike lease still cannot acquire recipient authority', () => {
  const controller = new AbortController();
  controller.abort();
  const lease = {
    bytes: Buffer.from('material'),
    credential: {},
    signal: controller.signal,
  } as NotificationCredentialLease;
  expect(() => assertNotificationCredentialLease(lease, lease.credential)).toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
});
