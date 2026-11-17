import { expect, it } from 'vitest';
import {
  notificationConsumerMount,
  NotificationDeliveryConsumerRuntime,
  notificationRunnableSources,
} from './delivery-consumer-runtime.js';
import type { NotificationAsyncWorkRecord } from './async-worker-state.js';
import {
  parseNotificationDeliveryServingConfiguration,
  loadPackagedNotificationDeliveryConsumer,
} from './packaged-delivery-runtime.js';
const id = '01900000-0000-7000-8000-000000000001',
  digest = `sha256:${'a'.repeat(64)}`;
const mount = {
  listen: { host: '127.0.0.1', port: 0 },
  serverName: 'localhost',
  unavailableRetryMs: 5000,
  ceilings: {
    poolMax: 12,
    maximumConcurrency: 2,
    maximumBatchSize: 2,
    cycleTimeoutMs: 15000,
    connectionLifetimeMs: 60000,
  },
};
const files = {
  caFile: '/run/notification/ca.pem',
  certificateFile: '/run/notification/client.pem',
  privateKeyFile: '/run/notification/client.key',
};
const configuration = {
  version: 2,
  worker: { participantId: id, privacyDomainId: id, installationDigest: digest },
  vaultDirectory: '/run/notification/vault',
  kmsTls: files,
  signerTls: files,
  signers: { start: digest, outcome: digest },
  cancellationSignerInstallationDigest: digest,
  timeoutMs: 1000,
  consumer: { ...mount, listenerTls: files, workerTls: files, recipientTls: files },
  providers: [
    {
      credential: {
        participantId: id,
        privacyDomainId: id,
        credentialRef: `urn:openpc:resource:${id}`,
        destinationRef: `urn:openpc:resource:${id}`,
        channel: 'WEBHOOK',
        owner: 'LS-NOTIFICATION',
        secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
        reference: 'secret://local/notification#1',
        version: '1',
        epoch: '1',
        fingerprint: digest,
        validFromMs: 1000,
        validUntilMs: 100000,
        state: 'ACTIVE',
      },
      address: '127.0.0.1',
      port: 3449,
      serverName: 'provider',
      serverSpkiDigest: digest,
      tls: files,
    },
  ],
};
it('parses serving mount metadata without starting a listener or conferring readiness', () => {
  expect(notificationConsumerMount.parse(mount)).toEqual(mount);
  expect(parseNotificationDeliveryServingConfiguration(configuration)).toEqual(configuration);
});
it.each(['ready', 'native', 'source', 'peers', 'generation', 'capacity'])(
  'rejects caller %s from the serving mount',
  (field) => {
    expect(() =>
      parseNotificationDeliveryServingConfiguration({ ...configuration, [field]: true }),
    ).toThrow();
    expect(() => notificationConsumerMount.parse({ ...mount, [field]: true })).toThrow();
  },
);
it('refuses partial serving mounts, a public listener and unsafe retry/resource limits', () => {
  for (const changed of [
    { version: 1 },
    { consumer: { ...configuration.consumer, listenerTls: undefined } },
    { consumer: { ...configuration.consumer, listen: { host: '0.0.0.0', port: 3448 } } },
    { consumer: { ...configuration.consumer, unavailableRetryMs: 0 } },
    { consumer: { ...configuration.consumer, ceilings: { ...mount.ceilings, poolMax: 100000 } } },
  ])
    expect(() =>
      parseNotificationDeliveryServingConfiguration({ ...configuration, ...changed }),
    ).toThrow();
});
it('missing optional serving configuration owns no resources', async () => {
  await expect(
    loadPackagedNotificationDeliveryConsumer(undefined, { database: {} }),
  ).resolves.toBeUndefined();
});
it('rejects malformed constructor inputs before transport construction', () => {
  expect(
    () => new NotificationDeliveryConsumerRuntime({ mount: { ready: true } } as never),
  ).toThrow();
});

// Pure scheduling corpus only. No entry is an installed native admission,
// durable quarantine or evidence of a real successful enqueue/restart.
const source = {
  worker: configuration.worker,
  eventId: id,
  notificationOccurrenceId: id,
};
const pending: NotificationAsyncWorkRecord = {
  source,
  state: 'PENDING',
  reason: null,
  revision: '1',
  proofEventId: id,
  deadlineAtMs: 10000,
  nextAtMs: null,
  lease: null,
  leaseUntilMs: null,
  charged: false,
  effectUncertain: false,
  original: { source },
};
it('keeps an independent admitted sibling selectable after a source rejection', () => {
  expect(
    notificationRunnableSources([
      { status: 'rejected', reason: new Error('source rejected') },
      { status: 'fulfilled', value: pending },
    ]),
  ).toEqual([source]);
});
it('never uses terminal quarantine, completed or unknown work as a dispatch anchor', () => {
  for (const state of ['QUARANTINED', 'DONE', 'CANCELLED', 'UNKNOWN']) {
    const retained = { ...pending, state };
    expect(notificationRunnableSources([{ status: 'fulfilled', value: retained }])).toEqual([]);
    expect(
      notificationRunnableSources([
        { status: 'fulfilled', value: retained },
        { status: 'fulfilled', value: pending },
      ]),
    ).toEqual([source]);
    expect(retained.state).toBe(state);
  }
});
it('preserves charged unknown-effect quarantine for original reconciliation', () => {
  const retained = { ...pending, state: 'QUARANTINED', charged: true, effectUncertain: true };
  expect(notificationRunnableSources([{ status: 'fulfilled', value: retained }])).toEqual([source]);
  expect(retained).toMatchObject({ charged: true, effectUncertain: true });
});
