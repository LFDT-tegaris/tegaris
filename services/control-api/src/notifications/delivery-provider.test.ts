import { signNotificationClaim, evidenceKeyId } from '@openpc/security-kernel';
import { verifyNotificationReceipt } from './gateway-contracts.js';
import { expect, it, vi, afterEach } from 'vitest';
import { getEventListeners } from 'node:events';
import { readFileSync } from 'node:fs';
import { sha256 } from '../configuration/digest.js';
import {
  notificationDeliveryProviderSample,
  createNotificationDeliveryExternalFixture,
} from '../../../../tests/integration/identity/notification-delivery-provider-cases.js';
import {
  deliverNotificationProvider,
  reconcileNotificationProvider,
  validateNotificationDeliveryProviderObservation,
} from './delivery-provider.js';
import type { NotificationChannelCredential } from './endpoint-owner-contract.js';
import type { NotificationCredentialLease } from '../../../identity-service/src/domain/notification-secret-recipient.js';
afterEach(() => vi.useRealTimers());
function fakeInput() {
  const f = notificationDeliveryProviderSample(),
    o = f.original;
  const credential: NotificationChannelCredential = {
    participantId: o.receipt.participantId,
    privacyDomainId: o.receipt.privacyDomainId,
    credentialRef: o.channel.transport.credentialRef,
    channel: o.channel.transport.channel,
    destinationRef: o.channel.transport.destinationRef,
    secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
    owner: 'LS-NOTIFICATION',
    reference: 'secret://notification-component/channel#v1',
    version: 'v1',
    fingerprint: sha256('not-material'),
    epoch: '1',
    validFromMs: Date.now() - 1000,
    validUntilMs: Date.now() + 600000,
    state: 'ACTIVE',
  };
  const controller = new AbortController(),
    bytes = Buffer.from('PRIVATE_CANARY');
  // Intentionally forged negative input, never used as positive authority.
  const lease = { credential, bytes, signal: controller.signal } as NotificationCredentialLease;
  return {
    f,
    bytes,
    controller,
    input: {
      original: o,
      current: o.channel,
      credential,
      lease,
      window: { signal: controller.signal, timeoutMs: 1000 },
    },
  };
}
it('rejects a caller-made or copied lease before outbound connection and leaves borrowed buffers intact', async () => {
  const { f, bytes, input, controller } = fakeInput(),
    payload = Buffer.from(f.payload),
    credentialBytes = Buffer.from(bytes);
  for (const lease of [input.lease, { ...input.lease }]) {
    await expect(deliverNotificationProvider({ ...input, lease }, f.payload)).rejects.toThrow(
      'CONTRACT',
    );
    await expect(reconcileNotificationProvider({ ...input, lease })).rejects.toThrow('CONTRACT');
  }
  expect(f.payload).toEqual(payload);
  expect(bytes).toEqual(credentialBytes);
  expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
});
it.each(['signature', 'extra', 'context', 'profile', 'window', 'scope'] as const)(
  'rejects malformed %s without caller supplied readiness',
  async (kind) => {
    const { f, input } = fakeInput(),
      value = structuredClone(input.original);
    if (kind === 'signature') value.coseHex = '00';
    if (kind === 'extra') Object.assign(value, { dispatched: true });
    if (kind === 'context') value.context.auditCorrelationId = value.sourceOperationId;
    if (kind === 'profile')
      input.current = { ...input.current, signedProfileDigest: sha256('other') };
    if (kind === 'window') input.window.timeoutMs = 0;
    if (kind === 'scope') input.credential.participantId = input.credential.privacyDomainId;
    await expect(
      deliverNotificationProvider({ ...input, original: value }, f.payload),
    ).rejects.toThrow();
  },
);
it('production leaf depends only on committed owners, separates payload-free recovery and has no dispatch or plaintext authority shortcut', () => {
  const source = readFileSync(new URL('./delivery-provider.ts', import.meta.url), 'utf8');
  for (const name of [
    'assertNotificationCredentialLease',
    'validateNotificationDeliveryStartTransition',
    'decodeNotificationCredentialMaterial',
    'createNotificationGatewayAdapter',
    'clientCertificateFingerprint',
  ])
    expect(source).toContain(name);
  const recovery = source.slice(
    source.indexOf('export async function reconcileNotificationProvider'),
  );
  expect(recovery).not.toMatch(/\.deliver\(|payloadBase64|\.consume\(|\.fill\(/u);
  expect(source).not.toMatch(
    /delivery-signing|delivery-start-atomic|NotificationPayloadReader|setInterval|createServer|\.query\(/u,
  );
});
it.each(['WEBHOOK', 'EMAIL', 'OPERATIONS_QUEUE'] as const)(
  'external mTLS component retains exact %s request/signature across lost ACK and gateway restart',
  async (channel) => {
    const f = await createNotificationDeliveryExternalFixture(channel),
      signal = new AbortController().signal;
    try {
      const request = { attempt: f.original.attempt, payloadBase64: f.payload.toString('base64') };
      f.setFault('LOST_ACK');
      await expect(
        f.provider({ signal, timeoutMs: 2000 }).deliver(request, f.original.context),
      ).rejects.toMatchObject({ reason: 'AMBIGUOUS' });
      expect(f.stats()).toMatchObject({ calls: 1, readbacks: 0, delivered: 1, receipts: 1 });
      f.setFault('NORMAL');
      const first = await f
        .provider({ signal, timeoutMs: 2000 })
        .reconcile(f.original.attempt, f.original.context);
      await f.restart();
      const before = f.stats();
      const retained = await f
        .provider({ signal, timeoutMs: 2000 })
        .reconcile(f.original.attempt, f.original.context);
      expect(retained).toEqual(first);
      expect(f.stats().calls).toBe(before.calls);
      expect(f.stats().readbacks - before.readbacks).toBe(1);
      expect(f.payload.toString()).toBe('{"message":"ready"}');
    } finally {
      await f.close();
    }
  },
);
it('real TLS sends no application bytes for a wrong client-certificate binding and never turns absent readback into no-effect', async () => {
  const f = await createNotificationDeliveryExternalFixture('WEBHOOK'),
    signal = new AbortController().signal;
  try {
    await expect(
      f
        .provider({ signal, timeoutMs: 1000 }, sha256('wrong-client'))
        .deliver(
          { attempt: f.original.attempt, payloadBase64: f.payload.toString('base64') },
          f.original.context,
        ),
    ).rejects.toMatchObject({ reason: 'AMBIGUOUS' });
    expect(f.stats().calls).toBe(0);
    await expect(
      f.provider({ signal, timeoutMs: 1000 }).reconcile(f.original.attempt, f.original.context),
    ).rejects.toMatchObject({ reason: 'AMBIGUOUS' });
    expect(f.stats()).toMatchObject({ calls: 0, readbacks: 1, delivered: 0, receipts: 0 });
  } finally {
    await f.close();
  }
});
it('real TLS recovers expired original identity without another deliver and aborts a stalled socket', async () => {
  const f = await createNotificationDeliveryExternalFixture('WEBHOOK'),
    controller = new AbortController();
  try {
    const first = await f
      .provider({ signal: controller.signal, timeoutMs: 2000 })
      .deliver(
        { attempt: f.original.attempt, payloadBase64: f.payload.toString('base64') },
        f.original.context,
      );
    const before = f.stats();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(f.original.attempt.deadlineAtMs + 1);
    const retained = await f
      .provider({ signal: controller.signal, timeoutMs: 1000 })
      .reconcile(f.original.attempt, f.original.context);
    expect(retained).toEqual(first);
    expect(f.stats().calls).toBe(before.calls);
    vi.useRealTimers();
    f.setFault('STALL');
    const pending = f
      .provider({ signal: controller.signal, timeoutMs: 1000 })
      .reconcile(f.original.attempt, f.original.context);
    await vi.waitFor(() => expect(f.stats().readbacks).toBe(before.readbacks + 2), {
      timeout: 700,
      interval: 5,
    });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ reason: 'AMBIGUOUS' });
    expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
  } finally {
    vi.useRealTimers();
    await f.close();
  }
});

it('reverifies retained original receipt and rejects a changed valid signature, sibling context or forged metadata', () => {
  const f = notificationDeliveryProviderSample(),
    o = f.original;
  const sign = (contextDigest = sha256(o.context)) => {
    const signed = signNotificationClaim(
      'NotificationDeliveryReceiptV1',
      f.signerPrivateKey,
      f.signerSpki,
      {
        environmentId: o.receipt.environmentId,
        participantId: o.receipt.participantId,
        privacyDomainId: o.receipt.privacyDomainId,
        receiptId: o.receipt.receiptId,
        signedProfileDigest: o.channel.signedProfileDigest,
        attemptDigest: sha256(o.attempt),
        contextDigest,
        outcome: 'DELIVERED',
        observedAtMs: o.attempt.startedAtMs + 1,
        signerKeyId: evidenceKeyId(f.signerSpki),
      },
    );
    return { payloadHex: signed.payload.toString('hex'), coseHex: signed.cose.toString('hex') };
  };
  try {
    const first = verifyNotificationReceipt(o.channel, o.attempt, o.context, sign());
    expect(validateNotificationDeliveryProviderObservation(o, first, first)).toEqual(first);
    const different = verifyNotificationReceipt(o.channel, o.attempt, o.context, sign());
    expect(different.signed.coseHex).not.toBe(first.signed.coseHex);
    expect(() => validateNotificationDeliveryProviderObservation(o, different, first)).toThrow(
      'AMBIGUOUS',
    );
    for (const changed of [
      { ...first, signed: sign(sha256('other-context')) },
      { ...first, receiptDigest: sha256('wrong') },
      { ...first, claims: { ...first.claims, outcome: 'RETRYABLE_NO_EFFECT' } },
      { ...first, ready: true },
    ])
      expect(() => validateNotificationDeliveryProviderObservation(o, changed)).toThrow();
  } finally {
    f.signerPrivateKey.fill(0);
    f.issuerPrivateKey.fill(0);
    f.payload.fill(0);
  }
});
