import * as gatewayContracts from './gateway-contracts.js';
import { EventEmitter } from 'node:events';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { PassThrough } from 'node:stream';
import type { SecureContext } from 'node:tls';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { evidenceKeyId, signNotificationClaim } from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  notificationIdempotencyDigest,
  notificationScopeDigest,
  verifyInstalledNotificationChannel,
  type AdapterCallContextV1,
  type NotificationDeliveryAttemptBinding,
  type NotificationGatewayTransportV1,
} from './gateway-contracts.js';
import { createNotificationGatewayAdapter } from './gateway-adapter.js';

// Only the external socket is substituted. Canonical profile/receipt codecs and
// signature, payload, context and deadline validation remain real.
const http = vi.hoisted(() => ({ request: vi.fn(), destroy: vi.fn() }));
vi.mock('node:https', () => ({
  request: http.request,
  Agent: class {
    destroy = http.destroy;
  },
}));
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const urn = (n: number) => `urn:openpc:resource:${id(n)}`;
const digest = (n: number) => `sha256:${String(n).repeat(64)}`;
function key() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
    spki: pair.publicKey.export({ type: 'spki', format: 'der' }),
  };
}
function fixture(channel: NotificationGatewayTransportV1['channel'] = 'WEBHOOK') {
  const issuer = key(),
    signer = key(),
    server = key(),
    now = Date.now();
  const transport: NotificationGatewayTransportV1 = {
    protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
    channel,
    destinationRef: urn(3),
    credentialRef: urn(4),
    endpoint: 'https://gateway.test:9443/',
    addresses: ['127.0.0.1'],
    serverSpkiDigest: sha256(server.spki),
    requestTimeoutMs: 1000,
    maxPayloadBytes: 1024,
  };
  function install(revision = '1') {
    const signed = signNotificationClaim(
      'NotificationChannelProfileV1',
      issuer.privateKey,
      issuer.spki,
      {
        environmentId: 'test',
        participantId: id(1),
        privacyDomainId: id(2),
        profileId: id(5),
        revision,
        validFromMs: now - 60000,
        validUntilMs: now + 60000,
        transportProfileDigest: sha256(transport),
        receiptSignerSpki: signer.spki.toString('hex'),
        issuerKeyId: evidenceKeyId(issuer.spki),
      },
    );
    return verifyInstalledNotificationChannel(
      {
        environmentId: 'test',
        participantId: id(1),
        privacyDomainId: id(2),
        signedProfileDigest: sha256(signed.cose),
        issuerSpkiHex: issuer.spki.toString('hex'),
      },
      {
        transport,
        payloadHex: signed.payload.toString('hex'),
        coseHex: signed.cose.toString('hex'),
      },
    );
  }
  const installed = install();
  const payload = Buffer.from('{"message":"ready"}');
  const attempt: NotificationDeliveryAttemptBinding = {
    version: 'NotificationDeliveryAttemptV1',
    participantId: id(1),
    privacyDomainId: id(2),
    notificationOccurrenceId: urn(6),
    endpointId: urn(7),
    endpointRevision: '1',
    channel,
    destinationRef: transport.destinationRef,
    credentialRef: transport.credentialRef,
    channelProfileDigest: installed.signedProfileDigest,
    templateDigest: digest(2),
    payloadDigest: sha256(payload),
    payloadBytes: payload.length,
    attemptId: id(8),
    attemptNumber: 1,
    startedAtMs: now,
    deadlineAtMs: now + 1000,
  };
  const context: AdapterCallContextV1 = {
    authorizationDigest: digest(3),
    profileDigest: installed.signedProfileDigest,
    authorizationContextId: id(9),
    authorizationContextEpoch: 1,
    accessClassIds: ['ACCESS-NOTIFICATION'],
    scopeDigest: notificationScopeDigest(attempt),
    deadlineAt: new Date(attempt.deadlineAtMs).toISOString(),
    idempotencyDigest: notificationIdempotencyDigest(attempt),
    occurrenceId: id(6),
    auditCorrelationId: id(10),
    cancellation: { mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION', occurrenceId: id(6) },
    reconciliation: { mode: 'EXACT_OCCURRENCE', occurrenceId: id(6) },
  };
  const controller = new AbortController();
  const window = { signal: controller.signal, timeoutMs: 1000 };
  const secureContext = {} as SecureContext; // Consumed only by the external socket mock.
  function signed(changes = {}) {
    const bytes = signNotificationClaim(
      'NotificationDeliveryReceiptV1',
      signer.privateKey,
      signer.spki,
      {
        environmentId: 'test',
        participantId: id(1),
        privacyDomainId: id(2),
        receiptId: id(11),
        signedProfileDigest: installed.signedProfileDigest,
        attemptDigest: sha256(attempt),
        contextDigest: sha256(context),
        outcome: 'DELIVERED',
        observedAtMs: now + 1,
        signerKeyId: evidenceKeyId(signer.spki),
        ...changes,
      },
    );
    return { payloadHex: bytes.payload.toString('hex'), coseHex: bytes.cose.toString('hex') };
  }
  const make = (current = installed, clientFingerprint?: string) =>
    createNotificationGatewayAdapter(installed, current, secureContext, window, clientFingerprint);
  return {
    installed,
    attempt,
    context,
    controller,
    window,
    make,
    install,
    server,
    signed,
    request: { attempt, payloadBase64: payload.toString('base64') },
  };
}

function socket(
  f: ReturnType<typeof fixture>,
  bytes: Buffer | undefined,
  status = 200,
  headers: Record<string, string> = {},
  peerDigestMismatch = false,
) {
  const outgoing = Object.assign(new EventEmitter(), { destroy: vi.fn(), end: vi.fn() });
  const sent: Buffer[] = [];
  const tls = Object.assign(new EventEmitter(), {
    authorized: true,
    getProtocol: (): string => 'TLSv1.3',
    getCertificate: () => ({ raw: Buffer.from('client') }),
    getPeerCertificate: () => ({
      subjectaltname: 'DNS:gateway.test',
    }),
    getPeerX509Certificate: () => ({
      publicKey: createPublicKey({
        key: peerDigestMismatch ? key().spki : f.server.spki,
        type: 'spki',
        format: 'der',
      }),
    }),
  });
  const response = Object.assign(new PassThrough(), {
    statusCode: status,
    headers: { 'content-type': 'application/json', ...headers },
    complete: true,
  });
  http.request.mockImplementationOnce((_options, received) => {
    outgoing.end.mockImplementation((wire: Buffer) => {
      sent.push(Buffer.from(wire));
      received(response);
      if (bytes) response.end(bytes);
    });
    queueMicrotask(() => {
      outgoing.emit('socket', tls);
      tls.emit('secureConnect');
    });
    return outgoing;
  });
  return { outgoing, tls, response, sent };
}
afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe('notification gateway transport', () => {
  it.each(['WEBHOOK', 'EMAIL', 'OPERATIONS_QUEUE'] as const)(
    'delivers %s through the exact pinned gateway with original signed bytes',
    async (channel) => {
      const f = fixture(channel),
        signed = f.signed();
      const external = socket(f, Buffer.from(canonicalJson(signed)));
      const result = await f.make().deliver(f.request, f.context);
      expect(result.signed).toEqual(signed);
      expect(result.claims.outcome).toBe('DELIVERED');
      expect(http.request).toHaveBeenCalledTimes(1);
      const options = http.request.mock.calls[0]![0];
      expect(options).toMatchObject({
        hostname: '127.0.0.1',
        port: 9443,
        servername: 'gateway.test',
        path: '/notifications/v1/deliver',
        method: 'POST',
        rejectUnauthorized: true,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        headers: { host: 'gateway.test:9443' },
      });
      expect(options.lookup).toBeUndefined();
      expect(JSON.parse(external.sent[0]!.toString())).toEqual({
        ...f.request,
        context: f.context,
      });
      expect(external.outgoing.end.mock.calls[0]![0]).toEqual(
        Buffer.alloc(external.sent[0]!.length),
      );
      expect(external.outgoing.destroy).toHaveBeenCalled();
      expect(http.destroy).toHaveBeenCalled();
    },
  );
  it('reconciles an expired original using a compatible renewed profile without payload or resend', async () => {
    const f = fixture();
    f.attempt.startedAtMs -= 2000;
    f.attempt.deadlineAtMs -= 2000;
    f.context.deadlineAt = new Date(f.attempt.deadlineAtMs).toISOString();
    const signed = f.signed(),
      external = socket(f, Buffer.from(canonicalJson(signed)));
    expect((await f.make(f.install('2')).reconcile(f.attempt, f.context)).signed).toEqual(signed);
    expect(http.request.mock.calls[0]![0].path).toBe('/notifications/v1/readback');
    expect(JSON.parse(external.sent[0]!.toString())).toEqual({
      attempt: f.attempt,
      context: f.context,
    });
  });
  it('rejects cancellation, expired authority and malformed payload before connecting', async () => {
    const f = fixture();
    f.controller.abort();
    await expect(f.make().deliver(f.request, f.context)).rejects.toMatchObject({
      reason: 'CANCELLED',
    });
    const expired = fixture();
    expired.window.timeoutMs = 0;
    await expect(expired.make().deliver(expired.request, expired.context)).rejects.toMatchObject({
      reason: 'CONTRACT',
    });
    const elapsed = fixture();
    elapsed.attempt.startedAtMs -= 2000;
    elapsed.attempt.deadlineAtMs -= 2000;
    elapsed.context.deadlineAt = new Date(elapsed.attempt.deadlineAtMs).toISOString();
    await expect(elapsed.make().deliver(elapsed.request, elapsed.context)).rejects.toMatchObject({
      reason: 'AUTHORITY_EXPIRED',
    });
    const malformed = fixture();
    expect(() =>
      malformed.make().deliver({ ...malformed.request, payloadBase64: 'eA==' }, malformed.context),
    ).toThrow('CONTRACT');
    expect(http.request).not.toHaveBeenCalled();
  });
  it('consumes one admitted window exactly once', async () => {
    const f = fixture(),
      adapter = f.make();
    socket(f, Buffer.from(canonicalJson(f.signed())));
    await adapter.deliver(f.request, f.context);
    await expect(adapter.reconcile(f.attempt, f.context)).rejects.toMatchObject({
      reason: 'CONTRACT',
    });
    expect(http.request).toHaveBeenCalledTimes(1);
  });
  it('never writes application bytes to a peer with a different SPKI', async () => {
    const f = fixture(),
      external = socket(f, undefined, 200, {}, true);
    await expect(f.make().deliver(f.request, f.context)).rejects.toMatchObject({
      reason: 'AMBIGUOUS',
    });
    expect(external.outgoing.end).not.toHaveBeenCalled();
  });
  it.each(['chain', 'hostname', 'client', 'protocol'] as const)(
    'sends no application bytes after a failed %s TLS check',
    async (failure) => {
      const f = fixture(),
        external = socket(f, undefined);
      if (failure === 'chain') external.tls.authorized = false;
      if (failure === 'hostname')
        external.tls.getPeerCertificate = () => ({ subjectaltname: 'DNS:unapproved.invalid' });
      if (failure === 'client') external.tls.getCertificate = () => ({ raw: Buffer.alloc(0) });
      if (failure === 'protocol') external.tls.getProtocol = () => 'TLSv1.2';
      await expect(f.make().deliver(f.request, f.context)).rejects.toMatchObject({
        reason: 'AMBIGUOUS',
      });
      expect(external.outgoing.end).not.toHaveBeenCalled();
    },
  );
  it.each([
    ['redirect', 307, { location: 'https://elsewhere.invalid/' }, Buffer.from('{}')],
    ['unsigned no-effect', 200, {}, Buffer.from('{"outcome":"RETRYABLE_NO_EFFECT"}')],
    ['oversized', 200, {}, Buffer.alloc(270337)],
    ['compressed', 200, { 'content-encoding': 'gzip' }, Buffer.from('{}')],
    ['partial', 200, { 'content-length': '1000' }, Buffer.from('{}')],
    ['provider failure', 503, {}, Buffer.from('private provider error')],
  ] as const)('retains %s as ambiguity, with no retry', async (_name, status, headers, bytes) => {
    const f = fixture();
    socket(f, bytes, status, headers);
    await expect(f.make().deliver(f.request, f.context)).rejects.toMatchObject({
      reason: 'AMBIGUOUS',
      message: 'Notification gateway AMBIGUOUS',
    });
    expect(http.request).toHaveBeenCalledTimes(1);
  });
  it('rejects validly signed replies for a sibling context and forged signatures', async () => {
    for (const forged of [false, true]) {
      const f = fixture(),
        signed = f.signed(forged ? {} : { contextDigest: digest(4) });
      if (forged)
        signed.coseHex = `${signed.coseHex.slice(0, -2)}${signed.coseHex.endsWith('00') ? '01' : '00'}`;
      socket(f, Buffer.from(canonicalJson(signed)));
      await expect(f.make().deliver(f.request, f.context)).rejects.toMatchObject({
        reason: 'AMBIGUOUS',
      });
    }
  });
  it.each(['DELIVERED', 'RETRYABLE_NO_EFFECT', 'PERMANENT_FAILURE', 'AMBIGUOUS'] as const)(
    'returns only authenticated %s observations',
    async (outcome) => {
      const f = fixture();
      socket(f, Buffer.from(canonicalJson(f.signed({ outcome }))));
      expect((await f.make().deliver(f.request, f.context)).claims.outcome).toBe(outcome);
    },
  );
  it('tears down a stalled socket on deadline or cancellation', async () => {
    for (const cancel of [true, false]) {
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
      const f = fixture(),
        external = socket(f, undefined);
      const pending = f.make().deliver(f.request, f.context);
      const assertion = expect(pending).rejects.toMatchObject({ reason: 'AMBIGUOUS' });
      await Promise.resolve();
      if (cancel) f.controller.abort();
      else await vi.advanceTimersByTimeAsync(1001);
      await assertion;
      expect(external.outgoing.destroy).toHaveBeenCalled();
      expect(external.response.destroyed).toBe(true);
      vi.useRealTimers();
    }
  });
});

it('binds the actual client certificate to the decoded exact-version material', async () => {
  for (const mismatch of [false, true]) {
    const f = fixture(),
      external = socket(f, Buffer.from(canonicalJson(f.signed())));
    const result = f
      .make(f.installed, sha256(Buffer.from(mismatch ? 'other-client' : 'client')))
      .deliver(f.request, f.context);
    if (mismatch) {
      await expect(result).rejects.toMatchObject({ reason: 'AMBIGUOUS' });
      expect(external.sent).toHaveLength(0);
    } else {
      await expect(result).resolves.toMatchObject({ claims: { outcome: 'DELIVERED' } });
      expect(external.sent).toHaveLength(1);
    }
  }
});
it('rejects malformed certificate bindings before creating a socket', () => {
  const f = fixture();
  expect(() => f.make(f.installed, 'bad')).toThrow('CONTRACT');
  expect(http.request).not.toHaveBeenCalled();
});
it('erases its request wire after a failed exchange and preserves the caller payload', async () => {
  const f = fixture(),
    before = f.request.payloadBase64,
    external = socket(f, Buffer.from('{}'), 503);
  await expect(f.make().deliver(f.request, f.context)).rejects.toMatchObject({
    reason: 'AMBIGUOUS',
  });
  expect(external.sent).toHaveLength(1);
  expect(external.outgoing.end.mock.calls[0]![0]).toEqual(Buffer.alloc(external.sent[0]!.length));
  expect(f.request.payloadBase64).toBe(before);
});

it('erases generated wire even when current admission rejects before socket construction', async () => {
  const f = fixture(),
    spy = vi.spyOn(gatewayContracts, 'notificationDeliveryWire');
  try {
    f.controller.abort();
    await expect(f.make().deliver(f.request, f.context)).rejects.toMatchObject({
      reason: 'CANCELLED',
    });
    expect(spy).toHaveBeenCalledTimes(1);
    const wire = spy.mock.results[0]!.value as Buffer;
    expect(wire).toEqual(Buffer.alloc(wire.length));
    expect(http.request).not.toHaveBeenCalled();
  } finally {
    spy.mockRestore();
  }
});
