import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationDeliveryReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  assertNotificationAttempt,
  assertNotificationDispatch,
  notificationDeliveryWire,
  notificationGatewayTransport,
  notificationIdempotencyDigest,
  notificationScopeDigest,
  notificationReadbackWire,
  parseNotificationReceiptWire,
  verifyInstalledNotificationChannel,
  verifyNotificationReceipt,
  type AdapterCallContextV1,
  type NotificationDeliveryAttemptBinding,
  type NotificationGatewayTransportV1,
} from './gateway-contracts.js';

const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const urn = (n: number) => `urn:openpc:resource:${id(n)}`;
const digest = (n: number) => `sha256:${String(n).repeat(64)}`;
function keys() {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: key.publicKey.export({ format: 'der', type: 'spki' }),
  };
}
function fixture() {
  const issuer = keys(),
    signer = keys();
  const transport: NotificationGatewayTransportV1 = {
    protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
    channel: 'EMAIL',
    destinationRef: urn(4),
    credentialRef: urn(5),
    endpoint: 'https://gateway.test/',
    addresses: ['127.0.0.1'],
    serverSpkiDigest: digest(1),
    requestTimeoutMs: 1000,
    maxPayloadBytes: 1024,
  };
  const profile = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(3),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 10000,
    transportProfileDigest: sha256(transport),
    receiptSignerSpki: signer.spki.toString('hex'),
    issuerKeyId: evidenceKeyId(issuer.spki),
  };
  function install(changes = {}) {
    const p = { ...profile, ...changes };
    const bytes = signNotificationClaim(
      'NotificationChannelProfileV1',
      issuer.privateKey,
      issuer.spki,
      p,
    );
    const signed = {
      transport,
      payloadHex: bytes.payload.toString('hex'),
      coseHex: bytes.cose.toString('hex'),
    };
    const trust = {
      environmentId: p.environmentId,
      participantId: p.participantId,
      privacyDomainId: p.privacyDomainId,
      signedProfileDigest: sha256(bytes.cose),
      issuerSpkiHex: issuer.spki.toString('hex'),
    };
    return { installed: verifyInstalledNotificationChannel(trust, signed), trust, signed };
  }
  const { installed, trust, signed } = install();
  const payload = Buffer.from('{"messageKey":"delivery.ready"}');
  const attempt: NotificationDeliveryAttemptBinding = {
    version: 'NotificationDeliveryAttemptV1',
    participantId: id(1),
    privacyDomainId: id(2),
    notificationOccurrenceId: urn(6),
    endpointId: urn(7),
    endpointRevision: '1',
    channel: transport.channel,
    destinationRef: transport.destinationRef,
    credentialRef: transport.credentialRef,
    channelProfileDigest: installed.signedProfileDigest,
    templateDigest: digest(2),
    payloadDigest: sha256(payload),
    payloadBytes: payload.length,
    attemptId: id(8),
    attemptNumber: 1,
    startedAtMs: 2000,
    deadlineAtMs: 3000,
  };
  const context: AdapterCallContextV1 = {
    authorizationDigest: digest(3),
    profileDigest: installed.signedProfileDigest,
    authorizationContextId: id(9),
    authorizationContextEpoch: 1,
    accessClassIds: ['ACCESS-NOTIFICATION'],
    scopeDigest: notificationScopeDigest(attempt),
    deadlineAt: new Date(3000).toISOString(),
    idempotencyDigest: notificationIdempotencyDigest(attempt),
    occurrenceId: id(6),
    auditCorrelationId: id(10),
    cancellation: { mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION', occurrenceId: id(6) },
    reconciliation: { mode: 'EXACT_OCCURRENCE', occurrenceId: id(6) },
  };
  const window = { signal: new AbortController().signal, timeoutMs: 1000 };
  const claims: NotificationDeliveryReceiptClaims = {
    environmentId: profile.environmentId,
    participantId: profile.participantId,
    privacyDomainId: profile.privacyDomainId,
    receiptId: id(11),
    signedProfileDigest: installed.signedProfileDigest,
    attemptDigest: sha256(attempt),
    contextDigest: sha256(context),
    outcome: 'DELIVERED',
    observedAtMs: 2500,
    signerKeyId: evidenceKeyId(signer.spki),
  };
  function observe(change = {}) {
    const bytes = signNotificationClaim(
      'NotificationDeliveryReceiptV1',
      signer.privateKey,
      signer.spki,
      { ...claims, ...change },
    );
    return { payloadHex: bytes.payload.toString('hex'), coseHex: bytes.cose.toString('hex') };
  }
  return {
    transport,
    installed,
    trust,
    signed,
    attempt,
    context,
    payload,
    window,
    install,
    observe,
  };
}
describe('NotificationGatewayAdapterV1 connected contract', () => {
  it('binds canonical delivery bytes and payload-free readback to one original identity', () => {
    const f = fixture();
    const request = { attempt: f.attempt, payloadBase64: f.payload.toString('base64') };
    expect(
      JSON.parse(notificationDeliveryWire(f.installed, request, f.context).toString()),
    ).toEqual({ ...request, context: f.context });
    expect(
      JSON.parse(notificationReadbackWire(f.installed, f.attempt, f.context).toString()),
    ).toEqual({ attempt: f.attempt, context: f.context });
    expect(
      notificationIdempotencyDigest({ ...f.attempt, attemptId: id(12), attemptNumber: 2 }),
    ).toBe(f.context.idempotencyDigest);
    expect(
      notificationIdempotencyDigest({ ...f.attempt, notificationOccurrenceId: urn(12) }),
    ).not.toBe(f.context.idempotencyDigest);
    expect(() =>
      notificationDeliveryWire(
        f.installed,
        { ...request, payloadBase64: Buffer.from('different').toString('base64') },
        f.context,
      ),
    ).toThrow('CONTRACT');
    expect(() =>
      notificationDeliveryWire(f.installed, { ...request, payloadBase64: 'Zh==' }, f.context),
    ).toThrow('CONTRACT');
  });
  it('does not accept a signed sibling, changed transport, changed trust or request getters', () => {
    const f = fixture();
    expect(() =>
      verifyInstalledNotificationChannel(f.trust, f.install({ revision: '2' }).signed),
    ).toThrow('CONTRACT');
    expect(() =>
      verifyInstalledNotificationChannel(f.trust, {
        ...f.signed,
        transport: { ...f.transport, destinationRef: urn(20) },
      }),
    ).toThrow('CONTRACT');
    expect(() =>
      verifyInstalledNotificationChannel({ ...f.trust, privacyDomainId: id(20) }, f.signed),
    ).toThrow('CONTRACT');
    let reads = 0;
    const attempt = { ...f.attempt };
    Object.defineProperty(attempt, 'attemptId', {
      get() {
        reads++;
        return f.attempt.attemptId;
      },
    });
    expect(() => assertNotificationAttempt(f.installed, attempt, f.context)).toThrow('CONTRACT');
    expect(reads).toBe(0);
  });
  it('rejects ungoverned paths, cleartext, credentials and malformed address sets', () => {
    const f = fixture();
    for (const endpoint of [
      'http://gateway.test/',
      'https://gateway.test/send',
      'https://u:p@gateway.test/',
      'https://gateway.test/?x=1',
      'https://gateway.test/#x',
      'https://gateway.test:443/',
    ])
      expect(notificationGatewayTransport.safeParse({ ...f.transport, endpoint }).success).toBe(
        false,
      );
    for (const addresses of [
      [],
      ['127.0.0.1', '127.0.0.1'],
      ['gateway.test'],
      ['127.0.0.2', '127.0.0.1'],
    ])
      expect(notificationGatewayTransport.safeParse({ ...f.transport, addresses }).success).toBe(
        false,
      );
  });
  it('rejects malformed original occurrence, channel, credential, context and deadline bindings', () => {
    const f = fixture();
    for (const change of [
      { notificationOccurrenceId: id(6) },
      { notificationOccurrenceId: `urn:openpc:notification:${id(6)}` },
      { endpointId: id(7) },
      { privacyDomainId: id(20) },
      { channel: 'WEBHOOK' as const },
      { credentialRef: urn(20) },
      { deadlineAtMs: 3001 },
      { attemptNumber: 7 },
      { payloadBytes: 1025 },
      { startedAtMs: 999 },
    ])
      expect(() =>
        assertNotificationAttempt(f.installed, { ...f.attempt, ...change }, f.context),
      ).toThrow('CONTRACT');
    for (const change of [
      { occurrenceId: id(20) },
      { profileDigest: digest(5) },
      { scopeDigest: digest(5) },
      { idempotencyDigest: digest(5) },
      { accessClassIds: ['ACCESS-Z', 'ACCESS-A'] as [string, ...string[]] },
      { cancellation: { mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION' as const, occurrenceId: id(20) } },
    ])
      expect(() =>
        assertNotificationAttempt(f.installed, f.attempt, { ...f.context, ...change }),
      ).toThrow('CONTRACT');
  });
  it('distinguishes expired send authority, current reconciliation and historical verification', () => {
    const f = fixture();
    expect(
      assertNotificationDispatch(
        f.installed,
        f.installed,
        f.attempt,
        f.context,
        'INITIAL_SEND',
        2500,
        f.window,
      ),
    ).toBe(500);
    expect(() =>
      assertNotificationDispatch(
        f.installed,
        f.installed,
        f.attempt,
        f.context,
        'INITIAL_SEND',
        3000,
        f.window,
      ),
    ).toThrow('AUTHORITY_EXPIRED');
    expect(
      assertNotificationDispatch(
        f.installed,
        f.installed,
        f.attempt,
        f.context,
        'RECONCILE',
        9000,
        f.window,
      ),
    ).toBe(1000);
    expect(() =>
      assertNotificationDispatch(
        f.installed,
        f.installed,
        f.attempt,
        f.context,
        'RECONCILE',
        10000,
        f.window,
      ),
    ).toThrow('AUTHORITY_EXPIRED');
    const renewed = f.install({ revision: '2', validFromMs: 10000, validUntilMs: 20000 }).installed;
    expect(
      assertNotificationDispatch(
        renewed,
        f.installed,
        f.attempt,
        f.context,
        'RECONCILE',
        11000,
        f.window,
      ),
    ).toBe(1000);
    expect(() =>
      assertNotificationDispatch(
        renewed,
        f.installed,
        f.attempt,
        f.context,
        'INITIAL_SEND',
        11000,
        f.window,
      ),
    ).toThrow('CONTRACT');
    expect(
      verifyNotificationReceipt(f.installed, f.attempt, f.context, f.observe()).claims.outcome,
    ).toBe('DELIVERED');
    expect(() =>
      assertNotificationDispatch(
        f.installed,
        f.installed,
        f.attempt,
        f.context,
        'INITIAL_SEND',
        2500,
        { ...f.window, signal: AbortSignal.abort() },
      ),
    ).toThrow('CANCELLED');
  });
  it('requires the gateway signature and exact original scope, attempt and context on every outcome', () => {
    const f = fixture();
    for (const outcome of [
      'DELIVERED',
      'RETRYABLE_NO_EFFECT',
      'PERMANENT_FAILURE',
      'AMBIGUOUS',
    ] as const)
      expect(
        verifyNotificationReceipt(f.installed, f.attempt, f.context, f.observe({ outcome })).claims
          .outcome,
      ).toBe(outcome);
    for (const change of [
      { attemptDigest: digest(4) },
      { contextDigest: digest(4) },
      { signedProfileDigest: digest(4) },
      { privacyDomainId: id(20) },
      { participantId: id(20) },
      { environmentId: 'different' },
      { observedAtMs: 1999 },
    ])
      expect(() =>
        verifyNotificationReceipt(f.installed, f.attempt, f.context, f.observe(change)),
      ).toThrow('CONTRACT');
    const signed = f.observe();
    expect(() =>
      verifyNotificationReceipt(f.installed, { ...f.attempt, attemptNumber: 2 }, f.context, signed),
    ).toThrow('CONTRACT');
    const corrupted = Buffer.from(signed.coseHex, 'hex');
    corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1]! ^ 1;
    expect(() =>
      verifyNotificationReceipt(f.installed, f.attempt, f.context, {
        ...signed,
        coseHex: corrupted.toString('hex'),
      }),
    ).toThrow('CONTRACT');
  });
  it('rejects unsigned ACKs, duplicate JSON members, noncanonical and oversized receipt wire', () => {
    const f = fixture();
    const signed = f.observe();
    expect(parseNotificationReceiptWire(Buffer.from(canonicalJson(signed)))).toEqual(signed);
    for (const bytes of [
      Buffer.from('{"ok":true}'),
      Buffer.from(JSON.stringify(signed, null, 2)),
      Buffer.from(`{"coseHex":"00",${canonicalJson(signed).slice(1)}`),
      Buffer.alloc(270337),
      Buffer.from([0xff]),
    ])
      expect(() => parseNotificationReceiptWire(bytes)).toThrow('CONTRACT');
  });
});

it.each([false, true])(
  'erases its own decoded payload on success/failure (mismatch=%s)',
  (mismatch) => {
    const f = fixture(),
      payloadBase64 = (mismatch ? Buffer.from('wrong') : f.payload).toString('base64');
    const borrowed = Buffer.from(f.payload),
      originalFrom = Buffer.from.bind(Buffer),
      owned: Buffer[] = [];
    const spy = vi.spyOn(Buffer, 'from').mockImplementation(((
      value: unknown,
      ...args: unknown[]
    ) => {
      const result = Reflect.apply(originalFrom, Buffer, [value, ...args]) as Buffer;
      if (value === payloadBase64 && args[0] === 'base64') owned.push(result);
      return result;
    }) as typeof Buffer.from);
    try {
      if (mismatch)
        expect(() =>
          notificationDeliveryWire(f.installed, { attempt: f.attempt, payloadBase64 }, f.context),
        ).toThrow('CONTRACT');
      else
        expect(
          notificationDeliveryWire(f.installed, { attempt: f.attempt, payloadBase64 }, f.context)
            .length,
        ).toBeGreaterThan(0);
    } finally {
      spy.mockRestore();
    }
    expect(owned.length).toBeGreaterThan(0);
    for (const bytes of owned) expect(bytes).toEqual(Buffer.alloc(bytes.length));
    expect(f.payload).toEqual(borrowed);
  },
);
