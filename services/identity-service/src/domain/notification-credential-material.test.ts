import { createHash, createPrivateKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { createServer, connect } from 'node:tls';
import { once } from 'node:events';
import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import { createTestNotificationCredentialProvider } from '../../../../scripts/operations/test-notification-credential-provider.js';
import {
  encodeCbor,
  type CborValue,
} from '../../../../packages/security-kernel/src/canonical-cbor.js';
import { runtimeSnapshotTlsFixture } from '../../../../tests/integration/identity/runtime-snapshot-tls-fixture.js';
import {
  decodeNotificationCredentialMaterial,
  notificationCredentialEncoding,
} from './notification-credential-material.js';
import type { NotificationCredentialProvider } from './notification-credential-material.js';

let fixture: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>;
let key: Buffer;
beforeAll(async () => {
  fixture = await runtimeSnapshotTlsFixture('urn:openpc:test:notification-channel-client');
  key = createPrivateKey(fixture.privateKey).export({ format: 'der', type: 'pkcs8' });
});
afterAll(async () => {
  key?.fill(0);
  fixture?.privateKey.fill(0);
  fixture?.server.privateKey.fill(0);
  await fixture?.close();
});
function material(change?: [number, CborValue]): Buffer {
  const map = new Map<number, CborValue>([
    [0, notificationCredentialEncoding],
    [1, key],
    [2, [fixture.parsed.raw, new X509Certificate(fixture.server.ca).raw]],
    [3, [new X509Certificate(fixture.server.ca).raw]],
  ]);
  if (change) map.set(...change);
  return encodeCbor(map);
}

function providerFixture() {
  const bytes = material();
  const credential = {
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    credentialRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000301',
    destinationRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000401',
    channel: 'WEBHOOK',
    owner: 'LS-NOTIFICATION',
    secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
    reference: 'secret://local/notification-fixture#1',
    version: '1',
    epoch: '1',
    validFromMs: Date.now() - 1000,
    validUntilMs: Date.now() + 60000,
    state: 'ACTIVE',
    fingerprint: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
  };
  const provider = createTestNotificationCredentialProvider(credential, bytes);
  const contract: NotificationCredentialProvider = provider;
  bytes.fill(0);
  return {
    provider,
    contract,
    credential,
    request: {
      participantId: credential.participantId,
      privacyDomainId: credential.privacyDomainId,
      credentialRef: credential.credentialRef,
      reference: credential.reference,
      version: credential.version,
      epoch: credential.epoch,
      purpose: 'NOTIFICATION_GATEWAY_CREDENTIAL' as const,
      consumer: 'LS-NOTIFICATION' as const,
    },
  };
}

it('the external TEST provider checks exact export descriptors and erases each borrowed copy', async () => {
  const f = providerFixture();
  let borrowed: Buffer | undefined;
  let check: (() => void) | undefined;
  try {
    const use = vi.fn();
    for (const change of [
      { version: '2' },
      { epoch: '2' },
      { consumer: 'LS-FACT-BRIDGE' },
      { purpose: 'OTHER' },
      { reference: 'secret://local/notification-fixture#current' },
      { participantId: f.request.privacyDomainId },
      { ready: true },
    ]) {
      await expect(
        f.provider.withExactVersion({ ...f.request, ...change } as never, use),
      ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
    }
    expect(use).not.toHaveBeenCalled();
    expect(
      await f.contract.withExactVersion(f.request, async (value) => {
        borrowed = value.bytes;
        check = value.assertCurrent;
        value.assertCurrent();
        expect(value.encoding).toBe(notificationCredentialEncoding);
        expect(decodeNotificationCredentialMaterial(value.bytes).fingerprint).toBe(
          f.credential.fingerprint,
        );
        return 'bounded-use';
      }),
    ).toBe('bounded-use');
    expect(borrowed!.every((byte) => byte === 0)).toBe(true);
    expect(() => check!()).toThrow('OPS_SECRET_UNRESOLVED');
  } finally {
    f.provider.close();
  }
});

it.each(['revoke', 'expire', 'callback'] as const)(
  'the physical provider preserves terminal %s and rejects in-flight success',
  async (mode) => {
    const f = providerFixture();
    let borrowed: Buffer | undefined;
    let now: ReturnType<typeof vi.spyOn> | undefined;
    try {
      await expect(
        f.contract.withExactVersion(f.request, async (value) => {
          borrowed = value.bytes;
          if (mode === 'callback') throw new Error('private synthetic callback detail');
          if (mode === 'revoke') f.provider.revoke();
          else now = vi.spyOn(Date, 'now').mockReturnValue(f.credential.validUntilMs + 1);
          expect(() => value.assertCurrent()).toThrow('OPS_SECRET_UNRESOLVED');
          expect(value.signal.aborted).toBe(true);
          expect(value.bytes.every((byte) => byte === 0)).toBe(true);
          return 'must-not-succeed';
        }),
      ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
      expect(borrowed!.every((byte) => byte === 0)).toBe(true);
      if (mode !== 'callback') {
        now?.mockRestore();
        const use = vi.fn();
        await expect(f.provider.withExactVersion(f.request, use)).rejects.toThrow(
          'OPS_SECRET_UNRESOLVED',
        );
        expect(use).not.toHaveBeenCalled();
      }
    } finally {
      now?.mockRestore();
      f.provider.close();
    }
  },
);
it('binds the exact binary material to a real TLS 1.3 client certificate and explicit server trust', async () => {
  const bytes = material();
  const before = Buffer.from(bytes);
  const decoded = decodeNotificationCredentialMaterial(bytes);
  expect(bytes.equals(before)).toBe(true);
  expect(decoded.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/u);
  const server = createServer({
    key: fixture.server.privateKey,
    cert: fixture.server.certificate,
    ca: fixture.server.ca,
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing TLS fixture address');
  const accepted = once(server, 'secureConnection');
  const socket = connect({
    host: '127.0.0.1',
    port: address.port,
    secureContext: decoded.secureContext,
    rejectUnauthorized: true,
  });
  let peer: typeof socket | undefined;
  try {
    await once(socket, 'secureConnect');
    [peer] = await accepted;
    expect(socket.authorized).toBe(true);
    expect(socket.getProtocol()).toBe('TLSv1.3');
    expect(peer!.authorized).toBe(true);
    expect(peer!.getPeerX509Certificate()?.raw.equals(fixture.parsed.raw)).toBe(true);
  } finally {
    socket.destroy();
    peer?.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    bytes.fill(0);
    before.fill(0);
  }
});
it('rejects substituted keys, server certificates, non-CA trust and extra fields with redacted errors', () => {
  const wrong = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({
    format: 'der',
    type: 'pkcs8',
  });
  const changes: [number, CborValue][] = [
    [0, 'UNRELATED_FORMAT'],
    [1, wrong],
    [2, [new X509Certificate(fixture.server.certificate).raw]],
    [3, [fixture.parsed.raw]],
    [4, 'untrusted_secret_value'],
  ];
  try {
    for (const change of changes) {
      const bytes = material(change);
      try {
        expect(() => decodeNotificationCredentialMaterial(bytes)).toThrow('OPS_SECRET_UNRESOLVED');
      } finally {
        bytes.fill(0);
      }
    }
  } finally {
    wrong.fill(0);
  }
});
it('rejects empty, oversized, noncanonical, truncated and trailing material without a fallback', () => {
  const original = material();
  const cases = [
    Buffer.alloc(0),
    Buffer.alloc(65537),
    Buffer.from('private synthetic invalid value'),
    original.subarray(0, -1),
    Buffer.concat([original, Buffer.from([0])]),
  ];
  try {
    for (const bytes of cases)
      expect(() => decodeNotificationCredentialMaterial(bytes)).toThrow('OPS_SECRET_UNRESOLVED');
  } finally {
    cases.forEach((bytes) => bytes.fill(0));
    original.fill(0);
  }
});
