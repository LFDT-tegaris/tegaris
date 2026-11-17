import assert from 'node:assert/strict';
import test from 'node:test';
import { createPrivateKey, generateKeyPairSync, X509Certificate, randomBytes } from 'node:crypto';
import { connect, createServer } from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
import { runtimeSnapshotTlsFixture } from '../identity/runtime-snapshot-tls-fixture.ts';
import { createTestNotificationCredentialProvider } from '../../../scripts/operations/test-notification-credential-provider.ts';
import { encodeCbor } from '../../../packages/security-kernel/src/canonical-cbor.ts';
import {
  evidenceKeyId,
  signNotificationClaim,
} from '../../../packages/security-kernel/src/index.ts';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import {
  createNotificationCredentialClient,
  NotificationProviderChannel,
  notificationProviderProtocol,
  notificationProviderFrameLimit,
} from '../../../services/control-api/src/notifications/credential-provider-client.ts';
import { createNotificationCredentialProviderFixture } from './notification-credential-provider-fixture.mjs';

const id = (n) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const urn = (n) => `urn:openpc:resource:${id(n)}`;
const gate = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
async function fixture(leaseMs = 3000) {
  const tls = await runtimeSnapshotTlsFixture(`urn:openpc:participant:${id(1)}:workload:${id(3)}`);
  let server, physical;
  const clients = [];
  try {
    const key = createPrivateKey(tls.privateKey).export({ format: 'der', type: 'pkcs8' });
    const bytes = encodeCbor(
      new Map([
        [0, 'OPENPC_NOTIFICATION_MTLS_1'],
        [1, key],
        [2, [tls.parsed.raw, new X509Certificate(tls.server.ca).raw]],
        [3, [new X509Certificate(tls.server.ca).raw]],
      ]),
    );
    key.fill(0);
    const credential = {
      participantId: id(1),
      privacyDomainId: id(2),
      credentialRef: urn(4),
      destinationRef: urn(5),
      channel: 'WEBHOOK',
      owner: 'LS-NOTIFICATION',
      secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
      reference: 'secret://local/notification#1',
      version: '1',
      epoch: '1',
      validFromMs: Date.now() - 1000,
      validUntilMs: Date.now() + 60000,
      state: 'ACTIVE',
      fingerprint: sha256(bytes),
    };
    physical = createTestNotificationCredentialProvider(credential, bytes);
    bytes.fill(0);
    const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
      spki = issuer.publicKey.export({ format: 'der', type: 'spki' }),
      receiptSpki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
        format: 'der',
        type: 'spki',
      });
    const serverSpkiDigest = sha256(
      new X509Certificate(tls.server.certificate).publicKey.export({ format: 'der', type: 'spki' }),
    );
    const transport = {
      protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
      channel: 'WEBHOOK',
      destinationRef: urn(5),
      credentialRef: urn(4),
      endpoint: 'https://127.0.0.1:12345/',
      addresses: ['127.0.0.1'],
      serverSpkiDigest,
      requestTimeoutMs: 3000,
      maxPayloadBytes: 1024,
    };
    const signed = signNotificationClaim(
      'NotificationChannelProfileV1',
      issuer.privateKey.export({ format: 'der', type: 'pkcs8' }),
      spki,
      {
        environmentId: 'local',
        participantId: id(1),
        privacyDomainId: id(2),
        profileId: id(6),
        revision: '1',
        validFromMs: Date.now() - 1000,
        validUntilMs: Date.now() + 60000,
        transportProfileDigest: sha256(transport),
        receiptSignerSpki: receiptSpki.toString('hex'),
        issuerKeyId: evidenceKeyId(spki),
      },
    );
    const installation = {
      credential,
      workloadId: `urn:openpc:workload:${id(3)}`,
      principalId: id(7),
      workloadCredentialId: id(8),
      workloadEpoch: '1',
      channelTrust: {
        environmentId: 'local',
        participantId: id(1),
        privacyDomainId: id(2),
        signedProfileDigest: sha256(signed.cose),
        issuerSpkiHex: spki.toString('hex'),
      },
      channelSigned: {
        transport,
        payloadHex: signed.payload.toString('hex'),
        coseHex: signed.cose.toString('hex'),
      },
    };
    server = await createNotificationCredentialProviderFixture({
      tls: tls.server,
      entries: [{ installation, provider: physical, clientCertificate: tls.certificate }],
      leaseMs,
    });
    const options = {
      address: '127.0.0.1',
      port: server.port,
      serverName: '127.0.0.1',
      serverSpkiDigest,
      tls: { ca: tls.server.ca, certificate: tls.certificate, privateKey: tls.privateKey },
      credential,
      timeoutMs: leaseMs + 500,
    };
    const request = {
      ...Object.fromEntries(
        ['participantId', 'privacyDomainId', 'credentialRef', 'reference', 'version', 'epoch'].map(
          (k) => [k, credential[k]],
        ),
      ),
      purpose: 'NOTIFICATION_GATEWAY_CREDENTIAL',
      consumer: 'LS-NOTIFICATION',
    };
    const client = (change = {}) => {
      const value = createNotificationCredentialClient({ ...options, ...change });
      clients.push(value);
      return value;
    };
    const raw = async (change = {}) => {
      const socket = connect({
        host: '127.0.0.1',
        port: server.port,
        ca: tls.server.ca,
        cert: tls.certificate,
        key: tls.privateKey,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        ...change,
      });
      socket.on('error', () => {});
      const channel = new NotificationProviderChannel(socket);
      await new Promise((resolve, reject) => {
        socket.once('secureConnect', resolve);
        socket.once('error', reject);
      });
      return channel;
    };
    return {
      server,
      physical,
      client,
      raw,
      request,
      options,
      installation,
      tls,
      async close(expectedUnknown = false) {
        for (const c of clients) c.close();
        try {
          if (expectedUnknown) await assert.rejects(server.close(), /drain unknown/);
          else await server.close();
        } finally {
          physical.close();
          tls.privateKey.fill(0);
          tls.server.privateKey.fill(0);
          await tls.close();
        }
      },
    };
  } catch (error) {
    physical?.close();
    await server?.close();
    tls.privateKey.fill(0);
    tls.server.privateKey.fill(0);
    await tls.close();
    throw error;
  }
}

test(
  'external provider TLS lease: exact export, completion, erasure and client restart',
  { timeout: 20000 },
  async () => {
    const f = await fixture();
    let retained, assertCurrent;
    try {
      const c = f.client();
      assert.equal(
        await c.withExactVersion(f.request, async (m) => {
          retained = m.bytes;
          assertCurrent = m.assertCurrent;
          m.assertCurrent();
          assert.equal(sha256(m.bytes), f.options.credential.fingerprint);
          return 'used';
        }),
        'used',
      );
      assert.ok(retained.every((x) => x === 0));
      assert.throws(assertCurrent);
      c.close();
      assert.equal(
        await f.client().withExactVersion(f.request, async () => 'fresh-client'),
        'fresh-client',
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'wrong peer pin/name and exact scope/purpose/version/epoch deny before use',
  { timeout: 20000 },
  async () => {
    const f = await fixture();
    let calls = 0;
    try {
      for (const change of [
        { version: '2' },
        { epoch: '2' },
        { participantId: id(9) },
        { privacyDomainId: id(9) },
        { purpose: 'EVIDENCE_KEY' },
        { consumer: 'LS-FACT-BRIDGE' },
        { ready: true },
      ])
        await assert.rejects(
          f.client().withExactVersion({ ...f.request, ...change }, async () => {
            calls++;
          }),
        );
      for (const change of [
        { serverSpkiDigest: `sha256:${'0'.repeat(64)}` },
        { serverName: 'wrong.invalid' },
      ])
        await assert.rejects(
          f.client(change).withExactVersion(f.request, async () => {
            calls++;
          }),
        );
      // Real mTLS handshake with a different certificate chain cannot reach export.
      const stranger = await runtimeSnapshotTlsFixture(
        `urn:openpc:participant:${id(9)}:workload:${id(3)}`,
      );
      try {
        await assert.rejects(
          f
            .client({
              tls: {
                ca: f.tls.server.ca,
                certificate: stranger.certificate,
                privateKey: stranger.privateKey,
              },
            })
            .withExactVersion(f.request, async () => {
              calls++;
            }),
        );
      } finally {
        stranger.privateKey.fill(0);
        stranger.server.privateKey.fill(0);
        await stranger.close();
      }
      assert.equal(calls, 0);
    } finally {
      await f.close();
    }
  },
);

test(
  'provider revocation cancels borrowed material and new clients cannot resurrect the same provider',
  { timeout: 20000 },
  async () => {
    const f = await fixture();
    const entered = gate();
    let bytes, signal;
    try {
      const client = f.client();
      const call = client.withExactVersion(f.request, async (m) => {
        bytes = m.bytes;
        signal = m.signal;
        entered.resolve();
        await new Promise((resolve) => m.signal.addEventListener('abort', resolve, { once: true }));
        throw new Error('callback secret must not escape');
      });
      const rejected = assert.rejects(call, /OPS_SECRET_UNRESOLVED/);
      await entered.promise;
      const drain = await f.server.revoke();
      await rejected;
      assert.equal(signal.aborted, true);
      assert.ok(bytes.every((x) => x === 0));
      assert.equal(drain.state, 'DRAINED');
      await assert.rejects(
        client.withExactVersion(f.request, async () => assert.fail('revoked repeat export')),
      );
      await assert.rejects(
        f.client().withExactVersion(f.request, async () => assert.fail('revoked export')),
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'revocation waits for abort-ignoring use; late completion after expiry or disconnect stays unknown',
  { timeout: 20000 },
  async () => {
    for (const mode of ['resolved', 'rejected', 'timeout', 'disconnect']) {
      const unknown = mode === 'timeout' || mode === 'disconnect';
      const f = await fixture(mode === 'timeout' ? 1000 : 3000);
      const entered = gate(),
        cancelled = gate(),
        finish = gate(),
        finished = gate();
      let bytes, drainState;
      let callbackCompleted = false,
        clientCompleted = false;
      const client = f.client();
      const call = client.withExactVersion(f.request, async (m) => {
        bytes = m.bytes;
        m.signal.addEventListener('abort', cancelled.resolve, { once: true });
        entered.resolve();
        try {
          // Deliberately ignore cancellation and retain active use until the test
          // settles it. An erased Buffer does not establish callback completion.
          await finish.promise;
          if (mode !== 'resolved') throw new Error('late callback failure must remain private');
          return 'late success cannot replace the original cancellation';
        } finally {
          callbackCompleted = true;
          finished.resolve();
        }
      });
      const denied = assert.rejects(call, /OPS_SECRET_UNRESOLVED/).then(() => {
        clientCompleted = true;
      });
      try {
        await entered.promise;
        const drain = f.server.revoke().then((result) => {
          drainState = result.state;
          return result;
        });
        await cancelled.promise;
        await delay(25);
        assert.ok(bytes.every((byte) => byte === 0));
        assert.equal(callbackCompleted, false);
        assert.equal(clientCompleted, false);
        assert.equal(drainState, undefined, 'pending use must not acknowledge provider drain');
        if (mode === 'disconnect') client.close();
        if (!unknown) finish.resolve();
        await denied;
        assert.equal((await drain).state, unknown ? 'UNKNOWN' : 'DRAINED');
        assert.equal(callbackCompleted, !unknown);
        if (unknown) {
          finish.resolve();
          await finished.promise;
          await delay(0);
          assert.equal((await f.server.revoke()).state, 'UNKNOWN');
          await assert.rejects(
            client.withExactVersion(f.request, async () =>
              assert.fail('unreconciled client reuse'),
            ),
          );
        }
      } finally {
        finish.resolve();
        client.close();
        await denied;
        await f.close(unknown);
      }
    }
  },
);

test(
  'expiry and disconnect erase buffers; uncertain remote drain is not called complete',
  { timeout: 20000 },
  async () => {
    for (const disconnect of [false, true]) {
      const f = await fixture(500);
      const entered = gate();
      let bytes;
      try {
        const c = f.client();
        const call = c.withExactVersion(f.request, async (m) => {
          bytes = m.bytes;
          entered.resolve();
          await delay(800);
          return 'late';
        });
        const denied = assert.rejects(call, /OPS_SECRET_UNRESOLVED/);
        await entered.promise;
        if (disconnect) c.close();
        await denied;
        assert.ok(bytes.every((x) => x === 0));
      } finally {
        await f.close(true);
      }
    }
  },
);

test(
  'disconnect before/after export and failed final acknowledgement cannot return callback success',
  { timeout: 20000 },
  async () => {
    for (const fault of ['BEFORE_EXPORT', 'AFTER_EXPORT', 'FINAL_ACK']) {
      const f = await fixture();
      let bytes;
      try {
        f.server.setFault(fault);
        await assert.rejects(
          f.client().withExactVersion(f.request, async (m) => {
            bytes = m.bytes;
            return 'not-success';
          }),
          /OPS_SECRET_UNRESOLVED/,
        );
        if (bytes) assert.ok(bytes.every((x) => x === 0));
      } finally {
        await f.close(fault === 'AFTER_EXPORT');
      }
    }
  },
);

test(
  'TLS-authenticated responses still require the exact lease binding and phase',
  { timeout: 20000 },
  async () => {
    const f = await fixture();
    try {
      for (const fault of ['nonce', 'digest', 'lease', 'phase', 'offset']) {
        const channels = new Set();
        const server = createServer({
          ca: f.tls.server.ca,
          cert: f.tls.server.certificate,
          key: f.tls.server.privateKey,
          minVersion: 'TLSv1.3',
          maxVersion: 'TLSv1.3',
          requestCert: true,
          rejectUnauthorized: true,
        });
        server.on('tlsClientError', () => {});
        server.on('secureConnection', (socket) => {
          const c = new NotificationProviderChannel(socket);
          channels.add(c);
          void (async () => {
            const open = await c.receive();
            const binding = {
              protocol: notificationProviderProtocol,
              nonce: fault === 'nonce' ? 'f'.repeat(64) : open.nonce,
              requestDigest: fault === 'digest' ? `sha256:${'f'.repeat(64)}` : sha256(f.request),
              leaseId: 'a'.repeat(64),
            };
            await c.send({
              ...binding,
              type: 'OPENED',
              deadline: Date.now() + 1000,
              encoding: 'OPENPC_NOTIFICATION_MTLS_1',
              materialLength: 1,
            });
            const next = await c.receive();
            assert.equal(next.type, 'FETCH');
            if (fault === 'phase') await c.send({ ...binding, type: 'FINALIZED' });
            else
              await c.send({
                ...binding,
                type: 'CHUNK',
                leaseId: fault === 'lease' ? 'b'.repeat(64) : binding.leaseId,
                offset: fault === 'offset' ? 1 : 0,
                material: 'AA==',
              });
          })().catch(() => c.destroy());
        });
        await new Promise((resolve, reject) => {
          server.once('error', reject);
          server.listen(0, '127.0.0.1', resolve);
        });
        try {
          await assert.rejects(
            f
              .client({ port: server.address().port })
              .withExactVersion(f.request, async () =>
                assert.fail('invalid provider response reached material use'),
              ),
            /OPS_SECRET_UNRESOLVED/,
          );
        } finally {
          for (const c of channels) c.destroy();
          await new Promise((resolve) => server.close(resolve));
        }
      }
    } finally {
      await f.close();
    }
  },
);

test(
  'framed TLS rejects malformed, oversize, truncated, reordered and replayed requests',
  { timeout: 30000 },
  async () => {
    const f = await fixture(500);
    const n = randomBytes(32).toString('hex');
    const open = {
      protocol: notificationProviderProtocol,
      type: 'OPEN',
      nonce: n,
      request: f.request,
    };
    try {
      for (const mode of ['oversize', 'invalid-json', 'duplicate-key', 'truncated', 'reordered']) {
        const c = await f.raw();
        try {
          if (mode === 'reordered')
            await c.send({
              protocol: notificationProviderProtocol,
              type: 'USE',
              nonce: n,
              requestDigest: sha256(f.request),
              leaseId: n,
            });
          else {
            const body = Buffer.from(
              mode === 'duplicate-key' ? ' {"type":"OPEN","type":"OPEN"}' : '{',
            );
            const wire = Buffer.alloc(4 + body.length);
            wire.writeUInt32BE(
              mode === 'oversize'
                ? notificationProviderFrameLimit + 1
                : mode === 'truncated'
                  ? 100
                  : body.length,
            );
            body.copy(wire, 4);
            c.socket.write(wire);
            if (mode === 'truncated') c.socket.end();
          }
          await assert.rejects(c.receive());
        } finally {
          c.destroy();
        }
      }
      const first = await f.raw();
      await first.send(open);
      const opened = await first.receive();
      assert.equal(opened.type, 'OPENED');
      const bound = {
        protocol: notificationProviderProtocol,
        nonce: n,
        requestDigest: sha256(f.request),
        leaseId: opened.leaseId,
      };
      await first.send({ ...bound, type: 'FETCH', offset: 0 });
      assert.equal((await first.receive()).type, 'CHUNK');
      first.destroy();
      await delay(25);
      const replay = await f.raw();
      try {
        await replay.send(open);
        await assert.rejects(replay.receive());
      } finally {
        replay.destroy();
      }
      const pipelined = await f.raw();
      try {
        const nonce = randomBytes(32).toString('hex');
        await pipelined.send({ ...open, nonce });
        const header = await pipelined.receive();
        assert.equal(header.type, 'OPENED');
        assert.ok(header.materialLength <= 32768);
        const binding = { ...bound, nonce, leaseId: header.leaseId };
        await pipelined.send({ ...binding, type: 'FETCH', offset: 0 });
        assert.equal((await pipelined.receive()).type, 'CHUNK');
        const encoded = ['USE', 'FINALIZE'].map((type) => {
          const body = Buffer.from(canonicalJson({ ...binding, type }));
          const wire = Buffer.alloc(body.length + 4);
          wire.writeUInt32BE(body.length);
          body.copy(wire, 4);
          return wire;
        });
        pipelined.socket.write(Buffer.concat(encoded));
        await assert.rejects(pipelined.receive());
      } finally {
        pipelined.destroy();
      }
      for (const change of [
        { privacyDomainId: id(9) },
        { version: '2', reference: 'secret://local/notification#2' },
        { epoch: '2' },
      ]) {
        const c = await f.raw();
        try {
          await c.send({
            ...open,
            nonce: randomBytes(32).toString('hex'),
            request: { ...f.request, ...change },
          });
          await assert.rejects(c.receive());
        } finally {
          c.destroy();
        }
      }
    } finally {
      await f.close(true);
    }
  },
);
