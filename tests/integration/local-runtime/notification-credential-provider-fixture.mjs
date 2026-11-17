import { randomBytes, X509Certificate } from 'node:crypto';
import { createServer } from 'node:tls';
import { isIP } from 'node:net';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import {
  NotificationProviderChannel,
  notificationProviderProtocol,
  notificationProviderRequest,
  notificationProviderChunkBytes,
} from '../../../services/control-api/src/notifications/credential-provider-client.ts';
import { notificationChannelCredential } from '../../../services/control-api/src/notifications/endpoint-owner-contract.ts';
import { verifyInstalledNotificationChannel } from '../../../services/control-api/src/notifications/gateway-contracts.ts';
import {
  notificationCredentialEncoding,
  decodeNotificationCredentialMaterial,
} from '../../../services/identity-service/src/domain/notification-credential-material.ts';

const fail = () => new Error('OPS_SECRET_UNRESOLVED');
/** External TEST provider transport, not Identity or installation admission.
 * Root binds the real installed workload certificate/scope and original physical
 * provider. It must keep this owner alive across Control client restarts. No
 * fixture constructor restores lost eligibility, bytes, revocation or lease state.
 * Fault controls and drain observations are process-private, never wire routes. */
export async function createNotificationCredentialProviderFixture({
  tls,
  entries,
  port = 0,
  leaseMs = 5000,
  network,
}) {
  if (
    !Array.isArray(entries) ||
    !entries.length ||
    entries.length > 8 ||
    !Number.isInteger(leaseMs) ||
    leaseMs < 100 ||
    leaseMs > 30000 ||
    !Number.isInteger(port) ||
    port < 0 ||
    port > 65535
  )
    throw fail();
  const listenHost = network?.listenHost ?? '127.0.0.1';
  if (network) {
    const cert = new X509Certificate(tls.certificate);
    if (
      canonicalJson(Object.keys(network).sort()) !==
        '["advertisedAddress","listenHost","serverName","serverSpkiDigest"]' ||
      !['127.0.0.1', '0.0.0.0'].includes(listenHost) ||
      !isIP(network.advertisedAddress) ||
      !(isIP(network.serverName)
        ? cert.checkIP(network.serverName)
        : cert.checkHost(network.serverName)) ||
      sha256(cert.publicKey.export({ type: 'spki', format: 'der' })) !== network.serverSpkiDigest
    )
      throw fail();
  }
  const bindings = entries.map((entry) => {
    const installation = entry.installation;
    const credential = notificationChannelCredential.parse(installation?.credential);
    const installed = verifyInstalledNotificationChannel(
      installation.channelTrust,
      installation.channelSigned,
    );
    const cert = new X509Certificate(entry.clientCertificate);
    const san = `URI:urn:openpc:participant:${credential.participantId}:workload:${installation.workloadId?.slice(-36)}`;
    if (
      !/^urn:openpc:workload:[0-9a-f-]{36}$/u.test(installation.workloadId) ||
      cert.subjectAltName !== san ||
      cert.ca ||
      !cert.keyUsage?.includes('1.3.6.1.5.5.7.3.2') ||
      typeof entry.provider?.withExactVersion !== 'function' ||
      typeof entry.provider?.revoke !== 'function' ||
      installed.transport.credentialRef !== credential.credentialRef ||
      installed.transport.destinationRef !== credential.destinationRef ||
      installed.transport.channel !== credential.channel ||
      installed.claims.participantId !== credential.participantId ||
      installed.claims.privacyDomainId !== credential.privacyDomainId
    )
      throw fail();
    const request = notificationProviderRequest.parse({
      ...Object.fromEntries(
        ['participantId', 'privacyDomainId', 'credentialRef', 'reference', 'version', 'epoch'].map(
          (k) => [k, credential[k]],
        ),
      ),
      purpose: 'NOTIFICATION_GATEWAY_CREDENTIAL',
      consumer: 'LS-NOTIFICATION',
    });
    return {
      credential,
      provider: entry.provider,
      certDigest: sha256(cert.raw),
      spki: sha256(cert.publicKey.export({ type: 'spki', format: 'der' })),
      san,
      request,
      terminal: false,
      sessions: new Set(),
    };
  });
  if (new Set(bindings.map((b) => sha256(b.request))).size !== bindings.length) throw fail();
  const sockets = new Set(),
    tasks = new Set(),
    usedNonces = new Set();
  let closed = false,
    fault = 'NORMAL',
    unresolvedExport = false;
  const server = createServer({
    ca: tls.ca,
    cert: tls.certificate,
    key: tls.privateKey,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    requestCert: true,
    rejectUnauthorized: true,
    handshakeTimeout: 5000,
  });
  server.maxConnections = 8;
  server.on('connection', (socket) => {
    if (closed || sockets.size >= 8) {
      socket.destroy();
      return;
    }
    sockets.add(socket);
    socket.on('error', () => {});
    const timer = setTimeout(() => socket.destroy(), leaseMs + 1000);
    timer.unref();
    socket.once('close', () => {
      clearTimeout(timer);
      sockets.delete(socket);
    });
  });
  server.on('tlsClientError', () => {});
  const serve = async (socket) => {
    const channel = new NotificationProviderChannel(socket);
    const session = {
      bound: undefined,
      cancel: undefined,
      released: false,
      exported: false,
      outcome: 'UNKNOWN',
    };
    let owner, borrowed, cancellation, timer;
    let expectedFrame = 'OPEN';
    channel.onFrame = (frame) => {
      const bound = session.bound;
      if (
        bound &&
        (frame.type === 'OPEN' ||
          frame.nonce !== bound.nonce ||
          frame.requestDigest !== bound.requestDigest ||
          frame.leaseId !== bound.leaseId)
      )
        throw fail();
      if (
        session.exported &&
        !session.released &&
        frame.type === 'RELEASE' &&
        frame.outcome === 'ABORTED'
      ) {
        session.released = true;
        session.outcome = 'ABORTED';
        expectedFrame = undefined;
        channel.interrupt();
        return false;
      }
      if (session.released || frame.type !== expectedFrame) throw fail();
      expectedFrame = undefined;
      return true;
    };
    try {
      if (!socket.authorized || socket.getProtocol() !== 'TLSv1.3') throw fail();
      const peer = new X509Certificate(socket.getPeerCertificate(true).raw);
      const open = await channel.receive();
      if (open.type !== 'OPEN' || usedNonces.has(open.nonce) || usedNonces.size >= 4096)
        throw fail();
      usedNonces.add(open.nonce);
      const selected = bindings.filter(
        (b) =>
          b.certDigest === sha256(peer.raw) &&
          b.spki === sha256(peer.publicKey.export({ type: 'spki', format: 'der' })) &&
          b.san === peer.subjectAltName &&
          canonicalJson(b.request) === canonicalJson(open.request),
      );
      if (selected.length !== 1 || selected[0].terminal || closed || selected[0].sessions.size)
        throw fail();
      owner = selected[0];
      owner.sessions.add(session);
      session.bound = {
        protocol: notificationProviderProtocol,
        nonce: open.nonce,
        requestDigest: sha256(open.request),
        leaseId: randomBytes(32).toString('hex'),
      };
      const bound = session.bound;
      const receive = async (type) => {
        if (session.released) throw fail();
        const frame = await channel.receive();
        if (
          frame.type === 'OPEN' ||
          frame.nonce !== bound.nonce ||
          frame.requestDigest !== bound.requestDigest ||
          frame.leaseId !== bound.leaseId
        )
          throw fail();
        if (session.released) throw fail();
        if (frame.type !== type) throw fail();
        return frame;
      };
      session.cancel = () => {
        if (cancellation) return;
        cancellation = channel.send({ ...bound, type: 'CANCEL' }).catch(() => channel.destroy());
      };
      if (fault === 'BEFORE_EXPORT') throw fail();
      await owner.provider.withExactVersion(open.request, async (material) => {
        material.assertCurrent();
        if (
          owner.terminal ||
          closed ||
          material.signal.aborted ||
          material.reference !== open.request.reference ||
          material.version !== open.request.version ||
          material.epoch !== open.request.epoch ||
          material.encoding !== notificationCredentialEncoding ||
          !Buffer.isBuffer(material.bytes)
        )
          throw fail();
        const decoded = decodeNotificationCredentialMaterial(material.bytes);
        if (decoded.fingerprint !== owner.credential.fingerprint) throw fail();
        borrowed = Buffer.from(material.bytes);
        const deadline = Math.min(
          Date.now() + leaseMs,
          material.validUntilMs,
          decoded.validUntilMs,
          owner.credential.validUntilMs,
        );
        if (deadline <= Date.now()) throw fail();
        timer = setTimeout(() => channel.destroy(), Math.max(1, deadline - Date.now()));
        timer.unref();
        material.signal.addEventListener('abort', session.cancel, { once: true });
        try {
          material.assertCurrent();
          expectedFrame = 'FETCH';
          await channel.send({
            ...bound,
            type: 'OPENED',
            deadline,
            encoding: notificationCredentialEncoding,
            materialLength: borrowed.length,
          });
          for (let offset = 0; offset < borrowed.length; offset += notificationProviderChunkBytes) {
            const fetch = await receive('FETCH');
            material.assertCurrent();
            if (
              fetch.offset !== offset ||
              owner.terminal ||
              closed ||
              session.released ||
              material.signal.aborted ||
              Date.now() >= deadline
            )
              throw fail();
            expectedFrame =
              offset + notificationProviderChunkBytes < borrowed.length ? 'FETCH' : 'USE';
            session.exported = true;
            await channel.send({
              ...bound,
              type: 'CHUNK',
              offset,
              material: borrowed
                .subarray(offset, offset + notificationProviderChunkBytes)
                .toString('base64'),
            });
            if (fault === 'AFTER_EXPORT') throw fail();
          }
          borrowed.fill(0);
          borrowed = undefined;
          await receive('USE');
          material.assertCurrent();
          if (owner.terminal || material.signal.aborted || session.released) throw fail();
          expectedFrame = 'FINALIZE';
          await channel.send({ ...bound, type: 'USING' });
          await receive('FINALIZE');
          material.assertCurrent();
          if (owner.terminal || closed || material.signal.aborted || Date.now() >= deadline)
            throw fail();
        } finally {
          material.signal.removeEventListener('abort', session.cancel);
        }
      });
      // The physical owner has completed its own post-use eligibility check and
      // erased its borrowed copy. Only now may FINALIZED be emitted.
      if (owner.terminal || closed || session.released) throw fail();
      expectedFrame = 'RELEASE';
      await channel.send({ ...bound, type: 'FINALIZED' });
      const release = await receive('RELEASE');
      if (release.outcome !== 'COMPLETE') throw fail();
      session.released = true;
      session.outcome = 'COMPLETE';
      if (fault === 'FINAL_ACK') throw fail();
      await channel.send({ ...bound, type: 'RELEASED', outcome: 'COMPLETE' });
    } catch {
      if (session.released && session.outcome === 'ABORTED' && session.bound && !socket.destroyed) {
        try {
          await channel.send({ ...session.bound, type: 'RELEASED', outcome: 'ABORTED' });
        } catch {
          session.outcome = 'UNKNOWN';
        }
      }
    } finally {
      clearTimeout(timer);
      borrowed?.fill(0);
      owner?.sessions.delete(session);
      channel.destroy();
    }
    if (session.exported && session.outcome === 'UNKNOWN') unresolvedExport = true;
    return session.exported ? session.outcome : 'NO_EXPORT';
  };
  server.on('secureConnection', (socket) => {
    const task = serve(socket).catch(() => 'UNKNOWN');
    tasks.add(task);
    // Make the provider-owned completion promise available to its drain owner.
    // Registration happens before the first OPEN is read; revoke snapshots tasks
    // as well as active sessions so an unauthenticated pending borrow cannot slip in.
    task.finally(() => tasks.delete(task));
  });
  server.on('error', () => {
    closed = true;
    for (const socket of sockets) socket.destroy();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, listenHost, resolve);
  });
  let terminalDrain;
  const revoke = () => {
    terminalDrain ??= (async () => {
      const inFlight = [...tasks];
      for (const owner of bindings) {
        owner.terminal = true;
        for (const s of owner.sessions) s.cancel?.();
        owner.provider.revoke();
      }
      const outcomes = await Promise.all(inFlight);
      // The authenticated client's ABORTED release follows actual callback
      // settlement and owned-buffer clearing. Signal abort alone is not drain.
      // Disconnect/expiry is UNKNOWN, never evidence of completed use or erasure.
      return Object.freeze({
        state: !unresolvedExport && outcomes.every((v) => v !== 'UNKNOWN') ? 'DRAINED' : 'UNKNOWN',
      });
    })();
    return terminalDrain;
  };
  return Object.freeze({
    port: server.address().port,
    setFault(value) {
      if (!['NORMAL', 'BEFORE_EXPORT', 'AFTER_EXPORT', 'FINAL_ACK'].includes(value)) throw fail();
      fault = value;
    },
    revoke,
    async close() {
      const drain = await revoke();
      closed = true;
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(fail()) : resolve())),
      );
      if (drain.state !== 'DRAINED') throw new Error('Notification provider drain unknown');
    },
  });
}
