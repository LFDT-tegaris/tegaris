import { randomBytes } from 'node:crypto';
import { open, readFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { isAbsolute } from 'node:path';
import {
  evidenceKeyId,
  signNotificationClaim,
} from '../../../packages/security-kernel/src/index.ts';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import {
  notificationDeliveryWire,
  notificationGatewayPaths,
  notificationIdempotencyDigest,
  notificationReadbackWire,
  parseNotificationReceiptWire,
  verifyNotificationReceipt,
} from '../../../services/control-api/src/notifications/gateway-contracts.ts';

import {
  notificationVerificationPath,
  parseNotificationVerificationRequest,
  assertNotificationVerificationChallenge,
  verifyNotificationVerificationResponse,
} from '../../../services/control-api/src/configuration/notification-verification-contract.ts';

const fail = () => {
  throw new Error('Notification fixture contract rejected');
};
const modes = [
  'NORMAL',
  'LOST_ACK',
  'PARTIAL',
  'STALL',
  'REDIRECT',
  'FORGED',
  'OVERSIZE',
  'UNSIGNED',
];
const outcomes = ['DELIVERED', 'RETRYABLE_NO_EFFECT', 'PERMANENT_FAILURE', 'AMBIGUOUS'];
function receiptId() {
  const bytes = randomBytes(16);
  bytes.writeUIntBE(Date.now(), 0, 6);
  bytes[6] = (bytes[6] & 15) | 112;
  bytes[8] = (bytes[8] & 63) | 128;
  const h = bytes.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** External gateway only. The caller provisions synthetic TLS/profile/signing
 * material and an exclusively owned temporary journal. No internal trust,
 * eligibility, STARTED state, retry queue or business effects are manufactured.
 * Importing this module performs no I/O and opens no listener. */
export async function createNotificationGatewayFixture({
  tls,
  installed,
  signerPrivateKey,
  signerSpki,
  clientSpkiDigest,
  journalPath,
  port = 0,
  listenHost = '127.0.0.1',
  verification,
}) {
  if (
    !['127.0.0.1', '0.0.0.0'].includes(listenHost) ||
    !Number.isInteger(port) ||
    port < 0 ||
    port > 65535 ||
    !isAbsolute(journalPath) ||
    !/^sha256:[0-9a-f]{64}$/u.test(clientSpkiDigest) ||
    Buffer.from(signerSpki).toString('hex') !== installed.claims.receiptSignerSpki
  )
    fail();
  if (
    verification &&
    (verification.installed.channel.signedProfileDigest !== installed.signedProfileDigest ||
      Buffer.from(verification.signerSpki).toString('hex') !==
        verification.installed.claims.verificationSignerSpki)
  )
    fail();
  const verifications = new Map();
  const verificationObservers = new Set();
  // External fixture observation only: no callback supplies a proof, changes the
  // challenge, or substitutes for the ordinary authenticated signing path.
  async function observeVerificationRequest(challenge) {
    if (verification?.observeRequest === undefined) return;
    if (typeof verification.observeRequest !== 'function') fail();
    const controller = new AbortController();
    verificationObservers.add(controller);
    let timer;
    try {
      await Promise.race([
        Promise.resolve().then(() => verification.observeRequest(challenge, controller.signal)),
        new Promise((_, reject) => {
          const abort = () => reject(new Error('Notification verification observer interrupted'));
          controller.signal.addEventListener('abort', abort, { once: true });
          timer = setTimeout(
            () => controller.abort(),
            Math.max(1, Math.min(5000, challenge.expiresAtMs - Date.now())),
          );
          timer.unref();
        }),
      ]);
    } finally {
      clearTimeout(timer);
      verificationObservers.delete(controller);
      controller.abort();
    }
  }
  let verificationCalls = 0,
    verificationOutcome = 'PROVED';
  function installVerification(record) {
    if (!verification || Object.keys(record).sort().join(',') !== 'challenge,signed,verifiedAtMs')
      fail();
    const wire = Buffer.from(canonicalJson(record.signed));
    verifyNotificationVerificationResponse(
      verification.installed,
      record.challenge,
      wire,
      record.verifiedAtMs,
    );
    if (verifications.has(record.challenge.challengeId)) fail();
    verifications.set(record.challenge.challengeId, { ...record, wire });
  }
  const records = new Map(),
    occurrences = new Map();
  let mode = 'NORMAL',
    outcome = 'DELIVERED',
    calls = 0,
    readbacks = 0,
    delivered = 0,
    poisoned = false;
  const occurrenceKey = (attempt) =>
    canonicalJson({
      participantId: attempt.participantId,
      privacyDomainId: attempt.privacyDomainId,
      notificationOccurrenceId: attempt.notificationOccurrenceId,
    });
  function install(record) {
    const { attempt, context, signed } = record;
    const wire = notificationReadbackWire(installed, attempt, context).toString();
    const receipt = verifyNotificationReceipt(installed, attempt, context, signed);
    const key = occurrenceKey(attempt),
      previous = occurrences.get(key);
    if (
      records.has(attempt.attemptId) ||
      context.idempotencyDigest !== notificationIdempotencyDigest(attempt) ||
      (!previous && attempt.attemptNumber !== 1)
    )
      fail();
    if (
      previous &&
      (previous.attempt.payloadDigest !== attempt.payloadDigest ||
        previous.attempt.attemptNumber + 1 !== attempt.attemptNumber ||
        previous.receipt.claims.outcome !== 'RETRYABLE_NO_EFFECT')
    )
      fail();
    const stored = { attempt, context, signed, wire, receipt };
    records.set(attempt.attemptId, stored);
    occurrences.set(key, stored);
    if (receipt.claims.outcome === 'DELIVERED') delivered++;
  }
  try {
    const text = await readFile(journalPath, 'utf8');
    if (text && !text.endsWith('\n')) fail();
    for (const line of text.split('\n').filter(Boolean)) {
      const record = JSON.parse(line);
      if (
        canonicalJson(record) !== line ||
        !['attempt,context,signed', 'challenge,signed,verifiedAtMs'].includes(
          Object.keys(record).sort().join(','),
        )
      )
        fail();
      if (record.challenge) installVerification(record);
      else install(record);
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error('Notification fixture journal rejected');
  }

  function send(response, signed, selectedMode) {
    const wire = Buffer.from(canonicalJson(signed));
    if (selectedMode === 'LOST_ACK') {
      response.destroy();
      return;
    }
    if (selectedMode === 'STALL') return;
    if (selectedMode === 'REDIRECT') {
      response.writeHead(307, { location: 'https://unapproved.invalid/' });
      response.end();
      return;
    }
    response.setHeader('content-type', 'application/json');
    if (selectedMode === 'PARTIAL') {
      response.setHeader('content-length', wire.length);
      response.write(wire.subarray(0, 16));
      response.destroy();
      return;
    }
    if (selectedMode === 'UNSIGNED') {
      response.end('{"outcome":"RETRYABLE_NO_EFFECT"}');
      return;
    }
    if (selectedMode === 'OVERSIZE') {
      response.end(Buffer.alloc(270337, 32));
      return;
    }
    if (selectedMode === 'FORGED') {
      const forged = {
        ...signed,
        coseHex: `${signed.coseHex.slice(0, -2)}${signed.coseHex.endsWith('00') ? '01' : '00'}`,
      };
      response.end(canonicalJson(forged));
      return;
    }
    response.end(wire);
  }

  const sockets = new Set();
  let tail = Promise.resolve();
  const serialize = (fn) => {
    const next = tail.then(fn);
    tail = next.catch(() => {});
    return next;
  };
  const server = createServer(
    {
      ...tls,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      maxHeaderSize: 8192,
    },
    async (request, response) => {
      try {
        const spki = request.socket.getPeerX509Certificate()?.publicKey.export({
          type: 'spki',
          format: 'der',
        });
        if (
          !request.socket.authorized ||
          !spki ||
          sha256(spki) !== clientSpkiDigest ||
          request.method !== 'POST' ||
          request.headers['content-type'] !== 'application/json' ||
          ![
            ...Object.values(notificationGatewayPaths),
            ...(verification ? [notificationVerificationPath] : []),
          ].includes(request.url)
        )
          fail();
        const chunks = [];
        let size = 0;
        for await (const chunk of request) {
          size += chunk.length;
          if (size > 131072) {
            request.destroy();
            return;
          }
          chunks.push(chunk);
        }
        const bytes = Buffer.concat(chunks, size);
        const selectedMode = mode;
        if (request.url === notificationVerificationPath) {
          const challenge = parseNotificationVerificationRequest(bytes);
          await observeVerificationRequest(challenge);
          const signed = await serialize(async () => {
            if (poisoned || !verification) fail();
            verificationCalls++;
            const retained = verifications.get(challenge.challengeId);
            if (retained) {
              if (canonicalJson(retained.challenge) !== canonicalJson(challenge)) fail();
              return retained.signed;
            }
            const verifiedAtMs = Date.now();
            assertNotificationVerificationChallenge(
              verification.installed,
              challenge,
              verifiedAtMs,
            );
            const value = signNotificationClaim(
              'NotificationVerificationReceiptV1',
              verification.signerPrivateKey,
              verification.signerSpki,
              {
                environmentId: challenge.environmentId,
                participantId: challenge.predecessor.participantId,
                privacyDomainId: challenge.predecessor.privacyDomainId,
                receiptId: receiptId(),
                signedVerificationProfileDigest: verification.installed.signedProfileDigest,
                challengeDigest: sha256(challenge),
                outcome: verificationOutcome,
                observedAtMs: verifiedAtMs,
                validUntilMs: challenge.expiresAtMs,
                signerKeyId: evidenceKeyId(verification.signerSpki),
              },
            );
            const signed = {
              payloadHex: value.payload.toString('hex'),
              coseHex: value.cose.toString('hex'),
            };
            const record = { challenge, signed, verifiedAtMs };
            try {
              const journal = await open(journalPath, 'a', 0o600);
              try {
                await journal.writeFile(`${canonicalJson(record)}\n`);
                await journal.sync();
              } finally {
                await journal.close();
              }
              installVerification(record);
            } catch {
              poisoned = true;
              fail();
            }
            return signed;
          });
          send(response, signed, selectedMode);
          return;
        }
        const body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        const isRead = request.url === notificationGatewayPaths.readback;
        const keys = isRead ? 'attempt,context' : 'attempt,context,payloadBase64';
        if (Object.keys(body).sort().join(',') !== keys) fail();
        const expected = isRead
          ? notificationReadbackWire(installed, body.attempt, body.context)
          : notificationDeliveryWire(
              installed,
              { attempt: body.attempt, payloadBase64: body.payloadBase64 },
              body.context,
            );
        if (!expected.equals(bytes)) fail();
        const selectedOutcome = outcome;
        const signed = await serialize(async () => {
          if (poisoned) fail();
          if (isRead) readbacks++;
          else calls++;
          const retained = records.get(body.attempt.attemptId);
          const wire = notificationReadbackWire(installed, body.attempt, body.context).toString();
          if (retained) {
            if (retained.wire !== wire) fail();
            return retained.signed;
          }
          if (isRead) fail(); // Unknown external state is not a signed no-effect claim.
          const previous = occurrences.get(occurrenceKey(body.attempt));
          if (!previous && body.attempt.attemptNumber !== 1) fail();
          if (
            previous &&
            (previous.attempt.payloadDigest !== body.attempt.payloadDigest ||
              previous.attempt.attemptNumber + 1 !== body.attempt.attemptNumber ||
              previous.receipt.claims.outcome !== 'RETRYABLE_NO_EFFECT')
          )
            fail();
          if (Date.now() >= body.attempt.deadlineAtMs || Date.now() < body.attempt.startedAtMs)
            fail();
          const value = signNotificationClaim(
            'NotificationDeliveryReceiptV1',
            signerPrivateKey,
            signerSpki,
            {
              environmentId: installed.claims.environmentId,
              participantId: body.attempt.participantId,
              privacyDomainId: body.attempt.privacyDomainId,
              receiptId: receiptId(),
              signedProfileDigest: installed.signedProfileDigest,
              attemptDigest: sha256(body.attempt),
              contextDigest: sha256(body.context),
              outcome: selectedOutcome,
              observedAtMs: Date.now(),
              signerKeyId: evidenceKeyId(signerSpki),
            },
          );
          const signed = {
            payloadHex: value.payload.toString('hex'),
            coseHex: value.cose.toString('hex'),
          };
          const record = { attempt: body.attempt, context: body.context, signed };
          // Uncertain persistence fences this fixture until restart/readback; it
          // cannot sign a second result after a partial or failed journal write.
          try {
            const journal = await open(journalPath, 'a', 0o600);
            try {
              await journal.writeFile(`${canonicalJson(record)}\n`);
              await journal.sync();
            } finally {
              await journal.close();
            }
            install(record);
          } catch {
            poisoned = true;
            fail();
          }
          return signed;
        });
        const wire = Buffer.from(canonicalJson(signed));
        parseNotificationReceiptWire(wire);
        send(response, signed, selectedMode);
      } catch {
        // Never echo request, identity, credentials, key material or provider errors.
        if (!response.headersSent) response.writeHead(409, { 'content-type': 'application/json' });
        response.end('{}');
      }
    },
  );
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  server.timeout = 30000;
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  server.on('tlsClientError', () => {});
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, listenHost, resolve);
  });
  return Object.freeze({
    port: server.address().port,
    listenHost: server.address().address,
    setFault(value) {
      if (!modes.includes(value)) fail();
      mode = value;
    },
    setOutcome(value) {
      if (!outcomes.includes(value)) fail();
      outcome = value;
    },
    setVerificationOutcome(value) {
      if (!verification || !['PROVED', 'REJECTED'].includes(value)) fail();
      verificationOutcome = value;
    },
    verificationStats() {
      return { calls: verificationCalls, receipts: verifications.size };
    },
    stats() {
      return { calls, readbacks, delivered, receipts: records.size, sockets: sockets.size };
    },
    async close() {
      for (const controller of verificationObservers) controller.abort();
      await new Promise((resolve) => {
        server.close(resolve);
        for (const socket of sockets) socket.destroy();
      });
      await tail;
    },
  });
}
