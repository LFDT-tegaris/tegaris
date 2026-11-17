import { checkServerIdentity, connect } from 'node:tls';
import { Pool } from 'pg';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { isAbsolute, normalize } from 'node:path';
import { immutableJsonCopy } from '../../../services/control-api/src/privacy-explorer/immutable.ts';
import { installInitialNotificationChannel } from '../../../services/control-api/src/notifications/endpoint-admission.ts';
import { notificationChannelCredential } from '../../../services/control-api/src/notifications/endpoint-owner-contract.ts';
import { verifyInstalledNotificationChannel } from '../../../services/control-api/src/notifications/gateway-contracts.ts';
import { verifyInstalledNotificationVerification } from '../../../services/control-api/src/configuration/notification-verification-contract.ts';
import { createNotificationGatewayFixture } from './notification-gateway-fixture.mjs';
import { createNotificationCredentialClient } from '../../../services/control-api/src/notifications/credential-provider-client.ts';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.ts';

// Process-private fixture identities. A serialized object/boolean cannot supply
// fault control or physical provider eligibility to the browser driver.
const fixtures = new WeakMap();
const unavailable = () => new Error('BLOCKED_NOTIFICATION_RUNTIME_INPUTS');
const requestKey = (value) =>
  JSON.stringify([
    value.participantId,
    value.privacyDomainId,
    value.credentialRef,
    value.reference,
    value.version,
    value.epoch,
  ]);

/** Trusted local root only. Inputs contain actual signed installation profiles,
 * existing workload identities and already-owned physical test providers. This
 * function does not issue Identity credentials, seed endpoints/attempts/proofs,
 * read material from disk/env, manufacture provider eligibility or restore it.
 * The canonical owner creates/reconciles providers independently; restarting a
 * Control process never invokes a provider constructor here.
 *
 * Gateway TLS/signing keys are external synthetic fixture inputs. Root owns and
 * erases those inputs and provider lifetimes; this owner closes its listeners
 * and client sockets. Journals are retained for original-result recovery. */
function closedObject(value, required, optional = []) {
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    required.some((key) => !Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => ![...required, ...optional].includes(key)) ||
    Object.values(Object.getOwnPropertyDescriptors(value)).some(
      (descriptor) => descriptor.get || descriptor.set,
    )
  )
    throw unavailable();
}

/** Pure connected input validation. This grants no installation or peer authority. */
export function validateNotificationRuntimeEntries(entries) {
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > 8) throw unavailable();
  const prepared = entries.map((entry) => {
    closedObject(
      entry,
      [
        'installation',
        'provider',
        'journalPath',
        'gatewayTls',
        'gatewaySignerPrivateKey',
        'gatewaySignerSpki',
        'verificationSignerPrivateKey',
        'verificationSignerSpki',
        'clientSpkiDigest',
      ],
      ['network'],
    );
    closedObject(entry.gatewayTls, ['ca', 'cert', 'key']);
    const installation = immutableJsonCopy(entry.installation);
    closedObject(installation, [
      'credential',
      'channelTrust',
      'channelSigned',
      'verification',
      'principalId',
      'workloadCredentialId',
      'workloadId',
      'workloadEpoch',
      'admissionReference',
    ]);
    const credential = notificationChannelCredential.parse(installation?.credential);
    if (
      !installation.verification ||
      typeof entry.provider?.withExactVersion !== 'function' ||
      !isAbsolute(entry.journalPath ?? '') ||
      normalize(entry.journalPath) !== entry.journalPath ||
      entry.journalPath.includes('\0') ||
      ![
        ...Object.values(entry.gatewayTls),
        entry.gatewaySignerPrivateKey,
        entry.gatewaySignerSpki,
        entry.verificationSignerPrivateKey,
        entry.verificationSignerSpki,
      ].every((value) => Buffer.isBuffer(value) && value.length > 0 && value.length <= 65536)
    )
      throw unavailable();
    const installed = verifyInstalledNotificationChannel(
      installation.channelTrust,
      installation.channelSigned,
    );
    const verification = verifyInstalledNotificationVerification(
      installation.verification.trust,
      installation.verification.signed,
      installation.channelTrust,
      installation.channelSigned,
    );
    if (
      installed.claims.participantId !== credential.participantId ||
      installed.claims.privacyDomainId !== credential.privacyDomainId ||
      installed.transport.channel !== credential.channel ||
      installed.transport.destinationRef !== credential.destinationRef ||
      installed.transport.credentialRef !== credential.credentialRef ||
      verification.claims.credentialBindingDigest !== sha256(credential) ||
      !/^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        installation.workloadId,
      ) ||
      !/^[1-9][0-9]*$/u.test(installation.workloadEpoch)
    )
      throw unavailable();
    notificationChannelCredential.shape.participantId.parse(installation.principalId);
    notificationChannelCredential.shape.participantId.parse(installation.workloadCredentialId);
    const endpoint = new URL(installed.transport.endpoint);
    // This argument belongs only to the root that owns the admitted network.
    // It is not an environment switch or a caller claim of provider eligibility.
    const network = entry.network;
    const listenHost = network?.listenHost ?? '127.0.0.1';
    if (
      !endpoint.port ||
      endpoint.protocol !== 'https:' ||
      !['127.0.0.1', '0.0.0.0'].includes(listenHost) ||
      (network
        ? canonicalJson(Object.keys(network).sort()) !==
            '["addresses","advertisedOrigin","listenHost"]' ||
          network.advertisedOrigin !== installed.transport.endpoint ||
          canonicalJson(network.addresses) !== canonicalJson(installed.transport.addresses)
        : endpoint.hostname !== '127.0.0.1' ||
          canonicalJson(installed.transport.addresses) !== '["127.0.0.1"]')
    )
      throw unavailable();
    const certificate = new X509Certificate(entry.gatewayTls.cert);
    if (!/^sha256:[0-9a-f]{64}$/u.test(entry.clientSpkiDigest)) throw unavailable();
    const host = endpoint.hostname.replace(/^\[|\]$/gu, '');
    if (
      !(isIP(host) ? certificate.checkIP(host) : certificate.checkHost(host)) ||
      !certificate.checkPrivateKey(createPrivateKey(entry.gatewayTls.key)) ||
      sha256(certificate.publicKey.export({ type: 'spki', format: 'der' })) !==
        installed.transport.serverSpkiDigest ||
      Date.parse(certificate.validFrom) > Date.now() ||
      Date.parse(certificate.validTo) <= Date.now()
    )
      throw unavailable();
    for (const [privateKey, publicKey] of [
      [entry.gatewaySignerPrivateKey, entry.gatewaySignerSpki],
      [entry.verificationSignerPrivateKey, entry.verificationSignerSpki],
    ]) {
      if (
        !createPublicKey(createPrivateKey({ key: privateKey, format: 'der', type: 'pkcs8' }))
          .export({ format: 'der', type: 'spki' })
          .equals(publicKey)
      )
        throw unavailable();
    }
    if (
      entry.gatewaySignerSpki.toString('hex') !== installed.claims.receiptSignerSpki ||
      entry.verificationSignerSpki.toString('hex') !== verification.claims.verificationSignerSpki
    )
      throw unavailable();
    return {
      credential,
      provider: entry.provider,
      installation,
      gatewayOptions: {
        tls: entry.gatewayTls,
        installed,
        signerPrivateKey: entry.gatewaySignerPrivateKey,
        signerSpki: entry.gatewaySignerSpki,
        clientSpkiDigest: entry.clientSpkiDigest,
        journalPath: entry.journalPath,
        port: Number(endpoint.port),
        listenHost,
        verification: {
          installed: verification,
          signerPrivateKey: entry.verificationSignerPrivateKey,
          signerSpki: entry.verificationSignerSpki,
        },
      },
    };
  });
  if (
    new Set(prepared.map((entry) => requestKey(entry.credential))).size !== prepared.length ||
    new Set(prepared.map((entry) => entry.gatewayOptions.port)).size !== prepared.length ||
    new Set(prepared.map((entry) => entry.gatewayOptions.journalPath)).size !== prepared.length
  )
    throw unavailable();
  return prepared;
}

export async function prepareNotificationRuntimeFixtures(input) {
  closedObject(input, ['installationPool', 'entries']);
  const { installationPool, entries } = input;
  if (
    !(installationPool instanceof Pool) ||
    !Number.isInteger(installationPool.options?.max) ||
    installationPool.options.max < 1 ||
    installationPool.options.max > 8 ||
    !['connectionTimeoutMillis', 'statement_timeout', 'idle_in_transaction_session_timeout'].every(
      (key) =>
        Number.isInteger(installationPool.options[key]) &&
        installationPool.options[key] > 0 &&
        installationPool.options[key] <= 30000,
    )
  )
    throw unavailable();
  const prepared = validateNotificationRuntimeEntries(entries);
  const gateways = [],
    sockets = new Set(),
    peerIdentities = new Set(),
    providerClients = new Set();
  let closed = false,
    closing;
  const stop = async () => {
    closed = true;
    const failures = [];
    for (const client of providerClients) {
      try {
        client.close();
      } catch (error) {
        failures.push(error);
      }
    }
    const disconnected = [...sockets].map(
      (socket) => new Promise((resolve) => socket.once('close', resolve)),
    );
    for (const socket of sockets) socket.destroy();
    const results = await Promise.allSettled([
      ...disconnected,
      ...gateways.map((gateway) => gateway.close()),
    ]);
    if (failures.length || results.some((item) => item.status === 'rejected'))
      throw new Error('Notification fixture cleanup failed');
  };
  try {
    // Bind the real pinned ports before committing installation metadata.
    for (const entry of prepared)
      gateways.push(await createNotificationGatewayFixture(entry.gatewayOptions));
    const client = await installationPool.connect();
    try {
      await client.query('begin');
      for (const entry of prepared)
        await installInitialNotificationChannel(client, entry.installation);
      await client.query('commit');
    } catch (error) {
      try {
        await client.query('rollback');
      } catch (rollback) {
        throw new AggregateError([error, rollback], 'Notification installation rollback failed');
      }
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    try {
      await stop();
    } catch (cleanup) {
      throw new AggregateError([error, cleanup], 'Notification fixture preparation failed');
    }
    throw error;
  }
  const fixture = Object.freeze({
    createCredentialClient(options) {
      if (closed || providerClients.size >= 8) throw unavailable();
      const matches = prepared.filter(
        (entry) => requestKey(entry.credential) === requestKey(options?.credential ?? {}),
      );
      if (
        matches.length !== 1 ||
        canonicalJson(matches[0].credential) !== canonicalJson(options.credential)
      )
        throw unavailable();
      const client = createNotificationCredentialClient(options);
      const owned = Object.freeze({
        withExactVersion: client.withExactVersion,
        close() {
          client.close();
          providerClients.delete(owned);
        },
      });
      providerClients.add(owned);
      return owned;
    },
    credentialProvider: Object.freeze({
      async withExactVersion(request, use) {
        if (
          closed ||
          request?.purpose !== 'NOTIFICATION_GATEWAY_CREDENTIAL' ||
          request.consumer !== 'LS-NOTIFICATION'
        )
          throw unavailable();
        const matching = prepared.filter(
          (entry) => requestKey(entry.credential) === requestKey(request),
        );
        if (matching.length !== 1) throw unavailable();
        // Dispatch to the existing physical owner; this map grants no export.
        return matching[0].provider.withExactVersion(request, use);
      },
    }),
    async connectWorkload(input) {
      closedObject(
        input,
        ['host', 'port', 'ca', 'certificate', 'privateKey'],
        ['serverName', 'serverSpkiDigest'],
      );
      const { host, port, ca, certificate, privateKey, serverName, serverSpkiDigest } = input;
      if (
        closed ||
        sockets.size >= 8 ||
        !isIP(host) ||
        !!serverName !== !!serverSpkiDigest ||
        (serverName !== undefined &&
          (!/^[a-zA-Z0-9.:-]{1,253}$/u.test(serverName) ||
            !/^sha256:[0-9a-f]{64}$/u.test(serverSpkiDigest))) ||
        !Number.isInteger(port) ||
        port < 1 ||
        port > 65535 ||
        ![ca, certificate, privateKey].every(
          (value) => Buffer.isBuffer(value) && value.length > 0 && value.length <= 65536,
        )
      )
        throw unavailable();
      const client = new X509Certificate(certificate);
      const identity = client.subjectAltName;
      const matches = prepared.filter(
        ({ installation, credential }) =>
          client.subjectAltName ===
          `URI:urn:openpc:participant:${credential.participantId}:workload:${installation.workloadId.slice(-36)}`,
      );
      if (
        !matches.length ||
        peerIdentities.has(identity) ||
        client.ca ||
        !client.keyUsage?.includes('1.3.6.1.5.5.7.3.2') ||
        !client.checkPrivateKey(createPrivateKey(privateKey))
      )
        throw unavailable();
      peerIdentities.add(identity);
      let socket;
      try {
        socket = connect({
          host,
          port,
          ca,
          cert: certificate,
          key: privateKey,
          minVersion: 'TLSv1.3',
          maxVersion: 'TLSv1.3',
          rejectUnauthorized: true,
          ...(serverName
            ? {
                ...(isIP(serverName) ? {} : { servername: serverName }),
                checkServerIdentity: (_host, cert) => checkServerIdentity(serverName, cert),
              }
            : {}),
        });
      } catch {
        peerIdentities.delete(identity);
        throw unavailable();
      }
      sockets.add(socket);
      socket.on('error', () => {});
      let ended;
      const closedPromise = new Promise((resolve) => {
        ended = resolve;
      });
      socket.once('close', () => {
        sockets.delete(socket);
        peerIdentities.delete(identity);
        ended();
      });
      try {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            socket.destroy();
            reject(unavailable());
          }, 5000);
          timer.unref();
          socket.once('secureConnect', () => {
            clearTimeout(timer);
            resolve();
          });
          socket.once('error', (error) => {
            clearTimeout(timer);
            const failure = unavailable();
            if (error.code === 'ECONNREFUSED') failure.code = 'ECONNREFUSED';
            reject(failure);
          });
          socket.once('close', () => {
            clearTimeout(timer);
            reject(unavailable());
          });
        });
        if (closed || !socket.authorized || socket.getProtocol() !== 'TLSv1.3') throw unavailable();
        if (
          serverSpkiDigest &&
          sha256(
            new X509Certificate(socket.getPeerCertificate(true).raw).publicKey.export({
              type: 'spki',
              format: 'der',
            }),
          ) !== serverSpkiDigest
        )
          throw unavailable();
        // Transport ownership only. This is not a server-side Identity admission
        // acknowledgement; actual runtime preflight/VERIFY must establish that.
        return Object.freeze({ closed: closedPromise, close: () => socket.destroy() });
      } catch (error) {
        socket.destroy();
        const failure = unavailable();
        if (error.code === 'ECONNREFUSED') failure.code = 'ECONNREFUSED';
        throw failure;
      }
    },
    close() {
      closing ??= stop();
      return closing;
    },
  });
  fixtures.set(fixture, {
    prepared,
    gateways,
    active: new Set(),
    poisoned: new Set(),
    closed: () => closed,
  });
  return fixture;
}
function selected(fixture, { participantId, privacyDomainId, destinationRef }) {
  const state = fixtures.get(fixture);
  if (!state || state.closed()) throw unavailable();
  const matches = state.prepared
    .map((entry, index) => ({ entry, index }))
    .filter(
      ({ entry }) =>
        entry.credential.participantId === participantId &&
        entry.credential.privacyDomainId === privacyDomainId &&
        entry.credential.destinationRef === destinationRef,
    );
  if (matches.length !== 1) throw unavailable();
  const { index } = matches[0];
  if (state.poisoned.has(index)) throw unavailable();
  return { state, index, gateway: state.gateways[index] };
}
export function notificationRuntimeVerificationStats(fixture, scope) {
  return selected(fixture, scope).gateway.verificationStats();
}
/** One external fault owner per installed gateway. Close and cleanup uncertainty
 * invalidate future use; original journals, receipts and counters remain intact. */
async function withGatewayControl(fixture, scope, change, restore, use) {
  const { state, index, gateway } = selected(fixture, scope);
  if (typeof use !== 'function' || state.active.has(index)) throw unavailable();
  state.active.add(index);
  let result,
    failure,
    failed = false;
  try {
    change(gateway);
    result = await use();
    if (state.closed()) throw unavailable();
  } catch (error) {
    failure = error;
    failed = true;
  } finally {
    try {
      // Never touch a gateway after close, even when a late callback settles.
      if (!state.closed()) restore(gateway);
    } catch (cleanup) {
      state.poisoned.add(index);
      failure = failed
        ? new AggregateError([failure, cleanup], 'Notification external control cleanup failed')
        : cleanup;
      failed = true;
    } finally {
      state.active.delete(index);
    }
  }
  if (failed) throw failure;
  return result;
}
/** External fault only; no secret, proof or business state is supplied by use(). */
export async function withNotificationRuntimeLostAck(fixture, scope, use) {
  return withGatewayControl(
    fixture,
    scope,
    (gateway) => gateway.setFault('LOST_ACK'),
    (gateway) => gateway.setFault('NORMAL'),
    use,
  );
}
const deliveryOutcomes = new Set([
  'DELIVERED',
  'RETRYABLE_NO_EFFECT',
  'PERMANENT_FAILURE',
  'AMBIGUOUS',
]);
function deliveryScope(value) {
  closedObject(value, ['participantId', 'privacyDomainId', 'destinationRef']);
  return {
    participantId: value.participantId,
    privacyDomainId: value.privacyDomainId,
    destinationRef: value.destinationRef,
  };
}
export function notificationRuntimeDeliveryStats(fixture, scope) {
  return selected(fixture, deliveryScope(scope)).gateway.stats();
}
/** Changes only the existing external simulator for this exact owned scope.
 * It grants no internal STARTED/dispatch/signing/publication authority. */
export async function withNotificationRuntimeDeliveryOutcome(fixture, scope, outcome, use) {
  if (!deliveryOutcomes.has(outcome)) throw unavailable();
  return withGatewayControl(
    fixture,
    deliveryScope(scope),
    (gateway) => gateway.setOutcome(outcome),
    (gateway) => gateway.setOutcome('DELIVERED'),
    use,
  );
}
