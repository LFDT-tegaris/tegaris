import assert from 'node:assert/strict';
import { createPrivateKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { getEventListeners } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { createSecureContext } from 'node:tls';
import test from 'node:test';
import {
  evidenceKeyId,
  signNotificationClaim,
} from '../../../packages/security-kernel/src/index.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import {
  notificationIdempotencyDigest,
  notificationScopeDigest,
  verifyInstalledNotificationChannel,
} from '../../../services/control-api/src/notifications/gateway-contracts.ts';
import { createNotificationGatewayAdapter } from '../../../services/control-api/src/notifications/gateway-adapter.ts';
import { createNotificationGatewayFixture } from './notification-gateway-fixture.mjs';
import {
  createNotificationVerificationChallenge,
  verifyInstalledNotificationVerification,
} from '../../../services/control-api/src/configuration/notification-verification-contract.ts';
import { exchangeNotificationEndpointTls } from '../../../services/control-api/src/notifications/endpoint-tls-binding.ts';
import { verifyNotificationEndpointProvider } from '../../../services/control-api/src/notifications/endpoint-verification-provider.ts';

import { Pool } from 'pg';
import { encodeCbor } from '../../../packages/security-kernel/src/canonical-cbor.ts';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import {
  decodeNotificationCredentialMaterial,
  notificationCredentialEncoding,
} from '../../../services/identity-service/src/domain/notification-credential-material.ts';
import { createTestNotificationCredentialProvider } from '../../../scripts/operations/test-notification-credential-provider.ts';
import {
  withNotificationSecretRecipient,
  assertNotificationCredentialLease,
} from '../../../services/identity-service/src/domain/notification-secret-recipient.ts';
import { installInitialNotificationChannel } from '../../../services/control-api/src/notifications/endpoint-admission.ts';
import { runtimeSnapshotTlsFixture } from '../identity/runtime-snapshot-tls-fixture.ts';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.ts';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.ts';

const identities = new Map();
const id = (n) => {
  if (!identities.has(n)) identities.set(n, localOperationId());
  return identities.get(n);
};
const urn = (n) => `urn:openpc:resource:${id(n)}`;
function key() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
    spki: pair.publicKey.export({ type: 'spki', format: 'der' }),
  };
}

// Initial trust only. The concrete external provider and gateway are synthetic;
// actual workload TLS, Identity, scoped PG grants and installation fences stay real.
async function recipientHarness() {
  const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
  const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
  assert.ok(
    adminUrl && runtimeUrl,
    'BLOCKED notification TLS: real I02 admin/runtime PostgreSQL required',
  );
  const admin = new Pool({ connectionString: adminUrl, max: 2 });
  const runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
  let peer, app;
  const pid = id(1),
    privacy = id(2),
    principal = id(100),
    credentialId = id(101),
    workload = id(102);
  let pending;
  try {
    peer = await runtimeSnapshotTlsFixture(`urn:openpc:participant:${pid}:workload:${workload}`);
    await admin.query(
      `insert into control.participant(participant_id,display_name,state,authority_epoch)
      values($1,'Notification TLS initial trust','ACTIVE',1)`,
      [pid],
    );
    await admin.query(
      `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
      values($1,$2,'Notification TLS','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
      [privacy, pid],
    );
    await admin.query(
      'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
      [pid, privacy],
    );
    await admin.query(
      `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD','Notification TLS recipient','ACTIVE',1)`,
      [principal, pid],
    );
    const spki = peer.parsed.publicKey.export({ format: 'der', type: 'spki' });
    await admin.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS','local-evidence-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
      [
        credentialId,
        pid,
        principal,
        `urn:openpc:participant:${pid}:workload:${workload}`,
        `urn:openpc:workload:${workload}`,
        Buffer.from(sha256(spki).slice(7), 'hex'),
        spki,
        Buffer.from(sha256(peer.parsed.raw).slice(7), 'hex'),
        new Date(peer.parsed.validFrom),
        new Date(peer.parsed.validTo),
      ],
    );
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
    app = buildLocalWorkloadMtlsService(runtime, kernel, peer.server);
    app.post('/test/notification-credential', async (request, reply) => {
      const call = pending;
      if (!call) return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
      try {
        call.value = await withNotificationSecretRecipient(
          runtime,
          kernel,
          request.raw.socket,
          request.body,
          call.provider,
          call.use,
        );
        return { ok: true };
      } catch (error) {
        call.error = error;
        return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
      }
    });
    const address = await app.listen({ host: '127.0.0.1', port: 0 });
    return {
      async install(installation) {
        const client = await admin.connect();
        try {
          await client.query('begin');
          await installInitialNotificationChannel(client, {
            ...installation,
            principalId: principal,
            workloadCredentialId: credentialId,
            workloadId: `urn:openpc:workload:${workload}`,
            workloadEpoch: '1',
            admissionReference: 'Initial exact notification TLS test channel',
          });
          await client.query('commit');
        } catch (error) {
          await client.query('rollback');
          throw error;
        } finally {
          client.release();
        }
      },
      async use(credential, provider, use, change = {}, anonymous = false) {
        assert.equal(pending, undefined, 'Exclusive recipient fixture call');
        const call = { provider, use };
        pending = call;
        const request = {
          participantId: credential.participantId,
          privacyDomainId: credential.privacyDomainId,
          credentialRef: credential.credentialRef,
          reference: credential.reference,
          version: credential.version,
          epoch: credential.epoch,
          ...change,
        };
        try {
          const response = await peer.post(
            `${address}/test/notification-credential`,
            request,
            ...(anonymous ? [null] : []),
          );
          if (call.error) throw call.error;
          assert.equal(response.status, 200);
          return call.value;
        } finally {
          pending = undefined;
        }
      },
      async close() {
        await app.close();
        await runtime.end();
        await admin.end();
        peer.privateKey.fill(0);
        peer.server.privateKey.fill(0);
        await peer.close();
      },
    };
  } catch (error) {
    await app?.close();
    await runtime.end();
    await admin.end();
    peer?.privateKey.fill(0);
    peer?.server.privateKey.fill(0);
    await peer?.close();
    throw error;
  }
}

test('notification gateway rejects an unapproved listener before reading TLS, trust or journals', async () => {
  for (const listenHost of ['gateway.example', '::', '192.0.2.1', '', null]) {
    // No valid TLS/profile/secret is supplied and no listener can be opened.
    await assert.rejects(
      createNotificationGatewayFixture({ listenHost, journalPath: '/not-owned' }),
      /Notification fixture contract rejected/,
    );
  }
});

// Explicit local execution only, under the integrator's existing runtime owner.
// Reuse the existing purpose-bound CA/client certificate fixture; no stored keys,
// production provider, internal Identity or business-state substitute is added.
test(
  'notification gateway external mTLS and retained receipt contract',
  { timeout: 120000 },
  async (t) => {
    const root = process.env.OPENPC_PNC_TMP_ROOT;
    assert.ok(root?.startsWith('/'), 'OPENPC_PNC_TMP_ROOT is required');
    const directory = await mkdtemp(join(root, 'notification-gateway-'));
    const provisioned = await runtimeSnapshotTlsFixture('urn:openpc:test:notification-gateway');
    let materials;
    try {
      const reservation = createServer();
      await new Promise((resolve, reject) => {
        reservation.once('error', reject);
        reservation.listen(0, '127.0.0.1', resolve);
      });
      const port = reservation.address().port;
      await new Promise((resolve, reject) =>
        reservation.close((error) => (error ? reject(error) : resolve())),
      );
      materials = {
        ca: Buffer.from(provisioned.server.ca),
        serverCert: Buffer.from(provisioned.server.certificate),
        serverKey: Buffer.from(provisioned.server.privateKey),
        cert: Buffer.from(provisioned.certificate),
        key: Buffer.from(provisioned.privateKey),
        port,
      };
    } finally {
      provisioned.privateKey.fill(0);
      provisioned.server.privateKey.fill(0);
      await provisioned.close();
    }
    const tls = { ca: materials.ca, cert: materials.serverCert, key: materials.serverKey };
    const secureContext = createSecureContext({
      ca: materials.ca,
      cert: materials.cert,
      key: materials.key,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    });
    const clientSpkiDigest = sha256(
      new X509Certificate(materials.cert).publicKey.export({ type: 'spki', format: 'der' }),
    );
    const serverSpkiDigest = sha256(
      new X509Certificate(materials.serverCert).publicKey.export({ type: 'spki', format: 'der' }),
    );
    const privateDer = createPrivateKey(materials.key).export({ format: 'der', type: 'pkcs8' });
    const credentialBytes = encodeCbor(
      new Map([
        [0, notificationCredentialEncoding],
        [1, privateDer],
        [2, [new X509Certificate(materials.cert).raw, new X509Certificate(materials.ca).raw]],
        [3, [new X509Certificate(materials.ca).raw]],
      ]),
    );
    privateDer.fill(0);
    // Validate the actual external credential before installing its metadata or
    // entering any dependent lease/I/O scenario. Certificate purpose is required.
    assert.ok(new X509Certificate(materials.cert).keyUsage?.includes('1.3.6.1.5.5.7.3.2'));
    assert.equal(
      decodeNotificationCredentialMaterial(credentialBytes).fingerprint,
      sha256(credentialBytes),
    );
    let recipient;
    const providers = [];
    let sequence = 0;
    function scenario(channel = 'WEBHOOK', providerLifetimeMs = 60000) {
      const credentialRef = urn(1000 + ++sequence);
      const issuer = key(),
        signer = key(),
        now = Date.now();
      const transport = {
        protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
        channel,
        destinationRef: urn(3),
        credentialRef,
        endpoint: `https://127.0.0.1:${materials.port}/`,
        addresses: ['127.0.0.1'],
        serverSpkiDigest,
        requestTimeoutMs: 5000,
        maxPayloadBytes: 1024,
      };
      const profile = signNotificationClaim(
        'NotificationChannelProfileV1',
        issuer.privateKey,
        issuer.spki,
        {
          environmentId: 'local',
          participantId: id(1),
          privacyDomainId: id(2),
          profileId: id(5),
          revision: '1',
          validFromMs: now - 1000,
          validUntilMs: now + 60000,
          transportProfileDigest: sha256(transport),
          receiptSignerSpki: signer.spki.toString('hex'),
          issuerKeyId: evidenceKeyId(issuer.spki),
        },
      );
      const installed = verifyInstalledNotificationChannel(
        {
          environmentId: 'local',
          participantId: id(1),
          privacyDomainId: id(2),
          signedProfileDigest: sha256(profile.cose),
          issuerSpkiHex: issuer.spki.toString('hex'),
        },
        {
          transport,
          payloadHex: profile.payload.toString('hex'),
          coseHex: profile.cose.toString('hex'),
        },
      );
      const credential = {
        participantId: id(1),
        privacyDomainId: id(2),
        credentialRef,
        channel,
        destinationRef: urn(3),
        secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
        owner: 'LS-NOTIFICATION',
        reference: 'secret://local/notification-mtls#1',
        version: '1',
        fingerprint: sha256(credentialBytes),
        epoch: '1',
        validFromMs: now - 1000,
        validUntilMs: now + 60000,
        state: 'ACTIVE',
      };
      const verificationSigner = key();
      const verificationProfile = signNotificationClaim(
        'NotificationVerificationProfileV1',
        issuer.privateKey,
        issuer.spki,
        {
          environmentId: 'local',
          participantId: id(1),
          privacyDomainId: id(2),
          profileId: id(20),
          revision: '1',
          validFromMs: now - 1000,
          validUntilMs: now + 60000,
          signedChannelProfileDigest: installed.signedProfileDigest,
          credentialBindingDigest: sha256(credential),
          verificationSignerSpki: verificationSigner.spki.toString('hex'),
          issuerKeyId: evidenceKeyId(issuer.spki),
        },
      );
      const verificationInstalled = verifyInstalledNotificationVerification(
        {
          environmentId: 'local',
          participantId: id(1),
          privacyDomainId: id(2),
          signedProfileDigest: sha256(verificationProfile.cose),
          issuerSpkiHex: issuer.spki.toString('hex'),
        },
        {
          payloadHex: verificationProfile.payload.toString('hex'),
          coseHex: verificationProfile.cose.toString('hex'),
        },
        {
          environmentId: 'local',
          participantId: id(1),
          privacyDomainId: id(2),
          signedProfileDigest: sha256(profile.cose),
          issuerSpkiHex: issuer.spki.toString('hex'),
        },
        {
          transport,
          payloadHex: profile.payload.toString('hex'),
          coseHex: profile.cose.toString('hex'),
        },
      );
      const challenge = createNotificationVerificationChallenge(
        verificationInstalled,
        {
          predecessor: {
            participantId: id(1),
            privacyDomainId: id(2),
            endpointId: id(7),
            revision: '1',
            channel,
            destinationRef: urn(3),
            credentialRef,
            channelProfileDigest: installed.signedProfileDigest,
          },
          credential,
          principalId: id(21),
          inputDigest: sha256({ reason: 'verify' }),
          businessIdempotencyDigest: sha256({ intent: ++sequence }),
        },
        now,
      );
      const installation = {
        credential,
        channelTrust: {
          environmentId: 'local',
          participantId: id(1),
          privacyDomainId: id(2),
          signedProfileDigest: sha256(profile.cose),
          issuerSpkiHex: issuer.spki.toString('hex'),
        },
        channelSigned: {
          transport,
          payloadHex: profile.payload.toString('hex'),
          coseHex: profile.cose.toString('hex'),
        },
        verification: {
          trust: {
            environmentId: 'local',
            participantId: id(1),
            privacyDomainId: id(2),
            signedProfileDigest: sha256(verificationProfile.cose),
            issuerSpkiHex: issuer.spki.toString('hex'),
          },
          signed: {
            payloadHex: verificationProfile.payload.toString('hex'),
            coseHex: verificationProfile.cose.toString('hex'),
          },
        },
      };
      let provider;
      const withLease = async (use, change = {}, anonymous = false) => {
        if (!provider) {
          assert.ok(recipient, 'Real recipient fixture not initialized');
          await recipient.install(installation);
          provider = createTestNotificationCredentialProvider(
            {
              ...credential,
              validUntilMs: Math.min(credential.validUntilMs, Date.now() + providerLifetimeMs),
            },
            credentialBytes,
          );
          providers.push(provider);
        }
        return recipient.use(credential, provider, use, change, anonymous);
      };
      const payload = Buffer.from('{"messageKey":"notification.ready"}');
      const attempt = {
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
        templateDigest: `sha256:${'11'.repeat(32)}`,
        payloadDigest: sha256(payload),
        payloadBytes: payload.length,
        attemptId: id(8),
        attemptNumber: 1,
        startedAtMs: now,
        deadlineAtMs: now + 5000,
      };
      const context = {
        authorizationDigest: `sha256:${'22'.repeat(32)}`,
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
      const options = {
        tls,
        installed,
        verification: {
          installed: verificationInstalled,
          signerPrivateKey: verificationSigner.privateKey,
          signerSpki: verificationSigner.spki,
        },
        signerPrivateKey: signer.privateKey,
        signerSpki: signer.spki,
        clientSpkiDigest,
        journalPath: join(directory, `gateway-${++sequence}.jsonl`),
        port: materials.port,
      };
      const adapter = (
        signal = new AbortController().signal,
        timeoutMs = 5000,
        client = secureContext,
      ) => createNotificationGatewayAdapter(installed, installed, client, { signal, timeoutMs });
      return {
        options,
        challenge,
        credential,
        withLease,
        revoke: () => provider?.revoke(),
        verify: (timeoutMs = 5000, original = challenge) =>
          withLease((lease) =>
            verifyNotificationEndpointProvider(verificationInstalled, original, lease, {
              signal: new AbortController().signal,
              timeoutMs,
            }),
          ),
        verifyLease: (lease, timeoutMs = 5000) =>
          verifyNotificationEndpointProvider(verificationInstalled, challenge, lease, {
            signal: new AbortController().signal,
            timeoutMs,
          }),
        attempt,
        context,
        adapter,
        request: { attempt, payloadBase64: payload.toString('base64') },
      };
    }
    try {
      recipient = await recipientHarness();
      for (const channel of ['WEBHOOK', 'EMAIL', 'OPERATIONS_QUEUE']) {
        await t.test(
          `${channel}: verification has zero deliveries and preserves original signed bytes through restart`,
          async () => {
            const f = scenario(channel);
            let gateway = await createNotificationGatewayFixture({
              ...f.options,
              listenHost: '0.0.0.0',
            });
            try {
              assert.equal(gateway.listenHost, '0.0.0.0');
              const first = await f.verify();
              assert.equal(first.authenticated.claims.outcome, 'PROVED');
              assert.equal(gateway.stats().calls, 0);
              assert.equal(gateway.stats().delivered, 0);
              assert.deepEqual((await f.verify()).responseBytes, first.responseBytes);
              await gateway.close();
              gateway = await createNotificationGatewayFixture(f.options);
              assert.deepEqual((await f.verify()).responseBytes, first.responseBytes);
              assert.equal(gateway.verificationStats().receipts, 1);
              await assert.rejects(
                f.verify(1000, {
                  ...f.challenge,
                  inputDigest: sha256({ changed: true }),
                }),
              );
              assert.equal(gateway.stats().delivered, 0);
            } finally {
              await gateway.close();
            }
          },
        );
      }
      await t.test(
        'signed nondelivery rejection is distinct from transport ambiguity',
        async () => {
          const f = scenario(),
            gateway = await createNotificationGatewayFixture(f.options);
          try {
            gateway.setVerificationOutcome('REJECTED');
            assert.equal((await f.verify()).authenticated.claims.outcome, 'REJECTED');
            assert.equal(gateway.stats().calls, 0);
            assert.equal(gateway.stats().delivered, 0);
          } finally {
            await gateway.close();
          }
        },
      );
      for (const fault of [
        'LOST_ACK',
        'FORGED',
        'PARTIAL',
        'OVERSIZE',
        'UNSIGNED',
        'REDIRECT',
        'STALL',
      ]) {
        await t.test(
          `${fault}: nondelivery observation remains original and no delivery is made`,
          async () => {
            const f = scenario(),
              gateway = await createNotificationGatewayFixture(f.options);
            try {
              gateway.setFault(fault);
              await assert.rejects(f.verify(300), /OPS_SECRET_UNRESOLVED/);
              assert.equal(gateway.stats().calls, 0);
              assert.equal(gateway.stats().delivered, 0);
              assert.equal(gateway.verificationStats().receipts, 1);
              // External fixture exact-byte replay only. The production attempt
              // owner deliberately does not automatically make this second call.
              gateway.setFault('NORMAL');
              assert.equal((await f.verify()).authenticated.claims.outcome, 'PROVED');
              assert.equal(gateway.verificationStats().receipts, 1);
            } finally {
              await gateway.close();
            }
          },
        );
      }
      await t.test(
        'verification refuses a client without the installed mTLS credential',
        async () => {
          const f = scenario(),
            gateway = await createNotificationGatewayFixture(f.options);
          try {
            await assert.rejects(f.withLease((lease) => f.verifyLease(lease), {}, true));
            assert.equal(gateway.verificationStats().calls, 0);
            assert.equal(gateway.stats().delivered, 0);
          } finally {
            await gateway.close();
          }
        },
      );
      await t.test(
        'real recipient rejects wrong scope/version/epoch and copied leases; callback exit erases bytes and aborts escaped use',
        async () => {
          const f = scenario(),
            gateway = await createNotificationGatewayFixture(f.options);
          let escaped;
          let rejectedUses = 0;
          try {
            for (const change of [
              { participantId: id(90) },
              { privacyDomainId: id(91) },
              { version: '2' },
              { epoch: '2' },
              { reference: 'secret://local/other#1' },
              { credentialRef: urn(92) },
            ]) {
              await assert.rejects(
                f.withLease(() => {
                  rejectedUses++;
                  throw new Error('Recipient must reject before use');
                }, change),
              );
              assert.equal(gateway.verificationStats().calls, 0);
              assert.equal(rejectedUses, 0);
            }
            await f.withLease(async (lease) => {
              escaped = lease;
              await assert.rejects(f.verifyLease({ ...lease }), /OPS_SECRET_UNRESOLVED/);
              for (const change of [
                { epoch: '2' },
                { version: '2' },
                { destinationRef: urn(93) },
                { privacyDomainId: id(94) },
              ])
                assert.throws(
                  () =>
                    assertNotificationCredentialLease(lease, { ...lease.credential, ...change }),
                  /OPS_SECRET_UNRESOLVED/,
                );
              await assert.rejects(
                exchangeNotificationEndpointTls(
                  lease,
                  lease.credential,
                  { ...f.options.installed.transport, addresses: ['127.0.0.2'] },
                  Buffer.from('{}'),
                  { signal: new AbortController().signal, timeoutMs: 1000 },
                ),
                /OPS_SECRET_UNRESOLVED/,
              );
              const listeners = getEventListeners(lease.signal, 'abort').length;
              assert.equal((await f.verifyLease(lease)).authenticated.claims.outcome, 'PROVED');
              assert.equal(getEventListeners(lease.signal, 'abort').length, listeners);
            });
            assert.equal(escaped.signal.aborted, true);
            assert.ok(escaped.bytes.every((byte) => byte === 0));
            await assert.rejects(f.verifyLease(escaped), /OPS_SECRET_UNRESOLVED/);
            assert.equal(gateway.verificationStats().calls, 1);
            assert.equal(gateway.stats().delivered, 0);
          } finally {
            await gateway.close();
          }
        },
      );
      await t.test(
        'callback rejection and unawaited dispatch erase leases and destroy outbound capability',
        async () => {
          const f = scenario(),
            gateway = await createNotificationGatewayFixture(f.options);
          let failed, escaped, unawaited;
          try {
            await assert.rejects(
              f.withLease(async (lease) => {
                failed = lease;
                throw new Error('Private test callback failure');
              }),
              /OPS_SECRET_UNRESOLVED/,
            );
            assert.equal(failed.signal.aborted, true);
            assert.ok(failed.bytes.every((byte) => byte === 0));
            await f.withLease(async (lease) => {
              escaped = lease;
              unawaited = f.verifyLease(lease).then(
                () => ({ success: true }),
                (error) => ({ error }),
              );
            });
            assert.ok((await unawaited).error);
            assert.equal(escaped.signal.aborted, true);
            assert.ok(escaped.bytes.every((byte) => byte === 0));
            assert.equal(getEventListeners(escaped.signal, 'abort').length, 0);
            assert.equal(gateway.verificationStats().calls, 0);
            assert.equal(gateway.stats().delivered, 0);
          } finally {
            await gateway.close();
          }
        },
      );
      await t.test(
        'wrong private key or client certificate cannot become a leased TLS material version',
        async () => {
          const f = scenario(),
            gateway = await createNotificationGatewayFixture(f.options);
          const wrong = key();
          const actualKey = createPrivateKey(materials.key).export({
            format: 'der',
            type: 'pkcs8',
          });
          try {
            for (const [privateKey, certificate] of [
              [wrong.privateKey, materials.cert],
              [actualKey, materials.serverCert],
            ]) {
              const bytes = encodeCbor(
                new Map([
                  [0, notificationCredentialEncoding],
                  [1, privateKey],
                  [
                    2,
                    [new X509Certificate(certificate).raw, new X509Certificate(materials.ca).raw],
                  ],
                  [3, [new X509Certificate(materials.ca).raw]],
                ]),
              );
              try {
                assert.throws(
                  () =>
                    createTestNotificationCredentialProvider(
                      { ...f.credential, fingerprint: sha256(bytes) },
                      bytes,
                    ),
                  /OPS_SECRET_UNRESOLVED/,
                );
              } finally {
                bytes.fill(0);
              }
            }
            assert.equal(gateway.verificationStats().calls, 0);
            assert.equal(gateway.stats().delivered, 0);
          } finally {
            wrong.privateKey.fill(0);
            actualKey.fill(0);
            await gateway.close();
          }
        },
      );
      await t.test('actual leased byte substitution fails before outbound TLS', async () => {
        const f = scenario(),
          gateway = await createNotificationGatewayFixture(f.options);
        let escaped;
        try {
          await assert.rejects(
            f.withLease(async (lease) => {
              escaped = lease;
              lease.bytes[lease.bytes.length - 1] ^= 1;
              await f.verifyLease(lease);
            }),
            /OPS_SECRET_UNRESOLVED/,
          );
          assert.equal(gateway.verificationStats().calls, 0);
          assert.equal(gateway.stats().delivered, 0);
          assert.ok(escaped.bytes.every((byte) => byte === 0));
        } finally {
          await gateway.close();
        }
      });
      for (const mode of ['revoke', 'expire']) {
        await t.test(
          `${mode} during actual leased TLS aborts I/O and leaves zero deliveries`,
          async () => {
            const f = scenario('WEBHOOK', mode === 'expire' ? 1500 : 60000);
            const gateway = await createNotificationGatewayFixture(f.options);
            let escaped;
            let invalidatedDuringIo = false;
            try {
              gateway.setFault('STALL');
              await assert.rejects(
                f.withLease(async (lease) => {
                  escaped = lease;
                  const exchange = f.verifyLease(lease, 5000);
                  // Attach rejection handling immediately while observing the real gateway.
                  const observed = exchange.then(
                    (value) => ({ value }),
                    (error) => ({ error }),
                  );
                  const deadline = Date.now() + 1000;
                  while (gateway.verificationStats().calls === 0 && Date.now() < deadline)
                    await delay(10);
                  assert.equal(
                    gateway.verificationStats().calls,
                    1,
                    'Required actual I/O before invalidation',
                  );
                  if (mode === 'revoke') f.revoke();
                  const result = await observed;
                  assert.ok(result.error, 'Expired/revoked active transport must not succeed');
                  assert.equal(lease.signal.aborted, true);
                  invalidatedDuringIo = true;
                }),
                /OPS_SECRET_UNRESOLVED/,
              );
              assert.equal(invalidatedDuringIo, true);
              assert.equal(escaped.signal.aborted, true);
              assert.ok(escaped.bytes.every((byte) => byte === 0));
              const deadline = Date.now() + 1000;
              while (gateway.stats().sockets !== 0 && Date.now() < deadline) await delay(10);
              assert.equal(gateway.stats().sockets, 0);
              assert.equal(gateway.stats().calls, 0);
              assert.equal(gateway.stats().delivered, 0);
              await assert.rejects(f.verify(), /OPS_SECRET_UNRESOLVED/);
              assert.equal(gateway.verificationStats().calls, 1);
            } finally {
              await gateway.close();
            }
          },
        );
      }
      for (const channel of ['WEBHOOK', 'EMAIL', 'OPERATIONS_QUEUE']) {
        await t.test(
          `${channel}: exact duplicate and restart readback preserve one external delivery`,
          async () => {
            const f = scenario(channel);
            let gateway = await createNotificationGatewayFixture(f.options);
            try {
              const receipt = await f.adapter().deliver(f.request, f.context);
              assert.equal(receipt.claims.outcome, 'DELIVERED');
              assert.deepEqual(
                (await f.adapter().deliver(f.request, f.context)).signed,
                receipt.signed,
              );
              assert.deepEqual(
                (await f.adapter().reconcile(f.attempt, f.context)).signed,
                receipt.signed,
              );
              assert.equal(gateway.stats().delivered, 1);
              await gateway.close();
              gateway = await createNotificationGatewayFixture(f.options);
              assert.deepEqual(
                (await f.adapter().reconcile(f.attempt, f.context)).signed,
                receipt.signed,
              );
              assert.equal(gateway.stats().calls, 0);
              assert.equal(gateway.stats().delivered, 1);
              const changed = Buffer.from('{"messageKey":"different"}');
              const attempt = {
                ...f.attempt,
                payloadDigest: sha256(changed),
                payloadBytes: changed.length,
              };
              const context = {
                ...f.context,
                idempotencyDigest: notificationIdempotencyDigest(attempt),
              };
              await assert.rejects(
                f
                  .adapter()
                  .deliver({ attempt, payloadBase64: changed.toString('base64') }, context),
                { reason: 'AMBIGUOUS' },
              );
              assert.equal(gateway.stats().delivered, 1);
            } finally {
              await gateway.close();
            }
          },
        );
      }
      await t.test(
        'lost acknowledgement survives gateway restart and is reconciled without another send',
        async () => {
          const f = scenario();
          let gateway = await createNotificationGatewayFixture(f.options);
          try {
            gateway.setFault('LOST_ACK');
            await assert.rejects(f.adapter().deliver(f.request, f.context), {
              reason: 'AMBIGUOUS',
            });
            assert.equal(gateway.stats().delivered, 1);
            await gateway.close();
            gateway = await createNotificationGatewayFixture(f.options);
            const receipt = await f.adapter().reconcile(f.attempt, f.context);
            assert.equal(receipt.claims.outcome, 'DELIVERED');
            assert.equal(gateway.stats().calls, 0);
            assert.equal(gateway.stats().readbacks, 1);
            assert.equal(gateway.stats().delivered, 1);
          } finally {
            await gateway.close();
          }
        },
      );
      await t.test(
        'only signed definitive no-effect permits a successor external attempt',
        async () => {
          const f = scenario(),
            gateway = await createNotificationGatewayFixture(f.options);
          try {
            gateway.setOutcome('RETRYABLE_NO_EFFECT');
            const first = await f.adapter().deliver(f.request, f.context);
            assert.equal(first.claims.outcome, 'RETRYABLE_NO_EFFECT');
            assert.equal(gateway.stats().delivered, 0);
            gateway.setOutcome('DELIVERED');
            const attempt = { ...f.attempt, attemptId: id(12), attemptNumber: 2 };
            assert.equal(
              (await f.adapter().deliver({ ...f.request, attempt }, f.context)).claims.outcome,
              'DELIVERED',
            );
            assert.deepEqual(
              (await f.adapter().reconcile(f.attempt, f.context)).signed,
              first.signed,
            );
            assert.equal(gateway.stats().delivered, 1);
          } finally {
            await gateway.close();
          }
        },
      );
      for (const fault of ['FORGED', 'PARTIAL', 'OVERSIZE', 'UNSIGNED', 'REDIRECT', 'STALL']) {
        await t.test(
          `${fault}: ambiguity retains original external effect for authenticated readback`,
          async () => {
            const f = scenario(),
              gateway = await createNotificationGatewayFixture(f.options);
            try {
              gateway.setFault(fault);
              await assert.rejects(f.adapter(undefined, 500).deliver(f.request, f.context), {
                reason: 'AMBIGUOUS',
              });
              assert.equal(gateway.stats().calls, 1);
              gateway.setFault('NORMAL');
              assert.equal(
                (await f.adapter().reconcile(f.attempt, f.context)).claims.outcome,
                'DELIVERED',
              );
              assert.equal(gateway.stats().delivered, 1);
            } finally {
              await gateway.close();
            }
          },
        );
      }
      await t.test(
        'cancelled window, unknown readback, wrong context and absent mTLS credentials never create effects',
        async () => {
          const f = scenario(),
            gateway = await createNotificationGatewayFixture(f.options);
          try {
            const aborted = new AbortController();
            aborted.abort();
            await assert.rejects(f.adapter(aborted.signal).deliver(f.request, f.context), {
              reason: 'CANCELLED',
            });
            await assert.rejects(f.adapter().reconcile(f.attempt, f.context), {
              reason: 'AMBIGUOUS',
            });
            const anonymous = createSecureContext({
              ca: materials.ca,
              minVersion: 'TLSv1.3',
              maxVersion: 'TLSv1.3',
            });
            await assert.rejects(
              f.adapter(undefined, 1000, anonymous).deliver(f.request, f.context),
              { reason: 'AMBIGUOUS' },
            );
            assert.equal(gateway.stats().delivered, 0);
            await f.adapter().deliver(f.request, f.context);
            await assert.rejects(
              f.adapter().reconcile(f.attempt, { ...f.context, auditCorrelationId: id(13) }),
              { reason: 'AMBIGUOUS' },
            );
            assert.equal(gateway.stats().delivered, 1);
          } finally {
            await gateway.close();
          }
        },
      );
    } finally {
      for (const provider of providers) provider.close();
      await recipient?.close();
      credentialBytes.fill(0);
      materials.serverKey.fill(0);
      materials.key.fill(0);
      await rm(directory, { recursive: true, force: true });
    }
  },
);
