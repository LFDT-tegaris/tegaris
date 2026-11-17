import { tmpdir } from 'node:os';
import { createSecureContext } from 'node:tls';
import { createNotificationGatewayAdapter } from '../../../services/control-api/src/notifications/gateway-adapter.ts';
import {
  notificationScopeDigest,
  notificationIdempotencyDigest,
  verifyInstalledNotificationChannel,
} from '../../../services/control-api/src/notifications/gateway-contracts.ts';
import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { Pool } from 'pg';
import { runtimeSnapshotTlsFixture } from '../identity/runtime-snapshot-tls-fixture.ts';
import {
  evidenceKeyId,
  signNotificationClaim,
} from '../../../packages/security-kernel/src/index.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.ts';
import { NotificationWorkloadTransport } from '../../../services/identity-service/src/domain/notification-workload-transport.ts';
import {
  prepareNotificationRuntimeFixtures,
  validateNotificationRuntimeEntries,
  notificationRuntimeVerificationStats,
  withNotificationRuntimeLostAck,
  notificationRuntimeDeliveryStats,
  withNotificationRuntimeDeliveryOutcome,
} from './notification-runtime-bootstrap.mjs';
import {
  notificationPackagedConfiguration,
  prepareNotificationPackagedRuntime,
  validateNotificationPackagedInputs,
} from './notification-packaged-runtime.mjs';

const id = (n) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const urn = (n) => `urn:openpc:resource:${id(n)}`;
const bounded = {
  max: 1,
  connectionTimeoutMillis: 1000,
  statement_timeout: 5000,
  idle_in_transaction_session_timeout: 10000,
};
const key = () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: pair.publicKey.export({ format: 'der', type: 'spki' }),
  };
};
async function closeAll(actions) {
  const results = await Promise.allSettled(actions.map((action) => Promise.resolve().then(action)));
  const failures = results
    .filter((result) => result.status === 'rejected')
    .map((result) => result.reason);
  if (failures.length) throw new AggregateError(failures, 'Notification test cleanup failed');
}
async function unusedPort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
async function inputs(
  root,
  scope = { participantId: id(1), privacyDomainId: id(2) },
  workloadId = id(3),
) {
  const peer = await runtimeSnapshotTlsFixture(
    `urn:openpc:participant:${scope.participantId}:workload:${workloadId}`,
  );
  const outbound = await runtimeSnapshotTlsFixture(
    `urn:openpc:participant:${scope.participantId}:workload:${id(9)}`,
  );
  const issuer = key(),
    gateway = key(),
    verification = key();
  const now = Date.now();
  const credential = {
    ...scope,
    credentialRef: `urn:openpc:resource:${localOperationId()}`,
    destinationRef: `urn:openpc:resource:${localOperationId()}`,
    channel: 'WEBHOOK',
    owner: 'LS-NOTIFICATION',
    secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
    reference: 'secret://local/packaged#1',
    version: '1',
    epoch: '1',
    fingerprint: `sha256:${'c'.repeat(64)}`,
    validFromMs: now - 1000,
    validUntilMs: now + 60000,
    state: 'ACTIVE',
  };
  const gatewayPort = await unusedPort();
  const transport = {
    protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
    channel: 'WEBHOOK',
    destinationRef: credential.destinationRef,
    credentialRef: credential.credentialRef,
    endpoint: `https://127.0.0.1:${gatewayPort}/`,
    addresses: ['127.0.0.1'],
    serverSpkiDigest: sha256(
      new X509Certificate(outbound.server.certificate).publicKey.export({
        format: 'der',
        type: 'spki',
      }),
    ),
    requestTimeoutMs: 5000,
    maxPayloadBytes: 1024,
  };
  const signed = signNotificationClaim(
    'NotificationChannelProfileV1',
    issuer.privateKey,
    issuer.spki,
    {
      ...scope,
      environmentId: 'notification-packaged-test',
      profileId: id(6),
      revision: '1',
      validFromMs: now - 1000,
      validUntilMs: now + 60000,
      transportProfileDigest: sha256(transport),
      receiptSignerSpki: gateway.spki.toString('hex'),
      issuerKeyId: evidenceKeyId(issuer.spki),
    },
  );
  const trust = {
    ...scope,
    environmentId: 'notification-packaged-test',
    signedProfileDigest: sha256(signed.cose),
    issuerSpkiHex: issuer.spki.toString('hex'),
  };
  const proof = signNotificationClaim(
    'NotificationVerificationProfileV1',
    issuer.privateKey,
    issuer.spki,
    {
      ...scope,
      environmentId: trust.environmentId,
      profileId: id(7),
      revision: '1',
      validFromMs: now - 1000,
      validUntilMs: now + 60000,
      signedChannelProfileDigest: trust.signedProfileDigest,
      credentialBindingDigest: sha256(credential),
      verificationSignerSpki: verification.spki.toString('hex'),
      issuerKeyId: evidenceKeyId(issuer.spki),
    },
  );
  let exports = 0;
  // Only this external provider is simulated. No internal Identity, SQL,
  // admission or business result is substituted in these tests.
  const provider = Object.freeze({
    async withExactVersion() {
      exports++;
      throw new Error('external provider deliberately unavailable');
    },
    revoke() {},
    close() {},
  });
  const fixture = {
    installation: {
      credential,
      channelTrust: trust,
      channelSigned: {
        transport,
        payloadHex: signed.payload.toString('hex'),
        coseHex: signed.cose.toString('hex'),
      },
      verification: {
        trust: { ...trust, signedProfileDigest: sha256(proof.cose) },
        signed: { payloadHex: proof.payload.toString('hex'), coseHex: proof.cose.toString('hex') },
      },
      principalId: localOperationId(),
      workloadCredentialId: localOperationId(),
      workloadId: `urn:openpc:workload:${workloadId}`,
      workloadEpoch: '1',
      admissionReference: 'packaged-test-initial-trust',
    },
    provider,
    journalPath: join(
      root,
      'evidence/notification-browser',
      `gateway-${credential.credentialRef.slice(-36)}.jsonl`,
    ),
    gatewayTls: {
      ca: outbound.server.ca,
      cert: outbound.server.certificate,
      key: outbound.server.privateKey,
    },
    gatewaySignerPrivateKey: gateway.privateKey,
    gatewaySignerSpki: gateway.spki,
    verificationSignerPrivateKey: verification.privateKey,
    verificationSignerSpki: verification.spki,
    clientSpkiDigest: sha256(outbound.parsed.publicKey.export({ format: 'der', type: 'spki' })),
    network: {
      addresses: transport.addresses,
      advertisedOrigin: transport.endpoint,
      listenHost: '127.0.0.1',
    },
  };
  const listenerPin = sha256(
    new X509Certificate(peer.server.certificate).publicKey.export({ format: 'der', type: 'spki' }),
  );
  const installationPool = new Pool({
    ...bounded,
    host: '127.0.0.1',
    port: 1,
    user: 'unavailable-test-owner',
  });
  const runtimePool = new Pool({
    ...bounded,
    host: '127.0.0.1',
    port: 1,
    user: 'openpc_configuration_runtime',
  });
  return {
    fixture,
    peer,
    outbound,
    credential,
    gatewayPort,
    exports: () => exports,
    packaged: {
      runRoot: root,
      containerRoot: '/app/notification-packaged',
      installationPool,
      runtimePool,
      entries: [
        {
          fixture,
          workloadTls: {
            ca: peer.server.ca,
            certificate: peer.certificate,
            privateKey: peer.privateKey,
          },
        },
      ],
      provider: {
        tls: peer.server,
        leaseMs: 1000,
        network: {
          advertisedAddress: '127.0.0.1',
          listenHost: '127.0.0.1',
          serverName: '127.0.0.1',
          serverSpkiDigest: listenerPin,
        },
      },
      control: {
        tls: peer.server,
        listen: { host: '0.0.0.0', port: 3448 },
        peer: {
          host: '127.0.0.1',
          port: 53448,
          serverName: '127.0.0.1',
          serverSpkiDigest: listenerPin,
        },
      },
      timeoutMs: 5000,
    },
    async close() {
      try {
        await closeAll([
          () => installationPool.end(),
          () => runtimePool.end(),
          () => peer.close(),
          () => outbound.close(),
        ]);
      } finally {
        for (const entry of [issuer, gateway, verification]) entry.privateKey.fill(0);
      }
    },
  };
}
let root, value;
before(async () => {
  root = await mkdtemp(
    join(process.env.OPENPC_PNC_TMP_ROOT ?? tmpdir(), 'notification-bootstrap-test-'),
  );
  await mkdir(join(root, 'evidence/notification-browser'), { recursive: true, mode: 0o700 });
  value = await inputs(root);
});
after(async () => {
  await closeAll([
    () => value?.close(),
    async () => {
      if (root) await rm(root, { recursive: true, force: true });
    },
  ]);
});

test('pure bootstrap preflight authenticates complete signed profile/key bindings without provider use', () => {
  const result = validateNotificationRuntimeEntries([value.fixture]);
  assert.deepEqual(result[0].credential, value.credential);
  assert.equal(value.exports(), 0);
  assert.ok(Object.isFrozen(result[0].installation));
});
test('unadmitted packaged execution returns only a closed ownership error without subprocess details', async () => {
  await assert.rejects(prepareNotificationPackagedRuntime(value.packaged), (error) => {
    assert.equal(error.message, 'BLOCKED_NOTIFICATION_PACKAGED_OWNERSHIP');
    assert.equal(error.cause, undefined);
    assert.equal(error.cmd, undefined);
    assert.equal(error.stderr, undefined);
    return true;
  });
  assert.equal(value.exports(), 0);
});
test('exact packaged loader configuration uses container paths and transport-only TLS metadata', () => {
  const config = notificationPackagedConfiguration(value.packaged, 23456);
  assert.deepEqual(Object.keys(config).sort(), [
    'connectionLifetimeMs',
    'listen',
    'providers',
    'timeoutMs',
    'tls',
    'version',
  ]);
  assert.equal(config.providers[0].port, 23456);
  assert.equal(config.providers[0].credential.fingerprint, value.credential.fingerprint);
  assert.equal(
    config.providers[0].tls.privateKeyFile,
    '/app/notification-packaged/workload-0-key.pem',
  );
  assert.equal(config.tls.privateKeyFile, '/app/notification-packaged/control-key.pem');
  assert.equal(config.connectionLifetimeMs, 300000);
  assert.equal(JSON.stringify(config).includes('PRIVATE KEY'), false);
  assert.equal(JSON.stringify(config).includes(root), false);
  assert.equal(value.exports(), 0);
});
test('signed profile, network, signer, path, duplicate and closed-shape substitutions fail before listeners', () => {
  const f = value.fixture;
  for (const entries of [
    [{ ...f, ready: true }],
    [{ ...f, journalPath: 'relative' }],
    [{ ...f, network: { ...f.network, addresses: ['127.0.0.2'] } }],
    [{ ...f, network: { ...f.network, advertisedOrigin: 'https://other/' } }],
    [{ ...f, gatewaySignerPrivateKey: f.verificationSignerPrivateKey }],
    [{ ...f, verificationSignerSpki: f.gatewaySignerSpki }],
    [
      {
        ...f,
        installation: {
          ...f.installation,
          channelSigned: {
            ...f.installation.channelSigned,
            transport: { ...f.installation.channelSigned.transport, destinationRef: urn(99) },
          },
        },
      },
    ],
    [{ ...f, installation: { ...f.installation, verification: undefined } }],
    [f, f],
    [],
  ])
    assert.throws(() => validateNotificationRuntimeEntries(entries));
  assert.equal(value.exports(), 0);
});
test('packaged inputs reject TLS pins, workload binding, static channel-key copies and unbounded pools', () => {
  const p = value.packaged;
  for (const changed of [
    { ...p, ready: true },
    {
      ...p,
      control: {
        ...p.control,
        peer: { ...p.control.peer, serverSpkiDigest: `sha256:${'0'.repeat(64)}` },
      },
    },
    { ...p, entries: [{ ...p.entries[0], workloadTls: p.control.tls }] },
    {
      ...p,
      entries: [
        {
          ...p.entries[0],
          fixture: {
            ...value.fixture,
            clientSpkiDigest: sha256(
              value.peer.parsed.publicKey.export({ format: 'der', type: 'spki' }),
            ),
          },
        },
      ],
    },
    {
      ...p,
      entries: [
        { ...p.entries[0], fixture: { ...value.fixture, journalPath: '/tmp/foreign.jsonl' } },
      ],
    },
    {
      ...p,
      installationPool: { options: bounded, connect: () => assert.fail('surrogate SQL owner') },
    },
    { ...p, runtimePool: p.installationPool },
  ])
    assert.throws(() => validateNotificationPackagedInputs(changed));
  assert.equal(value.exports(), 0);
});
test('real database connection failure closes already bound gateway without provider export or journal deletion', async () => {
  await assert.rejects(
    prepareNotificationRuntimeFixtures({
      installationPool: value.packaged.installationPool,
      entries: [value.fixture],
    }),
  );
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(value.gatewayPort, '127.0.0.1', resolve);
  });
  await new Promise((resolve) => server.close(resolve));
  assert.equal(value.exports(), 0);
});
test('fixture serialization and caller booleans cannot supply private fault or statistics control', async () => {
  for (const fake of [{}, { ready: true }, { credentialProvider: value.fixture.provider }]) {
    assert.throws(() => notificationRuntimeVerificationStats(fake, value.credential));
    const scope = {
      participantId: value.credential.participantId,
      privacyDomainId: value.credential.privacyDomainId,
      destinationRef: value.credential.destinationRef,
    };
    assert.throws(() => notificationRuntimeDeliveryStats(fake, scope));
    await assert.rejects(
      withNotificationRuntimeDeliveryOutcome(fake, scope, 'DELIVERED', async () =>
        assert.fail('forged fixture callback'),
      ),
    );
    await assert.rejects(
      withNotificationRuntimeLostAck(fake, value.credential, async () =>
        assert.fail('must not enter'),
      ),
    );
  }
});

// Required real-owner acceptance, selected by the existing admitted database
// runner. Missing inputs are BLOCKED, never a skipped/passed journey. Focused
// source checks select non-PG cases explicitly and report this case unexecuted.
test('PG: current installed Identity, actual TLS peer, duplicate ownership and Control transport restart', async () => {
  const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
  const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
  const participantId = process.env.OPENPC_NOTIFICATION_PARTICIPANT_ID;
  const privacyDomainId = process.env.OPENPC_NOTIFICATION_PRIVACY_DOMAIN_ID;
  assert.ok(
    adminUrl && runtimeUrl && participantId && privacyDomainId,
    'BLOCKED: real admitted notification PostgreSQL scope required',
  );
  const f = await inputs(root, { participantId, privacyDomainId }, localOperationId());
  const installationPool = new Pool({ ...bounded, connectionString: adminUrl });
  const runtimePool = new Pool({ ...bounded, connectionString: runtimeUrl });
  const recipientPool = new Pool({ ...bounded, connectionString: runtimeUrl });
  let fixture, transport, firstFailure;
  const createTransport = () =>
    new NotificationWorkloadTransport({
      pool: runtimePool,
      kernel: new IdentityKernel(new PostgresIdentityRepository(recipientPool, systemClock)),
      tls: f.peer.server,
    });
  try {
    const installation = f.fixture.installation,
      cert = f.peer.parsed;
    await installationPool.query(
      "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Notification packaged initial trust','ACTIVE',1)",
      [installation.principalId, participantId],
    );
    await installationPool.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS','local-evidence-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
      [
        installation.workloadCredentialId,
        participantId,
        installation.principalId,
        cert.subjectAltName.slice(4),
        installation.workloadId,
        Buffer.from(sha256(cert.publicKey.export({ format: 'der', type: 'spki' })).slice(7), 'hex'),
        cert.publicKey.export({ format: 'der', type: 'spki' }),
        Buffer.from(sha256(cert.raw).slice(7), 'hex'),
        new Date(cert.validFrom),
        new Date(cert.validTo),
      ],
    );
    fixture = await prepareNotificationRuntimeFixtures({ installationPool, entries: [f.fixture] });
    for (let cycle = 0; cycle < 2; cycle++) {
      transport = createTransport();
      const listen = await transport.listen({ host: '127.0.0.1', port: 0 });
      await assert.rejects(
        transport.withPeer(f.credential, async () => assert.fail('missing peer')),
      );
      const connection = await fixture.connectWorkload({
        host: listen.host,
        port: listen.port,
        ca: f.peer.server.ca,
        certificate: f.peer.certificate,
        privateKey: f.peer.privateKey,
      });
      // The real transport asynchronously commits Identity admission; each probe
      // remains real and has no gateway/provider/business callback.
      let admitted = false;
      for (let attempt = 0; attempt < 20 && !admitted; attempt++) {
        try {
          await transport.withPeer(f.credential, async () => {});
          admitted = true;
        } catch {
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
      }
      assert.ok(admitted, 'BLOCKED: actual peer admission did not complete');
      await assert.rejects(
        fixture.connectWorkload({
          host: listen.host,
          port: listen.port,
          ca: f.peer.server.ca,
          certificate: f.peer.certificate,
          privateKey: f.peer.privateKey,
        }),
      );
      await transport.close();
      await connection.closed;
      assert.equal(f.exports(), 0);
    }
    const before = notificationRuntimeVerificationStats(fixture, f.credential);
    await assert.rejects(
      withNotificationRuntimeLostAck(fixture, f.credential, async () => {
        throw new Error('original scenario failure');
      }),
      /original scenario failure/u,
    );
    await withNotificationRuntimeLostAck(fixture, f.credential, async () =>
      assert.deepEqual(notificationRuntimeVerificationStats(fixture, f.credential), before),
    );
    const scope = { participantId, privacyDomainId, destinationRef: f.credential.destinationRef };
    const foreign = { ...scope, privacyDomainId: localOperationId() };
    let forbidden = 0;
    for (const [actualFixture, actualScope, outcome] of [
      [{ ...fixture }, scope, 'DELIVERED'],
      [fixture, foreign, 'DELIVERED'],
      [fixture, { ...scope, ready: true }, 'DELIVERED'],
      [fixture, scope, 'UNDECLARED'],
    ])
      await assert.rejects(
        withNotificationRuntimeDeliveryOutcome(actualFixture, actualScope, outcome, async () => {
          forbidden++;
        }),
      );
    assert.equal(forbidden, 0);
    const installed = verifyInstalledNotificationChannel(
      f.fixture.installation.channelTrust,
      f.fixture.installation.channelSigned,
    );
    const secure = createSecureContext({
      ca: f.outbound.server.ca,
      cert: f.outbound.certificate,
      key: f.outbound.privateKey,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    });
    // External adapter protocol acceptance only. Synthetic request bindings here
    // are not internal STARTED/dispatch admission or product journey evidence.
    const deliver = async () => {
      const now = Date.now(),
        occurrence = localOperationId(),
        payload = Buffer.from('external-fixture-probe');
      const attempt = {
        version: 'NotificationDeliveryAttemptV1',
        participantId,
        privacyDomainId,
        notificationOccurrenceId: `urn:openpc:resource:${occurrence}`,
        endpointId: `urn:openpc:resource:${localOperationId()}`,
        endpointRevision: '1',
        channel: installed.transport.channel,
        destinationRef: installed.transport.destinationRef,
        credentialRef: installed.transport.credentialRef,
        channelProfileDigest: installed.signedProfileDigest,
        templateDigest: sha256('external-fixture-template'),
        payloadDigest: sha256(payload),
        payloadBytes: payload.length,
        attemptId: localOperationId(),
        attemptNumber: 1,
        startedAtMs: now,
        deadlineAtMs: now + 4000,
      };
      const context = {
        authorizationDigest: sha256('external-fixture-authority'),
        profileDigest: installed.signedProfileDigest,
        authorizationContextId: localOperationId(),
        authorizationContextEpoch: 1,
        accessClassIds: ['ACCESS-NOTIFICATION'],
        scopeDigest: notificationScopeDigest(attempt),
        deadlineAt: new Date(attempt.deadlineAtMs).toISOString(),
        idempotencyDigest: notificationIdempotencyDigest(attempt),
        occurrenceId: occurrence,
        auditCorrelationId: localOperationId(),
        cancellation: { mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION', occurrenceId: occurrence },
        reconciliation: { mode: 'EXACT_OCCURRENCE', occurrenceId: occurrence },
      };
      const adapter = createNotificationGatewayAdapter(installed, installed, secure, {
        signal: new AbortController().signal,
        timeoutMs: 4000,
      });
      try {
        return await adapter.deliver(
          { attempt, payloadBase64: payload.toString('base64') },
          context,
        );
      } finally {
        payload.fill(0);
      }
    };
    const originalFailure = new Error('retained external callback failure');
    await assert.rejects(
      withNotificationRuntimeDeliveryOutcome(fixture, scope, 'PERMANENT_FAILURE', async () => {
        await assert.rejects(
          withNotificationRuntimeLostAck(fixture, f.credential, async () => {
            forbidden++;
          }),
        );
        await assert.rejects(
          withNotificationRuntimeDeliveryOutcome(fixture, scope, 'DELIVERED', async () => {
            forbidden++;
          }),
        );
        assert.equal((await deliver()).claims.outcome, 'PERMANENT_FAILURE');
        throw originalFailure;
      }),
      (error) => error === originalFailure,
    );
    const failed = notificationRuntimeDeliveryStats(fixture, scope);
    assert.equal(failed.calls, 1);
    assert.equal(failed.receipts, 1);
    assert.equal(failed.delivered, 0);
    assert.equal(
      (await deliver()).claims.outcome,
      'DELIVERED',
      'Outcome restored after callback failure',
    );
    const recovered = notificationRuntimeDeliveryStats(fixture, scope);
    assert.equal(recovered.calls, 2);
    assert.equal(recovered.receipts, 2);
    assert.equal(recovered.delivered, 1);
    assert.equal(forbidden, 0);
    await assert.rejects(
      withNotificationRuntimeLostAck(fixture, f.credential, async () => {
        await assert.rejects(
          withNotificationRuntimeDeliveryOutcome(fixture, scope, 'DELIVERED', async () => {
            forbidden++;
          }),
        );
        throw originalFailure;
      }),
      (error) => error === originalFailure,
    );
    let entered, release;
    const active = new Promise((resolve) => {
        entered = resolve;
      }),
      pending = new Promise((resolve) => {
        release = resolve;
      });
    const late = withNotificationRuntimeDeliveryOutcome(fixture, scope, 'AMBIGUOUS', async () => {
      entered();
      await pending;
    });
    const rejectedLate = assert.rejects(late);
    await active;
    await fixture.close();
    release();
    await rejectedLate;
    assert.throws(() => notificationRuntimeDeliveryStats(fixture, scope));
    await assert.rejects(
      withNotificationRuntimeDeliveryOutcome(fixture, scope, 'DELIVERED', async () => {
        forbidden++;
      }),
    );
    assert.equal(forbidden, 0);
    assert.equal(f.exports(), 0);
  } catch (error) {
    firstFailure = error;
  }
  try {
    // Stop both real transport owners before their borrowed pools. Keep the
    // first scenario failure even when one or more cleanup operations fail.
    let transportFailure;
    try {
      await closeAll([() => transport?.close(), () => fixture?.close()]);
    } catch (error) {
      transportFailure = error;
    }
    await closeAll([
      () => installationPool.end(),
      () => runtimePool.end(),
      () => recipientPool.end(),
      () => f.close(),
      () => {
        if (transportFailure) throw transportFailure;
      },
    ]);
  } catch (cleanup) {
    if (firstFailure)
      throw new AggregateError([firstFailure, cleanup], 'Notification scenario and cleanup failed');
    throw cleanup;
  }
  if (firstFailure) throw firstFailure;
});
