import assert from 'node:assert/strict';
import test from 'node:test';
import { X509Certificate } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Pool } from 'pg';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { verifyInstalledNotificationChannel } from '../../../services/control-api/src/notifications/gateway-contracts.ts';
import { verifyInstalledNotificationVerification } from '../../../services/control-api/src/configuration/notification-verification-contract.ts';
import {
  notificationPackagedValidity,
  prepareNotificationPackagedInputs,
  validateNotificationPackagedInputRequest,
} from './notification-packaged-inputs.mjs';

const request = () => ({
  runRoot: '/tmp/owned-notification-test',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  database: {
    installationUrl: 'postgresql://openpc_control:synthetic-test@127.0.0.1:55432/openpc_control',
    runtimeUrl:
      'postgresql://openpc_configuration_runtime:synthetic-test@127.0.0.1:55432/openpc_control',
  },
  minimumRemainingMs: 120000,
});

test('closed input request derives bounded defaults without accepting runtime authority or secrets', () => {
  const actual = validateNotificationPackagedInputRequest(request());
  assert.equal(actual.containerRoot, '/app/notification-packaged');
  assert.equal(actual.validityMs, 3600000);
  assert.equal(actual.controlListenPort, 3448);
  assert.deepEqual(actual.channels, ['WEBHOOK', 'WEBHOOK', 'WEBHOOK']);
  assert.throws(
    () => validateNotificationPackagedInputRequest(Object.create(request())),
    /BLOCKED_NOTIFICATION_INPUTS_REQUEST/u,
  );
  let getterReads = 0;
  const accessor = {
    ...request(),
    get ready() {
      getterReads++;
      return true;
    },
  };
  assert.throws(
    () => validateNotificationPackagedInputRequest(accessor),
    /BLOCKED_NOTIFICATION_INPUTS_REQUEST/u,
  );
  assert.equal(getterReads, 0);
  for (const unknown of [
    { ready: true },
    { installation: {} },
    { workload: {} },
    { provider: {} },
    { tls: {} },
    { channelSecretFile: '/tmp/secret' },
    { serverSpkiDigest: `sha256:${'0'.repeat(64)}` },
    { grants: [] },
    { restore: true },
    { mounts: [] },
    { network: { gateway: '127.0.0.1' } },
  ])
    assert.throws(
      () => validateNotificationPackagedInputRequest({ ...request(), ...unknown }),
      /BLOCKED_NOTIFICATION_INPUTS_REQUEST/u,
    );
});
test('invalid scopes, channels, path aliases, ports and lifetimes reject before owned execution', async () => {
  for (const changes of [
    { participantId: 'foreign' },
    { privacyDomainId: 'urn:openpc:privacy:invalid' },
    { runRoot: 'relative' },
    { containerRoot: '/app/../escape' },
    { runRoot: '/tmp/owned\0' },
    { channels: [] },
    { channels: ['SMS'] },
    { channels: Array(9).fill('WEBHOOK') },
    { controlListenPort: 0 },
    { controlListenPort: 65536 },
    { controlListenPort: 1.5 },
    { validityMs: 3600001 },
    { minimumRemainingMs: 0 },
    { validityMs: 1000, minimumRemainingMs: 1001 },
    { environmentId: 'foreign environment' },
  ])
    await assert.rejects(
      prepareNotificationPackagedInputs({ ...request(), ...changes }),
      /BLOCKED_NOTIFICATION_INPUTS_REQUEST/u,
    );
});
test('database inputs require distinct local installation/runtime roles on the same store', () => {
  const value = request();
  for (const database of [
    { ...value.database, ready: true },
    { installationUrl: value.database.runtimeUrl, runtimeUrl: value.database.runtimeUrl },
    { ...value.database, runtimeUrl: value.database.installationUrl },
    { ...value.database, runtimeUrl: value.database.runtimeUrl.replace('55432', '55433') },
    {
      ...value.database,
      runtimeUrl: value.database.runtimeUrl.replace('openpc_control', 'foreign_control'),
    },
    {
      ...value.database,
      runtimeUrl: `${value.database.runtimeUrl}?options=-c%20role%3Dopenpc_control`,
    },
    {
      ...value.database,
      installationUrl: value.database.installationUrl.replace('127.0.0.1', 'remote.test'),
    },
    {
      ...value.database,
      installationUrl: value.database.installationUrl.replace(':synthetic-test', ''),
    },
  ])
    assert.throws(
      () => validateNotificationPackagedInputRequest({ ...value, database }),
      /BLOCKED_NOTIFICATION_INPUTS_REQUEST/u,
    );
});
test('lifetime is capped by the earliest actual certificate, not extended to meet the requested phase', () => {
  const observed = {
    databaseNowMs: 10000,
    validityMs: 20000,
    minimumRemainingMs: 5000,
    certificates: [
      { validFromMs: 9000, validUntilMs: 40000 },
      { validFromMs: 8000, validUntilMs: 18000 },
    ],
  };
  assert.deepEqual(notificationPackagedValidity(observed), {
    validFromMs: 10000,
    validUntilMs: 18000,
  });
  assert.throws(
    () => notificationPackagedValidity({ ...observed, minimumRemainingMs: 8001 }),
    /BLOCKED_NOTIFICATION_INPUTS_LIFETIME/u,
  );
  assert.deepEqual(notificationPackagedValidity({ ...observed, validityMs: 6000 }), {
    validFromMs: 10000,
    validUntilMs: 16000,
  });
});
test('expired, future, malformed or caller-declared lifetime authority fails closed', () => {
  const value = {
    databaseNowMs: 10000,
    validityMs: 20000,
    minimumRemainingMs: 5000,
    certificates: [{ validFromMs: 9000, validUntilMs: 40000 }],
  };
  for (const changes of [
    { certificates: [] },
    { certificates: [{ validFromMs: 10001, validUntilMs: 40000 }] },
    { certificates: [{ validFromMs: 9000, validUntilMs: 10000 }] },
    { certificates: [{ validFromMs: 11000, validUntilMs: 10000 }] },
    { certificates: [{ validFromMs: 9000, validUntilMs: Infinity }] },
    { certificates: [{ validFromMs: 9000, validUntilMs: 40000, ready: true }] },
    { databaseNowMs: NaN },
    { databaseNowMs: Number.MAX_SAFE_INTEGER },
    { ready: true },
  ])
    assert.throws(
      () => notificationPackagedValidity({ ...value, ...changes }),
      /BLOCKED_NOTIFICATION_INPUTS_LIFETIME/u,
    );
});
test('shape errors contain no database credentials or supplied diagnostic values', async () => {
  const value = request(),
    secret = 'private-sentinel-never-log';
  const rejected = {
    ...value,
    ready: secret,
    database: {
      ...value.database,
      installationUrl: value.database.installationUrl.replace('synthetic-test', secret),
    },
  };
  await assert.rejects(prepareNotificationPackagedInputs(rejected), (error) => {
    assert.equal(error.message, 'BLOCKED_NOTIFICATION_INPUTS_REQUEST');
    assert.equal(String(error).includes(secret), false);
    assert.equal(error.cause, undefined);
    return true;
  });
});

// The canonical runtime owner supplies its already-admitted NEW owned root and
// real active scope/database logins. No fixture callbacks, SQL mocks or ready
// flags substitute for those owners. This test starts only the external gateway/
// provider composition; packaged Control startup and full browser VERIFY remain
// the root runner's separate acceptance. Excluding PG explicitly is not a pass.
test('PG: prepare actual scoped initial trust, signed inputs, physical providers and transport-only mounts; retain revoked originals', async () => {
  const runRoot = process.env.OPENPC_NOTIFICATION_PACKAGED_RUN_ROOT,
    participantId = process.env.OPENPC_NOTIFICATION_PARTICIPANT_ID,
    privacyDomainId = process.env.OPENPC_NOTIFICATION_PRIVACY_DOMAIN_ID,
    installationUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
    runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
  assert.ok(
    runRoot && participantId && privacyDomainId && installationUrl && runtimeUrl,
    'BLOCKED: canonical admitted root, active notification scope and real PostgreSQL roles required',
  );
  const input = {
    runRoot,
    participantId,
    privacyDomainId,
    database: { installationUrl, runtimeUrl },
    channels: ['WEBHOOK', 'WEBHOOK'],
    minimumRemainingMs: 30000,
  };
  const observer = new Pool({
    connectionString: installationUrl,
    max: 1,
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
    idle_in_transaction_session_timeout: 30000,
  });
  let prepared, runtime, firstFailure, original;
  try {
    await assert.rejects(
      prepareNotificationPackagedInputs({ ...input, privacyDomainId: localOperationId() }),
      /BLOCKED_NOTIFICATION_INPUTS_ACTIVE_SCOPE/u,
    );
    const before = await observer.query(
      'select count(*)::text count from control.notification_endpoint where participant_id=$1 and privacy_domain_id=$2',
      [participantId, privacyDomainId],
    );
    prepared = await prepareNotificationPackagedInputs(input);
    assert.equal(Object.isFrozen(prepared), true);
    assert.equal(Object.isFrozen(prepared.destinations), true);
    assert.equal(prepared.destinations.length, 2);
    assert.equal(new Set(prepared.destinations.map((d) => d.destinationRef)).size, 2);
    assert.equal(new Set(prepared.destinations.map((d) => d.credentialRef)).size, 2);
    await prepared.assertCurrent();
    const first = prepared.prepareRuntime();
    assert.equal(prepared.prepareRuntime(), first, 'same original provider composition');
    runtime = await first;
    await prepared.assertCurrent();
    const configuration = runtime.mounts.find(
      (mount) => mount.target === runtime.configurationFile,
    );
    assert.ok(configuration);
    const config = JSON.parse(await readFile(configuration.source, 'utf8'));
    const network = JSON.parse(
      await readFile(join(runRoot, 'data/local-runtime-network.json'), 'utf8'),
    );
    assert.equal(config.providers.length, 2);
    assert.equal(config.providers[0].address, network.gateway);
    assert.equal(config.providers[0].port, config.providers[1].port);
    assert.equal(config.listen.port, runtime.port.target);
    for (const mount of runtime.mounts) {
      assert.equal(mount.type, 'bind');
      assert.equal(mount.read_only, true);
      assert.equal((await stat(dirname(mount.source))).mode & 0o777, 0o700);
      assert.equal((await stat(mount.source)).mode & 0o777, 0o444);
      assert.ok(mount.target.startsWith('/app/notification-packaged/'));
    }
    const certificate = new X509Certificate(
      await readFile(
        runtime.mounts.find((m) => m.target === config.providers[0].tls.certificateFile).source,
      ),
    );
    assert.match(
      certificate.subjectAltName,
      new RegExp(`^URI:urn:openpc:participant:${participantId}:workload:`),
    );
    const rows = await observer.query(
      'select * from control.installed_notification_channel where participant_id=$1 and privacy_domain_id=$2 and credential_ref=any($3::text[]) order by credential_ref',
      [participantId, privacyDomainId, prepared.destinations.map((d) => d.credentialRef)],
    );
    assert.equal(rows.rowCount, 2);
    original = rows.rows;
    for (const row of original) {
      const channel = verifyInstalledNotificationChannel(row.channel_trust, row.channel_signed);
      const verification = verifyInstalledNotificationVerification(
        row.verification_trust,
        row.verification_signed,
        row.channel_trust,
        row.channel_signed,
      );
      assert.equal(verification.claims.credentialBindingDigest, sha256(row.credential));
      assert.equal(channel.claims.validUntilMs, prepared.validUntilMs);
      assert.deepEqual(channel.transport.addresses, [network.gateway]);
      assert.notEqual(
        channel.transport.serverSpkiDigest,
        sha256(certificate.publicKey.export({ format: 'der', type: 'spki' })),
      );
      const substituted = {
        ...row.channel_signed,
        transport: { ...row.channel_signed.transport, addresses: ['127.0.0.2'] },
      };
      assert.throws(() => verifyInstalledNotificationChannel(row.channel_trust, substituted));
    }
    const unchanged = await observer.query(
      'select count(*)::text count from control.notification_endpoint where participant_id=$1 and privacy_domain_id=$2',
      [participantId, privacyDomainId],
    );
    assert.deepEqual(
      unchanged.rows,
      before.rows,
      'initial trust creates no endpoint or verification result',
    );
    // Explicit revocation fault on this test's fresh credential. Never reactivate
    // it, replay a business request or construct a replacement physical provider.
    await observer.query(
      "update control.credential set state='REVOKED' where participant_id=$1 and credential_id=$2",
      [participantId, original[0].workload_credential_id],
    );
    await assert.rejects(prepared.assertCurrent(), /BLOCKED_NOTIFICATION_INPUTS_CURRENT_WORKLOAD/u);
  } catch (error) {
    firstFailure = error;
  }
  const cleanupFailures = [];
  try {
    await prepared?.close();
  } catch (error) {
    cleanupFailures.push(error);
  }
  try {
    if (prepared && !cleanupFailures.length) {
      await assert.rejects(prepared.assertCurrent(), /BLOCKED_NOTIFICATION_INPUTS_CLOSED/u);
      await assert.rejects(prepared.prepareRuntime(), /BLOCKED_NOTIFICATION_INPUTS_CLOSED/u);
      await assert.rejects(
        prepareNotificationPackagedInputs(input),
        /BLOCKED_NOTIFICATION_INPUTS_FRESH_OWNER/u,
      );
      if (original) {
        const retained = await observer.query(
          'select * from control.installed_notification_channel where participant_id=$1 and privacy_domain_id=$2 and credential_ref=any($3::text[]) order by credential_ref',
          [participantId, privacyDomainId, original.map((r) => r.credential_ref)],
        );
        assert.deepEqual(retained.rows, original);
      }
    }
  } catch (error) {
    cleanupFailures.push(error);
  }
  try {
    await observer.end();
  } catch (error) {
    cleanupFailures.push(error);
  }
  if (firstFailure || cleanupFailures.length)
    throw new AggregateError(
      [...(firstFailure ? [firstFailure] : []), ...cleanupFailures],
      'Notification packaged input test failed',
    );
});
