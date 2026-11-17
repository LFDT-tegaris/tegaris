import { generateKeyPairSync } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { expect } from 'vitest';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationWorkerProfileClaims,
} from '../../../packages/security-kernel/src/index.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import {
  installInitialNotificationWorker,
  withdrawNotificationWorker,
  fenceNotificationWorkerInstallation,
} from '../../../services/control-api/src/notifications/worker-installation.js';
import { validateNotificationWorkerInstallation } from '../../../services/control-api/src/notifications/worker-installation-contract.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import type { EvidenceScope } from '../../../services/control-api/src/evidence/segment.js';

/** Initial public profile trust, real existing TLS credential and PostgreSQL only.
 * Route/KMS references are deliberately uninstalled negative prerequisites: this
 * gate cannot manufacture occurrence, signing, source or delivery authorization. */
export async function assertNotificationWorkerAdmissionCases(input: {
  runtime: Pool;
  installer: Pool;
  scope: EvidenceScope;
  principalId: string;
  credentialId: string;
  workloadId: string;
  tlsSpki: Buffer;
  producerTrustDigest: string;
  call(value: unknown, missingTls?: boolean): Promise<{ status: number; body: unknown }>;
  restart(): Promise<void>;
}) {
  const { scope } = input;
  const scoped = async <T>(
    pool: Pool,
    run: (client: PoolClient) => Promise<T>,
    privacy = scope.privacyDomainId,
  ) => {
    const c = await pool.connect();
    try {
      await c.query('begin');
      await c.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        [scope.participantId, privacy, id()],
      );
      const value = await run(c);
      await c.query('commit');
      return value;
    } catch (e) {
      await c.query('rollback');
      throw e;
    } finally {
      c.release();
    }
  };
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = issuer.publicKey.export({ type: 'spki', format: 'der' }),
    privateKey = issuer.privateKey.export({ type: 'pkcs8', format: 'der' });
  const now = Date.now();
  const make = (control = false) => {
    const claims: NotificationWorkerProfileClaims = {
      environmentId: 'local-export',
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      profileId: id(),
      revision: '1',
      validFromMs: now - 1000,
      validUntilMs: now + 600000,
      sourceId: id(),
      serviceId: control ? 'LS-CONTROL-WORK' : 'LS-NOTIFICATION',
      processRole: control ? 'ROLE-CONTROL-WORKER' : 'ROLE-NOTIFICATION-WORKER',
      subscriptionId: control
        ? 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1'
        : 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1',
      principalId: input.principalId,
      workloadCredentialId: input.credentialId,
      workloadEpoch: '1',
      workloadId: input.workloadId,
      producerTrustDigest: input.producerTrustDigest,
      routingProfileDigest: sha256('not-installed-route-admission-only'),
      kmsInstallationDigest: sha256('not-installed-kms-admission-only'),
      receiptSignerSpki: signer.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
      issuerKeyId: evidenceKeyId(spki),
    };
    const signed = signNotificationClaim('NotificationWorkerProfileV1', privateKey, spki, claims);
    const {
      environmentId,
      participantId,
      privacyDomainId,
      profileId,
      revision,
      serviceId,
      processRole,
      subscriptionId,
      principalId,
      workloadCredentialId,
      workloadEpoch,
      workloadId,
    } = claims;
    return {
      pins: {
        issuerSpkiHex: spki.toString('hex'),
        signedProfileDigest: sha256(signed.cose),
        environmentId,
        participantId,
        privacyDomainId,
        profileId,
        revision,
        serviceId,
        processRole,
        subscriptionId,
        principalId,
        workloadCredentialId,
        workloadEpoch,
        workloadId,
        workloadKeyDigest: evidenceKeyId(input.tlsSpki),
      },
      signed: { payloadHex: signed.payload.toString('hex'), coseHex: signed.cose.toString('hex') },
      installationReference: 'initial-local-notification-worker-trust',
    };
  };
  try {
    const notification = make(),
      control = make(true);
    const original = validateNotificationWorkerInstallation(notification, now);
    await expect(
      scoped(input.runtime, (c) => installInitialNotificationWorker(c, notification)),
    ).rejects.toThrow('Notification worker admission unavailable');
    const installationDigest = await scoped(input.installer, (c) =>
      installInitialNotificationWorker(c, notification),
    );
    expect(
      await scoped(input.installer, (c) => installInitialNotificationWorker(c, notification)),
    ).toBe(installationDigest);
    const selector = {
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      installationDigest,
    };
    expect(await input.call(selector)).toMatchObject({
      status: 200,
      body: {
        serviceId: 'LS-NOTIFICATION',
        processRole: 'ROLE-NOTIFICATION-WORKER',
        installationDigest,
      },
    });
    expect(await input.call({ ...selector, privacyDomainId: id() })).toMatchObject({ status: 403 });
    expect(await input.call({ ...selector, installationDigest: sha256('absent') })).toMatchObject({
      status: 403,
    });
    expect(await input.call({ ...selector, ready: true })).toMatchObject({ status: 403 });
    await expect(input.call(selector, true)).rejects.toThrow(/certificate required/iu);
    const changed = { ...notification, installationReference: 'replace-original' };
    await expect(
      scoped(input.installer, (c) => installInitialNotificationWorker(c, changed)),
    ).rejects.toThrow();
    const invalid = make();
    invalid.pins.workloadKeyDigest = sha256('other-transport');
    await expect(
      scoped(input.installer, (c) => installInitialNotificationWorker(c, invalid)),
    ).rejects.toThrow();
    // Actual direct SQL cannot replace trust, resurrect a withdrawn profile or truncate history.
    await expect(
      scoped(input.installer, (c) =>
        c.query(
          'update control.installed_notification_worker set signed_profile_digest=$1 where installation_digest=$2',
          [sha256('forged'), installationDigest],
        ),
      ),
    ).rejects.toThrow('NOTIFICATION-WORKER-IMMUTABLE');
    await expect(
      scoped(input.installer, (c) => c.query('truncate control.installed_notification_worker')),
    ).rejects.toThrow('NOTIFICATION-WORKER-IMMUTABLE');
    await scoped(input.runtime, async (c) => {
      const retained = await fenceNotificationWorkerInstallation(c, selector);
      expect(retained.bytes.equals(original.bytes)).toBe(true);
      await expect(
        scoped(input.installer, (other) => withdrawNotificationWorker(other, selector)),
      ).rejects.toThrow();
    });
    await input.restart();
    expect(await input.call(selector)).toMatchObject({ status: 200 });
    const controlDigest = await scoped(input.installer, (c) =>
      installInitialNotificationWorker(c, control),
    );
    expect(await input.call({ ...selector, installationDigest: controlDigest })).toMatchObject({
      status: 200,
      body: { serviceId: 'LS-CONTROL-WORK', processRole: 'ROLE-CONTROL-WORKER' },
    });
    await scoped(input.installer, (c) => withdrawNotificationWorker(c, selector));
    await scoped(input.installer, (c) => withdrawNotificationWorker(c, selector));
    expect(await input.call(selector)).toMatchObject({ status: 403 });
    await expect(
      scoped(input.installer, (c) => installInitialNotificationWorker(c, notification)),
    ).rejects.toThrow();
    await expect(
      scoped(input.installer, (c) =>
        c.query(
          "update control.installed_notification_worker set state='ACTIVE' where installation_digest=$1",
          [installationDigest],
        ),
      ),
    ).rejects.toThrow('NOTIFICATION-WORKER-IMMUTABLE');
    const rows = await scoped(input.installer, (c) =>
      c.query<{ installation_bytes: Buffer; state: string }>(
        'select installation_bytes,state from control.installed_notification_worker where installation_digest=$1',
        [installationDigest],
      ),
    );
    expect(rows.rows[0]!.installation_bytes.equals(original.bytes)).toBe(true);
    expect(rows.rows[0]!.state).toBe('REVOKED');
    await scoped(input.installer, (c) =>
      withdrawNotificationWorker(c, { ...selector, installationDigest: controlDigest }),
    );
    process.stdout.write(
      'OPENPC_NOTIFICATION_WORKER|PASS|real-tls-current-identity|immutable-initial-profile|distinct-roles|withdrawal-fence|restart-original|NO-occurrence-or-delivery-authority\n',
    );
  } finally {
    privateKey.fill(0);
  }
}
