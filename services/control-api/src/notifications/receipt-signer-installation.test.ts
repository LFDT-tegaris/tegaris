import type { PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { sha256 } from '../configuration/digest.js';
import type { NotificationWorkerAdmission } from '../../../identity-service/src/domain/notification-worker.js';
import { notificationReceiptProviderSample } from '../../../../tests/integration/identity/notification-receipt-provider-fixture.js';
import {
  validateNotificationReceiptSignerInstallation,
  bindNotificationReceiptSignerWorker,
  assertNotificationReceiptSigner,
  withCurrentNotificationReceiptSigner,
  installInitialNotificationReceiptSigner,
} from './receipt-signer-installation.js';
const sample = notificationReceiptProviderSample({ nowMs: 1800000000000 });
it('retains exact public trust and cryptographically binds the actual delivery subscriber and separate keys', () => {
  const signer = validateNotificationReceiptSignerInstallation(sample.trust.signer);
  expect(signer.digest).toBe(sha256(signer.bytes));
  expect(
    bindNotificationReceiptSignerWorker(signer, sample.trust.worker, sample.claims.startedAtMs)
      .profile,
  ).toEqual(sample.profile);
  const bytes = signer.bytes;
  bytes.fill(0);
  expect(signer.bytes).not.toEqual(bytes);
  expect(signer).not.toHaveProperty('authorized');
  expect(signer).not.toHaveProperty('privateKey');
  expect(() =>
    assertNotificationReceiptSigner(signer, {} as PoolClient, {
      worker: {
        participantId: sample.profile.participantId,
        privacyDomainId: sample.profile.privacyDomainId,
        installationDigest: sample.trust.signer.workerInstallationDigest,
      },
      signerInstallationDigest: signer.digest,
    }),
  ).toThrow('Notification receipt signer unavailable');
});
it('closes installation fields, aliases, key/purpose/owner ambiguity and accessor evaluation', () => {
  const pins = sample.trust.signer;
  for (const patch of [
    { owner: 'LS-EVIDENCE-EXPORT' },
    { purpose: 'pc.cose.control-business-transition.v1' },
    { secretClass: 'SECRET-EVIDENCE-VAULT' },
    { secretVersion: 'v2' },
    { secretReference: 'secret://test-notification/receipt#latest', secretVersion: 'latest' },
    { publicKeySpkiHex: '00'.repeat(91) },
    { publicKeySpkiHex: pins.workerIssuerSpkiHex },
    { keyEpoch: '0' },
    { keyEpoch: '18446744073709551616' },
    { validFromNs: pins.validUntilNs },
    { validUntilNs: '1800000600000000001' },
    { providerOrigin: 'http://localhost' },
    { providerOrigin: 'https://localhost/' },
    { providerOrigin: 'https://user:PRIVATE_CANARY@localhost' },
    { providerOrigin: 'https://localhost?key=PRIVATE_CANARY' },
    { privateKey: 'PRIVATE_CANARY' },
    { ready: true },
    { workloadId: 'worker\n' },
  ])
    expect(() => validateNotificationReceiptSignerInstallation({ ...pins, ...patch })).toThrow(
      'Notification receipt signer unavailable',
    );
  for (const key of Object.keys(pins)) {
    const missing = { ...pins } as Record<string, unknown>;
    delete missing[key];
    expect(() => validateNotificationReceiptSignerInstallation(missing)).toThrow();
  }
  let reads = 0;
  const accessor = Object.defineProperty({ ...pins }, 'privateKey', {
    enumerable: true,
    get() {
      reads++;
      throw new Error('PRIVATE_CANARY');
    },
  });
  expect(() => validateNotificationReceiptSignerInstallation(accessor)).toThrow(
    'Notification receipt signer unavailable',
  );
  expect(reads).toBe(0);
});
it('rejects mismatched original worker, issuer, scope, epoch, reference profile and expiry', () => {
  for (const patch of [
    { workerInstallationDigest: sha256('other') },
    { workerProfileDigest: sha256('other') },
    { workloadEpoch: '2' },
    { privacyDomainId: '01990000-0000-7000-8000-000000000099' },
    { environmentId: 'other' },
    { workloadCredentialId: '01990000-0000-7000-8000-000000000099' },
  ]) {
    const signer = validateNotificationReceiptSignerInstallation({
      ...sample.trust.signer,
      ...patch,
    });
    expect(() =>
      bindNotificationReceiptSignerWorker(signer, sample.trust.worker, sample.claims.startedAtMs),
    ).toThrow();
  }
  const signer = validateNotificationReceiptSignerInstallation(sample.trust.signer);
  expect(() =>
    bindNotificationReceiptSignerWorker(
      signer,
      {
        ...sample.trust.worker,
        pins: {
          ...sample.trust.worker.pins,
          subscriptionId: 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1',
        },
      },
      sample.claims.startedAtMs,
    ),
  ).toThrow();
  expect(() =>
    bindNotificationReceiptSignerWorker(signer, sample.trust.worker, sample.profile.validUntilMs),
  ).toThrow();
  expect(() =>
    bindNotificationReceiptSignerWorker(
      signer,
      sample.trust.worker,
      sample.profile.validFromMs - 1,
    ),
  ).toThrow();
});
it('forged Identity or copied signer metadata grants no query or callback; malformed install performs no SQL', async () => {
  let queries = 0,
    calls = 0;
  const client = {
    query() {
      queries++;
      throw new Error('PRIVATE_CANARY');
    },
  } as unknown as PoolClient;
  const signer = validateNotificationReceiptSignerInstallation(sample.trust.signer),
    worker = {
      participantId: sample.profile.participantId,
      privacyDomainId: sample.profile.privacyDomainId,
      installationDigest: sample.trust.signer.workerInstallationDigest,
    };
  for (const admission of [
    {},
    { installation: { profile: sample.profile }, authorityDigest: sha256('fake') },
  ])
    await expect(
      withCurrentNotificationReceiptSigner(
        client,
        admission as unknown as NotificationWorkerAdmission,
        { worker, signerInstallationDigest: signer.digest },
        async () => {
          calls++;
        },
      ),
    ).rejects.toThrow('Notification receipt signer unavailable');
  await expect(
    installInitialNotificationReceiptSigner(client, { ...sample.trust.signer, ready: true }),
  ).rejects.toThrow('Notification receipt signer unavailable');
  expect(queries).toBe(0);
  expect(calls).toBe(0);
});

it('cancellation requires its own purpose-bound trust and cannot borrow STARTED admission', async () => {
  const {
    notificationCancellationSigningPurpose,
    validateNotificationCancellationSignerInstallation,
  } = await import('./receipt-signer-installation.js');
  const pins = { ...sample.trust.signer, purpose: notificationCancellationSigningPurpose };
  const cancellation = validateNotificationCancellationSignerInstallation(pins);
  const started = validateNotificationReceiptSignerInstallation(sample.trust.signer);
  expect(cancellation.digest).not.toBe(started.digest);
  expect(cancellation.trust.schemaDefinitionDigest).not.toBe(started.trust.schemaDefinitionDigest);
  expect(() => validateNotificationReceiptSignerInstallation(pins)).toThrow();
  expect(() => validateNotificationCancellationSignerInstallation(sample.trust.signer)).toThrow();
  expect(
    bindNotificationReceiptSignerWorker(
      cancellation,
      sample.trust.worker,
      sample.claims.startedAtMs,
    ).profile,
  ).toEqual(sample.profile);
});

it('outcome trust is distinct from both STARTED and cancellation trust', async () => {
  const {
    notificationOutcomeSigningPurpose,
    validateNotificationOutcomeSignerInstallation,
    validateNotificationCancellationSignerInstallation,
  } = await import('./receipt-signer-installation.js');
  const pins = { ...sample.trust.signer, purpose: notificationOutcomeSigningPurpose };
  const outcome = validateNotificationOutcomeSignerInstallation(pins);
  expect(outcome.digest).not.toBe(
    validateNotificationReceiptSignerInstallation(sample.trust.signer).digest,
  );
  expect(() => validateNotificationReceiptSignerInstallation(pins)).toThrow();
  expect(() => validateNotificationCancellationSignerInstallation(pins)).toThrow();
  expect(() => validateNotificationOutcomeSignerInstallation(sample.trust.signer)).toThrow();
});
