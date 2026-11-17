import { it, expect } from 'vitest';
import type { PoolClient } from 'pg';
import {
  completionDispositionFixture,
  completionTestHash,
} from '../../../../tests/integration/identity/notification-completion-disposition-cases.js';
import {
  bindNotificationCompletionDispositionSignerWorker,
  validateNotificationCompletionDispositionSignerInstallation,
  assertNotificationCompletionDispositionSigner,
} from './completion-disposition-signer.js';
it('binds distinct installed signing trust to the signed completion worker', () => {
  const f = completionDispositionFixture();
  expect(
    bindNotificationCompletionDispositionSignerWorker(f.validatedSigner, f.worker.input, 3000)
      .installationDigest,
  ).toBe(f.worker.installationDigest);
  expect(() =>
    bindNotificationCompletionDispositionSignerWorker(f.validatedSigner, f.worker.input, 100000),
  ).toThrow();
  expect(() =>
    assertNotificationCompletionDispositionSigner(f.validatedSigner, {} as PoolClient, {
      worker: {
        participantId: f.worker.profile.participantId,
        privacyDomainId: f.worker.profile.privacyDomainId,
        installationDigest: f.worker.installationDigest,
      },
      signerInstallationDigest: f.validatedSigner.digest,
    }),
  ).toThrow();
});
it.each([
  { owner: 'LS-NOTIFICATION' },
  { purpose: 'pc.cose.notification-delivery-outcome-receipt.v1' },
  { secretVersion: 'v2' },
  { providerOrigin: 'http://completion.test' },
  { providerOrigin: 'https://completion.test/' },
  { validUntilNs: '1000000000' },
  { keyEpoch: '0' },
  { extra: true },
])('rejects malformed or borrowed signer trust %j', (change) => {
  const f = completionDispositionFixture();
  expect(() =>
    validateNotificationCompletionDispositionSignerInstallation({ ...f.signer, ...change }),
  ).toThrow();
});
it('rejects receipt/issuer/provider/workload key reuse and copied worker bindings', () => {
  const f = completionDispositionFixture();
  expect(() =>
    validateNotificationCompletionDispositionSignerInstallation({
      ...f.signer,
      publicKeySpkiHex: f.worker.input.pins.issuerSpkiHex,
    }),
  ).toThrow();
  expect(() =>
    validateNotificationCompletionDispositionSignerInstallation({
      ...f.signer,
      providerTlsSpkiDigest: f.validatedSigner.signerKeyId,
    }),
  ).toThrow();
  const wrong = validateNotificationCompletionDispositionSignerInstallation({
    ...f.signer,
    workerInstallationDigest: completionTestHash(200),
  });
  expect(() =>
    bindNotificationCompletionDispositionSignerWorker(wrong, f.worker.input, 3000),
  ).toThrow();
});
