import {
  createPinnedSigningTransport,
  type PinnedSigningTlsConfiguration as TlsConfiguration,
} from './pinned-signing-transport.js';
import { X509Certificate } from 'node:crypto';
import {
  validateNotificationCompletionWorkerOriginal,
  validateNotificationCompletionWorkerInstallation,
} from '../../../control-api/src/notifications/completion-worker-installation-contract.js';
import {
  validateNotificationCompletionDispositionSignerInstallation,
  bindNotificationCompletionDispositionSignerWorker,
} from '../../../control-api/src/notifications/completion-disposition-signer.js';
import {
  validateNotificationCompletionDispositionRequest,
  validateNotificationCompletionDispositionObservation,
  validateNotificationCompletionDispositionLookup,
  type NotificationCompletionDispositionProviderTrust,
  type NotificationCompletionDispositionRequest,
} from './notification-completion-disposition-provider.js';
import { immutableJsonCopy } from '../../../control-api/src/privacy-explorer/immutable.js';
import {
  notificationReceiptSigningPurpose,
  notificationCancellationSigningPurpose,
  notificationOutcomeSigningPurpose,
  validateNotificationReceiptSignerInstallation,
} from '../../../control-api/src/notifications/receipt-signer-installation.js';
import { notificationWorkerInstallation } from '../../../control-api/src/notifications/worker-installation-contract.js';
import {
  validateNotificationCancellationReceiptRequest,
  validateNotificationCancellationReceiptObservation,
  validateNotificationCancellationReceiptLookup,
  type NotificationCancellationReceiptRequest,
} from './notification-cancellation-receipt-provider.js';
import {
  validateNotificationOutcomeReceiptRequest,
  validateNotificationOutcomeReceiptObservation,
  validateNotificationOutcomeReceiptLookup,
  type NotificationOutcomeReceiptRequest,
} from './notification-outcome-receipt-provider.js';
import {
  type NotificationReceiptProviderObservation,
  validateNotificationReceiptRequest,
  validateNotificationReceiptObservation,
  validateNotificationReceiptLookup,
  NotificationReceiptProviderUnknown,
  type NotificationReceiptProvider,
  type NotificationReceiptProviderTrust,
} from './notification-receipt-provider.js';

/** Private exact native signer protocol. Strict CA+hostname+SPKI TLS1.3 and a
 * pinned client key. One exchange per call, no redirects/retries. This leaf does
 * not confer the durable committed DISPATCHED admission required for perform. */
type TransportConfiguration = {
  trust: NotificationReceiptProviderTrust;
} & TlsConfiguration;

function createReceiptTransport(
  config: TransportConfiguration,
  purpose:
    | typeof notificationReceiptSigningPurpose
    | typeof notificationCancellationSigningPurpose
    | typeof notificationOutcomeSigningPurpose,
) {
  try {
    const signer = validateNotificationReceiptSignerInstallation(config.trust.signer, purpose);
    const worker = notificationWorkerInstallation.parse(immutableJsonCopy(config.trust.worker));
    const trust = immutableJsonCopy({ signer: signer.pins, worker });
    return {
      trust,
      ...createPinnedTransport(config, signer.pins, worker.pins.workloadKeyDigest),
    };
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}

/** Preserve this adapter's public error family across the shared transport. */
function createPinnedTransport(
  config: TlsConfiguration,
  signer: Readonly<{ providerOrigin: string; providerTlsSpkiDigest: string }>,
  workloadKeyDigest: string,
) {
  try {
    const transport = createPinnedSigningTransport(config, signer, workloadKeyDigest);
    return {
      close: transport.close,
      async exchange(path: string, input: unknown) {
        try {
          return await transport.exchange(path, input);
        } catch {
          throw new NotificationReceiptProviderUnknown();
        }
      },
    };
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}

export function createHttpNotificationReceiptProvider(
  config: TransportConfiguration,
): NotificationReceiptProvider & { close(): void } {
  const { trust, exchange, close } = createReceiptTransport(
    config,
    notificationReceiptSigningPurpose,
  );
  return {
    async perform(value) {
      const { request, claims } = validateNotificationReceiptRequest(value, trust);
      const now = Date.now();
      if (now < claims.startedAtMs || now >= claims.deadlineAtMs)
        throw new NotificationReceiptProviderUnknown();
      return validateNotificationReceiptObservation(
        request,
        await exchange('/v1/notification-receipts/perform', request),
        trust,
      );
    },
    async lookup(original, first) {
      const { request, requestDigest } = validateNotificationReceiptRequest(original, trust);
      if (first !== undefined) validateNotificationReceiptObservation(request, first, trust);
      return validateNotificationReceiptLookup(
        request,
        await exchange('/v1/notification-receipts/lookup', {
          originalRequest: request,
          requestDigest,
        }),
        trust,
        first,
      );
    },
    close,
  };
}

/** Distinct cancellation protocol over the same strict TLS owner. This leaf has
 * no business/dispatch authority; perform still requires its durable owner claim. */
export function createHttpNotificationCancellationReceiptProvider(config: TransportConfiguration) {
  const { trust, exchange, close } = createReceiptTransport(
    config,
    notificationCancellationSigningPurpose,
  );
  return {
    async perform(value: NotificationCancellationReceiptRequest) {
      const bound = validateNotificationCancellationReceiptRequest(value, trust);
      const now = Date.now();
      if (now < bound.notBeforeMs || now >= bound.notAfterMs)
        throw new NotificationReceiptProviderUnknown();
      return validateNotificationCancellationReceiptObservation(
        bound.request,
        await exchange('/v1/notification-cancellation-receipts/perform', bound.request),
        trust,
      );
    },
    async lookup(
      original: NotificationCancellationReceiptRequest,
      first?: NotificationReceiptProviderObservation,
    ) {
      const { request, requestDigest } = validateNotificationCancellationReceiptRequest(
        original,
        trust,
      );
      if (first !== undefined)
        validateNotificationCancellationReceiptObservation(request, first, trust);
      return validateNotificationCancellationReceiptLookup(
        request,
        await exchange('/v1/notification-cancellation-receipts/lookup', {
          originalRequest: request,
          requestDigest,
        }),
        trust,
        first,
      );
    },
    close,
  };
}

/** Distinct outcome protocol over the same strict TLS owner. This leaf has
 * no business/dispatch authority; perform still requires its durable owner claim. */
export function createHttpNotificationOutcomeReceiptProvider(config: TransportConfiguration) {
  const { trust, exchange, close } = createReceiptTransport(
    config,
    notificationOutcomeSigningPurpose,
  );
  return {
    async perform(value: NotificationOutcomeReceiptRequest) {
      const bound = validateNotificationOutcomeReceiptRequest(value, trust);
      const now = Date.now();
      if (now < bound.notBeforeMs || now >= bound.notAfterMs)
        throw new NotificationReceiptProviderUnknown();
      return validateNotificationOutcomeReceiptObservation(
        bound.request,
        await exchange('/v1/notification-outcome-receipts/perform', bound.request),
        trust,
      );
    },
    async lookup(
      original: NotificationOutcomeReceiptRequest,
      first?: NotificationReceiptProviderObservation,
    ) {
      const { request, requestDigest } = validateNotificationOutcomeReceiptRequest(original, trust);
      if (first !== undefined) validateNotificationOutcomeReceiptObservation(request, first, trust);
      return validateNotificationOutcomeReceiptLookup(
        request,
        await exchange('/v1/notification-outcome-receipts/lookup', {
          originalRequest: request,
          requestDigest,
        }),
        trust,
        first,
      );
    },
    close,
  };
}

/** Native TLS leaf only. The durable owner must consume its exclusive committed
 * signing claim before perform; this public trust is never effect admission.
 * Historical request trust is immutable. A separately authenticated current
 * completion-worker successor may look up that original, but may not sign it. */
export function createHttpNotificationCompletionDispositionProvider(
  config: TlsConfiguration & {
    trust: NotificationCompletionDispositionProviderTrust;
    transportWorker: unknown;
  },
) {
  try {
    const signer = validateNotificationCompletionDispositionSignerInstallation(config.trust.signer);
    const originalWorker = validateNotificationCompletionWorkerOriginal(config.trust.worker);
    const transportWorker = validateNotificationCompletionWorkerOriginal(config.transportWorker);
    const trust = immutableJsonCopy({ signer: signer.pins, worker: originalWorker.input });
    const p = transportWorker.profile,
      o = originalWorker.profile;
    if (
      p.environmentId !== o.environmentId ||
      p.participantId !== o.participantId ||
      p.privacyDomainId !== o.privacyDomainId ||
      p.producerTrustDigest !== o.producerTrustDigest ||
      signer.pins.environmentId !== p.environmentId ||
      signer.pins.participantId !== p.participantId ||
      signer.pins.privacyDomainId !== p.privacyDomainId ||
      new Set([
        p.issuerKeyId,
        p.workloadKeyDigest,
        signer.signerKeyId,
        signer.pins.providerTlsSpkiDigest,
      ]).size !== 4 ||
      p.workloadKeyDigest === o.issuerKeyId
    )
      throw new Error();
    const certificate = new X509Certificate(config.certificate);
    const current = () => {
      const now = Date.now();
      validateNotificationCompletionWorkerInstallation(transportWorker.input, now);
      if (now < Date.parse(certificate.validFrom) || now >= Date.parse(certificate.validTo))
        throw new NotificationReceiptProviderUnknown();
      return now;
    };
    current();
    const { exchange, close } = createPinnedTransport(config, signer.pins, p.workloadKeyDigest);
    return {
      async perform(value: NotificationCompletionDispositionRequest) {
        try {
          const bound = validateNotificationCompletionDispositionRequest(value, trust),
            now = current();
          if (
            transportWorker.installationDigest !== bound.worker.installationDigest ||
            now < bound.notBeforeMs ||
            now >= bound.notAfterMs
          )
            throw new Error();
          bindNotificationCompletionDispositionSignerWorker(signer, transportWorker.input, now);
          return validateNotificationCompletionDispositionObservation(
            bound.request,
            await exchange(
              '/v1/notification-completion-disposition-receipts/perform',
              bound.request,
            ),
            trust,
          );
        } catch {
          throw new NotificationReceiptProviderUnknown();
        }
      },
      async lookup(
        original: NotificationCompletionDispositionRequest,
        first?: NotificationReceiptProviderObservation,
      ) {
        try {
          current();
          const { request, requestDigest } = validateNotificationCompletionDispositionRequest(
            original,
            trust,
          );
          if (first !== undefined)
            validateNotificationCompletionDispositionObservation(request, first, trust);
          return validateNotificationCompletionDispositionLookup(
            request,
            await exchange('/v1/notification-completion-disposition-receipts/lookup', {
              originalRequest: request,
              requestDigest,
            }),
            trust,
            first,
          );
        } catch {
          throw new NotificationReceiptProviderUnknown();
        }
      },
      close,
    };
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}
