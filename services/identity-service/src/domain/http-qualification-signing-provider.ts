import { X509Certificate } from 'node:crypto';
import { qualificationDigest } from '../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import {
  createPinnedSigningTransport,
  type PinnedSigningTlsConfiguration,
} from './pinned-signing-transport.js';
import { type QualificationKeyInstallation } from './qualification-key-provider.js';
import {
  QualificationSigningUnknown,
  qualificationSigningInstallation,
  qualificationSigningRequestDigest,
  validateQualificationSigningRequest,
  validateQualificationSigningObservation,
  validateQualificationSigningLookup,
  type QualificationSigningProvider,
} from './qualification-signing-provider.js';

/** Closed 369/370 transport. Caller must already hold a committed native claim.
 * Only independent B's certificate/key is used; no application retry or fallback. */
export function createHttpQualificationSigningProvider(
  config: PinnedSigningTlsConfiguration & { trust: QualificationKeyInstallation },
): QualificationSigningProvider {
  try {
    const trust = qualificationSigningInstallation(config.trust).pins;
    if (
      qualificationDigest(new X509Certificate(config.certificate).raw) !==
      trust.observer.certificateDigest
    )
      throw new Error();
    const transport = createPinnedSigningTransport(config, trust, trust.observer.keyDigest);
    return {
      close: transport.close,
      async perform(original) {
        try {
          const r = validateQualificationSigningRequest(original, trust),
            now = Date.now();
          if (now < r.issuedAtMs || now >= r.deadlineAtMs) throw new Error();
          return validateQualificationSigningObservation(
            r,
            await transport.exchange('/v1/qualification-signing/perform', r),
            trust,
          );
        } catch {
          throw new QualificationSigningUnknown();
        }
      },
      async lookup(original, first) {
        try {
          const r = validateQualificationSigningRequest(original, trust);
          if (first !== undefined) validateQualificationSigningObservation(r, first, trust);
          return validateQualificationSigningLookup(
            r,
            await transport.exchange('/v1/qualification-signing/lookup', {
              schemaVersion: 1,
              method: 'ORIGINAL_LOOKUP',
              original: r,
              requestDigest: qualificationSigningRequestDigest(r),
            }),
            trust,
            first,
          );
        } catch {
          throw new QualificationSigningUnknown();
        }
      },
    };
  } catch {
    throw new QualificationSigningUnknown();
  }
}
