import { z } from 'zod';
import { X509Certificate } from 'node:crypto';
import { qualificationDigest } from '../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import {
  createPinnedSigningTransport,
  type PinnedSigningTlsConfiguration,
} from './pinned-signing-transport.js';
import {
  QualificationKeyProviderUnknown,
  qualificationKeyInstallation,
  qualificationKeyRequestDigest,
  validateQualificationKeyRequest,
  validateQualificationKeyObservation,
  qualificationKeyObservationSchema,
  type QualificationKeyInstallation,
  type QualificationKeyProvider,
} from './qualification-key-provider.js';

const lookup = z.discriminatedUnion('state', [
  z.strictObject({
    state: z.literal('ABSENT'),
    attemptId: z.uuidv7(),
    requestDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  }),
  z.strictObject({ state: z.literal('OBSERVED'), observation: qualificationKeyObservationSchema }),
]);

/** Pure transport. The native custody owner must commit dispatch before perform. */
export function createHttpQualificationKeyProvider(
  config: PinnedSigningTlsConfiguration & { trust: QualificationKeyInstallation },
): QualificationKeyProvider {
  try {
    const trust = qualificationKeyInstallation(config.trust).pins;
    const peer = trust.schemaVersion === 2 ? trust.observer : trust.peer;
    if (qualificationDigest(new X509Certificate(config.certificate).raw) !== peer.certificateDigest)
      throw new QualificationKeyProviderUnknown();
    const transport = createPinnedSigningTransport(config, trust, peer.keyDigest);
    return {
      close: transport.close,
      async perform(original) {
        try {
          const request = validateQualificationKeyRequest(original, trust);
          return validateQualificationKeyObservation(
            request,
            await transport.exchange('/v1/qualification-keys/observe', request),
            trust,
          );
        } catch {
          throw new QualificationKeyProviderUnknown();
        }
      },
      async lookup(original, first) {
        try {
          const request = validateQualificationKeyRequest(original, trust);
          const result = lookup.parse(
            await transport.exchange('/v1/qualification-keys/lookup', {
              schemaVersion: request.schemaVersion,
              original: request,
            }),
          );
          if (result.state === 'ABSENT') {
            if (
              result.attemptId !== request.attemptId ||
              result.requestDigest !== qualificationKeyRequestDigest(request) ||
              first
            )
              throw new Error();
            return undefined;
          }
          return validateQualificationKeyObservation(request, result.observation, trust, first);
        } catch {
          throw new QualificationKeyProviderUnknown();
        }
      },
    };
  } catch {
    throw new QualificationKeyProviderUnknown();
  }
}
