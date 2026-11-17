import {
  createPinnedSigningTransport,
  type PinnedSigningTlsConfiguration,
} from './pinned-signing-transport.js';
import {
  identityEnvelopeRotationRequestSchema,
  IdentityEnvelopeRotationUnknown,
  validateIdentityEnvelopeRotationLookup,
  validateIdentityEnvelopeRotationObservation,
  type IdentityEnvelopeRotationProvider,
} from './identity-envelope-rotation-provider.js';

/** AF-25 lifecycle transport only. No grant, trust admission, signing selection or
 * automatic write retry is performed by this adapter. */
export function createHttpIdentityEnvelopeRotationProvider(
  config: PinnedSigningTlsConfiguration & {
    providerOrigin: string;
    providerTlsSpkiDigest: string;
    callerWorkloadKeyDigest: string;
  },
): IdentityEnvelopeRotationProvider {
  const transport = createPinnedSigningTransport(config, config, config.callerWorkloadKeyDigest);
  return {
    close: transport.close,
    async perform(input) {
      try {
        const request = identityEnvelopeRotationRequestSchema.parse(input);
        return validateIdentityEnvelopeRotationObservation(
          request,
          await transport.exchange('/v1/identity-envelope-signing/rotation/perform', request),
        );
      } catch {
        throw new IdentityEnvelopeRotationUnknown();
      }
    },
    async lookup(input, first) {
      try {
        const request = identityEnvelopeRotationRequestSchema.parse(input);
        if (first !== undefined) validateIdentityEnvelopeRotationObservation(request, first);
        return validateIdentityEnvelopeRotationLookup(
          request,
          await transport.exchange('/v1/identity-envelope-signing/rotation/lookup', request),
          first,
        );
      } catch {
        throw new IdentityEnvelopeRotationUnknown();
      }
    },
  };
}
