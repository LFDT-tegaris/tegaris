import {
  createPinnedSigningTransport,
  type PinnedSigningTlsConfiguration,
} from './pinned-signing-transport.js';
import {
  identityEnvelopeProviderRequestSchema,
  IdentityEnvelopeSigningUnknown,
  validateIdentityEnvelopeProviderLookup,
  validateIdentityEnvelopeProviderObservation,
  type IdentityEnvelopeSigningProvider,
} from './identity-envelope-signing-provider.js';

/** Fixed 371 port over the shared pinned transport. The transaction owner must
 * persist DISPATCHED before calling perform and reconcile the original on error. */
export function createHttpIdentityEnvelopeSigningProvider(
  config: PinnedSigningTlsConfiguration & {
    providerOrigin: string;
    providerTlsSpkiDigest: string;
    callerWorkloadKeyDigest: string;
  },
): IdentityEnvelopeSigningProvider {
  const transport = createPinnedSigningTransport(config, config, config.callerWorkloadKeyDigest);
  return {
    close: transport.close,
    async perform(input) {
      try {
        const request = identityEnvelopeProviderRequestSchema.parse(input);
        return validateIdentityEnvelopeProviderObservation(
          request,
          await transport.exchange('/v1/identity-envelope-signing/perform', request),
        );
      } catch {
        throw new IdentityEnvelopeSigningUnknown();
      }
    },
    async lookup(input, first) {
      try {
        const request = identityEnvelopeProviderRequestSchema.parse(input);
        if (first !== undefined) validateIdentityEnvelopeProviderObservation(request, first);
        return validateIdentityEnvelopeProviderLookup(
          request,
          await transport.exchange('/v1/identity-envelope-signing/lookup', request),
          first,
        );
      } catch {
        throw new IdentityEnvelopeSigningUnknown();
      }
    },
  };
}
