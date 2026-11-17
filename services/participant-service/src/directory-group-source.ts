import { directoryGroupObservationSchema } from '../../identity-service/src/contracts/directory-group-observation.js';
import type { ParticipantDirectoryGroupSource } from './directory-group-app.js';
import { ParticipantKernelError } from './domain/participant-errors.js';

/** Registered Identity owner only; provider URLs and directory secrets never enter Participant. */
export function createParticipantDirectoryGroupSource(
  identityUrl: string,
  fetchImplementation: typeof fetch = fetch,
): ParticipantDirectoryGroupSource {
  const base = new URL(identityUrl);
  return {
    async observe(actor, privacyDomainId, connectorId, externalId) {
      if (!actor.sessionToken) throw new ParticipantKernelError('PC-AUTH-0002');
      try {
        const response = await fetchImplementation(
          new URL(
            `/v1/identity/directory-connectors/${encodeURIComponent(connectorId)}/groups/${encodeURIComponent(externalId)}/observation`,
            base,
          ),
          {
            headers: {
              'Cookie': `__Host-openpc_session=${actor.sessionToken}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
            },
            signal: AbortSignal.timeout(8000),
            redirect: 'error',
          },
        );
        if (!response.ok || !response.body) throw new Error('Directory observation unavailable');
        const chunks: Uint8Array[] = [];
        let size = 0;
        const reader = response.body.getReader();
        try {
          for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            size += chunk.value.length;
            if (size > 1_048_576) {
              await reader.cancel();
              throw new Error('Directory observation capacity exceeded');
            }
            chunks.push(chunk.value);
          }
        } finally {
          reader.releaseLock();
        }
        const value = directoryGroupObservationSchema.parse(
          JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))),
        );
        if (
          value.participantId !== actor.participantId ||
          value.connectorId !== connectorId ||
          value.source.id !== externalId
        )
          throw new Error('Directory observation binding mismatch');
        return value;
      } catch {
        throw new ParticipantKernelError('PC-AUTH-0002');
      }
    },
  };
}
