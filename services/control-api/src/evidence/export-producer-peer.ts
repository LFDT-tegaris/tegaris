import type { TLSSocket } from 'node:tls';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { withAuthenticatedWorkloadPeer } from '../../../identity-service/src/domain/workload-peer.js';
import { fenceEvidenceExportProducer } from './export-producer-installation.js';

const request = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  trustDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
});

/** Trusted Identity service composition only: the actual TLS peer must be the
 * installed export producer. The callback still owns source/attempt/key-provider
 * admission; identity plus public trust does not authorize arbitrary signing.
 * No external irreversible effect belongs inside this transaction callback. */
export async function withEvidenceExportProducerPeer<T>(
  identityPool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  input: unknown,
  operation: (
    client: PoolClient,
    producer: Awaited<ReturnType<typeof fenceEvidenceExportProducer>>,
  ) => Promise<T>,
): Promise<T> {
  const scope = request.parse(input);
  return withAuthenticatedWorkloadPeer(
    identityPool,
    kernel,
    socket,
    async (client, peer) => {
      if (peer.participantId !== scope.participantId)
        throw new Error('Evidence export producer peer mismatch');
      const producer = await fenceEvidenceExportProducer(client, scope, scope.trustDigest);
      const pins = producer.pins;
      if (
        peer.principalId !== pins.principalId ||
        peer.credentialId !== pins.workloadCredentialId ||
        peer.workloadId !== pins.workloadId ||
        peer.workloadEpoch !== pins.workloadEpoch
      )
        throw new Error('Evidence export producer peer mismatch');
      const result = await operation(client, producer);
      // Time can expire while the callback runs even though identity and trust
      // rows remain locked. Recheck the exact installed authority before commit.
      const current = await fenceEvidenceExportProducer(client, scope, scope.trustDigest);
      if (current.authorityDigest !== producer.authorityDigest)
        throw new Error('Evidence export producer authority changed');
      return result;
    },
    scope,
  );
}
