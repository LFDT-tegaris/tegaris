import { createHash } from 'node:crypto';
import type { TLSSocket } from 'node:tls';
import type { Pool } from 'pg';
import type { IdentityKernel, AuthenticatedWorkloadIdentity } from './identity-kernel.js';
import { withAuthenticatedWorkloadPeer } from './workload-peer.js';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { localOperationId } from './local-operation-id.js';
import {
  collectQualificationDeployment,
  deploymentCopy,
  qualificationDeploymentDigest,
  qualificationDeploymentPeerSchema,
  qualificationDeploymentSelectionSchema,
  qualificationDeploymentIntentSchema,
  type QualificationDeploymentSelection,
  type QualificationDeploymentIntent,
  type CollectedQualificationDeployment,
} from '../../../../scripts/operations/qualification-deployment-observation.mjs';
import {
  reserveQualificationDeployment,
  confirmQualificationDeployment,
  retainQualificationDeployment,
  readQualificationDeployment,
} from '../../../control-api/src/configuration/operations/qualification-deployment-observation.js';

function peer(socket: TLSSocket, identity: AuthenticatedWorkloadIdentity) {
  const raw = socket.getPeerCertificate(true).raw;
  if (
    !raw ||
    socket.destroyed ||
    !socket.authorized ||
    socket.getProtocol() !== 'TLSv1.3' ||
    !socket.remoteAddress ||
    !socket.localAddress
  )
    throw new Error('QUALIFICATION_DEPLOYMENT_PEER_REJECTED');
  return qualificationDeploymentPeerSchema.parse({
    principalId: identity.principalId,
    credentialId: identity.credentialId,
    participantEpoch: identity.participantEpoch,
    principalEpoch: identity.principalEpoch,
    credentialEpoch: identity.workloadEpoch,
    workloadId: identity.workloadId,
    keyDigest: identity.keyId,
    certificateDigest: 'sha256:' + createHash('sha256').update(raw).digest('hex'),
  });
}
/** Compose in the EXISTING privileged host installation root, outside observed
 * containers. ownerPool already has its exact protected role and narrow Identity
 * read/fence grants; this module never changes roles, starts services or injects
 * a native reader. kernel retains its real Identity repository.
 *
 * Observe accepts only installed selection/original intent and a real socket.
 * readOriginal is protected root-local reconciliation, not a public route.
 * OBSERVED is the original native bracket plus Identity check at the stated
 * time; every readback is HISTORICAL_ONLY, never a lease or qualification. */
export function createQualificationDeploymentPeer(options: {
  ownerPool: Pool;
  kernel: IdentityKernel;
}) {
  const historical = <T>(
    s: QualificationDeploymentSelection,
    fn: Parameters<typeof runScopedTransaction<T>>[3],
  ) =>
    runScopedTransaction(
      options.ownerPool,
      {
        participantId: s.participantId,
        privacyDomainId: s.privacyDomainId,
        actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
      },
      localOperationId,
      fn,
    );
  const read = (s: QualificationDeploymentSelection, observationId: string) =>
    historical(s, (c) => readQualificationDeployment(c, s, observationId));
  return Object.freeze({
    readOriginal(selection: QualificationDeploymentSelection, observationId: string) {
      return read(
        deploymentCopy(qualificationDeploymentSelectionSchema.parse(selection)),
        observationId,
      );
    },
    async observe(
      socket: TLSSocket,
      selection: QualificationDeploymentSelection,
      intent: QualificationDeploymentIntent,
    ) {
      const s = deploymentCopy(qualificationDeploymentSelectionSchema.parse(selection)),
        wanted = deploymentCopy(qualificationDeploymentIntentSchema.parse(intent));
      const reserved = await withAuthenticatedWorkloadPeer(
        options.ownerPool,
        options.kernel,
        socket,
        async (c, identity, confirm) => {
          await confirm();
          const result = await reserveQualificationDeployment(c, s, peer(socket, identity), wanted);
          await confirm();
          return result;
        },
        s,
      );
      // Actual scoped COMMIT has returned. An ambiguous reservation commit throws
      // before this point; recovery reads its original ID and cannot collect it.
      if (!reserved.collect) return read(s, wanted.observationId);
      let collected: CollectedQualificationDeployment | null = null;
      let identityRecheckedAtMs: number | null = null;
      try {
        collected = await collectQualificationDeployment(
          reserved.request.pins,
          reserved.request.separatedPins,
          { remoteAddress: socket.remoteAddress!, localAddress: socket.localAddress! },
          {
            observationId: wanted.observationId,
            requestDigest: qualificationDeploymentDigest(reserved.request),
          },
        );
        identityRecheckedAtMs = await withAuthenticatedWorkloadPeer(
          options.ownerPool,
          options.kernel,
          socket,
          async (c, identity, confirm) => {
            await confirm();
            const checked = await confirmQualificationDeployment(
              c,
              s,
              wanted.observationId,
              peer(socket, identity),
            );
            await confirm();
            return checked;
          },
          s,
        );
      } catch {
        // A real native result survives subsequent source/Identity invalidation.
        // Failed/partial inspection has no result and remains UNKNOWN.
      }
      await historical(s, (c) =>
        retainQualificationDeployment(c, s, wanted.observationId, collected, identityRecheckedAtMs),
      );
      return read(s, wanted.observationId);
    },
  });
}
