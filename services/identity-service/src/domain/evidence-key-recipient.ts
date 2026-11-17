import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from './identity-kernel.js';
import { withEvidenceExportProducerPeer } from '../../../control-api/src/evidence/export-producer-peer.js';
import { fenceEvidenceKmsInstallation } from '../../../control-api/src/evidence/kms-installation.js';
import {
  EvidenceKmsError,
  evidenceKmsRecipientRequest,
  parseEvidenceKms,
  rejectEvidenceKms,
  type EvidenceKmsRecipientRequest,
} from '../../../control-api/src/evidence/kms-contracts.js';

export interface EvidenceKeyAdmission {
  readonly installation: Awaited<ReturnType<typeof fenceEvidenceKmsInstallation>>;
  readonly authorityDigest: string;
  readonly use: 'ENCRYPT' | 'DECRYPT' | 'READBACK';
}
const active = new WeakMap<object, { client: PoolClient; request: EvidenceKmsRecipientRequest }>();

/** A copied descriptor cannot stand in for the currently executing peer fence. */
export function assertEvidenceKeyAdmission(
  admission: EvidenceKeyAdmission,
  client: PoolClient,
  request: EvidenceKmsRecipientRequest,
): void {
  const entry = active.get(admission);
  if (
    !entry ||
    entry.client !== client ||
    entry.request.participantId !== request.participantId ||
    entry.request.privacyDomainId !== request.privacyDomainId ||
    entry.request.producerTrustDigest !== request.producerTrustDigest ||
    entry.request.installationDigest !== request.installationDigest
  )
    rejectEvidenceKms('SCOPE');
}

/** Database admission and local crypto/ciphertext persistence belong in this
 * callback. Provider/network I/O stays outside it; DEKs must be erased before
 * asynchronous ciphertext persistence. No ongoing lease or provider success is
 * returned by this Identity boundary. Re-enter for dispatch and material use. */
export async function withEvidenceKeyRecipient<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  input: unknown,
  use: 'ENCRYPT' | 'DECRYPT' | 'READBACK',
  operation: (client: PoolClient, admission: EvidenceKeyAdmission) => Promise<T>,
): Promise<T> {
  const request = parseEvidenceKms(evidenceKmsRecipientRequest, input);
  if (use !== 'ENCRYPT' && use !== 'DECRYPT' && use !== 'READBACK') rejectEvidenceKms('INVALID');
  try {
    return await withEvidenceExportProducerPeer(
      pool,
      kernel,
      socket,
      {
        participantId: request.participantId,
        privacyDomainId: request.privacyDomainId,
        trustDigest: request.producerTrustDigest,
      },
      async (client, producer) => {
        const installation = await fenceEvidenceKmsInstallation(client, request, use);
        if (producer.pins.environmentId !== installation.pins.environmentId)
          rejectEvidenceKms('SCOPE');
        Object.freeze(installation.pins.permissions);
        Object.freeze(installation.pins);
        Object.freeze(installation);
        const admission = Object.freeze({
          installation,
          authorityDigest: producer.authorityDigest,
          use,
        });
        active.set(admission, { client, request });
        try {
          const result = await operation(client, admission);
          const current = await fenceEvidenceKmsInstallation(client, request, use);
          if (current.digest !== installation.digest) rejectEvidenceKms('STALE');
          return result;
        } finally {
          active.delete(admission);
        }
      },
    );
  } catch (error) {
    if (error instanceof EvidenceKmsError) throw error;
    throw new EvidenceKmsError('UNAVAILABLE');
  }
}
