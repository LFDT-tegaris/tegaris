import type { TLSSocket } from 'node:tls';
import type { Pool } from 'pg';
import { z } from 'zod';
import { verifyEvidenceExportCompletion } from '@openpc/security-kernel';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { withEvidenceExportProducerPeer } from './export-producer-peer.js';
import { readPreparedEvidenceExportCompletion } from './export-completion.js';
import { readEvidenceExportCompletionSource } from './export-completion-source.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { evidenceScope, digest, EvidenceCustodyError } from './segment.js';

const input = evidenceScope
  .extend({
    trustDigest: digest,
    evidenceExportId: z.uuidv7(),
    coseHex: z
      .string()
      .min(130)
      .max(133120)
      .regex(/^(?:[0-9a-f]{2})+$/u),
  })
  .strict();

/** Accept the installed producer's original signing result, not caller-selected
 * claims or keys. The external signer must retain its original result across
 * ambiguous replies. This owner never dispatches/repeats signing or publishes an
 * event; it records verified observation under current Identity/source fences. */
export async function observeEvidenceExportCompletion(
  identityPool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const parsed = input.safeParse(value);
  if (!parsed.success) throw new EvidenceCustodyError('INVALID');
  const { trustDigest, evidenceExportId, coseHex, ...scope } = parsed.data;
  const cose = Buffer.from(coseHex, 'hex');
  return withEvidenceExportProducerPeer(
    identityPool,
    kernel,
    socket,
    { participantId: scope.participantId, privacyDomainId: scope.privacyDomainId, trustDigest },
    async (client, producer) => {
      await client.query(
        "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
      );
      await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
      const original = await readPreparedEvidenceExportCompletion(client, scope, evidenceExportId);
      if (
        !original ||
        original.trustDigest !== trustDigest ||
        !original.authoritySnapshot.equals(producer.authority) ||
        !verifyEvidenceExportCompletion(
          original.claims,
          Buffer.from(producer.pins.publicKeySpkiHex, 'hex'),
          cose,
        )
      )
        throw new EvidenceCustodyError('INTEGRITY');
      const source = await readEvidenceExportCompletionSource(client, scope, evidenceExportId);
      if (
        !original.sourceData.equals(source.data) ||
        original.claims.dataDigest !== source.dataDigest
      )
        throw new EvidenceCustodyError('INTEGRITY');
      if (original.state !== 'PREPARED') {
        if (!original.coseSign1?.equals(cose)) throw new EvidenceCustodyError('CONFLICT');
        return original;
      }
      const updated = await client.query(
        `update control.evidence_export_completion set state='OBSERVED',cose_sign1=$5
         where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and evidence_export_id=$4 and state='PREPARED'`,
        [scope.participantId, scope.privacyDomainId, scope.streamId, evidenceExportId, cose],
      );
      if (updated.rowCount !== 1) throw new EvidenceCustodyError('CONFLICT');
      const observed = await readPreparedEvidenceExportCompletion(client, scope, evidenceExportId);
      if (observed?.state !== 'OBSERVED' || !observed.coseSign1?.equals(cose))
        throw new EvidenceCustodyError('INTEGRITY');
      return observed;
    },
  );
}
