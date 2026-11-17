import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import {
  evidenceExportCompletionEnvelope,
  verifyEvidenceExportCompletion,
} from '@openpc/security-kernel';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { canonicalJson } from '../configuration/digest.js';
import { withEvidenceExportProducerPeer } from './export-producer-peer.js';
import { readPreparedEvidenceExportCompletion } from './export-completion.js';
import { readEvidenceExportCompletionSource } from './export-completion-source.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { evidenceScope, digest, EvidenceCustodyError } from './segment.js';
const selector = evidenceScope
  .extend({ trustDigest: digest, evidenceExportId: z.uuidv7() })
  .strict();

/** Publish the retained signed completion exactly once. No new key use, receipt
 * construction, caller-supplied event fields or notification admission occurs. */
export async function publishEvidenceExportCompletion(
  identityPool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const parsed = selector.safeParse(value);
  if (!parsed.success) throw new EvidenceCustodyError('INVALID');
  const { trustDigest, evidenceExportId, ...scope } = parsed.data;
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
        original.state === 'PREPARED' ||
        !original.coseSign1 ||
        original.trustDigest !== trustDigest ||
        !original.authoritySnapshot.equals(producer.authority) ||
        !verifyEvidenceExportCompletion(
          original.claims,
          Buffer.from(producer.pins.publicKeySpkiHex, 'hex'),
          original.coseSign1,
        )
      )
        throw new EvidenceCustodyError('INTEGRITY');
      const source = await readEvidenceExportCompletionSource(client, scope, evidenceExportId);
      if (
        !source.data.equals(original.sourceData) ||
        source.dataDigest !== original.claims.dataDigest
      )
        throw new EvidenceCustodyError('INTEGRITY');
      const envelope = evidenceExportCompletionEnvelope(original.claims);
      if (!original.eventPayload.equals(Buffer.from(canonicalJson(envelope))))
        throw new EvidenceCustodyError('INTEGRITY');
      if (original.state === 'OBSERVED') {
        await client.query(
          `insert into control.outbox_event(participant_id,privacy_domain_id,event_id,event_type,
          aggregate_type,aggregate_id,business_sequence,proof_kind,sequence_namespace,data_schema_uri,source,subject,
          correlation_id,causation_id,payload_cbor,payload_digest,occurred_at)
          values($1,$2,$3,$4,'evidence-export',$5,1,'EVIDENCE_EXPORT_COMPLETION_REFERENCE','EVIDENCE_EXPORT_COMPLETION_V1',
          $6,$7,$8,$9,$10,$11,sha256($11),$12)`,
          [
            scope.participantId,
            scope.privacyDomainId,
            original.claims.eventId,
            envelope.type,
            evidenceExportId,
            envelope.dataschema,
            envelope.source,
            envelope.subject,
            envelope.correlationid,
            envelope.causationid,
            original.sourceData,
            envelope.time,
          ],
        );
        const result = await client.query(
          `update control.evidence_export_completion set state='PUBLISHED'
          where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 and state='OBSERVED'`,
          [scope.participantId, scope.privacyDomainId, original.claims.eventId],
        );
        if (result.rowCount !== 1) throw new EvidenceCustodyError('CONFLICT');
      }
      const checked = await client.query(
        `select openpc.check_evidence_export_completion_event(e)
        from control.outbox_event e where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
        [scope.participantId, scope.privacyDomainId, original.claims.eventId],
      );
      if (checked.rowCount !== 1) throw new EvidenceCustodyError('INTEGRITY');
      const published = await readPreparedEvidenceExportCompletion(client, scope, evidenceExportId);
      if (published?.state !== 'PUBLISHED' || !published.coseSign1?.equals(original.coseSign1))
        throw new EvidenceCustodyError('INTEGRITY');
      return published;
    },
  );
}
