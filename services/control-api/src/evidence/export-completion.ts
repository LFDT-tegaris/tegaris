import type { TLSSocket } from 'node:tls';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import {
  decodeEvidenceExportCompletion,
  encodeEvidenceExportCompletion,
  encodeEvidenceExportCompletedData,
  evidenceExportCompletionEnvelope,
  type EvidenceExportCompletionClaims,
} from '@openpc/security-kernel';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { withEvidenceExportProducerPeer } from './export-producer-peer.js';
import { readEvidenceExportCompletionSource } from './export-completion-source.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { evidenceScope, digest, EvidenceCustodyError, type EvidenceScope } from './segment.js';

const prepareInput = evidenceScope.extend({
  trustDigest: digest,
  evidenceExportId: z.uuidv7(),
});
interface RetainedCompletion {
  readonly trustDigest: string;
  readonly claims: EvidenceExportCompletionClaims;
  readonly receiptPayload: Buffer;
  readonly receiptPayloadDigest: string;
  readonly authoritySnapshot: Buffer;
  readonly sourceData: Buffer;
  readonly eventPayload: Buffer;
  readonly eventPayloadDigest: string;
  readonly state: 'PREPARED' | 'OBSERVED' | 'PUBLISHED';
  readonly coseSign1: Buffer | null;
}

/** Original preparation readback only. Caller owns current read authorization,
 * scope and transaction. A historical record never grants signing or delivery. */
export async function readPreparedEvidenceExportCompletion(
  client: Pick<PoolClient, 'query'>,
  scopeValue: EvidenceScope,
  exportId: string,
): Promise<RetainedCompletion | undefined> {
  const scope = evidenceScope.parse(scopeValue);
  z.uuidv7().parse(exportId);
  const rows = await client.query<RetainedCompletion>(
    `select trust_digest as "trustDigest",claims,receipt_payload as "receiptPayload",
     receipt_payload_digest as "receiptPayloadDigest",authority_snapshot as "authoritySnapshot",
     source_data as "sourceData",event_payload as "eventPayload",event_payload_digest as "eventPayloadDigest",state,cose_sign1 as "coseSign1"
     from control.evidence_export_completion where participant_id=$1 and privacy_domain_id=$2
     and stream_id=$3 and evidence_export_id=$4`,
    [scope.participantId, scope.privacyDomainId, scope.streamId, exportId],
  );
  if (rows.rowCount === 0) return undefined;
  if (rows.rowCount !== 1) throw new EvidenceCustodyError('INTEGRITY');
  const row = rows.rows[0]!;
  try {
    const claims = decodeEvidenceExportCompletion(row.receiptPayload);
    const data = encodeEvidenceExportCompletedData({
      evidenceExportId: claims.evidenceExportId,
      checkpoint: claims.checkpoint,
      outputDigest: claims.outputDigest,
      recordCount: claims.recordCount,
    });
    if (
      !row.sourceData.equals(data) ||
      sha256(data) !== claims.dataDigest ||
      !['PREPARED', 'OBSERVED', 'PUBLISHED'].includes(row.state) ||
      (row.state === 'PREPARED'
        ? row.coseSign1 !== null
        : !Buffer.isBuffer(row.coseSign1) ||
          row.coseSign1.length < 65 ||
          row.coseSign1.length > 66560) ||
      canonicalJson(claims) !== canonicalJson(row.claims) ||
      claims.participantId !== scope.participantId ||
      claims.privacyDomainId !== scope.privacyDomainId ||
      claims.evidenceExportId !== exportId ||
      claims.signerTrustSnapshotDigest !== row.trustDigest ||
      claims.authoritySnapshotDigest !== sha256(row.authoritySnapshot) ||
      row.receiptPayloadDigest !== sha256(row.receiptPayload) ||
      row.eventPayloadDigest !== sha256(row.eventPayload) ||
      !row.eventPayload.equals(Buffer.from(canonicalJson(evidenceExportCompletionEnvelope(claims))))
    )
      throw new Error();
    return {
      ...row,
      claims,
      receiptPayload: Buffer.from(row.receiptPayload),
      coseSign1: row.coseSign1 === null ? null : Buffer.from(row.coseSign1),
      authoritySnapshot: Buffer.from(row.authoritySnapshot),
      sourceData: Buffer.from(row.sourceData),
      eventPayload: Buffer.from(row.eventPayload),
    };
  } catch {
    throw new EvidenceCustodyError('INTEGRITY');
  }
}

/** One exact signing input per genuinely completed governed export. Authenticate
 * the real TLS producer, retain its current Identity/installation fence and the
 * Evidence lifecycle fence through durable commit. No provider I/O occurs here.
 * PREPARED does not claim signing, event publication or notification acceptance. */
export async function prepareEvidenceExportCompletion(
  identityPool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
): Promise<RetainedCompletion> {
  const input = prepareInput.safeParse(value);
  if (!input.success) throw new EvidenceCustodyError('INVALID');
  const { trustDigest, evidenceExportId, ...scope } = input.data;
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
      const existing = await readPreparedEvidenceExportCompletion(client, scope, evidenceExportId);
      if (existing) {
        if (existing.trustDigest !== trustDigest) throw new EvidenceCustodyError('CONFLICT');
        return existing;
      }
      const { source, data, dataDigest } = await readEvidenceExportCompletionSource(
        client,
        scope,
        evidenceExportId,
      );
      const clock = await client.query<{ ns: string }>(
        'select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text ns',
      );
      const { streamId, ...sourceClaims } = source;
      if (streamId !== scope.streamId) throw new EvidenceCustodyError('INTEGRITY');
      const claims: EvidenceExportCompletionClaims = {
        ...sourceClaims,
        environmentId: producer.pins.environmentId,
        eventId: localOperationId(),
        sourceId: producer.pins.sourceId,
        // There is exactly one terminal completion for this immutable export.
        // This is the distinct EVIDENCE_EXPORT_COMPLETION_V1 aggregate stream.
        sequence: '1',
        recordedAtNs: clock.rows[0]!.ns,
        dataDigest,
        authoritySnapshotDigest: producer.authorityDigest,
        signerTrustSnapshotDigest: producer.digest,
        signerKeyId: producer.signerKeyId,
      };
      const receiptPayload = encodeEvidenceExportCompletion(claims);
      const eventPayload = Buffer.from(canonicalJson(evidenceExportCompletionEnvelope(claims)));
      await client.query(
        `insert into control.evidence_export_completion
         (participant_id,privacy_domain_id,event_id,evidence_export_id,stream_id,trust_digest,
          claims,receipt_payload,receipt_payload_digest,authority_snapshot,event_payload,event_payload_digest,source_data)
         values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          claims.eventId,
          evidenceExportId,
          scope.streamId,
          producer.digest,
          claims,
          receiptPayload,
          sha256(receiptPayload),
          producer.authority,
          eventPayload,
          sha256(eventPayload),
          data,
        ],
      );
      const retained = await readPreparedEvidenceExportCompletion(client, scope, evidenceExportId);
      if (!retained) throw new EvidenceCustodyError('INTEGRITY');
      return retained;
    },
  );
}
