import type { Pool, PoolClient } from 'pg';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import type { VaultObject } from './local-vault.js';
import { RemoteArchiveAuthority } from './remote-archive-authority.js';
import { RemoteArchiveError, type RemoteArchiveIntent } from './remote-archive-contracts.js';
import {
  archiveReceiptReference,
  loadArchiveHistoryReceipt,
  type ArchiveHistoryAttempt,
} from './remote-archive-history.js';
import { PostgresRemoteArchiveAttemptOwner } from './remote-archive-owner.js';
import { RemoteEvidenceArchive } from './remote-archive.js';
import type { S3ArchiveCredentials } from './remote-archive-s3.js';
import { EvidenceCustodyError } from './segment.js';

/** Read-only consumer of committed custody. The approved export transaction
 * owns its lifecycle fence. Historical verification uses the original signing
 * profiles under current workload authority; reading never admits a new attempt
 * or repairs a missing checkpoint. */
export class RemoteArchiveEvidenceReader {
  readonly assurance = 'REMOTE_INTERFACE_VERIFIED' as const;
  readonly sinkId: string;

  constructor(
    private readonly pool: Pool,
    private readonly authority: RemoteArchiveAuthority,
    private readonly credentials: () => Promise<S3ArchiveCredentials>,
  ) {
    this.sinkId = authority.profile.sinkId;
  }

  async read(client: PoolClient, object: VaultObject, checkpointDigest: string) {
    const scope = {
      participantId: object.participantId,
      privacyDomainId: object.privacyDomainId,
      streamId: object.streamId,
    };
    try {
      this.authority.assertSourceKind('SEGMENT');
      this.authority.assertScope(scope);
      await client.query("select set_config('openpc.archive_profile_digest',$1,true)", [
        this.authority.profileDigest,
      ]);
      await this.authority.admit(client, scope);
      const selected = await client.query<{
        intent: RemoteArchiveIntent;
        receipt: unknown;
        receiptDigest: string;
        previousCheckpointDigest: string | null;
        covered: boolean;
      }>(
        `select i.intent,c.receipt,c.receipt_digest as "receiptDigest",
          c.previous_checkpoint_digest as "previousCheckpointDigest",
          openpc.remote_archive_covers(s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id,i.sink_id) covered
         from control.evidence_checkpoint c join control.evidence_segment s
          using(participant_id,privacy_domain_id,stream_id,segment_id,object_digest)
         join control.evidence_remote_archive_intent i
          using(participant_id,privacy_domain_id,stream_id,segment_id,sink_id)
         where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3
          and c.segment_id=$4 and c.sink_id=$5 and c.checkpoint_digest=$6`,
        [
          scope.participantId,
          scope.privacyDomainId,
          scope.streamId,
          object.segmentId,
          this.sinkId,
          checkpointDigest,
        ],
      );
      const row = selected.rows[0];
      if (selected.rowCount !== 1 || !row || !row.covered)
        throw new EvidenceCustodyError('UNAVAILABLE');
      if (
        row.intent.source.kind !== 'SEGMENT' ||
        canonicalJson(row.intent.source.object) !== canonicalJson(object) ||
        row.intent.profileDigest !== sha256(this.authority.profile) ||
        sha256({
          ...scope,
          sinkId: this.sinkId,
          segmentId: object.segmentId,
          throughSequence: object.throughSequence,
          objectDigest: object.objectDigest,
          previousCheckpointDigest: row.previousCheckpointDigest,
          receiptDigest: row.receiptDigest,
        }) !== checkpointDigest
      )
        throw new EvidenceCustodyError('INTEGRITY');
      const attempts = (
        await client.query<ArchiveHistoryAttempt>(
          `select binding,state,observation from control.evidence_remote_archive_attempt
         where participant_id=$1 and privacy_domain_id=$2 and intent_id=$3
         order by (binding->'protection'->>'revision')::numeric,attempt_id`,
          [scope.participantId, scope.privacyDomainId, row.intent.intentId],
        )
      ).rows;
      let previous: string | null = null;
      let checkpointFound = false;
      for (const attempt of attempts) {
        const receipt = await loadArchiveHistoryReceipt(
          client,
          scope,
          this.authority.trust,
          attempt,
        );
        if (
          !receipt ||
          receipt.claims.previousReceiptDigest !== previous ||
          canonicalJson(attempt.binding.intent) !== canonicalJson(row.intent)
        )
          throw new EvidenceCustodyError('INTEGRITY');
        if (receipt.receiptDigest === row.receiptDigest) {
          if (canonicalJson(archiveReceiptReference(receipt)) !== canonicalJson(row.receipt))
            throw new EvidenceCustodyError('INTEGRITY');
          checkpointFound = true;
        }
        previous = receipt.receiptDigest;
      }
      const latest = attempts.at(-1);
      if (!checkpointFound || !latest?.observation) throw new EvidenceCustodyError('INTEGRITY');
      const archive = new RemoteEvidenceArchive(
        this.authority.profile,
        this.credentials,
        new PostgresRemoteArchiveAttemptOwner(this.pool, scope, this.authority),
      );
      return await archive.readVerified(
        row.intent,
        latest.observation.locator,
        latest.binding.protection,
      );
    } catch (error) {
      if (error instanceof RemoteArchiveError)
        throw new EvidenceCustodyError(
          error.code === 'INTEGRITY' || error.code === 'INVALID' ? 'INTEGRITY' : 'UNAVAILABLE',
        );
      throw error;
    }
  }
}
