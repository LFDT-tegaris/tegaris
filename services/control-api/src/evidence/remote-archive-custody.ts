import type { PoolClient } from 'pg';
import { archiveDigest, evidenceKeyId } from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import { RemoteArchiveAuthority, type SignedArchiveReceipt } from './remote-archive-authority.js';
import { PostgresRemoteArchiveAttemptOwner } from './remote-archive-owner.js';
import { RemoteEvidenceArchive } from './remote-archive.js';
import {
  archiveProtection,
  remoteArchiveReceipt,
  retentionMicros,
  RemoteArchiveError,
  type RemoteArchiveIntent,
} from './remote-archive-contracts.js';
import type { S3ArchiveCredentials } from './remote-archive-s3.js';
import {
  archiveReceiptReference,
  persistArchiveReceipt,
  loadArchiveHistoryReceipt,
  type ArchiveHistoryAttempt,
} from './remote-archive-history.js';
export { archiveReceiptReference, archiveReceiptEvent } from './remote-archive-history.js';
import { inspectSegment } from './segment.js';
import { vaultObject } from './local-vault.js';

const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);

/** The sole segment-to-remote-custody owner. STARTED commits before I/O;
 * signed receipts commit atomically with their outbox before a checkpoint can
 * advance. The session lifecycle fence survives all intervening commits.
 * This attests the tested remote interface, never provider WORM qualification. */
export class RemoteArchiveCustody {
  constructor(
    private readonly owner: PostgresRemoteArchiveAttemptOwner,
    private readonly authority: RemoteArchiveAuthority,
    private readonly credentials: () => Promise<S3ArchiveCredentials>,
  ) {
    authority.assertSourceKind('SEGMENT');
    authority.assertScope(owner.scope);
    if (!same(owner.profile, authority.profile)) throw new RemoteArchiveError('INVALID');
  }

  private values() {
    const s = this.owner.scope;
    return [s.participantId, s.privacyDomainId, s.streamId];
  }

  private async persistReceipt(
    client: PoolClient,
    attempt: ArchiveHistoryAttempt,
    previous: SignedArchiveReceipt | null,
  ) {
    const b = attempt.binding,
      observation = remoteArchiveReceipt.parse(attempt.observation);
    if (
      b.intent.source.kind !== 'SEGMENT' ||
      attempt.state !== 'OBSERVED' ||
      !same(observation.intent, b.intent) ||
      !same(observation.protection, b.protection) ||
      observation.protectionDigest !== b.protectionDigest
    )
      throw new RemoteArchiveError('INTEGRITY');
    const nowMicros = await this.authority.admit(client, this.owner.scope);
    const signed = this.authority.sign({
      ...this.owner.scope,
      environmentId: this.authority.trust.environmentId,
      receiptId: uuidv7(),
      intentId: b.intent.intentId,
      attemptId: b.attemptId,
      signedProfileDigest: this.authority.profileDigest,
      observationDigest: sha256(observation),
      attemptBindingDigest: sha256(b),
      objectDigest: b.intent.source.object.objectDigest,
      locatorDigest: sha256(observation.locator),
      protectionDigest: b.protectionDigest,
      protectionRevision: b.protection.revision,
      retentionUntilMicros: retentionMicros(observation.observedRetention.retainUntil).toString(),
      recordedAtMicros: nowMicros,
      previousReceiptDigest: previous?.receiptDigest ?? null,
      action: b.action,
      signerKeyId: evidenceKeyId(Buffer.from(this.authority.claims.receiptSignerSpki, 'hex')),
      segmentId: b.intent.source.object.segmentId,
      throughSequence: b.intent.source.object.throughSequence,
      assurance: 'REMOTE_INTERFACE_VERIFIED',
      providerQualification: 'NOT_ESTABLISHED',
    });
    await persistArchiveReceipt(client, this.authority, signed);
    return signed;
  }

  async exportNext(signal?: AbortSignal) {
    return this.processNext(false, signal);
  }

  async reconcileHolds(signal?: AbortSignal) {
    return this.processNext(true, signal);
  }

  private async processNext(holdsOnly: boolean, signal?: AbortSignal) {
    return this.owner.withCustody(async ({ client, begin, alive, attempts }) => {
      const archive = new RemoteEvidenceArchive(this.authority.profile, this.credentials, attempts);
      return archive.withinDeadline(async () => {
        await begin();
        const previous = (
          await client.query<{ throughSequence: string; checkpointDigest: string }>(
            `select through_sequence::text as "throughSequence",checkpoint_digest as "checkpointDigest" from control.evidence_checkpoint
         where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and sink_id=$4 order by through_sequence desc limit 1`,
            [...this.values(), this.authority.profile.sinkId],
          )
        ).rows[0];
        const source = (
          await client.query<{
            segmentId: string;
            payload: Buffer | null;
            intent: RemoteArchiveIntent | null;
            rules: unknown;
          }>(
            `select s.segment_id::text as "segmentId",p.encrypted_segment as payload,i.intent,openpc.remote_archive_rules(s) as rules
         from control.evidence_segment s left join control.evidence_segment_payload p using(participant_id,privacy_domain_id,stream_id,segment_id)
         left join control.evidence_remote_archive_intent i on (i.participant_id,i.privacy_domain_id,i.stream_id,i.segment_id)=(s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id) and i.sink_id=$5
         where s.participant_id=$1 and s.privacy_domain_id=$2 and s.stream_id=$3 and
          ((not $6::boolean and s.first_sequence=$4) or ($6::boolean and not openpc.remote_archive_covers(s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id,$5)
           and exists(select 1 from control.evidence_checkpoint c where c.participant_id=s.participant_id and c.privacy_domain_id=s.privacy_domain_id
            and c.stream_id=s.stream_id and c.segment_id=s.segment_id and c.sink_id=$5 and c.receipt->>'kind'='SIGNED_REMOTE_ARCHIVE_V1')))
         order by s.first_sequence limit 1`,
            [
              ...this.values(),
              String(BigInt(previous?.throughSequence ?? '0') + 1n),
              this.authority.profile.sinkId,
              holdsOnly,
            ],
          )
        ).rows[0];
        if (!source) {
          await client.query('commit');
          return null;
        }
        let intent = source.intent;
        if (!intent) {
          if (!source.payload) throw new RemoteArchiveError('UNAVAILABLE');
          const header = inspectSegment(source.payload).header;
          const object = vaultObject(
            this.authority.profile.sinkId,
            header,
            archiveDigest(source.payload),
          );
          intent = {
            intentId: uuidv7(),
            profileDigest: sha256(this.authority.profile),
            source: { kind: 'SEGMENT', object },
            payloadDigest: object.objectDigest,
            payloadBytes: source.payload.length,
            initialProtection: archiveProtection.parse({ revision: '1', rules: source.rules }),
          };
        }
        const rows = (
          await client.query<ArchiveHistoryAttempt>(
            `select binding,state,observation from control.evidence_remote_archive_attempt
        where participant_id=$1 and privacy_domain_id=$2 and intent_id=$3 order by (binding->'protection'->>'revision')::numeric,attempt_id`,
            [this.owner.scope.participantId, this.owner.scope.privacyDomainId, intent.intentId],
          )
        ).rows;
        await client.query('commit');
        let last: SignedArchiveReceipt | null = null;
        if (!rows.length) {
          if (!source.payload) throw new RemoteArchiveError('UNAVAILABLE');
          const attemptId = uuidv7();
          const observation = await archive.withinDeadline(
            () => archive.put(intent!, source.payload!, attemptId),
            signal,
          );
          rows.push({
            state: 'OBSERVED',
            observation,
            binding: {
              attemptId,
              intent,
              intentDigest: sha256(intent),
              action: 'PUT',
              locator: null,
              protection: intent.initialProtection,
              protectionDigest: sha256(intent.initialProtection),
            },
          });
        }
        for (const row of rows) {
          await begin();
          const stored = await loadArchiveHistoryReceipt(
            client,
            this.owner.scope,
            this.authority.trust,
            row,
          );
          await client.query('commit');
          if (stored) {
            if (stored.claims.previousReceiptDigest !== (last?.receiptDigest ?? null))
              throw new RemoteArchiveError('INTEGRITY');
            last = stored;
            continue;
          }
          const b = row.binding;
          const observation = await archive.withinDeadline(async () => {
            if (row.state === 'OBSERVED' && row.observation)
              return archive.verifyExact(intent!, row.observation.locator, b.protection);
            return attempts.run(b, () =>
              b.action === 'PUT'
                ? archive.reconcilePut(intent!, b.protection)
                : archive.verifyExact(intent!, b.locator!, b.protection),
            );
          }, signal);
          if (row.observation && !same(row.observation, observation))
            throw new RemoteArchiveError('INTEGRITY');
          row.observation = observation;
          row.state = 'OBSERVED';
          alive();
          await begin();
          last = await this.persistReceipt(client, row, last);
          await client.query('commit');
        }
        const prior = rows.at(-1)!;
        const wanted = archiveProtection.parse({
          revision: same(source.rules, prior.binding.protection.rules)
            ? prior.binding.protection.revision
            : String(BigInt(prior.binding.protection.revision) + 1n),
          rules: source.rules,
        });
        let final = prior;
        if (!same(wanted, prior.binding.protection)) {
          const attemptId = uuidv7(),
            locator = prior.observation!.locator;
          const observation = await archive.withinDeadline(
            () => archive.reconcileProtection(intent!, locator, wanted, attemptId),
            signal,
          );
          final = {
            state: 'OBSERVED',
            observation,
            binding: {
              attemptId,
              intent,
              intentDigest: sha256(intent),
              action: 'PROTECTION',
              locator,
              protection: wanted,
              protectionDigest: sha256(wanted),
            },
          };
          await begin();
          last = await this.persistReceipt(client, final, last);
          // Receipt and checkpoint below commit together.
        } else {
          await archive.withinDeadline(
            () => archive.verifyExact(intent!, prior.observation!.locator, wanted),
            signal,
          );
          await begin();
        }
        alive();
        if (!last || intent.source.kind !== 'SEGMENT') throw new RemoteArchiveError('INTEGRITY');
        if (holdsOnly) {
          signal?.throwIfAborted();
          await client.query('commit');
          alive();
          return { ...archiveReceiptReference(last), result: 'PROTECTION' as const };
        }
        const checkpoint = {
          ...this.owner.scope,
          sinkId: this.authority.profile.sinkId,
          segmentId: intent.source.object.segmentId,
          throughSequence: intent.source.object.throughSequence,
          objectDigest: intent.source.object.objectDigest,
          previousCheckpointDigest: previous?.checkpointDigest ?? null,
          receiptDigest: last.receiptDigest,
        };
        const checkpointDigest = sha256(checkpoint);
        await client.query(
          `insert into control.evidence_checkpoint(participant_id,privacy_domain_id,stream_id,sink_id,through_sequence,segment_id,
        object_digest,previous_checkpoint_digest,receipt,receipt_digest,checkpoint_digest) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [
            ...this.values(),
            checkpoint.sinkId,
            checkpoint.throughSequence,
            checkpoint.segmentId,
            checkpoint.objectDigest,
            checkpoint.previousCheckpointDigest,
            archiveReceiptReference(last),
            last.receiptDigest,
            checkpointDigest,
          ],
        );
        signal?.throwIfAborted();
        await client.query('commit');
        alive();
        return { ...checkpoint, checkpointDigest, assurance: 'REMOTE_INTERFACE_VERIFIED' as const };
      }, signal);
    });
  }
}
