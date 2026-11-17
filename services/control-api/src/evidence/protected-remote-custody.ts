import type { PoolClient } from 'pg';
import { evidenceKeyId } from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import {
  RemoteArchiveAuthority,
  type SignedProtectedArchiveReceipt,
} from './remote-archive-authority.js';
import { PostgresRemoteArchiveAttemptOwner } from './remote-archive-owner.js';
import { RemoteEvidenceArchive } from './remote-archive.js';
import {
  archiveProtection,
  retentionMicros,
  RemoteArchiveError,
  type RemoteArchiveIntent,
} from './remote-archive-contracts.js';
import {
  loadProtectedRemoteArchiveSource,
  protectedRemoteArchiveIntentBytes,
} from './protected-remote-archive-source.js';
import {
  loadProtectedArchiveHistoryReceipt,
  protectedArchiveReceiptReference,
  persistArchiveReceipt,
  type ArchiveHistoryAttempt,
} from './remote-archive-history.js';
import type { S3ArchiveCredentials } from './remote-archive-s3.js';

const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);

/** Independent protected-copy lifetime; no decryption or source authority reuse.
 * Original attempts reconcile exact remote versions after expiry. Only a fresh
 * signed protected profile and unexpired proof may start the first PUT. */
export class ProtectedRemoteArchiveCustody {
  constructor(
    private readonly owner: PostgresRemoteArchiveAttemptOwner,
    private readonly authority: RemoteArchiveAuthority,
    private readonly credentials: () => Promise<S3ArchiveCredentials>,
  ) {
    authority.assertSourceKind('PROTECTED_PROOF');
    authority.assertScope(owner.scope);
    if (!same(authority.profile, owner.profile)) throw new RemoteArchiveError('INVALID');
  }

  private async persist(
    client: PoolClient,
    attempt: ArchiveHistoryAttempt,
    previous: SignedProtectedArchiveReceipt | null,
  ) {
    const b = attempt.binding,
      observation = attempt.observation;
    if (
      b.intent.source.kind !== 'PROTECTED_PROOF' ||
      attempt.state !== 'OBSERVED' ||
      !observation ||
      !same(observation.intent, b.intent) ||
      !same(observation.protection, b.protection) ||
      observation.protectionDigest !== b.protectionDigest
    )
      throw new RemoteArchiveError('INTEGRITY');
    const object = b.intent.source.object;
    const now = await this.authority.admit(client, this.owner.scope);
    const signed = this.authority.signProtected({
      ...this.owner.scope,
      environmentId: this.authority.trust.environmentId,
      receiptId: uuidv7(),
      intentId: b.intent.intentId,
      attemptId: b.attemptId,
      signedProfileDigest: this.authority.profileDigest,
      observationDigest: sha256(observation),
      attemptBindingDigest: sha256(b),
      objectDigest: object.objectDigest,
      locatorDigest: sha256(observation.locator),
      protectionDigest: b.protectionDigest,
      protectionRevision: b.protection.revision,
      retentionUntilMicros: retentionMicros(observation.observedRetention.retainUntil).toString(),
      recordedAtMicros: now,
      previousReceiptDigest: previous?.receiptDigest ?? null,
      action: b.action,
      signerKeyId: evidenceKeyId(Buffer.from(this.authority.claims.receiptSignerSpki, 'hex')),
      objectId: object.objectRef.slice(-36),
      objectVersion: object.objectVersion,
      payloadDigest: object.payloadDigest,
      sourceDigest: sha256(object.source),
      proofRetainUntilMicros: retentionMicros(object.retainUntil).toString(),
      assurance: 'REMOTE_INTERFACE_VERIFIED',
      providerQualification: 'NOT_ESTABLISHED',
    });
    await persistArchiveReceipt(client, this.authority, signed);
    return signed;
  }

  exportNext(signal?: AbortSignal) {
    return this.process(false, signal);
  }
  reconcileHolds(signal?: AbortSignal) {
    return this.process(true, signal);
  }

  private process(holdsOnly: boolean, signal?: AbortSignal) {
    const scope = this.owner.scope,
      sinkId = this.authority.profile.sinkId;
    return this.owner.withCustody(async ({ client, begin, alive, attempts }) => {
      const archive = new RemoteEvidenceArchive(this.authority.profile, this.credentials, attempts);
      return archive.withinDeadline(async () => {
        await begin();
        const selected = (
          await client.query<{ objectRef: string; intent: RemoteArchiveIntent | null }>(
            `select 'urn:openpc:resource:'||o.object_id::text as "objectRef",i.intent
           from control.protected_proof_object o join control.evidence_catalogue c
            on c.participant_id=o.participant_id and c.privacy_domain_id=o.privacy_domain_id
             and 'urn:openpc:resource:'||c.evidence_id::text=o.source->>'evidenceId'
           left join control.evidence_remote_archive_intent i on i.participant_id=o.participant_id
            and i.privacy_domain_id=o.privacy_domain_id and i.protected_object_id=o.object_id and i.sink_id=$4
           where o.participant_id=$1 and o.privacy_domain_id=$2 and c.stream_id=$3
            and (($5::boolean and i.intent_id is not null and not openpc.protected_remote_archive_covers(o.participant_id,o.privacy_domain_id,o.object_id,$4))
             or (not $5::boolean and (i.intent_id is not null or o.retain_until>clock_timestamp()) and not exists(
              select 1 from control.protected_proof_checkpoint p where p.participant_id=o.participant_id
               and p.privacy_domain_id=o.privacy_domain_id and p.object_id=o.object_id and p.sink_id=$4)))
           order by o.object_id limit 1`,
            [scope.participantId, scope.privacyDomainId, scope.streamId, sinkId, holdsOnly],
          )
        ).rows[0];
        if (!selected) {
          await client.query('commit');
          return null;
        }
        const facts = await loadProtectedRemoteArchiveSource(client, {
          participantId: scope.participantId,
          privacyDomainId: scope.privacyDomainId,
          objectRef: selected.objectRef,
          sinkId,
          ...(selected.intent ? { originalIntentId: selected.intent.intentId } : {}),
        });
        if (facts.state !== 'BOUND' || facts.lineage.streamId !== scope.streamId)
          throw new RemoteArchiveError('INTEGRITY');
        const intent: RemoteArchiveIntent = selected.intent ?? {
          intentId: uuidv7(),
          profileDigest: sha256(this.authority.profile),
          source: { kind: 'PROTECTED_PROOF', object: facts.object },
          payloadDigest: facts.object.payloadDigest,
          payloadBytes: facts.payloadBytes,
          initialProtection: archiveProtection.parse({ revision: '1', rules: facts.rules }),
        };
        if (intent.source.kind !== 'PROTECTED_PROOF' || !same(intent.source.object, facts.object))
          throw new RemoteArchiveError('INTEGRITY');
        const rows = (
          await client.query<ArchiveHistoryAttempt>(
            `select binding,state,observation from control.evidence_remote_archive_attempt where participant_id=$1
           and privacy_domain_id=$2 and intent_id=$3 order by (binding->'protection'->>'revision')::numeric,attempt_id`,
            [scope.participantId, scope.privacyDomainId, intent.intentId],
          )
        ).rows;
        await client.query('commit');
        if (!rows.length) {
          const bytes = protectedRemoteArchiveIntentBytes(facts, intent),
            attemptId = uuidv7();
          const observation = await archive.put(intent, bytes, attemptId);
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
        let last: SignedProtectedArchiveReceipt | null = null;
        for (const row of rows) {
          await begin();
          const stored = await loadProtectedArchiveHistoryReceipt(
            client,
            scope,
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
          const observation =
            row.state === 'OBSERVED' && row.observation
              ? await archive.verifyExact(intent, row.observation.locator, b.protection)
              : await attempts.run(b, (_dispatch, admittedWindow) =>
                  archive.withinDeadline(
                    () =>
                      b.action === 'PUT'
                        ? archive.reconcilePut(intent, b.protection)
                        : archive.verifyExact(intent, b.locator!, b.protection),
                    admittedWindow?.signal,
                    admittedWindow?.deadlineMs,
                  ),
                );
          if (row.observation && !same(row.observation, observation))
            throw new RemoteArchiveError('INTEGRITY');
          row.observation = observation;
          row.state = 'OBSERVED';
          alive();
          await begin();
          last = await this.persist(client, row, last);
          await client.query('commit');
        }
        const prior = rows.at(-1)!;
        const wanted = archiveProtection.parse({
          revision: same(facts.rules, prior.binding.protection.rules)
            ? prior.binding.protection.revision
            : String(BigInt(prior.binding.protection.revision) + 1n),
          rules: facts.rules,
        });
        if (!same(wanted, prior.binding.protection)) {
          const attemptId = uuidv7(),
            locator = prior.observation!.locator;
          const observation = await archive.reconcileProtection(intent, locator, wanted, attemptId);
          await begin();
          last = await this.persist(
            client,
            {
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
            },
            last,
          );
        } else {
          await archive.verifyExact(intent, prior.observation!.locator, wanted);
          await begin();
        }
        alive();
        if (!last) throw new RemoteArchiveError('INTEGRITY');
        if (!holdsOnly) {
          const object = intent.source.object;
          const checkpoint = {
            domain: 'pc.evidence.protected-checkpoint.v1',
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            objectRef: object.objectRef,
            objectVersion: object.objectVersion,
            sinkId,
            payloadDigest: object.payloadDigest,
            receiptDigest: last.receiptDigest,
          };
          await client.query(
            `insert into control.protected_proof_checkpoint(participant_id,privacy_domain_id,object_id,sink_id,payload_digest,ciphertext_bytes,receipt,receipt_digest,checkpoint_digest)
            values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
            [
              scope.participantId,
              scope.privacyDomainId,
              object.objectRef.slice(-36),
              sinkId,
              object.payloadDigest,
              object.ciphertextBytes,
              protectedArchiveReceiptReference(last),
              last.receiptDigest,
              sha256(checkpoint),
            ],
          );
        }
        signal?.throwIfAborted();
        await client.query('commit');
        alive();
        return {
          ...protectedArchiveReceiptReference(last),
          result: holdsOnly ? ('PROTECTION' as const) : ('CHECKPOINT' as const),
        };
      }, signal);
    });
  }
}
