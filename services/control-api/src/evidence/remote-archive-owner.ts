import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import { loadProtectedRemoteArchiveSource } from './protected-remote-archive-source.js';
import { vaultObject } from './local-vault.js';
import { evidenceScope, type EvidenceScope } from './segment.js';
import { RemoteArchiveAuthority } from './remote-archive-authority.js';
import {
  archiveProtection,
  archiveKey,
  protectionState,
  remoteArchiveIntent,
  remoteArchiveReceipt,
  remoteArchiveLocator,
  retainUntil,
  retentionMicros,
  RemoteArchiveError,
  type ArchiveAttemptBinding,
  type ArchiveDispatchWindow,
  type ArchiveProtection,
  type RemoteArchiveAttemptOwner,
  type RemoteArchiveIntent,
  type RemoteArchiveProfile,
  type RemoteArchiveReceipt,
} from './remote-archive-contracts.js';

const same = (left: unknown, right: unknown) => canonicalJson(left) === canonicalJson(right);
const attemptBinding = z.strictObject({
  attemptId: z.uuidv7(),
  intent: remoteArchiveIntent,
  intentDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  action: z.enum(['PUT', 'PROTECTION']),
  locator: remoteArchiveLocator.nullable(),
  protection: archiveProtection,
  protectionDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
});
interface AttemptRow {
  binding: ArchiveAttemptBinding;
  state: 'STARTED' | 'AMBIGUOUS' | 'OBSERVED';
  observation: RemoteArchiveReceipt | null;
}

/** Database owner for transport observations. Only a host-configured custody
 * worker may construct it; it is not a public admission API. Its observations
 * deliberately do not satisfy the existing signed receipt/checkpoint gates.
 * The production custody/signing dispatch must be connected before activation. */
export class PostgresRemoteArchiveAttemptOwner implements RemoteArchiveAttemptOwner {
  readonly scope: EvidenceScope;
  readonly profile: RemoteArchiveProfile;

  constructor(
    private readonly pool: Pool,
    scope: EvidenceScope,
    private readonly authority: RemoteArchiveAuthority,
  ) {
    this.scope = evidenceScope.parse(structuredClone(scope));
    this.profile = authority.profile;
    authority.assertScope(this.scope);
  }

  private async begin(client: PoolClient, admit = true) {
    await client.query('begin');
    await client.query('set local synchronous_commit=on');
    await client.query('set local row_security=on');
    await client.query("set local statement_timeout='10s'");
    await client.query("set local idle_in_transaction_session_timeout='10s'");
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true),openpc.assert_request_context(true)",
      [this.scope.participantId, this.scope.privacyDomainId, uuidv7()],
    );
    if (admit) {
      await client.query("select set_config('openpc.archive_profile_digest',$1,true)", [
        this.authority.profileDigest,
      ]);
      return this.authority.admit(client, this.scope);
    }
  }

  private intent(value: RemoteArchiveIntent) {
    const intent = remoteArchiveIntent.parse(structuredClone(value));
    this.authority.assertSourceKind(intent.source.kind);
    if (
      intent.profileDigest !== sha256(this.profile) ||
      intent.source.object.sinkId !== this.profile.sinkId ||
      intent.source.object.participantId !== this.scope.participantId ||
      intent.source.object.privacyDomainId !== this.scope.privacyDomainId ||
      (intent.source.kind === 'SEGMENT' && intent.source.object.streamId !== this.scope.streamId)
    )
      throw new RemoteArchiveError('INVALID');
    return intent;
  }

  private async requireSource(client: PoolClient, intent: RemoteArchiveIntent, initial: boolean) {
    if (intent.source.kind === 'PROTECTED_PROOF') {
      const facts = await this.protectedSource(client, intent);
      if (
        initial &&
        (facts.packet === null ||
          retentionMicros(facts.object.retainUntil) <= retentionMicros(facts.observedAt))
      )
        throw new RemoteArchiveError('INVALID');
      return;
    }
    const source = (
      await client.query(
        `select s.segment_id::text as "segmentId",s.first_sequence::text as "firstSequence",
       s.through_sequence::text as "throughSequence",s.previous_segment_digest as "previousSegmentDigest",
       s.object_digest as "objectDigest",s.key_id as "keyId",
       to_char(s.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "retentionUntil",
       octet_length(p.encrypted_segment) bytes,
       'sha256:'||encode(sha256(p.encrypted_segment),'hex') as "payloadDigest"
       from control.evidence_segment s left join control.evidence_segment_payload p
        using(participant_id,privacy_domain_id,stream_id,segment_id)
       where s.participant_id=$1 and s.privacy_domain_id=$2 and s.stream_id=$3 and s.segment_id=$4`,
        [
          this.scope.participantId,
          this.scope.privacyDomainId,
          this.scope.streamId,
          intent.source.object.segmentId,
        ],
      )
    ).rows[0];
    if (
      !source ||
      !same(
        vaultObject(
          this.profile.sinkId,
          { ...this.scope, ...source, version: 'OPENPC_EVIDENCE_SEGMENT_V1' },
          source.objectDigest,
        ),
        intent.source.object,
      ) ||
      (initial &&
        (source.bytes !== intent.payloadBytes || source.payloadDigest !== intent.payloadDigest))
    )
      throw new RemoteArchiveError('INTEGRITY');
  }

  private async protectedSource(client: PoolClient, intent: RemoteArchiveIntent) {
    if (intent.source.kind !== 'PROTECTED_PROOF') throw new RemoteArchiveError('INVALID');
    const facts = await loadProtectedRemoteArchiveSource(client, {
      participantId: this.scope.participantId,
      privacyDomainId: this.scope.privacyDomainId,
      objectRef: intent.source.object.objectRef,
      sinkId: this.profile.sinkId,
      originalIntentId: intent.intentId,
    });
    if (facts.state !== 'BOUND') throw new RemoteArchiveError('UNAVAILABLE');
    if (
      !same(facts.object, intent.source.object) ||
      facts.lineage.streamId !== this.scope.streamId ||
      facts.payloadBytes !== intent.payloadBytes ||
      facts.object.payloadDigest !== intent.payloadDigest
    )
      throw new RemoteArchiveError('INTEGRITY');
    return facts;
  }

  private async protection(
    client: PoolClient,
    intent: RemoteArchiveIntent,
  ): Promise<ArchiveProtection> {
    const rules =
      intent.source.kind === 'PROTECTED_PROOF'
        ? (await this.protectedSource(client, intent)).rules
        : (
            await client.query(
              `select retention_hold_id::text as "holdId",selector_digest as "selectorDigest",
       creation_operation_id::text as "creationOperationId",release_operation_id::text as "releaseOperationId",
       state,revision::text from control.retention_hold h where participant_id=$1
        and (selector_type='PARTICIPANT' or privacy_domain_id=$2)
        and openpc.evidence_hold_requires_coverage(h,$3,$4) order by retention_hold_id limit 1025`,
              [
                this.scope.participantId,
                this.scope.privacyDomainId,
                this.scope.streamId,
                intent.source.object.segmentId,
              ],
            )
          ).rows;
    if (rules.length > 1024) throw new RemoteArchiveError('UNAVAILABLE');
    const previous = (
      await client.query<{ protection: ArchiveProtection }>(
        `select binding->'protection' protection from control.evidence_remote_archive_attempt
       where participant_id=$1 and privacy_domain_id=$2 and intent_id=$3
       order by (binding->'protection'->>'revision')::numeric desc,attempt_id desc limit 1`,
        [this.scope.participantId, this.scope.privacyDomainId, intent.intentId],
      )
    ).rows[0]?.protection;
    const prior = previous ?? intent.initialProtection;
    return archiveProtection.parse({
      revision: same(rules, prior.rules) ? prior.revision : String(BigInt(prior.revision) + 1n),
      rules,
    });
  }

  /** The shared session-level fence survives STARTED's commit. Always destroy a
   * connection whose unlock failed; a pooled session may never retain this lock. */
  private async fenced<T>(work: (client: PoolClient, alive: () => void) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    const lock = `evidence-lifecycle:${this.scope.participantId}`;
    let failed = false;
    const fail = () => {
      failed = true;
    };
    client.on('error', fail);
    const alive = () => {
      if (failed) throw new RemoteArchiveError('AMBIGUOUS');
    };
    try {
      // A bounded try-lock avoids a session setting leaking into the pool.
      const held = await client.query<{ held: boolean }>(
        'select pg_try_advisory_lock(hashtextextended($1,0)) held',
        [lock],
      );
      if (held.rows[0]?.held !== true) throw new RemoteArchiveError('UNAVAILABLE');
      return await work(client, alive);
    } finally {
      await client.query('rollback').catch(fail);
      await client.query('select pg_advisory_unlock(hashtextextended($1,0))', [lock]).catch(fail);
      client.off('error', fail);
      client.release(failed);
    }
  }

  /** Reload desired protection, never accept a caller's eligibility flags. The
   * later run revalidates this snapshot immediately before dispatch admission. */
  async currentProtection(value: RemoteArchiveIntent) {
    const intent = this.intent(value);
    return this.fenced(async (client) => {
      await this.begin(client);
      await this.requireSource(client, intent, false);
      const result = await this.protection(client, intent);
      await client.query('commit');
      return result;
    });
  }

  /** Historical transport observation only. Do not replay an original PUT to
   * read its old OFF acknowledgement after a later governed hold changed it.
   * This read grants neither current protection nor signed custody/checkpoint. */
  async readObservation(value: RemoteArchiveIntent, attemptId: string) {
    const intent = this.intent(value);
    if (!z.uuidv7().safeParse(attemptId).success) throw new RemoteArchiveError('INVALID');
    return this.fenced(async (client) => {
      await this.begin(client, false);
      const row = (
        await client.query<AttemptRow & { observationDigest: string | null }>(
          `select binding,state,observation,observation_digest as "observationDigest"
         from control.evidence_remote_archive_attempt where participant_id=$1
          and privacy_domain_id=$2 and intent_id=$3 and attempt_id=$4`,
          [this.scope.participantId, this.scope.privacyDomainId, intent.intentId, attemptId],
        )
      ).rows[0];
      if (row && (!same(row.binding.intent, intent) || row.binding.intentDigest !== sha256(intent)))
        throw new RemoteArchiveError('INTEGRITY');
      let observation: RemoteArchiveReceipt | null = null;
      if (row?.state === 'OBSERVED') {
        const parsed = remoteArchiveReceipt.safeParse(row.observation);
        if (!parsed.success || row.observationDigest !== sha256(parsed.data))
          throw new RemoteArchiveError('INTEGRITY');
        observation = parsed.data;
      }
      await client.query('commit');
      return observation;
    });
  }

  async run(
    value: ArchiveAttemptBinding,
    perform: (
      dispatch: 'INITIAL_SEND' | 'RECONCILE',
      window?: ArchiveDispatchWindow,
    ) => Promise<RemoteArchiveReceipt>,
  ): Promise<RemoteArchiveReceipt> {
    return this.fenced((client, alive) => this.runInSession(value, perform, client, alive));
  }

  /** Custody keeps this same session fence through transport, signature and
   * checkpoint commits. Its attempt port reuses the admitted session instead
   * of deadlocking on a second pool connection or releasing the source fence. */
  async withCustody<T>(
    work: (session: {
      client: PoolClient;
      begin: () => Promise<void>;
      alive: () => void;
      attempts: RemoteArchiveAttemptOwner;
    }) => Promise<T>,
  ): Promise<T> {
    return this.fenced((client, alive) =>
      work({
        client,
        alive,
        begin: async () => {
          await this.begin(client);
        },
        attempts: { run: (binding, perform) => this.runInSession(binding, perform, client, alive) },
      }),
    );
  }

  private async runInSession(
    value: ArchiveAttemptBinding,
    perform: (
      dispatch: 'INITIAL_SEND' | 'RECONCILE',
      window?: ArchiveDispatchWindow,
    ) => Promise<RemoteArchiveReceipt>,
    client: PoolClient,
    alive: () => void,
  ): Promise<RemoteArchiveReceipt> {
    const parsed = attemptBinding.safeParse(structuredClone(value));
    if (!parsed.success) throw new RemoteArchiveError('INVALID');
    const binding = parsed.data,
      intent = this.intent(binding.intent);
    if (
      binding.intentDigest !== sha256(intent) ||
      binding.protectionDigest !== sha256(binding.protection)
    )
      throw new RemoteArchiveError('INTEGRITY');
    const keys = [this.scope.participantId, this.scope.privacyDomainId, binding.attemptId];
    const admissionStarted = performance.now();
    const admittedAtMicros = await this.begin(client);
    if (!admittedAtMicros) throw new RemoteArchiveError('INTEGRITY');
    let previous = (
      await client.query<AttemptRow>(
        `select binding,state,observation from control.evidence_remote_archive_attempt
         where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 for update`,
        keys,
      )
    ).rows[0];
    if (previous && !same(previous.binding, binding)) throw new RemoteArchiveError('CONFLICT');
    await this.requireSource(client, intent, !previous && binding.action === 'PUT');
    if (!previous) {
      const current = await this.protection(client, intent);
      if (!same(current, binding.protection)) throw new RemoteArchiveError('CONFLICT');
      if (
        binding.action === 'PUT' &&
        (!same(binding.protection, intent.initialProtection) ||
          binding.protection.revision !== '1' ||
          binding.locator !== null)
      )
        throw new RemoteArchiveError('INVALID');
      // No new external effect while another original attempt is unresolved.
      const unresolved = await client.query(
        `select 1 from control.evidence_remote_archive_attempt where participant_id=$1 and privacy_domain_id=$2
           and intent_id=$3 and state in ('STARTED','AMBIGUOUS')`,
        [this.scope.participantId, this.scope.privacyDomainId, intent.intentId],
      );
      if (unresolved.rowCount) throw new RemoteArchiveError('AMBIGUOUS');
      let original = (
        await client.query<{ intent: RemoteArchiveIntent }>(
          `select intent from control.evidence_remote_archive_intent where participant_id=$1 and privacy_domain_id=$2 and intent_id=$3`,
          [this.scope.participantId, this.scope.privacyDomainId, intent.intentId],
        )
      ).rows[0];
      if (!original) {
        if (binding.action !== 'PUT') throw new RemoteArchiveError('CONFLICT');
        await client.query(
          `insert into control.evidence_remote_archive_intent
           (participant_id,privacy_domain_id,stream_id,intent_id,segment_id,sink_id,profile_digest,intent,intent_digest,profile,source_kind,protected_object_id,protected_object_version,protected_object_digest)
           values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            this.scope.participantId,
            this.scope.privacyDomainId,
            this.scope.streamId,
            intent.intentId,
            intent.source.kind === 'SEGMENT' ? intent.source.object.segmentId : null,
            this.profile.sinkId,
            intent.profileDigest,
            intent,
            binding.intentDigest,
            this.profile,
            intent.source.kind,
            intent.source.kind === 'PROTECTED_PROOF'
              ? intent.source.object.objectRef.slice(-36)
              : null,
            intent.source.kind === 'PROTECTED_PROOF' ? intent.source.object.objectVersion : null,
            intent.source.kind === 'PROTECTED_PROOF' ? intent.source.object.objectDigest : null,
          ],
        );
        original = (
          await client.query<{ intent: RemoteArchiveIntent }>(
            `select intent from control.evidence_remote_archive_intent where participant_id=$1 and privacy_domain_id=$2 and intent_id=$3`,
            [this.scope.participantId, this.scope.privacyDomainId, intent.intentId],
          )
        ).rows[0];
      }
      if (!original || !same(original.intent, intent)) throw new RemoteArchiveError('CONFLICT');
      await client.query(
        `insert into control.evidence_remote_archive_attempt
           (participant_id,privacy_domain_id,intent_id,attempt_id,action,binding,binding_digest,protection_digest,state)
           values($1,$2,$3,$4,$5,$6,$7,$8,'STARTED')`,
        [
          this.scope.participantId,
          this.scope.privacyDomainId,
          intent.intentId,
          binding.attemptId,
          binding.action,
          binding,
          sha256(binding),
          binding.protectionDigest,
        ],
      );
    }
    // A failed/uncertain commit cannot dispatch. A subsequent owner reloads
    // the same attempt and uses RECONCILE, including an absent remote version.
    await client.query('commit');
    alive();
    let observation: RemoteArchiveReceipt;
    try {
      let deadline = BigInt(this.authority.claims.validUntilMs) * 1000n;
      if (!previous && binding.action === 'PUT' && intent.source.kind === 'PROTECTED_PROOF') {
        const proofDeadline = retentionMicros(intent.source.object.retainUntil);
        if (proofDeadline < deadline) deadline = proofDeadline;
      }
      const remainingMs =
        Number((deadline - BigInt(admittedAtMicros)) / 1000n) -
        (performance.now() - admissionStarted);
      if (remainingMs < 1) throw new RemoteArchiveError('UNAVAILABLE');
      const signal = AbortSignal.timeout(Math.min(2147483647, Math.floor(remainingMs)));
      observation = remoteArchiveReceipt.parse(
        await perform(previous ? 'RECONCILE' : 'INITIAL_SEND', {
          signal,
          deadlineMs: admissionStarted + Number((deadline - BigInt(admittedAtMicros)) / 1000n),
        }),
      );
      alive();
      const { receiptDigest, ...receiptBody } = observation;
      if (
        !same(observation.intent, intent) ||
        observation.intentDigest !== binding.intentDigest ||
        !same(observation.protection, binding.protection) ||
        observation.protectionDigest !== binding.protectionDigest ||
        receiptDigest !== sha256(receiptBody) ||
        observation.locator.sinkId !== this.profile.sinkId ||
        observation.locator.profileDigest !== sha256(this.profile) ||
        observation.locator.bucket !== this.profile.bucket ||
        observation.locator.key !== archiveKey(this.profile, intent) ||
        observation.observedLegalHold !== protectionState(binding.protection) ||
        retentionMicros(observation.observedRetention.retainUntil) <
          retentionMicros(retainUntil(intent)) ||
        (intent.source.kind === 'PROTECTED_PROOF' &&
          retentionMicros(observation.observedRetention.retainUntil) !==
            retentionMicros(intent.source.object.retainUntil)) ||
        (binding.locator !== null && !same(observation.locator, binding.locator)) ||
        (previous?.observation && !same(previous.observation, observation))
      )
        throw new RemoteArchiveError('INTEGRITY');
    } catch (error) {
      alive();
      if (previous?.state !== 'OBSERVED') {
        await this.begin(client);
        await client.query(
          `update control.evidence_remote_archive_attempt set state='AMBIGUOUS'
            where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and state in ('STARTED','AMBIGUOUS')`,
          keys,
        );
        await client.query('commit');
      }
      throw error;
    }
    await this.begin(client);
    previous = (
      await client.query<AttemptRow>(
        `select binding,state,observation from control.evidence_remote_archive_attempt
         where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 for update`,
        keys,
      )
    ).rows[0];
    if (!previous || !same(previous.binding, binding)) throw new RemoteArchiveError('INTEGRITY');
    if (previous.state === 'OBSERVED') {
      if (!same(previous.observation, observation)) throw new RemoteArchiveError('INTEGRITY');
    } else {
      await client.query(
        `update control.evidence_remote_archive_attempt
          set state='OBSERVED',observation=$4,observation_digest=$5
          where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        [...keys, observation, sha256(observation)],
      );
    }
    await client.query('commit');
    alive();
    return observation;
  }
}
