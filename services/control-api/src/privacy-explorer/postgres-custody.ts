import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import {
  assertPrivacyExplorerEvidence,
  type PrivacyExplorerEvidenceDigestRecordV1,
} from '../contracts/privacy-explorer-adapter.js';
import { sha256CanonicalJson } from './canonical.js';
import type { PrivacyExplorerEvidenceSink } from './evidence-sink.js';
import type { ExecutionPersistence } from './execution-persistence.js';
import { requireExecutionSnapshot, type ExecutionSnapshot } from './execution-repository.js';
import {
  governedBoundaryRegistrationId,
  requireGovernedProjectionBoundary,
  type GovernedProjectionBoundary,
} from './request.js';

export type ExplorerCustodyScope = Readonly<{
  participantId: string;
  privacyDomainId: string;
  subject: string;
  actionIntentId: string;
}>;

const unavailable = () => new Error('Privacy Explorer execution unavailable');

/** Scope is supplied by the authenticated owner, never by an HTTP persistence envelope. */
export class PostgresExplorerCustody implements ExecutionPersistence {
  private readonly ownerId = randomUUID();
  constructor(
    private readonly pool: Pool,
    private readonly scope: ExplorerCustodyScope,
  ) {}

  async transaction<T>(
    work: (client: PoolClient, commit: () => Promise<void>) => Promise<T>,
  ): Promise<T> {
    const client = await this.pool.connect();
    let committed = false;
    const commit = async () => {
      if (committed) throw unavailable();
      await client.query('commit');
      committed = true;
    };
    try {
      await client.query('begin isolation level read committed');
      await client.query(
        "set local row_security=on; set local lock_timeout='3s'; set local statement_timeout='5s'; set local idle_in_transaction_session_timeout='10s'",
      );
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
        [this.scope.participantId, this.scope.privacyDomainId, uuidv7(), this.scope.actionIntentId],
      );
      const result = await work(client, commit);
      if (!committed) await commit();
      return result;
    } catch (error) {
      if (!committed) await client.query('rollback').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  private admit(boundary: GovernedProjectionBoundary, snapshot?: ExecutionSnapshot) {
    const admitted = requireGovernedProjectionBoundary(boundary);
    if (
      admitted.request.scope.participantId !== this.scope.participantId ||
      admitted.request.scope.privacyDomainId !== this.scope.privacyDomainId ||
      admitted.request.subject !== this.scope.subject
    )
      throw unavailable();
    if (snapshot) {
      requireExecutionSnapshot(snapshot);
      if (
        snapshot.occurrenceId !== admitted.context.occurrenceId ||
        snapshot.requestDigest !== admitted.requestDigest ||
        snapshot.profileDigest !== admitted.request.exportProfile.digest ||
        snapshot.queryDigest !== admitted.request.queryDigest
      )
        throw unavailable();
    }
    return sha256CanonicalJson(admitted);
  }

  async create(boundary: GovernedProjectionBoundary, initial: ExecutionSnapshot) {
    const boundaryDigest = this.admit(boundary, initial);
    if (initial.revision !== 0) throw unavailable();
    await this.transaction(async (client) => {
      const created = await client.query(
        `insert into control.privacy_explorer_execution
         (occurrence_id,participant_id,privacy_domain_id,subject,owner_id,registration_id,boundary_digest,
          scope_digest,authorization_digest,snapshot,revision,deadline_at)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,0,$11::timestamptz
         where $11::timestamptz>clock_timestamp()
         on conflict (occurrence_id) do nothing returning occurrence_id`,
        [
          initial.occurrenceId,
          this.scope.participantId,
          this.scope.privacyDomainId,
          this.scope.subject,
          this.ownerId,
          governedBoundaryRegistrationId(boundary),
          boundaryDigest,
          boundary.context.scopeDigest,
          boundary.context.authorizationDigest,
          JSON.stringify(initial),
          boundary.context.deadlineAt,
        ],
      );
      // Exact retries use authorized status readback, never replay of protected bytes.
      if (created.rowCount !== 1) throw unavailable();
    });
  }

  async transition(
    boundary: GovernedProjectionBoundary,
    previous: ExecutionSnapshot,
    next: ExecutionSnapshot,
    evidence?: PrivacyExplorerEvidenceDigestRecordV1,
  ) {
    const boundaryDigest = this.admit(boundary, previous);
    this.admit(boundary, next);
    if (next.revision !== previous.revision + 1 || next.revision > 128) throw unavailable();
    const record = evidence ? assertPrivacyExplorerEvidence(evidence) : undefined;
    if (
      (next.state === 'EVIDENCE_SEALED') !== !!record ||
      (record &&
        (record.occurrenceId !== next.occurrenceId ||
          record.resultDigest !== next.resultDigest ||
          record.requestDigest !== next.requestDigest ||
          record.scopeDigest !== boundary.context.scopeDigest ||
          record.authorizationDigest !== boundary.context.authorizationDigest))
    )
      throw unavailable();
    await this.transaction(async (client) => {
      const changed = await client.query(
        `update control.privacy_explorer_execution set snapshot=$1::jsonb,revision=$2,
          evidence=$3::jsonb,evidence_digest=$4,
          disposition=case when $5 then 'SUPPRESSED' else disposition end,updated_at=clock_timestamp()
         where occurrence_id=$6 and participant_id=$7 and privacy_domain_id=$8 and subject=$9
           and owner_id=$10 and boundary_digest=$11 and revision=$12 and snapshot=$13::jsonb
           and disposition='OPEN' returning occurrence_id`,
        [
          JSON.stringify(next),
          next.revision,
          record ? JSON.stringify(record) : null,
          record ? sha256CanonicalJson(record) : null,
          !!record && next.delivery === 'SUPPRESSED',
          next.occurrenceId,
          this.scope.participantId,
          this.scope.privacyDomainId,
          this.scope.subject,
          this.ownerId,
          boundaryDigest,
          previous.revision,
          JSON.stringify(previous),
        ],
      );
      if (changed.rowCount !== 1) throw unavailable();
    });
  }

  evidenceSink(): PrivacyExplorerEvidenceSink {
    return Object.freeze({
      append: async (value: PrivacyExplorerEvidenceDigestRecordV1) => {
        const record = assertPrivacyExplorerEvidence(value);
        const recordDigest = sha256CanonicalJson(record);
        await this.transaction(async (client) => {
          const row = await client.query(
            `select 1 from control.privacy_explorer_execution where occurrence_id=$1
             and participant_id=$2 and privacy_domain_id=$3 and subject=$4 and owner_id=$5
             and scope_digest=$6 and evidence_digest=$7 and evidence=$8::jsonb
             and snapshot->>'state'='EVIDENCE_SEALED'`,
            [
              record.occurrenceId,
              this.scope.participantId,
              this.scope.privacyDomainId,
              this.scope.subject,
              this.ownerId,
              record.scopeDigest,
              recordDigest,
              JSON.stringify(record),
            ],
          );
          if (row.rowCount !== 1) throw unavailable();
        });
        return {
          outcome: 'ACCEPTED',
          occurrenceId: record.occurrenceId,
          scopeDigest: record.scopeDigest,
          resultDigest: record.resultDigest,
          recordDigest,
        };
      },
    });
  }

  /** Called inside the live authority/profile/policy/Fact fence, immediately before COMMIT.
   * Kernel RELEASED means the buffer is ready; only this durable claim authorizes HTTP delivery.
   */
  async claim(
    client: PoolClient,
    boundary: GovernedProjectionBoundary,
    evidence: PrivacyExplorerEvidenceDigestRecordV1,
  ) {
    const boundaryDigest = this.admit(boundary);
    const record = assertPrivacyExplorerEvidence(evidence);
    const claimId = randomUUID();
    const claimed = await client.query(
      `update control.privacy_explorer_execution set disposition='RELEASE_AUTHORIZED',
       release_claim_id=$1,release_authorized_at=clock_timestamp(),updated_at=clock_timestamp()
       where occurrence_id=$2 and participant_id=$3 and privacy_domain_id=$4 and subject=$5
         and owner_id=$6 and boundary_digest=$7 and evidence_digest=$8 and evidence=$9::jsonb
         and disposition='OPEN' and release_claim_id is null and deadline_at>clock_timestamp()
         and snapshot->>'state'='EVIDENCE_SEALED' and snapshot->>'delivery'='RELEASED'
         and snapshot->>'rawState' in ('NEVER_CREATED','DISPOSED') returning release_claim_id`,
      [
        claimId,
        boundary.context.occurrenceId,
        this.scope.participantId,
        this.scope.privacyDomainId,
        this.scope.subject,
        this.ownerId,
        boundaryDigest,
        sha256CanonicalJson(record),
        JSON.stringify(record),
      ],
    );
    if (claimed.rowCount !== 1) throw unavailable();
    return claimId;
  }

  /** A process crash is never permission to resume a buffer or claim an old occurrence. */
  async interrupt(occurrenceId: string) {
    await this.transaction(async (client) => {
      await client.query(
        `update control.privacy_explorer_execution set disposition='INTERRUPTED',updated_at=clock_timestamp()
         where occurrence_id=$1 and participant_id=$2 and privacy_domain_id=$3 and subject=$4
           and owner_id=$5 and disposition='OPEN'`,
        [
          occurrenceId,
          this.scope.participantId,
          this.scope.privacyDomainId,
          this.scope.subject,
          this.ownerId,
        ],
      );
    });
  }
}
