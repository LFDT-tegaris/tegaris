import { randomBytes } from 'node:crypto';

import type { Pool } from 'pg';

import {
  authorityEvaluationSchema,
  canonicalAuthorizationJson,
  type AuthorityContext,
} from '../contracts/authorization.js';
import {
  FullyScopedPendingDeliveryIdentity,
  type PendingAgeSummary,
  pendingAgeSummarySchema,
  pendingDeliveryAuthorityRequest,
  pendingDeliveryInternalActions,
  type PendingDeliveryReasonCode,
  type PendingDeliveryReceipt,
  pendingDeliveryReceiptSchema,
  type PendingDeliveryState,
  type PendingDeliverySurface,
  SafePendingScope,
} from '../contracts/pending-delivery.js';
import { runScopedTransaction, type ScopedTransactionOperation } from '../db/scoped-transaction.js';
import {
  pendingDeliveryLimits,
  pendingDeliverySql,
  pendingDeliveryUuidV7Schema,
} from '../generated/pending-delivery-projection.js';

const INTEGRATION_ERROR = 'PC-INTEGRATION-5001' as const;
const RUNTIME_ERROR = 'PC-RUNTIME-3001' as const;
type PendingDeliveryPublicCode = typeof INTEGRATION_ERROR | typeof RUNTIME_ERROR;

export interface PendingDeliveryDiagnosticSink {
  record(diagnostic: {
    readonly code: PendingDeliveryPublicCode;
    readonly reason: PendingDeliveryReasonCode;
  }): void;
}

const silentDiagnosticSink: PendingDeliveryDiagnosticSink = { record() {} };

export class PendingDeliveryError extends Error {
  readonly code!: PendingDeliveryPublicCode;

  constructor(code: PendingDeliveryPublicCode) {
    super(code);
    Object.defineProperties(this, {
      code: { value: code, enumerable: false, writable: false, configurable: false },
      stack: { value: undefined, enumerable: false, writable: false, configurable: false },
    });
    Object.freeze(this);
  }
}

function failure(
  code: PendingDeliveryPublicCode,
  reason: PendingDeliveryReasonCode,
  diagnostics: PendingDeliveryDiagnosticSink,
): PendingDeliveryError {
  try {
    diagnostics.record(Object.freeze({ code, reason }));
  } catch {
    // Diagnostics are best-effort and cannot alter the public fail-closed result.
  }
  return new PendingDeliveryError(code);
}

export interface IdentityAuthorityEvaluationExecutor {
  evaluate(request: ReturnType<typeof pendingDeliveryAuthorityRequest>): Promise<unknown>;
}

const rejectingAuthorityEvaluationExecutor: IdentityAuthorityEvaluationExecutor = {
  async evaluate() {
    throw new Error('authority evaluation is unavailable');
  },
};

export type PendingDeliveryTransition =
  | Readonly<{ kind: 'LEASE' }>
  | Readonly<{ kind: 'DELIVER' }>
  | Readonly<{ kind: 'RETRY_WAIT' }>
  | Readonly<{ kind: 'QUARANTINE'; reason: PendingDeliveryReasonCode }>;

export interface PendingDeliveryRepository {
  enqueue(identity: FullyScopedPendingDeliveryIdentity): Promise<PendingDeliveryReceipt>;
  transition(
    identity: FullyScopedPendingDeliveryIdentity,
    transition: PendingDeliveryTransition,
  ): Promise<PendingDeliveryReceipt>;
  summarize(scope: SafePendingScope): Promise<unknown>;
}

const rejectingRepository: PendingDeliveryRepository = {
  async enqueue() {
    throw new Error('pending delivery store is unavailable');
  },
  async transition() {
    throw new Error('pending delivery store is unavailable');
  },
  async summarize() {
    throw new Error('pending delivery store is unavailable');
  },
};

function sameAuthorityContext(left: AuthorityContext, right: AuthorityContext): boolean {
  return canonicalAuthorizationJson(left) === canonicalAuthorizationJson(right);
}

export class PendingDeliveryKernel {
  constructor(
    private readonly repository: PendingDeliveryRepository = rejectingRepository,
    private readonly authority: IdentityAuthorityEvaluationExecutor = rejectingAuthorityEvaluationExecutor,
    private readonly diagnostics: PendingDeliveryDiagnosticSink = silentDiagnosticSink,
  ) {}

  async enqueue(identity: FullyScopedPendingDeliveryIdentity): Promise<PendingDeliveryReceipt> {
    try {
      return await this.repository.enqueue(identity);
    } catch (error) {
      if (error instanceof PendingDeliveryError) throw error;
      throw failure(INTEGRATION_ERROR, 'PENDING_STORE_UNAVAILABLE', this.diagnostics);
    }
  }

  async lease(identity: FullyScopedPendingDeliveryIdentity): Promise<PendingDeliveryReceipt> {
    return this.transition(identity, { kind: 'LEASE' });
  }

  async deliver(identity: FullyScopedPendingDeliveryIdentity): Promise<PendingDeliveryReceipt> {
    return this.transition(identity, { kind: 'DELIVER' });
  }

  async retry(identity: FullyScopedPendingDeliveryIdentity): Promise<PendingDeliveryReceipt> {
    return this.transition(identity, { kind: 'RETRY_WAIT' });
  }

  async quarantine(
    identity: FullyScopedPendingDeliveryIdentity,
    reason: PendingDeliveryReasonCode,
  ): Promise<PendingDeliveryReceipt> {
    return this.transition(identity, { kind: 'QUARANTINE', reason });
  }

  async summary(
    scope: SafePendingScope,
    authorityContext: AuthorityContext,
  ): Promise<PendingAgeSummary> {
    let request: ReturnType<typeof pendingDeliveryAuthorityRequest>;
    try {
      request = pendingDeliveryAuthorityRequest(scope, authorityContext);
      const rawEvaluation = await this.authority.evaluate(request);
      const evaluation = authorityEvaluationSchema.parse(rawEvaluation);
      if (
        evaluation.decision !== 'ALLOW' ||
        !sameAuthorityContext(evaluation.authorityContext, request.authorityContext) ||
        evaluation.authorityContext.participantId !== scope.value.participantId ||
        evaluation.authorityContext.privacyDomainId !== scope.value.privacyDomainId ||
        evaluation.authorityContext.actionIntentId !== pendingDeliveryInternalActions.summary ||
        evaluation.inputsDigest !== request.inputsDigest
      ) {
        throw new Error('authority evaluation did not bind the pending scope');
      }
    } catch {
      throw failure(RUNTIME_ERROR, 'PENDING_SCOPE_INVALID', this.diagnostics);
    }

    try {
      return pendingAgeSummarySchema.parse(await this.repository.summarize(scope));
    } catch {
      throw failure(RUNTIME_ERROR, 'PENDING_STORE_UNAVAILABLE', this.diagnostics);
    }
  }

  private async transition(
    identity: FullyScopedPendingDeliveryIdentity,
    transition: PendingDeliveryTransition,
  ): Promise<PendingDeliveryReceipt> {
    try {
      return await this.repository.transition(identity, transition);
    } catch (error) {
      if (error instanceof PendingDeliveryError) throw error;
      throw failure(INTEGRATION_ERROR, 'PENDING_STATE_CONFLICT', this.diagnostics);
    }
  }
}

interface PendingDeliveryRow {
  pending_delivery_id: string;
  participant_id: string;
  privacy_domain_id: string;
  chain_id: string;
  profile_id: string;
  profile_version: string;
  correlated_log_identity_hmac: Buffer;
  entity_hmac: Buffer;
  entity_scope_digest: Buffer;
  delivery_surface: PendingDeliverySurface;
  protected_delivery_reference_digest: Buffer;
  subscription_reference_digest: Buffer | null;
  session_reference_digest: Buffer | null;
  state: PendingDeliveryState;
}

function uuidV7(): string {
  const bytes = randomBytes(16);
  const timestamp = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number((timestamp >> BigInt((5 - index) * 8)) & 0xffn);
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function receipt(row: PendingDeliveryRow, replay: boolean): PendingDeliveryReceipt {
  return pendingDeliveryReceiptSchema.parse({
    pendingDeliveryId: row.pending_delivery_id,
    state: row.state,
    replay,
  });
}

function identityFromRow(row: PendingDeliveryRow): FullyScopedPendingDeliveryIdentity {
  return FullyScopedPendingDeliveryIdentity.create({
    participantId: `${pendingDeliveryLimits.participantPrefix}${row.participant_id}`,
    privacyDomainId: `${pendingDeliveryLimits.privacyDomainPrefix}${row.privacy_domain_id}`,
    chainId: row.chain_id,
    profileId: row.profile_id,
    profileVersion: row.profile_version,
    correlatedLogIdentityHmac: row.correlated_log_identity_hmac,
    entityHmac: row.entity_hmac,
    entityScopeDigest: row.entity_scope_digest,
    deliverySurface: row.delivery_surface,
    protectedDeliveryReferenceDigest: row.protected_delivery_reference_digest,
    ...(row.subscription_reference_digest === null
      ? {}
      : { subscriptionReferenceDigest: row.subscription_reference_digest }),
    ...(row.session_reference_digest === null
      ? {}
      : { sessionReferenceDigest: row.session_reference_digest }),
  });
}

const pendingDeliverySelect = `select pending_delivery_id,participant_id,privacy_domain_id,
  chain_id::text,profile_id,profile_version,correlated_log_identity_hmac,entity_hmac,
  entity_scope_digest,delivery_surface,protected_delivery_reference_digest,
  subscription_reference_digest,session_reference_digest,state
  from control.pending_delivery`;

export class PostgresPendingDeliveryRepository implements PendingDeliveryRepository {
  constructor(
    private readonly pool: Pool,
    private readonly leaseOwner: string,
    private readonly leaseMilliseconds = 30_000,
    private readonly retryMilliseconds = 5_000,
    private readonly diagnostics: PendingDeliveryDiagnosticSink = silentDiagnosticSink,
  ) {
    if (
      !pendingDeliveryUuidV7Schema.safeParse(leaseOwner).success ||
      !Number.isSafeInteger(leaseMilliseconds) ||
      leaseMilliseconds <= 0 ||
      !Number.isSafeInteger(retryMilliseconds) ||
      retryMilliseconds <= 0
    ) {
      throw failure(INTEGRATION_ERROR, 'PENDING_SCOPE_INVALID', this.diagnostics);
    }
  }

  async enqueue(identity: FullyScopedPendingDeliveryIdentity): Promise<PendingDeliveryReceipt> {
    const value = identity.persistenceSnapshot();
    try {
      return await this.transaction(
        value.participantId,
        value.privacyDomainId,
        pendingDeliveryInternalActions.enqueue,
        async (client) => {
          const inserted = await client.query<PendingDeliveryRow>(
            `insert into control.pending_delivery
            (participant_id,privacy_domain_id,chain_id,profile_id,profile_version,
             correlated_log_identity_hmac,entity_hmac,entity_scope_digest,delivery_surface,
             protected_delivery_reference_digest,subscription_reference_digest,
             session_reference_digest,state)
           values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'PENDING')
           on conflict do nothing
           returning pending_delivery_id,participant_id,privacy_domain_id,chain_id::text,
             profile_id,profile_version,correlated_log_identity_hmac,entity_hmac,
             entity_scope_digest,delivery_surface,protected_delivery_reference_digest,
             subscription_reference_digest,session_reference_digest,state`,
            [
              value.participantId,
              value.privacyDomainId,
              value.chainId,
              value.profileId,
              value.profileVersion,
              value.correlatedLogIdentityHmac,
              value.entityHmac,
              value.entityScopeDigest,
              value.deliverySurface,
              value.protectedDeliveryReferenceDigest,
              value.subscriptionReferenceDigest ?? null,
              value.sessionReferenceDigest ?? null,
            ],
          );
          const created = inserted.rows[0];
          if (created !== undefined) return receipt(created, false);

          const existing = await client.query<PendingDeliveryRow>(
            `${pendingDeliverySelect}
           where participant_id=$1 and privacy_domain_id=$2 and profile_version=$3
             and protected_delivery_reference_digest=$4
           for update`,
            [
              value.participantId,
              value.privacyDomainId,
              value.profileVersion,
              value.protectedDeliveryReferenceDigest,
            ],
          );
          const row = existing.rows[0];
          if (row === undefined || !identity.equals(identityFromRow(row))) {
            throw failure(INTEGRATION_ERROR, 'PENDING_STATE_CONFLICT', this.diagnostics);
          }
          return receipt(row, true);
        },
      );
    } catch (error) {
      if (error instanceof PendingDeliveryError) throw error;
      throw failure(INTEGRATION_ERROR, 'PENDING_STORE_UNAVAILABLE', this.diagnostics);
    }
  }

  async transition(
    identity: FullyScopedPendingDeliveryIdentity,
    transition: PendingDeliveryTransition,
  ): Promise<PendingDeliveryReceipt> {
    const value = identity.persistenceSnapshot();
    try {
      return await this.transaction(
        value.participantId,
        value.privacyDomainId,
        pendingDeliveryInternalActions.transition,
        async (client) => {
          const existing = await client.query<PendingDeliveryRow>(
            `${pendingDeliverySelect}
           where participant_id=$1 and privacy_domain_id=$2 and profile_version=$3
             and protected_delivery_reference_digest=$4
           for update`,
            [
              value.participantId,
              value.privacyDomainId,
              value.profileVersion,
              value.protectedDeliveryReferenceDigest,
            ],
          );
          const row = existing.rows[0];
          if (row === undefined || !identity.equals(identityFromRow(row))) {
            throw failure(INTEGRATION_ERROR, 'PENDING_STATE_CONFLICT', this.diagnostics);
          }

          const baseParameters = [
            row.pending_delivery_id,
            value.participantId,
            value.privacyDomainId,
            value.profileVersion,
          ];
          const [update, parameters] =
            transition.kind === 'LEASE'
              ? [
                  `state='LEASED',lease_owner=$5,lease_expires_at=clock_timestamp()+($6::bigint * interval '1 millisecond')`,
                  [...baseParameters, this.leaseOwner, this.leaseMilliseconds],
                ]
              : transition.kind === 'DELIVER'
                ? [`state='DELIVERED'`, baseParameters]
                : transition.kind === 'RETRY_WAIT'
                  ? [
                      `state='RETRY_WAIT',next_retry_at=clock_timestamp()+($5::bigint * interval '1 millisecond')`,
                      [...baseParameters, this.retryMilliseconds],
                    ]
                  : [`state='QUARANTINED',safe_reason=$5`, [...baseParameters, transition.reason]];
          const updated = await client.query<PendingDeliveryRow>(
            `update control.pending_delivery set ${update}
             where pending_delivery_id=$1 and participant_id=$2 and privacy_domain_id=$3
               and profile_version=$4
             returning pending_delivery_id,participant_id,privacy_domain_id,chain_id::text,
               profile_id,profile_version,correlated_log_identity_hmac,entity_hmac,
               entity_scope_digest,delivery_surface,protected_delivery_reference_digest,
               subscription_reference_digest,session_reference_digest,state`,
            parameters,
          );
          const result = updated.rows[0];
          if (result === undefined) {
            throw failure(INTEGRATION_ERROR, 'PENDING_STATE_CONFLICT', this.diagnostics);
          }
          return receipt(result, false);
        },
      );
    } catch (error) {
      if (error instanceof PendingDeliveryError) throw error;
      throw failure(INTEGRATION_ERROR, 'PENDING_STATE_CONFLICT', this.diagnostics);
    }
  }

  async summarize(scope: SafePendingScope): Promise<unknown> {
    const value = scope.persistenceSnapshot();
    try {
      return await this.transaction(
        value.participantId,
        value.privacyDomainId,
        pendingDeliveryInternalActions.summary,
        async (client) => {
          const result = await client.query<{
            pending_count: string;
            oldest_age: string | null;
            as_of: string;
          }>(
            `with captured as (select clock_timestamp() as as_of), aggregate as (
             select count(*)::numeric as pending_count,min(first_observed_at) as oldest
               from control.pending_delivery
              where participant_id=$1 and privacy_domain_id=$2 and chain_id=$3
                and profile_id collate "C"=$4 collate "C"
                and profile_version collate "C"=$5 collate "C"
                and delivery_surface=$6 and ${pendingDeliverySql.activePredicate}
           )
           select aggregate.pending_count::text as pending_count,
             case when aggregate.pending_count=0 then null
                  else floor(extract(epoch from greatest(interval '0',captured.as_of-aggregate.oldest))*1000)::numeric::text
             end as oldest_age,
             to_char(captured.as_of at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as as_of
             from aggregate cross join captured`,
            [
              value.participantId,
              value.privacyDomainId,
              value.chainId,
              value.profileId,
              value.profileVersion,
              value.deliverySurface,
            ],
          );
          const row = result.rows[0];
          if (row === undefined) throw new Error('summary result missing');
          if (
            BigInt(row.pending_count) > BigInt(pendingDeliveryLimits.uint64Maximum) ||
            (row.oldest_age !== null &&
              (BigInt(row.oldest_age) < 0n ||
                BigInt(row.oldest_age) > BigInt(pendingDeliveryLimits.uint64Maximum)))
          ) {
            throw new Error('summary result outside uint64');
          }
          return pendingAgeSummarySchema.parse({
            pendingCount: row.pending_count,
            oldestPendingAgeMilliseconds: row.oldest_age,
            asOf: row.as_of,
          } satisfies PendingAgeSummary);
        },
      );
    } catch (error) {
      if (error instanceof PendingDeliveryError) throw error;
      throw failure(RUNTIME_ERROR, 'PENDING_STORE_UNAVAILABLE', this.diagnostics);
    }
  }

  private async transaction<T>(
    participantId: string,
    privacyDomainId: string,
    actionIntentId: string,
    operation: ScopedTransactionOperation<T>,
  ): Promise<T> {
    return runScopedTransaction(
      this.pool,
      { participantId, privacyDomainId, actionIntentId },
      uuidV7,
      operation,
    );
  }
}
