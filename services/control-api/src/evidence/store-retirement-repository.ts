import type { Pool } from 'pg';
import type { PoolClient } from 'pg';
import { readFactProvenance } from './fact-provenance.js';
import { readFactRetirementSelection } from './store-retirement-selection.js';
import { readCandidateRetirementSelection } from './candidate-archive/retirement-selection.js';
import {
  parseRetirementWire,
  retirementHost,
  retirementSelection,
  retirementWireBytes,
  retirementWireDigest,
} from './store-retirement-wire.js';
import { z } from 'zod';
import { AtomicConfigurationMutation } from '../configuration/persistence/atomic-mutation.js';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../configuration/persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import type { ResourceApiOptions } from '../configuration/governed-mutation-http.js';
import {
  bindStoreRetirementAdmission,
  readStoreRetirementAdmissionState,
} from './store-retirement-business-state.js';
import {
  admitStoreRetirement,
  storeRetirementPlanInput,
  storeRetirementPlan,
  storeRetirementSourceBinding,
  factRetirementPlanInput,
  factRetirementHosts,
  candidateRetirementHosts,
  candidateRetirementPlanInput,
  storeRetirementView,
} from './store-retirement-contracts.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';

export { storeRetirementView } from './store-retirement-contracts.js';

/** Only the source-binding function's declared eligibility failures are public
 * precondition denials. Preserve unexpected SQL/permission failures for the
 * ordinary error boundary; never expose its internal diagnostic suffix. */
export function retirementSourceFailure(error: unknown): never {
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error.code === 'P0002' ||
      (error.code === 'P0001' &&
        'message' in error &&
        typeof error.message === 'string' &&
        /^PC-DATA-6007(?:-(?:UNSUPPORTED-SOURCE|SOURCE|ACTIVE-HOLD|CHECKPOINT|SINK-QUORUM|RETENTION))?$/u.test(
          error.message,
        )))
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  throw error;
}

export class StoreRetirementRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(
    pool: Pool,
    private readonly options: Pick<
      ResourceApiOptions,
      'identityRuntimeVerifier' | 'businessEvidence' | 'storeRetirementAdmissions'
    >,
  ) {
    this.mutations = new AtomicConfigurationMutation(
      pool,
      options.identityRuntimeVerifier,
      options.businessEvidence,
    );
    this.reads = new ScopedConfigurationRead(pool);
  }
  private async factSource(client: PoolClient, context: ReadContext) {
    const participantId = context.authorization.participantId,
      privacyDomainId = context.authorization.privacyDomainId;
    const selected = await client.query<{
      recordId: string;
      recordDigest: string;
      occurredAt: string;
      sequence: string;
      streamId: string;
    }>(
      `select record_id as "recordId",receipt_digest as "recordDigest",sequence::text,stream_id as "streamId",
      to_char(occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt"
      from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and evidence_id=$3
      and source_format='OPENPC_CANONICAL_FACT_V1' and evidence_class='EFFECT'`,
      [participantId, privacyDomainId, context.resourceId],
    );
    const record = selected.rows[0];
    if (selected.rowCount !== 1 || !record) throw new ConfigurationRepositoryError('PC-DATA-6004');
    const projection = await readFactProvenance(client, {
      ...record,
      participantId,
      privacyDomainId,
    });
    if (!projection) throw new ConfigurationRepositoryError('PC-DATA-6007');
    return {
      participantId,
      privacyDomainId,
      candidateId: projection.candidateId,
      signedFactDigest: record.recordDigest.slice(7),
    };
  }
  factHosts(context: ReadContext) {
    return this.hosts(context, 'openpc_facts').then((value) => factRetirementHosts.parse(value));
  }
  candidateHosts(context: ReadContext) {
    return this.hosts(context, 'openpc_candidate_index').then((value) =>
      candidateRetirementHosts.parse(value),
    );
  }
  private hosts(context: ReadContext, store: 'openpc_facts' | 'openpc_candidate_index') {
    return this.reads.execute({ ...context, resourceId: '*' }, async (client) => {
      if (store === 'openpc_facts') await this.factSource(client, context);
      else await readCandidateRetirementSelection(client, context);
      const selected = await client.query<{ host_digest: string; host_wire: Buffer }>(
        `select host_digest,host_wire from control.store_retirement_host where participant_id=$1 and privacy_domain_id=$2
        and valid_from_ms<=floor(extract(epoch from clock_timestamp())*1000) and valid_until_ms>floor(extract(epoch from clock_timestamp())*1000)
        order by host_digest limit 257`,
        [context.authorization.participantId, context.authorization.privacyDomainId],
      );
      if (selected.rows.length > 256) throw new ConfigurationRepositoryError('PC-DATA-6007');
      const items = selected.rows.flatMap((row) => {
        if (!this.options.storeRetirementAdmissions?.has(row.host_digest)) return [];
        const host = retirementHost.parse(parseRetirementWire(row.host_wire));
        if (
          retirementWireDigest(host) !== row.host_digest ||
          host.scope.participant_id !== context.authorization.participantId ||
          host.scope.privacy_domain_id !== context.authorization.privacyDomainId
        )
          throw new ConfigurationRepositoryError('PC-DATA-6007');
        return host.store === store
          ? [{ hostDigest: row.host_digest, targetId: host.target_id, store: host.store }]
          : [];
      });
      return { items, authority: 'NONE' as const };
    });
  }
  async factPlan(context: ReadContext, input: z.infer<typeof factRetirementPlanInput>) {
    const source = await this.reads.execute({ ...context, resourceId: '*' }, (client) =>
      this.factSource(client, context),
    );
    const selection = await readFactRetirementSelection(source);
    return this.plan(context, {
      ...input,
      selectionWireHex: retirementWireBytes(selection).toString('hex'),
      recordRefs: [{ candidateId: source.candidateId, evidenceId: context.resourceId }],
    });
  }
  async candidatePlan(context: ReadContext, input: z.infer<typeof candidateRetirementPlanInput>) {
    const selection = await this.reads.execute({ ...context, resourceId: '*' }, (client) =>
      readCandidateRetirementSelection(client, context),
    );
    return this.plan(context, {
      ...input,
      selectionWireHex: retirementWireBytes(selection).toString('hex'),
      recordRefs: [
        { candidateId: selection.rows[0]!.candidate_id, evidenceId: context.resourceId },
      ],
    });
  }
  plan(context: ReadContext, input: z.infer<typeof storeRetirementPlanInput>) {
    if (context.resourceId !== input.recordRefs[0]?.evidenceId)
      throw new ConfigurationRepositoryError('PC-DATA-6004');
    return this.reads.execute({ ...context, resourceId: '*' }, async (client) => {
      const host = await client.query<{ host_wire: Buffer }>(
        `select host_wire from control.store_retirement_host where participant_id=$1 and privacy_domain_id=$2 and host_digest=$3
       and valid_from_ms<=floor(extract(epoch from clock_timestamp())*1000) and valid_until_ms>floor(extract(epoch from clock_timestamp())*1000)`,
        [
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          input.hostDigest,
        ],
      );
      if (host.rowCount !== 1 || !this.options.storeRetirementAdmissions?.has(input.hostDigest))
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      const installed = retirementHost.parse(parseRetirementWire(host.rows[0]!.host_wire));
      const selection = retirementSelection.parse(
        parseRetirementWire(Buffer.from(input.selectionWireHex, 'hex')),
      );
      if (
        retirementWireDigest(installed) !== input.hostDigest ||
        installed.scope.participant_id !== context.authorization.participantId ||
        installed.scope.privacy_domain_id !== context.authorization.privacyDomainId ||
        installed.store !==
          (selection.class === 'ADMITTED_FACT' ? 'openpc_facts' : 'openpc_candidate_index')
      )
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      const selected = await client
        .query('select openpc.store_retirement_source_binding($1,$2,$3) binding', [
          input.retentionPolicyId.slice(-36),
          Buffer.from(input.selectionWireHex, 'hex'),
          JSON.stringify(input.recordRefs),
        ])
        .catch(retirementSourceFailure);
      return storeRetirementPlan.parse({
        hostDigest: input.hostDigest,
        retentionPolicyId: input.retentionPolicyId,
        sourceBinding: storeRetirementSourceBinding.parse(selected.rows[0]?.binding),
        nativeSourceCheck: 'REQUIRED_AT_ADMISSION',
      });
    });
  }
  admit(context: MutationContext, input: z.infer<typeof admitStoreRetirement>) {
    const authority = this.options.storeRetirementAdmissions?.get(input.hostDigest);
    if (!authority) throw new ConfigurationRepositoryError('PC-DATA-6007');
    return this.mutations.execute(context, async (client, _attemptId, operationId) => {
      await lockEvidenceLifecycle(
        client,
        context.authorization.participantId,
        context.authorization.privacyDomainId,
      );
      const before = await readStoreRetirementAdmissionState(client, context);
      if (before) throw new ConfigurationRepositoryError('PC-DATA-6007');
      await authority.insert(client, context, operationId, input);
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'openpc.evidence.store-retirement.admitted.v1',
        businessState: bindStoreRetirementAdmission(
          context,
          operationId,
          before,
          await readStoreRetirementAdmissionState(client, context),
        ),
      };
    });
  }
  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query(
        `select 'urn:openpc:resource:'||a.attempt_id::text as "attemptId",
        'urn:openpc:resource:'||a.retirement_id::text as "retirementId",
        case when a.previous_attempt_id is null then null else 'urn:openpc:resource:'||a.previous_attempt_id::text end as "previousAttemptId",
        'urn:openpc:participant:'||a.participant_id::text as "participantId",a.privacy_domain_id::text as "privacyDomainId",
        a.host_digest as "hostDigest",'ADMITTED' as "admissionState",a.operation_id::text as "operationId",a.revision::text,
        'sha256:'||encode(receipt.receipt_digest,'hex') as "admissionReceiptDigest",coalesce(o.state,'UNKNOWN') as "physicalState",
        c.cancellation_id::text as "cancellationId",case when o.wire_digest is null then null else 'sha256:'||o.wire_digest end as "outcomeDigest",
        a.dispatch_not_after_ms::text as "dispatchNotAfterMs"
        from control.store_retirement_admission a join control.audit_occurrence receipt on receipt.participant_id=a.participant_id
         and receipt.privacy_domain_id=a.privacy_domain_id and receipt.operation_id=a.operation_id and receipt.aggregate_id=a.attempt_id
         and receipt.aggregate_type='store-retirement' and receipt.profile_id='pc.control.store-retirement.admit'
        left join control.store_retirement_outcome o on o.participant_id=a.participant_id and o.privacy_domain_id=a.privacy_domain_id and o.attempt_id=a.attempt_id
        left join control.store_retirement_cancellation c on c.participant_id=a.participant_id and c.privacy_domain_id=a.privacy_domain_id and c.attempt_id=a.attempt_id
        where a.participant_id=$1 and a.privacy_domain_id=$2 and a.attempt_id=$3`,
        [
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          context.resourceId,
        ],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      return storeRetirementView.parse(selected.rows[0]);
    });
  }
}
