import type { Pool } from 'pg';
import type { z } from 'zod';
import { AtomicConfigurationMutation } from '../configuration/persistence/atomic-mutation.js';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../configuration/persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import { selectPage, type ListRequest } from '../configuration/pagination.js';
import type { ResourceApiOptions } from '../configuration/governed-mutation-http.js';
import {
  activateRetentionPolicy,
  encodeRetentionPolicy,
  retentionPolicyView,
} from './retention-contracts.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { bindRetentionTransition, readRetentionBusinessState } from './retention-business-state.js';

type PolicyRow = z.infer<typeof retentionPolicyView>;
const projection = `retention_policy_id::text as "retentionPolicyId",participant_id::text as "participantId",
 predecessor_policy_id::text as "predecessorPolicyId",data_class as "dataClass",policy_version as "policyVersion",
 retention_period_ms::text as "retentionPeriodMs",local_grace_ms::text as "localGraceMs",sink_quorum as "sinkQuorum",
 deletion_mode as "deletionMode",maker_checker_required as "makerCheckerRequired",policy_digest as "policyDigest",state,revision::text,
 activation_operation_id::text as "activationOperationId",retirement_operation_id::text as "retirementOperationId",
 activation_receipt_digest as "activationReceiptDigest",retirement_receipt_digest as "retirementReceiptDigest",
 to_char(active_from at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "activeFrom",
 to_char(active_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "activeUntil",
 to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "createdAt",
 to_char(updated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "updatedAt"`;
const source = `(select p.*,case when active_until is null then 'ACTIVE' else 'RETIRED' end state,
 (select 'sha256:'||encode(a.receipt_digest,'hex') from control.audit_occurrence a
  where a.participant_id=p.participant_id and a.privacy_domain_id=p.privacy_domain_id
   and a.operation_id=p.activation_operation_id and a.aggregate_type='retention-policy' and a.aggregate_id=p.retention_policy_id
   and a.profile_id='pc.control.retention-policy.activate') activation_receipt_digest,
 (select 'sha256:'||encode(a.receipt_digest,'hex') from control.audit_occurrence a
  where a.participant_id=p.participant_id and a.privacy_domain_id=p.privacy_domain_id
   and a.operation_id=p.retirement_operation_id and a.aggregate_type='retention-policy' and a.aggregate_id=p.retention_policy_id
   and a.profile_id='pc.control.retention-policy.retire') retirement_receipt_digest
 from control.retention_policy p where p.participant_id=current_setting('openpc.participant_id')::uuid
 and p.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid) policies`;
const view = (row: PolicyRow) =>
  retentionPolicyView.parse({
    ...row,
    retentionPolicyId: `urn:openpc:resource:${row.retentionPolicyId}`,
    participantId: `urn:openpc:participant:${row.participantId}`,
    predecessorPolicyId:
      row.predecessorPolicyId === null ? null : `urn:openpc:resource:${row.predecessorPolicyId}`,
  });

export class RetentionPolicyRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(
    pool: Pool,
    options: Pick<ResourceApiOptions, 'identityRuntimeVerifier' | 'businessEvidence'> = {},
  ) {
    this.mutations = new AtomicConfigurationMutation(
      pool,
      options.identityRuntimeVerifier,
      options.businessEvidence,
    );
    this.reads = new ScopedConfigurationRead(pool);
  }
  activate(context: MutationContext, input: z.infer<typeof activateRetentionPolicy>) {
    const scope = context.authorization,
      bound = encodeRetentionPolicy(scope, input.policy);
    return this.mutations.execute(context, async (client, policyId, operationId) => {
      await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
      const before = await readRetentionBusinessState(client, context);
      const latest = await client.query<{ id: string; retired: boolean }>(
        `select retention_policy_id::text id,active_until is not null retired
       from control.retention_policy where participant_id=$1 and privacy_domain_id=$2 and data_class=$3
       order by active_from desc,retention_policy_id desc limit 1 for update`,
        [scope.participantId, scope.privacyDomainId, bound.policy.dataClass],
      );
      const predecessor = input.predecessorPolicyId?.slice(-36) ?? null;
      if (
        (latest.rows[0]?.id ?? null) !== predecessor ||
        (latest.rowCount && !latest.rows[0]!.retired)
      )
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      const duplicate = await client.query(
        `select 1 from control.retention_policy where participant_id=$1 and privacy_domain_id=$2 and data_class=$3 and policy_version=$4`,
        [
          scope.participantId,
          scope.privacyDomainId,
          bound.policy.dataClass,
          bound.policy.policyVersion,
        ],
      );
      if (duplicate.rowCount) throw new ConfigurationRepositoryError('PC-DATA-6007');
      await client.query(
        `insert into control.retention_policy(retention_policy_id,participant_id,privacy_domain_id,predecessor_policy_id,
       data_class,policy_version,retention_period_ms,local_grace_ms,sink_quorum,deletion_mode,maker_checker_required,
       policy_cbor,policy_digest,approval_request_id,activation_operation_id)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
        [
          policyId,
          scope.participantId,
          scope.privacyDomainId,
          predecessor,
          bound.policy.dataClass,
          bound.policy.policyVersion,
          bound.policy.retentionPeriodMs,
          bound.policy.localGraceMs,
          bound.policy.sinkQuorum,
          bound.policy.deletionMode,
          bound.policy.makerCheckerRequired,
          bound.bytes,
          bound.digest,
          scope.approvalRequestId,
          operationId,
        ],
      );
      return {
        result: undefined,
        revision: '1',
        businessState: bindRetentionTransition(
          context,
          operationId,
          before,
          await readRetentionBusinessState(client, context),
        ),
        outboxEventType: 'openpc.retention.policy.activated.v1',
      };
    });
  }
  retire(context: MutationContext) {
    const scope = context.authorization;
    return this.mutations.execute(context, async (client, policyId, operationId) => {
      await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
      const before = await readRetentionBusinessState(client, context);
      const changed = await client.query(
        `update control.retention_policy set revision=2,active_until=clock_timestamp(),
        retirement_operation_id=$4,retirement_approval_request_id=$5
        where participant_id=$1 and privacy_domain_id=$2 and retention_policy_id=$3 and revision=$6 and active_until is null
        returning retention_policy_id`,
        [
          scope.participantId,
          scope.privacyDomainId,
          policyId,
          operationId,
          scope.approvalRequestId,
          context.expectedRevision,
        ],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      return {
        result: undefined,
        revision: '2',
        businessState: bindRetentionTransition(
          context,
          operationId,
          before,
          await readRetentionBusinessState(client, context),
        ),
        outboxEventType: 'openpc.retention.policy.retired.v1',
      };
    });
  }
  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query<PolicyRow>(
        `select ${projection} from ${source} where retention_policy_id=$1`,
        [context.resourceId],
      );
      if (result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      return view(result.rows[0]!);
    });
  }
  list(context: ReadContext, request: ListRequest) {
    return this.reads.execute(context, (client) =>
      selectPage(client, request, {
        table: source,
        idColumn: 'retention_policy_id',
        projection,
        filterColumns: { state: 'state', dataClass: 'data_class' },
        rowId: (row: PolicyRow) => row.retentionPolicyId,
        rowUpdatedAt: (row: PolicyRow) => row.updatedAt,
        map: view,
      }),
    );
  }
}
