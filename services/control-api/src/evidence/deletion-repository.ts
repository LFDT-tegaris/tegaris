import {
  deleteRuntimeArtifactBatch,
  runtimeArtifactRetirementPlan,
  runtimeArtifactRetirementPlanInput,
  runtimeArtifactRetirementSelection,
} from './runtime-artifact-deletion-contracts.js';
import {
  readRuntimeArtifactRetirement,
  runtimeArtifactRetirementView,
} from './runtime-artifact-retirement.js';
import {
  deleteLocalEvidenceBatch,
  evidenceDeletionBatchPlan,
  evidenceDeletionResultView,
} from './deletion-continuation-contracts.js';
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
import { uuidv7, type ResourceApiOptions } from '../configuration/governed-mutation-http.js';
import { canonicalJson } from '../configuration/digest.js';
import { deleteLocalEvidence, localEvidenceDeletionPlan } from './deletion-contracts.js';
import { bindDeletionTransition, readDeletionBusinessState } from './deletion-business-state.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { verifyEvidenceDeletionSources } from './deletion-sources.js';
import { deleteRawProofBatch, rawProofDeletionPlan } from './raw-deletion-contracts.js';
import { readProtectedProofSource, requireExactProofSource } from './protected-source.js';
import {
  deleteProjectionBatch,
  projectionDataClass,
  projectionDeletionPlan,
} from './projection-deletion-contracts.js';
import { verifyProjectionDeletionSource } from './projection-deletion-source.js';
import { acquireFactRetirementFence, FactRetirementBlocked } from './fact-retirement.js';
import { acquireDeploymentRetirementFence } from './deployment-retirement.js';

type DeletionRow = z.infer<typeof evidenceDeletionResultView>;
const projection = `deletion_job_id::text as "deletionJobId",participant_id::text as "participantId",
 selection,state,revision::text,operation_id::text as "operationId",attempt_id::text as "attemptId",
 external_attempt_state as "externalAttemptState",deleted_count::text as "deletedCount",deleted_bytes::text as "deletedBytes",
 retained_alias_count::text as "retainedAliasCount",before_digest as "beforeDigest",after_digest as "afterDigest",receipt_digest as "receiptDigest",
 to_char(started_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "startedAt",
 to_char(completed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "completedAt",
 to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "createdAt",
 to_char(updated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "updatedAt"`;
const source = `(select j.*,(select 'sha256:'||encode(a.receipt_digest,'hex') from control.audit_occurrence a
 where a.participant_id=j.participant_id and a.privacy_domain_id=j.privacy_domain_id and a.operation_id=j.operation_id
  and a.aggregate_type='evidence-deletion' and a.aggregate_id=j.deletion_job_id
  and a.profile_id IN ('pc.control.evidence-deletion.local','pc.control.evidence-deletion.batch','pc.control.evidence-deletion.raw-proof','pc.control.evidence-deletion.projection','pc.control.evidence-deletion.runtime-artifact')) receipt_digest
 from control.deletion_job j where j.participant_id=current_setting('openpc.participant_id')::uuid
  and j.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid) deletions`;
const view = (row: DeletionRow) =>
  evidenceDeletionResultView.parse({
    ...row,
    deletionJobId: `urn:openpc:resource:${row.deletionJobId}`,
    participantId: `urn:openpc:participant:${row.participantId}`,
  });

export class EvidenceDeletionRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(
    private readonly pool: Pool,
    private readonly options: Pick<
      ResourceApiOptions,
      'identityRuntimeVerifier' | 'businessEvidence'
    > = {},
  ) {
    this.mutations = new AtomicConfigurationMutation(
      pool,
      options.identityRuntimeVerifier,
      options.businessEvidence,
    );
    this.reads = new ScopedConfigurationRead(pool);
  }
  async runtimePlan(
    context: ReadContext,
    input: z.infer<typeof runtimeArtifactRetirementPlanInput>,
  ) {
    try {
      return await this.reads.executeCurrent(context, async (client) => {
        const result = await client.query(
          'select openpc.runtime_artifact_retirement_plan($1::uuid,$2::uuid) plan',
          [input.retentionPolicyId.slice(-36), input.previousDeletionJobId?.slice(-36) ?? null],
        );
        if (result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        return runtimeArtifactRetirementPlan.parse(result.rows[0].plan);
      });
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'P0002')
        throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      throw error;
    }
  }
  runtimeRetirement(context: ReadContext) {
    return this.reads.executeCurrent(context, async (client) => {
      const result = await client.query<{ selection: unknown }>(
        `select selection from control.deletion_job where participant_id=$1 and privacy_domain_id=$2
        and deletion_job_id=$3 and target_data_class='RUNTIME_ARTIFACT' and state='SUCCEEDED'`,
        [
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          context.resourceId,
        ],
      );
      if (result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      const selected = runtimeArtifactRetirementSelection.parse(result.rows[0]!.selection);
      const proof = await readRuntimeArtifactRetirement(client, {
        participantId: context.authorization.participantId,
        privacyDomainId: context.authorization.privacyDomainId,
        runtimeConfigurationInputId: selected.source.runtimeConfigurationInputId,
        configurationDigest: selected.source.configurationDigest,
      });
      if (proof.status !== 'RETIRED' || proof.retirement.deletionJobId !== context.resourceId)
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      return runtimeArtifactRetirementView.parse(proof);
    });
  }
  plan(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const rows = await client.query('select openpc.local_evidence_deletion_plan($1::uuid) plan', [
        context.resourceId,
      ]);
      if (!rows.rows[0]?.plan) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      const plan = localEvidenceDeletionPlan.parse(rows.rows[0].plan);
      await verifyEvidenceDeletionSources(client, plan.selection);
      return plan;
    });
  }
  batchPlan(context: ReadContext, continuation = false) {
    return this.reads.execute(
      continuation ? context : { ...context, resourceId: '*' },
      async (client) => {
        const rows = await client.query(
          'select openpc.local_evidence_deletion_batch_plan($1::uuid,$2::uuid) plan',
          continuation ? [null, context.resourceId] : [context.resourceId, null],
        );
        if (!rows.rows[0]?.plan) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
        const plan = evidenceDeletionBatchPlan.parse(rows.rows[0].plan);
        await verifyEvidenceDeletionSources(client, plan.selection);
        return plan;
      },
    );
  }
  rawPlan(context: ReadContext, continuation = false) {
    return this.reads.execute(
      continuation ? context : { ...context, resourceId: '*' },
      async (client) => {
        const rows = await client.query(
          'select openpc.raw_proof_deletion_batch_plan($1::uuid,$2::uuid) plan',
          continuation ? [null, context.resourceId] : [context.resourceId, null],
        );
        if (!rows.rows[0]?.plan) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
        const plan = rawProofDeletionPlan.parse(rows.rows[0].plan);
        if (plan.selection)
          requireExactProofSource(
            plan.selection.source,
            (
              await readProtectedProofSource(
                client,
                context.authorization,
                plan.selection.source.evidenceId,
                this.options.identityRuntimeVerifier,
              )
            ).source,
          );
        return plan;
      },
    );
  }
  projectionPlan(context: ReadContext, dataClass?: z.infer<typeof projectionDataClass>) {
    return this.reads.execute(
      dataClass ? { ...context, resourceId: '*' } : context,
      async (client) => {
        let selectedClass = dataClass;
        if (!selectedClass) {
          const prior = await client.query<{ target_data_class: string }>(
            `select target_data_class from control.deletion_job where participant_id=$1 and privacy_domain_id=$2 and deletion_job_id=$3`,
            [
              context.authorization.participantId,
              context.authorization.privacyDomainId,
              context.resourceId,
            ],
          );
          const parsed = projectionDataClass.safeParse(prior.rows[0]?.target_data_class);
          if (prior.rowCount !== 1 || !parsed.success)
            throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
          selectedClass = parsed.data;
        }
        const rows = await client.query(
          'select openpc.projection_deletion_batch_plan($1::uuid,$2::uuid,$3::text) plan',
          dataClass
            ? [context.resourceId, null, selectedClass]
            : [null, context.resourceId, selectedClass],
        );
        if (!rows.rows[0]?.plan) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
        const plan = projectionDeletionPlan.parse(rows.rows[0].plan);
        if (plan.selection && !plan.blockers.includes('UNSUPPORTED_SOURCE')) {
          try {
            await verifyProjectionDeletionSource(client, plan.selection);
          } catch (error) {
            if (!(error instanceof FactRetirementBlocked)) throw error;
            return projectionDeletionPlan.parse({
              ...plan,
              eligible: false,
              blockers: [...new Set([...plan.blockers, error.blocker])].sort(),
              continuationState: 'BLOCKED',
            });
          }
        }
        return plan;
      },
    );
  }
  create(
    context: MutationContext,
    input:
      | z.infer<typeof deleteLocalEvidence>
      | z.infer<typeof deleteLocalEvidenceBatch>
      | z.infer<typeof deleteRawProofBatch>
      | z.infer<typeof deleteProjectionBatch>
      | z.infer<typeof deleteRuntimeArtifactBatch>,
  ) {
    const scope = context.authorization;
    const runtimeSelection =
      input.selection.version === 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1';
    const profileVersion =
      input.selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1'
        ? input.selection.sourceKind === 'RPC_RETIRED_CATALOGUE'
          ? 3
          : input.selection.sourceKind === 'RETENTION_POLICY_CATALOGUE'
            ? 2
            : 1
        : input.selection.version === 'OPENPC_LOCAL_EVIDENCE_DELETION_V1' ||
            input.selection.version === 'OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1'
          ? input.selection.sourceRpcRetirements
            ? 2
            : 1
          : 1;
    const factSelection =
      input.selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1' &&
      input.selection.sourceKind === 'FACT_PROVENANCE'
        ? input.selection
        : undefined;
    const deploymentSelection =
      input.selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1' &&
      input.selection.sourceKind === 'DEPLOYMENT_PROVENANCE'
        ? input.selection
        : undefined;
    return this.mutations.execute(
      context,
      async (client, jobId, operationId) => {
        await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
        const before = await readDeletionBusinessState(client, context);
        const rows = await client.query(
          'select openpc.evidence_deletion_selection_plan($1::jsonb) plan',
          [input.selection],
        );
        const planSchema = runtimeSelection
          ? runtimeArtifactRetirementPlan
          : input.selection.version === 'OPENPC_LOCAL_EVIDENCE_DELETION_V1'
            ? localEvidenceDeletionPlan
            : input.selection.version === 'OPENPC_RAW_PROOF_DELETION_BATCH_V1'
              ? rawProofDeletionPlan
              : input.selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1'
                ? projectionDeletionPlan
                : evidenceDeletionBatchPlan;
        const plan = rows.rows[0]?.plan ? planSchema.parse(rows.rows[0].plan) : null;
        if (
          !plan?.eligible ||
          canonicalJson(plan.selection) !== canonicalJson(input.selection) ||
          plan.beforeDigest !== input.beforeDigest
        )
          throw new ConfigurationRepositoryError('PC-DATA-6007');
        const selection = input.selection;
        if (selection.version === 'OPENPC_RAW_PROOF_DELETION_BATCH_V1') {
          requireExactProofSource(
            selection.source,
            (
              await readProtectedProofSource(
                client,
                scope,
                selection.source.evidenceId,
                this.options.identityRuntimeVerifier,
              )
            ).source,
          );
        } else if (selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1') {
          // Fact verification was acquired after authorization and remains held
          // by the atomic owner through signing and the Control commit.
          if (!factSelection) await verifyProjectionDeletionSource(client, selection);
        } else if (!runtimeSelection) await verifyEvidenceDeletionSources(client, selection);
        await client.query(
          `insert into control.deletion_job(deletion_job_id,participant_id,privacy_domain_id,retention_policy_id,
       stream_id,segment_id,selection,before_digest,approval_request_id,operation_id,attempt_id,protected_object_id,target_data_class)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [
            jobId,
            scope.participantId,
            scope.privacyDomainId,
            input.selection.retentionPolicyId.slice(-36),
            selection.version === 'OPENPC_RAW_PROOF_DELETION_BATCH_V1' ? null : selection.streamId,
            selection.version === 'OPENPC_RAW_PROOF_DELETION_BATCH_V1' ||
            selection.version === 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1'
              ? null
              : selection.segmentId,
            input.selection,
            input.beforeDigest,
            scope.approvalRequestId,
            operationId,
            uuidv7(),
            selection.version === 'OPENPC_RAW_PROOF_DELETION_BATCH_V1'
              ? selection.objectRef.slice(-36)
              : null,
            selection.dataClass,
          ],
        );
        // The payload's BEFORE DELETE trigger captures the actual OLD effect.
        // The following accounting and receipt guards consume that immutable row.
        if (selection.version === 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1') {
          const removed = await client.query(
            'delete from control.runtime_configuration_input where participant_id=$1 and privacy_domain_id=$2 and runtime_configuration_input_id=$3 returning runtime_configuration_input_id',
            [
              scope.participantId,
              scope.privacyDomainId,
              selection.source.runtimeConfigurationInputId,
            ],
          );
          if (removed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        } else if (selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1') {
          const table =
            selection.dataClass === 'SEARCH_PROJECTION'
              ? 'evidence_catalogue'
              : selection.sourceKind === 'FACT_PROVENANCE'
                ? 'evidence_fact_provenance'
                : selection.sourceKind === 'DEPLOYMENT_PROVENANCE'
                  ? 'evidence_deployment_provenance'
                  : 'evidence_rpc_provenance';
          const removed = await client.query(
            `delete from control.${table} where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4 returning record_id`,
            [scope.participantId, scope.privacyDomainId, selection.streamId, selection.recordId],
          );
          if (removed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        } else if (selection.version === 'OPENPC_RAW_PROOF_DELETION_BATCH_V1') {
          const removed = await client.query(
            `delete from control.protected_proof_payload
          where participant_id=$1 and privacy_domain_id=$2 and object_id=$3 returning object_id`,
            [scope.participantId, scope.privacyDomainId, selection.objectRef.slice(-36)],
          );
          if (removed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        } else {
          const removed = await client.query(
            `delete from control.evidence_segment_payload
       where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and segment_id=$4 returning segment_id`,
            [scope.participantId, scope.privacyDomainId, selection.streamId, selection.segmentId],
          );
          if (removed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
          const accounted = await client.query(
            `update control.evidence_stream s set used_bytes=s.used_bytes-i.ciphertext_bytes
       from control.evidence_deletion_item i where s.participant_id=$1 and s.privacy_domain_id=$2 and s.stream_id=$3
        and i.participant_id=s.participant_id and i.privacy_domain_id=s.privacy_domain_id and i.deletion_job_id=$4`,
            [scope.participantId, scope.privacyDomainId, selection.streamId, jobId],
          );
          if (accounted.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        }
        const completed = await client.query(
          `update control.deletion_job set state='SUCCEEDED',revision=1
       where participant_id=$1 and privacy_domain_id=$2 and deletion_job_id=$3 and state='EXECUTING' and revision=0`,
          [scope.participantId, scope.privacyDomainId, jobId],
        );
        if (completed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        return {
          result: undefined,
          revision: '1',
          outboxEventType:
            selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1'
              ? 'openpc.evidence.projection.deleted.v1'
              : 'openpc.evidence.local-payload.deleted.v1',
          businessState: bindDeletionTransition(
            context,
            operationId,
            before,
            await readDeletionBusinessState(client, context),
            profileVersion,
          ),
        };
      },
      async () => profileVersion,
      factSelection
        ? async (client) => {
            // Acquire the Control fence first so a queued hold does not consume the
            // bounded historical Fact lease while this transaction waits for it.
            await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
            return acquireFactRetirementFence(client, factSelection);
          }
        : deploymentSelection
          ? async (client) => {
              await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
              return acquireDeploymentRetirementFence(this.pool, deploymentSelection);
            }
          : undefined,
    );
  }
  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const rows = await client.query<DeletionRow>(
        `select ${projection} from ${source} where deletion_job_id=$1`,
        [context.resourceId],
      );
      if (rows.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      return view(rows.rows[0]!);
    });
  }
  list(context: ReadContext, request: ListRequest) {
    return this.reads.execute(context, (client) =>
      selectPage(client, request, {
        table: source,
        idColumn: 'deletion_job_id',
        projection,
        filterColumns: { state: 'state' },
        rowId: (row: DeletionRow) => row.deletionJobId,
        rowUpdatedAt: (row: DeletionRow) => row.updatedAt,
        map: view,
      }),
    );
  }
}
