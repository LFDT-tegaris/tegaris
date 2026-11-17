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
import type { ResourceApiOptions } from '../configuration/governed-mutation-http.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  disposeRuntimeArtifactSource,
  runtimeArtifactDispositionSelection,
  runtimeArtifactDispositionPlan,
  runtimeArtifactDispositionPlanInput,
  runtimeArtifactDispositionView,
} from './runtime-artifact-disposition-contract.js';
import {
  bindRuntimeArtifactDisposition,
  readRuntimeArtifactDispositionState,
} from './runtime-artifact-disposition-state.js';
import { readBusinessProvenance } from './receipt-provenance.js';
import { businessOccurrenceTime } from './business-source.js';
import { readRuntimeArtifactRetirement } from './runtime-artifact-retirement.js';

const blockers = new Set([
  'INCOMPLETE_REFERENCES',
  'REFERENCES',
  'SOURCE_UNPROVEN',
  'SELECTED_INPUT',
  'ALREADY_DISPOSED',
  'ARCHIVE_UNPROVEN',
  'ACTIVE_HOLD',
  'SINK_QUORUM',
  'RETENTION_NOT_ELAPSED',
  'STALE_SELECTION',
]);
function precondition(error: unknown): string | undefined {
  if (!error || typeof error !== 'object' || !('code' in error)) return;
  if (error.code === 'P0002') return 'SOURCE_OR_POLICY_UNAVAILABLE';
  if (error.code !== 'P0001' || !('message' in error) || typeof error.message !== 'string') return;
  const reason = error.message.startsWith('RUNTIME-DISPOSITION-')
    ? error.message.slice('RUNTIME-DISPOSITION-'.length)
    : '';
  return blockers.has(reason) ? reason : undefined;
}

export class RuntimeArtifactDispositionRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(
    pool: Pool,
    options: Pick<ResourceApiOptions, 'identityRuntimeVerifier' | 'businessEvidence'>,
  ) {
    this.mutations = new AtomicConfigurationMutation(
      pool,
      options.identityRuntimeVerifier,
      options.businessEvidence,
    );
    this.reads = new ScopedConfigurationRead(pool);
  }

  async plan(context: ReadContext, input: z.infer<typeof runtimeArtifactDispositionPlanInput>) {
    try {
      return await this.reads.executeCurrent(context, async (client) => {
        const result = await client.query(
          'select openpc.runtime_artifact_disposition_selection($1::uuid,$2::uuid) selection',
          [input.runtimeConfigurationInputId.slice(-36), input.retentionPolicyId.slice(-36)],
        );
        if (result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        return runtimeArtifactDispositionPlan.parse({
          selection: result.rows[0]!.selection,
          blockers: [],
          nativeCustody: 'REQUIRED_AFTER_COMMITTED_ADMISSION',
          authority: 'NONE',
        });
      });
    } catch (error) {
      const blocked = precondition(error);
      if (!blocked) throw error;
      return runtimeArtifactDispositionPlan.parse({
        selection: null,
        blockers: [blocked],
        nativeCustody: 'REQUIRED_AFTER_COMMITTED_ADMISSION',
        authority: 'NONE',
      });
    }
  }

  async dispose(context: MutationContext, input: z.infer<typeof disposeRuntimeArtifactSource>) {
    try {
      return await this.mutations.execute(context, async (client, _id, operationId) => {
        const selected = runtimeArtifactDispositionSelection.parse(input.selection);
        const observed = selected.observation;
        if (
          input.participantId !== `urn:openpc:participant:${context.authorization.participantId}` ||
          observed.participantId !== input.participantId ||
          observed.privacyDomainId !== context.authorization.privacyDomainId
        )
          throw new ConfigurationRepositoryError('PC-AUTH-0005');
        const result = await client.query(
          'select openpc.runtime_artifact_disposition_selection($1::uuid,$2::uuid) selection',
          [observed.source.runtimeConfigurationInputId, observed.retentionPolicyId.slice(-36)],
        );
        if (
          result.rowCount !== 1 ||
          canonicalJson(result.rows[0]!.selection) !== canonicalJson(selected)
        )
          throw new ConfigurationRepositoryError('PC-DATA-6007');
        const before = await readRuntimeArtifactDispositionState(client, context);
        if (before) throw new ConfigurationRepositoryError('PC-DATA-6007');
        await client.query(
          `insert into control.runtime_artifact_source_disposition
          (participant_id,privacy_domain_id,source_owner_id,disposition_id,runtime_configuration_input_id,configuration_digest,
           selection,selection_digest,approval_request_id,operation_id) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            selected.sourceOwnerId,
            context.resourceId,
            observed.source.runtimeConfigurationInputId,
            Buffer.from(observed.source.configurationDigest.slice(7), 'hex'),
            selected,
            Buffer.from(sha256(selected).slice(7), 'hex'),
            context.authorization.approvalRequestId,
            operationId,
          ],
        );
        return {
          result: undefined,
          revision: '1',
          outboxEventType: 'openpc.runtime-artifact.source-disposition.admitted.v1',
          businessState: bindRuntimeArtifactDisposition(
            context,
            operationId,
            before,
            await readRuntimeArtifactDispositionState(client, context),
          ),
        };
      });
    } catch (error) {
      if (precondition(error)) throw new ConfigurationRepositoryError('PC-DATA-6007');
      throw error;
    }
  }

  get(context: ReadContext) {
    return this.reads.executeCurrent(context, async (client) => {
      await client.query('select openpc.lock_runtime_artifact_disposition()');
      const rows = await client.query(
        `select openpc.assert_runtime_artifact_source_disposition_committed(a),
        'urn:openpc:resource:'||a.disposition_id::text as "dispositionId",'urn:openpc:participant:'||a.participant_id::text as "participantId",
        a.privacy_domain_id::text as "privacyDomainId",a.source_owner_id::text as "sourceOwnerId",
        'urn:openpc:resource:'||a.runtime_configuration_input_id::text as "runtimeConfigurationInputId",
        'sha256:'||encode(a.configuration_digest,'hex') as "configurationDigest",'sha256:'||encode(a.selection_digest,'hex') as "selectionDigest",
        a.operation_id::text as "operationId",a.revision::text,to_char(a.admitted_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "admittedAt",
        'sha256:'||encode(receipt.receipt_digest,'hex') as "admissionReceiptDigest",'DENIED' as "newUseState",
        case when denial.disposition_id is null then 'PENDING' else 'DENIED' end as "nativeState",
        'sha256:'||encode(denial.denial_digest,'hex') as "nativeDenialDigest",'NOT_ESTABLISHED' as "physicalState",
        e.evidence_record_id::text as "recordId",'sha256:'||encode(sha256(receipt.cose_sign1),'hex') as "recordDigest",
        receipt.recorded_at_ns::text as "recordedAtNs",e.evidence_format as "evidenceFormat"
        from control.runtime_artifact_source_disposition a join control.audit_occurrence receipt
         on receipt.participant_id=a.participant_id and receipt.privacy_domain_id=a.privacy_domain_id and receipt.operation_id=a.operation_id
          and receipt.aggregate_type='runtime-artifact-disposition' and receipt.aggregate_id=a.disposition_id
        join control.evidence_record e on e.participant_id=a.participant_id and e.privacy_domain_id=a.privacy_domain_id
         and e.receipt_id=receipt.receipt_id and e.receipt_digest=receipt.receipt_digest and e.evidence_role='BUSINESS_TRANSITION_RECEIPT' and e.custody='CONTROL_STORE'
        left join control.runtime_artifact_source_denial denial on denial.participant_id=a.participant_id
         and denial.privacy_domain_id=a.privacy_domain_id and denial.disposition_id=a.disposition_id
        where a.participant_id=$1 and a.privacy_domain_id=$2 and a.disposition_id=$3`,
        [
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          context.resourceId,
        ],
      );
      if (rows.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      const {
        assert_runtime_artifact_source_disposition_committed: _assertion,
        recordId,
        recordDigest,
        recordedAtNs,
        evidenceFormat,
        ...view
      } = rows.rows[0]!;
      void _assertion;
      const receipt = await readBusinessProvenance(
        client,
        {
          participantId: context.authorization.participantId,
          privacyDomainId: context.authorization.privacyDomainId,
          recordId,
          recordDigest,
          occurredAt: businessOccurrenceTime(BigInt(recordedAtNs)),
        },
        evidenceFormat,
      );
      if (
        receipt.profileId !== 'pc.control.runtime-artifact.disposition' ||
        receipt.aggregateId !== context.resourceId ||
        receipt.operationId !== `urn:openpc:operation:${view.operationId}`
      )
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      const physical = await readRuntimeArtifactRetirement(client, {
        participantId: context.authorization.participantId,
        privacyDomainId: context.authorization.privacyDomainId,
        runtimeConfigurationInputId: view.runtimeConfigurationInputId.slice(-36),
        configurationDigest: view.configurationDigest,
      });
      return runtimeArtifactDispositionView.parse({
        ...view,
        physicalState: physical.status === 'RETIRED' ? 'RETIRED' : 'NOT_ESTABLISHED',
      });
    });
  }
}
