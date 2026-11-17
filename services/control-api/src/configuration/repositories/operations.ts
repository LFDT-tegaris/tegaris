import type { Pool } from 'pg';
import {
  rotationCommandColumns,
  rotationOperationView,
  type RotationCommand,
} from '../../../../identity-service/src/db/signing-rotation-command.js';

import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import { ConfigurationRepositoryError, type OperationRecord } from '../persistence/types.js';
import { readDeploymentResult, managementDeploymentState } from '../deployment/result-readback.js';
import { readCiglProfile } from '../cigl/profile-readback.js';
import { readEvidenceExportResult } from '../../evidence/export-result.js';

export type { OperationRecord } from '../persistence/types.js';

interface OperationRow {
  readonly operationId: string;
  readonly aggregateId: string | null;
  readonly resultPayload: {
    readonly resourceRef?: string | null;
    readonly state?: string;
    readonly truthState?: string;
  } | null;
  readonly actionIntentId: string;
  readonly intentDigest: Buffer;
  readonly idempotencyKey: string;
  readonly terminalState: string | null;
  readonly deploymentHandoffState?: string | null;
  readonly workState: string | null;
  readonly workKind: string | null;
  readonly executionStartedAt: string | null;
  readonly resultReceiptDigest: string | null;
  readonly lastErrorCode: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly revision: string | null;
}

function timestamp(value: string): string {
  return new Date(value).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
}

export function deriveOperationState(input: {
  readonly terminalState: string | null;
  readonly deploymentHandoffState?: string | null;
  readonly workState: string | null;
  readonly executionStartedAt?: string | null;
  readonly resultReceiptDigest: string | null;
  readonly lastErrorCode: string | null;
  readonly resultPayload?: { readonly state?: string; readonly truthState?: string } | null;
}): Pick<OperationRecord, 'state' | 'truthState'> {
  if (input.terminalState === 'WRITE_AMBIGUITY' || input.deploymentHandoffState === 'HANDOFF') {
    return { state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' };
  }
  if (input.workState === null) {
    // COMMITTED describes command acceptance. A durable asynchronous command
    // without an execution result must not be promoted to effect success.
    if (input.resultPayload?.state === 'ACCEPTED' && input.resultPayload.truthState === 'UNKNOWN')
      return { state: 'ACCEPTED', truthState: 'UNKNOWN' };
    if (input.terminalState === 'COMMITTED') return { state: 'SUCCEEDED', truthState: 'SUCCESS' };
    return { state: 'ACCEPTED', truthState: 'UNKNOWN' };
  }
  if (input.workState === 'PENDING') return { state: 'ACCEPTED', truthState: 'UNKNOWN' };
  if (
    input.workState === 'LEASED' &&
    input.executionStartedAt !== null &&
    input.executionStartedAt !== undefined
  ) {
    return { state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' };
  }
  if (input.workState === 'LEASED') return { state: 'RUNNING', truthState: 'UNKNOWN' };
  if (input.workState === 'RECONCILING') {
    return { state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' };
  }
  if (
    input.workState === 'FAILED' &&
    input.lastErrorCode !== null &&
    input.resultReceiptDigest !== null
  ) {
    return { state: 'FAILED', truthState: 'FAILED' };
  }
  if (
    input.workState === 'COMPLETED' &&
    input.resultReceiptDigest !== null &&
    input.lastErrorCode === null
  ) {
    return { state: 'SUCCEEDED', truthState: 'SUCCESS' };
  }
  throw new ConfigurationRepositoryError('PC-FACT-4001');
}

export class OperationRepository {
  private readonly reads: ScopedConfigurationRead;

  constructor(pool: Pool) {
    this.reads = new ScopedConfigurationRead(pool);
  }

  async get(
    context: ReadContext,
    missing?: () => Promise<OperationRecord>,
  ): Promise<OperationRecord> {
    return this.reads.execute(context, async (client) => {
      const rotation = await client.query<RotationCommand>(
        `select ${rotationCommandColumns} from control.signing_rotation_command
        where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
        [
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          context.resourceId,
        ],
      );
      if (rotation.rowCount === 1)
        return rotationOperationView(rotation.rows[0]!) as OperationRecord;
      const selected = await client.query<OperationRow>(
        `select record.operation_id::text as "operationId",evidence.aggregate_id::text as "aggregateId",
                record.result_payload as "resultPayload",
                record.action_intent_id as "actionIntentId",intent.semantic_digest as "intentDigest",
                record.idempotency_key as "idempotencyKey",record.terminal_state as "terminalState",
                reservation.state as "deploymentHandoffState",
                work.state as "workState",work.work_kind as "workKind",work.result_receipt_digest as "resultReceiptDigest",
                work.last_error_code as "lastErrorCode",work.execution_started_at::text as "executionStartedAt",
                record.created_at::text as "createdAt",
                coalesce(work.updated_at,reservation.handoff_at,evidence.occurred_at,record.created_at)::text as "updatedAt",
                record.result_aggregate_version::text as revision
           from control.idempotency_record record
           join control.action_intent intent on intent.action_intent_id=record.action_intent_id
           left join control.mutation_evidence evidence
             on evidence.participant_id=record.participant_id
            and evidence.operation_id=record.operation_id
           left join control.configuration_work work
             on work.participant_id=record.participant_id and work.operation_id=record.operation_id
           left join control.deployment_address_reservation reservation
             on reservation.participant_id=record.participant_id and reservation.privacy_domain_id=record.privacy_domain_id
            and reservation.command_id=record.operation_id
          where record.participant_id=$1 and record.operation_id=$2 and record.privacy_domain_id=$3`,
        [
          context.authorization.participantId,
          context.resourceId,
          context.authorization.privacyDomainId,
        ],
      );
      const row = selected.rows[0];
      // A scoped miss says nothing about whether this identifier exists elsewhere.
      if (selected.rowCount === 0) {
        if (missing) return missing();
        throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      }
      if (selected.rowCount !== 1 || row === undefined) {
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      }
      // Control can retain the authorized proposal, but only the Fact receipt
      // owns admission truth. Its current principal/scope checks still apply.
      if (row.actionIntentId === 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1') {
        if (missing) return missing();
        throw new ConfigurationRepositoryError('PC-INTEGRATION-5001', 503);
      }
      const deployment =
        row.actionIntentId === 'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
          ? await readDeploymentResult(
              client,
              row.operationId,
              context.authorization.participantId,
              context.authorization.privacyDomainId,
            )
          : undefined;
      if (row.workKind === 'CIGL_PROFILE_COMPILATION' && row.workState === 'COMPLETED') {
        if (row.aggregateId === null) throw new ConfigurationRepositoryError('PC-FACT-4001');
        const profile = await readCiglProfile(
          client,
          row.aggregateId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
        );
        if (profile?.state !== 'COMPILED') throw new ConfigurationRepositoryError('PC-FACT-4001');
      }
      const evidenceExport =
        row.actionIntentId === 'ACT-EVIDENCE_EXPORT_RECORDS-V1'
          ? await readEvidenceExportResult(client, context)
          : undefined;
      const truth =
        evidenceExport ??
        (deployment === undefined
          ? deriveOperationState(row)
          : managementDeploymentState(deployment.status));
      return {
        operationId: row.operationId,
        resourceRef:
          row.aggregateId === null
            ? (row.resultPayload?.resourceRef ?? null)
            : `urn:openpc:resource:${row.aggregateId}`,
        actionIntentId: row.actionIntentId,
        intentDigest: `sha256:${row.intentDigest.toString('hex')}`,
        idempotencyKey: row.idempotencyKey,
        ...truth,
        createdAt: timestamp(row.createdAt),
        updatedAt: timestamp(evidenceExport?.updatedAt ?? deployment?.updatedAt ?? row.updatedAt),
        revision: evidenceExport?.revision ?? deployment?.sequence ?? row.revision ?? '0',
      };
    });
  }
}
