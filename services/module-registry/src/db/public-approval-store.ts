import { isEnvelopeCreateResumeCandidate } from '../envelope-create-resume-contract.js';
import { isRuntimeProfileResumeCandidate } from '../runtime-profile-resume-contract.js';
import {
  lockLiveStepUpRecord,
  consumeLiveStepUpRecord,
} from '../../../identity-service/src/db/live-step-up.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import {
  prepareEnvelopeSubmission,
  commitEnvelopeSubmission,
  prepareEnvelopeDecision,
  commitEnvelopeDecision,
  readEnvelopeApprovalCandidate,
} from './envelope-approval-store.js';
import { currentMutationCandidateSql } from '../../../identity-service/src/db/mutation-candidate-fence.js';
import { currentPlatformEnvelopeSql } from '../../../identity-service/src/db/current-platform-envelope.js';
import { readEnvelopeCreation } from '../../../identity-service/src/db/identity-envelope-readback.js';
import { assertRecoveryPrincipalAction } from '../../../identity-service/src/domain/recovery-principal.js';
import { signingCandidateApprovalSql } from '../../../identity-service/src/db/signing-candidate-catalog.js';
import { createHash } from 'node:crypto';
import { isModuleInstallResumeCandidate } from '../module-install-resume-contract.js';
import { setTimeout as delay } from 'node:timers/promises';
import { consumeSigningRotationApproval } from '../../../identity-service/src/db/signing-rotation-store.js';
import { assertCurrentHandoverAdmissionCandidate } from '../../../identity-service/src/db/workload-signing-handover-admission-reader.js';
import { WorkloadSigningHandoverStoreError } from '../../../identity-service/src/db/workload-signing-handover-custody.js';
import { workloadSigningHandoverAdmissionOperation } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import { signingRotationActions } from '../../../identity-service/src/domain/signing-rotation.js';
import { readStoredDeploymentIntent } from '../../../control-api/src/configuration/deployment/intent-readback.js';

import type { Pool, PoolClient } from 'pg';

import {
  AuthorityFenceError,
  fenceBoundAuthorities,
  type AuthorityFence,
  type BoundAuthority,
} from '../../../identity-service/src/db/authority-fence.js';

import { canonicalJson } from '../domain/digest.js';
import { policyApprovalTtlMs } from '../domain/approval-lifetime.js';
import { ContractError, PolicyTransactionConflict } from '../domain/errors.js';
import type { PublicApprovalListRequest } from '../public-approval-pagination.js';
import { approvalReadAuthoritySql } from './approval-read-authority.js';
import { consumeAdministrationReservation } from './administration-resource-reservation.js';
import {
  approvalCandidateResponseSchema,
  projectApprovalCandidate,
  qualifyApprovalCandidateSuccessor,
  type ApprovalCandidateView,
} from '../approval-candidate-contract.js';
import {
  approvalDecisionAuthorityDependencies,
  stepUpCredentialDependencies,
} from '../../../identity-service/src/db/approval-authority-fence.js';

export interface PublicApprovalScope {
  readonly authority: BoundAuthority;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly principalId: string;
  readonly operationId: string;
  readonly actionIntentId: string;
  readonly actionIntentDigest?: string;
  readonly idempotencyKey?: string;
}

export interface ApprovalDecisionAuthority {
  readonly sessionId: string;
  readonly sessionEpoch: string;
  readonly participantEpoch: string;
  readonly principalEpoch: string;
  readonly assignmentId: string;
  readonly assignmentRowVersion: string;
  readonly authorityEnvelopeId: string;
  readonly authorityEpoch: string;
  readonly delegationEpoch: string;
}

export interface ApprovalCandidateAuthority extends ApprovalDecisionAuthority {
  readonly sessionEpoch: string;
  readonly principalId: string;
}

export interface ApprovalRequestView {
  readonly approvalRequestId: string;
  readonly actionIntentId: string;
  readonly candidateDigest: string;
  readonly state: 'REQUESTED' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CANCELLED';
  readonly makerSubjectRef: string;
  readonly checkerSubjectRef: string | null;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface PublicOperation {
  readonly operationId: string;
  readonly actionIntentId: string;
  readonly intentDigest: string;
  readonly idempotencyKey: string;
  readonly resourceRef: string;
  readonly revision: string;
  readonly state: 'ACCEPTED';
  readonly truthState: 'SUCCESS';
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface PublicApprovalPage {
  readonly items: readonly ApprovalRequestView[];
  readonly next?: { readonly updatedAt: string; readonly id: string };
  readonly total: string;
  readonly snapshotRevision: string;
}

export interface ApprovalRow {
  readonly approvalRequestId: string;
  readonly actionIntentId: string;
  readonly subjectType: string;
  readonly subjectId: string;
  readonly subjectDigest: Buffer;
  readonly subjectVersion: string;
  readonly makerPrincipalId: string;
  readonly makerAuthority: BoundAuthority | null;
  readonly checkerPrincipalId: string | null;
  readonly decidedCheckerPrincipalId: string | null;
  readonly state: 'OPEN' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CANCELLED';
  readonly expiresAt: string;
  readonly rowVersion: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

function timestamp(value: string | Date): string {
  return new Date(value).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
}

function digest(value: unknown): Buffer {
  return createHash('sha256').update(canonicalJson(value)).digest();
}

function digestString(value: Buffer): string {
  return `sha256:${value.toString('hex')}`;
}

function approvalUrn(id: string): string {
  return `urn:openpc:resource:${id}`;
}

function resourceUrn(id: string): string {
  return `urn:openpc:resource:${id}`;
}

function view(row: ApprovalRow, now = Date.now()): ApprovalRequestView {
  const state =
    row.state === 'OPEN' && new Date(row.expiresAt).getTime() <= now ? 'EXPIRED' : row.state;
  return {
    approvalRequestId: approvalUrn(row.approvalRequestId),
    actionIntentId: row.actionIntentId,
    candidateDigest: digestString(row.subjectDigest),
    state: state === 'OPEN' ? 'REQUESTED' : state,
    makerSubjectRef: resourceUrn(row.makerPrincipalId),
    checkerSubjectRef:
      row.checkerPrincipalId === null && row.decidedCheckerPrincipalId === null
        ? null
        : resourceUrn((row.checkerPrincipalId ?? row.decidedCheckerPrincipalId) as string),
    revision: row.rowVersion,
    createdAt: timestamp(row.createdAt),
    updatedAt: timestamp(row.updatedAt),
  };
}

async function begin(client: PoolClient, scope: PublicApprovalScope): Promise<void> {
  await client.query('begin isolation level serializable');
  await client.query('set local row_security=on');
  await client.query(
    `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
    [scope.participantId, scope.privacyDomainId, scope.operationId, scope.actionIntentId],
  );
}

function retryableTransactionConflict(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error.code === '40001' || error.code === '40P01')
  );
}

export async function inScope<T>(
  pool: Pool,
  scope: PublicApprovalScope,
  operation: (client: PoolClient) => Promise<T>,
  dependencies?: (client: PoolClient) => Promise<{
    readonly authorities: readonly BoundAuthority[];
    readonly rows?: AuthorityFence;
  }>,
): Promise<T> {
  return scopedTransaction(pool, scope, operation, dependencies, 3, 10);
}

// Page reads can overlap session touches from the same browser. Retry only
// known-aborted database conflicts, with a fresh snapshot and authority fence.
// Business mutations retain their existing three-attempt budget.
function inReadScope<T>(
  pool: Pool,
  scope: PublicApprovalScope,
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  return scopedTransaction(pool, scope, operation, undefined, 5, 50);
}

async function scopedTransaction<T>(
  pool: Pool,
  scope: PublicApprovalScope,
  operation: (client: PoolClient) => Promise<T>,
  dependencies: Parameters<typeof inScope<T>>[3],
  attempts: number,
  backoffMs: number,
): Promise<T> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const client = await pool.connect();
    let discard = false;
    try {
      await begin(client, scope);
      const additional = await dependencies?.(client);
      await fenceBoundAuthorities(
        client,
        scope.participantId,
        [scope.authority, ...(additional?.authorities ?? [])],
        additional?.rows,
      );
      if (
        dependencies !== undefined &&
        canonicalJson(await dependencies(client)) !== canonicalJson(additional)
      ) {
        throw new ContractError('PC-POLICY-2004');
      }
      const result = await operation(client);
      await client.query('commit');
      return result;
    } catch (error) {
      try {
        await client.query('rollback');
      } catch {
        discard = true;
        throw error;
      }
      if (error instanceof AuthorityFenceError) throw new ContractError('PC-POLICY-2004');
      if (!retryableTransactionConflict(error)) throw error;
      if (attempt === attempts - 1) throw new PolicyTransactionConflict();
    } finally {
      client.release(discard);
    }
    // Release the aborted transaction before yielding to its concurrent writer.
    // Every retry reconstructs the snapshot and revalidates the bound authority.
    await delay(backoffMs * 3 ** attempt);
  }
  throw new ContractError('PC-POLICY-2004');
}

export async function assertActionIntent(
  client: PoolClient,
  scope: PublicApprovalScope,
  operationClass: 'CREATE' | 'READ' | 'UPDATE' | 'APPROVE' | 'ACTIVATE' | 'RECOVER' | 'ROLLBACK',
  resourceTypes: readonly string[],
): Promise<Buffer> {
  const selected = await client.query<{
    readonly operationClass: string;
    readonly resourceType: string;
    readonly semanticDigest: Buffer;
  }>(
    `select operation_class as "operationClass",resource_type as "resourceType",
            semantic_digest as "semanticDigest"
       from control.action_intent where action_intent_id=$1`,
    [scope.actionIntentId],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    row === undefined ||
    row.operationClass !== operationClass ||
    !resourceTypes.includes(row.resourceType) ||
    (scope.actionIntentDigest !== undefined &&
      scope.actionIntentDigest !== digestString(row.semanticDigest))
  ) {
    throw new ContractError('PC-POLICY-2004');
  }
  return row.semanticDigest;
}

export async function approvalRow(
  client: PoolClient,
  scope: PublicApprovalScope,
  approvalRequestId: string,
  lock = false,
): Promise<ApprovalRow> {
  const selected = await client.query<ApprovalRow>(
    `select request.approval_request_id::text as "approvalRequestId",
            request.action_intent_id as "actionIntentId",request.subject_type as "subjectType",
            request.subject_id::text as "subjectId",
            request.subject_digest as "subjectDigest",request.subject_version::text as "subjectVersion",
            request.maker_principal_id::text as "makerPrincipalId",
            request.maker_authority as "makerAuthority",
            request.checker_principal_id::text as "checkerPrincipalId",
            decision.approver_principal_id::text as "decidedCheckerPrincipalId",
            request.state,request.expires_at::text as "expiresAt",
            request.row_version::text as "rowVersion",request.created_at::text as "createdAt",
            request.updated_at::text as "updatedAt"
       from control.approval_request request
       left join lateral (
         select approver_principal_id
           from control.approval_decision_record
          where participant_id=request.participant_id
            and approval_request_id=request.approval_request_id
          order by decided_at desc,approval_decision_id desc limit 1
       ) decision on true
      where request.participant_id=$1 and request.privacy_domain_id=$2
        and request.approval_request_id=$3${lock ? ' for update of request' : ''}`,
    [scope.participantId, scope.privacyDomainId, approvalRequestId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2001');
  return row;
}

export async function reserveOperation<T = PublicOperation>(
  client: PoolClient,
  scope: PublicApprovalScope,
  inputDigest: Buffer,
  expectedRevision: string,
): Promise<T | undefined> {
  if (scope.idempotencyKey === undefined || scope.actionIntentDigest === undefined) {
    throw new ContractError('PC-POLICY-2000');
  }
  const inserted = await client.query(
    `insert into control.idempotency_record
       (participant_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,
        operation_id,input_digest,expected_aggregate_version,expires_at,privacy_domain_id)
     values ($1,$2,$3,'LEGACY',$4,$5,$6,$7,clock_timestamp()+interval '24 hours',$8)
     on conflict (participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key)
       do nothing returning operation_id`,
    [
      scope.participantId,
      scope.principalId,
      scope.actionIntentId,
      scope.idempotencyKey,
      scope.operationId,
      inputDigest,
      expectedRevision,
      scope.privacyDomainId,
    ],
  );
  if (inserted.rowCount === 1) return undefined;
  const existing = await client.query<{
    readonly inputDigest: Buffer;
    readonly expectedRevision: string;
    readonly terminalState: string | null;
    readonly resultPayload: T | null;
  }>(
    `select input_digest as "inputDigest",expected_aggregate_version::text as "expectedRevision",
            terminal_state as "terminalState",result_payload as "resultPayload"
       from control.idempotency_record
      where participant_id=$1 and principal_id=$2 and action_intent_id=$3
        and privacy_domain_id=$5
        and catalog_operation_id='LEGACY' and idempotency_key=$4 for share`,
    [
      scope.participantId,
      scope.principalId,
      scope.actionIntentId,
      scope.idempotencyKey,
      scope.privacyDomainId,
    ],
  );
  const row = existing.rows[0];
  if (
    existing.rowCount !== 1 ||
    row === undefined ||
    !row.inputDigest.equals(inputDigest) ||
    row.expectedRevision !== expectedRevision ||
    row.terminalState !== 'COMMITTED' ||
    row.resultPayload === null
  ) {
    throw new ContractError('PC-POLICY-2002');
  }
  return row.resultPayload;
}

export async function completeOperation(
  client: PoolClient,
  scope: PublicApprovalScope,
  intentDigest: Buffer,
  resourceId: string,
  revision: string,
  resourceKind: 'resource' | 'policy-version' = 'resource',
): Promise<PublicOperation> {
  const now = timestamp(new Date());
  const operation: PublicOperation = {
    operationId: scope.operationId,
    actionIntentId: scope.actionIntentId,
    intentDigest: digestString(intentDigest),
    idempotencyKey: scope.idempotencyKey as string,
    resourceRef: `urn:openpc:${resourceKind}:${resourceId}`,
    revision,
    state: 'ACCEPTED',
    truthState: 'SUCCESS',
    createdAt: now,
    updatedAt: now,
  };
  const updated = await client.query(
    `update control.idempotency_record
        set result_aggregate_version=$3,result_digest=$4,result_payload=$5,
            terminal_state='COMMITTED'
      where participant_id=$1 and operation_id=$2 and terminal_state is null`,
    [scope.participantId, scope.operationId, revision, digest(operation), operation],
  );
  if (updated.rowCount !== 1) throw new ContractError('PC-POLICY-2005');
  return operation;
}

export async function createPublicPolicyApproval(
  pool: Pool,
  scope: PublicApprovalScope,
  input: {
    readonly candidateDigest: string;
    readonly makerPrincipalId: string;
    readonly checkerPrincipalId: string | null;
    readonly request: unknown;
    readonly reason: string;
    readonly resourceReservationId?: string;
    readonly authority: ApprovalCandidateAuthority;
    readonly identityRuntimeVerifier?: IdentityRuntimeVerifier;
  },
): Promise<PublicOperation> {
  return inScope(pool, scope, async (client) => {
    const intentDigest = await assertActionIntent(client, scope, 'CREATE', ['approval-requests']);
    const requestDigest = digest(input.request);
    const replay = await reserveOperation(client, scope, requestDigest, '0');
    if (replay !== undefined) return replay;
    if (input.makerPrincipalId !== scope.principalId) {
      throw new ContractError('PC-POLICY-2004');
    }
    if (input.authority.principalId !== scope.principalId) {
      throw new ContractError('PC-POLICY-2004');
    }
    const candidateDigest = Buffer.from(input.candidateDigest.slice('sha256:'.length), 'hex');
    const candidate = await client.query<{
      readonly candidateId: string;
      readonly catalogOperationId: string;
      readonly resourceId: string;
      readonly actionIntentId: string;
      readonly candidateDigest: Buffer;
      readonly expectedRevision: string;
    }>(
      `select candidate.mutation_candidate_id::text as "candidateId",
              candidate.catalog_operation_id as "catalogOperationId",candidate.resource_id::text as "resourceId",
              candidate.action_intent_id as "actionIntentId",
              candidate.candidate_digest as "candidateDigest",
              candidate.expected_revision::text as "expectedRevision"
         from control.mutation_candidate candidate
         join control.participant participant
           on participant.participant_id=candidate.participant_id
          and participant.state='ACTIVE'
          and participant.authority_epoch=candidate.maker_participant_epoch
         join control.principal principal
           on principal.participant_id=candidate.participant_id
          and principal.principal_id=candidate.maker_principal_id
          and principal.state='ACTIVE'
          and principal.authority_epoch=candidate.maker_principal_epoch
         join control.session session
           on session.participant_id=candidate.participant_id
          and session.session_id=candidate.maker_session_id
          and session.principal_id=candidate.maker_principal_id
          and session.state='ACTIVE' and session.session_epoch=candidate.maker_session_epoch
          and session.participant_epoch=candidate.maker_participant_epoch
          and session.authority_epoch=candidate.maker_principal_epoch
          and session.delegation_epoch=candidate.maker_delegation_epoch
          and session.idle_expires_at>clock_timestamp()
          and session.absolute_expires_at>clock_timestamp()
         join control.assignment assignment
           on assignment.participant_id=candidate.participant_id
          and assignment.assignment_id=candidate.maker_assignment_id
          and assignment.principal_id=candidate.maker_principal_id
          and assignment.state='ACTIVE'
          and assignment.row_version=candidate.maker_assignment_row_version
          and assignment.delegation_epoch=candidate.maker_delegation_epoch
          and assignment.maker_checker_required=true
          and assignment.valid_during @> clock_timestamp()
          and candidate.action_intent_id=any(assignment.action_intent_ids)
          and candidate.privacy_domain_id::text=any(assignment.privacy_domain_ids)
          and (candidate.resource_id::text=any(assignment.resource_ids)
               or '*'=any(assignment.resource_ids))
         join control.authority_envelope envelope
           on envelope.participant_id=candidate.participant_id
          and envelope.authority_envelope_id=candidate.maker_authority_envelope_id
          and envelope.authority_envelope_id=assignment.authority_envelope_id
          and (envelope.principal_id=candidate.maker_principal_id
            or (envelope.representation='TYPED_V1' and envelope.principal_id is null))
          and envelope.state='ACTIVE'
          and ${currentPlatformEnvelopeSql('envelope', false, true)}
          and envelope.authority_epoch=candidate.maker_authority_epoch
          and envelope.delegation_epoch=candidate.maker_delegation_epoch
          and envelope.maker_checker_required=true
          and envelope.valid_from<=clock_timestamp()
          and (envelope.valid_until is null or envelope.valid_until>clock_timestamp())
          and candidate.action_intent_id=any(envelope.action_intent_ids)
          and candidate.privacy_domain_id::text=any(envelope.privacy_domain_ids)
          and (candidate.resource_id::text=any(envelope.resource_ids)
               or '*'=any(envelope.resource_ids))
         join control.action_intent intent
           on intent.action_intent_id=candidate.action_intent_id
          and intent.resource_type=candidate.resource_type
          and intent.operation_class=candidate.operation_class
          and (intent.maker_checker_required=true or openpc.signing_governance_required(candidate.participant_id,
            candidate.privacy_domain_id,candidate.resource_id,candidate.action_intent_id)) and intent.idempotency_required=true
          and ${signingCandidateApprovalSql}
        where candidate.participant_id=$1 and candidate.privacy_domain_id=$2
          and candidate.maker_principal_id=$3 and candidate.candidate_digest=$4
          and candidate.state in ('PROPOSED','APPROVAL_REQUESTED')
          and ${currentMutationCandidateSql('candidate')}
          and candidate.expires_at>clock_timestamp()
          and candidate.maker_session_id=$5 and candidate.maker_session_epoch=$6
        for update of candidate`,
      [
        scope.participantId,
        scope.privacyDomainId,
        scope.principalId,
        candidateDigest,
        input.authority.sessionId,
        input.authority.sessionEpoch,
      ],
    );
    const candidateRow = candidate.rows[0];
    const version = await client.query<{
      readonly policyVersionId: string;
      readonly semanticDigest: Buffer;
    }>(
      `select policy_version_id::text as "policyVersionId",semantic_digest as "semanticDigest"
         from control.policy_version
        where participant_id=$1 and privacy_domain_id=$2 and semantic_digest=$3`,
      [scope.participantId, scope.privacyDomainId, candidateDigest],
    );
    const versionRow = version.rows[0];
    const envelope = await client.query<{ id: string; digest: Buffer }>(
      `select envelope_id::text as id,proposal_digest as digest
      from control.identity_envelope_proposal where participant_id=$1 and privacy_domain_id=$2 and proposal_digest=$3`,
      [scope.participantId, scope.privacyDomainId, candidateDigest],
    );
    const counts = [candidate.rowCount ?? 0, version.rowCount ?? 0, envelope.rowCount ?? 0];
    if (counts.some((count) => count > 1) || counts.reduce((sum, count) => sum + count, 0) !== 1) {
      throw new ContractError('PC-POLICY-2003');
    }
    const subject = envelope.rows[0]
      ? {
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          digest: envelope.rows[0].digest,
          id: envelope.rows[0].id,
          type: 'AUTHORITY_ENVELOPE' as const,
          version: '1',
        }
      : candidateRow === undefined
        ? versionRow === undefined
          ? undefined
          : {
              actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
              digest: versionRow.semanticDigest,
              id: versionRow.policyVersionId,
              type: 'POLICY_VERSION' as const,
              version: '1',
            }
        : {
            actionIntentId: candidateRow.actionIntentId,
            digest: candidateRow.candidateDigest,
            id: candidateRow.candidateId,
            type: 'CONFIGURATION_CANDIDATE' as const,
            version: candidateRow.expectedRevision,
          };
    if (subject === undefined || digestString(subject.digest) !== input.candidateDigest) {
      throw new ContractError('PC-POLICY-2003');
    }
    await assertRecoveryPrincipalAction(client, {
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      principalId: scope.principalId,
      actionIntentId: subject.actionIntentId,
      catalogOperationId:
        subject.type === 'AUTHORITY_ENVELOPE'
          ? 'ID-OP-ENVELOPE-CREATE'
          : candidateRow?.catalogOperationId,
      resourceId:
        subject.type === 'AUTHORITY_ENVELOPE'
          ? subject.id
          : (candidateRow?.resourceId ?? scope.authority.resourceId),
    });
    const submission =
      subject.type === 'AUTHORITY_ENVELOPE'
        ? await prepareEnvelopeSubmission(
            client,
            scope,
            input.request,
            input.identityRuntimeVerifier,
          )
        : undefined;
    if (input.checkerPrincipalId !== null) {
      const checker = await client.query(
        `select 1 from control.principal where participant_id=$1 and principal_id=$2 and state='ACTIVE'`,
        [scope.participantId, input.checkerPrincipalId],
      );
      if (checker.rowCount !== 1 || input.checkerPrincipalId === scope.principalId) {
        throw new ContractError('PC-POLICY-2004');
      }
    }
    const reservedId =
      input.resourceReservationId === undefined
        ? undefined
        : await consumeAdministrationReservation(client, scope, input.resourceReservationId, {
            purpose: 'APPROVAL_REQUEST',
            businessActionIntentId: subject.actionIntentId,
            businessResourceId: candidateRow?.resourceId ?? subject.id,
            expectedBusinessRevision: subject.version,
            checkerPrincipalId: input.checkerPrincipalId,
          });
    const inserted = await client.query<{
      readonly approvalRequestId: string;
      readonly makerPrincipalId: string;
      readonly checkerPrincipalId: string | null;
      readonly reason: string | null;
    }>(
      `insert into control.approval_request
         (participant_id,privacy_domain_id,action_intent_id,subject_type,subject_id,
          subject_digest,subject_version,maker_principal_id,checker_principal_id,
          required_approvals,state,expires_at,maker_authority,reason,approval_request_id)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,1,'OPEN',least(clock_timestamp()+$13::bigint*interval '1 millisecond',
         case when $3::varchar='${workloadSigningHandoverAdmissionOperation.actionIntentId}' and $4='CONFIGURATION_CANDIDATE'
           then (select expires_at from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2
             and mutation_candidate_id=$5 and catalog_operation_id='${workloadSigningHandoverAdmissionOperation.catalogOperationId}') end),
         $10,$11,coalesce($12::uuid,uuidv7()))
       on conflict (participant_id,subject_type,subject_id,subject_digest,state)
       do update set approval_request_id=control.approval_request.approval_request_id
       returning approval_request_id::text as "approvalRequestId",
                 maker_principal_id::text as "makerPrincipalId",
                 checker_principal_id::text as "checkerPrincipalId",reason`,
      [
        scope.participantId,
        scope.privacyDomainId,
        subject.actionIntentId,
        subject.type,
        subject.id,
        subject.digest,
        subject.version,
        scope.principalId,
        input.checkerPrincipalId,
        scope.authority,
        input.reason,
        reservedId ?? null,
        policyApprovalTtlMs(process.env),
      ],
    );
    const approval = inserted.rows[0];
    if (
      inserted.rowCount !== 1 ||
      approval === undefined ||
      (reservedId !== undefined && approval.approvalRequestId !== reservedId)
    ) {
      throw new ContractError('PC-POLICY-2005');
    }
    if (
      approval.makerPrincipalId !== scope.principalId ||
      approval.checkerPrincipalId !== input.checkerPrincipalId ||
      approval.reason !== input.reason
    ) {
      throw new ContractError('PC-POLICY-2002');
    }
    if (subject.type === 'CONFIGURATION_CANDIDATE') {
      const staged = await client.query(
        `update control.mutation_candidate
            set state='APPROVAL_REQUESTED',updated_at=clock_timestamp()
          where participant_id=$1 and privacy_domain_id=$2 and mutation_candidate_id=$3
            and state in ('PROPOSED','APPROVAL_REQUESTED')`,
        [scope.participantId, scope.privacyDomainId, subject.id],
      );
      if (staged.rowCount !== 1) throw new ContractError('PC-POLICY-2005');
    }
    if (submission)
      await commitEnvelopeSubmission(client, scope, submission, approval.approvalRequestId);
    return completeOperation(client, scope, intentDigest, approval.approvalRequestId, '1');
  });
}

export async function getPublicPolicyApproval(
  pool: Pool,
  scope: PublicApprovalScope,
  approvalRequestId: string,
): Promise<ApprovalRequestView> {
  return inReadScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['approval-requests']);
    return view(await approvalRow(client, scope, approvalRequestId));
  });
}

/** Historical proposal readback is not execution authority. Current read
 * authority is fenced even when the maker's original session has expired. */
export async function getPublicApprovalCandidate(
  pool: Pool,
  scope: PublicApprovalScope,
  approvalRequestId: string,
): Promise<ApprovalCandidateView> {
  return inReadScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['approval-requests']);
    const approval = await approvalRow(client, scope, approvalRequestId);
    if (approval.subjectType === 'AUTHORITY_ENVELOPE') {
      return readEnvelopeApprovalCandidate(client, scope, approval);
    }
    if (approval.subjectType !== 'CONFIGURATION_CANDIDATE') {
      throw new ContractError('PC-POLICY-2001');
    }
    const selected = await client.query<{
      attemptId: string;
      attempt: string;
      predecessorApprovalId: string | null;
      rawChildCount: number;
      successorLinks: unknown;
      discoveryChildRead: boolean;
      genericSuccessorApprovalId: string | null;
      businessKey: string;
      approvalUsable: boolean;
      makerSessionMatches: boolean;
      current: boolean;
      discoveryResumeEligible: boolean;
      platformResumeEligible: boolean;
      resourceId: string;
      catalogOperationId: string;
      resourceType: string;
      operationClass: string;
      document: unknown;
      state: string;
      expiresAt: string;
      operationId: string | null;
    }>(
      `select c.mutation_candidate_id::text as "attemptId",c.attempt::text as attempt,
              c.predecessor_approval_id::text as "predecessorApprovalId",
              (c.catalog_operation_id,c.action_intent_id,c.resource_type,c.operation_class)=
               ('ID-OP-WORKLOAD-ROTATE','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','participant','UPDATE') as "discoveryChildRead",
              CASE WHEN (c.catalog_operation_id,c.action_intent_id,c.resource_type,c.operation_class)=
               ('ID-OP-WORKLOAD-ROTATE','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','participant','UPDATE') THEN NULL::text ELSE
               (select r.approval_request_id::text from control.mutation_candidate s
                join control.approval_request r on r.participant_id=s.participant_id and r.privacy_domain_id=s.privacy_domain_id
                 and r.subject_id=s.mutation_candidate_id and r.subject_type='CONFIGURATION_CANDIDATE'
                where s.predecessor_candidate_id=c.mutation_candidate_id) END as "genericSuccessorApprovalId",
              (select count(*)::int from control.mutation_candidate s where s.participant_id=c.participant_id
               and s.privacy_domain_id=c.privacy_domain_id and s.predecessor_candidate_id=c.mutation_candidate_id) as "rawChildCount",
              coalesce((select jsonb_agg(jsonb_build_object('approvalId',r.approval_request_id::text,'compatible',coalesce(
               row(s.participant_id,s.privacy_domain_id,s.action_intent_id,s.catalog_operation_id,s.resource_type,s.operation_class,
                s.resource_id,s.candidate_digest,s.candidate_document,s.expected_revision,s.idempotency_key,s.maker_principal_id)=
               row(c.participant_id,c.privacy_domain_id,c.action_intent_id,c.catalog_operation_id,c.resource_type,c.operation_class,
                c.resource_id,c.candidate_digest,c.candidate_document,c.expected_revision,c.idempotency_key,c.maker_principal_id)
               and s.attempt=c.attempt+1 and s.predecessor_approval_id=$8
               and c.consumed_operation_id IS NULL and s.resume_operation_id IS NOT NULL and s.resume_request->>'command'='RESUME'
               and (s.state='CONSUMED')=(s.consumed_operation_id IS NOT NULL)
               and r.subject_type='CONFIGURATION_CANDIDATE' and r.expires_at=s.expires_at
               and r.required_approvals=(select prior.required_approvals from control.approval_request prior where prior.approval_request_id=$8
                and prior.participant_id=c.participant_id and prior.privacy_domain_id=c.privacy_domain_id)
               and r.reason=s.resume_request->>'reason'
               and r.subject_digest=s.candidate_digest and r.subject_version=s.expected_revision and r.action_intent_id=s.action_intent_id
               and r.maker_principal_id=s.maker_principal_id and r.checker_principal_id=$13
               and r.checker_principal_id<>r.maker_principal_id,false))) from control.mutation_candidate s
               left join control.approval_request r on r.participant_id=s.participant_id and r.privacy_domain_id=s.privacy_domain_id
                and r.subject_id=s.mutation_candidate_id
               where s.participant_id=c.participant_id and s.privacy_domain_id=c.privacy_domain_id
                and s.predecessor_candidate_id=c.mutation_candidate_id),'[]'::jsonb) as "successorLinks",
              c.idempotency_key as "businessKey",${currentMutationCandidateSql('c')} as current,
              (c.maker_principal_id=$9 and c.maker_session_id=$10 and c.maker_session_epoch=$11) as "makerSessionMatches",
              exists(select 1 from control.approval_decision_record d join control.mfa_challenge m
                on m.participant_id=d.participant_id and m.mfa_challenge_id=d.mfa_challenge_id
                join control.session proof_session on proof_session.participant_id=m.participant_id
                  and proof_session.session_id=m.session_id and proof_session.principal_id=m.principal_id
                  and proof_session.session_id=d.approver_session_id
                  and proof_session.session_epoch=d.approver_session_epoch
                where d.participant_id=$1 and d.privacy_domain_id=$2
                  and d.approval_request_id=$8 and d.decision='APPROVE'
                  and m.principal_id=d.approver_principal_id and m.session_id=d.approver_session_id
                  and case when proof_session.step_up_mfa_challenge_id is null
                    then m.consumed_at>clock_timestamp()-interval '5 minutes'
                    else proof_session.step_up_mfa_challenge_id=m.mfa_challenge_id
                      and openpc.session_step_up_valid_until(m.participant_id,m.session_id,m.principal_id)>clock_timestamp()
                    end
                  and m.expires_at>clock_timestamp()) as "approvalUsable",
              (c.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND
               openpc.discovery_approval_resume_eligible($1,$2,$9,$12,$8)) as "discoveryResumeEligible",
              (case when c.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' then
                coalesce((select case when original.representation='RECOVERY_V1' then
                  openpc.platform_recovery_approval_resume_subject_visible($1,$2,$9,$12,$8)
                  else true end from control.authority_envelope original
                  where original.participant_id=c.participant_id
                    and original.authority_envelope_id=c.maker_authority_envelope_id),false)
                else true end) as "platformResumeEligible",
              c.resource_id::text as "resourceId",c.catalog_operation_id as "catalogOperationId",
              c.resource_type as "resourceType",c.operation_class as "operationClass",c.candidate_document as document,
              case when c.state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED')
                    and (c.expires_at<=clock_timestamp() or not (${currentMutationCandidateSql('c')})) then 'EXPIRED' else c.state::text end as state,
              c.expires_at::text as "expiresAt",c.consumed_operation_id::text as "operationId"
         from control.mutation_candidate c
        where c.participant_id=$1 and c.privacy_domain_id=$2 and c.mutation_candidate_id=$3
          and c.action_intent_id=$4 and c.candidate_digest=$5 and c.expected_revision=$6
          and c.maker_principal_id=$7`,
      [
        scope.participantId,
        scope.privacyDomainId,
        approval.subjectId,
        approval.actionIntentId,
        approval.subjectDigest,
        approval.subjectVersion,
        approval.makerPrincipalId,
        approvalRequestId,
        scope.principalId,
        scope.authority.sessionId,
        scope.authority.sessionEpoch,
        scope.authority.authorityEnvelopeId,
        approval.checkerPrincipalId,
      ],
    );
    const row = selected.rows[0];
    if (
      selected.rowCount !== 1 ||
      row === undefined ||
      (row.state === 'CONSUMED') !== (row.operationId !== null)
    ) {
      throw new ContractError('PC-POLICY-2001');
    }
    const candidateDigest = digestString(approval.subjectDigest);
    const successorApprovalId = row.discoveryChildRead
      ? qualifyApprovalCandidateSuccessor(row.rawChildCount, row.successorLinks, row.current)
      : row.genericSuccessorApprovalId;
    const projection = projectApprovalCandidate({
      ...row,
      actionIntentId: approval.actionIntentId,
      candidateDigest,
    });
    if (
      row.catalogOperationId === 'ID-OP-WALLET-BINDING-CREATE' &&
      (projection.candidate.participantId !== scope.participantId ||
        projection.candidate.walletBindingId !== row.resourceId)
    ) {
      throw new ContractError('PC-POLICY-2001');
    }
    if (row.catalogOperationId === 'ID-OP-ENVELOPE-CREATE' && row.state === 'CONSUMED') {
      const creation = await readEnvelopeCreation(client, scope, row.resourceId);
      if (
        creation.original.candidateId !== row.attemptId ||
        !creation.original.candidateDigest.equals(approval.subjectDigest) ||
        creation.original.operationId !== row.operationId
      )
        throw new ContractError('PC-POLICY-2001');
    }
    const deploymentIntent =
      row.catalogOperationId === 'CFG-OP-SUBMIT-DEPLOYMENT'
        ? await readStoredDeploymentIntent(client, {
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            makerPrincipalId: approval.makerPrincipalId,
            deploymentIntentId: String(projection.candidate.deploymentIntentId).slice(
              'urn:openpc:resource:'.length,
            ),
          })
        : null;
    return approvalCandidateResponseSchema.parse({
      approvalRequestId: approvalUrn(approvalRequestId),
      attemptId: row.attemptId,
      attempt: row.attempt,
      predecessorApprovalRef:
        row.predecessorApprovalId === null ? null : approvalUrn(row.predecessorApprovalId),
      successorApprovalRef: successorApprovalId === null ? null : approvalUrn(successorApprovalId),
      businessIdempotencyKey:
        scope.principalId === approval.makerPrincipalId ? row.businessKey : null,
      approvalUsable:
        row.approvalUsable &&
        row.current &&
        row.state === 'APPROVED' &&
        approval.state === 'APPROVED' &&
        Date.parse(approval.expiresAt) > Date.now(),
      makerSessionMatches: row.makerSessionMatches,
      canRequestResume:
        (row.catalogOperationId !== 'ID-OP-PLATFORM-SCOPE-PREPARE' ||
          row.platformResumeEligible === true) &&
        (isModuleInstallResumeCandidate({ ...row, actionIntentId: approval.actionIntentId }) ||
          isRuntimeProfileResumeCandidate({ ...row, actionIntentId: approval.actionIntentId }) ||
          row.discoveryResumeEligible ||
          isEnvelopeCreateResumeCandidate({
            ...row,
            participantId: scope.participantId,
            actionIntentId: approval.actionIntentId,
            expectedRevision: approval.subjectVersion,
          }) ||
          [
            'MOD-OP-REGISTER',
            'ID-OP-ASSIGNMENT-CREATE',
            'ID-OP-ENVELOPE-ACTIVATE',
            'ID-OP-PLATFORM-SCOPE-PREPARE',
            'ID-OP-PLATFORM-SCOPE-COMMIT',
            'CFG-OP-CREATE-EVIDENCE-HOLD',
            'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD',
            'CFG-OP-DELETE-PROJECTION-BATCH',
            'CFG-OP-ACTIVATE-RETENTION-POLICY',
            'CFG-OP-ADMIT-STORE-RETIREMENT',
            'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
            'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH',
            'CFG-OP-QUALIFY-PROVIDER-PROFILE',
            'CFG-OP-CREATE-PROVIDER-PROFILE',
            'CFG-OP-CREATE-ABI-ARTIFACT',
            'CFG-OP-CREATE-LOGICAL-CONTRACT',
            'CFG-OP-CREATE-RUNTIME-BINDING',
            'CFG-OP-CREATE-METHOD-POLICY',
          ].includes(row.catalogOperationId)) &&
        row.current &&
        row.operationId === null &&
        ['OPEN', 'APPROVED', 'EXPIRED'].includes(approval.state) &&
        (row.state === 'EXPIRED' ||
          Date.parse(approval.expiresAt) <= Date.now() ||
          (approval.state === 'APPROVED' && !row.approvalUsable)),
      candidateDigest,
      actionIntentId: approval.actionIntentId,
      resourceRef: resourceUrn(row.resourceId),
      expectedRevision: approval.subjectVersion,
      state: row.state,
      expiresAt: timestamp(row.expiresAt),
      operationRef: row.operationId === null ? null : `urn:openpc:operation:${row.operationId}`,
      runtimePermission: 'NONE',
      deploymentIntent,
      ...projection,
    });
  });
}

export async function listPublicPolicyApprovals(
  pool: Pool,
  scope: PublicApprovalScope,
  request: PublicApprovalListRequest,
): Promise<PublicApprovalPage> {
  return inReadScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['approval-requests']);
    const values: unknown[] = [
      scope.participantId,
      scope.privacyDomainId,
      request.snapshotAt,
      scope.principalId,
      scope.authority.sessionId,
    ];
    const stateExpression =
      "case when request.state='OPEN' and request.expires_at <= $3::timestamptz then 'EXPIRED' " +
      "when request.state='OPEN' then 'REQUESTED' else request.state::text end";
    const filterColumns = {
      actionIntentId: 'request.action_intent_id',
      approvalRequestId: "'urn:openpc:resource:'||request.approval_request_id::text",
      candidateDigest: "'sha256:'||encode(request.subject_digest,'hex')",
      checkerSubjectRef:
        "'urn:openpc:resource:'||coalesce(request.checker_principal_id,decision.approver_principal_id)::text",
      makerSubjectRef: "'urn:openpc:resource:'||request.maker_principal_id::text",
      state: stateExpression,
    } as const;
    const where = [
      'request.participant_id=$1',
      'request.privacy_domain_id=$2',
      'request.updated_at <= $3::timestamptz',
      approvalReadAuthoritySql,
    ];
    if (request.filter !== undefined) {
      values.push(request.filter.value);
      const column = filterColumns[request.filter.field];
      const parameter = `$${values.length}`;
      where.push(
        request.filter.operator === 'eq'
          ? `${column}=${parameter}`
          : request.filter.operator === 'ne'
            ? `${column}<>${parameter}`
            : `${column} like replace(replace(replace(${parameter},'\\','\\\\'),'%','\\%'),'_','\\_')||'%' escape '\\'`,
      );
    }
    const from = `from control.approval_request request
         left join lateral (
           select approver_principal_id
             from control.approval_decision_record
            where participant_id=request.participant_id
              and approval_request_id=request.approval_request_id
            order by decided_at desc,approval_decision_id desc limit 1
         ) decision on true`;
    const count = await client.query<{ readonly total: string }>(
      `select count(*)::text as total ${from} where ${where.join(' and ')}`,
      values,
    );
    const pageWhere = [...where];
    if (request.after !== undefined) {
      values.push(request.after.updatedAt, request.after.id);
      const comparison = request.sort === '-updatedAt' ? '<' : '>';
      pageWhere.push(
        `(request.updated_at,request.approval_request_id) ${comparison} ` +
          `($${values.length - 1}::timestamptz,$${values.length}::uuid)`,
      );
    }
    values.push(request.limit + 1);
    const direction = request.sort === '-updatedAt' ? 'desc' : 'asc';
    const selected = await client.query<ApprovalRow>(
      `select request.approval_request_id::text as "approvalRequestId",
              request.action_intent_id as "actionIntentId",request.subject_type as "subjectType",
              request.subject_id::text as "subjectId",
              request.subject_digest as "subjectDigest",request.subject_version::text as "subjectVersion",
              request.maker_principal_id::text as "makerPrincipalId",
              request.checker_principal_id::text as "checkerPrincipalId",
              decision.approver_principal_id::text as "decidedCheckerPrincipalId",
              request.state,request.expires_at::text as "expiresAt",
              request.row_version::text as "rowVersion",request.created_at::text as "createdAt",
              request.updated_at::text as "updatedAt"
         ${from}
        where ${pageWhere.join(' and ')}
        order by request.updated_at ${direction},request.approval_request_id ${direction}
        limit $${values.length}`,
      values,
    );
    const hasNext = selected.rows.length > request.limit;
    const rows = selected.rows.slice(0, request.limit);
    const last = hasNext ? rows.at(-1) : undefined;
    return {
      items: rows.map((row) => view(row, Date.parse(request.snapshotAt))),
      ...(last === undefined
        ? {}
        : { next: { updatedAt: timestamp(last.updatedAt), id: last.approvalRequestId } }),
      total: count.rows[0]?.total ?? '0',
      snapshotRevision: request.snapshotRevision,
    };
  });
}

export async function updatePublicPolicyApproval(
  pool: Pool,
  scope: PublicApprovalScope,
  approvalRequestId: string,
  expectedRevision: string,
  replacementDigest: string,
  request: unknown,
): Promise<PublicOperation> {
  return inScope(pool, scope, async (client) => {
    const intentDigest = await assertActionIntent(client, scope, 'UPDATE', ['approval-requests']);
    const requestDigest = digest(request);
    const replay = await reserveOperation(client, scope, requestDigest, expectedRevision);
    if (replay !== undefined) return replay;
    const current = await approvalRow(client, scope, approvalRequestId, true);
    if (
      current.subjectType !== 'POLICY_VERSION' ||
      current.state !== 'OPEN' ||
      new Date(current.expiresAt).getTime() <= Date.now() ||
      current.rowVersion !== expectedRevision ||
      current.makerPrincipalId !== scope.principalId ||
      digestString(current.subjectDigest) === replacementDigest
    ) {
      throw new ContractError('PC-POLICY-2003');
    }
    const replacement = await client.query<{ readonly policyVersionId: string }>(
      `select policy_version_id::text as "policyVersionId"
         from control.policy_version
        where participant_id=$1 and privacy_domain_id=$2 and semantic_digest=$3`,
      [
        scope.participantId,
        scope.privacyDomainId,
        Buffer.from(replacementDigest.slice('sha256:'.length), 'hex'),
      ],
    );
    const replacementRow = replacement.rows[0];
    if (replacement.rowCount !== 1 || replacementRow === undefined) {
      throw new ContractError('PC-POLICY-2003');
    }
    const duplicate = await client.query(
      `select 1 from control.approval_request
        where participant_id=$1 and subject_type='POLICY_VERSION' and subject_id=$2
          and subject_digest=$3 and state='OPEN' and approval_request_id<>$4`,
      [
        scope.participantId,
        replacementRow.policyVersionId,
        Buffer.from(replacementDigest.slice('sha256:'.length), 'hex'),
        approvalRequestId,
      ],
    );
    if (duplicate.rowCount !== 0) throw new ContractError('PC-POLICY-2002');
    const updated = await client.query<{ readonly revision: string }>(
      `update control.approval_request
          set subject_id=$4,subject_digest=$5,subject_version=subject_version+1,
              maker_authority=$6,
              row_version=row_version+1,updated_at=clock_timestamp()
        where participant_id=$1 and approval_request_id=$2 and row_version=$3 and state='OPEN'
        returning row_version::text as revision`,
      [
        scope.participantId,
        approvalRequestId,
        expectedRevision,
        replacementRow.policyVersionId,
        Buffer.from(replacementDigest.slice('sha256:'.length), 'hex'),
        scope.authority,
      ],
    );
    const row = updated.rows[0];
    if (updated.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2002');
    return completeOperation(client, scope, intentDigest, approvalRequestId, row.revision);
  });
}

export async function approvePublicPolicyApproval(
  pool: Pool,
  scope: PublicApprovalScope,
  authority: ApprovalDecisionAuthority,
  approvalRequestId: string,
  expectedRevision: string,
  inputDigest: string,
  identityRuntimeVerifier?: IdentityRuntimeVerifier,
): Promise<PublicOperation> {
  let handoverAdmission: Awaited<
    ReturnType<typeof approvalDecisionAuthorityDependencies>
  >['handoverAdmission'];
  return inScope(
    pool,
    scope,
    async (client) => {
      const intentDigest = await assertActionIntent(client, scope, 'APPROVE', ['approval-request']);
      const inputDigestBytes = Buffer.from(inputDigest.slice('sha256:'.length), 'hex');
      const replay = await reserveOperation(client, scope, inputDigestBytes, expectedRevision);
      if (replay !== undefined) return replay;
      if (handoverAdmission) {
        if (!identityRuntimeVerifier) throw new ContractError('PC-POLICY-2004');
        try {
          await assertCurrentHandoverAdmissionCandidate(
            client,
            {
              participantId: scope.participantId,
              privacyDomainId: scope.privacyDomainId,
              environmentId: handoverAdmission.candidate.environmentId,
              authority: handoverAdmission.maker,
              verifier: identityRuntimeVerifier,
            },
            handoverAdmission.candidate,
          );
        } catch (error) {
          if (error instanceof WorkloadSigningHandoverStoreError)
            throw new ContractError(error.code === 'DENIED' ? 'PC-POLICY-2004' : 'PC-POLICY-2005');
          throw error;
        }
      }
      const current = await approvalRow(client, scope, approvalRequestId, true);
      const expectedInputDigest = digestString(
        digest({
          actionIntentId: scope.actionIntentId,
          approvalRequestId: approvalUrn(approvalRequestId),
          candidateDigest: digestString(current.subjectDigest),
          expectedRevision,
          decision: 'APPROVE',
        }),
      );
      if (
        current.state !== 'OPEN' ||
        new Date(current.expiresAt).getTime() <= Date.now() ||
        current.rowVersion !== expectedRevision ||
        current.makerPrincipalId === scope.principalId ||
        (current.checkerPrincipalId !== null && current.checkerPrincipalId !== scope.principalId) ||
        inputDigest !== expectedInputDigest
      ) {
        throw new ContractError('PC-POLICY-2004');
      }
      const stepUpBinding = {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        principalId: scope.principalId,
        operationId: scope.operationId,
        actionIntentId: scope.actionIntentId,
        resourceDigest: inputDigestBytes,
        resourceId: current.subjectType === 'AUTHORITY_ENVELOPE' ? approvalRequestId : undefined,
        sessionId: authority.sessionId,
        participantEpoch: authority.participantEpoch,
        principalEpoch: authority.principalEpoch,
      };
      const envelopeDecision =
        current.subjectType === 'AUTHORITY_ENVELOPE'
          ? await prepareEnvelopeDecision(
              client,
              scope,
              approvalRequestId,
              current.subjectDigest,
              stepUpBinding,
              identityRuntimeVerifier,
            )
          : undefined;
      const verified =
        envelopeDecision?.proof.record ?? (await lockLiveStepUpRecord(client, stepUpBinding));
      const inserted = await client.query(
        `insert into control.approval_decision_record
         (participant_id,privacy_domain_id,approval_request_id,approver_principal_id,
          approver_participant_epoch,approver_principal_epoch,approver_authority_envelope_id,
          approver_envelope_epoch,approver_assignment_id,approver_assignment_row_version,
          approver_delegation_epoch,signer_credential_id,mfa_challenge_id,aggregate_version,
          candidate_digest,decision,decision_digest,evidence_cbor,cose_sign1,
          approver_session_id,approver_session_epoch,signer_credential_epoch)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'APPROVE',$16,$17,$18,$19,$20,$21)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          approvalRequestId,
          scope.principalId,
          authority.participantEpoch,
          authority.principalEpoch,
          authority.authorityEnvelopeId,
          authority.authorityEpoch,
          authority.assignmentId,
          authority.assignmentRowVersion,
          authority.delegationEpoch,
          verified.signerCredentialId,
          verified.mfaChallengeId,
          current.subjectVersion,
          current.subjectDigest,
          inputDigestBytes,
          verified.evidenceCbor,
          verified.coseSign1,
          authority.sessionId,
          authority.sessionEpoch,
          verified.signerCredentialEpoch,
        ],
      );
      if (inserted.rowCount !== 1) throw new ContractError('PC-POLICY-2005');
      const updated = await client.query<{ readonly revision: string }>(
        `update control.approval_request
          set state='APPROVED',row_version=row_version+1,updated_at=clock_timestamp()
        where participant_id=$1 and approval_request_id=$2 and state='OPEN' and row_version=$3
        returning row_version::text as revision`,
        [scope.participantId, approvalRequestId, expectedRevision],
      );
      const updatedRow = updated.rows[0];
      if (updated.rowCount !== 1 || updatedRow === undefined) {
        throw new ContractError('PC-POLICY-2005');
      }
      if (current.subjectType === 'CONFIGURATION_CANDIDATE') {
        const approvedCandidate = await client.query(
          `update control.mutation_candidate
            set state='APPROVED',updated_at=clock_timestamp()
          where participant_id=$1 and privacy_domain_id=$2 and mutation_candidate_id=$3
            and action_intent_id=$4 and candidate_digest=$5
            and expected_revision=$6 and state='APPROVAL_REQUESTED'
            and expires_at>clock_timestamp()`,
          [
            scope.participantId,
            scope.privacyDomainId,
            current.subjectId,
            current.actionIntentId,
            current.subjectDigest,
            current.subjectVersion,
          ],
        );
        if (approvedCandidate.rowCount !== 1) throw new ContractError('PC-POLICY-2005');
      }
      if (envelopeDecision) await commitEnvelopeDecision(client, scope, envelopeDecision);
      await consumeLiveStepUpRecord(client, stepUpBinding, verified);
      if (current.actionIntentId === signingRotationActions.create) {
        await consumeSigningRotationApproval(client, scope, approvalRequestId);
      }
      const sequence = await client.query<{ readonly sequence: string }>(
        `insert into control.outbox_aggregate_head
         (participant_id,aggregate_type,aggregate_id,last_sequence)
       values ($1,'approval-request',$2,1)
       on conflict (participant_id,aggregate_type,aggregate_id) do update
         set last_sequence=control.outbox_aggregate_head.last_sequence+1,
             updated_at=clock_timestamp()
       returning last_sequence::text as sequence`,
        [scope.participantId, approvalRequestId],
      );
      const sequenceRow = sequence.rows[0];
      if (sequence.rowCount !== 1 || sequenceRow === undefined) {
        throw new ContractError('PC-POLICY-2005');
      }
      await client.query(
        `insert into control.outbox_event
         (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
          aggregate_sequence,payload_cbor,payload_digest,cose_sign1,
          webauthn_assertion_binding_digest,occurred_at)
       values ($1,$2,uuidv7(),'openpc.policy.approval-request.approved.v1',
               'approval-request',$3,$4,$5,$6,$7,$8,clock_timestamp())`,
        [
          scope.participantId,
          scope.privacyDomainId,
          approvalRequestId,
          sequenceRow.sequence,
          verified.evidenceCbor,
          verified.evidenceDigest,
          verified.coseSign1,
          verified.assertionBindingDigest,
        ],
      );
      return completeOperation(client, scope, intentDigest, approvalRequestId, updatedRow.revision);
    },
    async (client) => {
      const approval = await approvalDecisionAuthorityDependencies(
        client,
        scope,
        approvalRequestId,
        scope.authority,
      );
      handoverAdmission = approval.handoverAdmission;
      const stepUp = await stepUpCredentialDependencies(
        client,
        scope,
        authority.sessionId,
        Buffer.from(inputDigest.slice('sha256:'.length), 'hex'),
      );
      return {
        authorities: approval.authorities,
        rows: {
          ...approval.rows,
          ...stepUp,
          credential: [...(approval.rows.credential ?? []), ...(stepUp.credential ?? [])],
        },
      };
    },
  );
}
