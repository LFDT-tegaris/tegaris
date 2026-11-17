import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

import type { Pool, PoolClient } from 'pg';
import { lockAuthorityFence } from '../../../identity-service/src/db/authority-fence.js';
import { fenceWorkloadPredictionAuthor } from '../../../identity-service/src/domain/workload-policy-prediction.js';

import { type EvaluationResult } from '../domain/policy-evaluator.js';
import { PolicyFactReader } from '../domain/policy-facts.js';
import {
  validatePolicySemantics,
  readActiveVisibilityDocument,
  type PolicySimulationRequest,
} from '../domain/policy-semantics.js';
import type { AuthorizedPolicyActor } from '../policy-http.js';
import { materializePolicySimulation } from './policy-simulation-input.js';
import { canonicalJson } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';
import {
  decodePolicyActivationAuthorizationPayload,
  verifyPolicyActivationAuthorizationCose,
} from '../domain/policy-activation-authorization.js';

export interface PolicyRuntimeScope {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly operationId: string;
  readonly actionIntentId: string;
}

export interface PolicySimulationResult {
  readonly simulationId: string;
  readonly policyVersionId: string;
  readonly authorityLabel: 'SIMULATION_ONLY';
  readonly evaluation: EvaluationResult;
  readonly completedAt: Date;
}

export interface PolicyApprovalActor {
  readonly participantId: string;
  readonly principalId: string;
  readonly principalEpoch: string;
  readonly assignmentId: string;
  readonly authorityEnvelopeId: string;
  readonly authorityEpoch: string;
}

function bytes(value: string): Buffer {
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new ContractError('PC-POLICY-2003');
  return Buffer.from(value, 'hex');
}

function digest(value: Buffer): Buffer {
  return createHash('sha256').update(value).digest();
}

async function scoped<T>(
  pool: Pool,
  scope: PolicyRuntimeScope,
  callback: (client: PoolClient) => Promise<T>,
  isolation = 'read committed',
  retrySerialization = false,
): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    const client = await pool.connect();
    try {
      await client.query(`begin isolation level ${isolation}`);
      await client.query('set local row_security=on');
      await client.query('select openpc.set_request_context($1,$2,$3,$4,$5,true)', [
        'PARTICIPANT',
        scope.participantId,
        scope.privacyDomainId,
        scope.operationId,
        scope.actionIntentId,
      ]);
      const result = await callback(client);
      await client.query('commit');
      return result;
    } catch (error) {
      const rolledBack = await client.query('rollback').then(
        () => true,
        () => false,
      );
      if (
        !retrySerialization ||
        isolation !== 'serializable' ||
        !rolledBack ||
        attempt >= 2 ||
        typeof error !== 'object' ||
        error === null ||
        !('code' in error) ||
        error.code !== '40001'
      )
        throw error;
    } finally {
      client.release();
    }
    // Retry only a confirmed aborted transaction, after releasing its locks.
    // The callback reloads facts and repeats every authority fence on each attempt.
    await delay(10 * 3 ** attempt);
  }
}

export async function simulatePolicyVersion(
  pool: Pool,
  scope: PolicyRuntimeScope,
  policyVersionId: string,
  request: PolicySimulationRequest,
  actor: AuthorizedPolicyActor,
  revalidateActor: () => Promise<AuthorizedPolicyActor>,
  facts = new PolicyFactReader(),
): Promise<PolicySimulationResult> {
  if (actor.participantId !== scope.participantId) throw new ContractError('PC-POLICY-2004');
  return scoped(
    pool,
    scope,
    async (client) => {
      const workloadBound =
        'indexerProfileId' in request ||
        'visibilityPolicyId' in request ||
        ('contractMethodPolicyId' in request &&
          request.workloadId !== undefined &&
          request.assignmentId !== undefined);
      if (workloadBound)
        await lockAuthorityFence(client, scope.participantId, {
          participant: [{ id: scope.participantId, write: true }],
        });
      const version = await client.query<{
        dependency_closure_digest: Buffer;
        policy_version_id: string;
        semantic_digest: Buffer;
        semantic_cbor: Buffer;
      }>(
        `select version.policy_version_id,version.semantic_digest,artifact.dependency_closure_digest,artifact.semantic_cbor
         from control.policy_version version
         join control.policy_artifact artifact
           on (artifact.participant_id,artifact.privacy_domain_id,artifact.policy_id,
               artifact.semantic_version,artifact.semantic_digest)=
              (version.participant_id,version.privacy_domain_id,version.policy_id,
               version.version,version.semantic_digest)
        where version.participant_id=$1 and version.privacy_domain_id=$2
          and version.policy_version_id=$3`,
        [scope.participantId, scope.privacyDomainId, policyVersionId],
      );
      const row = version.rows[0];
      if (version.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2001');
      const { evaluation, factDigest } = await materializePolicySimulation(
        client,
        row,
        actor,
        scope.privacyDomainId,
        request,
        facts,
      );
      if (workloadBound) {
        await fenceWorkloadPredictionAuthor(client, scope.participantId, {
          ...actor,
          privacyDomainId: scope.privacyDomainId,
          actionIntentId: scope.actionIntentId,
          resourceId: policyVersionId,
        });
      } else if (canonicalJson(await revalidateActor()) !== canonicalJson(actor))
        throw new ContractError('PC-POLICY-2004', 'simulation authority changed');
      const inputDigest = bytes(evaluation.inputDigest);
      const resultDigest = bytes(evaluation.resultDigest);
      const inserted = await client.query<{ completed_at: Date; simulation_id: string }>(
        `insert into control.policy_simulation
         (participant_id,privacy_domain_id,policy_version_id,input_digest,result_digest,
          fact_generation_digest,dependency_closure_digest,truth_state,authority_label,
          result_document,completed_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,'SIMULATION_ONLY',$9,clock_timestamp())
       on conflict (participant_id,policy_version_id,input_digest,fact_generation_digest)
       do nothing
       returning simulation_id,completed_at`,
        [
          scope.participantId,
          scope.privacyDomainId,
          policyVersionId,
          inputDigest,
          resultDigest,
          factDigest,
          row.dependency_closure_digest,
          evaluation.truthState,
          evaluation,
        ],
      );
      let stored = inserted.rows[0];
      if (inserted.rowCount !== 1) {
        const replay = await client.query<{
          authority_label: string;
          completed_at: Date;
          dependency_closure_digest: Buffer;
          result_digest: Buffer;
          simulation_id: string;
          truth_state: string;
        }>(
          `select simulation_id,result_digest,dependency_closure_digest,truth_state,
                authority_label,completed_at
           from control.policy_simulation
          where participant_id=$1 and policy_version_id=$2 and input_digest=$3
            and fact_generation_digest=$4`,
          [scope.participantId, policyVersionId, inputDigest, factDigest],
        );
        const prior = replay.rows[0];
        if (
          replay.rowCount !== 1 ||
          prior === undefined ||
          !prior.result_digest.equals(resultDigest) ||
          !prior.dependency_closure_digest.equals(row.dependency_closure_digest) ||
          prior.truth_state !== evaluation.truthState ||
          prior.authority_label !== 'SIMULATION_ONLY'
        ) {
          throw new ContractError('PC-POLICY-2002');
        }
        stored = prior;
      }
      if (stored === undefined) throw new ContractError('PC-POLICY-2005');
      return {
        simulationId: stored.simulation_id,
        policyVersionId,
        authorityLabel: 'SIMULATION_ONLY',
        evaluation,
        completedAt: stored.completed_at,
      };
    },
    'serializable',
    true,
  );
}

export async function evaluateActivePolicy(
  pool: Pool,
  scope: PolicyRuntimeScope,
  scopeDigest: Buffer,
  request: PolicySimulationRequest,
  actor: AuthorizedPolicyActor,
  revalidateActor: () => Promise<AuthorizedPolicyActor>,
  facts = new PolicyFactReader(),
): Promise<EvaluationResult> {
  return (
    await evaluateActivePolicyView(pool, scope, scopeDigest, request, actor, revalidateActor, facts)
  ).evaluation;
}

export async function evaluateActivePolicyView(
  pool: Pool,
  scope: PolicyRuntimeScope,
  scopeDigest: Buffer,
  request: PolicySimulationRequest,
  actor: AuthorizedPolicyActor,
  revalidateActor: () => Promise<AuthorizedPolicyActor>,
  facts = new PolicyFactReader(),
) {
  if (scopeDigest.length !== 32 || actor.participantId !== scope.participantId)
    throw new ContractError('PC-POLICY-2004');
  return scoped(pool, scope, async (client) => {
    if ('indexerProfileId' in request || 'visibilityPolicyId' in request)
      await lockAuthorityFence(client, scope.participantId, {
        participant: [{ id: scope.participantId, write: true }],
      });
    const active = await client.query<{
      generation_digest: Buffer;
      policy_schema_digest: Buffer;
      policy_version_id: string;
      dependency_closure_digest: Buffer;
      fact_generation_digest: Buffer;
      semantic_digest: Buffer;
      semantic_cbor: Buffer;
    }>(
      `select generation.generation_digest,version.policy_version_id,generation.fact_generation_digest,generation.dependency_closure_digest,
              version.semantic_digest,artifact.semantic_cbor,artifact.policy_schema_digest
         from control.policy_generation generation
         join control.policy_version version
           on (version.participant_id,version.privacy_domain_id,version.policy_version_id)=
              (generation.participant_id,generation.privacy_domain_id,generation.policy_version_id)
         join control.policy_artifact artifact
           on (artifact.participant_id,artifact.privacy_domain_id,artifact.policy_id,artifact.semantic_version,artifact.semantic_digest)=
              (version.participant_id,version.privacy_domain_id,version.policy_id,version.version,version.semantic_digest)
        where generation.participant_id=$1 and generation.privacy_domain_id=$2
          and generation.scope_digest=$3 and generation.state='ACTIVE' and generation.active=true
        for share of generation`,
      [scope.participantId, scope.privacyDomainId, scopeDigest],
    );
    const row = active.rows[0];
    if (active.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2001');
    const document =
      'visibilityPolicyId' in request
        ? readActiveVisibilityDocument(
            row.semantic_cbor,
            row.policy_schema_digest,
            request.visibilityPolicyId,
          )
        : validatePolicySemantics(Array.from(row.semantic_cbor), 'DECODE_SEMANTICS').document;
    const resolved = await materializePolicySimulation(
      client,
      row,
      actor,
      scope.privacyDomainId,
      request,
      facts,
      true,
    );
    if ('indexerProfileId' in request || 'visibilityPolicyId' in request) {
      await fenceWorkloadPredictionAuthor(client, scope.participantId, {
        ...actor,
        privacyDomainId: scope.privacyDomainId,
        actionIntentId: scope.actionIntentId,
        resourceId: `sha256:${scopeDigest.toString('hex')}`,
      });
    } else if (canonicalJson(await revalidateActor()) !== canonicalJson(actor))
      throw new ContractError('PC-POLICY-2004', 'evaluation authority changed');
    if (!resolved.factDigest.equals(row.fact_generation_digest))
      throw new ContractError('PC-POLICY-2003', 'active policy fact generation changed');
    const visibility =
      'visibilityPolicyId' in request
        ? document.visibilityPolicies?.find(
            (policy) => policy.policyId === request.visibilityPolicyId,
          )
        : undefined;
    const subjectRef =
      visibility?.subject.kind === 'WORKLOAD'
        ? visibility.subject.workloadId
        : `urn:openpc:principal:${actor.principalId}`;
    const resource = visibility?.selector;
    const resourceId =
      resource?.kind === 'DISCLOSURE'
        ? resource.profileId
        : resource?.kind === 'STATE_READ'
          ? resource.contractMethodPolicyId
          : resource?.runtimeBindingId;
    return {
      evaluation: resolved.evaluation,
      authorityGeneration: `sha256:${row.generation_digest.toString('hex')}`,
      subjectRef,
      resourceRef: `urn:openpc:resource:${resourceId ?? row.policy_version_id}`,
      explanationRefs: [`urn:openpc:policy-version:${row.policy_version_id}`],
    };
  });
}

export async function createPolicyApprovalRequest(
  pool: Pool,
  scope: PolicyRuntimeScope,
  makerPrincipalId: string,
  policyVersionId: string,
  candidateDigest: Buffer,
): Promise<{ approvalRequestId: string; expiresAt: Date }> {
  if (candidateDigest.length !== 32) throw new ContractError('PC-POLICY-2003');
  return scoped(pool, scope, async (client) => {
    const version = await client.query<{ semantic_digest: Buffer }>(
      `select semantic_digest from control.policy_version
        where participant_id=$1 and privacy_domain_id=$2 and policy_version_id=$3`,
      [scope.participantId, scope.privacyDomainId, policyVersionId],
    );
    const versionRow = version.rows[0];
    if (version.rowCount !== 1 || versionRow === undefined) {
      throw new ContractError('PC-POLICY-2001');
    }
    if (!versionRow.semantic_digest.equals(candidateDigest)) {
      throw new ContractError('PC-POLICY-2003');
    }
    const inserted = await client.query<{ approval_request_id: string; expires_at: Date }>(
      `insert into control.approval_request
         (participant_id,privacy_domain_id,action_intent_id,subject_type,subject_id,
          subject_digest,subject_version,maker_principal_id,required_approvals,state,expires_at)
       values ($1,$2,'ACT-POLICY_APPROVE_REQUEST-V1','POLICY_VERSION',$3,$4,1,$5,1,'OPEN',
               clock_timestamp()+interval '30 minutes')
       on conflict (participant_id,subject_type,subject_id,subject_digest,state)
       do update set approval_request_id=control.approval_request.approval_request_id
       returning approval_request_id,expires_at`,
      [
        scope.participantId,
        scope.privacyDomainId,
        policyVersionId,
        candidateDigest,
        makerPrincipalId,
      ],
    );
    const row = inserted.rows[0];
    if (inserted.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2005');
    return { approvalRequestId: row.approval_request_id, expiresAt: row.expires_at };
  });
}

export async function approvePolicyRequest(
  pool: Pool,
  scope: PolicyRuntimeScope,
  actor: PolicyApprovalActor,
  approvalRequestId: string,
  signerCredentialId: string,
  evidenceCbor: Buffer,
  coseSign1: Buffer,
): Promise<{ approvalRequestId: string; decidedAt: Date }> {
  return scoped(
    pool,
    scope,
    async (client) => {
      const locked = await client.query<{
        candidate_digest: Buffer;
        credential_epoch: string;
        expires_at: Date;
        maker_principal_id: string;
        public_key_spki_der: Buffer;
        state: string;
        subject_version: string;
      }>(
        `select request.subject_digest candidate_digest,request.subject_version::text,
                request.maker_principal_id,request.state,request.expires_at,
                credential.credential_epoch::text,credential.public_key_spki_der
           from control.approval_request request
           join control.credential credential
             on credential.participant_id=request.participant_id
            and credential.principal_id=$4 and credential.credential_id=$5
            and credential.kind='WEBAUTHN' and credential.state='ACTIVE'
            and credential.valid_from<=clock_timestamp()
            and (credential.valid_until is null or credential.valid_until>clock_timestamp())
          where request.participant_id=$1 and request.privacy_domain_id=$2
            and request.approval_request_id=$3 for update of request,credential`,
        [
          scope.participantId,
          scope.privacyDomainId,
          approvalRequestId,
          actor.principalId,
          signerCredentialId,
        ],
      );
      const row = locked.rows[0];
      if (locked.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2005');
      const payload = decodePolicyActivationAuthorizationPayload(evidenceCbor);
      const now = Date.now();
      if (
        row.state !== 'OPEN' ||
        row.expires_at.getTime() <= now ||
        row.maker_principal_id === actor.principalId ||
        payload.participantId !== `urn:openpc:participant:${scope.participantId}` ||
        payload.checkerPrincipalId !== `urn:openpc:principal:${actor.principalId}` ||
        payload.checkerPrincipalEpoch !== actor.principalEpoch ||
        payload.approvalRequestId !== approvalRequestId ||
        payload.aggregateVersion !== row.subject_version ||
        !payload.candidateDigest.equals(row.candidate_digest) ||
        Date.parse(payload.issuedAt) > now + 5_000 ||
        now - Date.parse(payload.issuedAt) > 5 * 60 * 1000 ||
        Date.parse(payload.expiresAt) <= now ||
        Date.parse(payload.expiresAt) - Date.parse(payload.issuedAt) > 5 * 60 * 1000 ||
        !verifyPolicyActivationAuthorizationCose(row.public_key_spki_der, evidenceCbor, coseSign1)
      ) {
        throw new ContractError('PC-POLICY-2004');
      }
      const inserted = await client.query<{ decided_at: Date }>(
        `insert into control.approval_decision_record
           (participant_id,privacy_domain_id,approval_request_id,approver_principal_id,
            approver_principal_epoch,approver_authority_envelope_id,approver_envelope_epoch,
            approver_assignment_id,signer_credential_id,aggregate_version,candidate_digest,
            decision,decision_digest,evidence_cbor,cose_sign1)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'APPROVE',$12,$13,$14)
         returning decided_at`,
        [
          scope.participantId,
          scope.privacyDomainId,
          approvalRequestId,
          actor.principalId,
          actor.principalEpoch,
          actor.authorityEnvelopeId,
          actor.authorityEpoch,
          actor.assignmentId,
          signerCredentialId,
          payload.aggregateVersion,
          row.candidate_digest,
          digest(evidenceCbor),
          evidenceCbor,
          coseSign1,
        ],
      );
      const decision = inserted.rows[0];
      if (inserted.rowCount !== 1 || decision === undefined) {
        throw new ContractError('PC-POLICY-2005');
      }
      const updated = await client.query(
        `update control.approval_request
            set state='APPROVED',row_version=row_version+1,updated_at=clock_timestamp()
          where participant_id=$1 and approval_request_id=$2 and state='OPEN'`,
        [scope.participantId, approvalRequestId],
      );
      if (updated.rowCount !== 1) throw new ContractError('PC-POLICY-2005');
      return { approvalRequestId, decidedAt: decision.decided_at };
    },
    'serializable',
  );
}

export async function readPolicyActivationEvidence(
  pool: Pool,
  scope: PolicyRuntimeScope,
  activationId: string,
) {
  return scoped(pool, scope, async (client) => {
    const result = await client.query<{
      activated_at: Date;
      aggregate_version: string;
      approval_request_id: string;
      event_id: string;
      evidence_digest: Buffer;
      generation_digest: Buffer;
      mfa_challenge_id: string;
      outbox_payload_digest: Buffer;
      policy_activation_id: string;
      receipt_digest: Buffer;
      state: string;
      webauthn_assertion_binding_digest: Buffer;
    }>(
      `select activation.policy_activation_id,activation.state,activation.approval_request_id,
              activation.mfa_challenge_id,activation.webauthn_assertion_binding_digest,
              activation.receipt_digest,activation.activated_at,generation.generation_digest,
              evidence.aggregate_version::text,evidence.evidence_digest,event.event_id,
              event.payload_digest outbox_payload_digest
         from control.policy_activation activation
         join control.policy_generation generation
           on (generation.participant_id,generation.privacy_domain_id,generation.policy_generation_id)=
              (activation.participant_id,activation.privacy_domain_id,activation.policy_generation_id)
         join control.mutation_evidence evidence
           on (evidence.participant_id,evidence.privacy_domain_id,evidence.aggregate_type,
               evidence.aggregate_id)=
              (activation.participant_id,activation.privacy_domain_id,'policy-activation',
               activation.policy_activation_id)
         join control.outbox_event event
           on (event.participant_id,event.privacy_domain_id,event.aggregate_type,event.aggregate_id,
               event.aggregate_sequence)=
              (evidence.participant_id,evidence.privacy_domain_id,evidence.aggregate_type,
               evidence.aggregate_id,evidence.aggregate_version)
        where activation.participant_id=$1 and activation.privacy_domain_id=$2
          and activation.policy_activation_id=$3`,
      [scope.participantId, scope.privacyDomainId, activationId],
    );
    const row = result.rows[0];
    if (result.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2001');
    if (!row.evidence_digest.equals(row.outbox_payload_digest)) {
      throw new ContractError('PC-POLICY-2003');
    }
    return {
      policyActivationId: row.policy_activation_id,
      state: row.state,
      approvalRequestId: row.approval_request_id,
      mfaChallengeId: row.mfa_challenge_id,
      webauthnAssertionBindingDigest: `sha256:${row.webauthn_assertion_binding_digest.toString('hex')}`,
      generationDigest: `sha256:${row.generation_digest.toString('hex')}`,
      receiptDigest: `sha256:${row.receipt_digest.toString('hex')}`,
      evidenceDigest: `sha256:${row.evidence_digest.toString('hex')}`,
      outboxEventId: row.event_id,
      aggregateVersion: row.aggregate_version,
      activatedAt: row.activated_at,
    };
  });
}

export const digestBytes = digest;
