import { isEnvelopeCreateResumeCandidate } from '../envelope-create-resume-contract.js';
import { runtimeProfileResumeSqlTuple } from '../runtime-profile-resume-contract.js';
import { z } from 'zod';
import { projectApprovalCandidate } from '../approval-candidate-contract.js';
import type { Pool, PoolClient } from 'pg';
import { createHash } from 'node:crypto';
import type { BoundAuthority } from '../../../identity-service/src/db/authority-fence.js';
import {
  assertMutationCandidateAuthority,
  workloadRotationAuthorityDependencies,
  type MutationCandidateContext,
} from '../../../identity-service/src/db/mutation-candidate-store.js';
import {
  fenceMutationIntent,
  currentMutationCandidateSql,
} from '../../../identity-service/src/db/mutation-candidate-fence.js';
import { canonicalJson } from '../domain/digest.js';
import { consumeLiveStepUpRecord } from '../../../identity-service/src/db/live-step-up.js';
import {
  lockDiscoveryApprovalResumeProof,
  authenticateDiscoveryApprovalResumeReplayProof,
  lockPlatformRecoveryApprovalResumeProof,
  authenticatePlatformRecoveryApprovalResumeReplayProof,
  type DiscoveryReceivingAuthenticator,
} from '../../../identity-service/src/db/discovery-preapproval-proof.js';
import { readPlatformRecoveryApprovalResumePurpose } from '../../../identity-service/src/db/platform-recovery-approval-resume.js';
import { ContractError } from '../domain/errors.js';
import { moduleInstallResumeSqlTuple } from '../module-install-resume-contract.js';
import {
  approvalRow,
  assertActionIntent,
  completeOperation,
  inScope,
  reserveOperation,
  type PublicApprovalScope,
  type PublicOperation,
} from './public-approval-store.js';

export interface ResumeApprovalInput {
  readonly command: 'RESUME';
  readonly actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
  readonly actionIntentDigest: string;
  readonly expectedRevision: string;
  readonly predecessorCandidateId: string;
  readonly expectedAttempt: string;
  readonly candidateDigest: string;
  readonly reason: string;
}

interface ResumeCandidate {
  readonly candidateId: string;
  readonly actionIntentId: string;
  readonly actionIntentDigest: string;
  readonly catalogOperationId: string;
  readonly resourceType: string;
  readonly operationClass: MutationCandidateContext['operationClass'];
  readonly resourceId: string;
  readonly expectedRevision: string;
  readonly idempotencyKey: string;
  readonly candidateDigest: string;
  readonly candidate: unknown;
  readonly attempt: string;
}

async function candidate(
  client: PoolClient,
  scope: PublicApprovalScope,
  approvalId: string,
  input: ResumeApprovalInput,
): Promise<ResumeCandidate> {
  const approval = await approvalRow(client, scope, approvalId);
  if (
    approval.subjectType !== 'CONFIGURATION_CANDIDATE' ||
    approval.makerPrincipalId !== scope.principalId ||
    approval.subjectId !== input.predecessorCandidateId ||
    approval.checkerPrincipalId === null ||
    approval.checkerPrincipalId === scope.principalId ||
    !['OPEN', 'APPROVED', 'EXPIRED'].includes(approval.state)
  )
    throw new ContractError('PC-POLICY-2004');
  if (approval.rowVersion !== input.expectedRevision) throw new ContractError('PC-POLICY-2003');
  const result = await client.query<ResumeCandidate>(
    `select c.mutation_candidate_id::text as "candidateId",
    c.action_intent_id as "actionIntentId",'sha256:'||encode(i.semantic_digest,'hex') as "actionIntentDigest",
    c.catalog_operation_id as "catalogOperationId",c.resource_type as "resourceType",c.operation_class as "operationClass",
    c.resource_id::text as "resourceId",c.expected_revision::text as "expectedRevision",c.idempotency_key as "idempotencyKey",
    'sha256:'||encode(c.candidate_digest,'hex') as "candidateDigest",c.candidate_document as candidate,c.attempt::text as attempt
    from control.mutation_candidate c join control.action_intent i using(action_intent_id)
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.mutation_candidate_id=$3
      and c.maker_principal_id=$4 and (c.catalog_operation_id in ('MOD-OP-REGISTER','ID-OP-ASSIGNMENT-CREATE',
        'CFG-OP-CREATE-EVIDENCE-HOLD','CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-DELETE-PROJECTION-BATCH',
        'CFG-OP-ACTIVATE-RETENTION-POLICY','CFG-OP-ADMIT-STORE-RETIREMENT','CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
        'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH','CFG-OP-QUALIFY-PROVIDER-PROFILE','CFG-OP-ADMIT-INDEXER-PROFILE')
        or (c.catalog_operation_id,c.action_intent_id,c.resource_type,c.operation_class) in (
          ${moduleInstallResumeSqlTuple},
          ${runtimeProfileResumeSqlTuple},
          ('ID-OP-WORKLOAD-ROTATE','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','participant','UPDATE'),
          ('ID-OP-ENVELOPE-ACTIVATE','ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1','participant','ACTIVATE'),
          ('ID-OP-ENVELOPE-CREATE','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','participant','UPDATE'),
          ('ID-OP-PLATFORM-SCOPE-PREPARE','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','participant','UPDATE'),
          ('ID-OP-PLATFORM-SCOPE-COMMIT','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','participant','UPDATE'),
          ('CFG-OP-CREATE-PROVIDER-PROFILE','ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1','provider-profiles','CREATE'),
          ('CFG-OP-CREATE-ABI-ARTIFACT','ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1','abi-artifact','CREATE'),
          ('CFG-OP-CREATE-LOGICAL-CONTRACT','ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1','logical-contract-asset','CREATE'),
          ('CFG-OP-CREATE-RUNTIME-BINDING','ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1','contract-runtime-binding','CREATE'),
          ('CFG-OP-CREATE-METHOD-POLICY','ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1','contract-method-policy','CREATE')))
      and (c.catalog_operation_id in ('ID-OP-WORKLOAD-ROTATE','ID-OP-ASSIGNMENT-CREATE','ID-OP-ENVELOPE-CREATE','ID-OP-ENVELOPE-ACTIVATE','ID-OP-PLATFORM-SCOPE-PREPARE','ID-OP-PLATFORM-SCOPE-COMMIT') or
        c.candidate_document->>'actionIntentDigest'='sha256:'||encode(i.semantic_digest,'hex'))`,
    [scope.participantId, scope.privacyDomainId, input.predecessorCandidateId, scope.principalId],
  );
  const row = result.rows[0];
  if (
    result.rowCount !== 1 ||
    !row ||
    row.candidateDigest !== input.candidateDigest ||
    row.candidateDigest !== `sha256:${approval.subjectDigest.toString('hex')}` ||
    row.expectedRevision !== approval.subjectVersion ||
    row.actionIntentId !== approval.actionIntentId
  )
    throw new ContractError('PC-POLICY-2004');
  projectApprovalCandidate({ ...row, document: row.candidate });
  if (
    row.catalogOperationId === 'ID-OP-ENVELOPE-CREATE' &&
    !isEnvelopeCreateResumeCandidate({
      ...row,
      participantId: scope.participantId,
      document: row.candidate,
    })
  )
    throw new ContractError('PC-POLICY-2004');
  if (row.attempt !== input.expectedAttempt) throw new ContractError('PC-POLICY-2003');
  return row;
}

const receivingProofSchema = z.strictObject({
  mfaChallengeId: z.uuidv7(),
  verificationOperationId: z.uuidv7(),
  evidenceDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
});
async function authenticateRecoveryResumeReplay(
  client: PoolClient,
  scope: PublicApprovalScope,
  old: ResumeCandidate,
  approvalId: string,
  request: ResumeApprovalInput & { approvalRequestId: string },
  replay: PublicOperation,
  underlying: BoundAuthority,
  receiving: DiscoveryReceivingAuthenticator | undefined,
  purpose: 'DISCOVERY' | 'PLATFORM_CONTINUATION',
) {
  if (
    !receiving ||
    replay.actionIntentId !== scope.actionIntentId ||
    replay.idempotencyKey !== scope.idempotencyKey ||
    replay.revision !== '1' ||
    replay.state !== 'ACCEPTED' ||
    replay.truthState !== 'SUCCESS'
  )
    throw new ContractError('PC-POLICY-2004');
  const proofProperty =
    purpose === 'DISCOVERY' ? 'discoveryReceivingProof' : 'platformReceivingProof';
  const assertion =
    purpose === 'DISCOVERY'
      ? 'assert_discovery_approval_resume'
      : 'assert_platform_recovery_approval_resume';
  const read = () =>
    client.query<{
      proof: unknown;
      authority: MutationCandidateContext['authorization'];
      candidateId: string;
    }>(
      `
 select child.resume_request->'${proofProperty}' as proof,child.mutation_candidate_id::text as "candidateId",
 jsonb_build_object('participantId',child.participant_id::text,'privacyDomainId',child.privacy_domain_id::text,
  'principalId',child.maker_principal_id::text,'sessionId',child.maker_session_id::text,'sessionEpoch',child.maker_session_epoch::text,
  'participantEpoch',child.maker_participant_epoch::text,'principalEpoch',child.maker_principal_epoch::text,
  'assignmentId',child.maker_assignment_id::text,'assignmentRowVersion',child.maker_assignment_row_version::text,
  'authorityEnvelopeId',child.maker_authority_envelope_id::text,'authorityEpoch',child.maker_authority_epoch::text,'delegationEpoch',child.maker_delegation_epoch::text) as authority
 from control.idempotency_record r join control.mutation_candidate child
  on child.participant_id=r.participant_id and child.privacy_domain_id=r.privacy_domain_id and child.resume_operation_id=r.operation_id
 join control.mutation_candidate parent on parent.mutation_candidate_id=child.predecessor_candidate_id
 join control.approval_request next on next.participant_id=child.participant_id and next.privacy_domain_id=child.privacy_domain_id
  and next.subject_type='CONFIGURATION_CANDIDATE' and next.subject_id=child.mutation_candidate_id
 join control.approval_request prior on prior.approval_request_id=child.predecessor_approval_id
 where r.participant_id=$1 and r.privacy_domain_id=$2 and r.principal_id=$3 and r.operation_id=$4
  and r.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' and r.catalog_operation_id='LEGACY'
  and r.idempotency_key=$5 and r.terminal_state='COMMITTED' and r.result_payload=$6::jsonb
  and r.input_digest=sha256(convert_to(openpc.signing_canonical_json($7::jsonb),'UTF8'))
  and r.expected_aggregate_version=prior.row_version and child.resume_request-'${proofProperty}'=$7::jsonb
  and parent.mutation_candidate_id=$8 and prior.approval_request_id=$9
  and child.attempt=parent.attempt+1 and child.state='APPROVAL_REQUESTED' and child.consumed_operation_id is null
  and row(child.participant_id,child.privacy_domain_id,child.action_intent_id,child.catalog_operation_id,child.resource_type,child.operation_class,
   child.resource_id,child.candidate_digest,child.candidate_document,child.expected_revision,child.idempotency_key,child.maker_principal_id)=
   row(parent.participant_id,parent.privacy_domain_id,parent.action_intent_id,parent.catalog_operation_id,parent.resource_type,parent.operation_class,
    parent.resource_id,parent.candidate_digest,parent.candidate_document,parent.expected_revision,parent.idempotency_key,parent.maker_principal_id)
  and 'urn:openpc:resource:'||next.approval_request_id::text=$10 and next.state='OPEN' and next.row_version=1
  and next.subject_digest=child.candidate_digest and next.subject_version=child.expected_revision and next.action_intent_id=child.action_intent_id
  and next.maker_principal_id=child.maker_principal_id and next.checker_principal_id=prior.checker_principal_id
  and next.checker_principal_id<>next.maker_principal_id and next.expires_at=child.expires_at and child.expires_at>clock_timestamp()
  and not exists(select 1 from control.mutation_candidate successor where successor.predecessor_candidate_id=child.mutation_candidate_id)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        scope.principalId,
        replay.operationId,
        scope.idempotencyKey,
        replay,
        request,
        old.candidateId,
        approvalId,
        replay.resourceRef,
      ],
    );
  const selected = await read();
  const row = selected.rows[0];
  const expected = Object.fromEntries(
    Object.entries({ ...underlying, participantId: scope.participantId }).filter(
      ([key]) => !['actionIntentId', 'resourceId', 'catalogOperationId'].includes(key),
    ),
  );
  if (selected.rowCount !== 1 || !row || canonicalJson(row.authority) !== canonicalJson(expected))
    throw new ContractError('PC-POLICY-2004');
  const proof = receivingProofSchema.parse(row.proof);
  const check = () =>
    client.query(
      `select openpc.${assertion}(c) from control.mutation_candidate c where mutation_candidate_id=$1`,
      [row.candidateId],
    );
  await check();
  if (
    !(await (
      purpose === 'DISCOVERY'
        ? authenticateDiscoveryApprovalResumeReplayProof
        : authenticatePlatformRecoveryApprovalResumeReplayProof
    )(
      client,
      {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        authorization: row.authority,
      },
      receiving,
      {
        actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
        resourceId: approvalId,
        candidateDigest: `sha256:${createHash('sha256').update(canonicalJson(request)).digest('hex')}`,
      },
      proof,
      replay.operationId,
    ))
  )
    throw new ContractError('PC-POLICY-2004');
  await check();
  const final = await read();
  if (final.rowCount !== 1 || canonicalJson(final.rows[0]) !== canonicalJson(row))
    throw new ContractError('PC-POLICY-2004');
}

/** Metadata is resolved under the authenticated update authority, never taken from the caller. */
export function resumeApprovalBinding(
  pool: Pool,
  scope: PublicApprovalScope,
  approvalId: string,
  input: ResumeApprovalInput,
) {
  return inScope(pool, scope, (client) => candidate(client, scope, approvalId, input));
}

export async function resumePublicPolicyApproval(
  pool: Pool,
  scope: PublicApprovalScope,
  approvalId: string,
  input: ResumeApprovalInput,
  underlying: BoundAuthority,
  receiving?: DiscoveryReceivingAuthenticator,
) {
  if (
    underlying.principalId !== scope.principalId ||
    underlying.sessionId !== scope.authority.sessionId ||
    underlying.sessionEpoch !== scope.authority.sessionEpoch ||
    underlying.privacyDomainId !== scope.privacyDomainId
  )
    throw new ContractError('PC-POLICY-2004');
  return inScope(
    pool,
    scope,
    async (client) => {
      const intentDigest = await assertActionIntent(client, scope, 'UPDATE', ['approval-requests']);
      const old = await candidate(client, scope, approvalId, input);
      if (
        underlying.actionIntentId !== old.actionIntentId ||
        underlying.resourceId !== old.resourceId
      )
        throw new ContractError('PC-POLICY-2004');
      if (old.catalogOperationId === 'MOD-OP-INSTALL')
        process.stderr.write('OPENPC_MODULE_INSTALL_APPROVAL_RESUME|stage=original_validated\n');
      const discovery = old.catalogOperationId === 'ID-OP-WORKLOAD-ROTATE';
      const request = { ...input, approvalRequestId: `urn:openpc:resource:${approvalId}` };
      const platformPurpose =
        old.catalogOperationId === 'ID-OP-ENVELOPE-ACTIVATE'
          ? await readPlatformRecoveryApprovalResumePurpose(client, {
              participantId: scope.participantId,
              privacyDomainId: scope.privacyDomainId,
              principalId: scope.principalId,
              authorityEnvelopeId: scope.authority.authorityEnvelopeId,
              approvalId,
              requireLeaf: false,
            })
          : undefined;
      if (platformPurpose && canonicalJson(request) !== canonicalJson(platformPurpose.request))
        throw new ContractError('PC-POLICY-2004');
      const receivingPurpose = discovery
        ? 'DISCOVERY'
        : platformPurpose
          ? 'PLATFORM_CONTINUATION'
          : undefined;
      if (
        receivingPurpose &&
        canonicalJson({
          ...underlying,
          actionIntentId: undefined,
          resourceId: undefined,
          catalogOperationId: undefined,
        }) !==
          canonicalJson({
            ...scope.authority,
            actionIntentId: undefined,
            resourceId: undefined,
            catalogOperationId: undefined,
          })
      )
        throw new ContractError('PC-POLICY-2004');
      const requestDigest = createHash('sha256').update(canonicalJson(request)).digest();
      const replay = await reserveOperation(client, scope, requestDigest, input.expectedRevision);
      if (replay) {
        if (receivingPurpose)
          await authenticateRecoveryResumeReplay(
            client,
            scope,
            old,
            approvalId,
            request,
            replay,
            underlying,
            receiving,
            receivingPurpose,
          );
        return replay;
      }
      const context: MutationCandidateContext = {
        ...old,
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        serverGeneratedResourceId: false,
        authorization: { ...underlying, participantId: scope.participantId },
      };
      await assertMutationCandidateAuthority(client, context, {
        principal: [{ id: (await approvalRow(client, scope, approvalId)).checkerPrincipalId! }],
      });
      await fenceMutationIntent(client, { ...context, principalId: scope.principalId });
      const current = await client.query(
        `select 1 from control.mutation_candidate c
      where c.mutation_candidate_id=$1 and ${currentMutationCandidateSql('c')} for update`,
        [old.candidateId],
      );
      if (current.rowCount !== 1) throw new ContractError('PC-POLICY-2002');
      const selectedProof =
        receivingPurpose && receiving
          ? await (
              receivingPurpose === 'DISCOVERY'
                ? lockDiscoveryApprovalResumeProof
                : lockPlatformRecoveryApprovalResumeProof
            )(client, context, receiving, {
              actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
              resourceId: approvalId,
              candidateDigest: `sha256:${requestDigest.toString('hex')}`,
            })
          : undefined;
      if (receivingPurpose && !selectedProof) throw new ContractError('PC-POLICY-2004');
      if (!discovery)
        await client.query('select openpc.assert_mutation_resume_no_effect($1)', [old.candidateId]);
      const storedRequest = selectedProof
        ? {
            ...request,
            [receivingPurpose === 'DISCOVERY'
              ? 'discoveryReceivingProof'
              : 'platformReceivingProof']: selectedProof.proof,
          }
        : request;
      // The trigger independently validates history, expiry, exact intent, reservation and no-effect.
      const inserted = await client.query<{ id: string; expiresAt: string }>(
        `insert into control.mutation_candidate
      (participant_id,privacy_domain_id,action_intent_id,catalog_operation_id,resource_type,operation_class,
       resource_id,candidate_digest,candidate_document,expected_revision,idempotency_key,maker_principal_id,
       maker_session_id,maker_session_epoch,maker_participant_epoch,maker_principal_epoch,maker_assignment_id,
       maker_assignment_row_version,maker_authority_envelope_id,maker_authority_epoch,maker_delegation_epoch,
       state,expires_at,predecessor_candidate_id,predecessor_approval_id,resume_operation_id,resume_request,attempt)
      select participant_id,privacy_domain_id,action_intent_id,catalog_operation_id,resource_type,operation_class,
       resource_id,candidate_digest,candidate_document,expected_revision,idempotency_key,maker_principal_id,
       $2,$3,$4,$5,$6,$7,$8,$9,$10,'PROPOSED',least(clock_timestamp()+interval '30 minutes',$14::timestamptz,
       case when catalog_operation_id='ID-OP-ENVELOPE-CREATE' then to_timestamp((candidate_document#>>'{usable,validUntilNs}')::numeric/1000000000) end,
       case when catalog_operation_id='ID-OP-ENVELOPE-CREATE' then to_timestamp((candidate_document#>>'{grantable,validUntilNs}')::numeric/1000000000) end),mutation_candidate_id,$11,$12,$13,attempt+1
      from control.mutation_candidate where mutation_candidate_id=$1
      returning mutation_candidate_id::text as id,expires_at::text as "expiresAt"`,
        [
          old.candidateId,
          underlying.sessionId,
          underlying.sessionEpoch,
          underlying.participantEpoch,
          underlying.principalEpoch,
          underlying.assignmentId,
          underlying.assignmentRowVersion,
          underlying.authorityEnvelopeId,
          underlying.authorityEpoch,
          underlying.delegationEpoch,
          approvalId,
          scope.operationId,
          storedRequest,
          selectedProof?.validUntil ?? null,
        ],
      );
      const next = inserted.rows[0];
      if (old.catalogOperationId === 'ID-OP-ENVELOPE-CREATE')
        process.stderr.write(
          JSON.stringify({
            event: 'envelope_create_resume_attempt_inserted',
            disposition: 'PENDING_TRANSACTION_COMMIT',
            predecessorCandidateId: old.candidateId,
            attempt: old.attempt,
            successorCandidateId: next?.id,
            expiresAt: next?.expiresAt,
          }) + '\n',
        );
      if (!next || inserted.rowCount !== 1) throw new ContractError('PC-POLICY-2005');
      const approved = await client.query<{ id: string }>(
        `insert into control.approval_request
      (participant_id,privacy_domain_id,action_intent_id,subject_type,subject_id,subject_digest,subject_version,
       maker_principal_id,checker_principal_id,required_approvals,state,expires_at,maker_authority,reason)
      select participant_id,privacy_domain_id,action_intent_id,subject_type,$2,subject_digest,subject_version,
       maker_principal_id,checker_principal_id,required_approvals,'OPEN',$3,$4,$5 from control.approval_request
      where approval_request_id=$1 returning approval_request_id::text as id`,
        [approvalId, next.id, next.expiresAt, scope.authority, input.reason],
      );
      if (approved.rowCount !== 1) throw new ContractError('PC-POLICY-2005');
      await client.query(
        `update control.mutation_candidate set state='APPROVAL_REQUESTED',updated_at=clock_timestamp()
      where mutation_candidate_id=$1`,
        [next.id],
      );
      if (selectedProof)
        await consumeLiveStepUpRecord(
          client,
          {
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            principalId: scope.principalId,
            sessionId: scope.authority.sessionId,
            participantEpoch: scope.authority.participantEpoch,
            principalEpoch: scope.authority.principalEpoch,
            actionIntentId: scope.actionIntentId,
            resourceId: approvalId,
            resourceDigest: requestDigest,
            operationId: scope.operationId,
          },
          selectedProof.record,
        );
      return completeOperation(client, scope, intentDigest, approved.rows[0]!.id, '1');
    },
    async (client) => {
      if (underlying.actionIntentId === 'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1') {
        // Physical execution takes the producer fence before authority/intent
        // rows. Preserve that order and fail closed without a late retry.
        const fence = await client.query<{ acquired: boolean }>(
          'select pg_try_advisory_xact_lock(hashtextextended($1,0)) as acquired',
          [`evidence-lifecycle:${scope.participantId}`],
        );
        if (fence.rows[0]?.acquired !== true) throw new ContractError('PC-POLICY-2004');
      }
      const old = await candidate(client, scope, approvalId, input);
      const request = { ...input, approvalRequestId: `urn:openpc:resource:${approvalId}` };
      const rows =
        old.catalogOperationId === 'ID-OP-WORKLOAD-ROTATE'
          ? await workloadRotationAuthorityDependencies(
              client,
              {
                participantId: scope.participantId,
                resourceId: old.resourceId,
                authorization: { ...underlying, participantId: scope.participantId },
              },
              {
                actionIntentId: scope.actionIntentId,
                candidateDigest: `sha256:${createHash('sha256').update(canonicalJson(request)).digest('hex')}`,
              },
              {
                principal: [
                  { id: (await approvalRow(client, scope, approvalId)).checkerPrincipalId! },
                ],
              },
            )
          : undefined;
      return { authorities: [underlying], ...(rows ? { rows } : {}) };
    },
  );
}
