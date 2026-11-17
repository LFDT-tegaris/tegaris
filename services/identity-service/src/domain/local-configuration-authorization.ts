import { stepUpOnlyConfigurationOperations } from './configuration-step-up-admission.js';
import { selectConfigurationStepUp, type StepUpRow } from './local-configuration-step-up.js';
import { currentMutationCandidateSql } from '../db/mutation-candidate-fence.js';
import { createHash } from 'node:crypto';
import {
  selectCommittedIdentityStepUp,
  type CommittedIdentityStepUpInput,
} from '../db/identity-step-up-signer.js';
import { identityGovernanceOperations } from '../contracts/principal-operations.js';

import type { Pool } from 'pg';
import { controlMutationForAction } from '@openpc/security-kernel';
import { createIdentityRuntimeAuthorizationAssertion } from './identity-runtime-authorization.js';
import type { IdentityRuntimeCryptoAdapter } from './identity-runtime-crypto.js';

import { runScopedTransaction } from '../db/scoped-transaction.js';
import { IdentityKernel, IdentityKernelError } from './identity-kernel.js';
import { localOperationId } from './local-operation-id.js';
import { authorizeLocalPolicyAction } from './policy-authorization.js';

export interface LocalConfigurationAuthorizationInput {
  readonly sessionToken: string;
  readonly idempotencyKey?: string;
  readonly privacyDomainId: string;
  readonly actionIntentId: string;
  readonly catalogOperationId?: string;
  readonly actionIntentDigest?: string;
  readonly resourceId: string;
  readonly candidateDigest: string;
  readonly expectedRevision: string;
}

interface ExistingAuthorizationRow {
  readonly approvalRequestId: string | null;
  readonly consumedOperationId: string | null;
  readonly checkerPrincipalId: string | null;
  readonly signerCredentialId: string;
  readonly evidenceCbor: Buffer;
  readonly coseSign1: Buffer;
  readonly mfaChallengeId: string | null;
  readonly webauthnSessionId: string | null;
  readonly webauthnSignerCredentialId: string | null;
  readonly webauthnAssertionBindingDigest: Buffer | null;
  readonly webauthnEvidenceCbor: Buffer | null;
  readonly webauthnEvidenceDigest: Buffer | null;
  readonly webauthnCoseSign1: Buffer | null;
}

interface ActionRequirements {
  readonly makerCheckerRequired: boolean;
  readonly stepUpRequired: boolean;
  readonly semanticDigest: Buffer;
}

const digest = (value: Buffer): Buffer => createHash('sha256').update(value).digest();

/** Bind ordinary actions to live session authority; governed actions require their actual approval. */
export async function authorizeLocalConfigurationMutation(
  pool: Pool,
  kernel: IdentityKernel,
  input: LocalConfigurationAuthorizationInput,
  identityRuntimeCrypto: IdentityRuntimeCryptoAdapter,
) {
  const session = await kernel.sessionSnapshot(input.sessionToken);
  const authority = await authorizeLocalPolicyAction(pool, kernel, {
    sessionToken: input.sessionToken,
    privacyDomainId: input.privacyDomainId,
    actionIntentId: input.actionIntentId,
    catalogOperationId: input.catalogOperationId,
    resourceId: input.resourceId,
    stagedMutation: {
      candidateDigest: input.candidateDigest,
      expectedRevision: input.expectedRevision,
    },
    stepUpRequired: false,
  });
  if (input.catalogOperationId === 'ID-OP-WORKLOAD-ISSUE')
    console.info(
      JSON.stringify({
        boundary: 'workload_issue_authorization',
        stage: 'live_authority_admitted',
        resourceId: input.resourceId,
      }),
    );
  return runScopedTransaction(
    pool,
    {
      participantId: session.participantId,
      privacyDomainId: input.privacyDomainId,
      actionIntentId: input.actionIntentId,
    },
    localOperationId,
    async (client) => {
      const candidateDigest = Buffer.from(input.candidateDigest.slice(7), 'hex');
      if (candidateDigest.length !== 32 || !/^(?:0|[1-9][0-9]*)$/u.test(input.expectedRevision)) {
        throw new IdentityKernelError('PC-IDENTITY-1005');
      }
      const actionResult = await client.query<ActionRequirements>(
        `select maker_checker_required as "makerCheckerRequired",
                step_up_required as "stepUpRequired",semantic_digest as "semanticDigest"
           from control.action_intent where action_intent_id=$1`,
        [input.actionIntentId],
      );
      const action = actionResult.rows[0];
      const operation = controlMutationForAction(input.actionIntentId, input.catalogOperationId);
      if (
        actionResult.rowCount !== 1 ||
        action === undefined ||
        operation === undefined ||
        operation.makerCheckerRequired !== action.makerCheckerRequired ||
        operation.stepUpRequired !== action.stepUpRequired ||
        (input.actionIntentDigest !== undefined &&
          `sha256:${action.semanticDigest.toString('hex')}` !== input.actionIntentDigest)
      ) {
        throw new IdentityKernelError('PC-IDENTITY-1005');
      }
      const authorityProof = {
        sessionId: session.sessionId,
        sessionEpoch: authority.sessionEpoch,
        participantId: session.participantId,
        privacyDomainId: input.privacyDomainId,
        principalId: session.principalId,
        principalEpoch: authority.principalEpoch,
        participantEpoch: authority.participantEpoch,
        authorityEnvelopeId: authority.authorityEnvelopeId,
        authorityEpoch: authority.authorityEpoch,
        delegationEpoch: authority.delegationEpoch,
        assignmentId: authority.assignmentId,
        assignmentEpoch: authority.assignmentRowVersion,
      };
      if (!action.makerCheckerRequired) {
        let stepUp: StepUpRow | undefined;
        if (action.stepUpRequired) {
          if (
            !stepUpOnlyConfigurationOperations.includes(operation.catalogOperationId) ||
            !input.idempotencyKey
          )
            throw new IdentityKernelError('PC-IDENTITY-1005');
          const prior = await client.query<{
            operationId: string;
            inputDigest: Buffer;
            expectedRevision: string;
            state: string;
          }>(
            `select operation_id::text as "operationId",input_digest as "inputDigest",
              expected_aggregate_version::text as "expectedRevision",terminal_state as state
             from control.idempotency_record where participant_id=$1 and privacy_domain_id=$2
              and principal_id=$3 and action_intent_id=$4 and catalog_operation_id=$5 and idempotency_key=$6`,
            [
              session.participantId,
              input.privacyDomainId,
              session.principalId,
              input.actionIntentId,
              operation.catalogOperationId,
              input.idempotencyKey,
            ],
          );
          const original = prior.rows[0];
          if (
            prior.rows.length > 1 ||
            (original &&
              (!original.inputDigest.equals(candidateDigest) ||
                original.expectedRevision !== input.expectedRevision ||
                original.state !== 'COMMITTED'))
          )
            throw new IdentityKernelError('PC-IDENTITY-1005');
          stepUp = await selectConfigurationStepUp(client, {
            participantId: session.participantId,
            privacyDomainId: input.privacyDomainId,
            principalId: session.principalId,
            sessionId: session.sessionId,
            actionIntentId: input.actionIntentId,
            candidateDigest,
            consumedOperationId: original?.operationId ?? null,
          });
        }
        const evidenceCbor = createIdentityRuntimeAuthorizationAssertion(
          localOperationId(),
          {
            ...authority,
            actionIntentId: input.actionIntentId,
            catalogOperationId: operation.catalogOperationId,
            resourceId: input.resourceId,
            candidateDigest: input.candidateDigest,
            sessionToken: input.sessionToken,
            configurationBinding: {
              privacyDomainId: input.privacyDomainId,
              actionIntentDigest: `sha256:${action.semanticDigest.toString('hex')}`,
              expectedRevision: input.expectedRevision,
            },
          },
          new Date(),
        );
        const signed = await identityRuntimeCrypto.signCanonicalAssertion(evidenceCbor);
        if (stepUp)
          return {
            ...authorityProof,
            evidenceKind: 'IDENTITY_RUNTIME_STEP_UP' as const,
            ...signed,
            ...stepUp,
          };
        return { ...authorityProof, evidenceKind: 'IDENTITY_RUNTIME' as const, ...signed };
      }
      const result = await client.query<ExistingAuthorizationRow>(
        `select ar.approval_request_id as "approvalRequestId",
                    candidate.consumed_operation_id as "consumedOperationId",
                    ad.approver_principal_id as "checkerPrincipalId",
                    ad.signer_credential_id as "signerCredentialId",
                    ad.evidence_cbor as "evidenceCbor",ad.cose_sign1 as "coseSign1",
                    null::uuid as "mfaChallengeId",null::uuid as "webauthnSessionId",
                    null::uuid as "webauthnSignerCredentialId",
                    null::bytea as "webauthnAssertionBindingDigest",
                    null::bytea as "webauthnEvidenceCbor",null::bytea as "webauthnEvidenceDigest",
                    null::bytea as "webauthnCoseSign1"
               from control.approval_request ar
               join control.mutation_candidate candidate
                 on candidate.participant_id=ar.participant_id
                and candidate.privacy_domain_id=ar.privacy_domain_id
                and candidate.mutation_candidate_id=ar.subject_id
                and candidate.action_intent_id=ar.action_intent_id
                and candidate.candidate_digest=ar.subject_digest
                and candidate.expected_revision=ar.subject_version
                and candidate.state in ('APPROVED','CONSUMED')
                and ${currentMutationCandidateSql('candidate')}
                and candidate.expires_at>clock_timestamp()
               join control.approval_decision_record ad
                 on ad.participant_id=ar.participant_id
                and ad.privacy_domain_id=ar.privacy_domain_id
                and ad.approval_request_id=ar.approval_request_id
                and ad.decision='APPROVE' and ad.approver_principal_id<>ar.maker_principal_id
                and ad.aggregate_version=ar.subject_version and ad.candidate_digest=ar.subject_digest
                and ad.evidence_cbor is not null and ad.signer_credential_id is not null
               join control.credential credential
                 on credential.credential_id=ad.signer_credential_id
                and credential.participant_id=ad.participant_id
                and credential.principal_id=ad.approver_principal_id
                and credential.kind='WEBAUTHN' and credential.state='ACTIVE'
                and credential.valid_from<=clock_timestamp()
                and (credential.valid_until is null or credential.valid_until>clock_timestamp())
              where ar.participant_id=$1 and ar.privacy_domain_id=$2
                and ar.action_intent_id=$3 and ar.subject_type='CONFIGURATION_CANDIDATE'
                and ar.subject_digest=$4 and ar.subject_version=$5
                and ar.maker_principal_id=$6 and ar.state='APPROVED'
                and candidate.resource_id=$7::uuid and candidate.catalog_operation_id=$8
                and ar.expires_at>clock_timestamp()
              order by ar.updated_at desc,ad.decided_at desc limit 2`,
        [
          session.participantId,
          input.privacyDomainId,
          input.actionIntentId,
          candidateDigest,
          input.expectedRevision,
          session.principalId,
          input.resourceId,
          operation.catalogOperationId,
        ],
      );
      const proof = result.rows[0];
      if (input.catalogOperationId === 'ID-OP-WORKLOAD-ISSUE')
        console.info(
          JSON.stringify({
            boundary: 'workload_issue_authorization',
            stage: 'approval_selected',
            resourceId: input.resourceId,
            count: result.rowCount,
          }),
        );
      if (
        result.rowCount !== 1 ||
        proof === undefined ||
        (action.makerCheckerRequired && proof.checkerPrincipalId === null)
      ) {
        throw new IdentityKernelError('PC-IDENTITY-1005');
      }
      let stepUp: StepUpRow | undefined;
      if (action.stepUpRequired) {
        // Only the exact committed Identity request may select historical C1.
        // Current session assurance is checked independently; C2 is not consumed.
        const historyInput: CommittedIdentityStepUpInput | undefined =
          input.idempotencyKey === undefined || proof.consumedOperationId === null
            ? undefined
            : {
                participantId: session.participantId,
                privacyDomainId: input.privacyDomainId,
                principalId: session.principalId,
                sessionId: session.sessionId,
                actionIntentId: input.actionIntentId,
                candidateDigest,
                assertionBindingDigest: undefined,
                idempotencyKey: input.idempotencyKey,
                catalogOperationId: operation.catalogOperationId,
                resourceId: input.resourceId,
                expectedRevision: input.expectedRevision,
                approvalRequestId: proof.approvalRequestId ?? '',
                checkerPrincipalId: proof.checkerPrincipalId ?? '',
                checkerCredentialId: proof.signerCredentialId,
                evidenceCbor: proof.evidenceCbor,
                evidenceDigest: digest(proof.evidenceCbor),
                coseSign1: proof.coseSign1,
                ...(proof.consumedOperationId === null
                  ? {}
                  : { operationId: proof.consumedOperationId }),
              };
        const history =
          historyInput === undefined
            ? undefined
            : await selectCommittedIdentityStepUp(client, historyInput);
        if (
          proof.consumedOperationId !== null &&
          history === undefined &&
          identityGovernanceOperations.some(
            (entry) =>
              entry.id === operation.catalogOperationId &&
              entry.makerCheckerRequired &&
              entry.webauthnStepUpRequired,
          )
        )
          throw new IdentityKernelError('PC-IDENTITY-1009');
        if (history !== undefined) {
          await authorizeLocalPolicyAction(pool, kernel, {
            sessionToken: input.sessionToken,
            privacyDomainId: input.privacyDomainId,
            actionIntentId: input.actionIntentId,
            catalogOperationId: input.catalogOperationId,
            resourceId: input.resourceId,
            stagedMutation: {
              candidateDigest: input.candidateDigest,
              expectedRevision: input.expectedRevision,
            },
            stepUpRequired: true,
          });
        }
        stepUp = await selectConfigurationStepUp(client, {
          participantId: session.participantId,
          privacyDomainId: input.privacyDomainId,
          principalId: session.principalId,
          sessionId: session.sessionId,
          actionIntentId: input.actionIntentId,
          candidateDigest,
          consumedOperationId: proof.consumedOperationId,
          ...(history === undefined || historyInput === undefined
            ? {}
            : {
                committedHistory: {
                  ...historyInput,
                  assertionBindingDigest: history.assertionBindingDigest,
                  operationId: history.operationId,
                },
              }),
        });
        if (input.catalogOperationId === 'ID-OP-WORKLOAD-ISSUE')
          console.info(
            JSON.stringify({
              boundary: 'workload_issue_authorization',
              stage: 'step_up_selected',
              resourceId: input.resourceId,
            }),
          );
      }
      return {
        ...authorityProof,
        evidenceKind: 'USER_WEBAUTHN' as const,
        ...(proof.checkerPrincipalId === null
          ? {}
          : { checkerPrincipalId: proof.checkerPrincipalId }),
        signerCredentialId: proof.signerCredentialId,
        approvalRequestId: proof.approvalRequestId ?? undefined,
        mfaChallengeId: stepUp?.mfaChallengeId,
        webauthnSessionId: stepUp?.webauthnSessionId,
        webauthnSignerCredentialId: stepUp?.webauthnSignerCredentialId,
        webauthnAssertionBindingDigest: stepUp?.webauthnAssertionBindingDigest,
        webauthnEvidenceCbor: stepUp?.webauthnEvidenceCbor,
        webauthnEvidenceDigest: stepUp?.webauthnEvidenceDigest,
        webauthnCoseSign1: stepUp?.webauthnCoseSign1,
        evidenceCbor: proof.evidenceCbor,
        evidenceDigest: digest(proof.evidenceCbor),
        coseSign1: proof.coseSign1,
      };
    },
  );
}
