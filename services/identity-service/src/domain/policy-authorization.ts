import { policyAuthoritySelectionSql } from '../db/policy-authority-selection.js';
import type { Pool } from 'pg';
import { assertRecoveryPrincipalAction } from './recovery-principal.js';

import { currentMutationCandidateSql } from '../db/mutation-candidate-fence.js';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { IdentityKernel, IdentityKernelError } from './identity-kernel.js';
import { localOperationId } from './local-operation-id.js';
import { platformBootstrapPolicyScope } from './platform-bootstrap-policy.js';
import { discoveryCertificateRecoveryPolicyScope } from './discovery-certificate-recovery-policy.js';
import type { DiscoveryApprovalResumePurpose } from '../contracts/discovery-certificate-recovery.js';

export interface PolicyAuthorizationRequest {
  readonly sessionToken: string;
  readonly privacyDomainId: string;
  readonly actionIntentId: string;
  readonly resourceId: string;
  readonly stepUpRequired: boolean;
  readonly catalogOperationId?: string;
  readonly stepUpCandidateDigest?: string;
  /** Strict-parsed approval body selector from the authenticated server owner. */
  readonly approvalCandidateDigest?: string;
  /** Canonical mutation parsed by the authenticated public Identity owner. */
  readonly proposedMutation?: { readonly candidate: unknown; readonly expectedRevision: string };
  readonly approvalResume?: DiscoveryApprovalResumePurpose;
  /** Selection of an existing candidate by the authenticated configuration owner. */
  readonly stagedMutation?: { readonly candidateDigest: string; readonly expectedRevision: string };
  readonly allowPlatformContextSelection?: boolean;
}

export interface PolicyAuthorizationContext {
  readonly sessionId: string;
  readonly sessionEpoch: string;
  readonly sessionIssuedAt: Date;
  readonly sessionIdleExpiresAt: Date;
  readonly sessionAbsoluteExpiresAt: Date;
  readonly participantId: string;
  readonly principalId: string;
  readonly participantEpoch: string;
  readonly principalEpoch: string;
  readonly assignmentId: string;
  readonly roleId?: string | null;
  readonly assignmentRowVersion: string;
  readonly authorityEnvelopeId: string;
  readonly authorityEpoch: string;
  readonly delegationEpoch: string;
  /** Earliest grant, envelope or external-group freshness deadline. */
  readonly authorityValidUntil?: Date | null;
}

export async function authorizeLocalPolicyAction(
  pool: Pool,
  kernel: IdentityKernel,
  input: PolicyAuthorizationRequest,
): Promise<PolicyAuthorizationContext> {
  const session = await kernel.sessionSnapshot(input.sessionToken);
  if (
    input.allowPlatformContextSelection &&
    !(
      (input.actionIntentId === 'ACT-IDENTITY_CREATE_SESSION-V1' &&
        input.catalogOperationId === 'ID-OP-SESSION-CONTEXT-SELECT' &&
        input.resourceId === session.participantId) ||
      (input.actionIntentId === 'ACT-IDENTITY_CREATE_SESSION-V1' &&
        input.catalogOperationId === 'ID-OP-SESSION-REFRESH' &&
        input.resourceId === session.sessionId) ||
      (input.actionIntentId === 'ACT-IDENTITY_DELETE_SESSION-V1' &&
        input.resourceId === session.sessionId) ||
      (input.actionIntentId === 'ACT-IDENTITY_UPDATE_STEP_UP-V1' &&
        input.resourceId === session.sessionId)
    )
  ) {
    throw new IdentityKernelError('PC-IDENTITY-1005');
  }
  return runScopedTransaction(
    pool,
    {
      participantId: session.participantId,
      privacyDomainId: input.privacyDomainId,
      actionIntentId: input.actionIntentId,
    },
    localOperationId,
    async (client) => {
      const discovery =
        session.contextMode === 'PLATFORM'
          ? await discoveryCertificateRecoveryPolicyScope(
              client,
              session.participantId,
              session.principalId,
              session.sessionId,
              input,
            )
          : undefined;
      if (discovery === false) throw new IdentityKernelError('PC-IDENTITY-1002');
      const platformBootstrap =
        session.contextMode === 'PLATFORM' &&
        (discovery !== undefined ||
          (await platformBootstrapPolicyScope(
            client,
            session.participantId,
            session.principalId,
            session.sessionId,
            input,
          )));
      await assertRecoveryPrincipalAction(client, {
        ...input,
        participantId: session.participantId,
        principalId: session.principalId,
        sessionId: session.sessionId,
      });
      // Resolve the business permission from the authoritative approval, never
      // from a caller-provided action or resource. The decision persists one
      // grant, so both permissions must survive that same complete chain.
      let business: { actionIntentId: string; resourceId: string } | undefined;
      if (input.actionIntentId === 'ACT-POLICY_APPROVE_REQUEST-V1') {
        const approval = await client.query<{
          subjectType: string;
          actionIntentId: string | null;
          resourceId: string | null;
        }>(
          `select r.subject_type as "subjectType",c.action_intent_id as "actionIntentId",
                  c.resource_id::text as "resourceId"
             from control.approval_request r
             left join control.mutation_candidate c
               on r.subject_type='CONFIGURATION_CANDIDATE'
              and c.participant_id=r.participant_id and c.privacy_domain_id=r.privacy_domain_id
              and c.mutation_candidate_id=r.subject_id and c.action_intent_id=r.action_intent_id
              and c.candidate_digest=r.subject_digest and c.expected_revision=r.subject_version
              and c.maker_principal_id=r.maker_principal_id
              and r.state in ('OPEN','APPROVED') and r.expires_at>clock_timestamp()
              and c.maker_principal_id<>$4
              and (r.checker_principal_id is null or r.checker_principal_id=$4)
              and c.expires_at>clock_timestamp() and ${currentMutationCandidateSql('c')}
              and c.state in ('APPROVAL_REQUESTED','APPROVED','CONSUMED')
            where r.participant_id=$1 and r.privacy_domain_id=$2 and r.approval_request_id=$3`,
          [session.participantId, input.privacyDomainId, input.resourceId, session.principalId],
        );
        const selected = approval.rows[0];
        if (selected?.subjectType === 'CONFIGURATION_CANDIDATE') {
          if (approval.rowCount !== 1 || !selected.actionIntentId || !selected.resourceId)
            throw new IdentityKernelError('PC-IDENTITY-1002');
          business = { actionIntentId: selected.actionIntentId, resourceId: selected.resourceId };
          await assertRecoveryPrincipalAction(client, {
            participantId: session.participantId,
            privacyDomainId: input.privacyDomainId,
            principalId: session.principalId,
            sessionId: session.sessionId,
            actionIntentId: business.actionIntentId,
            resourceId: business.resourceId,
          });
        }
      }
      const result = await client.query<PolicyAuthorizationContext>(policyAuthoritySelectionSql, [
        session.participantId,
        input.privacyDomainId,
        input.actionIntentId,
        input.resourceId,
        session.principalId,
        session.sessionId,
        input.stepUpRequired,
        input.allowPlatformContextSelection ?? false,
        platformBootstrap,
        business?.actionIntentId ?? null,
        business?.resourceId ?? null,
      ]);
      if (result.rowCount !== 1) {
        process.stderr.write(
          `${JSON.stringify({
            boundary: 'local_policy_authorization',
            stage: 'grant_selection',
            actionIntentId: input.actionIntentId,
            contextMode: session.contextMode,
            sessionId: session.sessionId,
            principalId: session.principalId,
            platformContextEligible: platformBootstrap,
            stepUpRequired: input.stepUpRequired,
            selectedGrantCount: result.rowCount,
            disposition: 'DENIED',
          })}\n`,
        );
        throw new IdentityKernelError('PC-IDENTITY-1002');
      }
      const authority = result.rows[0]!;
      if (
        discovery !== undefined &&
        authority.authorityEnvelopeId !== discovery.authorityEnvelopeId
      )
        throw new IdentityKernelError('PC-IDENTITY-1002');
      if (
        authority.participantEpoch !== session.participantEpoch ||
        authority.principalEpoch !== session.authorityEpoch
      ) {
        throw new IdentityKernelError('PC-IDENTITY-1001');
      }
      return authority;
    },
  );
}
