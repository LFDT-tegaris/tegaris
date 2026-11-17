import { createHash } from 'node:crypto';

import type { Pool } from 'pg';

import type { IdentityAuthorizationAdapter } from '../app.js';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { IdentityKernel, IdentityKernelError } from './identity-kernel.js';
import {
  createIdentityRuntimeAuthorizationAssertion,
  type IdentityRuntimeAuthorizationContext,
} from './identity-runtime-authorization.js';
import type { IdentityRuntimeCryptoAdapter } from './identity-runtime-crypto.js';
import { localOperationId } from './local-operation-id.js';
import { authorizeLocalPolicyAction } from './policy-authorization.js';
import { authorizeLocalConfigurationMutation } from './local-configuration-authorization.js';
import { sessionPrivacyContext } from './session-privacy-context.js';

interface BootstrapProof {
  readonly signerCredentialId: string;
  readonly evidenceCbor: Buffer;
  readonly coseSign1: Buffer;
  readonly subjectDigest: Buffer;
  readonly decisionDigest: Buffer;
}

/** Authorize only the local step-up verification mutation from preexisting identity truth. */
export function createLocalIdentityAuthorizationAdapter(
  pool: Pool,
  kernel: IdentityKernel,
  _privacyDomainId: string,
  identityRuntimeCrypto: IdentityRuntimeCryptoAdapter,
): IdentityAuthorizationAdapter {
  return {
    async propose(input) {
      const privacyDomainId = await sessionPrivacyContext(pool, kernel, input.actor.sessionToken);
      const context = await authorizeLocalPolicyAction(pool, kernel, {
        sessionToken: input.actor.sessionToken,
        privacyDomainId,
        actionIntentId: input.actionIntentId,
        catalogOperationId: input.catalogOperationId,
        resourceId: input.resourceId,
        proposedMutation:
          input.expectedRevision === undefined || input.candidate === undefined
            ? undefined
            : {
                candidate: input.candidate,
                expectedRevision: input.expectedRevision,
              },
        stepUpRequired: false,
      });
      return {
        participantId: context.participantId,
        privacyDomainId,
        principalId: context.principalId,
        sessionId: context.sessionId,
        sessionEpoch: context.sessionEpoch,
        participantEpoch: context.participantEpoch,
        principalEpoch: context.principalEpoch,
        assignmentId: context.assignmentId,
        assignmentRowVersion: context.assignmentRowVersion,
        authorityEnvelopeId: context.authorityEnvelopeId,
        authorityEpoch: context.authorityEpoch,
        delegationEpoch: context.delegationEpoch,
      };
    },
    async authorize(input) {
      const privacyDomainId = await sessionPrivacyContext(pool, kernel, input.actor.sessionToken);
      const platformContextSelection =
        (input.actionIntentId === 'ACT-IDENTITY_CREATE_SESSION-V1' &&
          input.catalogOperationId === 'ID-OP-SESSION-CONTEXT-SELECT' &&
          input.resourceId === input.actor.participantId) ||
        (input.actionIntentId === 'ACT-IDENTITY_CREATE_SESSION-V1' &&
          input.catalogOperationId === 'ID-OP-SESSION-REFRESH' &&
          input.resourceId === input.actor.sessionToken.split('.')[1]) ||
        (input.actionIntentId === 'ACT-IDENTITY_DELETE_SESSION-V1' &&
          input.resourceId === input.actor.sessionToken.split('.')[1]) ||
        (input.actionIntentId === 'ACT-IDENTITY_UPDATE_STEP_UP-V1' &&
          input.stepUpTargetActionIntentId === 'ACT-IDENTITY_CREATE_SESSION-V1' &&
          input.stepUpTargetResourceId === input.actor.participantId);
      const authorizeRuntime = async () => {
        const authority = await authorizeLocalPolicyAction(pool, kernel, {
          sessionToken: input.actor.sessionToken,
          privacyDomainId,
          actionIntentId: input.actionIntentId,
          catalogOperationId: input.catalogOperationId!,
          resourceId: input.resourceId,
          stepUpRequired: false,
          allowPlatformContextSelection: platformContextSelection,
        });
        const assertionInput: IdentityRuntimeAuthorizationContext = {
          ...authority,
          actionIntentId: input.actionIntentId,
          catalogOperationId: input.catalogOperationId!,
          resourceId: input.resourceId,
          candidateDigest: input.candidateDigest!,
          sessionToken: input.actor.sessionToken,
        };
        const evidenceCbor = createIdentityRuntimeAuthorizationAssertion(
          localOperationId(),
          assertionInput,
          new Date(),
        );
        const signed = await identityRuntimeCrypto.signCanonicalAssertion(evidenceCbor);
        return {
          allowed: true,
          evidenceKind: 'IDENTITY_RUNTIME' as const,
          signerKeyDigest: signed.signerKeyDigest,
          privacyDomainId,
          evidenceCbor: signed.evidenceCbor,
          evidenceDigest: signed.evidenceDigest,
          coseSign1: signed.coseSign1,
        };
      };
      if (
        input.makerCheckerRequired &&
        input.stepUpRequired &&
        input.catalogOperationId !== undefined &&
        input.candidateDigest !== undefined &&
        input.approvalRequestId !== undefined &&
        input.expectedAggregateVersion !== undefined &&
        input.actor.mutationAuthorization === undefined
      ) {
        const proof = await authorizeLocalConfigurationMutation(
          pool,
          kernel,
          {
            sessionToken: input.actor.sessionToken,
            privacyDomainId,
            actionIntentId: input.actionIntentId,
            catalogOperationId: input.catalogOperationId,
            resourceId: input.resourceId,
            candidateDigest: input.candidateDigest,
            idempotencyKey: input.idempotencyKey,
            expectedRevision: input.expectedAggregateVersion,
          },
          identityRuntimeCrypto,
        );
        if (
          !('approvalRequestId' in proof) ||
          proof.approvalRequestId !== input.approvalRequestId
        ) {
          return { allowed: false };
        }
        return { allowed: true, ...proof };
      }
      if (
        (input.actionIntentId !== 'ACT-IDENTITY_UPDATE_STEP_UP-V1' ||
          (input.resourceId === input.actor.sessionToken.split('.')[1] &&
            input.stepUpCandidateDigest !== undefined &&
            /^sha256:[0-9a-f]{64}$/u.test(input.stepUpCandidateDigest))) &&
        !input.makerCheckerRequired &&
        !input.stepUpRequired &&
        input.approvalRequestId === undefined &&
        input.candidateDigest === undefined
      ) {
        await authorizeLocalPolicyAction(pool, kernel, {
          sessionToken: input.actor.sessionToken,
          privacyDomainId,
          actionIntentId: input.actionIntentId,
          catalogOperationId: input.catalogOperationId,
          resourceId: input.resourceId,
          stepUpCandidateDigest: input.stepUpCandidateDigest,
          stepUpRequired: false,
          allowPlatformContextSelection: platformContextSelection,
        });
        return { allowed: true };
      }
      if (
        input.actionIntentId !== 'ACT-IDENTITY_UPDATE_STEP_UP-V1' &&
        !input.makerCheckerRequired &&
        !input.stepUpRequired &&
        input.approvalRequestId === undefined &&
        input.catalogOperationId !== undefined &&
        input.candidateDigest !== undefined &&
        /^sha256:[0-9a-f]{64}$/u.test(input.candidateDigest)
      ) {
        return authorizeRuntime();
      }
      if (
        input.actionIntentId !== 'ACT-IDENTITY_UPDATE_STEP_UP-V1' ||
        input.makerCheckerRequired ||
        input.stepUpRequired ||
        input.approvalRequestId !== undefined ||
        input.candidateDigest === undefined ||
        !/^sha256:[0-9a-f]{64}$/u.test(input.candidateDigest)
      ) {
        return { allowed: false };
      }
      await authorizeLocalPolicyAction(pool, kernel, {
        sessionToken: input.actor.sessionToken,
        privacyDomainId,
        actionIntentId: input.actionIntentId,
        catalogOperationId: input.catalogOperationId,
        resourceId: input.resourceId,
        stepUpRequired: false,
        allowPlatformContextSelection: platformContextSelection,
      });
      const result = await runScopedTransaction(
        pool,
        {
          participantId: input.actor.participantId,
          privacyDomainId,
          actionIntentId: input.actionIntentId,
        },
        localOperationId,
        async (client) =>
          client.query<BootstrapProof>(
            `select ad.signer_credential_id as "signerCredentialId",
                    ad.evidence_cbor as "evidenceCbor",ad.cose_sign1 as "coseSign1",
                    ar.subject_digest as "subjectDigest",ad.decision_digest as "decisionDigest"
               from control.approval_request ar
               join control.approval_decision_record ad
                 on ad.participant_id=ar.participant_id
                and ad.privacy_domain_id=ar.privacy_domain_id
                and ad.approval_request_id=ar.approval_request_id
                and ad.approver_principal_id=ar.maker_principal_id
                and ad.signer_credential_id=ar.subject_id
                and ad.aggregate_version=ar.subject_version
                and ad.candidate_digest=ar.subject_digest and ad.decision='APPROVE'
               join control.credential credential
                 on credential.participant_id=ad.participant_id
                and credential.principal_id=ad.approver_principal_id
                and credential.credential_id=ad.signer_credential_id
                and credential.kind='WEBAUTHN' and credential.state='ACTIVE'
                and credential.valid_from<=clock_timestamp()
                and (credential.valid_until is null or credential.valid_until>clock_timestamp())
              where ar.participant_id=$1 and ar.privacy_domain_id=$2
                and ar.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
                and ar.subject_type='LOCAL_IDENTITY_CREDENTIAL_BOOTSTRAP'
                and ar.maker_principal_id=$3 and ar.state='APPROVED'
                and ar.expires_at>clock_timestamp()
              order by ar.updated_at desc,ad.decided_at desc limit 2`,
            [input.actor.participantId, privacyDomainId, input.actor.principalId],
          ),
      );
      // Preserve admitted bootstrap evidence for existing consumers. A newly
      // enrolled authenticator has no private certificate and uses the existing
      // Identity runtime assertion profile for this verified ceremony only.
      if (result.rowCount === 0 && input.catalogOperationId === 'ID-OP-WEBAUTHN-VERIFY') {
        return authorizeRuntime();
      }
      const proof = result.rows[0];
      if (
        result.rowCount !== 1 ||
        proof === undefined ||
        !createHash('sha256')
          .update(proof.subjectDigest)
          .update(proof.evidenceCbor)
          .digest()
          .equals(proof.decisionDigest)
      ) {
        throw new IdentityKernelError('PC-IDENTITY-1005');
      }
      return {
        allowed: true,
        evidenceKind: 'USER_WEBAUTHN',
        signerCredentialId: proof.signerCredentialId,
        privacyDomainId,
        evidenceCbor: proof.evidenceCbor,
        evidenceDigest: createHash('sha256').update(proof.evidenceCbor).digest(),
        coseSign1: proof.coseSign1,
      };
    },
  };
}
