import type { PoolClient } from 'pg';
import { IdentityKernelError } from './identity-kernel.js';
import {
  selectCommittedIdentityStepUp,
  type CommittedIdentityStepUpInput,
} from '../db/identity-step-up-signer.js';

export interface StepUpRow {
  readonly mfaChallengeId: string;
  readonly webauthnSessionId: string;
  readonly webauthnSignerCredentialId: string;
  readonly webauthnAssertionBindingDigest: Buffer;
  readonly webauthnEvidenceCbor: Buffer;
  readonly webauthnEvidenceDigest: Buffer;
  readonly webauthnCoseSign1: Buffer;
}

/** Select only the real committed verification for this session and exact intent. */
export async function selectConfigurationStepUp(
  client: PoolClient,
  input: {
    participantId: string;
    privacyDomainId: string;
    principalId: string;
    sessionId: string;
    actionIntentId: string;
    candidateDigest: Buffer;
    consumedOperationId: string | null;
    committedHistory?: CommittedIdentityStepUpInput & { readonly operationId: string };
  },
): Promise<StepUpRow> {
  if (input.committedHistory !== undefined) {
    const history = input.committedHistory;
    if (
      history.participantId !== input.participantId ||
      history.privacyDomainId !== input.privacyDomainId ||
      history.principalId !== input.principalId ||
      history.sessionId !== input.sessionId ||
      history.actionIntentId !== input.actionIntentId ||
      !history.candidateDigest.equals(input.candidateDigest) ||
      history.operationId !== input.consumedOperationId
    )
      throw new IdentityKernelError('PC-IDENTITY-1005');
    const original = await selectCommittedIdentityStepUp(client, history);
    if (!original || original.operationId !== history.operationId)
      throw new IdentityKernelError('PC-IDENTITY-1005');
    return {
      mfaChallengeId: original.mfaChallengeId,
      webauthnSessionId: original.verificationSessionId,
      webauthnSignerCredentialId: original.credentialId,
      webauthnAssertionBindingDigest: original.assertionBindingDigest,
      webauthnEvidenceCbor: original.verificationEvidenceCbor,
      webauthnEvidenceDigest: original.verificationEvidenceDigest,
      webauthnCoseSign1: original.verificationCoseSign1,
    };
  }
  const stepUpResult = await client.query<StepUpRow>(
    `with selected_challenge as (
             select source.mfa_challenge_id from control.mfa_challenge source
              join control.session proof_session on proof_session.participant_id=source.participant_id
                and proof_session.principal_id=source.principal_id and proof_session.session_id=source.session_id
              where source.participant_id=$1 and source.principal_id=$3 and source.session_id=$6
                and source.action_intent_id=$4 and source.resource_digest=$5
                and case when proof_session.step_up_mfa_challenge_id is null
                  then source.consumed_at>clock_timestamp()-interval '5 minutes'
                  else proof_session.step_up_mfa_challenge_id=source.mfa_challenge_id
                    and openpc.session_step_up_valid_until(source.participant_id,source.session_id,source.principal_id)>clock_timestamp()
                  end
                and (($7::uuid is null and source.used_at is null) or source.used_operation_id=$7::uuid)
              order by source.consumed_at desc,source.mfa_challenge_id desc limit 1
           )
           select challenge.mfa_challenge_id as "mfaChallengeId",
                  challenge.session_id as "webauthnSessionId",
                  verification.signer_credential_id as "webauthnSignerCredentialId",
                  verification.webauthn_assertion_binding_digest as "webauthnAssertionBindingDigest",
                  verification.evidence_cbor as "webauthnEvidenceCbor",
                  verification.evidence_digest as "webauthnEvidenceDigest",
                  verification.cose_sign1 as "webauthnCoseSign1"
             from control.mfa_challenge challenge
             join selected_challenge selected on selected.mfa_challenge_id=challenge.mfa_challenge_id
             join control.mutation_evidence verification
               on verification.participant_id=challenge.participant_id
              and verification.privacy_domain_id=$2
              and verification.principal_id=challenge.principal_id
              and verification.mfa_challenge_id=challenge.mfa_challenge_id
              and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
              and verification.aggregate_type='webauthn-verification'
              and verification.aggregate_id=challenge.session_id
              and verification.webauthn_assertion_binding_digest is not null
             join control.idempotency_record verification_idempotency
               on verification_idempotency.participant_id=verification.participant_id
              and verification_idempotency.privacy_domain_id=verification.privacy_domain_id
              and verification_idempotency.principal_id=verification.principal_id
              and verification_idempotency.operation_id=verification.operation_id
              and verification_idempotency.catalog_operation_id=verification.catalog_operation_id
              and verification_idempotency.input_digest=verification.candidate_digest
              and verification_idempotency.webauthn_assertion_binding_digest=
                  verification.webauthn_assertion_binding_digest
              and verification_idempotency.terminal_state='COMMITTED'
             join control.outbox_event verification_event
               on verification_event.participant_id=verification.participant_id
              and verification_event.privacy_domain_id=verification.privacy_domain_id
              and verification_event.aggregate_type=verification.aggregate_type
              and verification_event.aggregate_id=verification.aggregate_id
              and verification_event.event_type=
                  'openpc.identity.webauthn-verification.mutation.committed.v1'
              and verification_event.webauthn_assertion_binding_digest=
                  verification.webauthn_assertion_binding_digest
              and verification_event.payload_cbor=verification.evidence_cbor
              and verification_event.payload_digest=verification.evidence_digest
              and verification_event.cose_sign1=verification.cose_sign1
            where challenge.participant_id=$1 and challenge.principal_id=$3
              and challenge.action_intent_id=$4 and challenge.resource_digest=$5
            order by challenge.consumed_at desc limit 2`,
    [
      input.participantId,
      input.privacyDomainId,
      input.principalId,
      input.actionIntentId,
      input.candidateDigest,
      input.sessionId,
      input.consumedOperationId,
    ],
  );
  const stepUp = stepUpResult.rows[0];
  if (stepUpResult.rowCount !== 1 || stepUp === undefined) {
    throw new IdentityKernelError('PC-IDENTITY-1005');
  }
  return stepUp;
}
