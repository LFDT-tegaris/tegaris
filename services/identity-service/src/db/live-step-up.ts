import type { PoolClient } from 'pg';
import { AuthorityFenceError } from './authority-fence.js';

export interface LiveStepUpBinding {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly principalId: string;
  readonly sessionId: string;
  readonly participantEpoch: string;
  readonly principalEpoch: string;
  readonly actionIntentId: string;
  readonly resourceDigest: Buffer;
  /** Required by typed attestation owners; older proof consumers retain their contract. */
  readonly resourceId?: string;
  readonly operationId: string;
}
export interface LiveStepUpRecord {
  readonly mfaChallengeId: string;
  readonly signerCredentialId: string;
  readonly signerCredentialEpoch: string;
  readonly evidenceCbor: Buffer;
  readonly evidenceDigest: Buffer;
  readonly coseSign1: Buffer;
  readonly assertionBindingDigest: Buffer;
  readonly credentialPublicKey: Buffer;
}

/** Existing committed WebAuthn record selection. The caller must fence current
 * actor/session/credential/action authority first, in Participant-before-child
 * order, and keep this transaction through effect + one-use consumption.
 * This lookup is not a signature check or permission grant. Typed attestation
 * owners additionally call verifyStoredStepUpEvidence for retained crypto. */
export async function lockLiveStepUpRecord(
  client: PoolClient,
  input: LiveStepUpBinding,
): Promise<LiveStepUpRecord> {
  const proof = await client.query<LiveStepUpRecord>(
    `select challenge.mfa_challenge_id::text as "mfaChallengeId",
              evidence.signer_credential_id::text as "signerCredentialId",
              credential.credential_epoch::text as "signerCredentialEpoch",
              credential.public_key_spki_der as "credentialPublicKey",
              evidence.evidence_cbor as "evidenceCbor",evidence.evidence_digest as "evidenceDigest",
              evidence.cose_sign1 as "coseSign1",
              evidence.webauthn_assertion_binding_digest as "assertionBindingDigest"
         from control.mfa_challenge challenge
         join control.mutation_evidence evidence
           on evidence.participant_id=challenge.participant_id
          and evidence.privacy_domain_id=$2 and evidence.principal_id=challenge.principal_id
          and evidence.mfa_challenge_id=challenge.mfa_challenge_id
          and evidence.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
          and evidence.aggregate_type='webauthn-verification'
          and evidence.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
         join control.idempotency_record verification
           on verification.participant_id=evidence.participant_id
          and verification.operation_id=evidence.operation_id
          and verification.catalog_operation_id=evidence.catalog_operation_id
          and verification.terminal_state='COMMITTED'
          and verification.input_digest=evidence.candidate_digest
          and verification.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
         join control.outbox_event verified_event
           on verified_event.participant_id=evidence.participant_id
          and verified_event.aggregate_type=evidence.aggregate_type
          and verified_event.aggregate_id=evidence.aggregate_id
          and verified_event.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
          and verified_event.payload_digest=evidence.evidence_digest
          and verified_event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
         join control.session proof_session on proof_session.participant_id=challenge.participant_id
          and proof_session.session_id=challenge.session_id and proof_session.principal_id=challenge.principal_id
         join control.credential credential
           on credential.participant_id=evidence.participant_id
          and credential.principal_id=evidence.principal_id
          and credential.credential_id=evidence.signer_credential_id
          and credential.kind='WEBAUTHN' and credential.state='ACTIVE'
          and credential.valid_from<=clock_timestamp()
          and (credential.valid_until is null or credential.valid_until>clock_timestamp())
        where challenge.participant_id=$1 and challenge.session_id=$3
          and challenge.principal_id=$4 and challenge.action_intent_id=$5
          and challenge.resource_digest=$6 and challenge.consumed_at is not null
          and case when proof_session.step_up_mfa_challenge_id is null
            then challenge.consumed_at>=clock_timestamp()-interval '5 minutes'
              and evidence.occurred_at>=clock_timestamp()-interval '5 minutes'
            else proof_session.step_up_mfa_challenge_id=challenge.mfa_challenge_id
              and openpc.session_step_up_valid_until(challenge.participant_id,challenge.session_id,challenge.principal_id)>clock_timestamp()
            end
          and challenge.expires_at>clock_timestamp()
          and (challenge.used_at is null or challenge.used_operation_id=$7)
          and evidence.bound_participant_epoch=$8 and evidence.bound_principal_epoch=$9
          and evidence.occurred_at>=challenge.consumed_at
          and ($10::text is null or (challenge.resource_id=$10
            and challenge.signer_credential_id=evidence.signer_credential_id
            and challenge.signer_credential_epoch=credential.credential_epoch))
        order by challenge.consumed_at desc,challenge.mfa_challenge_id desc
        limit 2 for update of challenge`,
    [
      input.participantId,
      input.privacyDomainId,
      input.sessionId,
      input.principalId,
      input.actionIntentId,
      input.resourceDigest,
      input.operationId,
      input.participantEpoch,
      input.principalEpoch,
      input.resourceId ?? null,
    ],
  );
  const selected = proof.rows[0];
  if (
    !selected ||
    proof.rows.some(
      (record) =>
        record.signerCredentialId !== selected.signerCredentialId ||
        record.signerCredentialEpoch !== selected.signerCredentialEpoch,
    )
  )
    throw new AuthorityFenceError();
  return selected;
}

export async function consumeLiveStepUpRecord(
  client: PoolClient,
  input: LiveStepUpBinding,
  proof: LiveStepUpRecord,
): Promise<void> {
  const used = await client.query(
    `update control.mfa_challenge
    set used_at=clock_timestamp(),used_operation_id=$2,row_version=row_version+1
    where mfa_challenge_id=$1 and used_at is null and participant_id=$3 and principal_id=$4
      and session_id=$5 and action_intent_id=$6 and resource_digest=$7
      and ($8::text is null or (resource_id=$8 and signer_credential_id=$9 and signer_credential_epoch=$10))`,
    [
      proof.mfaChallengeId,
      input.operationId,
      input.participantId,
      input.principalId,
      input.sessionId,
      input.actionIntentId,
      input.resourceDigest,
      input.resourceId ?? null,
      proof.signerCredentialId,
      proof.signerCredentialEpoch,
    ],
  );
  if (used.rowCount !== 1) throw new AuthorityFenceError();
}
