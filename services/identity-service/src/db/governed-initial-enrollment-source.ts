import { createHash } from 'node:crypto';
import {
  decodeIdentityAuthContextAssertionPayload,
  identityCredentialCoseContext,
  verifyCoseSign1Es256,
} from '@openpc/security-kernel';
import { identityActorKeyDigest } from '../domain/identity-runtime-authorization.js';
import {
  authenticateHistoricalRuntimeStepUpEvidence,
  verifyStoredStepUpEvidence,
} from './verified-step-up-evidence.js';
import type { PoolClient } from 'pg';
import {
  governedInitialEnrollmentAccountSchema,
  type GovernedInitialEnrollmentAccount,
} from '../domain/governed-initial-enrollment.js';
import type { IdentityRuntimeAssertionVerifier } from '../domain/identity-kernel.js';
import { IdentityKernelError } from '../domain/identity-errors.js';

interface EnrollmentSourceRow {
  authentication_occurrence_id: string;
  authentication_receipt_digest: Buffer;
  oidc_credential_id: string;
  oidc_credential_epoch: string;
  activation_evidence_cbor: Buffer;
  activation_evidence_digest: Buffer;
  activation_cose_sign1: Buffer;
  acceptance_evidence_cbor: Buffer;
  acceptance_evidence_digest: Buffer;
  acceptance_cose_sign1: Buffer;
  maker_evidence_cbor: Buffer;
  maker_evidence_digest: Buffer;
  maker_cose_sign1: Buffer;
  maker_principal_id: string;
  maker_session_id: string;
  maker_candidate_digest: Buffer;
  maker_occurred_at: Date;
  maker_public_key: Buffer;
  checker_principal_id: string;
  checker_credential_id: string;
  checker_public_key: Buffer;
  approval_request_id: string;
  acceptance_occurred_at: Date;
  enrollment_created_at: Date;
  enrollment_valid_until: Date;
}

export interface GovernedInitialEnrollmentSource {
  readonly authenticationOccurrenceId: string;
  readonly authenticationReceiptDigest: string;
  readonly oidcCredentialId: string;
  readonly oidcCredentialEpoch: string;
  readonly activationEvidenceDigest: string;
  readonly acceptanceEvidenceDigest: string;
  readonly makerVerificationEvidenceDigest: string;
  readonly enrollmentCreatedAt: Date;
  readonly enrollmentValidUntil: Date;
}

const sha = (value: Buffer) => createHash('sha256').update(value).digest();
const hex = (value: Buffer) => `sha256:${value.toString('hex')}`;
const denied = () => new IdentityKernelError('PC-IDENTITY-1002');

/** Read-only eligibility inside the existing principal/session enrollment
 * fence. This owner never creates an assignment or selects a different actor.
 * The profile is operator configuration, not a browser command field. */
export async function readGovernedInitialEnrollmentSource(
  client: PoolClient,
  input: {
    readonly account: GovernedInitialEnrollmentAccount;
    readonly sessionId: string;
    readonly enrollmentId: string;
    readonly profileDigest: string;
    readonly origin: string;
    readonly rpId: string;
  },
  verifier: IdentityRuntimeAssertionVerifier,
): Promise<GovernedInitialEnrollmentSource> {
  const account = governedInitialEnrollmentAccountSchema.parse(input.account);
  if (!/^sha256:[0-9a-f]{64}$/u.test(input.profileDigest)) throw denied();
  const settings = [
    ['openpc.initial_enrollment_session_id', input.sessionId],
    ['openpc.initial_enrollment_principal_id', account.principalId],
    ['openpc.initial_enrollment_profile_digest', input.profileDigest],
    ['openpc.initial_enrollment_id', input.enrollmentId],
  ] as const;
  for (const [name, value] of settings)
    await client.query('select set_config($1,$2,true)', [name, value]);
  let readCompleted = false;
  try {
    const selected = await client.query<EnrollmentSourceRow>(
      `select occurrence.occurrence_id::text authentication_occurrence_id,
          occurrence.receipt_digest authentication_receipt_digest,
          credential.credential_id::text oidc_credential_id,
          credential.credential_epoch::text oidc_credential_epoch,
          activation.evidence_cbor activation_evidence_cbor,
          activation.evidence_digest activation_evidence_digest,
          activation.cose_sign1 activation_cose_sign1,
          accepted.evidence_cbor acceptance_evidence_cbor,
          accepted.evidence_digest acceptance_evidence_digest,
          accepted.cose_sign1 acceptance_cose_sign1,
          maker_verification.evidence_cbor maker_evidence_cbor,
          maker_verification.evidence_digest maker_evidence_digest,
          maker_verification.cose_sign1 maker_cose_sign1,
          activation.principal_id::text maker_principal_id,
          maker_challenge.session_id::text maker_session_id,
          maker_verification.candidate_digest maker_candidate_digest,
          maker_verification.occurred_at maker_occurred_at,
          maker_credential.public_key_spki_der maker_public_key,
          decision.approver_principal_id::text checker_principal_id,
          decision.signer_credential_id::text checker_credential_id,
          checker_credential.public_key_spki_der checker_public_key,
          approval.approval_request_id::text approval_request_id,
          accepted.accepted_at acceptance_occurred_at,
          enrollment.created_at enrollment_created_at,
          enrollment.expires_at enrollment_valid_until
        from control.webauthn_enrollment enrollment
        join control.governed_initial_enrollment_profile profile on profile.participant_id=enrollment.participant_id
          and profile.privacy_domain_id=$4 and profile.profile_digest=enrollment.governed_initial_profile_digest
          and profile.profile_digest=$19 and profile.state='ACTIVE'
          and current_setting('openpc.local_qa_runtime',true)='1'
          and profile.valid_from<=clock_timestamp() and profile.valid_until>clock_timestamp()
          and profile.document->>'origin'=$17 and (profile.document->'accounts') @> jsonb_build_array($20::jsonb)
        join control.session session on session.participant_id=enrollment.participant_id
          and session.session_id=enrollment.session_id and session.principal_id=enrollment.principal_id
        join control.principal principal on principal.participant_id=session.participant_id
          and principal.principal_id=session.principal_id and principal.state='ACTIVE'
          and principal.kind in ('USER','PLATFORM_OPERATOR')
          and principal.authority_epoch=$5::bigint and session.authority_epoch=principal.authority_epoch
        join control.participant participant on participant.participant_id=principal.participant_id
          and participant.state='ACTIVE' and participant.authority_epoch=$6::bigint
          and session.participant_epoch=participant.authority_epoch
          and participant.root_privacy_domain_id=$4
        join control.privacy_domain privacy on privacy.participant_id=participant.participant_id
          and privacy.privacy_domain_id=$4 and privacy.state='ACTIVE'
        join control.participant_membership membership on membership.participant_id=principal.participant_id
          and membership.membership_id=principal.principal_id and membership.identity_subject_id=$7
        join control.participant_invitation_acceptance accepted on accepted.participant_id=principal.participant_id
          and accepted.privacy_domain_id=$4 and accepted.membership_id=principal.principal_id
          and accepted.identity_subject_id=membership.identity_subject_id
          and accepted.invitation_id=$8 and accepted.token_version=$9::bigint and accepted.operation_id=$10
        join control.participant_invitation invitation on invitation.participant_id=accepted.participant_id
          and invitation.privacy_domain_id=accepted.privacy_domain_id and invitation.invitation_id=accepted.invitation_id
          and invitation.state='ACCEPTED' and invitation.token_version=accepted.token_version
          and invitation.recipient_issuer=$11 and invitation.recipient_subject=$12
          and invitation.recipient_audience=$13
        join control.authentication_occurrence occurrence on occurrence.participant_id=session.participant_id
          and occurrence.privacy_domain_id=$4 and occurrence.principal_id=session.principal_id
          and occurrence.session_id=session.session_id and occurrence.method='OIDC_CODE_PKCE_S256'
          and occurrence.context_mode='PLATFORM' and sha256(occurrence.receipt)=occurrence.receipt_digest
        join control.credential credential on credential.participant_id=occurrence.participant_id
          and credential.principal_id=occurrence.principal_id and credential.credential_id=occurrence.credential_id
          and credential.kind='OIDC_SUBJECT' and credential.state='ACTIVE'
          and credential.issuer=$11 and credential.subject=$12 and credential.audience=$13
          and credential.valid_from<=clock_timestamp()
          and (credential.valid_until is null or credential.valid_until>clock_timestamp())
        join control.mutation_evidence activation on activation.participant_id=principal.participant_id
          and activation.privacy_domain_id=$4 and activation.operation_id=$14
          and activation.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
          and activation.catalog_operation_id='ID-OP-PRINCIPAL-ACTIVATE'
          and activation.aggregate_type='principal' and activation.aggregate_id=principal.principal_id
          and activation.candidate_digest=$15 and activation.approval_request_id is not null
          and activation.checker_principal_id is not null
          and activation.checker_principal_id<>activation.principal_id
          and activation.principal_id<>principal.principal_id
          and activation.checker_principal_id<>principal.principal_id
          and activation.mfa_challenge_id is not null
          and activation.webauthn_assertion_binding_digest is not null
        join control.mutation_candidate candidate on candidate.participant_id=activation.participant_id
          and candidate.privacy_domain_id=activation.privacy_domain_id
          and candidate.catalog_operation_id=activation.catalog_operation_id
          and candidate.resource_id=principal.principal_id and candidate.state='CONSUMED'
          and candidate.consumed_operation_id=activation.operation_id
          and candidate.candidate_digest=activation.candidate_digest
          and candidate.expected_revision=principal.row_version-1
          and candidate.candidate_document->>'principalId'=principal.principal_id::text
          and candidate.candidate_document->>'state'='ACTIVE'
        join control.approval_request approval on approval.participant_id=candidate.participant_id
          and approval.privacy_domain_id=candidate.privacy_domain_id
          and approval.approval_request_id=activation.approval_request_id
          and approval.subject_id=candidate.mutation_candidate_id
          and approval.subject_digest=candidate.candidate_digest
          and approval.subject_version=candidate.expected_revision
          and approval.action_intent_id=activation.action_intent_id
        join control.approval_decision_record decision on decision.participant_id=approval.participant_id
          and decision.privacy_domain_id=approval.privacy_domain_id
          and decision.approval_request_id=approval.approval_request_id
          and decision.decision='APPROVE'
          and decision.approver_principal_id=activation.checker_principal_id
          and decision.evidence_cbor=activation.evidence_cbor
          and decision.cose_sign1=activation.cose_sign1
          and sha256(decision.evidence_cbor)=activation.evidence_digest
        join control.mfa_challenge maker_challenge on maker_challenge.participant_id=activation.participant_id
          and maker_challenge.mfa_challenge_id=activation.mfa_challenge_id
          and maker_challenge.principal_id=activation.principal_id
          and maker_challenge.used_operation_id=activation.operation_id
          and maker_challenge.action_intent_id=activation.action_intent_id
          and maker_challenge.resource_id=principal.principal_id::text
          and maker_challenge.resource_digest=activation.candidate_digest
          and maker_challenge.signer_credential_id is not null
          and maker_challenge.signer_credential_epoch is not null
          and maker_challenge.consumed_at is not null and maker_challenge.used_at is not null
        join control.mutation_evidence maker_verification on maker_verification.participant_id=activation.participant_id
          and maker_verification.privacy_domain_id=activation.privacy_domain_id
          and maker_verification.principal_id=activation.principal_id
          and maker_verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
          and maker_verification.mfa_challenge_id=maker_challenge.mfa_challenge_id
          and maker_verification.signer_credential_id=maker_challenge.signer_credential_id
          and maker_verification.webauthn_assertion_binding_digest=activation.webauthn_assertion_binding_digest
          and maker_verification.aggregate_type='webauthn-verification'
          and maker_verification.aggregate_id=maker_challenge.session_id
          and maker_verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
          and maker_verification.occurred_at>=maker_challenge.consumed_at
        join control.credential maker_credential on maker_credential.participant_id=activation.participant_id
          and maker_credential.principal_id=activation.principal_id
          and maker_credential.credential_id=maker_challenge.signer_credential_id and maker_credential.kind='WEBAUTHN'
          and maker_credential.credential_epoch=maker_challenge.signer_credential_epoch
        join control.credential checker_credential on checker_credential.participant_id=decision.participant_id
          and checker_credential.principal_id=decision.approver_principal_id
          and checker_credential.credential_id=decision.signer_credential_id and checker_credential.kind='WEBAUTHN'
        join control.idempotency_record maker_committed on maker_committed.participant_id=maker_verification.participant_id
          and maker_committed.privacy_domain_id=maker_verification.privacy_domain_id
          and maker_committed.principal_id=maker_verification.principal_id
          and maker_committed.operation_id=maker_verification.operation_id
          and maker_committed.catalog_operation_id=maker_verification.catalog_operation_id
          and maker_committed.input_digest=maker_verification.candidate_digest
          and maker_committed.terminal_state='COMMITTED'
          and maker_committed.webauthn_assertion_binding_digest=maker_verification.webauthn_assertion_binding_digest
        join control.outbox_event maker_event on maker_event.participant_id=maker_verification.participant_id
          and maker_event.privacy_domain_id=maker_verification.privacy_domain_id
          and maker_event.aggregate_type=maker_verification.aggregate_type
          and maker_event.aggregate_id=maker_verification.aggregate_id
          and maker_event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
          and maker_event.payload_cbor=maker_verification.evidence_cbor
          and maker_event.payload_digest=maker_verification.evidence_digest
          and maker_event.cose_sign1=maker_verification.cose_sign1
          and maker_event.webauthn_assertion_binding_digest=maker_verification.webauthn_assertion_binding_digest
        where enrollment.participant_id=$1 and enrollment.principal_id=$2
          and enrollment.session_id=$3 and enrollment.enrollment_id=$16
          and enrollment.origin=$17 and enrollment.rp_id=$18
          and enrollment.replaced_credential_id is null and enrollment.consumed_at is null
          and enrollment.expires_at>clock_timestamp()
          and session.state='ACTIVE' and session.context_mode='PLATFORM'
          and session.step_up_verified_at is null
          and session.idle_expires_at>clock_timestamp() and session.absolute_expires_at>clock_timestamp()
          and not exists (select 1 from control.credential prior
            where prior.participant_id=$1 and prior.principal_id=$2 and prior.kind='WEBAUTHN')
          and not exists (select 1 from control.assignment ordinary
            where ordinary.participant_id=$1 and ordinary.principal_id=$2)
        -- Historical proofs are immutable and pinned; they need no UPDATE privilege.
        for share of profile,participant,principal,privacy,invitation,credential`,
      [
        account.participantId,
        account.principalId,
        input.sessionId,
        account.privacyDomainId,
        account.principalEpoch,
        account.participantEpoch,
        account.identitySubjectId,
        account.invitationId,
        account.invitationVersion,
        account.acceptanceOperationId,
        account.issuer,
        account.subject,
        account.audience,
        account.activationOperationId,
        Buffer.from(account.activationDigest.slice(7), 'hex'),
        input.enrollmentId,
        input.origin,
        input.rpId,
        Buffer.from(input.profileDigest.slice(7), 'hex'),
        JSON.stringify(account),
      ],
    );
    readCompleted = true;
    if (selected.rowCount !== 1 || !selected.rows[0]) throw denied();
    const row = selected.rows[0];
    // Exact operator-reviewed pins prevent substitution by a different but
    // authentically signed historical record. The signer roles remain separate.
    for (const [bytes, digest, expected] of [
      [
        row.activation_evidence_cbor,
        row.activation_evidence_digest,
        account.activationEvidenceDigest,
      ],
      [
        row.acceptance_evidence_cbor,
        row.acceptance_evidence_digest,
        account.acceptanceEvidenceDigest,
      ],
      [row.maker_evidence_cbor, row.maker_evidence_digest, account.makerVerificationEvidenceDigest],
    ] as const)
      if (!sha(bytes).equals(digest) || hex(digest) !== expected) throw denied();
    if (
      !(await verifyStoredStepUpEvidence(
        client,
        {
          participantId: account.participantId,
          privacyDomainId: account.privacyDomainId,
          principalId: row.checker_principal_id,
          credentialId: row.checker_credential_id,
          credentialPublicKey: row.checker_public_key,
          approvalRequestId: row.approval_request_id,
          evidenceCbor: row.activation_evidence_cbor,
          coseSign1: row.activation_cose_sign1,
        },
        verifier,
      ))
    )
      throw denied();
    const legacyMaker = verifyCoseSign1Es256(
      row.maker_public_key,
      row.maker_evidence_cbor,
      row.maker_cose_sign1,
      identityCredentialCoseContext,
    );
    const runtimeMaker =
      (await verifier.verifyCanonicalAssertion(row.maker_evidence_cbor, row.maker_cose_sign1)) !==
        undefined &&
      authenticateHistoricalRuntimeStepUpEvidence(
        {
          participantId: account.participantId,
          principalId: row.maker_principal_id,
          evidenceCbor: row.maker_evidence_cbor,
        },
        {
          candidate_digest: row.maker_candidate_digest,
          session_id: row.maker_session_id,
          occurred_at: row.maker_occurred_at,
        },
      );
    if (!legacyMaker && !runtimeMaker) throw denied();
    // Historical invitation rows retain the exact signed acceptance but not the
    // old JWT's full preimage. Authenticate its pinned bytes, recipient actor,
    // operation and issuance time; never invent or reissue those missing claims.
    const acceptance = decodeIdentityAuthContextAssertionPayload(row.acceptance_evidence_cbor);
    const acceptedAtNs = BigInt(row.acceptance_occurred_at.getTime()) * 1_000_000n;
    if (
      (await verifier.verifyCanonicalAssertion(
        row.acceptance_evidence_cbor,
        row.acceptance_cose_sign1,
      )) === undefined ||
      acceptance.assertionId !== account.acceptanceOperationId ||
      acceptance.actorKind !== 0 ||
      !acceptance.actorKeyDigest.equals(
        identityActorKeyDigest(account.participantId, account.principalId),
      ) ||
      acceptance.senderBindingKind !== 1 ||
      !acceptance.senderCredentialBindingDigest ||
      acceptance.issuedAtNs > acceptedAtNs + 5_000_000_000n ||
      acceptance.expiresAtNs <= acceptedAtNs ||
      acceptance.expiresAtNs <= acceptance.issuedAtNs ||
      acceptance.expiresAtNs - acceptance.issuedAtNs > 60_000_000_000n
    )
      throw denied();
    return {
      authenticationOccurrenceId: row.authentication_occurrence_id,
      authenticationReceiptDigest: hex(row.authentication_receipt_digest),
      oidcCredentialId: row.oidc_credential_id,
      oidcCredentialEpoch: row.oidc_credential_epoch,
      activationEvidenceDigest: hex(row.activation_evidence_digest),
      acceptanceEvidenceDigest: hex(row.acceptance_evidence_digest),
      makerVerificationEvidenceDigest: hex(row.maker_evidence_digest),
      enrollmentCreatedAt: row.enrollment_created_at,
      enrollmentValidUntil: row.enrollment_valid_until,
    };
  } finally {
    // A failed SQL statement leaves the transaction aborted; its owning
    // rollback/discard clears settings without masking the original failure.
    if (readCompleted)
      for (const [name] of settings) await client.query("select set_config($1,'',true)", [name]);
  }
}
