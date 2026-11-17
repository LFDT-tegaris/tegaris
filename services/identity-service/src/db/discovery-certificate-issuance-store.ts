import type { PoolClient } from 'pg';
import { discoveryCertificateRecoveryIntent } from '../contracts/discovery-certificate-recovery.js';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';
import {
  nextDiscoveryCertificateIssuance,
  type DiscoveryCertificateIssuanceState,
} from '../domain/discovery-certificate-issuance.js';
import type { DiscoveryCertificateIssuancePolicy } from '../domain/discovery-certificate-issuance-policy.js';
import { assertDiscoveryCertificateRecoveryOperation } from '../domain/discovery-certificate-recovery.js';
import { IdentityKernelError } from '../domain/identity-errors.js';
import {
  workloadCertificateRequestDigest,
  type WorkloadCertificateRequest,
  type WorkloadIssuerRecovery,
  type IssuedWorkloadCertificate,
} from '../domain/workload-credential-issuer.js';
import type { WorkloadRotationEffectInput } from '../domain/workload-rotation-effect.js';
import type { MutationAuthorityContext } from './authority-fence.js';
import type { IdentityMutationAuthorization } from '../domain/identity-kernel.js';

const unavailable = () => new IdentityKernelError('PC-IDENTITY-1006');
interface IssuanceRow extends DiscoveryCertificateIssuanceState {
  readonly issuanceId: string;
  readonly certificateDer: Buffer | null;
  readonly requestDigest: Buffer;
  readonly candidateDigest: Buffer;
  readonly request: unknown;
  readonly approvalRequestId: string;
  readonly recoveryId: string;
}
export type DiscoveryCertificatePreparation =
  | {
      readonly kind: 'CLAIM';
      readonly issuanceId: string;
      readonly attemptId: string;
      readonly deadline: Date;
      readonly request: WorkloadCertificateRequest;
    }
  | {
      readonly kind: 'OBSERVED';
      readonly issuanceId: string;
      readonly request: WorkloadCertificateRequest;
    }
  | { readonly kind: 'UNAVAILABLE' };

/** Called only inside the shared admitted-mutation preparation transaction,
 * after current source, candidate, approval, crypto and one-use proof fences.
 * The SQL owners independently enforce the same real joins before a claim.
 * Returning a claim is not permission to issue until this transaction commits. */
export async function prepareDiscoveryCertificateIssuance(
  client: PoolClient,
  input: {
    readonly participantId: string;
    readonly operationId: string;
    readonly rotation: WorkloadRotationEffectInput;
    readonly candidate: unknown;
    readonly proof: IdentityMutationAuthorization;
    readonly authority: MutationAuthorityContext;
    readonly issuer: WorkloadIssuerRecovery;
    readonly policy: DiscoveryCertificateIssuancePolicy;
    readonly now: Date;
    readonly newId: () => string;
  },
): Promise<DiscoveryCertificatePreparation> {
  const maker = input.authority.makerAuthority;
  const selected = await client.query<{
    intent: unknown;
    candidateId: string;
    authorityExpiresAt: Date;
  }>(
    `select recovery.intent,candidate.mutation_candidate_id::text as "candidateId",
      least(recovery.valid_until,approval.expires_at,candidate.expires_at,
        challenge.expires_at,proof_session.idle_expires_at,proof_session.absolute_expires_at,credential.valid_until,
        case when proof_session.step_up_mfa_challenge_id is null then challenge.consumed_at+interval '5 minutes'
          else coalesce(openpc.session_step_up_valid_until(challenge.participant_id,challenge.session_id,challenge.principal_id),'-infinity'::timestamptz) end) as "authorityExpiresAt"
     from control.authority_envelope envelope join control.platform_recovery_case recovery
       on recovery.participant_id=envelope.participant_id and recovery.recovery_id=envelope.recovery_case_id
     join control.mutation_candidate candidate on candidate.participant_id=envelope.participant_id
       and candidate.maker_authority_envelope_id=envelope.authority_envelope_id
       and candidate.privacy_domain_id=recovery.privacy_domain_id and candidate.state='APPROVED'
       and candidate.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' and candidate.resource_id=$4
       and candidate.maker_principal_id=$5 and candidate.maker_session_id=$6
       and candidate.idempotency_key=$7 and candidate.candidate_document=$8::jsonb
       and candidate.expected_revision=$9 and candidate.expires_at>clock_timestamp()
     join control.approval_request approval on approval.participant_id=candidate.participant_id
       and approval.privacy_domain_id=candidate.privacy_domain_id and approval.subject_id=candidate.mutation_candidate_id
       and approval.subject_digest=candidate.candidate_digest and approval.subject_version=candidate.expected_revision
       and approval.approval_request_id=$10 and approval.state='APPROVED' and approval.expires_at>clock_timestamp()
     join control.session proof_session on proof_session.participant_id=candidate.participant_id
       and proof_session.principal_id=candidate.maker_principal_id and proof_session.session_id=candidate.maker_session_id
     join control.mfa_challenge challenge on challenge.participant_id=candidate.participant_id
       and challenge.principal_id=candidate.maker_principal_id and challenge.session_id=candidate.maker_session_id
       and challenge.action_intent_id=candidate.action_intent_id and challenge.resource_digest=candidate.candidate_digest
       and challenge.used_at is null and challenge.used_operation_id is null and challenge.expires_at>clock_timestamp()
       and (case when proof_session.step_up_mfa_challenge_id is null
         then challenge.consumed_at>clock_timestamp()-interval '5 minutes'
         else proof_session.step_up_mfa_challenge_id=challenge.mfa_challenge_id
           and openpc.session_step_up_valid_until(challenge.participant_id,challenge.session_id,challenge.principal_id)>clock_timestamp() end)
     join control.mutation_evidence verification on verification.participant_id=challenge.participant_id
       and verification.principal_id=challenge.principal_id and verification.privacy_domain_id=candidate.privacy_domain_id
       and verification.mfa_challenge_id=challenge.mfa_challenge_id and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
       and verification.aggregate_type='webauthn-verification' and verification.aggregate_id=challenge.session_id
       and verification.webauthn_assertion_binding_digest=$11
     join control.credential credential on credential.participant_id=verification.participant_id
       and credential.principal_id=verification.principal_id and credential.credential_id=verification.signer_credential_id
       and credential.kind='WEBAUTHN' and credential.state='ACTIVE' and credential.valid_from<=clock_timestamp()
       and (credential.valid_until is null or credential.valid_until>clock_timestamp())
     where envelope.participant_id=$1 and envelope.authority_envelope_id=$2 and recovery.privacy_domain_id=$3
       and envelope.representation='RECOVERY_V1' and openpc.platform_recovery_envelope_current(envelope.authority_envelope_id)`,
    [
      input.participantId,
      maker.authorityEnvelopeId,
      input.proof.privacyDomainId,
      input.rotation.replacedCredentialId,
      maker.principalId,
      maker.sessionId,
      input.proof.idempotencyKey,
      input.candidate,
      input.proof.aggregateVersion,
      input.proof.approvalRequestId,
      input.proof.webauthnAssertionBindingDigest ?? null,
    ],
  );
  const source = selected.rows[0];
  if (selected.rowCount !== 1 || !source || !Number.isFinite(source.authorityExpiresAt?.getTime()))
    throw unavailable();
  const intent = discoveryCertificateRecoveryIntent.parse(source.intent);
  if (
    maker.principalId !== intent.administrators[0].principalId ||
    input.proof.checkerPrincipalId !== intent.administrators[1].principalId
  )
    throw unavailable();
  assertDiscoveryCertificateRecoveryOperation(
    intent.certificateRecovery,
    'ID-OP-WORKLOAD-ROTATE',
    input.rotation.replacedCredentialId,
    input.proof.aggregateVersion,
    input.candidate,
  );
  const request: WorkloadCertificateRequest = {
    credentialId: input.rotation.credentialId,
    participantId: input.participantId,
    principalId: input.rotation.principalId,
    workloadId: input.rotation.workloadId,
    publicKeySpkiDer: input.rotation.publicKeySpkiDer,
  };
  const requestDocument = {
    ...request,
    publicKeySpkiDer: request.publicKeySpkiDer.toString('base64'),
  };
  const requestDigest = workloadCertificateRequestDigest(request);
  const candidateDigest = canonicalAuthorizationDigestBytes(input.candidate);
  await client.query(
    `insert into control.discovery_certificate_issuance
      (issuance_id,participant_id,privacy_domain_id,recovery_id,mutation_candidate_id,approval_request_id,candidate_digest,
       predecessor_credential_id,successor_credential_id,request,request_digest,issuer_profile_digest,replay_profile)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     on conflict (participant_id,privacy_domain_id,mutation_candidate_id) do nothing`,
    [
      input.newId(),
      input.participantId,
      input.proof.privacyDomainId,
      intent.recoveryId,
      source.candidateId,
      input.proof.approvalRequestId,
      candidateDigest,
      input.rotation.replacedCredentialId,
      input.rotation.credentialId,
      requestDocument,
      requestDigest,
      input.issuer.profileDigest,
      input.issuer.replayProfile,
    ],
  );
  const result = await client.query<IssuanceRow>(
    `select i.issuance_id::text as "issuanceId",i.recovery_id::text as "recoveryId",i.state,
      i.approval_request_id::text as "approvalRequestId",i.request,i.request_digest as "requestDigest",
      i.candidate_digest as "candidateDigest",i.issuer_profile_digest as "issuerProfileDigest",
      i.replay_profile as "replayProfile",i.certificate_der as "certificateDer",
      (select count(*)::int from control.discovery_certificate_issuer_attempt a where a.issuance_id=i.issuance_id) as "attemptCount",
      (select a.deadline from control.discovery_certificate_issuer_attempt a where a.issuance_id=i.issuance_id order by a.sequence desc limit 1) as "latestAttemptDeadline"
     from control.discovery_certificate_issuance i where i.participant_id=$1 and i.privacy_domain_id=$2
       and i.mutation_candidate_id=$3 for update`,
    [input.participantId, input.proof.privacyDomainId, source.candidateId],
  );
  const row = result.rows[0];
  if (
    result.rowCount !== 1 ||
    !row ||
    row.recoveryId !== intent.recoveryId ||
    row.approvalRequestId !== input.proof.approvalRequestId ||
    !row.requestDigest.equals(requestDigest) ||
    !row.candidateDigest.equals(candidateDigest) ||
    !canonicalAuthorizationDigestBytes(row.request).equals(requestDigest)
  )
    throw unavailable();
  const next = nextDiscoveryCertificateIssuance(
    row,
    input.issuer,
    input.policy,
    input.now,
    source.authorityExpiresAt,
  );
  if (next.kind === 'COMMIT_OBSERVATION')
    return { kind: 'OBSERVED', issuanceId: row.issuanceId, request };
  if (next.kind === 'MARK_AMBIGUOUS') {
    await client.query(
      `update control.discovery_certificate_issuer_attempt set state='AMBIGUOUS',row_version=row_version+1,
      finished_at=clock_timestamp(),failure_code='CLAIM_EXPIRED' where participant_id=$1 and privacy_domain_id=$2
        and issuance_id=$3 and state='ISSUING' and deadline<=clock_timestamp()`,
      [input.participantId, input.proof.privacyDomainId, row.issuanceId],
    );
    await client.query(
      `update control.discovery_certificate_issuance set state='AMBIGUOUS',row_version=row_version+1,
      updated_at=clock_timestamp(),failure_code='CLAIM_EXPIRED' where participant_id=$1 and privacy_domain_id=$2 and issuance_id=$3 and state='ISSUING'`,
      [input.participantId, input.proof.privacyDomainId, row.issuanceId],
    );
    return { kind: 'UNAVAILABLE' };
  }
  if (next.kind !== 'CLAIM') return { kind: 'UNAVAILABLE' };
  if (!input.proof.webauthnAssertionBindingDigest) throw unavailable();
  const attemptId = input.newId();
  await client.query(
    `insert into control.discovery_certificate_issuer_attempt
      (attempt_id,participant_id,privacy_domain_id,issuance_id,sequence,maker_principal_id,maker_session_id,
       preparation_operation_id,idempotency_key,authorization_evidence_cbor,authorization_evidence_digest,authorization_cose,
       webauthn_assertion_binding_digest,deadline)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      attemptId,
      input.participantId,
      input.proof.privacyDomainId,
      row.issuanceId,
      row.attemptCount + 1,
      maker.principalId,
      maker.sessionId,
      input.operationId,
      input.proof.idempotencyKey,
      input.proof.evidenceCbor,
      input.proof.evidenceDigest,
      input.proof.coseSign1,
      input.proof.webauthnAssertionBindingDigest,
      next.deadline,
    ],
  );
  await client.query(
    `update control.discovery_certificate_issuance set state='ISSUING',row_version=row_version+1,
    updated_at=clock_timestamp(),failure_code=null where participant_id=$1 and privacy_domain_id=$2 and issuance_id=$3`,
    [input.participantId, input.proof.privacyDomainId, row.issuanceId],
  );
  return { kind: 'CLAIM', issuanceId: row.issuanceId, attemptId, deadline: next.deadline, request };
}

/** Observation custody may outlive human authority. It changes neither a
 * credential nor a lease, candidate, approval, business effect or outbox. An
 * already ambiguous attempt is retained and never rewritten as observed. */
export async function finishDiscoveryCertificateIssuerAttempt(
  client: PoolClient,
  input: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly issuanceId: string;
    readonly attemptId: string;
  },
  observed?: IssuedWorkloadCertificate,
): Promise<void> {
  const failure = observed ? null : 'HTTP_IO_AMBIGUOUS';
  const state = observed ? 'OBSERVED' : 'AMBIGUOUS';
  const changed = await client.query(
    `update control.discovery_certificate_issuer_attempt set state=$5,row_version=row_version+1,finished_at=clock_timestamp(),
      certificate_fingerprint=$6,failure_code=$7 where participant_id=$1 and privacy_domain_id=$2 and issuance_id=$3 and attempt_id=$4 and state='ISSUING'`,
    [
      input.participantId,
      input.privacyDomainId,
      input.issuanceId,
      input.attemptId,
      state,
      observed?.certificateFingerprint ?? null,
      failure,
    ],
  );
  if (changed.rowCount !== 1) throw unavailable();
  const issuance = await client.query(
    `update control.discovery_certificate_issuance set state=$4,row_version=row_version+1,updated_at=clock_timestamp(),
      certificate_der=$5,certificate_fingerprint=$6,failure_code=$7 where participant_id=$1 and privacy_domain_id=$2 and issuance_id=$3 and state='ISSUING'`,
    [
      input.participantId,
      input.privacyDomainId,
      input.issuanceId,
      state,
      observed?.certificateDer ?? null,
      observed?.certificateFingerprint ?? null,
      failure,
    ],
  );
  if (issuance.rowCount !== 1) throw unavailable();
}

/** Final mutation admission has already been repeated. The observation is
 * locked and independently verified against the same current issuer profile;
 * this reader never dispatches the issuer. */
export async function readDiscoveryCertificateObservation(
  client: PoolClient,
  input: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly issuanceId: string;
    readonly request: WorkloadCertificateRequest;
  },
  issuer: WorkloadIssuerRecovery,
  now: Date,
): Promise<IssuedWorkloadCertificate> {
  const selected = await client.query<{
    certificateDer: Buffer;
    profileDigest: Buffer;
    replayProfile: string;
    requestDigest: Buffer;
  }>(
    `select certificate_der as "certificateDer",issuer_profile_digest as "profileDigest",replay_profile as "replayProfile",request_digest as "requestDigest"
     from control.discovery_certificate_issuance where participant_id=$1 and privacy_domain_id=$2 and issuance_id=$3 and state='OBSERVED' for update`,
    [input.participantId, input.privacyDomainId, input.issuanceId],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    !row.profileDigest.equals(issuer.profileDigest) ||
    row.replayProfile !== issuer.replayProfile ||
    !row.requestDigest.equals(workloadCertificateRequestDigest(input.request))
  )
    throw unavailable();
  const observed = issuer.verifyObservation(input.request, row.certificateDer, now);
  if (!observed) throw unavailable();
  return observed;
}

/** Runs after the native candidate consumption, signed evidence/outbox and
 * idempotent result have been durably written in the SAME final transaction. */
export async function completeDiscoveryCertificateRecoveryMutation(
  client: PoolClient,
  input: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly operationId: string;
    readonly predecessorCredentialId: string;
    readonly authorityEnvelopeId: string;
    readonly candidateDigest: Buffer;
  },
): Promise<void> {
  const selected = await client.query<{
    issuanceId: string;
    recoveryId: string;
    successorCredentialId: string;
    fingerprint: Buffer;
  }>(
    `select issuance.issuance_id::text as "issuanceId",issuance.recovery_id::text as "recoveryId",
      issuance.successor_credential_id::text as "successorCredentialId",issuance.certificate_fingerprint as fingerprint
     from control.discovery_certificate_issuance issuance join control.mutation_candidate candidate
       on candidate.participant_id=issuance.participant_id and candidate.privacy_domain_id=issuance.privacy_domain_id
       and candidate.mutation_candidate_id=issuance.mutation_candidate_id and candidate.state='CONSUMED'
       and candidate.consumed_operation_id=$3 and candidate.candidate_digest=issuance.candidate_digest
     where issuance.participant_id=$1 and issuance.privacy_domain_id=$2 and issuance.predecessor_credential_id=$4
       and issuance.state='OBSERVED' and issuance.candidate_digest=$5 for update of issuance`,
    [
      input.participantId,
      input.privacyDomainId,
      input.operationId,
      input.predecessorCredentialId,
      input.candidateDigest,
    ],
  );
  if (selected.rowCount === 0) {
    const purpose = await client.query<{ discovery: boolean }>(
      `select (representation='RECOVERY_V1' and exists(select 1 from control.platform_recovery_case c
        where c.participant_id=e.participant_id and c.recovery_id=e.recovery_case_id
          and c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent')) as discovery
       from control.authority_envelope e where e.participant_id=$1 and e.authority_envelope_id=$2`,
      [input.participantId, input.authorityEnvelopeId],
    );
    if (purpose.rowCount !== 1 || purpose.rows[0]!.discovery) throw unavailable();
    return;
  }
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row || row.fingerprint.length !== 32) throw unavailable();
  const changed = await client.query(
    `update control.discovery_certificate_issuance set state='COMMITTED',row_version=row_version+1,
    updated_at=clock_timestamp(),committed_operation_id=$4 where participant_id=$1 and privacy_domain_id=$2 and issuance_id=$3 and state='OBSERVED'`,
    [input.participantId, input.privacyDomainId, row.issuanceId, input.operationId],
  );
  if (changed.rowCount !== 1) throw unavailable();
  const completed = await client.query(
    `update control.platform_recovery_case set state='COMPLETED',row_version=row_version+1,
    updated_at=clock_timestamp(),completion_operation_id=$4,completion_result=$5
    where participant_id=$1 and privacy_domain_id=$2 and recovery_id=$3 and state='ACTIVE'`,
    [
      input.participantId,
      input.privacyDomainId,
      row.recoveryId,
      input.operationId,
      {
        issuanceId: row.issuanceId,
        operationId: input.operationId,
        predecessorCredentialId: input.predecessorCredentialId,
        successorCredentialId: row.successorCredentialId,
        certificateFingerprint: `sha256:${row.fingerprint.toString('hex')}`,
      },
    ],
  );
  if (completed.rowCount !== 1) throw unavailable();
}
