import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { identityCredentialCoseContext, verifyCoseSign1Es256 } from '@openpc/security-kernel';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { authenticateHistoricalRuntimeStepUpEvidence } from './verified-step-up-evidence.js';
import { workloadCredentialSuccessorSql } from './workload-credential-successor.mjs';

const epoch = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .pipe(z.string().refine((value) => BigInt(value) <= 18446744073709551615n));
const inputSchema = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  predecessorCredentialId: z.uuidv7(),
  predecessorCredentialEpoch: epoch,
  successorCredentialId: z.uuidv7(),
  successorCredentialEpoch: epoch,
  credentialRotationOperationId: z.uuidv7(),
});

export class WorkloadSigningHandoverProvenanceUnavailable extends Error {
  constructor() {
    super('Workload signing handover provenance is unavailable');
  }
}
const hash = (value: Buffer) => createHash('sha256').update(value).digest();
const tagged = (value: Buffer) => `sha256:${value.toString('hex')}`;

/** Historical evidence only, through the caller's actual scoped runtime role.
 * No role change, current actor authorization, signing grant or provider effect
 * follows from this read. Admission must independently fence current authority,
 * workload/security epochs, old trust, exact selections and successor custody. */
export async function readWorkloadSigningHandoverProvenance(
  client: PoolClient,
  input: z.infer<typeof inputSchema>,
  verifier: IdentityRuntimeVerifier,
) {
  const value = inputSchema.parse(input);
  if (
    value.predecessorCredentialId === value.successorCredentialId ||
    BigInt(value.successorCredentialEpoch) !== BigInt(value.predecessorCredentialEpoch) + 1n
  )
    throw new WorkloadSigningHandoverProvenanceUnavailable();
  await client.query('select openpc.assert_request_context(true)');
  const result = await client.query<{
    principalId: string;
    makerPrincipalId: string;
    checkerPrincipalId: string;
    candidateDigest: Buffer;
    credentialPublicKey: Buffer;
    credentialPublicKeyDigest: Buffer;
    evidenceCbor: Buffer;
    evidenceDigest: Buffer;
    coseSign1: Buffer;
    verificationCandidateDigest: Buffer | null;
    verificationSessionId: string | null;
    verificationOccurredAt: Date | null;
  }>(
    `select successor.principal_id::text as "principalId",history.principal_id::text as "makerPrincipalId",
      history.checker_principal_id::text as "checkerPrincipalId",history.candidate_digest as "candidateDigest",
      credential.public_key_spki_der as "credentialPublicKey",credential.public_key_digest as "credentialPublicKeyDigest",
      history.evidence_cbor as "evidenceCbor",history.evidence_digest as "evidenceDigest",history.cose_sign1 as "coseSign1",
      verified.candidate_digest as "verificationCandidateDigest",verified.session_id::text as "verificationSessionId",
      verified.occurred_at as "verificationOccurredAt"
    from control.credential successor
    join control.mutation_evidence history on history.participant_id=successor.participant_id
      and history.privacy_domain_id=$2 and history.operation_id=$7
      and history.aggregate_id=$3 and history.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'
    join control.approval_decision_record decision on decision.participant_id=history.participant_id
      and decision.privacy_domain_id=history.privacy_domain_id and decision.approval_request_id=history.approval_request_id
      and decision.approver_principal_id=history.checker_principal_id and decision.decision='APPROVE'
      and decision.evidence_cbor=history.evidence_cbor and decision.cose_sign1=history.cose_sign1
    join control.credential credential on credential.participant_id=decision.participant_id
      and credential.credential_id=decision.signer_credential_id and credential.principal_id=decision.approver_principal_id
      and credential.kind='WEBAUTHN' and credential.valid_from<=decision.decided_at
      and (credential.valid_until is null or credential.valid_until>decision.decided_at)
    left join lateral (
      select verification.candidate_digest,challenge.session_id,verification.occurred_at
      from control.mutation_evidence verification join control.mfa_challenge challenge
        on challenge.participant_id=verification.participant_id and challenge.mfa_challenge_id=verification.mfa_challenge_id
        and challenge.principal_id=verification.principal_id and challenge.session_id=verification.aggregate_id
        and challenge.consumed_at is not null and challenge.mfa_challenge_id=decision.mfa_challenge_id
        and challenge.action_intent_id='ACT-POLICY_APPROVE_REQUEST-V1' and challenge.resource_digest=decision.decision_digest
      join control.idempotency_record committed on committed.participant_id=verification.participant_id
        and committed.privacy_domain_id=verification.privacy_domain_id and committed.principal_id=verification.principal_id
        and committed.operation_id=verification.operation_id and committed.catalog_operation_id=verification.catalog_operation_id
        and committed.input_digest=verification.candidate_digest and committed.terminal_state='COMMITTED'
        and committed.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
      join control.outbox_event event on event.participant_id=verification.participant_id
        and event.privacy_domain_id=verification.privacy_domain_id and event.aggregate_type=verification.aggregate_type
        and event.aggregate_id=verification.aggregate_id and event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
        and event.payload_cbor=verification.evidence_cbor and event.payload_digest=verification.evidence_digest
        and event.cose_sign1=verification.cose_sign1 and event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
      where verification.participant_id=decision.participant_id and verification.privacy_domain_id=decision.privacy_domain_id
        and verification.principal_id=decision.approver_principal_id and verification.signer_credential_id=decision.signer_credential_id
        and verification.evidence_cbor=decision.evidence_cbor and verification.cose_sign1=decision.cose_sign1
        and verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1' and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
        and verification.aggregate_type='webauthn-verification' and verification.evidence_digest=sha256(verification.evidence_cbor)
        and verification.webauthn_assertion_binding_digest is not null and verification.occurred_at>=challenge.consumed_at
        and verification.occurred_at<=decision.decided_at
    ) verified on true
    where openpc.matches_participant($1::uuid) and openpc.matches_privacy($2::uuid)
      and successor.participant_id=$1 and successor.credential_id=$5
      and ${workloadCredentialSuccessorSql({ participantId: '$1', privacyDomainId: '$2', predecessorId: '$3', predecessorEpoch: '$4::numeric', successorId: '$5', successorEpoch: '$6::numeric', operationId: '$7' })}
    limit 2`,
    [
      value.participantId,
      value.privacyDomainId,
      value.predecessorCredentialId,
      value.predecessorCredentialEpoch,
      value.successorCredentialId,
      value.successorCredentialEpoch,
      value.credentialRotationOperationId,
    ],
  );
  const row = result.rows[0];
  if (
    result.rowCount !== 1 ||
    !row ||
    !hash(row.evidenceCbor).equals(row.evidenceDigest) ||
    !hash(row.credentialPublicKey).equals(row.credentialPublicKeyDigest)
  )
    throw new WorkloadSigningHandoverProvenanceUnavailable();
  let authenticated = false;
  try {
    authenticated = verifyCoseSign1Es256(
      row.credentialPublicKey,
      row.evidenceCbor,
      row.coseSign1,
      identityCredentialCoseContext,
    );
    if (
      !authenticated &&
      row.verificationCandidateDigest &&
      row.verificationSessionId &&
      row.verificationOccurredAt
    ) {
      authenticated =
        (await verifier.verifyCanonicalAssertion(row.evidenceCbor, row.coseSign1)) !== undefined &&
        authenticateHistoricalRuntimeStepUpEvidence(
          {
            participantId: value.participantId,
            principalId: row.checkerPrincipalId,
            evidenceCbor: row.evidenceCbor,
          },
          {
            candidate_digest: row.verificationCandidateDigest,
            session_id: row.verificationSessionId,
            occurred_at: row.verificationOccurredAt,
          },
        );
    }
  } catch {
    authenticated = false;
  }
  if (!authenticated) throw new WorkloadSigningHandoverProvenanceUnavailable();
  return Object.freeze({
    ...value,
    principalId: row.principalId,
    makerPrincipalId: row.makerPrincipalId,
    checkerPrincipalId: row.checkerPrincipalId,
    candidateDigest: tagged(row.candidateDigest),
    evidenceDigest: tagged(row.evidenceDigest),
  });
}
