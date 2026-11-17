import {
  discoveryCertificateRecoveryEnrollment,
  discoveryCertificateRecoveryIntent,
  discoveryCertificateRecoveryCompletion,
  discoveryCertificateRecoveryReceiptView,
} from '../contracts/discovery-certificate-recovery.js';
import type {
  RecoveryCustodyEnrollment,
  RecoveryCustodyIntent,
} from '../domain/platform-recovery-ceremony.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { decodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import {
  platformAdministrationRecoveryEnrollment,
  platformRecoveryIntent,
} from '../contracts/platform-recovery.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeAssertionVerifier,
} from '../domain/identity-kernel.js';
import { identityActorKeyDigest } from '../domain/identity-runtime-authorization.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { readPlatformRecoverySession } from './platform-recovery-proof.js';

const deny = () => new PlatformRecoveryError();
const digest = (value: Buffer) => createHash('sha256').update(value).digest();

/** Historical receipt only. Root changes, rotated administrators and expiry never resurrect a lease. */
export async function readPlatformRecoveryReceipt(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
  verifier: IdentityRuntimeAssertionVerifier,
  preparationDigest?: string,
) {
  return readRecoveryReceipt(
    client,
    actor,
    enrollmentId,
    recoveryId,
    verifier,
    platformAdministrationRecoveryEnrollment,
    platformRecoveryIntent,
    'FIXED_PLATFORM_HANDOFF_ONLY',
    preparationDigest,
  );
}

export async function readDiscoveryCertificateRecoveryReceipt(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
  verifier: IdentityRuntimeAssertionVerifier,
) {
  const read = await readRecoveryReceipt(
    client,
    actor,
    enrollmentId,
    recoveryId,
    verifier,
    discoveryCertificateRecoveryEnrollment,
    discoveryCertificateRecoveryIntent,
    'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY',
  );
  const intent = discoveryCertificateRecoveryIntent.parse(read.receipt.intent);
  let completion;
  if (read.receipt.state === 'COMPLETED') {
    const selected = await client.query<{ completion: unknown }>(
      `select recovery.completion_result as completion
       from control.platform_recovery_case recovery
       join control.discovery_certificate_issuance issuance
         on issuance.participant_id=recovery.participant_id and issuance.privacy_domain_id=recovery.privacy_domain_id
         and issuance.recovery_id=recovery.recovery_id and issuance.state='COMMITTED'
         and issuance.committed_operation_id=recovery.completion_operation_id
       join control.credential successor on successor.participant_id=issuance.participant_id
         and successor.credential_id=issuance.successor_credential_id and successor.kind='WORKLOAD_MTLS'
         and successor.certificate_der=issuance.certificate_der and successor.secret_fingerprint=issuance.certificate_fingerprint
         and sha256(successor.certificate_der)=issuance.certificate_fingerprint
         and successor.public_key_spki_der=decode($5,'base64')
         and successor.public_key_digest=sha256(successor.public_key_spki_der)
       join control.credential predecessor on predecessor.participant_id=successor.participant_id
         and predecessor.credential_id=issuance.predecessor_credential_id and predecessor.kind='WORKLOAD_MTLS'
         and successor.rotated_from_credential_id=predecessor.credential_id
         and successor.principal_id=predecessor.principal_id and successor.audience=predecessor.audience
       join control.mutation_candidate candidate on candidate.participant_id=issuance.participant_id
         and candidate.privacy_domain_id=issuance.privacy_domain_id and candidate.mutation_candidate_id=issuance.mutation_candidate_id
         and candidate.state='CONSUMED' and candidate.consumed_operation_id=issuance.committed_operation_id
         and candidate.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' and candidate.resource_id=issuance.predecessor_credential_id
         and candidate.expected_revision=$6 and candidate.candidate_digest=issuance.candidate_digest
         and candidate.candidate_document=jsonb_build_object('replacedCredentialId',issuance.predecessor_credential_id::text,
           'credentialId',issuance.successor_credential_id::text,'publicKeySpkiDer',$5::text)
         and candidate.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(candidate.candidate_document),'UTF8'))
         and candidate.maker_principal_id=$7
       join control.approval_request approval on approval.participant_id=candidate.participant_id
         and approval.privacy_domain_id=candidate.privacy_domain_id and approval.subject_id=candidate.mutation_candidate_id
         and approval.approval_request_id=issuance.approval_request_id and approval.state='APPROVED'
         and approval.subject_digest=candidate.candidate_digest and approval.subject_version=candidate.expected_revision
         and approval.maker_principal_id=candidate.maker_principal_id
       join control.approval_decision_record decision on decision.participant_id=approval.participant_id
         and decision.privacy_domain_id=approval.privacy_domain_id and decision.approval_request_id=approval.approval_request_id
         and decision.decision='APPROVE' and decision.approver_principal_id=$8
         and decision.approver_principal_id<>approval.maker_principal_id
         and decision.candidate_digest=candidate.candidate_digest and decision.aggregate_version=candidate.expected_revision
       join control.mutation_evidence evidence on evidence.participant_id=candidate.participant_id
         and evidence.privacy_domain_id=candidate.privacy_domain_id and evidence.operation_id=issuance.committed_operation_id
         and evidence.catalog_operation_id=candidate.catalog_operation_id and evidence.action_intent_id=candidate.action_intent_id
         and evidence.aggregate_type='workload-credential' and evidence.aggregate_id=issuance.predecessor_credential_id
         and evidence.candidate_digest=candidate.candidate_digest and evidence.principal_id=approval.maker_principal_id
         and evidence.checker_principal_id=decision.approver_principal_id and evidence.approval_request_id=approval.approval_request_id
         and evidence.evidence_cbor=decision.evidence_cbor and evidence.cose_sign1=decision.cose_sign1
         and evidence.evidence_digest=sha256(evidence.evidence_cbor) and octet_length(evidence.cose_sign1)>0
         and evidence.webauthn_assertion_binding_digest is not null and evidence.mfa_challenge_id is not null
       join control.idempotency_record committed on committed.participant_id=evidence.participant_id
         and committed.privacy_domain_id=evidence.privacy_domain_id and committed.operation_id=evidence.operation_id
         and committed.terminal_state='COMMITTED' and committed.catalog_operation_id=evidence.catalog_operation_id
         and committed.action_intent_id=evidence.action_intent_id and committed.principal_id=evidence.principal_id
         and committed.input_digest=evidence.candidate_digest and committed.idempotency_key=candidate.idempotency_key
         and committed.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
         and committed.result_payload->>'credentialId'=successor.credential_id::text
         and committed.result_payload->>'replacedCredentialId'=predecessor.credential_id::text
         and committed.result_payload->>'principalId'=successor.principal_id::text
         and committed.result_payload->>'workloadId'=successor.audience and committed.result_payload->>'state'='ACTIVE'
       where recovery.participant_id=$1 and recovery.enrollment_id=$2 and recovery.recovery_id=$3
         and recovery.state='COMPLETED' and recovery.intent=$4::jsonb
         and issuance.predecessor_credential_id::text=recovery.intent#>>'{certificateRecovery,predecessorCredentialId}'
         and issuance.successor_credential_id::text=recovery.intent#>>'{certificateRecovery,successorCredentialId}'
         and successor.principal_id::text=recovery.intent#>>'{certificateRecovery,workloadPrincipalId}'
         and successor.audience='urn:openpc:workload:'||(recovery.intent#>>'{certificateRecovery,targetId}')
         and issuance.request=jsonb_build_object('credentialId',successor.credential_id::text,
           'participantId',successor.participant_id::text,'principalId',successor.principal_id::text,
           'workloadId',successor.audience,'publicKeySpkiDer',$5::text)
         and issuance.request_digest=sha256(convert_to(openpc.signing_canonical_json(issuance.request),'UTF8'))
         and octet_length(issuance.issuer_profile_digest)=32
         and recovery.completion_result=jsonb_build_object('issuanceId',issuance.issuance_id::text,
           'operationId',issuance.committed_operation_id::text,'predecessorCredentialId',issuance.predecessor_credential_id::text,
           'successorCredentialId',issuance.successor_credential_id::text,
           'certificateFingerprint','sha256:'||encode(issuance.certificate_fingerprint,'hex'))
         and exists(select 1 from control.discovery_certificate_issuer_attempt attempt
           where attempt.participant_id=issuance.participant_id and attempt.privacy_domain_id=issuance.privacy_domain_id
             and attempt.issuance_id=issuance.issuance_id and attempt.state='OBSERVED'
             and attempt.certificate_fingerprint=issuance.certificate_fingerprint)
         and exists(select 1 from control.outbox_event event where event.participant_id=evidence.participant_id
           and event.privacy_domain_id=evidence.privacy_domain_id and event.aggregate_type=evidence.aggregate_type
           and event.aggregate_id=evidence.aggregate_id and event.event_type='openpc.identity.workload-credential.mutation.committed.v1'
           and event.payload_cbor=evidence.evidence_cbor and event.payload_digest=evidence.evidence_digest
           and event.cose_sign1=evidence.cose_sign1 and event.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest)`,
      [
        actor.participantId,
        enrollmentId,
        recoveryId,
        intent,
        intent.certificateRecovery.successorPublicKeySpkiDer,
        intent.certificateRecovery.predecessorRevision,
        intent.administrators[0].principalId,
        intent.administrators[1].principalId,
      ],
    );
    if (selected.rowCount !== 1 || !selected.rows[0]) throw deny();
    completion = discoveryCertificateRecoveryCompletion.parse(selected.rows[0].completion);
  }
  return {
    ...read,
    receipt: discoveryCertificateRecoveryReceiptView.parse({
      ...read.receipt,
      ...(completion ? { completion } : {}),
    }),
  };
}

/** Authenticate the stored receipt before either a public session read or an
 * installation-owner historical read. Historical bytes never confer a lease. */
async function readRecoveryReceipt<
  E extends RecoveryCustodyEnrollment,
  I extends RecoveryCustodyIntent,
  A extends string,
>(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
  verifier: IdentityRuntimeAssertionVerifier,
  enrollmentParser: { parse(input: unknown): E },
  intentParser: { parse(input: unknown): I },
  authority: A,
  preparationDigest?: string,
) {
  const { receipt, enrollment } = await readStoredRecoveryReceipt(
    client,
    { participantId: actor.participantId },
    enrollmentId,
    recoveryId,
    verifier,
    enrollmentParser,
    intentParser,
    authority,
    true,
    preparationDigest,
  );
  if (
    ![
      enrollment.recoveryPrincipal.principalId,
      ...enrollment.custodians.map((v) => v.principalId),
      ...enrollment.administratorPrincipalIds,
    ].includes(actor.principalId)
  )
    throw deny();
  const session = await readPlatformRecoverySession(client, actor, enrollment);
  return { receipt, enrollment, session };
}

/** Scoped installation validation shares the original signature oracle. No
 * authenticated business actor is invented and no historical lease is current. */
export async function readStoredPlatformRecoveryReceipt(
  client: PoolClient,
  scope: { readonly participantId: string; readonly privacyDomainId: string },
  enrollmentId: string,
  recoveryId: string,
  verifier: IdentityRuntimeAssertionVerifier,
  preparationDigest?: string,
) {
  return readStoredRecoveryReceipt(
    client,
    scope,
    enrollmentId,
    recoveryId,
    verifier,
    platformAdministrationRecoveryEnrollment,
    platformRecoveryIntent,
    'FIXED_PLATFORM_HANDOFF_ONLY',
    false,
    preparationDigest,
  );
}

async function readStoredRecoveryReceipt<
  E extends RecoveryCustodyEnrollment,
  I extends RecoveryCustodyIntent,
  A extends string,
>(
  client: PoolClient,
  scope: { readonly participantId: string; readonly privacyDomainId?: string },
  enrollmentId: string,
  recoveryId: string,
  verifier: IdentityRuntimeAssertionVerifier,
  enrollmentParser: { parse(input: unknown): E },
  intentParser: { parse(input: unknown): I },
  authority: A,
  live = true,
  preparationDigest?: string,
) {
  const selected = await client.query<{
    document: unknown;
    documentDigest: Buffer;
    intent: unknown;
    intentDigest: Buffer;
    state: string;
    revision: string;
    activatedAt: Date | null;
    operationId: string | null;
    evidenceCbor: Buffer | null;
    evidenceDigest: Buffer | null;
    cose: Buffer | null;
    bindings:
      | { principalId: string; principalEpoch: string; envelopeId: string; assignmentId: string }[]
      | null;
    current: boolean;
    matchingPreparationCount?: string;
  }>(
    `select source.document,source.document_digest as "documentDigest",c.intent,c.intent_digest as "intentDigest",
      c.state,c.row_version::text as revision,c.activated_at as "activatedAt",c.activation_operation_id::text as "operationId",
      c.activation_evidence_cbor as "evidenceCbor",c.activation_evidence_digest as "evidenceDigest",c.activation_cose as cose,c.lease_bindings as bindings,
      ($5::boolean and c.state='ACTIVE' and c.valid_until>clock_timestamp() and jsonb_array_length(c.lease_bindings)=2
       and not exists(select 1 from jsonb_array_elements(c.lease_bindings) b
         where not openpc.platform_recovery_envelope_current((b->>'envelopeId')::uuid))) as current
      ${
        preparationDigest === undefined
          ? ''
          : `,(select count(*)::text from control.platform_recovery_case matching
        where matching.participant_id=c.participant_id and matching.privacy_domain_id=c.privacy_domain_id
          and matching.intent->'preparation'=c.intent->'preparation') as "matchingPreparationCount"`
      }
     from control.platform_recovery_case c join control.platform_recovery_enrollment source
      on source.participant_id=c.participant_id and source.privacy_domain_id=c.privacy_domain_id and source.enrollment_id=c.enrollment_id
     where c.participant_id=$1 and c.enrollment_id=$2 and c.recovery_id=$3
       and ($4::uuid is null or c.privacy_domain_id=$4)`,
    [scope.participantId, enrollmentId, recoveryId, scope.privacyDomainId ?? null, live],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw deny();
  const enrollment = enrollmentParser.parse(row.document);
  const intent = intentParser.parse(row.intent);
  if (
    enrollment.enrollmentId !== enrollmentId ||
    intent.enrollmentId !== enrollmentId ||
    intent.recoveryId !== recoveryId ||
    canonicalAuthorizationDigest(enrollment) !== `sha256:${row.documentDigest.toString('hex')}` ||
    canonicalAuthorizationDigest(intent) !== `sha256:${row.intentDigest.toString('hex')}` ||
    enrollment.participantId !== scope.participantId ||
    (scope.privacyDomainId !== undefined && enrollment.privacyDomainId !== scope.privacyDomainId) ||
    intent.enrollmentDigest !== canonicalAuthorizationDigest(enrollment)
  )
    throw deny();
  const proofs = await client.query<{ principalId: string; phase: string; proofId: string }>(
    `select principal_id::text as "principalId",phase,proof_id::text as "proofId" from control.platform_recovery_proof
     where participant_id=$1 and privacy_domain_id=$2 and recovery_id=$3 order by verified_at,proof_id`,
    [enrollment.participantId, enrollment.privacyDomainId, recoveryId],
  );
  let activation;
  if (row.operationId !== null) {
    if (
      !row.activatedAt ||
      !row.evidenceCbor ||
      !row.evidenceDigest ||
      !row.cose ||
      row.bindings?.length !== 2
    )
      throw deny();
    const result = {
      recoveryId,
      enrollmentId,
      operationId: row.operationId,
      state: 'ACTIVE' as const,
      authority,
      assurance: enrollment.assurance,
      activatedAt: row.activatedAt.toISOString(),
      expiresAt: intent.validUntil,
      intentDigest: canonicalAuthorizationDigest(intent),
      bindings: row.bindings.map((v) => ({
        principalId: v.principalId,
        principalEpoch: v.principalEpoch,
        envelopeId: v.envelopeId,
        assignmentId: v.assignmentId,
      })),
    };
    const claims = decodeIdentityAuthContextAssertionPayload(row.evidenceCbor);
    if (
      !digest(row.evidenceCbor).equals(row.evidenceDigest) ||
      claims.assertionId !== row.operationId ||
      !claims.actorKeyDigest.equals(
        identityActorKeyDigest(enrollment.participantId, enrollment.recoveryPrincipal.principalId),
      ) ||
      !claims.audienceDigest.equals(
        canonicalAuthorizationDigestBytes({
          domain: 'pc.identity.platform-recovery.activation.v1',
          value: { result, bindings: row.bindings },
        }),
      ) ||
      claims.issuedAtNs !== BigInt(row.activatedAt.getTime()) * 1000000n ||
      claims.expiresAtNs !== BigInt(Date.parse(intent.validUntil)) * 1000000n ||
      !(await verifier.verifyCanonicalAssertion(row.evidenceCbor, row.cose))
    )
      throw deny();
    activation = result;
  } else if (
    row.activatedAt ||
    row.evidenceCbor ||
    row.evidenceDigest ||
    row.cose ||
    row.bindings ||
    ['ACTIVE', 'COMPLETED'].includes(row.state)
  ) {
    throw deny();
  }
  // Receipt and complete same-scope preparation cardinality were selected in
  // one PostgreSQL statement snapshot. This proves correspondence at that read,
  // never the original browser token's issuance provenance or a business outcome.
  const closedPreparationCorrespondence =
    preparationDigest === undefined
      ? undefined
      : (() => {
          if (
            !['EXPIRED', 'REVOKED'].includes(row.state) ||
            !activation ||
            authority !== 'FIXED_PLATFORM_HANDOFF_ONLY' ||
            !('preparation' in intent) ||
            'continuation' in intent ||
            canonicalAuthorizationDigest(intent.preparation) !== preparationDigest ||
            row.matchingPreparationCount !== '1'
          )
            throw deny();
          return {
            schema: 'pc.identity.closed-platform-preparation-correspondence' as const,
            schemaVersion: 1 as const,
            preparationDigest,
            enrollmentId,
            recoveryId,
            intentDigest: canonicalAuthorizationDigest(intent),
            activationOperationId: activation.operationId,
          };
        })();
  return {
    receipt: {
      recoveryId,
      enrollmentId,
      intent,
      intentDigest: canonicalAuthorizationDigest(intent),
      state: row.state,
      revision: row.revision,
      assurance: enrollment.assurance,
      actors: {
        executorPrincipalId: enrollment.recoveryPrincipal.principalId,
        custodianPrincipalIds: enrollment.custodians.map((v) => v.principalId),
        administratorPrincipalIds: enrollment.administratorPrincipalIds,
      },
      authority: live && row.current === true && activation ? authority : ('NONE' as const),
      proofs: proofs.rows,
      ...(activation ? { activation } : {}),
      ...(closedPreparationCorrespondence ? { closedPreparationCorrespondence } : {}),
    },
    enrollment,
    activationEvidenceDigest: row.evidenceDigest,
  };
}
