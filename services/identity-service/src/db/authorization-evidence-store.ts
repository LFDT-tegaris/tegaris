import type { PoolClient } from 'pg';
import type { MutationAuthorization } from '../domain/control-mutation-authorization.js';

export interface AuthorizationEvidenceContext {
  readonly authorization: Exclude<MutationAuthorization, { readonly evidenceKind: 'READ_CONTEXT' }>;
  readonly actionIntentId: string;
  readonly catalogOperationId: string;
  readonly aggregateType: string;
  readonly resourceId: string;
}
/** Immutable authorization input, distinct from a signed business transition receipt. */
export async function persistAuthorizationEvidence(
  client: PoolClient,
  context: AuthorizationEvidenceContext,
  operationId: string,
  candidateDigest: Buffer,
  revision: string,
): Promise<string> {
  const proof = context.authorization;
  const evidence = await client.query<{ evidenceId: string }>(
    `insert into control.mutation_evidence
      (participant_id,privacy_domain_id,operation_id,principal_id,checker_principal_id,
       action_intent_id,catalog_operation_id,aggregate_type,aggregate_id,aggregate_version,
       candidate_digest,approval_request_id,mfa_challenge_id,bound_participant_epoch,
       bound_principal_epoch,bound_authority_envelope_id,bound_envelope_epoch,bound_assignment_id,
       webauthn_assertion_binding_digest,evidence_cbor,evidence_digest,cose_sign1,evidence_role,evidence_format)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24) returning mutation_evidence_id as "evidenceId"`,
    [
      proof.participantId,
      proof.privacyDomainId,
      operationId,
      proof.principalId,
      proof.checkerPrincipalId ?? null,
      context.actionIntentId,
      context.catalogOperationId,
      context.aggregateType,
      context.resourceId,
      revision,
      candidateDigest,
      proof.approvalRequestId ?? null,
      proof.mfaChallengeId ?? null,
      proof.participantEpoch,
      proof.principalEpoch,
      proof.authorityEnvelopeId,
      proof.authorityEpoch,
      proof.assignmentId,
      proof.webauthnAssertionBindingDigest ?? null,
      proof.evidenceCbor,
      proof.evidenceDigest,
      proof.coseSign1,
      proof.evidenceKind === 'IDENTITY_RUNTIME' || proof.evidenceKind === 'IDENTITY_RUNTIME_STEP_UP'
        ? 'AUTHORIZATION_INPUT'
        : 'LEGACY_UNQUALIFIED_BUSINESS_EVIDENCE',
      proof.evidenceKind === 'IDENTITY_RUNTIME' || proof.evidenceKind === 'IDENTITY_RUNTIME_STEP_UP'
        ? 'IDENTITY_RUNTIME_ASSERTION_3002_2_13'
        : 'LEGACY',
    ],
  );
  if (evidence.rowCount !== 1 || evidence.rows[0] === undefined)
    throw new Error('Incomplete authorization evidence insert');
  return evidence.rows[0].evidenceId;
}
