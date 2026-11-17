import type { PoolClient } from 'pg';
import { stepUpOnlyConfigurationOperations } from '../domain/configuration-step-up-admission.js';
import type { AuthorizationEvidenceContext } from './authorization-evidence-store.js';

/** A consumed actor verification augments, never replaces, runtime authorization. */
export async function stepUpReceiptInput(
  client: PoolClient,
  context: AuthorizationEvidenceContext,
  operationId: string,
) {
  const proof = context.authorization;
  if (
    proof.evidenceKind !== 'IDENTITY_RUNTIME_STEP_UP' ||
    !stepUpOnlyConfigurationOperations.includes(context.catalogOperationId)
  )
    throw new Error('Unadmitted step-up receipt input');
  const result = await client.query<{ id: string; digest: Buffer }>(
    `select v.mutation_evidence_id::text as id,v.evidence_digest as digest
     from control.mutation_evidence v join control.mfa_challenge c using(participant_id,mfa_challenge_id)
     where v.participant_id=$1 and v.privacy_domain_id=$2 and v.principal_id=$3
      and v.mfa_challenge_id=$4 and v.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
      and v.aggregate_type='webauthn-verification' and v.aggregate_id=$5
      and v.webauthn_assertion_binding_digest=$6
      and v.evidence_cbor=$7 and v.evidence_digest=$8 and v.cose_sign1=$9
      and c.session_id=$5 and c.principal_id=$3 and c.used_operation_id=$10
      and c.action_intent_id=$11 and c.used_at is not null`,
    [
      proof.participantId,
      proof.privacyDomainId,
      proof.principalId,
      proof.mfaChallengeId,
      proof.sessionId,
      proof.webauthnAssertionBindingDigest,
      proof.webauthnEvidenceCbor,
      proof.webauthnEvidenceDigest,
      proof.webauthnCoseSign1,
      operationId,
      context.actionIntentId,
    ],
  );
  if (result.rowCount !== 1 || !result.rows[0])
    throw new Error('Step-up receipt lacks consumed owner evidence');
  return { kind: 4 as const, evidenceId: result.rows[0].id, evidenceDigest: result.rows[0].digest };
}
