import type { PoolClient } from 'pg';
import { identityActorKeyDigest } from '../domain/identity-runtime-authorization.js';
import type { AuthorizationEvidenceContext } from './authorization-evidence-store.js';
import { workloadRenewalPolicyOperations } from '../../../../packages/security-kernel/src/workload-renewal-operations.js';

/** Explicit receipt-input admission; shared by the TypeScript and database owners. */
export const governedReceiptOperationIds: readonly string[] = [
  ...workloadRenewalPolicyOperations.map((operation) => operation.catalogOperationId),
  'MOD-OP-REGISTER',
  'MOD-OP-INSTALL',
  'MOD-OP-ENABLE',
  'MOD-OP-DISABLE',
  'CFG-OP-CREATE-EVIDENCE-HOLD',
  'CFG-OP-RELEASE-EVIDENCE-HOLD',
  'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD',
  'CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD',
  'CFG-OP-DELETE-LOCAL-EVIDENCE',
  'CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH',
  'CFG-OP-DELETE-RAW-PROOF-BATCH',
  'CFG-OP-DELETE-PROJECTION-BATCH',
  'CFG-OP-ADMIT-STORE-RETIREMENT',
  'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
  'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH',
  'CFG-OP-ACTIVATE-RETENTION-POLICY',
  'CFG-OP-RETIRE-RETENTION-POLICY',
];

/** Retain references to the real consumed approval and actor step-up, with their own evidence kinds. */
export async function governedReceiptInputs(
  client: PoolClient,
  context: AuthorizationEvidenceContext,
  operationId: string,
) {
  const proof = context.authorization;
  if (
    !governedReceiptOperationIds.includes(context.catalogOperationId) ||
    proof.evidenceKind !== 'USER_WEBAUTHN'
  )
    throw new Error('Unadmitted governed receipt input profile');
  const approval = await client.query<{ id: string; digest: Buffer }>(
    `select d.approval_decision_id::text as id,sha256(d.evidence_cbor) as digest
      from control.approval_decision_record d
      join control.approval_request r using(participant_id,privacy_domain_id,approval_request_id)
      join control.mutation_candidate c on c.participant_id=r.participant_id and c.privacy_domain_id=r.privacy_domain_id
        and c.mutation_candidate_id=r.subject_id and c.action_intent_id=r.action_intent_id
        and c.candidate_digest=r.subject_digest and c.expected_revision=r.subject_version
      where d.participant_id=$1 and d.privacy_domain_id=$2 and d.approval_request_id=$3
        and d.decision='APPROVE' and d.approver_principal_id=$4 and d.approver_principal_id<>$5
        and d.evidence_cbor=$6 and sha256(d.evidence_cbor)=$7 and d.cose_sign1=$8
        and c.state='CONSUMED' and c.consumed_operation_id=$9 and c.catalog_operation_id=$10`,
    [
      proof.participantId,
      proof.privacyDomainId,
      proof.approvalRequestId,
      proof.checkerPrincipalId,
      proof.principalId,
      proof.evidenceCbor,
      proof.evidenceDigest,
      proof.coseSign1,
      operationId,
      context.catalogOperationId,
    ],
  );
  const stepUp = await client.query<{ id: string; digest: Buffer }>(
    `select v.mutation_evidence_id::text as id,v.evidence_digest as digest
      from control.mutation_evidence v join control.mfa_challenge c using(participant_id,mfa_challenge_id)
      where v.participant_id=$1 and v.privacy_domain_id=$2 and v.principal_id=$3
        and v.mfa_challenge_id=$4 and v.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
        and v.evidence_cbor=$5 and v.evidence_digest=$6 and v.cose_sign1=$7
        and c.used_operation_id=$8 and c.action_intent_id=$9`,
    [
      proof.participantId,
      proof.privacyDomainId,
      proof.principalId,
      proof.mfaChallengeId,
      proof.webauthnEvidenceCbor,
      proof.webauthnEvidenceDigest,
      proof.webauthnCoseSign1,
      operationId,
      context.actionIntentId,
    ],
  );
  if (approval.rowCount !== 1 || stepUp.rowCount !== 1)
    throw new Error('Governed receipt lacks consumed owner evidence');
  return {
    actorKeyDigest: identityActorKeyDigest(proof.participantId, proof.principalId),
    authorizationEvidence: [
      {
        kind: 3 as const,
        evidenceId: approval.rows[0]!.id,
        evidenceDigest: approval.rows[0]!.digest,
      },
      { kind: 4 as const, evidenceId: stepUp.rows[0]!.id, evidenceDigest: stepUp.rows[0]!.digest },
    ],
  };
}
