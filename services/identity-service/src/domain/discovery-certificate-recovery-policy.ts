import { readDiscoveryApprovalResumePurpose } from '../db/discovery-approval-resume.js';
import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  discoveryCertificateRecoveryIntent,
  discoveryCertificateRotationCandidate,
} from '../contracts/discovery-certificate-recovery.js';
import { currentMutationCandidateSql } from '../db/mutation-candidate-fence.js';
import { discoveryCertificateRecoveryContextEligible } from '../db/platform-recovery-commit-purpose.js';
import { assertDiscoveryCertificateRecoveryOperation } from './discovery-certificate-recovery.js';
import type { PolicyAuthorizationRequest } from './policy-authorization.js';

const rotation = 'ID-OP-WORKLOAD-ROTATE';
const update = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
const requestApproval = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
const resumeApproval = 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
const readApproval = 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1';
const approve = 'ACT-POLICY_APPROVE_REQUEST-V1';
const hash = /^sha256:[0-9a-f]{64}$/u;

/** Admit only the enrolled Discovery purpose into the existing direct Platform
 * grant selector. This read supplies no authority and creates no candidate or
 * approval; the selected envelope must be the same one at the enclosing owner. */
export async function discoveryCertificateRecoveryPolicyScope(
  client: PoolClient,
  participantId: string,
  principalId: string,
  sessionId: string,
  input: PolicyAuthorizationRequest,
): Promise<{ authorityEnvelopeId: string } | false | undefined> {
  const rotating = input.catalogOperationId === rotation && input.actionIntentId === update;
  const proving =
    input.catalogOperationId === undefined &&
    input.actionIntentId === update &&
    input.stepUpCandidateDigest !== undefined;
  const requesting =
    input.catalogOperationId === undefined &&
    input.actionIntentId === requestApproval &&
    input.approvalCandidateDigest !== undefined;
  const reviewing =
    input.catalogOperationId === undefined &&
    [readApproval, approve].includes(input.actionIntentId);
  const resuming =
    input.catalogOperationId === undefined && input.actionIntentId === resumeApproval;
  if (!rotating && !proving && !requesting && !reviewing && !resuming) return undefined;
  const selected = await client.query<{
    authorityEnvelopeId: string;
    recoveryId: string;
    intent: unknown;
  }>(
    // Keep the currentness check behind the exact Discovery selection. Without
    // this boundary, the planner may evaluate unrelated recovery envelopes first.
    `select selected.authority_envelope_id::text as "authorityEnvelopeId",
       selected.recovery_id::text as "recoveryId",selected.intent
     from (select e.authority_envelope_id,c.recovery_id,c.intent
       from control.authority_envelope e join control.platform_recovery_case c
         on c.participant_id=e.participant_id and c.recovery_id=e.recovery_case_id
       where e.participant_id=$1 and e.principal_id=$2 and c.privacy_domain_id=$3
         and e.representation='RECOVERY_V1' and e.state='ACTIVE'
         and e.valid_from<=clock_timestamp() and e.valid_until>clock_timestamp()
         and c.state='ACTIVE' and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()
         and c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
       offset 0) selected
     where openpc.platform_recovery_envelope_current(selected.authority_envelope_id)`,
    [participantId, principalId, input.privacyDomainId],
  );
  const source = selected.rows[0];
  const parsed = discoveryCertificateRecoveryIntent.safeParse(source?.intent);
  if (selected.rowCount === 0) return undefined;
  if (
    selected.rowCount !== 1 ||
    !source ||
    !parsed.success ||
    parsed.data.recoveryId !== source.recoveryId
  )
    return false;
  const intent = parsed.data;
  const maker = intent.administrators[0].principalId;
  const checker = intent.administrators[1].principalId;
  if (![maker, checker].includes(principalId)) return false;
  const admitted = { authorityEnvelopeId: source.authorityEnvelopeId };
  if (
    intent.schemaVersion === 2 &&
    principalId === maker &&
    input.actionIntentId === readApproval
  ) {
    const visible = await client.query<{ visible: boolean }>(
      'select openpc.discovery_approval_resume_subject_visible($1,$2,$3,$4,$5) as visible',
      [
        participantId,
        input.privacyDomainId,
        principalId,
        source.authorityEnvelopeId,
        input.resourceId,
      ],
    );
    if (visible.rows[0]?.visible === true) return admitted;
  }
  if (resuming && input.approvalResume === undefined && input.stepUpCandidateDigest === undefined)
    return false;
  if (
    intent.schemaVersion === 2 &&
    principalId === maker &&
    (resuming || input.actionIntentId === readApproval || (rotating && input.approvalResume))
  ) {
    const approvalId =
      input.approvalResume?.approvalRequestId.slice('urn:openpc:resource:'.length) ??
      input.resourceId;
    const purpose = await readDiscoveryApprovalResumePurpose(client, {
      participantId,
      privacyDomainId: input.privacyDomainId,
      principalId,
      authorityEnvelopeId: source.authorityEnvelopeId,
      approvalId,
      requireLeaf: input.approvalResume === undefined,
    });
    if (
      purpose &&
      (input.approvalResume === undefined ||
        canonicalAuthorizationDigest(input.approvalResume) === purpose.requestDigest) &&
      (input.stepUpCandidateDigest === undefined ||
        input.stepUpCandidateDigest === purpose.requestDigest) &&
      (!rotating ||
        (input.resourceId === purpose.resourceId &&
          input.proposedMutation?.expectedRevision === purpose.expectedRevision &&
          canonicalAuthorizationDigest(input.proposedMutation.candidate) ===
            purpose.candidateDigest))
    )
      return admitted;
    if (resuming || (rotating && input.approvalResume)) return false;
  }
  if (resuming) return false;
  if (rotating && input.proposedMutation) {
    return (await discoveryCertificateRecoveryContextEligible(client, {
      participantId,
      privacyDomainId: input.privacyDomainId,
      principalId,
      authorityEnvelopeId: source.authorityEnvelopeId,
      catalogOperationId: rotation,
      actionIntentId: update,
      resourceId: input.resourceId,
      ...input.proposedMutation,
    }))
      ? admitted
      : false;
  }
  if (proving) {
    return principalId === maker &&
      input.resourceId === intent.certificateRecovery.predecessorCredentialId &&
      input.stepUpCandidateDigest ===
        canonicalAuthorizationDigest(
          discoveryCertificateRotationCandidate(intent.certificateRecovery),
        )
      ? admitted
      : false;
  }
  const candidateDigest = rotating
    ? input.stagedMutation?.candidateDigest
    : requesting
      ? input.approvalCandidateDigest
      : undefined;
  if ((rotating || requesting) && (!candidateDigest || !hash.test(candidateDigest))) return false;
  if ((rotating || requesting) && principalId !== maker) return false;
  if (requesting && input.resourceId !== maker) return false;
  const result = await client.query<{
    candidate: unknown;
    candidateDigest: Buffer;
    expectedRevision: string;
    resourceId: string;
    approvalRevision: string | null;
    checkerPrincipalId: string | null;
    makerSessionId: string;
  }>(
    `select c.candidate_document as candidate,c.candidate_digest as "candidateDigest",
       c.expected_revision::text as "expectedRevision",c.resource_id::text as "resourceId",
       a.row_version::text as "approvalRevision",a.checker_principal_id::text as "checkerPrincipalId",
       c.maker_session_id::text as "makerSessionId"
     from control.mutation_candidate c
     join control.authority_envelope maker on maker.participant_id=c.participant_id
       and maker.authority_envelope_id=c.maker_authority_envelope_id
       and maker.representation='RECOVERY_V1' and maker.recovery_case_id=$5
       and maker.principal_id=$4 and openpc.platform_recovery_envelope_current(maker.authority_envelope_id)
     left join control.approval_request a on a.participant_id=c.participant_id
       and a.privacy_domain_id=c.privacy_domain_id and a.subject_type='CONFIGURATION_CANDIDATE'
       and a.subject_id=c.mutation_candidate_id and a.subject_digest=c.candidate_digest
       and a.subject_version=c.expected_revision and a.action_intent_id=c.action_intent_id
       and a.maker_principal_id=c.maker_principal_id
     where c.participant_id=$1 and c.privacy_domain_id=$2 and c.maker_principal_id=$4
       and c.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'
       and c.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
       and ((c.state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED')
         and c.expires_at>clock_timestamp() and ${currentMutationCandidateSql('c')})
         or ($9 and c.state='CONSUMED' and c.consumed_operation_id is not null))
       and (not $6 or c.maker_session_id=$10::uuid)
       and (case when $6 then c.candidate_digest=$7
         else a.approval_request_id::text=$3 and a.checker_principal_id=$8
           and ($9 or (a.state in ('OPEN','APPROVED') and a.expires_at>clock_timestamp())) end)`,
    [
      participantId,
      input.privacyDomainId,
      input.resourceId,
      maker,
      intent.recoveryId,
      rotating || requesting,
      candidateDigest ? Buffer.from(candidateDigest.slice(7), 'hex') : null,
      checker,
      input.actionIntentId === readApproval,
      sessionId,
    ],
  );
  const row = result.rows[0];
  if ((rotating || requesting) && row?.makerSessionId !== sessionId) return false;
  if (
    result.rowCount !== 1 ||
    !row ||
    row.candidateDigest.length !== 32 ||
    canonicalAuthorizationDigest(row.candidate) !== `sha256:${row.candidateDigest.toString('hex')}`
  )
    return false;
  try {
    assertDiscoveryCertificateRecoveryOperation(
      intent.certificateRecovery,
      rotation,
      row.resourceId,
      row.expectedRevision,
      row.candidate,
    );
  } catch {
    return false;
  }
  if (
    rotating &&
    (input.resourceId !== row.resourceId ||
      input.stagedMutation?.expectedRevision !== row.expectedRevision)
  )
    return false;
  if (requesting) {
    const count = await client.query<{ count: string }>(
      `select ((select count(*) from control.mutation_candidate c where participant_id=$1
         and privacy_domain_id=$2 and candidate_digest=$3 and ${currentMutationCandidateSql('c')})+
       (select count(*) from control.policy_version where participant_id=$1
         and privacy_domain_id=$2 and semantic_digest=$3)+
       (select count(*) from control.identity_envelope_proposal where participant_id=$1
         and privacy_domain_id=$2 and proposal_digest=$3))::text count`,
      [participantId, input.privacyDomainId, row.candidateDigest],
    );
    if (count.rows[0]?.count !== '1') return false;
  }
  if (input.actionIntentId === approve) {
    if (principalId !== checker || row.checkerPrincipalId !== checker) return false;
    if (
      input.stepUpCandidateDigest !== undefined &&
      input.stepUpCandidateDigest !==
        canonicalAuthorizationDigest({
          actionIntentId: approve,
          approvalRequestId: `urn:openpc:resource:${input.resourceId}`,
          candidateDigest: `sha256:${row.candidateDigest.toString('hex')}`,
          expectedRevision: row.approvalRevision,
          decision: 'APPROVE',
        })
    )
      return false;
  }
  return admitted;
}
