import { sql, type SQL, type SQLWrapper } from 'drizzle-orm';
import { pgPolicy } from 'drizzle-orm/pg-core';
import { controlOwnerRole, controlRuntimeRole, controlPlatformRuntimeRole } from './common.js';
import {
  platformRecoveryLeaseActions,
  platformRecoveryContinuationLeaseActions,
} from '../../domain/platform-recovery-lease.js';
import { discoveryCertificateRecoveryResumeActions } from '../../domain/discovery-certificate-recovery.js';
import { historyOwnerLeafPolicy } from './platform-recovery-source.js';

/** Complete partial-effect observation for the two declared administration
 * envelopes before any successor enrollment exists. Read visibility does not
 * make an expired lease usable or permit a candidate/approval mutation. */
export function rootExpiryPendingEffectSourcePolicy(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  exactEffectBinding: SQL,
) {
  return pgPolicy('root_expiry_pending_effect_source_read', {
    for: 'select',
    to: [controlOwnerRole],
    using: sql`openpc.matches_participant(${participantId}) and openpc.matches_privacy(${privacyDomainId})
      and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
      and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
      and exists(select 1 from control.platform_scope_replacement pending
        join control.platform_context root on root.platform_context_id=pending.platform_context_id
          and root.owner_participant_id=pending.participant_id and root.state='ACTIVE'
          and ((root.authority_epoch=pending.predecessor_epoch and root.row_version=pending.expected_root_revision)
            or openpc.root_expiry_pending_ancestry(pending.platform_context_id,to_jsonb(pending)) is not null)
        join (select platform_context_id,platform_authority_epoch,scope_cbor,admission_digest from control.platform_envelope_scope
          union all select platform_context_id,platform_authority_epoch,scope_cbor,admission_digest from control.platform_envelope_scope_successor
          union all select platform_context_id,platform_authority_epoch,scope_cbor,admission_digest from control.root_expiry_recovery_scope) scope
          on scope.platform_context_id=root.platform_context_id and scope.platform_authority_epoch=pending.predecessor_epoch
            and scope.admission_digest=pending.predecessor_digest
        where pending.participant_id=${participantId} and pending.privacy_domain_id=${privacyDomainId}
          and pending.state='WITHDRAWING' and pending.row_version=1 and pending.superseded_by is null
          and num_nonnulls(pending.commit_operation_id,pending.commit_candidate_id,pending.commit_approval_id,pending.readiness_digest,pending.committed_at)=0
          and pending.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(pending.candidate),'UTF8'))
          and pending.successor_digest=sha256(pending.successor_preimage)
          and (openpc.business_cbor(scope.scope_cbor)->>'4')::numeric<=floor(extract(epoch from clock_timestamp())*1000000000)
          and pending.candidate#>'{successorScope,runtime}'=openpc.platform_scope_document(scope.scope_cbor)->'runtime'
          and jsonb_array_length(pending.candidate->'administrators')=2
          and not exists(select 1 from jsonb_array_elements(pending.candidate->'administrators') administrator
            where (administrator#>>'{usable,validUntilNs}')::numeric>floor(extract(epoch from clock_timestamp())*1000000000)
              or (administrator#>>'{grantable,validUntilNs}')::numeric>floor(extract(epoch from clock_timestamp())*1000000000))
          and ${exactEffectBinding})`,
  });
}

/** The independently governed pending-expiry bootstrap has no new enrollment
 * yet. Read only its original consumed preparation event, without making an
 * expired ordinary recovery enrollment current again. */
export function rootExpiryPendingPreparationOutboxSourcePolicy(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  exactEventBinding: SQL,
) {
  const policy = pgPolicy('root_expiry_pending_preparation_outbox_source_read', {
    for: 'select',
    to: [controlOwnerRole],
    using: sql`openpc.matches_participant(${participantId}) and openpc.matches_privacy(${privacyDomainId})
      and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
      and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
      and exists(select 1 from control.platform_scope_replacement pending
        join control.platform_context root on root.platform_context_id=pending.platform_context_id
          and root.owner_participant_id=pending.participant_id and root.state='ACTIVE'
          and ((root.authority_epoch=pending.predecessor_epoch and root.row_version=pending.expected_root_revision)
            or openpc.root_expiry_pending_ancestry(pending.platform_context_id,to_jsonb(pending)) is not null)
        join (select platform_context_id,platform_authority_epoch,scope_cbor,admission_digest from control.platform_envelope_scope
          union all select platform_context_id,platform_authority_epoch,scope_cbor,admission_digest from control.platform_envelope_scope_successor
          union all select platform_context_id,platform_authority_epoch,scope_cbor,admission_digest from control.root_expiry_recovery_scope) scope
          on scope.platform_context_id=root.platform_context_id and scope.platform_authority_epoch=pending.predecessor_epoch
            and scope.admission_digest=pending.predecessor_digest
        join control.mutation_candidate candidate on candidate.participant_id=pending.participant_id
          and candidate.privacy_domain_id=pending.privacy_domain_id and candidate.mutation_candidate_id=pending.prepare_candidate_id
          and candidate.candidate_document=pending.candidate and candidate.candidate_digest=pending.candidate_digest
          and candidate.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE'
          and candidate.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
          and candidate.resource_id=pending.replacement_id and candidate.expected_revision=0
          and candidate.state='CONSUMED' and candidate.consumed_operation_id=pending.prepare_operation_id
        join control.approval_request approval on approval.participant_id=candidate.participant_id
          and approval.privacy_domain_id=candidate.privacy_domain_id and approval.approval_request_id=pending.prepare_approval_id
          and approval.subject_type='CONFIGURATION_CANDIDATE' and approval.subject_id=candidate.mutation_candidate_id
          and approval.subject_digest=candidate.candidate_digest and approval.subject_version=candidate.expected_revision
          and approval.state='APPROVED' and approval.maker_principal_id=candidate.maker_principal_id
          and approval.checker_principal_id<>approval.maker_principal_id
        join control.mutation_evidence evidence on evidence.participant_id=candidate.participant_id
          and evidence.privacy_domain_id=candidate.privacy_domain_id and evidence.operation_id=pending.prepare_operation_id
          and evidence.catalog_operation_id=candidate.catalog_operation_id and evidence.action_intent_id=candidate.action_intent_id
          and evidence.aggregate_type='platform-scope-replacement' and evidence.aggregate_id=pending.replacement_id
          and evidence.candidate_digest=candidate.candidate_digest and evidence.principal_id=candidate.maker_principal_id
          and evidence.checker_principal_id=approval.checker_principal_id and evidence.approval_request_id=approval.approval_request_id
          and evidence.evidence_digest=sha256(evidence.evidence_cbor) and octet_length(evidence.cose_sign1)>0
          and evidence.mfa_challenge_id is not null and evidence.webauthn_assertion_binding_digest is not null
        join control.idempotency_record committed on committed.participant_id=evidence.participant_id
          and committed.privacy_domain_id=evidence.privacy_domain_id and committed.operation_id=evidence.operation_id
          and committed.terminal_state='COMMITTED' and committed.principal_id=evidence.principal_id
          and committed.catalog_operation_id=evidence.catalog_operation_id and committed.action_intent_id=evidence.action_intent_id
          and committed.idempotency_key=candidate.idempotency_key and committed.input_digest=candidate.candidate_digest
          and committed.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
          and committed.result_payload->>'replacementId'=pending.replacement_id::text
          and committed.result_payload->>'successorDigest'='sha256:'||encode(pending.successor_digest,'hex')
        where pending.participant_id=${participantId} and pending.privacy_domain_id=${privacyDomainId}
          and pending.state='WITHDRAWING' and pending.row_version=1 and pending.superseded_by is null
          and num_nonnulls(pending.commit_operation_id,pending.commit_candidate_id,pending.commit_approval_id,pending.readiness_digest,pending.committed_at)=0
          and pending.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(pending.candidate),'UTF8'))
          and pending.successor_digest=sha256(pending.successor_preimage)
          and (openpc.business_cbor(scope.scope_cbor)->>'4')::numeric<=floor(extract(epoch from clock_timestamp())*1000000000)
          and pending.candidate#>'{successorScope,runtime}'=openpc.platform_scope_document(scope.scope_cbor)->'runtime'
          and jsonb_array_length(pending.candidate->'administrators')=2
          and not exists(select 1 from jsonb_array_elements(pending.candidate->'administrators') administrator
            where (administrator#>>'{usable,validUntilNs}')::numeric>floor(extract(epoch from clock_timestamp())*1000000000)
              or (administrator#>>'{grantable,validUntilNs}')::numeric>floor(extract(epoch from clock_timestamp())*1000000000))
          and ${exactEventBinding})`,
  });
  return historyOwnerLeafPolicy(
    policy,
    'outbox_event',
    sql`openpc.matches_participant(${participantId}) and openpc.matches_privacy(${privacyDomainId})
      and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
      and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
      and "control"."outbox_event"."aggregate_type"='platform-scope-replacement'
      and "control"."outbox_event"."event_type"='openpc.platform-scope-replacement.mutation.committed.v1'`,
  );
}

/** The installation owner authenticates the exact historical receipt before
 * committing a V2 enrollment. No lease exists at this boundary. */
export function rootExpiryAdministrationOutboxSourcePolicies(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  exactEventBinding: SQL,
) {
  return [
    // Only immutable events declared by the native pending lineage or a stored
    // V3 ceremony. This leaf never reads the outbox it is admitting.
    pgPolicy('root_expiry_pending_ancestry_receipt_read', {
      for: 'select',
      to: [controlOwnerRole, controlRuntimeRole, controlPlatformRuntimeRole],
      using: sql`case when "control"."outbox_event"."aggregate_type"='local-root-expiry-recovery'
        and "control"."outbox_event"."aggregate_sequence"=1
        and "control"."outbox_event"."event_type"='openpc.identity.local-root-expiry-recovery.completed.v1'
        then openpc.matches_participant(${participantId}) and openpc.matches_privacy(${privacyDomainId})
          and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
          and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
          and exists(select 1 from control.root_expiry_recovery_case receipt
            where receipt.participant_id=${participantId} and receipt.privacy_domain_id=${privacyDomainId}
              and receipt.state='COMPLETED' and ${exactEventBinding}
              and ((current_user='openpc_control_owner' and exists(
                select 1 from control.platform_scope_replacement pending
                cross join lateral jsonb_array_elements(
                  openpc.root_expiry_pending_ancestry(pending.platform_context_id,to_jsonb(pending))->'receipts') declared
                where pending.participant_id=receipt.participant_id and pending.privacy_domain_id=receipt.privacy_domain_id
                  and pending.state='WITHDRAWING' and pending.row_version=1
                  and declared->>'recoveryId'=receipt.recovery_id::text
                  and declared->>'enrollmentId'=receipt.enrollment_id::text
                  and declared->>'activationOperationId'=receipt.operation_id::text
                  and declared->>'enrollmentDigest'='sha256:'||encode(receipt.enrollment_digest,'hex')
                  and declared->>'intentDigest'='sha256:'||encode(receipt.intent_digest,'hex')
                  and declared->>'receiptDigest'='sha256:'||encode(receipt.evidence_digest,'hex')))
              or exists(select 1 from control.root_expiry_recovery_enrollment source
                left join control.root_expiry_recovery_case ceremony on ceremony.enrollment_id=source.enrollment_id
                  and ceremony.participant_id=source.participant_id and ceremony.privacy_domain_id=source.privacy_domain_id
                  and ceremony.enrollment_digest=source.document_digest and ceremony.enrollment_revision=source.row_version
                  and ceremony.intent->'rootAncestry'=source.document->'rootAncestry'
                where source.participant_id=receipt.participant_id and source.privacy_domain_id=receipt.privacy_domain_id
                  and source.state='ACTIVE' and source.row_version=1
                  and source.document->>'schemaVersion'='3'
                  and source.document->>'purpose'='pc.installation.local-root-expiry-pending-ancestry-custody.v3'
                  and source.document_digest=sha256(convert_to(openpc.signing_canonical_json(source.document),'UTF8'))
                  and (((ceremony.recovery_id is null or ceremony.state in ('DRAFT','REQUESTED')) and source.valid_from<=clock_timestamp()
                    and source.valid_until>clock_timestamp() and (ceremony.recovery_id is null or ceremony.valid_until>clock_timestamp())
                    and exists(select 1 from control.platform_context root where root.platform_context_id=source.platform_context_id
                      and root.owner_participant_id=source.participant_id and root.state='ACTIVE'
                      and root.authority_epoch::text=source.document->>'rootEpoch'
                      and root.row_version::text=source.document->>'rootRevision'))
                    or (ceremony.state='COMPLETED' and ceremony.operation_id is not null
                      and ceremony.evidence_digest=sha256(ceremony.evidence_cbor) and octet_length(ceremony.evidence_cose)>0))
                  and jsonb_array_length(source.document#>'{rootAncestry,receipts}') between 1 and 32
                  and exists(select 1 from jsonb_array_elements(source.document#>'{rootAncestry,receipts}') declared
                    where declared->>'recoveryId'=receipt.recovery_id::text
                      and declared->>'enrollmentId'=receipt.enrollment_id::text
                      and declared->>'activationOperationId'=receipt.operation_id::text
                      and declared->>'enrollmentDigest'='sha256:'||encode(receipt.enrollment_digest,'hex')
                      and declared->>'intentDigest'='sha256:'||encode(receipt.intent_digest,'hex')
                      and declared->>'receiptDigest'='sha256:'||encode(receipt.evidence_digest,'hex')))))
        else false end`,
    }),
    pgPolicy('root_expiry_admin_outbox_source_read', {
      for: 'select',
      to: [controlOwnerRole],
      using: sql`openpc.matches_participant(${participantId}) and openpc.matches_privacy(${privacyDomainId})
        and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
        and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
        and exists(select 1 from control.platform_recovery_enrollment source
          join control.root_expiry_recovery_case receipt on (receipt.recovery_id=source.root_expiry_recovery_id
            or exists(select 1 from jsonb_array_elements(coalesce(source.document#>'{source,ancestorReceipts}','[]'::jsonb)) declared
              where declared->>'recoveryId'=receipt.recovery_id::text
                and declared->>'enrollmentId'=receipt.enrollment_id::text
                and declared->>'activationOperationId'=receipt.operation_id::text
                and declared->>'receiptDigest'='sha256:'||encode(receipt.evidence_digest,'hex')))
            and receipt.participant_id=source.participant_id and receipt.privacy_domain_id=source.privacy_domain_id
          join control.platform_context root on root.platform_context_id=source.platform_context_id
            and root.owner_participant_id=source.participant_id and root.state='ACTIVE'
            and root.authority_epoch=source.root_epoch and root.row_version=source.root_revision
          where source.participant_id=${participantId} and source.privacy_domain_id=${privacyDomainId}
            and source.source_purpose in ('ROOT_EXPIRY_RECOVERY','ROOT_EXPIRY_RECOVERY_CONTINUATION','PENDING_ADMINISTRATION_EXPIRY_RECOVERY') and source.expired_replacement_id is null
            and source.state='ACTIVE' and source.row_version=1
            and source.document->>'schema' in ('pc.identity.platform-recovery-enrollment','pc.identity.discovery-certificate-recovery-enrollment')
            and ((source.source_purpose='ROOT_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='2')
              or (source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' and source.document->>'schema'='pc.identity.platform-recovery-enrollment' and source.document->>'schemaVersion'='3')
              or (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schema'='pc.identity.platform-recovery-enrollment' and source.document->>'schemaVersion'='4' and jsonb_typeof(source.document#>'{source,pendingExpiry}')='object'))
            and source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
            and source.valid_from<=clock_timestamp() and source.valid_until>clock_timestamp()
            and receipt.state='COMPLETED'
            and ((receipt.recovery_id=source.root_expiry_recovery_id
              and source.document#>>'{source,enrollmentId}'=receipt.enrollment_id::text
              and source.document#>>'{source,activationOperationId}'=receipt.operation_id::text
              and source.document#>>'{source,receiptDigest}'='sha256:'||encode(receipt.evidence_digest,'hex')
              and receipt.result->>'rootEpoch'=source.root_epoch::text
              and receipt.result->>'rootRevision'=source.root_revision::text
              and receipt.result->>'rootDigest'='sha256:'||encode(source.root_digest,'hex'))
            or (jsonb_array_length(source.document#>'{source,ancestorReceipts}') between 1 and 31
              and (receipt.result->>'rootEpoch')::numeric<source.root_epoch
              and exists(select 1 from jsonb_array_elements(source.document#>'{source,ancestorReceipts}') declared
                where declared->>'recoveryId'=receipt.recovery_id::text
                  and declared->>'enrollmentId'=receipt.enrollment_id::text
                  and declared->>'activationOperationId'=receipt.operation_id::text
                  and declared->>'receiptDigest'='sha256:'||encode(receipt.evidence_digest,'hex'))))
            and ${exactEventBinding})`,
    }),
    // Source4 installation authenticates these receipts before its own row
    // exists. Follow only the current V2 Root's exact predecessor chain;
    // these immutable facts provide no actor, session or lease authority.
    pgPolicy('root_expiry_admin_installation_receipt_read', {
      for: 'select',
      to: [controlOwnerRole],
      using: sql`openpc.matches_participant(${participantId}) and openpc.matches_privacy(${privacyDomainId})
        and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
        and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
        and exists(with recursive ancestry as (
          select completed.recovery_id,completed.participant_id,completed.privacy_domain_id,
            completed.intent,completed.result,1 as depth
          from control.root_expiry_recovery_case completed
          join control.root_expiry_recovery_scope scope on scope.recovery_id=completed.recovery_id
            and scope.owner_participant_id=completed.participant_id
            and scope.installation_privacy_domain_id=completed.privacy_domain_id
            and scope.activation_operation_id=completed.operation_id
            and scope.intent_digest=completed.intent_digest and scope.enrollment_digest=completed.enrollment_digest
            and scope.admission_digest=sha256(scope.admission_preimage)
          join control.platform_context root on root.platform_context_id=scope.platform_context_id
            and root.owner_participant_id=scope.owner_participant_id and root.state='ACTIVE'
            and root.authority_epoch=scope.platform_authority_epoch
          join control.root_expiry_recovery_enrollment custody on custody.enrollment_id=completed.enrollment_id
            and custody.participant_id=completed.participant_id and custody.privacy_domain_id=completed.privacy_domain_id
            and custody.document_digest=completed.enrollment_digest and custody.row_version=completed.enrollment_revision
            and custody.state='ACTIVE' and custody.document->>'schemaVersion'='2'
            and custody.document->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'
            and custody.document_digest=sha256(convert_to(openpc.signing_canonical_json(custody.document),'UTF8'))
          join control.root_expiry_recovery_trust trust on trust.custody_trust_id=custody.custody_trust_id
            and trust.participant_id=custody.participant_id and trust.privacy_domain_id=custody.privacy_domain_id
            and trust.document_digest=custody.custody_trust_digest and trust.state='ACTIVE' and trust.row_version=1
            and trust.document_digest=sha256(convert_to(openpc.signing_canonical_json(trust.document),'UTF8'))
            and trust.document->>'schemaVersion'='2' and trust.document->>'purpose'=custody.document->>'purpose'
            and trust.document->'pending'=custody.document->'pending'
          join control.platform_scope_replacement pending on pending.participant_id=custody.participant_id
            and pending.privacy_domain_id=custody.privacy_domain_id and pending.platform_context_id=scope.platform_context_id
            and pending.replacement_id::text=custody.document#>>'{pending,replacementId}'
          where completed.participant_id=${participantId} and completed.privacy_domain_id=${privacyDomainId}
            and completed.state='COMPLETED' and completed.intent->>'schemaVersion'='2'
            and completed.intent->>'purpose'='LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY'
            and completed.intent->'pending'=custody.document->'pending'
            and completed.intent_digest=sha256(convert_to(openpc.signing_canonical_json(completed.intent),'UTF8'))
            and completed.evidence_digest=sha256(completed.evidence_cbor) and octet_length(completed.evidence_cose)>0
            and completed.result=jsonb_build_object('rootEpoch',root.authority_epoch::text,
              'rootRevision',root.row_version::text,'rootDigest','sha256:'||encode(scope.admission_digest,'hex'),
              'operationId',completed.operation_id::text)
            and (openpc.business_cbor(scope.scope_cbor)->>'4')::numeric>floor(extract(epoch from clock_timestamp())*1000000000)
            and root.authority_epoch=pending.predecessor_epoch+1 and root.row_version=pending.expected_root_revision+1
            and scope.predecessor_epoch=pending.predecessor_epoch and scope.predecessor_digest=pending.predecessor_digest
            and pending.state='WITHDRAWING' and pending.row_version=1 and pending.superseded_by is null
            and num_nonnulls(pending.commit_operation_id,pending.commit_candidate_id,pending.commit_approval_id,pending.readiness_digest,pending.committed_at)=0
            and custody.document#>>'{pending,preparationCandidateId}'=pending.prepare_candidate_id::text
            and custody.document#>>'{pending,preparationOperationId}'=pending.prepare_operation_id::text
            and custody.document#>>'{pending,preparationApprovalId}'=pending.prepare_approval_id::text
            and custody.document#>>'{pending,preparationDigest}'='sha256:'||encode(pending.candidate_digest,'hex')
            and custody.document#>>'{pending,successorDigest}'='sha256:'||encode(pending.successor_digest,'hex')
            and custody.document#>>'{pending,pendingRecordDigest}'='sha256:'||encode(openpc.platform_scope_pending_record_digest(pending),'hex')
            and (select count(*) from control.root_expiry_recovery_proof proof
              where proof.recovery_id=completed.recovery_id and proof.participant_id=completed.participant_id
                and proof.privacy_domain_id=completed.privacy_domain_id and proof.intent_digest=completed.intent_digest)=4
          union all
          select predecessor.recovery_id,predecessor.participant_id,predecessor.privacy_domain_id,
            predecessor.intent,predecessor.result,ancestry.depth+1
          from ancestry join control.root_expiry_recovery_case predecessor
            on predecessor.participant_id=ancestry.participant_id and predecessor.privacy_domain_id=ancestry.privacy_domain_id
            and predecessor.result->>'rootEpoch'=ancestry.intent->>'predecessorEpoch'
            and predecessor.result->>'rootRevision'=ancestry.intent->>'predecessorRevision'
            and predecessor.result->>'rootDigest'=ancestry.intent->>'predecessorDigest'
          where ancestry.depth<32 and predecessor.state='COMPLETED'
            and predecessor.intent_digest=sha256(convert_to(openpc.signing_canonical_json(predecessor.intent),'UTF8'))
            and predecessor.evidence_digest=sha256(predecessor.evidence_cbor) and octet_length(predecessor.evidence_cose)>0
            and (predecessor.result->>'rootEpoch')::numeric=(predecessor.intent->>'predecessorEpoch')::numeric+1
            and (predecessor.result->>'rootRevision')::numeric=(predecessor.intent->>'predecessorRevision')::numeric+1
        ) select 1 from ancestry join control.root_expiry_recovery_case receipt
          on receipt.recovery_id=ancestry.recovery_id and receipt.participant_id=ancestry.participant_id
            and receipt.privacy_domain_id=ancestry.privacy_domain_id
          where ${exactEventBinding})`,
    }),
    // An active pending-expiry or unused-handoff lease must read the same
    // immutable Root event under its authentic action. Never call the consuming bridge
    // from its own outbox prerequisite visibility policy.
    ...rootExpiryAdministrationReceiptPolicies(
      participantId,
      privacyDomainId,
      sql`(source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY'
        or (source.source_purpose='ROOT_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='2'
          and source.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'
          and source.document#>>'{uneffectedPredecessor,schemaVersion}'='1'
          and lease.intent->'supersession'=jsonb_build_object(
            'recoveryId',source.document#>>'{uneffectedPredecessor,recoveryId}',
            'intentDigest',source.document#>>'{uneffectedPredecessor,intentDigest}',
            'replacementId',source.document#>>'{uneffectedPredecessor,replacementId}',
            'preparationDigest',source.document#>>'{uneffectedPredecessor,preparationDigest}',
            'preparationOperationId',source.document#>>'{uneffectedPredecessor,preparationOperationId}',
            'preparationApprovalId',source.document#>>'{uneffectedPredecessor,preparationApprovalId}',
            'expectedRevision',source.document#>>'{uneffectedPredecessor,expectedRevision}',
            'successorDigest',source.document#>>'{uneffectedPredecessor,successorDigest}')))
        and exists(select 1 from control.root_expiry_recovery_case receipt
          join control.root_expiry_recovery_enrollment custody on custody.enrollment_id=receipt.enrollment_id
            and custody.participant_id=receipt.participant_id and custody.privacy_domain_id=receipt.privacy_domain_id
            and custody.document_digest=receipt.enrollment_digest and custody.row_version=receipt.enrollment_revision
          join control.platform_context root on root.platform_context_id=source.platform_context_id
            and root.owner_participant_id=source.participant_id and root.state='ACTIVE'
            and root.authority_epoch=source.root_epoch and root.row_version=source.root_revision
          where receipt.participant_id=source.participant_id and receipt.privacy_domain_id=source.privacy_domain_id
            and receipt.recovery_id=source.root_expiry_recovery_id and receipt.state='COMPLETED'
            and receipt.intent->>'schemaVersion'='2' and receipt.intent->>'purpose'='LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY'
            and receipt.intent->'pending'=custody.document->'pending'
            and custody.state='ACTIVE' and custody.document->>'schemaVersion'='2'
            and custody.document->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'
            and source.document#>>'{source,enrollmentId}'=receipt.enrollment_id::text
            and source.document#>>'{source,activationOperationId}'=receipt.operation_id::text
            and source.document#>>'{source,receiptDigest}'='sha256:'||encode(receipt.evidence_digest,'hex')
            and receipt.result->>'rootEpoch'=source.root_epoch::text
            and receipt.result->>'rootRevision'=source.root_revision::text
            and receipt.result->>'rootDigest'='sha256:'||encode(source.root_digest,'hex')
            and ${exactEventBinding})`,
    ),
  ].map((policy) =>
    [
      'root_expiry_admin_outbox_source_read',
      'root_expiry_admin_installation_receipt_read',
    ].includes(policy.name)
      ? historyOwnerLeafPolicy(
          policy,
          'outbox_event',
          sql`openpc.matches_participant(${participantId}) and openpc.matches_privacy(${privacyDomainId})
          and "control"."outbox_event"."aggregate_type"='local-root-expiry-recovery'`,
        )
      : policy,
  );
}

/** Only prerequisite facts for the exact independently governed live lease.
 * Request context has no actor GUC: actor selection remains at the existing
 * authenticated authority owner, which consumes these facts and rechecks Root,
 * signers and original rows. This policy does not admit a caller or a grant.
 * Do not invoke that consuming predicate here: it reads these same witnesses. */
export function rootExpiryAdministrationReceiptPolicies(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  exactReceiptBinding: SQL,
  exactAncestorBinding?: SQL,
) {
  const binding =
    exactAncestorBinding === undefined
      ? exactReceiptBinding
      : sql`(${exactReceiptBinding}
    or (jsonb_array_length(source.document#>'{source,ancestorReceipts}') between 1 and 31
      and exists(select 1 from jsonb_array_elements(source.document#>'{source,ancestorReceipts}') declared
        where ${exactAncestorBinding})))`;
  const actions = sql.join(
    platformRecoveryLeaseActions.map((action) => sql`${sql.raw("'" + action + "'")}`),
    sql`, `,
  );
  const continuationActions = sql.join(
    platformRecoveryContinuationLeaseActions.map((action) => sql`${sql.raw("'" + action + "'")}`),
    sql`, `,
  );
  const discoveryActions = sql.join(
    discoveryCertificateRecoveryResumeActions.map((action) => sql`${sql.raw("'" + action + "'")}`),
    sql`, `,
  );
  return [
    pgPolicy('root_expiry_admin_receipt_prerequisite_read', {
      for: 'select',
      to: [controlOwnerRole, controlRuntimeRole, controlPlatformRuntimeRole],
      using: sql`openpc.matches_participant(${participantId}) and openpc.matches_privacy(${privacyDomainId})
      and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
      and exists(select 1 from control.platform_recovery_enrollment source
        join control.platform_recovery_case lease on lease.enrollment_id=source.enrollment_id
          and lease.participant_id=source.participant_id and lease.privacy_domain_id=source.privacy_domain_id
          and lease.enrollment_revision=source.row_version and lease.enrollment_digest=source.document_digest
        where source.participant_id=${participantId} and source.privacy_domain_id=${privacyDomainId}
          and source.source_purpose in ('ROOT_EXPIRY_RECOVERY','ROOT_EXPIRY_RECOVERY_CONTINUATION','PENDING_ADMINISTRATION_EXPIRY_RECOVERY') and source.expired_replacement_id is null
          and source.root_expiry_recovery_id is not null and source.state='ACTIVE' and source.row_version=1
          and source.document->>'schema' in ('pc.identity.platform-recovery-enrollment','pc.identity.discovery-certificate-recovery-enrollment')
          and ((source.source_purpose='ROOT_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='2')
              or (source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' and source.document->>'schema'='pc.identity.platform-recovery-enrollment' and source.document->>'schemaVersion'='3')
              or (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schema'='pc.identity.platform-recovery-enrollment' and source.document->>'schemaVersion'='4' and jsonb_typeof(source.document#>'{source,pendingExpiry}')='object')) and source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
          and source.valid_from<=clock_timestamp() and source.valid_until>clock_timestamp()
          and ((source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY')=(lease.intent ? 'pendingExpiry'))
          and (source.source_purpose<>'PENDING_ADMINISTRATION_EXPIRY_RECOVERY'
            or lease.intent->'pendingExpiry'=source.document#>'{source,pendingExpiry}')
          and ((source.document->>'schema'='pc.identity.platform-recovery-enrollment'
            and lease.intent->>'schema'='pc.identity.platform-recovery-intent'
            and (openpc.current_action_intent_id() in (${actions})
              or (source.document->>'schemaVersion'='3' and lease.intent ? 'continuation'
                and openpc.current_action_intent_id() in (${continuationActions}))
              or (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='4'
                and lease.intent->'pendingExpiry'=source.document#>'{source,pendingExpiry}'
                and (openpc.current_action_intent_id() in (${actions})
                  or (lease.intent ? 'approvalContinuation'
                    and openpc.current_action_intent_id()='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1')))))
            or (source.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
              and lease.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
              and openpc.current_action_intent_id() in (${discoveryActions})
              and (openpc.current_action_intent_id()<>'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
                or lease.intent->>'schemaVersion'='2')))
          and lease.state='ACTIVE'
          and lease.valid_from<=clock_timestamp() and lease.valid_until>clock_timestamp()
          and lease.activation_operation_id is not null and lease.activation_evidence_cbor is not null
          and lease.activation_evidence_digest is not null and lease.activation_cose is not null
          and jsonb_typeof(lease.lease_bindings)='array' and jsonb_array_length(lease.lease_bindings)=2
          and ${binding})`,
    }),
  ];
}

/** Only the proof oracle's exact persisted sessions are visible to its owner.
 * This creates no runtime privilege and permits no session mutation. */
export function rootExpiryRecoverySessionSourcePolicies(
  participantId: SQLWrapper,
  principalId: SQLWrapper,
  sessionId: SQLWrapper,
) {
  return [
    pgPolicy('root_expiry_recovery_session_read', {
      for: 'select',
      to: [controlOwnerRole],
      using: sql`openpc.matches_participant(${participantId})
        and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
        and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
        and exists(select 1 from control.root_expiry_recovery_proof proof
          join control.root_expiry_recovery_case recovery on recovery.recovery_id=proof.recovery_id
            and recovery.participant_id=proof.participant_id and recovery.privacy_domain_id=proof.privacy_domain_id
          where proof.participant_id=${participantId} and proof.principal_id=${principalId} and proof.session_id=${sessionId}
            and openpc.matches_privacy(proof.privacy_domain_id) and recovery.state='REQUESTED'
            and recovery.valid_until>clock_timestamp()
            and openpc.root_expiry_recovery_source_current(recovery.enrollment_id))`,
    }),
  ];
}
export function rootExpiryRecoveryInstallationSourcePolicies(
  participantId: SQLWrapper,
  identity: SQLWrapper,
  kind: 'principal' | 'credential' | 'executor-assignment',
) {
  const actors = sql`jsonb_build_array(enrollment.document->'recoveryPrincipal') || (enrollment.document->'custodians')`;
  const match =
    kind === 'principal'
      ? sql`exists(select 1 from jsonb_array_elements(${actors}) actor where actor->>'principalId'=${identity}::text) or enrollment.document->'administratorPrincipalIds' @> jsonb_build_array(${identity}::text)`
      : kind === 'credential'
        ? sql`exists(select 1 from jsonb_array_elements(${actors}) actor where actor->>'credentialId'=${identity}::text)`
        : sql`enrollment.document#>>'{recoveryPrincipal,principalId}'=${identity}::text`;
  const using = sql`openpc.matches_participant(${participantId}) and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
    and exists(select 1 from control.root_expiry_recovery_enrollment enrollment where enrollment.participant_id=${participantId}
      and openpc.matches_privacy(enrollment.privacy_domain_id) and enrollment.state='ACTIVE' and enrollment.row_version=1
      and enrollment.valid_from<=clock_timestamp() and enrollment.valid_until>clock_timestamp()
      and openpc.root_expiry_recovery_installation_source_current(enrollment.enrollment_id) and (${match}))`;
  return [
    pgPolicy('root_expiry_recovery_source_read', { for: 'select', to: [controlOwnerRole], using }),
    ...(kind === 'executor-assignment'
      ? []
      : [
          pgPolicy('root_expiry_recovery_source_lock', {
            for: 'update',
            to: [controlOwnerRole],
            using,
            withCheck: sql`false`,
          }),
        ]),
  ];
}
