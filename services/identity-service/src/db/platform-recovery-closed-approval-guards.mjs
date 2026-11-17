/** Native correspondence for the explicit closed-approval source only.
 * Signature authentication remains mandatory in the installation/custody owner. */
export const platformRecoveryClosedApprovalLinkSql = `
CREATE OR REPLACE FUNCTION openpc.platform_recovery_closed_approval_link_current(p_participant uuid,p_enrollment uuid,p_recovery uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE source control.platform_recovery_enrollment; original control.platform_recovery_enrollment;
 history control.platform_recovery_case; link jsonb; closure jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(p_participant)
  OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1' THEN RETURN false; END IF;
 SELECT * INTO STRICT source FROM control.platform_recovery_enrollment e WHERE e.participant_id=p_participant
  AND e.privacy_domain_id=openpc.current_privacy_domain_id() AND e.enrollment_id=p_enrollment
  AND e.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' AND e.document->>'schemaVersion'='4'
  AND e.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' AND e.state='ACTIVE' AND e.row_version=1
  AND e.valid_from<=clock_timestamp() AND e.valid_until>clock_timestamp();
 link:=source.document#>'{source,closedApproval}'; closure:=link->'closure';
 IF link->>'schema' IS DISTINCT FROM 'pc.identity.closed-platform-approval-source'
  OR link->>'schemaVersion' IS DISTINCT FROM '1' OR link#>>'{approval,attempt}' IS DISTINCT FROM '1'
  OR link#>>'{approval,recoveryId}' IS DISTINCT FROM p_recovery::text
  OR source.document_digest<>sha256(convert_to(openpc.signing_canonical_json(source.document),'UTF8'))
 THEN RETURN false; END IF;
 SELECT * INTO STRICT original FROM control.platform_recovery_enrollment e WHERE e.participant_id=p_participant
  AND e.privacy_domain_id=source.privacy_domain_id AND e.enrollment_id::text=link->>'enrollmentId'
  AND e.enrollment_id<>source.enrollment_id AND e.source_purpose=source.source_purpose
  AND e.state='ACTIVE' AND e.row_version=1;
 SELECT * INTO STRICT history FROM control.platform_recovery_case c WHERE c.participant_id=p_participant
  AND c.privacy_domain_id=source.privacy_domain_id AND c.enrollment_id=original.enrollment_id
  AND c.recovery_id=p_recovery;
 IF original.document->>'schemaVersion' IS DISTINCT FROM '4'
  OR original.document#>'{source}' ? 'closedApproval'
  OR original.document_digest<>sha256(convert_to(openpc.signing_canonical_json(original.document),'UTF8'))
  OR 'sha256:'||encode(original.document_digest,'hex') IS DISTINCT FROM link->>'enrollmentDigest'
  OR (original.document-ARRAY['enrollmentId','validFrom','validUntil']) IS DISTINCT FROM
     ((source.document#-'{source,closedApproval}')-ARRAY['enrollmentId','validFrom','validUntil'])
  OR history.enrollment_digest<>original.document_digest OR history.enrollment_revision<>original.row_version
  OR history.intent ? 'approvalContinuation' OR history.intent ? 'closedApprovalSourceDigest'
  OR history.intent ? 'continuation' OR history.intent ? 'supersession'
  OR history.state NOT IN ('REVOKED','EXPIRED') OR history.state IS DISTINCT FROM closure->>'state'
  OR history.row_version::text IS DISTINCT FROM closure->>'revision' OR history.row_version<2
  OR date_trunc('milliseconds',history.updated_at) IS DISTINCT FROM (closure->>'closedAt')::timestamptz
  OR history.updated_at>source.valid_from OR history.updated_at<history.activated_at
  OR (history.state='EXPIRED' AND history.updated_at<history.valid_until)
  OR (history.state='REVOKED' AND history.updated_at>=history.valid_until)
  OR 'sha256:'||encode(history.intent_digest,'hex') IS DISTINCT FROM link#>>'{approval,intentDigest}'
  OR history.activation_operation_id::text IS DISTINCT FROM link#>>'{approval,activationOperationId}'
  OR 'sha256:'||encode(history.activation_evidence_digest,'hex') IS DISTINCT FROM link#>>'{approval,activationReceiptDigest}'
  OR NOT (closure->>'actorPrincipalId'=original.document#>>'{recoveryPrincipal,principalId}'
    OR closure->>'actorPrincipalId'=original.document#>>'{custodians,0,principalId}'
    OR closure->>'actorPrincipalId'=original.document#>>'{custodians,1,principalId}')
  OR (SELECT count(*) FROM control.outbox_event event WHERE event.participant_id=p_participant
    AND event.privacy_domain_id=source.privacy_domain_id AND event.aggregate_type='platform-recovery'
    AND event.aggregate_id=history.recovery_id AND event.event_type='openpc.identity.platform-recovery.closed.v1'
    AND event.event_id::text=closure->>'eventId'
    AND event.occurred_at=(closure->>'closedAt')::timestamptz
    AND 'sha256:'||encode(event.payload_digest,'hex')=closure->>'evidenceDigest'
    AND event.payload_digest=sha256(event.payload_cbor) AND octet_length(event.cose_sign1)>0)<>1
 THEN RETURN false; END IF;
 RETURN true;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR numeric_value_out_of_range
 OR invalid_datetime_format OR datetime_field_overflow THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_closed_approval_link_current(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_closed_approval_link_current(uuid,uuid,uuid)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;

/** Installation and fresh custody require an untouched original. The ordinary
 * receiving guard separately follows its sole child after a successful RESUME. */
export const platformRecoveryClosedApprovalSourceSql = `
CREATE OR REPLACE FUNCTION openpc.platform_recovery_closed_approval_source_current(p_participant uuid,p_enrollment uuid,p_receiving uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE source control.platform_recovery_enrollment; original control.mutation_candidate; witness jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO STRICT source FROM control.platform_recovery_enrollment e WHERE e.participant_id=p_participant
  AND e.privacy_domain_id=openpc.current_privacy_domain_id() AND e.enrollment_id=p_enrollment;
 witness:=source.document#>'{source,closedApproval,approval}';
 IF witness IS NULL OR openpc.platform_recovery_pending_approval_history_current(p_participant,p_enrollment,
   (witness->>'recoveryId')::uuid,(witness->>'candidateId')::uuid,(witness->>'approvalId')::uuid,p_receiving)
   IS DISTINCT FROM true THEN RETURN false; END IF;
 SELECT * INTO STRICT original FROM control.mutation_candidate m WHERE m.participant_id=p_participant
  AND m.privacy_domain_id=source.privacy_domain_id AND m.mutation_candidate_id::text=witness->>'candidateId';
 RETURN NOT EXISTS(SELECT 1 FROM control.mutation_candidate child WHERE child.predecessor_candidate_id=original.mutation_candidate_id)
  AND NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.participant_id=p_participant
    AND r.privacy_domain_id=source.privacy_domain_id AND r.replacement_id=original.resource_id)
  AND NOT EXISTS(SELECT 1 FROM control.idempotency_record effect WHERE effect.participant_id=p_participant
    AND effect.privacy_domain_id=source.privacy_domain_id AND effect.principal_id=original.maker_principal_id
    AND effect.catalog_operation_id=original.catalog_operation_id AND effect.action_intent_id=original.action_intent_id
    AND effect.idempotency_key=original.idempotency_key)
  AND NOT EXISTS(SELECT 1 FROM control.mutation_evidence effect WHERE effect.participant_id=p_participant
    AND effect.privacy_domain_id=source.privacy_domain_id AND effect.aggregate_type='platform-scope-replacement'
    AND effect.aggregate_id=original.resource_id)
  AND NOT EXISTS(SELECT 1 FROM control.outbox_event effect WHERE effect.participant_id=p_participant
    AND effect.privacy_domain_id=source.privacy_domain_id AND effect.aggregate_type='platform-scope-replacement'
    AND effect.aggregate_id=original.resource_id);
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR numeric_value_out_of_range
 THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_closed_approval_source_current(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_closed_approval_source_current(uuid,uuid,uuid)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;
