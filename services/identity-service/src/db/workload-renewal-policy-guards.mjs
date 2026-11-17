/** Governed revision/receipt/current-head coupling. No routine issuer, instance,
 * challenge, worker or certificate mutation is admitted by this owner. */
export const workloadRenewalPolicyGuardsSql = `
ALTER TABLE control.workload_renewal_policy ALTER CONSTRAINT wr_policy_governance_fk DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE control.workload_renewal_policy ALTER CONSTRAINT wr_policy_receipt_operation_fk DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE control.workload_renewal_policy FORCE ROW LEVEL SECURITY;
ALTER TABLE control.workload_renewal_policy_head FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.workload_renewal_policy,control.workload_renewal_policy_head FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.workload_renewal_policy,control.workload_renewal_policy_head TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT INSERT ON control.workload_renewal_policy,control.workload_renewal_policy_head TO openpc_control_runtime;
GRANT UPDATE(current_revision,state,row_version) ON control.workload_renewal_policy_head TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.workload_renewal_policy_projection(policy control.workload_renewal_policy)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',openpc.business_bytes((policy).digest),'1',openpc.business_uuid((policy).principal_id),
  '2',(policy).workload_id,'3',(policy).state,'4',openpc.business_uuid((policy).governance_operation_id),
  '5',openpc.business_bytes(sha256(convert_to(openpc.signing_canonical_json((policy).business_ancestors),'UTF8'))),
  '6',floor(extract(epoch from (policy).valid_from)*1000000)*1000,
  '7',floor(extract(epoch from (policy).valid_until)*1000000)*1000)
$$;

CREATE OR REPLACE FUNCTION openpc.check_workload_renewal_policy_ancestors(policy control.workload_renewal_policy,receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE snapshot jsonb:=convert_from(receipt.authority_snapshot,'UTF8')::jsonb; ancestor jsonb; bound jsonb;
 grant_row jsonb; path jsonb; expected jsonb; assignment control.assignment%ROWTYPE; delegation control.delegation%ROWTYPE;
 root uuid; prior_delegation uuid; principal_ids uuid[]; delegation_ids uuid[]; path_role_id uuid; i integer:=0; id uuid;
BEGIN
 IF jsonb_array_length(policy.business_ancestors)<>jsonb_array_length(snapshot->'authorities') THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-PARENTS'; END IF;
 FOR ancestor IN SELECT value FROM jsonb_array_elements(policy.business_ancestors) LOOP
  bound:=snapshot->'authorities'->i;i:=i+1;grant_row:=ancestor->'grant';path:=ancestor->'dependencies'->'path';
  IF ancestor IS DISTINCT FROM jsonb_build_object('grant',grant_row,'dependencies',ancestor->'dependencies')
   OR grant_row-'catalogOperationId' IS DISTINCT FROM bound-ARRAY['sessionId','sessionEpoch']
   OR (grant_row ? 'catalogOperationId' AND grant_row->>'catalogOperationId'<>receipt.catalog_operation_id)
   OR path IS DISTINCT FROM jsonb_build_object('delegationIds',path->'delegationIds','principalIds',path->'principalIds','roleId',path->'roleId')
  THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-PARENT-BINDING'; END IF;
  SELECT * INTO STRICT assignment FROM control.assignment a WHERE a.participant_id=policy.participant_id
   AND a.assignment_id=(grant_row->>'assignmentId')::uuid;
  root:=assignment.principal_id;principal_ids:=ARRAY[root];delegation_ids:=ARRAY[]::uuid[];prior_delegation:=NULL;
  IF jsonb_typeof(path->'delegationIds') IS DISTINCT FROM 'array' OR jsonb_array_length(path->'delegationIds')>32 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  FOR id IN SELECT value::uuid FROM jsonb_array_elements_text(path->'delegationIds') LOOP
   SELECT * INTO STRICT delegation FROM control.delegation d WHERE d.participant_id=policy.participant_id AND d.delegation_id=id;
   IF id=ANY(delegation_ids) OR delegation.grantor_principal_id<>root
    OR (prior_delegation IS NULL AND (delegation.parent_assignment_id IS DISTINCT FROM assignment.assignment_id OR delegation.parent_delegation_id IS NOT NULL))
    OR (prior_delegation IS NOT NULL AND delegation.parent_delegation_id IS DISTINCT FROM prior_delegation)
   THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-PARENT-PATH'; END IF;
   delegation_ids:=delegation_ids||id;root:=delegation.delegate_principal_id;principal_ids:=principal_ids||root;prior_delegation:=id;
  END LOOP;
  SELECT r.authority_role_id INTO path_role_id FROM control.authority_role r WHERE r.participant_id=policy.participant_id AND r.role_id=assignment.role_id;
  IF root IS DISTINCT FROM (grant_row->>'principalId')::uuid OR path IS DISTINCT FROM jsonb_build_object(
   'delegationIds',to_jsonb(delegation_ids),'principalIds',to_jsonb(principal_ids),'roleId',path_role_id) THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-PARENT-PATH'; END IF;
  SELECT jsonb_build_object('path',path,
   'principals',(SELECT jsonb_agg(jsonb_build_array(principal_id,authority_epoch::text) ORDER BY principal_id)
    FROM control.principal WHERE participant_id=policy.participant_id AND principal_id=ANY(principal_ids)),
   'privacy',(SELECT row_version::text FROM control.privacy_domain WHERE participant_id=policy.participant_id AND privacy_domain_id=(grant_row->>'privacyDomainId')::uuid),
   'role',(SELECT row_version::text FROM control.authority_role WHERE participant_id=policy.participant_id AND authority_role_id=path_role_id),
   'delegations',(SELECT jsonb_agg(jsonb_build_array(delegation_id,delegation_epoch::text,row_version::text) ORDER BY delegation_id)
    FROM control.delegation WHERE participant_id=policy.participant_id AND delegation_id=ANY(delegation_ids))) INTO expected;
  IF ancestor->'dependencies' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-PARENT-EPOCHS'; END IF;
 END LOOP;
END $$;

CREATE OR REPLACE FUNCTION openpc.assert_workload_renewal_policy_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE candidate control.mutation_candidate%ROWTYPE; policy control.workload_renewal_policy%ROWTYPE;
 prior control.workload_renewal_policy%ROWTYPE; projection jsonb; command text;
BEGIN
 IF receipt.aggregate_type<>'workload-renewal-policy' OR receipt.action_intent_id<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR receipt.catalog_operation_id NOT IN ('ID-OP-WORKLOAD-RENEWAL-POLICY-CREATE','ID-OP-WORKLOAD-RENEWAL-POLICY-REVISE',
   'ID-OP-WORKLOAD-RENEWAL-POLICY-SUSPEND','ID-OP-WORKLOAD-RENEWAL-POLICY-REVOKE') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 candidate:=openpc.check_governed_configuration_receipt(receipt);
 command:=replace(receipt.catalog_operation_id,'ID-OP-WORKLOAD-RENEWAL-POLICY-','');
 SELECT * INTO STRICT policy FROM control.workload_renewal_policy p WHERE p.participant_id=receipt.participant_id
  AND p.privacy_domain_id=receipt.privacy_domain_id AND p.policy_id=receipt.aggregate_id
  AND p.revision=receipt.after_revision AND p.governance_operation_id=receipt.operation_id;
 IF receipt.after_existence<>1 OR receipt.before_revision<>candidate.expected_revision
  OR receipt.after_revision<>candidate.expected_revision+1
  OR candidate.resource_type<>'participant' OR candidate.operation_class<>'UPDATE'
  OR candidate.candidate_document->>'expectedRevision' IS DISTINCT FROM candidate.expected_revision::text
  OR jsonb_typeof(candidate.candidate_document->'requestId') IS DISTINCT FROM 'string'
  OR coalesce(candidate.candidate_document->>'requestId','')!~'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR jsonb_typeof(candidate.candidate_document->'reason') IS DISTINCT FROM 'string'
  OR length(candidate.candidate_document->>'reason')<1
  OR length(candidate.candidate_document->>'reason')+(SELECT count(*) FROM regexp_split_to_table(candidate.candidate_document->>'reason','') scalar(character) WHERE ascii(character)>65535)>1024
  OR candidate.candidate_document->>'reason' IS DISTINCT FROM normalize(candidate.candidate_document->>'reason',NFC)
  OR NOT EXISTS(SELECT 1 FROM control.workload_renewal_policy_head h WHERE h.participant_id=policy.participant_id
   AND h.privacy_domain_id=policy.privacy_domain_id AND h.policy_id=policy.policy_id AND h.current_revision=policy.revision
   AND h.state=policy.state AND h.principal_id=policy.principal_id AND h.workload_id=policy.workload_id AND h.row_version=policy.revision)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-CURRENT-REVISION'; END IF;
 IF command IN ('CREATE','REVISE') THEN
  IF candidate.candidate_document IS DISTINCT FROM jsonb_build_object('requestId',candidate.candidate_document->'requestId',
   'expectedRevision',candidate.expected_revision::text,'definition',policy.definition,'reason',candidate.candidate_document->'reason')
   OR policy.state<>'ACTIVE' THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-DEFINITION'; END IF;
 ELSE
  IF candidate.candidate_document IS DISTINCT FROM jsonb_build_object('requestId',candidate.candidate_document->'requestId',
   'expectedRevision',candidate.expected_revision::text,'reason',candidate.candidate_document->'reason')
   OR policy.state<>(CASE command WHEN 'SUSPEND' THEN 'SUSPENDED' ELSE 'REVOKED' END)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-STOP'; END IF;
 END IF;
 IF command='CREATE' THEN
  IF receipt.before_existence<>0 OR receipt.before_revision<>0 OR policy.revision<>1 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  projection:='{}'::jsonb;
 ELSE
  SELECT * INTO STRICT prior FROM control.workload_renewal_policy p WHERE p.participant_id=policy.participant_id
   AND p.privacy_domain_id=policy.privacy_domain_id AND p.policy_id=policy.policy_id AND p.revision=candidate.expected_revision;
  IF receipt.before_existence<>1 OR prior.state='REVOKED'
   OR (prior.principal_id,prior.workload_id) IS DISTINCT FROM (policy.principal_id,policy.workload_id)
   OR (command='REVISE' AND prior.digest=policy.digest)
   OR (command IN ('SUSPEND','REVOKE') AND prior.definition IS DISTINCT FROM policy.definition)
   OR (command='SUSPEND' AND prior.state<>'ACTIVE') THEN RAISE EXCEPTION 'PC-DATA-6007-RENEWAL-TRANSITION'; END IF;
  projection:=openpc.workload_renewal_policy_projection(prior);
 END IF;
 IF openpc.business_cbor(receipt.before_state_preimage)->8 IS DISTINCT FROM projection
  OR openpc.business_cbor(receipt.after_state_preimage)->8 IS DISTINCT FROM openpc.workload_renewal_policy_projection(policy)
 THEN RAISE EXCEPTION 'DATA-6021-RENEWAL-TYPED-STATE'; END IF;
 PERFORM openpc.check_workload_renewal_policy_ancestors(policy,receipt);
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_workload_renewal_policy_insert()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE d jsonb:=NEW.definition; lifetime numeric; reserve numeric; overlap numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.governance_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR NEW.definition_canonical IS DISTINCT FROM convert_to(openpc.signing_canonical_json(d),'UTF8')
  OR (d-ARRAY['version','participantId','privacyDomainId','policyId','principalId','workloadId','issuerProfileDigest','providerQualificationDigest',
   'attestationProfileDigest','managedAttestorScopeDigest','maximumInstances','maximumEnrollmentsPerMinute','certificateLifetimeSeconds',
   'recoveryReserveSeconds','maximumOverlapSeconds','validFrom','validUntil'])<>'{}'::jsonb
  OR d->'version' IS DISTINCT FROM '1'::jsonb OR d->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR d->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text OR d->>'policyId' IS DISTINCT FROM NEW.policy_id::text
  OR d->>'principalId' IS DISTINCT FROM NEW.principal_id::text OR d->>'workloadId' IS DISTINCT FROM NEW.workload_id
  OR NEW.workload_id!~'^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR d->>'attestationProfileDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.attestation_profile_digest,'hex')
  OR d->>'issuerProfileDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.issuer_profile_digest,'hex')
  OR d->>'providerQualificationDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.provider_qualification_digest,'hex')
  OR coalesce(d->>'managedAttestorScopeDigest','')!~'^sha256:[0-9a-f]{64}$'
  OR coalesce(d->>'validFrom','')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$'
  OR coalesce(d->>'validUntil','')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$'
  OR (d->>'validFrom')::timestamptz IS DISTINCT FROM NEW.valid_from OR (d->>'validUntil')::timestamptz IS DISTINCT FROM NEW.valid_until
 THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-POLICY-OWNER'; END IF;
 IF jsonb_typeof(d->'maximumInstances') IS DISTINCT FROM 'number' OR coalesce(d->>'maximumInstances','')!~'^[1-9][0-9]{0,3}$'
  OR (d->>'maximumInstances')::numeric NOT BETWEEN 1 AND 1024
  OR jsonb_typeof(d->'maximumEnrollmentsPerMinute') IS DISTINCT FROM 'number' OR coalesce(d->>'maximumEnrollmentsPerMinute','')!~'^[1-9][0-9]{0,3}$'
  OR (d->>'maximumEnrollmentsPerMinute')::numeric NOT BETWEEN 1 AND 1024
  OR jsonb_typeof(d->'certificateLifetimeSeconds') IS DISTINCT FROM 'number' OR coalesce(d->>'certificateLifetimeSeconds','')!~'^[1-9][0-9]{0,4}$'
  OR jsonb_typeof(d->'recoveryReserveSeconds') IS DISTINCT FROM 'number' OR coalesce(d->>'recoveryReserveSeconds','')!~'^[1-9][0-9]{0,4}$'
  OR jsonb_typeof(d->'maximumOverlapSeconds') IS DISTINCT FROM 'number' OR coalesce(d->>'maximumOverlapSeconds','')!~'^[1-9][0-9]{0,2}$'
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 lifetime:=(d->>'certificateLifetimeSeconds')::numeric;reserve:=(d->>'recoveryReserveSeconds')::numeric;overlap:=(d->>'maximumOverlapSeconds')::numeric;
 IF lifetime NOT BETWEEN 1 AND 86400 OR reserve NOT BETWEEN 1 AND 86400 OR overlap NOT BETWEEN 1 AND 300
  OR NOT (overlap<reserve AND reserve<lifetime-least(lifetime/2,43200) AND lifetime-least(lifetime/2,43200)<lifetime)
  OR NOT EXISTS(SELECT 1 FROM control.principal p WHERE p.participant_id=NEW.participant_id AND p.principal_id=NEW.principal_id AND p.kind='WORKLOAD'
   AND (NEW.state<>'ACTIVE' OR (p.state='ACTIVE' AND NEW.valid_until>clock_timestamp()))
   AND EXISTS(SELECT 1 FROM control.credential c WHERE c.participant_id=p.participant_id AND c.principal_id=p.principal_id AND c.kind='WORKLOAD_MTLS' AND c.subject=NEW.workload_id))
 THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-POLICY-BOUNDS'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS wr_policy_insert_owner ON control.workload_renewal_policy;
CREATE TRIGGER wr_policy_insert_owner BEFORE INSERT ON control.workload_renewal_policy FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_renewal_policy_insert();

CREATE OR REPLACE FUNCTION openpc.guard_workload_renewal_policy_head()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6007-RENEWAL-HISTORY'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.current_revision<>1 OR NEW.row_version<>1 OR NEW.state<>'ACTIVE' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSE
  IF (NEW.participant_id,NEW.privacy_domain_id,NEW.policy_id,NEW.principal_id,NEW.workload_id) IS DISTINCT FROM
   (OLD.participant_id,OLD.privacy_domain_id,OLD.policy_id,OLD.principal_id,OLD.workload_id)
   OR NEW.current_revision<>OLD.current_revision+1 OR NEW.row_version<>OLD.row_version+1 OR OLD.state='REVOKED'
  THEN RAISE EXCEPTION 'PC-DATA-6007-RENEWAL-CURRENT-CAS'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.workload_renewal_policy p WHERE p.participant_id=NEW.participant_id
  AND p.privacy_domain_id=NEW.privacy_domain_id AND p.policy_id=NEW.policy_id AND p.revision=NEW.current_revision
  AND p.state=NEW.state AND p.principal_id=NEW.principal_id AND p.workload_id=NEW.workload_id
  AND p.governance_operation_id=current_setting('openpc.operation_id')::uuid)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-CURRENT-OWNER'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS wr_policy_head_owner ON control.workload_renewal_policy_head;
CREATE TRIGGER wr_policy_head_owner BEFORE INSERT OR UPDATE OR DELETE ON control.workload_renewal_policy_head
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_renewal_policy_head();

CREATE OR REPLACE FUNCTION openpc.require_workload_renewal_policy_receipt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.audit_occurrence%ROWTYPE;
BEGIN
 SELECT * INTO STRICT receipt FROM control.audit_occurrence r WHERE r.participant_id=NEW.participant_id
  AND r.privacy_domain_id=NEW.privacy_domain_id AND r.aggregate_type='workload-renewal-policy'
  AND r.aggregate_id=NEW.policy_id AND r.after_revision=NEW.revision AND r.operation_id=NEW.governance_operation_id;
 PERFORM openpc.assert_workload_renewal_policy_receipt(receipt);
 IF NOT EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=receipt.participant_id
  AND e.privacy_domain_id=receipt.privacy_domain_id AND e.receipt_id=receipt.receipt_id AND e.aggregate_id=receipt.aggregate_id
  AND e.aggregate_type=receipt.aggregate_type AND e.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1'
  AND e.event_type='io.openpc.control.command.committed.v1' AND e.proof_kind='BUSINESS_RECEIPT_REFERENCE'
  AND e.payload_digest=sha256(e.payload_cbor)) THEN RAISE EXCEPTION 'PC-AUTH-0005-RENEWAL-OUTBOX'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS wr_policy_receipt_required ON control.workload_renewal_policy;
CREATE CONSTRAINT TRIGGER wr_policy_receipt_required AFTER INSERT ON control.workload_renewal_policy
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_workload_renewal_policy_receipt();
REVOKE ALL ON FUNCTION openpc.workload_renewal_policy_projection(control.workload_renewal_policy),
 openpc.check_workload_renewal_policy_ancestors(control.workload_renewal_policy,control.audit_occurrence),
 openpc.assert_workload_renewal_policy_receipt(control.audit_occurrence) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.workload_renewal_policy_projection(control.workload_renewal_policy),
 openpc.check_workload_renewal_policy_ancestors(control.workload_renewal_policy,control.audit_occurrence),
 openpc.assert_workload_renewal_policy_receipt(control.audit_occurrence) TO openpc_control_runtime;
`;
