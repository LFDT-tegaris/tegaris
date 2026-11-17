/** Current relational source bindings for a restored original capsule. This function
 * only locks and validates sources; it cannot admit, sign, restore or ACK.
 * The native owner separately verifies canonical artifacts and CIGL under the
 * same transaction, including the owning feature admissions, before the
 * MAC-bound admission may consume this result. */
export const targetDispositionCurrentSourcesSql = `
CREATE OR REPLACE FUNCTION openpc.lock_runtime_target_current_sources(
 target uuid,expected_source jsonb,proof jsonb,operation text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE pid uuid; privacy uuid; original control.configuration_work;
 input control.runtime_configuration_input; binding jsonb; current_identity_expiry numeric;
 workload_principals uuid[]; workload_principal uuid; current_policy control.policy_generation;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR current_setting('transaction_isolation')<>'read committed' OR target IS NULL
  OR jsonb_typeof(expected_source) IS DISTINCT FROM 'object' OR jsonb_typeof(proof) IS DISTINCT FROM 'object'
  OR operation IS NULL OR operation NOT IN ('RESTORE','CONFIRM')
  OR proof->>'targetId' IS DISTINCT FROM target::text
  OR proof->>'sourceMode' IS NULL OR proof->>'sourceMode' NOT IN ('FACT_FREE','FACT_BOUND')
  OR coalesce(proof->>'capsuleValidUntilNs','') !~ '^[1-9][0-9]{0,19}$'
  OR (proof->>'capsuleValidUntilNs')::numeric>18446744073709551615
  OR (proof->>'capsuleValidUntilNs')::numeric<=extract(epoch from clock_timestamp())*1000000000
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-SOURCE-CONTEXT'; END IF;
 PERFORM openpc.check_runtime_target_fact_proof(proof);
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 -- All advisory fences are fail-fast before row locks. A held competing owner
 -- produces retryable contention, never an ordinary business failure or wait cycle.
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||pid::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||pid::text||':'||privacy::text||':'||target::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 -- The policy workload and the target transport are different identities.
 -- Revalidate the actual policy workload; the authenticated request still needs
 -- its own concrete credential/authority checks at the runtime decision owner.
 SELECT array_agg(DISTINCT c.principal_id ORDER BY c.principal_id) INTO workload_principals
  FROM control.credential c WHERE c.participant_id=pid AND c.kind='WORKLOAD_MTLS'
   AND c.audience=proof->>'workloadId' AND c.state='ACTIVE' AND c.credential_epoch>0
   AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp();
 IF coalesce(cardinality(workload_principals),0)<>1 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-WORKLOAD-AMBIGUOUS'; END IF;
 workload_principal:=workload_principals[1];
 PERFORM 1 FROM control.principal p WHERE p.participant_id=pid AND p.principal_id=workload_principal
  AND p.kind='WORKLOAD' AND p.state='ACTIVE' AND p.authority_epoch>0 FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'TARGET-DISPOSITION-WORKLOAD-WITHDRAWN'; END IF;
 PERFORM 1 FROM control.credential c WHERE c.participant_id=pid AND c.principal_id=workload_principal
  AND c.kind='WORKLOAD_MTLS' AND c.audience=proof->>'workloadId' AND c.state='ACTIVE'
  AND c.credential_epoch>0 AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
  AND c.certificate_der IS NOT NULL AND sha256(c.certificate_der)=c.secret_fingerprint
  ORDER BY c.credential_id FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'TARGET-DISPOSITION-WORKLOAD-CREDENTIAL'; END IF;
 SELECT * INTO STRICT original FROM control.configuration_work w
  WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
   AND w.configuration_work_id=(expected_source->>'original_work_id')::uuid
   AND w.operation_id::text=expected_source->>'original_operation_id'
   AND w.execution_attempt_id::text=expected_source->>'original_execution_attempt_id'
   AND w.runtime_target_id=target AND w.work_kind='RUNTIME_ACTIVATION'
   AND (w.state='COMPLETED' OR (operation='CONFIRM' AND w.state IN ('LEASED','RECONCILING')))
   AND w.execution_started_at IS NOT NULL
   AND w.runtime_configuration_generation_id::text=expected_source->>'runtime_configuration_generation_id'
   AND w.configuration_digest='sha256:'||(expected_source->>'configuration_digest')
   AND w.xds_version_digest='sha256:'||(expected_source->>'xds_version_digest')
   AND w.predecessor_digest IS NOT DISTINCT FROM 'sha256:'||(expected_source->>'predecessor_capsule_digest')
   AND w.policy_generation_digest='sha256:'||(proof->>'policyGenerationDigest') FOR SHARE NOWAIT;
 PERFORM 1 FROM control.runtime_activation_observation o
  WHERE o.participant_id=pid AND o.privacy_domain_id=privacy AND o.configuration_work_id=original.configuration_work_id
   AND o.operation_id=original.operation_id AND o.execution_attempt_id=original.execution_attempt_id
   AND o.runtime_target_id=target AND o.runtime_configuration_generation_id=original.runtime_configuration_generation_id
   AND o.generation_digest=original.generation_digest AND o.xds_version_digest=original.xds_version_digest
   AND (original.state<>'COMPLETED' OR o.activation_receipt_digest=original.result_receipt_digest)
   AND encode(sha256(decode(o.activation_receipt->>'activationReceiptCoseHex','hex')),'hex')=proof->>'originalReceiptDigest'
   AND o.capsule_digest='sha256:'||(expected_source->>'capsule_digest')
   AND o.capsule_digest='sha256:'||(proof->>'capsuleDigest');
 IF NOT FOUND THEN RAISE EXCEPTION 'TARGET-DISPOSITION-SOURCE-OBSERVATION'; END IF;
 SELECT * INTO STRICT input FROM control.runtime_configuration_input i
  WHERE i.participant_id=pid AND i.privacy_domain_id=privacy
   AND i.runtime_configuration_input_id=(expected_source->>'runtime_configuration_input_id')::uuid
   AND i.configuration_digest=decode(expected_source->>'configuration_digest','hex')
   AND i.module_installation_id::text=expected_source->>'module_installation_id'
   AND i.module_configuration_generation_id::text=expected_source->>'module_configuration_generation_id'
   AND i.selected FOR SHARE NOWAIT;
 -- Lock each mutable source before re-evaluating the shared canonical view.
 -- A source's signature/digest alone does not establish its current admission.
 FOR binding IN SELECT value FROM jsonb_array_elements(input.resource_bindings) ORDER BY value->>'kind',value->>'id' LOOP
  CASE binding->>'kind'
   WHEN 'ProviderProfile' THEN
    PERFORM 1 FROM control.provider_profile p WHERE p.participant_id=pid AND p.privacy_domain_id=privacy
     AND p.provider_profile_id=(binding->>'id')::uuid AND p.behavior_fingerprint=binding->>'digest'
     AND p.chain_id=binding->>'chainId' AND p.state<>'RETIRED' FOR SHARE NOWAIT;
   WHEN 'ClientIndexerProfile' THEN
    PERFORM 1 FROM control.indexer_profile p WHERE p.participant_id=pid AND p.privacy_domain_id=privacy
     AND p.indexer_profile_id=(binding->>'id')::uuid AND p.method_profile_digest=binding->>'digest'
     AND p.engine_version=binding->>'engineVersion' AND p.state<>'RETIRED' FOR SHARE NOWAIT;
   WHEN 'ProjectionPlan' THEN
    PERFORM 1 FROM control.projection_plan p WHERE p.participant_id=pid AND p.privacy_domain_id=privacy
     AND p.projection_plan_id=(binding->>'id')::uuid AND p.plan_digest=binding->>'digest'
     AND p.state<>'RETIRED' FOR SHARE NOWAIT;
   WHEN 'CiglSettings' THEN
    PERFORM 1 FROM control.cigl_settings p WHERE p.participant_id=pid AND p.privacy_domain_id=privacy
     AND p.cigl_settings_id=(binding->>'id')::uuid;
   ELSE RAISE EXCEPTION 'TARGET-DISPOSITION-SOURCE-KIND';
  END CASE;
  IF NOT FOUND THEN RAISE EXCEPTION 'TARGET-DISPOSITION-SOURCE-RESTRICTED'; END IF;
 END LOOP;
 PERFORM 1 FROM control.runtime_configuration_input_current_metadata i
  WHERE i.participant_id=pid AND i.privacy_domain_id=privacy
   AND i.runtime_configuration_input_id=input.runtime_configuration_input_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'TARGET-DISPOSITION-SOURCE-WITHDRAWN'; END IF;
 SELECT g.* INTO STRICT current_policy FROM control.policy_generation g JOIN control.policy_version v
  ON v.participant_id=g.participant_id AND v.privacy_domain_id=g.privacy_domain_id AND v.policy_version_id=g.policy_version_id
  JOIN control.policy_artifact a ON a.participant_id=g.participant_id AND a.privacy_domain_id=g.privacy_domain_id
   AND a.semantic_digest=v.semantic_digest AND a.payload_digest=g.artifact_digest
  WHERE g.participant_id=pid AND g.privacy_domain_id=privacy
   AND ((g.active AND g.state='ACTIVE') OR (operation='CONFIRM' AND EXISTS(
    SELECT 1 FROM control.policy_activation_occurrence_target ot
     JOIN control.policy_activation_occurrence oc ON oc.participant_id=ot.participant_id
      AND oc.privacy_domain_id=ot.privacy_domain_id AND oc.activation_occurrence_id=ot.activation_occurrence_id
     JOIN control.policy_activation a ON a.participant_id=oc.participant_id
      AND a.privacy_domain_id=oc.privacy_domain_id AND a.policy_activation_id=oc.activation_occurrence_id
    WHERE ot.participant_id=pid AND ot.privacy_domain_id=privacy AND ot.configuration_work_id=original.configuration_work_id
     AND ((ot.phase='FORWARD' AND oc.policy_generation_id=g.policy_generation_id AND g.state='PREPARED')
       OR (ot.phase='ROLLBACK' AND a.state='ACTIVE' AND a.prior_generation_digest=g.generation_digest AND g.state='RETIRED')))))
   AND g.generation_digest=decode(proof->>'policyGenerationDigest','hex') FOR SHARE OF g NOWAIT;
 SELECT s.expires_at_ns INTO STRICT current_identity_expiry FROM control.identity_runtime_snapshot_head h
  JOIN control.identity_runtime_snapshot s ON s.snapshot_id=h.snapshot_id AND s.participant_id=h.participant_id
   AND s.privacy_domain_id=h.privacy_domain_id AND s.target_runtime_id=h.target_runtime_id
  WHERE h.participant_id=pid AND h.privacy_domain_id=privacy AND h.target_runtime_id=target
   AND s.manifest_digest=decode(proof->>'identityManifestDigest','hex')
   AND s.expires_at_ns>extract(epoch from clock_timestamp())*1000000000 FOR SHARE OF h NOWAIT;
 -- The proof may shorten, never extend, the original Identity publication.
 IF (proof->>'capsuleValidUntilNs')::numeric>current_identity_expiry
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-IDENTITY-EXPIRY'; END IF;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'PC-DATA-6007';
END $$;
ALTER FUNCTION openpc.lock_runtime_target_current_sources(uuid,jsonb,jsonb,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.lock_runtime_target_current_sources(uuid,jsonb,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_runtime_target_current_sources(uuid,jsonb,jsonb,text) TO openpc_control_worker;
`;

/** Restoration remains a distinct, stricter operation gate. */
export const targetDispositionRestoreSourcesSql = `
CREATE OR REPLACE FUNCTION openpc.lock_runtime_target_restore_sources(
 target uuid,expected_source jsonb,proof jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
BEGIN
 PERFORM openpc.lock_runtime_target_current_sources(target,expected_source,proof,'RESTORE');
END $$;
ALTER FUNCTION openpc.lock_runtime_target_restore_sources(uuid,jsonb,jsonb) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.lock_runtime_target_restore_sources(uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_runtime_target_restore_sources(uuid,jsonb,jsonb) TO openpc_control_worker;
`;
