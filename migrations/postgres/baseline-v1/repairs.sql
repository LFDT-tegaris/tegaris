ALTER TABLE control."workload_signing_handover_generation" DROP CONSTRAINT "workload_handover_generation_size_ck";
ALTER TABLE control."workload_signing_handover_generation" ADD CONSTRAINT "workload_handover_generation_size_ck" CHECK (octet_length("control"."workload_signing_handover_generation"."request_canonical") between 1 and 8192 and octet_length("control"."workload_signing_handover_generation"."document_canonical") between 1 and 1048576 and octet_length("control"."workload_signing_handover_generation"."authority_snapshot") between 1 and 65536);
ALTER TABLE control."workload_signing_handover_observation" DROP CONSTRAINT "workload_handover_observation_size_ck";
ALTER TABLE control."workload_signing_handover_observation" ADD CONSTRAINT "workload_handover_observation_size_ck" CHECK (octet_length("control"."workload_signing_handover_observation"."result_canonical") between 1 and 262144 and octet_length("control"."workload_signing_handover_observation"."entry_canonical") between 1 and 8192);
ALTER TABLE control."workload_signing_handover" DROP CONSTRAINT "workload_signing_handover_sizes_ck";
ALTER TABLE control."workload_signing_handover" ADD CONSTRAINT "workload_signing_handover_sizes_ck" CHECK (octet_length("control"."workload_signing_handover"."request_canonical") between 1 and 262144 and octet_length("control"."workload_signing_handover"."source_canonical") between 1 and 8388608 and octet_length("control"."workload_signing_handover"."authority_snapshot") between 1 and 65536);
ALTER TABLE control."workload_signing_handover_attempt" DROP CONSTRAINT "workload_handover_attempt_size_ck";
ALTER TABLE control."workload_signing_handover_attempt" ADD CONSTRAINT "workload_handover_attempt_size_ck" CHECK (octet_length("control"."workload_signing_handover_attempt"."binding_canonical") between 1 and 16384 and octet_length("control"."workload_signing_handover_attempt"."attempt_canonical") between 1 and 16384 and octet_length("control"."workload_signing_handover_attempt"."authority_snapshot") between 1 and 65536);
ALTER TABLE control."workload_renewal_signing_grant" DROP CONSTRAINT "wr_signing_grant_security_ck";
ALTER TABLE control."workload_renewal_signing_grant" ADD CONSTRAINT "wr_signing_grant_security_ck" CHECK ("control"."workload_renewal_signing_grant"."family_security_epoch" between 0 and 18446744073709551615
    and "control"."workload_renewal_signing_grant"."participant_security_invalidation_epoch" between 0 and 18446744073709551615
    and "control"."workload_renewal_signing_grant"."key_security_generation" between 1 and 18446744073709551615
    and octet_length("control"."workload_renewal_signing_grant"."provider_qualification_digest")=32);
ALTER TABLE control."workload_renewal_policy" DROP CONSTRAINT "wr_policy_bounds_ck";
ALTER TABLE control."workload_renewal_policy" ADD CONSTRAINT "wr_policy_bounds_ck" CHECK ("control"."workload_renewal_policy"."revision" between 1 and 18446744073709551615 and "control"."workload_renewal_policy"."valid_until">"control"."workload_renewal_policy"."valid_from" and "control"."workload_renewal_policy"."state" in ('ACTIVE','SUSPENDED','REVOKED') and jsonb_typeof("control"."workload_renewal_policy"."business_ancestors")='array' and jsonb_array_length("control"."workload_renewal_policy"."business_ancestors") between 1 and 64);
ALTER TABLE control."workload_renewal_policy" DROP CONSTRAINT "wr_policy_definition_ck";
ALTER TABLE control."workload_renewal_policy" ADD CONSTRAINT "wr_policy_definition_ck" CHECK (octet_length("control"."workload_renewal_policy"."definition_canonical") between 1 and 65536 and "control"."workload_renewal_policy"."digest"=sha256("control"."workload_renewal_policy"."definition_canonical") and jsonb_typeof("control"."workload_renewal_policy"."definition")='object');
ALTER TABLE control."workload_renewal_policy_head" DROP CONSTRAINT "wr_policy_head_bounds_ck";
ALTER TABLE control."workload_renewal_policy_head" ADD CONSTRAINT "wr_policy_head_bounds_ck" CHECK ("control"."workload_renewal_policy_head"."current_revision" between 1 and 18446744073709551615 and "control"."workload_renewal_policy_head"."row_version" between 1 and 18446744073709551615 and "control"."workload_renewal_policy_head"."state" in ('ACTIVE','SUSPENDED','REVOKED'));
ALTER TABLE control."workload_credential_family" DROP CONSTRAINT "wr_family_bounds_ck";
ALTER TABLE control."workload_credential_family" ADD CONSTRAINT "wr_family_bounds_ck" CHECK ("control"."workload_credential_family"."generation" between 1 and 18446744073709551615 and "control"."workload_credential_family"."instance_generation" between 1 and 18446744073709551615 and "control"."workload_credential_family"."security_epoch" between 0 and 18446744073709551615 and "control"."workload_credential_family"."row_version" between 1 and 18446744073709551615 and octet_length("control"."workload_credential_family"."current_fingerprint")=32 and "control"."workload_credential_family"."state" in ('ACTIVE','REVOKED','TERMINATED'));
ALTER TABLE control."workload_renewal_attempt" DROP CONSTRAINT "wr_attempt_bounds_ck";
ALTER TABLE control."workload_renewal_attempt" ADD CONSTRAINT "wr_attempt_bounds_ck" CHECK ("control"."workload_renewal_attempt"."lease_fence" between 1 and 18446744073709551615 and "control"."workload_renewal_attempt"."provider_timeout_ms" between 1 and 60000 and length("control"."workload_renewal_attempt"."worker_id") between 1 and 160 and "control"."workload_renewal_attempt"."lease_expires_at">"control"."workload_renewal_attempt"."claimed_at");
ALTER TABLE control."workload_renewal_intent" DROP CONSTRAINT "wr_intent_attestation_ck";
ALTER TABLE control."workload_renewal_intent" ADD CONSTRAINT "wr_intent_attestation_ck" CHECK (octet_length("control"."workload_renewal_intent"."attestation_evidence") between 1 and 65536 and "control"."workload_renewal_intent"."renewal_deadline">"control"."workload_renewal_intent"."created_at");
ALTER TABLE control."root_expiry_recovery_scope" DROP CONSTRAINT "root_expiry_scope_bytes_ck";
ALTER TABLE control."root_expiry_recovery_scope" ADD CONSTRAINT "root_expiry_scope_bytes_ck" CHECK (octet_length("control"."root_expiry_recovery_scope"."scope_cbor") between 1 and 60000 and octet_length("control"."root_expiry_recovery_scope"."admission_preimage") between 1 and 65536 and octet_length("control"."root_expiry_recovery_scope"."admission_digest")=32 and "control"."root_expiry_recovery_scope"."admission_digest"=sha256("control"."root_expiry_recovery_scope"."admission_preimage") and octet_length("control"."root_expiry_recovery_scope"."enrollment_digest")=32 and octet_length("control"."root_expiry_recovery_scope"."intent_digest")=32 and octet_length("control"."root_expiry_recovery_scope"."predecessor_digest")=32);
ALTER TABLE control."root_expiry_recovery_scope" DROP CONSTRAINT "root_expiry_scope_epoch_ck";
ALTER TABLE control."root_expiry_recovery_scope" ADD CONSTRAINT "root_expiry_scope_epoch_ck" CHECK ("control"."root_expiry_recovery_scope"."platform_authority_epoch" between 2 and 18446744073709551615 and "control"."root_expiry_recovery_scope"."predecessor_epoch"="control"."root_expiry_recovery_scope"."platform_authority_epoch"-1);
ALTER TABLE control."platform_envelope_scope_successor" DROP CONSTRAINT "platform_scope_successor_bytes_ck";
ALTER TABLE control."platform_envelope_scope_successor" ADD CONSTRAINT "platform_scope_successor_bytes_ck" CHECK (octet_length("control"."platform_envelope_scope_successor"."scope_cbor") between 1 and 60000
    and octet_length("control"."platform_envelope_scope_successor"."admission_preimage") between 1 and 65536
    and octet_length("control"."platform_envelope_scope_successor"."admission_digest")=32 and "control"."platform_envelope_scope_successor"."admission_digest"=sha256("control"."platform_envelope_scope_successor"."admission_preimage")
    and octet_length("control"."platform_envelope_scope_successor"."predecessor_digest")=32);
ALTER TABLE control."platform_envelope_scope_successor" DROP CONSTRAINT "platform_scope_successor_epoch_ck";
ALTER TABLE control."platform_envelope_scope_successor" ADD CONSTRAINT "platform_scope_successor_epoch_ck" CHECK ("control"."platform_envelope_scope_successor"."platform_authority_epoch" between 2 and 18446744073709551615
    and "control"."platform_envelope_scope_successor"."predecessor_epoch"="control"."platform_envelope_scope_successor"."platform_authority_epoch"-1);
ALTER TABLE control."platform_scope_replacement" DROP CONSTRAINT "platform_scope_replacement_epoch_ck";
ALTER TABLE control."platform_scope_replacement" ADD CONSTRAINT "platform_scope_replacement_epoch_ck" CHECK ("control"."platform_scope_replacement"."predecessor_epoch" between 1 and 18446744073709551614
    and "control"."platform_scope_replacement"."expected_root_revision" between 1 and 18446744073709551615);
ALTER TABLE control."identity_envelope_proposal" DROP CONSTRAINT "identity_envelope_proposal_bytes_ck";
ALTER TABLE control."identity_envelope_proposal" ADD CONSTRAINT "identity_envelope_proposal_bytes_ck" CHECK (octet_length("control"."identity_envelope_proposal"."proposal_cbor") between 1 and 65536 and octet_length("control"."identity_envelope_proposal"."proposal_digest")=32 and "control"."identity_envelope_proposal"."proposal_digest"=sha256("control"."identity_envelope_proposal"."proposal_cbor"));
ALTER TABLE control."platform_envelope_scope" DROP CONSTRAINT "platform_envelope_scope_bytes_ck";
ALTER TABLE control."platform_envelope_scope" ADD CONSTRAINT "platform_envelope_scope_bytes_ck" CHECK (octet_length("control"."platform_envelope_scope"."scope_cbor") between 1 and 60000 and octet_length("control"."platform_envelope_scope"."admission_preimage") between 1 and 65536
    and octet_length("control"."platform_envelope_scope"."admission_digest")=32 and "control"."platform_envelope_scope"."admission_digest"=sha256("control"."platform_envelope_scope"."admission_preimage"));
ALTER TABLE control."idempotency_record" DROP CONSTRAINT "idempotency_catalog_operation_ck";
ALTER TABLE control."idempotency_record" ADD CONSTRAINT "idempotency_catalog_operation_ck" CHECK ("control"."idempotency_record"."catalog_operation_id" = 'LEGACY' or "control"."idempotency_record"."catalog_operation_id" ~ '^(ID|CFG)-OP-[A-Z0-9-]+$' or "control"."idempotency_record"."catalog_operation_id" in ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE') or "control"."idempotency_record"."catalog_operation_id" = 'POL-OP-ACTIVATE' or "control"."idempotency_record"."catalog_operation_id" in ('OPS-OP-ADVANCE-SIGNING-KEY-ROTATION','OPS-OP-RECOVER-SIGNING-KEY-ROTATION'));
ALTER TABLE control."mutation_evidence" DROP CONSTRAINT "mutation_evidence_catalog_operation_ck";
ALTER TABLE control."mutation_evidence" ADD CONSTRAINT "mutation_evidence_catalog_operation_ck" CHECK ("control"."mutation_evidence"."catalog_operation_id" = 'LEGACY' or "control"."mutation_evidence"."catalog_operation_id" ~ '^(ID|CFG)-OP-[A-Z0-9-]+$' or "control"."mutation_evidence"."catalog_operation_id" in ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE') or "control"."mutation_evidence"."catalog_operation_id" = 'POL-OP-ACTIVATE' or "control"."mutation_evidence"."catalog_operation_id" in ('OPS-OP-ADVANCE-SIGNING-KEY-ROTATION','OPS-OP-RECOVER-SIGNING-KEY-ROTATION'));
ALTER TABLE control."installed_secret_recipient" DROP CONSTRAINT "installed_secret_recipient_bounds_ck";
ALTER TABLE control."installed_secret_recipient" ADD CONSTRAINT "installed_secret_recipient_bounds_ck" CHECK ("control"."installed_secret_recipient"."generation" between 1 and 18446744073709551615 and "control"."installed_secret_recipient"."workload_credential_epoch" between 0 and 18446744073709551615 and length("control"."installed_secret_recipient"."admission_reference") between 1 and 256);
ALTER TABLE control."platform_context" DROP CONSTRAINT "platform_context_epoch_ck";
ALTER TABLE control."platform_context" ADD CONSTRAINT "platform_context_epoch_ck" CHECK ("control"."platform_context"."authority_epoch" between 0 and 18446744073709551615 and "control"."platform_context"."row_version" between 1 and 18446744073709551615);
ALTER TABLE control."participant_bootstrap_custody" DROP CONSTRAINT "bootstrap_ttl_ck";
ALTER TABLE control."participant_bootstrap_custody" ADD CONSTRAINT "bootstrap_ttl_ck" CHECK ("control"."participant_bootstrap_custody"."first_admin_invite_ttl_ms" between 900000 and 604800000 and "control"."participant_bootstrap_custody"."expires_at">"control"."participant_bootstrap_custody"."created_at" and "control"."participant_bootstrap_custody"."expires_at"<="control"."participant_bootstrap_custody"."created_at"+interval '7 days');
ALTER TABLE control."authority_role" DROP CONSTRAINT "authority_role_origin_ck";
ALTER TABLE control."authority_role" ADD CONSTRAINT "authority_role_origin_ck" CHECK ("control"."authority_role"."origin" in ('GOVERNED','MIGRATED_ASSIGNMENT','BOOTSTRAP'));
ALTER TABLE control."authority_role" DROP CONSTRAINT "authority_role_state_ck";
ALTER TABLE control."authority_role" ADD CONSTRAINT "authority_role_state_ck" CHECK ("control"."authority_role"."state" in ('ACTIVE','ARCHIVED'));
ALTER TABLE control."identity_runtime_snapshot" DROP CONSTRAINT "identity_runtime_snapshot_count_ck";
ALTER TABLE control."identity_runtime_snapshot" ADD CONSTRAINT "identity_runtime_snapshot_count_ck" CHECK ("control"."identity_runtime_snapshot"."actor_count" between 1 and 8192 and "control"."identity_runtime_snapshot"."shard_count" between 1 and 256);
ALTER TABLE control."business_signing_selection" DROP CONSTRAINT "business_signing_selection_version_ck";
ALTER TABLE control."business_signing_selection" ADD CONSTRAINT "business_signing_selection_version_ck" CHECK ("control"."business_signing_selection"."row_version" between 1 and 18446744073709551615 and "control"."business_signing_selection"."fence_generation" between 1 and 18446744073709551615 and "control"."business_signing_selection"."admission_version" between 1 and 18446744073709551615);
ALTER TABLE control."receipt_signing_attempt" DROP CONSTRAINT "receipt_attempt_payload_ck";
ALTER TABLE control."receipt_signing_attempt" ADD CONSTRAINT "receipt_attempt_payload_ck" CHECK (octet_length("control"."receipt_signing_attempt"."payload_cbor") between 1 and 65536 and octet_length("control"."receipt_signing_attempt"."payload_digest")=32 and "control"."receipt_signing_attempt"."payload_digest"=sha256("control"."receipt_signing_attempt"."payload_cbor"));
ALTER TABLE control."signing_continuation" DROP CONSTRAINT "signing_continuation_digest_ck";
ALTER TABLE control."signing_continuation" ADD CONSTRAINT "signing_continuation_digest_ck" CHECK (octet_length("control"."signing_continuation"."context_preimage") between 2 and 16384 and octet_length("control"."signing_continuation"."context_digest")=32
  and "control"."signing_continuation"."context_digest"=sha256("control"."signing_continuation"."context_preimage") and octet_length("control"."signing_continuation"."assertion_digest")=32 and octet_length("control"."signing_continuation"."issuer_key_digest")=32);
ALTER TABLE control."signing_rotation_attestation" DROP CONSTRAINT "signing_attestation_payload_ck";
ALTER TABLE control."signing_rotation_attestation" ADD CONSTRAINT "signing_attestation_payload_ck" CHECK (octet_length("control"."signing_rotation_attestation"."receipt_cbor") between 1 and 65536 and octet_length("control"."signing_rotation_attestation"."authority_snapshot") between 2 and 65536 and octet_length("control"."signing_rotation_attestation"."signer_trust_digest")=32);
ALTER TABLE control."signing_rotation_command" DROP CONSTRAINT "signing_command_authorization_ck";
ALTER TABLE control."signing_rotation_command" ADD CONSTRAINT "signing_command_authorization_ck" CHECK (octet_length("control"."signing_rotation_command"."authorization_snapshot") between 2 and 65536 and "control"."signing_rotation_command"."authorization_snapshot_digest"=sha256("control"."signing_rotation_command"."authorization_snapshot") and octet_length("control"."signing_rotation_command"."authorization_snapshot_digest")=32);
ALTER TABLE control."signing_rotation_history" DROP CONSTRAINT "signing_history_digest_ck";
ALTER TABLE control."signing_rotation_history" ADD CONSTRAINT "signing_history_digest_ck" CHECK (octet_length("control"."signing_rotation_history"."history_preimage") between 2 and 262144 and "control"."signing_rotation_history"."history_digest"=sha256("control"."signing_rotation_history"."history_preimage") and octet_length("control"."signing_rotation_history"."history_digest")=32);
ALTER TABLE control."signing_rotation_observation" DROP CONSTRAINT "signing_observation_digest_ck";
ALTER TABLE control."signing_rotation_observation" ADD CONSTRAINT "signing_observation_digest_ck" CHECK (octet_length("control"."signing_rotation_observation"."observation_preimage") between 2 and 4096 and "control"."signing_rotation_observation"."observation_digest"=sha256("control"."signing_rotation_observation"."observation_preimage") and octet_length("control"."signing_rotation_observation"."observation_digest")=32);
ALTER TABLE control."signing_rotation_operation_evidence" DROP CONSTRAINT "signing_operation_evidence_digest_ck";
ALTER TABLE control."signing_rotation_operation_evidence" ADD CONSTRAINT "signing_operation_evidence_digest_ck" CHECK (octet_length("control"."signing_rotation_operation_evidence"."preimage") between 2 and 262144 and "control"."signing_rotation_operation_evidence"."digest"=sha256("control"."signing_rotation_operation_evidence"."preimage") and octet_length("control"."signing_rotation_operation_evidence"."digest")=32 and "control"."signing_rotation_operation_evidence"."recorded_at_ns">0);
ALTER TABLE control."audit_occurrence" DROP CONSTRAINT "audit_occurrence_digests_ck";
ALTER TABLE control."audit_occurrence" ADD CONSTRAINT "audit_occurrence_digests_ck" CHECK (octet_length("control"."audit_occurrence"."receipt_cbor") between 1 and 65536 and octet_length("control"."audit_occurrence"."cose_sign1") between 1 and 66560 and "control"."audit_occurrence"."receipt_digest"=sha256("control"."audit_occurrence"."receipt_cbor") and "control"."audit_occurrence"."before_state_digest"=sha256("control"."audit_occurrence"."before_state_preimage") and "control"."audit_occurrence"."after_state_digest"=sha256("control"."audit_occurrence"."after_state_preimage") and "control"."audit_occurrence"."pre_commit_authority_digest"=sha256("control"."audit_occurrence"."authority_snapshot"));
ALTER TABLE control."audit_occurrence" DROP CONSTRAINT "audit_occurrence_time_ck";
ALTER TABLE control."audit_occurrence" ADD CONSTRAINT "audit_occurrence_time_ck" CHECK ("control"."audit_occurrence"."recorded_at_ns" between 0 and 18446744073709551615 and mod("control"."audit_occurrence"."recorded_at_ns",1000)=0);
ALTER TABLE control."business_signing_key" DROP CONSTRAINT "business_signing_key_epoch_ck";
ALTER TABLE control."business_signing_key" ADD CONSTRAINT "business_signing_key_epoch_ck" CHECK ("control"."business_signing_key"."key_epoch" between 1 and 18446744073709551615 and "control"."business_signing_key"."workload_credential_epoch" between 0 and 18446744073709551615);
ALTER TABLE control."business_signing_key" DROP CONSTRAINT "business_signing_key_trust_ck";
ALTER TABLE control."business_signing_key" ADD CONSTRAINT "business_signing_key_trust_ck" CHECK (octet_length("control"."business_signing_key"."trust_preimage") between 1 and 65536 and octet_length("control"."business_signing_key"."trust_digest")=32 and "control"."business_signing_key"."trust_digest"=sha256("control"."business_signing_key"."trust_preimage"));
ALTER TABLE control."business_signing_key_state" DROP CONSTRAINT "business_signing_state_change_ck";
ALTER TABLE control."business_signing_key_state" ADD CONSTRAINT "business_signing_state_change_ck" CHECK ("control"."business_signing_key_state"."changed_at_ns" between 0 and 18446744073709551615 and mod("control"."business_signing_key_state"."changed_at_ns",1000)=0 and length("control"."business_signing_key_state"."change_reference") between 1 and 256 and octet_length("control"."business_signing_key_state"."change_digest")=32);
ALTER TABLE control."business_signing_selection" DROP CONSTRAINT "business_signing_selection_change_ck";
ALTER TABLE control."business_signing_selection" ADD CONSTRAINT "business_signing_selection_change_ck" CHECK ("control"."business_signing_selection"."changed_at_ns" between 0 and 18446744073709551615 and mod("control"."business_signing_selection"."changed_at_ns",1000)=0 and length("control"."business_signing_selection"."change_reference") between 1 and 256 and octet_length("control"."business_signing_selection"."change_digest")=32);
ALTER TABLE control."evidence_record" DROP CONSTRAINT "evidence_record_time_ck";
ALTER TABLE control."evidence_record" ADD CONSTRAINT "evidence_record_time_ck" CHECK ("control"."evidence_record"."recorded_at_ns" between 0 and 18446744073709551615 and mod("control"."evidence_record"."recorded_at_ns",1000)=0);
ALTER TABLE control."action_intent" DROP CONSTRAINT "action_intent_operation_ck";
ALTER TABLE control."action_intent" ADD CONSTRAINT "action_intent_operation_ck" CHECK ("control"."action_intent"."operation_class" in ('READ','CREATE','UPDATE','DELETE','APPROVE','ACTIVATE','ROLLBACK','EXPORT','RECOVER','UNINSTALL'));
ALTER TABLE control."action_intent" DROP CONSTRAINT "action_intent_risk_ck";
ALTER TABLE control."action_intent" ADD CONSTRAINT "action_intent_risk_ck" CHECK ("control"."action_intent"."risk_class" in ('LOW','STANDARD','HIGH','BREAK_GLASS'));
ALTER TABLE control."runtime_target_profile_binding" DROP CONSTRAINT "runtime_profile_name_ck";
ALTER TABLE control."runtime_target_profile_binding" ADD CONSTRAINT "runtime_profile_name_ck" CHECK (length("control"."runtime_target_profile_binding"."target_profile_id") between 1 and 128 and "control"."runtime_target_profile_binding"."target_profile_id" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$');
ALTER TABLE control."runtime_artifact_source_denial" DROP CONSTRAINT "runtime_artifact_source_denial_wire_ck";
ALTER TABLE control."runtime_artifact_source_denial" ADD CONSTRAINT "runtime_artifact_source_denial_wire_ck" CHECK ("control"."runtime_artifact_source_denial"."sequence" between 1 and 4096 and octet_length("control"."runtime_artifact_source_denial"."signed_denial") between 1 and 8192 and "control"."runtime_artifact_source_denial"."denial_digest"=sha256("control"."runtime_artifact_source_denial"."signed_denial") and octet_length("control"."runtime_artifact_source_denial"."verification_nonce")=32 and octet_length("control"."runtime_artifact_source_denial"."verification_mac")=32 and (("control"."runtime_artifact_source_denial"."sequence"=1 and "control"."runtime_artifact_source_denial"."previous_denial_digest" is null) or ("control"."runtime_artifact_source_denial"."sequence">1 and octet_length("control"."runtime_artifact_source_denial"."previous_denial_digest")=32)));
ALTER TABLE control."qualification_deployment_attempt" DROP CONSTRAINT "qualification_deployment_attempt_bytes_ck";
ALTER TABLE control."qualification_deployment_attempt" ADD CONSTRAINT "qualification_deployment_attempt_bytes_ck" CHECK (octet_length("control"."qualification_deployment_attempt"."request_bytes") between 1 and 524288 and "control"."qualification_deployment_attempt"."request_digest"='sha256:'||encode(sha256("control"."qualification_deployment_attempt"."request_bytes"),'hex'));
ALTER TABLE control."qualification_deployment_installation" DROP CONSTRAINT "qualification_deployment_installation_bytes_ck";
ALTER TABLE control."qualification_deployment_installation" ADD CONSTRAINT "qualification_deployment_installation_bytes_ck" CHECK (octet_length("control"."qualification_deployment_installation"."pins_bytes") between 1 and 65536 and "control"."qualification_deployment_installation"."pins_digest"='sha256:'||encode(sha256("control"."qualification_deployment_installation"."pins_bytes"),'hex'));
ALTER TABLE control."qualification_deployment_observation" DROP CONSTRAINT "qualification_deployment_observation_bytes_ck";
ALTER TABLE control."qualification_deployment_observation" ADD CONSTRAINT "qualification_deployment_observation_bytes_ck" CHECK (octet_length("control"."qualification_deployment_observation"."observation_bytes") between 1 and 524288 and "control"."qualification_deployment_observation"."observation_digest"='sha256:'||encode(sha256("control"."qualification_deployment_observation"."observation_bytes"),'hex'));
ALTER TABLE control."notification_async_work_transition" DROP CONSTRAINT "notification_async_transition_bytes_ck";
ALTER TABLE control."notification_async_work_transition" ADD CONSTRAINT "notification_async_transition_bytes_ck" CHECK (octet_length("control"."notification_async_work_transition"."transition_bytes") between 1 and 1048576 and "control"."notification_async_work_transition"."transition_digest"='sha256:'||encode(sha256("control"."notification_async_work_transition"."transition_bytes"),'hex') and "control"."notification_async_work_transition"."recorded_at_ms" between 0 and 9007199254740991);
ALTER TABLE control."qualification_key_attempt" DROP CONSTRAINT "qualification_key_attempt_bytes_ck";
ALTER TABLE control."qualification_key_attempt" ADD CONSTRAINT "qualification_key_attempt_bytes_ck" CHECK (octet_length("control"."qualification_key_attempt"."request_bytes") between 1 and 131072 and "control"."qualification_key_attempt"."request_digest"='sha256:'||encode(sha256(convert_to('pc.qualification-key-observation-request.v1','UTF8')||decode('00','hex')||"control"."qualification_key_attempt"."request_bytes"),'hex'));
ALTER TABLE control."qualification_key_installation" DROP CONSTRAINT "qualification_key_installation_bytes_ck";
ALTER TABLE control."qualification_key_installation" ADD CONSTRAINT "qualification_key_installation_bytes_ck" CHECK (octet_length("control"."qualification_key_installation"."pins_bytes") between 1 and 131072 and "control"."qualification_key_installation"."pins_digest"='sha256:'||encode(sha256("control"."qualification_key_installation"."pins_bytes"),'hex'));
ALTER TABLE control."qualification_key_observation" DROP CONSTRAINT "qualification_key_observation_bytes_ck";
ALTER TABLE control."qualification_key_observation" ADD CONSTRAINT "qualification_key_observation_bytes_ck" CHECK (octet_length("control"."qualification_key_observation"."observation_bytes") between 1 and 131072 and "control"."qualification_key_observation"."observation_digest"='sha256:'||encode(sha256("control"."qualification_key_observation"."observation_bytes"),'hex'));
ALTER TABLE control."notification_completion_attempt" DROP CONSTRAINT "completion_attempt_bytes_ck";
ALTER TABLE control."notification_completion_attempt" ADD CONSTRAINT "completion_attempt_bytes_ck" CHECK (octet_length("control"."notification_completion_attempt"."attempt_bytes") between 1 and 4096 and "control"."notification_completion_attempt"."attempt_digest"='sha256:'||encode(sha256("control"."notification_completion_attempt"."attempt_bytes"),'hex'));
ALTER TABLE control."notification_completion_disposition" DROP CONSTRAINT "completion_disposition_bytes_ck";
ALTER TABLE control."notification_completion_disposition" ADD CONSTRAINT "completion_disposition_bytes_ck" CHECK (octet_length("control"."notification_completion_disposition"."transition_bytes") between 1 and 1048576 and "control"."notification_completion_disposition"."transition_digest"='sha256:'||encode(sha256("control"."notification_completion_disposition"."transition_bytes"),'hex') and octet_length("control"."notification_completion_disposition"."receipt_payload") between 1 and 65536 and octet_length("control"."notification_completion_disposition"."cose_sign1") between 65 and 131072);
ALTER TABLE control."notification_completion_disposition_signer_installation" DROP CONSTRAINT "completion_signer_bytes_ck";
ALTER TABLE control."notification_completion_disposition_signer_installation" ADD CONSTRAINT "completion_signer_bytes_ck" CHECK (octet_length("control"."notification_completion_disposition_signer_installation"."trust_bytes") between 1 and 65536 and "control"."notification_completion_disposition_signer_installation"."trust_digest"='sha256:'||encode(sha256("control"."notification_completion_disposition_signer_installation"."trust_bytes"),'hex'));
ALTER TABLE control."notification_completion_disposition_signing" DROP CONSTRAINT "completion_signing_bytes_ck";
ALTER TABLE control."notification_completion_disposition_signing" ADD CONSTRAINT "completion_signing_bytes_ck" CHECK (octet_length("control"."notification_completion_disposition_signing"."preparation_bytes") between 1 and 1048576 and "control"."notification_completion_disposition_signing"."preparation_digest"='sha256:'||encode(sha256("control"."notification_completion_disposition_signing"."preparation_bytes"),'hex'));
ALTER TABLE control."notification_completion_source" DROP CONSTRAINT "completion_source_bytes_ck";
ALTER TABLE control."notification_completion_source" ADD CONSTRAINT "completion_source_bytes_ck" CHECK (octet_length("control"."notification_completion_source"."source_bytes") between 1 and 524288 and "control"."notification_completion_source"."source_digest"='sha256:'||encode(sha256("control"."notification_completion_source"."source_bytes"),'hex'));
ALTER TABLE control."runtime_target_disposition_acknowledgement" DROP CONSTRAINT "runtime_target_disposition_ack_ck";
ALTER TABLE control."runtime_target_disposition_acknowledgement" ADD CONSTRAINT "runtime_target_disposition_ack_ck" CHECK (octet_length("control"."runtime_target_disposition_acknowledgement"."signed_acknowledgement") between 1 and 65536 and "control"."runtime_target_disposition_acknowledgement"."acknowledgement_digest"='sha256:'||encode(sha256("control"."runtime_target_disposition_acknowledgement"."signed_acknowledgement"),'hex') and jsonb_typeof("control"."runtime_target_disposition_acknowledgement"."claims")='object');
ALTER TABLE control."runtime_target_disposition_delivery" DROP CONSTRAINT "runtime_target_disposition_delivery_ck";
ALTER TABLE control."runtime_target_disposition_delivery" ADD CONSTRAINT "runtime_target_disposition_delivery_ck" CHECK (octet_length("control"."runtime_target_disposition_delivery"."signed_delivery") between 1 and 65536 and "control"."runtime_target_disposition_delivery"."delivery_digest"='sha256:'||encode(sha256("control"."runtime_target_disposition_delivery"."signed_delivery"),'hex') and jsonb_typeof("control"."runtime_target_disposition_delivery"."claims")='object');
ALTER TABLE control."notification_cancellation_signing" DROP CONSTRAINT "notification_cancel_signing_preimage_ck";
ALTER TABLE control."notification_cancellation_signing" ADD CONSTRAINT "notification_cancel_signing_preimage_ck" CHECK (octet_length("control"."notification_cancellation_signing"."preparation_bytes") between 1 and 1048576 and "control"."notification_cancellation_signing"."preparation_digest"='sha256:'||encode(sha256("control"."notification_cancellation_signing"."preparation_bytes"),'hex') and "control"."notification_cancellation_signing"."request_digest" ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE control."notification_delivery_cancellation" DROP CONSTRAINT "notification_cancellation_transition_ck";
ALTER TABLE control."notification_delivery_cancellation" ADD CONSTRAINT "notification_cancellation_transition_ck" CHECK (octet_length("control"."notification_delivery_cancellation"."transition_bytes") between 1 and 1048576 and "control"."notification_delivery_cancellation"."transition_digest"='sha256:'||encode(sha256("control"."notification_delivery_cancellation"."transition_bytes"),'hex'));
ALTER TABLE control."notification_delivery_outcome" DROP CONSTRAINT "notification_outcome_receipt_ck";
ALTER TABLE control."notification_delivery_outcome" ADD CONSTRAINT "notification_outcome_receipt_ck" CHECK (octet_length("control"."notification_delivery_outcome"."receipt_payload") between 1 and 65536 and octet_length("control"."notification_delivery_outcome"."cose_sign1") between 65 and 131072 and "control"."notification_delivery_outcome"."receipt_digest"='sha256:'||encode(sha256("control"."notification_delivery_outcome"."receipt_payload"),'hex'));
ALTER TABLE control."notification_delivery_outcome" DROP CONSTRAINT "notification_outcome_transition_ck";
ALTER TABLE control."notification_delivery_outcome" ADD CONSTRAINT "notification_outcome_transition_ck" CHECK (octet_length("control"."notification_delivery_outcome"."transition_bytes") between 1 and 524288 and "control"."notification_delivery_outcome"."transition_digest"='sha256:'||encode(sha256("control"."notification_delivery_outcome"."transition_bytes"),'hex'));
ALTER TABLE control."notification_delivery_outcome_signing" DROP CONSTRAINT "notification_outcome_signing_preparation_ck";
ALTER TABLE control."notification_delivery_outcome_signing" ADD CONSTRAINT "notification_outcome_signing_preparation_ck" CHECK (octet_length("control"."notification_delivery_outcome_signing"."preparation_bytes") between 1 and 524288 and "control"."notification_delivery_outcome_signing"."preparation_digest"='sha256:'||encode(sha256("control"."notification_delivery_outcome_signing"."preparation_bytes"),'hex'));
ALTER TABLE control."operations_qualification_root" DROP CONSTRAINT "ops_qualification_root_ck";
ALTER TABLE control."operations_qualification_root" ADD CONSTRAINT "ops_qualification_root_ck" CHECK ("control"."operations_qualification_root"."root_epoch" between 1 and 18446744073709551615 and "control"."operations_qualification_root"."root_key_id"='sha256:'||encode(sha256("control"."operations_qualification_root"."root_spki"),'hex') and octet_length("control"."operations_qualification_root"."root_spki") between 1 and 256 and "control"."operations_qualification_root"."valid_from_ms">=0 and "control"."operations_qualification_root"."valid_until_ms">"control"."operations_qualification_root"."valid_from_ms" and "control"."operations_qualification_root"."valid_until_ms"<=9007199254740991 and "control"."operations_qualification_root"."policy_signer" in ('OFFLINE_TRUST_ROOT','THRESHOLD_TRUST_ROOT') and "control"."operations_qualification_root"."state" in ('ACTIVE','REVOKED') and "control"."operations_qualification_root"."authority_id" ~ '^[a-z][a-z0-9-]{2,31}$');
ALTER TABLE control."operations_qualification_state" DROP CONSTRAINT "ops_qualification_state_ck";
ALTER TABLE control."operations_qualification_state" ADD CONSTRAINT "ops_qualification_state_ck" CHECK ("control"."operations_qualification_state"."sequence" between 1 and 18446744073709551615 and "control"."operations_qualification_state"."snapshot_sequence" between 1 and 18446744073709551615 and "control"."operations_qualification_state"."valid_until_ms" between 1 and 9007199254740991 and octet_length("control"."operations_qualification_state"."custody_bytes") between 1 and 10000000 and "control"."operations_qualification_state"."custody_digest"='sha256:'||encode(sha256("control"."operations_qualification_state"."custody_bytes"),'hex') and "control"."operations_qualification_state"."keyset_digest" ~ '^sha256:[0-9a-f]{64}$' and "control"."operations_qualification_state"."revocations_digest" ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE control."notification_delivery_dispatch_intent" DROP CONSTRAINT "notification_dispatch_state_ck";
ALTER TABLE control."notification_delivery_dispatch_intent" ADD CONSTRAINT "notification_dispatch_state_ck" CHECK ("control"."notification_delivery_dispatch_intent"."delivery_revision" between 2 and 18446744073709551615 and "control"."notification_delivery_dispatch_intent"."receipt_digest" ~ '^sha256:[0-9a-f]{64}$'
 and (("control"."notification_delivery_dispatch_intent"."state"='PENDING' and "control"."notification_delivery_dispatch_intent"."claim_token" is null and "control"."notification_delivery_dispatch_intent"."claimed_at_ms" is null)
 or ("control"."notification_delivery_dispatch_intent"."state"='CLAIMED' and "control"."notification_delivery_dispatch_intent"."claim_token" is not null and "control"."notification_delivery_dispatch_intent"."claim_token" ~ '^[0-9a-f]{64}$' and "control"."notification_delivery_dispatch_intent"."claimed_at_ms" is not null and "control"."notification_delivery_dispatch_intent"."claimed_at_ms" between 0 and 9007199254740991)));
ALTER TABLE control."notification_delivery_attempt" DROP CONSTRAINT "notification_attempt_count_ck";
ALTER TABLE control."notification_delivery_attempt" ADD CONSTRAINT "notification_attempt_count_ck" CHECK ("control"."notification_delivery_attempt"."attempt_number" between 1 and 6 and "control"."notification_delivery_attempt"."started_at_ms" between 0 and 9007199254740991
    and "control"."notification_delivery_attempt"."worker_credential_epoch" between 0 and 18446744073709551615);
ALTER TABLE control."notification_delivery_signing" DROP CONSTRAINT "notification_delivery_signing_bytes_ck";
ALTER TABLE control."notification_delivery_signing" ADD CONSTRAINT "notification_delivery_signing_bytes_ck" CHECK (octet_length("control"."notification_delivery_signing"."preparation_bytes") between 1 and 524288 and "control"."notification_delivery_signing"."preparation_digest"='sha256:'||encode(sha256("control"."notification_delivery_signing"."preparation_bytes"),'hex'));
ALTER TABLE control."notification_delivery_start" DROP CONSTRAINT "notification_delivery_start_receipt_ck";
ALTER TABLE control."notification_delivery_start" ADD CONSTRAINT "notification_delivery_start_receipt_ck" CHECK (octet_length("control"."notification_delivery_start"."receipt_payload") between 1 and 65536 and octet_length("control"."notification_delivery_start"."cose_sign1") between 65 and 131072 and "control"."notification_delivery_start"."receipt_digest"='sha256:'||encode(sha256("control"."notification_delivery_start"."receipt_payload"),'hex'));
ALTER TABLE control."notification_delivery_start" DROP CONSTRAINT "notification_delivery_start_transition_ck";
ALTER TABLE control."notification_delivery_start" ADD CONSTRAINT "notification_delivery_start_transition_ck" CHECK (octet_length("control"."notification_delivery_start"."transition_bytes") between 1 and 262144 and "control"."notification_delivery_start"."transition_digest"='sha256:'||encode(sha256("control"."notification_delivery_start"."transition_bytes"),'hex'));
ALTER TABLE control."operations_secret_association" DROP CONSTRAINT "operations_secret_association_bytes_ck";
ALTER TABLE control."operations_secret_association" ADD CONSTRAINT "operations_secret_association_bytes_ck" CHECK (octet_length("control"."operations_secret_association"."association_bytes") between 1 and 262144 and "control"."operations_secret_association"."association_digest"='sha256:'||encode(sha256("control"."operations_secret_association"."association_bytes"),'hex'));
ALTER TABLE control."operations_secret_observation" DROP CONSTRAINT "operations_secret_observation_bytes_ck";
ALTER TABLE control."operations_secret_observation" ADD CONSTRAINT "operations_secret_observation_bytes_ck" CHECK (octet_length("control"."operations_secret_observation"."payload") between 1 and 65536 and octet_length("control"."operations_secret_observation"."cose") between 65 and 66560 and "control"."operations_secret_observation"."source_digest"='sha256:'||encode(sha256("control"."operations_secret_observation"."cose"),'hex'));
ALTER TABLE control."notification_delivery_preparation" DROP CONSTRAINT "notification_delivery_preparation_bytes_ck";
ALTER TABLE control."notification_delivery_preparation" ADD CONSTRAINT "notification_delivery_preparation_bytes_ck" CHECK (octet_length("control"."notification_delivery_preparation"."preparation_bytes") between 1 and 262144 and "control"."notification_delivery_preparation"."preparation_digest"='sha256:'||encode(sha256("control"."notification_delivery_preparation"."preparation_bytes"),'hex'));
ALTER TABLE control."notification_delivery_preparation" DROP CONSTRAINT "notification_delivery_preparation_revision_ck";
ALTER TABLE control."notification_delivery_preparation" ADD CONSTRAINT "notification_delivery_preparation_revision_ck" CHECK ("control"."notification_delivery_preparation"."delivery_revision" between 1 and 18446744073709551614 and "control"."notification_delivery_preparation"."attempt_number" between 1 and 6);
ALTER TABLE control."notification_delivery" DROP CONSTRAINT "notification_delivery_budget_ck";
ALTER TABLE control."notification_delivery" ADD CONSTRAINT "notification_delivery_budget_ck" CHECK ("control"."notification_delivery"."attempt_count" between 0 and 6 and "control"."notification_delivery"."attempt_limit" between 0 and 6);
ALTER TABLE control."notification_delivery" DROP CONSTRAINT "notification_delivery_budget_provenance_ck";
ALTER TABLE control."notification_delivery" ADD CONSTRAINT "notification_delivery_budget_provenance_ck" CHECK ("control"."notification_delivery"."budget_configured_limit" between 0 and 100
          and "control"."notification_delivery"."attempt_limit"<=least("control"."notification_delivery"."budget_configured_limit",6)
          and "control"."notification_delivery"."budget_effective_digest" ~ '^sha256:[0-9a-f]{64}$'
          and "control"."notification_delivery"."budget_worker_installation_digest" ~ '^sha256:[0-9a-f]{64}$'
          and "control"."notification_delivery"."budget_environment_id" ~ '^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$');
ALTER TABLE control."operations_generation" DROP CONSTRAINT "operations_generation_bytes_ck";
ALTER TABLE control."operations_generation" ADD CONSTRAINT "operations_generation_bytes_ck" CHECK (octet_length("control"."operations_generation"."candidate_bytes") between 1 and 1048576 and "control"."operations_generation"."candidate_digest"='sha256:'||encode(sha256("control"."operations_generation"."candidate_bytes"),'hex'));
ALTER TABLE control."operations_generation_commit" DROP CONSTRAINT "operations_commit_sequence_ck";
ALTER TABLE control."operations_generation_commit" ADD CONSTRAINT "operations_commit_sequence_ck" CHECK ("control"."operations_generation_commit"."sequence" between 1 and 18446744073709551615 and "control"."operations_generation_commit"."effective_digest" ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE control."operations_installation" DROP CONSTRAINT "operations_installation_bytes_ck";
ALTER TABLE control."operations_installation" ADD CONSTRAINT "operations_installation_bytes_ck" CHECK (octet_length("control"."operations_installation"."installation_bytes") between 1 and 1048576 and "control"."operations_installation"."installation_digest"='sha256:'||encode(sha256("control"."operations_installation"."installation_bytes"),'hex'));
ALTER TABLE control."notification_source_cursor" DROP CONSTRAINT "notification_cursor_position_ck";
ALTER TABLE control."notification_source_cursor" ADD CONSTRAINT "notification_cursor_position_ck" CHECK (("control"."notification_source_cursor"."last_sequence"=0 and "control"."notification_source_cursor"."last_event_id" is null and "control"."notification_source_cursor"."last_data_digest" is null)
    or ("control"."notification_source_cursor"."last_sequence" between 1 and 18446744073709551615 and "control"."notification_source_cursor"."last_event_id" is not null and "control"."notification_source_cursor"."last_data_digest" is not null));
ALTER TABLE control."notification_source_cursor" DROP CONSTRAINT "notification_cursor_source_ck";
ALTER TABLE control."notification_source_cursor" ADD CONSTRAINT "notification_cursor_source_ck" CHECK (octet_length("control"."notification_source_cursor"."source") between 1 and 2048 and octet_length("control"."notification_source_cursor"."partition") between 1 and 256);
ALTER TABLE control."notification_source_inbox" DROP CONSTRAINT "notification_inbox_source_ck";
ALTER TABLE control."notification_source_inbox" ADD CONSTRAINT "notification_inbox_source_ck" CHECK (octet_length("control"."notification_source_inbox"."source") between 1 and 2048 and octet_length("control"."notification_source_inbox"."partition") between 1 and 256);
ALTER TABLE control."notification_occurrence_observation" DROP CONSTRAINT "notification_occurrence_observation_bytes_ck";
ALTER TABLE control."notification_occurrence_observation" ADD CONSTRAINT "notification_occurrence_observation_bytes_ck" CHECK (octet_length("control"."notification_occurrence_observation"."receipt_payload") between 1 and 65536 and octet_length("control"."notification_occurrence_observation"."cose_sign1") between 65 and 131072 and "control"."notification_occurrence_observation"."receipt_digest"='sha256:'||encode(sha256("control"."notification_occurrence_observation"."receipt_payload"),'hex'));
ALTER TABLE control."notification_occurrence_preparation" DROP CONSTRAINT "notification_occurrence_preparation_bytes_ck";
ALTER TABLE control."notification_occurrence_preparation" ADD CONSTRAINT "notification_occurrence_preparation_bytes_ck" CHECK (octet_length("control"."notification_occurrence_preparation"."preparation_bytes") between 1 and 262144 and "control"."notification_occurrence_preparation"."preparation_digest"='sha256:'||encode(sha256("control"."notification_occurrence_preparation"."preparation_bytes"),'hex'));
ALTER TABLE control."notification_key_preparation" DROP CONSTRAINT "notification_key_preparation_bytes_ck";
ALTER TABLE control."notification_key_preparation" ADD CONSTRAINT "notification_key_preparation_bytes_ck" CHECK (octet_length("control"."notification_key_preparation"."preparation_bytes") between 1 and 32768 and "control"."notification_key_preparation"."preparation_digest"='sha256:'||encode(sha256("control"."notification_key_preparation"."preparation_bytes"),'hex'));
ALTER TABLE control."evidence_kms_attempt" DROP CONSTRAINT "evidence_kms_attempt_request_ck";
ALTER TABLE control."evidence_kms_attempt" ADD CONSTRAINT "evidence_kms_attempt_request_ck" CHECK (octet_length("control"."evidence_kms_attempt"."request_bytes") between 1 and 32768
    and "control"."evidence_kms_attempt"."request_digest"='sha256:'||encode(sha256("control"."evidence_kms_attempt"."request_bytes"),'hex')
    and "control"."evidence_kms_attempt"."object_version"='1' and "control"."evidence_kms_attempt"."object_intent_digest" ~ '^sha256:[0-9a-f]{64}$'
    and "control"."evidence_kms_attempt"."authority_digest" ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE control."evidence_kms_attempt" DROP CONSTRAINT "evidence_kms_attempt_result_ck";
ALTER TABLE control."evidence_kms_attempt" ADD CONSTRAINT "evidence_kms_attempt_result_ck" CHECK (("control"."evidence_kms_attempt"."state" in ('PROVED','REJECTED'))=("control"."evidence_kms_attempt"."result_receipt_bytes" is not null)
    and ("control"."evidence_kms_attempt"."result_receipt_bytes" is null)=("control"."evidence_kms_attempt"."result_receipt_digest" is null)
    and ("control"."evidence_kms_attempt"."result_receipt_bytes" is null or (octet_length("control"."evidence_kms_attempt"."result_receipt_bytes") between 1 and 262144
    and "control"."evidence_kms_attempt"."result_receipt_digest"='sha256:'||encode(sha256("control"."evidence_kms_attempt"."result_receipt_bytes"),'hex'))));
ALTER TABLE control."evidence_kms_exchange" DROP CONSTRAINT "evidence_kms_exchange_receipt_ck";
ALTER TABLE control."evidence_kms_exchange" ADD CONSTRAINT "evidence_kms_exchange_receipt_ck" CHECK (("control"."evidence_kms_exchange"."state" in ('PROVED','REJECTED'))=("control"."evidence_kms_exchange"."receipt_bytes" is not null)
    and ("control"."evidence_kms_exchange"."receipt_bytes" is null)=("control"."evidence_kms_exchange"."receipt_digest" is null)
    and ("control"."evidence_kms_exchange"."receipt_bytes" is null)=("control"."evidence_kms_exchange"."provider_sequence" is null)
    and ("control"."evidence_kms_exchange"."receipt_bytes" is null)=("control"."evidence_kms_exchange"."recovery_floor" is null)
    and ("control"."evidence_kms_exchange"."receipt_bytes" is null or (octet_length("control"."evidence_kms_exchange"."receipt_bytes") between 1 and 262144
    and "control"."evidence_kms_exchange"."receipt_digest"='sha256:'||encode(sha256("control"."evidence_kms_exchange"."receipt_bytes"),'hex')
    and "control"."evidence_kms_exchange"."provider_sequence" between 1 and 18446744073709551615
    and "control"."evidence_kms_exchange"."recovery_floor" between 1 and "control"."evidence_kms_exchange"."provider_sequence")));
ALTER TABLE control."evidence_kms_installation" DROP CONSTRAINT "evidence_kms_installation_digest_ck";
ALTER TABLE control."evidence_kms_installation" ADD CONSTRAINT "evidence_kms_installation_digest_ck" CHECK (octet_length("control"."evidence_kms_installation"."pins_bytes") between 1 and 16384
    and "control"."evidence_kms_installation"."installation_digest"='sha256:'||encode(sha256("control"."evidence_kms_installation"."pins_bytes"),'hex'));
ALTER TABLE control."evidence_wrapped_key" DROP CONSTRAINT "evidence_wrapped_key_bytes_ck";
ALTER TABLE control."evidence_wrapped_key" ADD CONSTRAINT "evidence_wrapped_key_bytes_ck" CHECK (octet_length("control"."evidence_wrapped_key"."record_bytes") between 1 and 65536
    and octet_length("control"."evidence_wrapped_key"."record_cose") between 1 and 131072
    and "control"."evidence_wrapped_key"."key_id"='sha256:'||encode(sha256("control"."evidence_wrapped_key"."record_bytes"),'hex'));
ALTER TABLE control."notification_verification_attempt" DROP CONSTRAINT "notification_verification_attempt_bytes_ck";
ALTER TABLE control."notification_verification_attempt" ADD CONSTRAINT "notification_verification_attempt_bytes_ck" CHECK (octet_length("control"."notification_verification_attempt"."challenge_bytes") between 1 and 16384
    and ("control"."notification_verification_attempt"."response_bytes" is null or octet_length("control"."notification_verification_attempt"."response_bytes") between 1 and 270336));
ALTER TABLE control."fact_consumer_failure_signer" DROP CONSTRAINT "fact_failure_signer_time_ck";
ALTER TABLE control."fact_consumer_failure_signer" ADD CONSTRAINT "fact_failure_signer_time_ck" CHECK ("control"."fact_consumer_failure_signer"."valid_from_ms" between 0 and 9007199254740991 and "control"."fact_consumer_failure_signer"."valid_until_ms" between "control"."fact_consumer_failure_signer"."valid_from_ms"+1 and 9007199254740991);
ALTER TABLE control."fleet_fact_delivery" DROP CONSTRAINT "fleet_delivery_budget_ck";
ALTER TABLE control."fleet_fact_delivery" ADD CONSTRAINT "fleet_delivery_budget_ck" CHECK ("control"."fleet_fact_delivery"."maximum_attempts" between 1 and 1000 and "control"."fleet_fact_delivery"."failed_attempts" between 0 and "control"."fleet_fact_delivery"."maximum_attempts" and "control"."fleet_fact_delivery"."initial_backoff_ms" between 1 and 3600000 and "control"."fleet_fact_delivery"."maximum_backoff_ms" between "control"."fleet_fact_delivery"."initial_backoff_ms" and 3600000 and "control"."fleet_fact_delivery"."lease_generation" between 0 and 18446744073709551615);
ALTER TABLE control."fleet_fact_delivery" DROP CONSTRAINT "fleet_delivery_material_ck";
ALTER TABLE control."fleet_fact_delivery" ADD CONSTRAINT "fleet_delivery_material_ck" CHECK (octet_length("control"."fleet_fact_delivery"."material") between 1 and 65536 and "control"."fleet_fact_delivery"."material_digest"=sha256("control"."fleet_fact_delivery"."material"));
ALTER TABLE control."fleet_fact_delivery" DROP CONSTRAINT "fleet_delivery_time_ck";
ALTER TABLE control."fleet_fact_delivery" ADD CONSTRAINT "fleet_delivery_time_ck" CHECK ("control"."fleet_fact_delivery"."next_attempt_ms" between 0 and 9007199254740991 and ("control"."fleet_fact_delivery"."lease_until_ms" is null or "control"."fleet_fact_delivery"."lease_until_ms" between 0 and 9007199254740991));
ALTER TABLE control."fleet_fact_delivery_attempt" DROP CONSTRAINT "fleet_delivery_attempt_time_ck";
ALTER TABLE control."fleet_fact_delivery_attempt" ADD CONSTRAINT "fleet_delivery_attempt_time_ck" CHECK ("control"."fleet_fact_delivery_attempt"."started_at_ms" between 0 and 9007199254740991 and "control"."fleet_fact_delivery_attempt"."lease_until_ms">"control"."fleet_fact_delivery_attempt"."started_at_ms" and "control"."fleet_fact_delivery_attempt"."lease_until_ms"<=9007199254740991 and ("control"."fleet_fact_delivery_attempt"."ended_at_ms" is null or "control"."fleet_fact_delivery_attempt"."ended_at_ms" between "control"."fleet_fact_delivery_attempt"."started_at_ms" and 9007199254740991) and "control"."fleet_fact_delivery_attempt"."lease_generation" between 1 and 18446744073709551615);
ALTER TABLE control."store_retirement_admission" DROP CONSTRAINT "store_retirement_admission_revision_ck";
ALTER TABLE control."store_retirement_admission" ADD CONSTRAINT "store_retirement_admission_revision_ck" CHECK ("control"."store_retirement_admission"."lifecycle_revision" between 1 and 9223372036854775807 and "control"."store_retirement_admission"."revision"=1 and "control"."store_retirement_admission"."previous_attempt_id" is distinct from "control"."store_retirement_admission"."attempt_id" and "control"."store_retirement_admission"."dispatch_not_after_ms">floor(extract(epoch from "control"."store_retirement_admission"."admitted_at")*1000) and "control"."store_retirement_admission"."dispatch_not_after_ms"<=floor(extract(epoch from "control"."store_retirement_admission"."admitted_at")*1000)+60000);
ALTER TABLE control."store_retirement_admission" DROP CONSTRAINT "store_retirement_admission_wire_ck";
ALTER TABLE control."store_retirement_admission" ADD CONSTRAINT "store_retirement_admission_wire_ck" CHECK (octet_length("control"."store_retirement_admission"."attempt_wire") between 1 and 1048576 and "control"."store_retirement_admission"."attempt_digest" ~ '^[0-9a-f]{64}$' and "control"."store_retirement_admission"."selection_digest" ~ '^[0-9a-f]{64}$');
ALTER TABLE control."store_retirement_cancellation" DROP CONSTRAINT "store_retirement_cancellation_binding_ck";
ALTER TABLE control."store_retirement_cancellation" ADD CONSTRAINT "store_retirement_cancellation_binding_ck" CHECK ("control"."store_retirement_cancellation"."lifecycle_revision" between 1 and 9223372036854775807 and "control"."store_retirement_cancellation"."committed_digest" ~ '^[0-9a-f]{64}$' and jsonb_typeof("control"."store_retirement_cancellation"."cause")='object' and octet_length("control"."store_retirement_cancellation"."cause"::text) between 1 and 8192);
ALTER TABLE control."store_retirement_host" DROP CONSTRAINT "store_retirement_host_validity_ck";
ALTER TABLE control."store_retirement_host" ADD CONSTRAINT "store_retirement_host_validity_ck" CHECK ("control"."store_retirement_host"."workload_credential_epoch" between 0 and 18446744073709551615 and "control"."store_retirement_host"."valid_from_ms">=0 and "control"."store_retirement_host"."valid_until_ms">"control"."store_retirement_host"."valid_from_ms" and "control"."store_retirement_host"."valid_until_ms"<=9223372036854775807);
ALTER TABLE control."evidence_projection_retirement" DROP CONSTRAINT "evidence_projection_retirement_size_ck";
ALTER TABLE control."evidence_projection_retirement" ADD CONSTRAINT "evidence_projection_retirement_size_ck" CHECK ("control"."evidence_projection_retirement"."projection_bytes" between 1 and 16384 and "control"."evidence_projection_retirement"."sequence">0 and jsonb_typeof("control"."evidence_projection_retirement"."preservation_metadata")='object' and octet_length("control"."evidence_projection_retirement"."preservation_metadata"::text)<=2048);
ALTER TABLE control."protected_proof_checkpoint" DROP CONSTRAINT "protected_proof_checkpoint_size_ck";
ALTER TABLE control."protected_proof_checkpoint" ADD CONSTRAINT "protected_proof_checkpoint_size_ck" CHECK ("control"."protected_proof_checkpoint"."ciphertext_bytes" between 17 and 65552 and "control"."protected_proof_checkpoint"."sink_id" ~ '^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$');
ALTER TABLE control."protected_proof_access" DROP CONSTRAINT "protected_proof_access_purpose_ck";
ALTER TABLE control."protected_proof_access" ADD CONSTRAINT "protected_proof_access_purpose_ck" CHECK (length("control"."protected_proof_access"."purpose") between 1 and 256 and length("control"."protected_proof_access"."case_reference") between 1 and 256);
ALTER TABLE control."protected_proof_object" DROP CONSTRAINT "protected_proof_object_purpose_ck";
ALTER TABLE control."protected_proof_object" ADD CONSTRAINT "protected_proof_object_purpose_ck" CHECK (length("control"."protected_proof_object"."purpose") between 1 and 256 and length("control"."protected_proof_object"."case_reference") between 1 and 256 and "control"."protected_proof_object"."retain_until">"control"."protected_proof_object"."created_at");
ALTER TABLE control."protected_proof_payload" DROP CONSTRAINT "protected_proof_payload_shape_ck";
ALTER TABLE control."protected_proof_payload" ADD CONSTRAINT "protected_proof_payload_shape_ck" CHECK (length("control"."protected_proof_payload"."key_id") between 1 and 128 and octet_length("control"."protected_proof_payload"."nonce")=12 and octet_length("control"."protected_proof_payload"."ciphertext") between 17 and 65552);
ALTER TABLE control."deletion_job" DROP CONSTRAINT "deletion_job_accounting_ck";
ALTER TABLE control."deletion_job" ADD CONSTRAINT "deletion_job_accounting_ck" CHECK ("control"."deletion_job"."before_used_bytes" between 1 and 1073741824 and
    (("control"."deletion_job"."state"='EXECUTING' and "control"."deletion_job"."after_used_bytes" is null) or ("control"."deletion_job"."state"='SUCCEEDED' and "control"."deletion_job"."after_used_bytes" is not null and "control"."deletion_job"."after_used_bytes">=0 and "control"."deletion_job"."after_used_bytes"="control"."deletion_job"."before_used_bytes"-"control"."deletion_job"."deleted_bytes")));
ALTER TABLE control."retention_policy" DROP CONSTRAINT "retention_policy_digest_ck";
ALTER TABLE control."retention_policy" ADD CONSTRAINT "retention_policy_digest_ck" CHECK (octet_length("control"."retention_policy"."policy_cbor") between 1 and 65536 and "control"."retention_policy"."policy_digest"='sha256:'||encode(sha256("control"."retention_policy"."policy_cbor"),'hex'));
ALTER TABLE control."retention_policy" DROP CONSTRAINT "retention_policy_duration_ck";
ALTER TABLE control."retention_policy" ADD CONSTRAINT "retention_policy_duration_ck" CHECK ("control"."retention_policy"."retention_period_ms" between 0 and 9223372036854775807 and "control"."retention_policy"."local_grace_ms" between 0 and 9223372036854775807 and "control"."retention_policy"."sink_quorum" between 0 and 8);
ALTER TABLE control."evidence_export_output" DROP CONSTRAINT "evidence_export_output_digest_ck";
ALTER TABLE control."evidence_export_output" ADD CONSTRAINT "evidence_export_output_digest_ck" CHECK (octet_length("control"."evidence_export_output"."artifact") between 1 and 1048576 and "control"."evidence_export_output"."output_digest"='sha256:'||encode(sha256("control"."evidence_export_output"."artifact"),'hex'));
ALTER TABLE control."evidence_export_request" DROP CONSTRAINT "evidence_export_request_revision_ck";
ALTER TABLE control."evidence_export_request" ADD CONSTRAINT "evidence_export_request_revision_ck" CHECK ("control"."evidence_export_request"."revision" between 1 and 18446744073709551615 and "control"."evidence_export_request"."checkpoint" between 0 and 18446744073709551615);
ALTER TABLE control."evidence_stream" DROP CONSTRAINT "evidence_stream_capacity_ck";
ALTER TABLE control."evidence_stream" ADD CONSTRAINT "evidence_stream_capacity_ck" CHECK ("control"."evidence_stream"."capacity_bytes" between 1024 and 1073741824 and "control"."evidence_stream"."used_bytes" between 0 and "control"."evidence_stream"."capacity_bytes");
ALTER TABLE control."evidence_stream" DROP CONSTRAINT "evidence_stream_sequence_ck";
ALTER TABLE control."evidence_stream" ADD CONSTRAINT "evidence_stream_sequence_ck" CHECK ("control"."evidence_stream"."last_sequence" between 0 and 18446744073709551615 and (("control"."evidence_stream"."last_sequence"=0 and "control"."evidence_stream"."last_segment_digest" is null) or ("control"."evidence_stream"."last_sequence">0 and "control"."evidence_stream"."last_segment_digest" ~ '^sha256:[0-9a-f]{64}$')));
ALTER TABLE control."runtime_configuration_input" DROP CONSTRAINT "runtime_configuration_input_bytes_ck";
ALTER TABLE control."runtime_configuration_input" ADD CONSTRAINT "runtime_configuration_input_bytes_ck" CHECK (octet_length("control"."runtime_configuration_input"."configuration_cbor") between 1 and 4194304 and "control"."runtime_configuration_input"."configuration_digest"=sha256("control"."runtime_configuration_input"."configuration_cbor"));
ALTER TABLE control."cigl_profile_dependency_path" DROP CONSTRAINT "cigl_profile_path_ordinal_ck";
ALTER TABLE control."cigl_profile_dependency_path" ADD CONSTRAINT "cigl_profile_path_ordinal_ck" CHECK ("control"."cigl_profile_dependency_path"."ordinal" between 1 and 2048 and "control"."cigl_profile_dependency_path"."document"->>'ordinal'="control"."cigl_profile_dependency_path"."ordinal"::text);
ALTER TABLE control."contract_governance_association" DROP CONSTRAINT "contract_association_bytes_ck";
ALTER TABLE control."contract_governance_association" ADD CONSTRAINT "contract_association_bytes_ck" CHECK (octet_length("control"."contract_governance_association"."document_bytes") between 1 and 4096 and "control"."contract_governance_association"."semantic_digest" ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE control."contract_governance_association" DROP CONSTRAINT "contract_association_sequences_ck";
ALTER TABLE control."contract_governance_association" ADD CONSTRAINT "contract_association_sequences_ck" CHECK ("control"."contract_governance_association"."activation_sequence" between 1 and 18446744073709551615 and "control"."contract_governance_association"."current_sequence" between "control"."contract_governance_association"."activation_sequence" and 18446744073709551615 and "control"."contract_governance_association"."participant_epoch" between 1 and 18446744073709551615);
ALTER POLICY "platform_recovery_pending_expiry_effect_read" ON "control"."mutation_candidate" TO openpc_control_owner USING (openpc.matches_participant("control"."mutation_candidate"."participant_id") and openpc.matches_privacy("control"."mutation_candidate"."privacy_domain_id")
      and exists(select 1 from control.platform_recovery_enrollment source
        where source.participant_id="control"."mutation_candidate"."participant_id" and source.privacy_domain_id="control"."mutation_candidate"."privacy_domain_id"
          and openpc.platform_recovery_continuation_root_matches(source.platform_context_id,source.participant_id,source.root_epoch,source.root_revision)
          and ((source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' and source.document->>'schemaVersion'='3')
            or (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='4')
            or (source.source_purpose='ROOT_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='2'
              and jsonb_typeof(source.document->'uneffectedPredecessor')='object'
              and source.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'
              and source.document#>>'{uneffectedPredecessor,schemaVersion}'='1'))
          and source.document->>'schema'='pc.identity.platform-recovery-enrollment' and source.state='ACTIVE' and source.row_version=1
          and source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
          and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
          and source.valid_from<=clock_timestamp() and source.valid_until>clock_timestamp()
          and openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1')
          and (((source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='4')
        or (source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' and source.document->>'schemaVersion'='3'
          and source.document#>>'{source,activatedHandoff,schemaVersion}'='1'))
      and (openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
        or (openpc.current_action_intent_id()='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
          and not (source.document#>'{source}' ? 'activatedHandoff')
          and exists(select 1 from control.platform_recovery_case lease
            where lease.participant_id=source.participant_id and lease.privacy_domain_id=source.privacy_domain_id
              and lease.enrollment_id=source.enrollment_id
              and lease.enrollment_revision=source.row_version and lease.enrollment_digest=source.document_digest
              and lease.state='ACTIVE' and lease.valid_from<=clock_timestamp() and lease.valid_until>clock_timestamp()
              and lease.intent->>'schema'='pc.identity.platform-recovery-intent'
              and lease.intent ? 'approvalContinuation'
              and lease.intent->'pendingExpiry'=source.document#>'{source,pendingExpiry}'
              and lease.activation_operation_id is not null
              and lease.activation_evidence_digest=sha256(lease.activation_evidence_cbor)
              and octet_length(lease.activation_cose)>0
              and jsonb_typeof(lease.lease_bindings)='array' and jsonb_array_length(lease.lease_bindings)=2
)))
      and exists(select 1 from jsonb_array_elements(coalesce(source.document#>'{source,activatedHandoff,administrators}',source.document#>'{source,pendingExpiry,administrators}')) partial_effect
        where (("control"."mutation_candidate"."resource_id"::text=partial_effect->>'envelopeId'
          and "control"."mutation_candidate"."catalog_operation_id" in ('ID-OP-ENVELOPE-CREATE','ID-OP-ENVELOPE-ACTIVATE'))
          or ((source.document#>>'{source,pendingExpiry,schemaVersion}'='2' or source.document#>>'{source,activatedHandoff,schemaVersion}'='1')
            and ("control"."mutation_candidate"."resource_id"::text=partial_effect->>'envelopeId'
              or "control"."mutation_candidate"."maker_authority_envelope_id"::text=partial_effect->>'envelopeId')))))));
ALTER POLICY "root_expiry_admin_receipt_prerequisite_read" ON "control"."root_expiry_recovery_case" TO openpc_control_owner,openpc_control_platform_runtime,openpc_control_runtime USING (openpc.matches_participant("control"."root_expiry_recovery_case"."participant_id") and openpc.matches_privacy("control"."root_expiry_recovery_case"."privacy_domain_id")
      and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
      and exists(select 1 from control.platform_recovery_enrollment source
        join control.platform_recovery_case lease on lease.enrollment_id=source.enrollment_id
          and lease.participant_id=source.participant_id and lease.privacy_domain_id=source.privacy_domain_id
          and lease.enrollment_revision=source.row_version and lease.enrollment_digest=source.document_digest
        where source.participant_id="control"."root_expiry_recovery_case"."participant_id" and source.privacy_domain_id="control"."root_expiry_recovery_case"."privacy_domain_id"
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
            and (openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
              or (source.document->>'schemaVersion'='3' and lease.intent ? 'continuation'
                and openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'))
              or (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='4'
                and lease.intent->'pendingExpiry'=source.document#>'{source,pendingExpiry}'
                and (openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
                  or (lease.intent ? 'approvalContinuation'
                    and openpc.current_action_intent_id()='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1')))))
            or (source.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
              and lease.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
              and openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
              and (openpc.current_action_intent_id()<>'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
                or lease.intent->>'schemaVersion'='2')))
          and lease.state='ACTIVE'
          and lease.valid_from<=clock_timestamp() and lease.valid_until>clock_timestamp()
          and lease.activation_operation_id is not null and lease.activation_evidence_cbor is not null
          and lease.activation_evidence_digest is not null and lease.activation_cose is not null
          and jsonb_typeof(lease.lease_bindings)='array' and jsonb_array_length(lease.lease_bindings)=2
          and (
        source.root_expiry_recovery_id="control"."root_expiry_recovery_case"."recovery_id" and "control"."root_expiry_recovery_case"."state"='COMPLETED'
        and source.document#>>'{source,enrollmentId}'="control"."root_expiry_recovery_case"."enrollment_id"::text
        and source.document#>>'{source,activationOperationId}'="control"."root_expiry_recovery_case"."operation_id"::text
        and source.document#>>'{source,receiptDigest}'='sha256:'||encode("control"."root_expiry_recovery_case"."evidence_digest",'hex')
    or (jsonb_array_length(source.document#>'{source,ancestorReceipts}') between 1 and 31
      and exists(select 1 from jsonb_array_elements(source.document#>'{source,ancestorReceipts}') declared
        where declared->>'recoveryId'="control"."root_expiry_recovery_case"."recovery_id"::text and "control"."root_expiry_recovery_case"."state"='COMPLETED'
          and declared->>'enrollmentId'="control"."root_expiry_recovery_case"."enrollment_id"::text
          and declared->>'activationOperationId'="control"."root_expiry_recovery_case"."operation_id"::text
          and declared->>'receiptDigest'='sha256:'||encode("control"."root_expiry_recovery_case"."evidence_digest",'hex'))))));
ALTER POLICY "root_expiry_admin_receipt_prerequisite_read" ON "control"."root_expiry_recovery_enrollment" TO openpc_control_owner,openpc_control_platform_runtime,openpc_control_runtime USING (openpc.matches_participant("control"."root_expiry_recovery_enrollment"."participant_id") and openpc.matches_privacy("control"."root_expiry_recovery_enrollment"."privacy_domain_id")
      and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
      and exists(select 1 from control.platform_recovery_enrollment source
        join control.platform_recovery_case lease on lease.enrollment_id=source.enrollment_id
          and lease.participant_id=source.participant_id and lease.privacy_domain_id=source.privacy_domain_id
          and lease.enrollment_revision=source.row_version and lease.enrollment_digest=source.document_digest
        where source.participant_id="control"."root_expiry_recovery_enrollment"."participant_id" and source.privacy_domain_id="control"."root_expiry_recovery_enrollment"."privacy_domain_id"
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
            and (openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
              or (source.document->>'schemaVersion'='3' and lease.intent ? 'continuation'
                and openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'))
              or (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='4'
                and lease.intent->'pendingExpiry'=source.document#>'{source,pendingExpiry}'
                and (openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
                  or (lease.intent ? 'approvalContinuation'
                    and openpc.current_action_intent_id()='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1')))))
            or (source.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
              and lease.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
              and openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
              and (openpc.current_action_intent_id()<>'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
                or lease.intent->>'schemaVersion'='2')))
          and lease.state='ACTIVE'
          and lease.valid_from<=clock_timestamp() and lease.valid_until>clock_timestamp()
          and lease.activation_operation_id is not null and lease.activation_evidence_cbor is not null
          and lease.activation_evidence_digest is not null and lease.activation_cose is not null
          and jsonb_typeof(lease.lease_bindings)='array' and jsonb_array_length(lease.lease_bindings)=2
          and (
        source.document#>>'{source,enrollmentId}'="control"."root_expiry_recovery_enrollment"."enrollment_id"::text
    or (jsonb_array_length(source.document#>'{source,ancestorReceipts}') between 1 and 31
      and exists(select 1 from jsonb_array_elements(source.document#>'{source,ancestorReceipts}') declared
        where declared->>'enrollmentId'="control"."root_expiry_recovery_enrollment"."enrollment_id"::text)))));
ALTER POLICY "root_expiry_admin_receipt_prerequisite_read" ON "control"."root_expiry_recovery_scope" TO openpc_control_owner,openpc_control_platform_runtime,openpc_control_runtime USING (openpc.matches_participant("control"."root_expiry_recovery_scope"."owner_participant_id") and openpc.matches_privacy("control"."root_expiry_recovery_scope"."installation_privacy_domain_id")
      and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
      and exists(select 1 from control.platform_recovery_enrollment source
        join control.platform_recovery_case lease on lease.enrollment_id=source.enrollment_id
          and lease.participant_id=source.participant_id and lease.privacy_domain_id=source.privacy_domain_id
          and lease.enrollment_revision=source.row_version and lease.enrollment_digest=source.document_digest
        where source.participant_id="control"."root_expiry_recovery_scope"."owner_participant_id" and source.privacy_domain_id="control"."root_expiry_recovery_scope"."installation_privacy_domain_id"
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
            and (openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
              or (source.document->>'schemaVersion'='3' and lease.intent ? 'continuation'
                and openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'))
              or (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='4'
                and lease.intent->'pendingExpiry'=source.document#>'{source,pendingExpiry}'
                and (openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
                  or (lease.intent ? 'approvalContinuation'
                    and openpc.current_action_intent_id()='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1')))))
            or (source.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
              and lease.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
              and openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
              and (openpc.current_action_intent_id()<>'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
                or lease.intent->>'schemaVersion'='2')))
          and lease.state='ACTIVE'
          and lease.valid_from<=clock_timestamp() and lease.valid_until>clock_timestamp()
          and lease.activation_operation_id is not null and lease.activation_evidence_cbor is not null
          and lease.activation_evidence_digest is not null and lease.activation_cose is not null
          and jsonb_typeof(lease.lease_bindings)='array' and jsonb_array_length(lease.lease_bindings)=2
          and (
        source.root_expiry_recovery_id="control"."root_expiry_recovery_scope"."recovery_id" and source.platform_context_id="control"."root_expiry_recovery_scope"."platform_context_id"
        and source.root_epoch="control"."root_expiry_recovery_scope"."platform_authority_epoch" and source.root_digest="control"."root_expiry_recovery_scope"."admission_digest"
        and source.document#>>'{source,activationOperationId}'="control"."root_expiry_recovery_scope"."activation_operation_id"::text
    or (jsonb_array_length(source.document#>'{source,ancestorReceipts}') between 1 and 31
      and exists(select 1 from jsonb_array_elements(source.document#>'{source,ancestorReceipts}') declared
        where declared->>'recoveryId'="control"."root_expiry_recovery_scope"."recovery_id"::text and source.platform_context_id="control"."root_expiry_recovery_scope"."platform_context_id"
          and "control"."root_expiry_recovery_scope"."platform_authority_epoch"<source.root_epoch
          and declared->>'activationOperationId'="control"."root_expiry_recovery_scope"."activation_operation_id"::text)))));
ALTER POLICY "root_expiry_scope_read" ON "control"."root_expiry_recovery_scope" TO openpc_control_owner,openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (case when current_user='openpc_control_owner'
          and openpc.matches_participant("control"."root_expiry_recovery_scope"."owner_participant_id") and openpc.matches_privacy("control"."root_expiry_recovery_scope"."installation_privacy_domain_id")
          and (openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' or (openpc.matches_participant("control"."root_expiry_recovery_scope"."owner_participant_id") and openpc.matches_privacy("control"."root_expiry_recovery_scope"."installation_privacy_domain_id")
      and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
      and exists(select 1 from control.platform_recovery_enrollment source
        join control.platform_recovery_case lease on lease.enrollment_id=source.enrollment_id
          and lease.participant_id=source.participant_id and lease.privacy_domain_id=source.privacy_domain_id
          and lease.enrollment_revision=source.row_version and lease.enrollment_digest=source.document_digest
        where source.participant_id="control"."root_expiry_recovery_scope"."owner_participant_id" and source.privacy_domain_id="control"."root_expiry_recovery_scope"."installation_privacy_domain_id"
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
            and (openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
              or (source.document->>'schemaVersion'='3' and lease.intent ? 'continuation'
                and openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'))
              or (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='4'
                and lease.intent->'pendingExpiry'=source.document#>'{source,pendingExpiry}'
                and (openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
                  or (lease.intent ? 'approvalContinuation'
                    and openpc.current_action_intent_id()='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1')))))
            or (source.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
              and lease.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
              and openpc.current_action_intent_id() in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1', 'ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-POLICY_APPROVE_REQUEST-V1', 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
              and (openpc.current_action_intent_id()<>'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
                or lease.intent->>'schemaVersion'='2')))
          and lease.state='ACTIVE'
          and lease.valid_from<=clock_timestamp() and lease.valid_until>clock_timestamp()
          and lease.activation_operation_id is not null and lease.activation_evidence_cbor is not null
          and lease.activation_evidence_digest is not null and lease.activation_cose is not null
          and jsonb_typeof(lease.lease_bindings)='array' and jsonb_array_length(lease.lease_bindings)=2
          and (
        source.root_expiry_recovery_id="control"."root_expiry_recovery_scope"."recovery_id" and source.platform_context_id="control"."root_expiry_recovery_scope"."platform_context_id"
        and source.root_epoch="control"."root_expiry_recovery_scope"."platform_authority_epoch" and source.root_digest="control"."root_expiry_recovery_scope"."admission_digest"
        and source.document#>>'{source,activationOperationId}'="control"."root_expiry_recovery_scope"."activation_operation_id"::text
    or (jsonb_array_length(source.document#>'{source,ancestorReceipts}') between 1 and 31
      and exists(select 1 from jsonb_array_elements(source.document#>'{source,ancestorReceipts}') declared
        where declared->>'recoveryId'="control"."root_expiry_recovery_scope"."recovery_id"::text and source.platform_context_id="control"."root_expiry_recovery_scope"."platform_context_id"
          and "control"."root_expiry_recovery_scope"."platform_authority_epoch"<source.root_epoch
          and declared->>'activationOperationId'="control"."root_expiry_recovery_scope"."activation_operation_id"::text))))))
          then false else exists(select 1 from control.authority_envelope e where e.platform_context_id="control"."root_expiry_recovery_scope"."platform_context_id" and openpc.matches_participant(e.participant_id)
          and openpc.current_privacy_domain_id()::text=any(e.privacy_domain_ids)) end);
