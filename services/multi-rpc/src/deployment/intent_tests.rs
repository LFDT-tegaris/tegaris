use super::*;
use crate::deployment::intent::{PreparationContext, PreparedDeploymentIntent};

fn fixture() -> (
    pc_policy_core::deployment_policy::AdmittedDeploymentPolicy,
    SignedTransaction,
    PreparationContext,
) {
    let input = super::simulation_tests::input("TRANSACTION_CREATE");
    let signed = test_transaction_to(9, 2, None, INIT);
    let context = PreparationContext {
        intent_id: "intent:1".into(),
        participant_id: input.actor.participant_id,
        privacy_domain_id: input.actor.privacy_domain_id,
        participant_epoch: 1,
        actor_subject_id: "principal:1".into(),
        workload_binding_id: Some("workload:1".into()),
        wallet_binding_id: "wallet:1".into(),
        wallet_binding_epoch: 1,
        sender: *signed.signer(),
        chain_environment_id: "chain:1".into(),
        target_runtime_id: "018f0000-0000-7000-8000-000000000301".into(),
        policy_generation_digest: Digest::of("generation"),
        authority_digest: Digest::of("authority"),
        policy_decision_digest: Digest::of("decision"),
        entitlement_envelope_digest: Digest::of("envelope"),
        routing_constraint_digest: Digest::of("route"),
        approval_set_digest: Digest::of("approval set"),
        native_value_authorization_bytes: None,
        issued_at_ms: 1000,
        expires_at_ms: 2000,
    };
    (input.deployments[0].clone(), signed, context)
}

#[test]
fn fee_bump_requires_fresh_exact_preparation_and_preserves_original_effect_context() {
    let (publication, original, context) = fixture();
    let old = PreparedDeploymentIntent::prepare(
        &publication,
        original.unsigned().clone(),
        context.clone(),
        1000,
    )
    .unwrap();
    let successor =
        crate::signed_transaction::test_transaction_with_fees(9, 4, 2, None, INIT, &[0; 32]);
    let mut fresh = context.clone();
    fresh.intent_id = "intent:replacement".into();
    fresh.issued_at_ms = 1100;
    fresh.policy_decision_digest = Digest::of("fresh decision");
    fresh.approval_set_digest = Digest::of("fresh approval");
    let next = PreparedDeploymentIntent::prepare(
        &publication,
        successor.unsigned().clone(),
        fresh.clone(),
        1100,
    )
    .unwrap();
    next.validate_fee_bump_from(&old, &successor).unwrap();
    assert!(
        old.rebind_signed(&publication, &context, &successor, 1100)
            .is_err()
    );
    assert!(next.validate_fee_bump_from(&old, &original).is_err());
    for mutate in [
        (|context: &mut PreparationContext| context.wallet_binding_epoch += 1)
            as fn(&mut PreparationContext),
        |context| context.participant_epoch += 1,
        |context| context.target_runtime_id = "018f0000-0000-7000-8000-000000000302".into(),
        |context| context.routing_constraint_digest = Digest::of("different route"),
    ] {
        let mut changed = fresh.clone();
        mutate(&mut changed);
        let changed = PreparedDeploymentIntent::prepare(
            &publication,
            successor.unsigned().clone(),
            changed,
            1100,
        )
        .unwrap();
        assert!(changed.validate_fee_bump_from(&old, &successor).is_err());
    }
}

#[test]
fn native_value_intent_binds_exact_independent_grant_and_preserves_zero_value_bytes() {
    use pc_policy_core::native_value::{
        NativeValueAmountMode, NativeValueAuthorizationV1, NativeValuePurpose,
    };
    let (mut publication, zero, mut context) = fixture();
    let zero_prepared = PreparedDeploymentIntent::prepare(
        &publication,
        zero.unsigned().clone(),
        context.clone(),
        1000,
    )
    .unwrap();
    let zero_record: serde_json::Value =
        serde_json::from_slice(&zero_prepared.record_bytes().unwrap()).unwrap();
    assert!(
        zero_record["context"]
            .get("nativeValueAuthorizationBytes")
            .is_none()
    );
    let mut value = [0; 32];
    value[31] = 10;
    publication.definition.transaction_policy.maximum_value = value;
    let definition = serde_json::to_value(&publication.definition).unwrap();
    publication.definition_digest = format!(
        "sha256:{}",
        Digest::of(canonical_bytes(&definition).unwrap()).as_str()
    );
    let signed =
        crate::signed_transaction::test_transaction_to_with_value(9, 2, None, INIT, &value);
    assert!(
        PreparedDeploymentIntent::prepare(
            &publication,
            signed.unsigned().clone(),
            context.clone(),
            1000
        )
        .is_err()
    );
    let mut grant = NativeValueAuthorizationV1 {
        authorization_id: "urn:openpc:resource:018f0000-0000-7000-8000-000000000801".into(),
        participant_id: context.participant_id.clone(),
        participant_epoch: context.participant_epoch,
        actor_subject_id: context.actor_subject_id.clone(),
        chain_environment_id: context.chain_environment_id.clone(),
        chain_id: "1".into(),
        genesis_hash: Digest::parse(publication.definition.genesis_digest[7..].to_owned()).unwrap(),
        purpose: NativeValuePurpose::ContractCreationEndowment,
        amount_mode: NativeValueAmountMode::Exact,
        max_amount_wei: "10".into(),
        one_use: true,
        used: false,
        policy_decision_digest: Digest::of("independent Native Value decision"),
        valid_until: "1970-01-01T00:00:02Z".into(),
        semantic_digest: Digest::of([]),
    };
    grant.semantic_digest = grant.computed_digest().unwrap();
    context.native_value_authorization_bytes = Some(hex(&grant.document_bytes().unwrap()));
    let prepared = PreparedDeploymentIntent::prepare(
        &publication,
        signed.unsigned().clone(),
        context.clone(),
        1000,
    )
    .unwrap();
    let document: serde_json::Value =
        serde_json::from_slice(&prepared.intent_bytes().unwrap()).unwrap();
    assert_eq!(document["valueWei"], "10");
    assert_eq!(
        document["nativeValueAuthorizationDigest"],
        grant.semantic_digest.as_str()
    );
    let restored =
        PreparedDeploymentIntent::restore(&prepared.record_bytes().unwrap(), &publication).unwrap();
    assert_eq!(
        restored.record_bytes().unwrap(),
        prepared.record_bytes().unwrap()
    );
    let binding = restored
        .reservation_binding(
            &publication,
            &signed,
            "018f0000-0000-7000-8000-000000000901",
            "018f0000-0000-7000-8000-000000000902",
            1500,
        )
        .unwrap();
    assert_eq!(
        binding["nativeValueAuthorizationId"],
        "018f0000-0000-7000-8000-000000000801"
    );
    assert_eq!(
        binding["nativeValueAuthorizationDigest"],
        format!("sha256:{}", grant.semantic_digest.as_str())
    );
    let signer =
        pc_runtime_types::PurposeSigner::from_secret_bytes(custody::HANDOFF_PURPOSE, [22; 32])
            .unwrap();
    let handoff = signer
        .sign(custody::DeploymentHandoff {
            predecessor_command_id: None,
            command_id: binding["commandId"].as_str().unwrap().into(),
            attempt_id: binding["attemptId"].as_str().unwrap().into(),
            reservation_binding_digest: Digest::of(canonical_bytes(&binding).unwrap()),
            publication_digest: Digest::of(
                canonical_bytes(&serde_json::to_value(&publication).unwrap()).unwrap(),
            ),
            candidate_digest: Digest::of("candidate"),
            authorization_evidence_digest: Digest::of("authorized submission"),
            workload_peer_binding_digest: Digest::of("workload peer"),
            identity_vector_digest: Digest::of("identity vector"),
            handoff_at_ms: 1500,
            expires_at_ms: 1900,
        })
        .unwrap();
    let verified = custody::VerifiedDeploymentHandoff::verify(
        &signer.verifier().sec1_bytes(),
        &handoff,
        &restored,
        &publication,
        &signed,
        1501,
    )
    .unwrap();
    assert_eq!(
        verified
            .submission()
            .native_value_authorization_digest
            .as_ref(),
        Some(&grant.semantic_digest)
    );
    let observed = BoundDeployment::for_observation(
        &verified.submission().constraints,
        *signed.hash(),
        verified.submission().transaction.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(observed.transaction_value, value);
    for scenario in 0..8 {
        let mut denied = grant.clone();
        match scenario {
            0 => denied.used = true,
            1 => denied.participant_id = "participant:foreign".into(),
            2 => denied.participant_epoch += 1,
            3 => denied.actor_subject_id = "actor:foreign".into(),
            4 => denied.chain_environment_id = "chain:foreign".into(),
            5 => denied.genesis_hash = Digest::of("foreign genesis"),
            6 => denied.max_amount_wei = "9".into(),
            _ => denied.valid_until = "1970-01-01T00:00:01.500Z".into(),
        }
        denied.semantic_digest = denied.computed_digest().unwrap();
        let mut changed = context.clone();
        changed.native_value_authorization_bytes = Some(hex(&denied.document_bytes().unwrap()));
        assert!(
            PreparedDeploymentIntent::prepare(
                &publication,
                signed.unsigned().clone(),
                changed.clone(),
                1000
            )
            .is_err(),
            "scenario {scenario}"
        );
        assert!(
            restored
                .rebind_signed(&publication, &changed, &signed, 1000)
                .is_err()
        );
    }
    let mut narrower = publication.clone();
    narrower.definition.transaction_policy.maximum_value[31] = 9;
    narrower.definition_digest = format!(
        "sha256:{}",
        Digest::of(canonical_bytes(&serde_json::to_value(&narrower.definition).unwrap()).unwrap())
            .as_str()
    );
    assert!(
        PreparedDeploymentIntent::prepare(&narrower, signed.unsigned().clone(), context, 1000)
            .is_err()
    );
}

#[test]
fn factory_intent_preserves_symbolic_create_and_exact_create2_identity() {
    for mechanism in ["CREATE", "CREATE2"] {
        let source = super::simulation_tests::input(mechanism);
        let publication = &source.deployments[0];
        let bytes = crate::write_preflight::data(
            &serde_json::json!(source.request.signed_transaction),
            131_072,
        )
        .unwrap();
        let signed = SignedTransaction::decode(&bytes).unwrap();
        let (_, _, mut context) = fixture();
        context.sender = *signed.signer();
        let prepared = PreparedDeploymentIntent::prepare(
            publication,
            signed.unsigned().clone(),
            context.clone(),
            1000,
        )
        .unwrap();
        let document: serde_json::Value =
            serde_json::from_slice(&prepared.intent_bytes().unwrap()).unwrap();
        assert_eq!(document["schemaVersion"], "PC-FACTORY-DEPLOYMENT-INTENT-1");
        assert_eq!(document["destination"], hex(&FACTORY));
        assert_eq!(document["initCode"], hex(INIT));
        assert_eq!(
            document["expectedContractAddress"].is_null(),
            mechanism == "CREATE"
        );
        let restored =
            PreparedDeploymentIntent::restore(&prepared.record_bytes().unwrap(), publication)
                .unwrap();
        assert_eq!(
            restored.record_bytes().unwrap(),
            prepared.record_bytes().unwrap()
        );
        let bound = restored
            .rebind_signed(publication, &context, &signed, 1500)
            .unwrap();
        assert_eq!(bound.creator, FACTORY);
        assert_eq!(bound.predicted_address().is_none(), mechanism == "CREATE");
        if mechanism == "CREATE2" {
            let expected =
                crate::signed_transaction::create2_address(&FACTORY, &[0x27; 32], INIT).unwrap();
            assert_eq!(bound.predicted_address(), Some(&expected));
            assert_eq!(document["expectedContractAddress"], hex(&expected));
        }
        for replacement in [
            test_transaction_to(10, 2, Some(FACTORY), signed.data()),
            test_transaction_to(9, 2, Some([0x36; 20]), signed.data()),
            test_transaction_to(9, 2, None, INIT),
        ] {
            assert!(
                restored
                    .rebind_signed(publication, &context, &replacement, 1500)
                    .is_err()
            );
        }
        for field in [
            "destination",
            "expectedContractAddress",
            "schemaVersion",
            "factoryConstraints",
        ] {
            let mut changed: serde_json::Value =
                serde_json::from_slice(&prepared.record_bytes().unwrap()).unwrap();
            changed["intent"][field] = serde_json::json!("substitution");
            assert!(
                PreparedDeploymentIntent::restore(
                    &serde_json::to_vec(&changed).unwrap(),
                    publication
                )
                .is_err(),
                "{mechanism}: {field}"
            );
        }
        assert!(
            PreparedDeploymentIntent::prepare_direct(
                publication,
                signed.unsigned().clone(),
                context,
                1000
            )
            .is_err()
        );
    }
}

#[test]
fn deployment_handoff_binds_worker_signature_and_exact_retained_reservation() {
    use crate::deployment::custody::{
        DeploymentHandoff, HANDOFF_PURPOSE, VerifiedDeploymentHandoff,
    };
    use pc_runtime_types::{PurposeSigner, canonical_bytes};
    let (publication, transaction, context) = fixture();
    let prepared = PreparedDeploymentIntent::prepare_direct(
        &publication,
        transaction.unsigned().clone(),
        context,
        1000,
    )
    .unwrap();
    let command = "018f0000-0000-7000-8000-000000000701";
    let attempt = "018f0000-0000-7000-8000-000000000702";
    let binding = prepared
        .reservation_binding(&publication, &transaction, command, attempt, 1100)
        .unwrap();
    let signer = PurposeSigner::from_secret_bytes(HANDOFF_PURPOSE, [21; 32]).unwrap();
    let claims = DeploymentHandoff {
        predecessor_command_id: None,
        command_id: command.into(),
        attempt_id: attempt.into(),
        reservation_binding_digest: Digest::of(canonical_bytes(&binding).unwrap()),
        publication_digest: Digest::of(
            canonical_bytes(&serde_json::to_value(&publication).unwrap()).unwrap(),
        ),
        candidate_digest: Digest::of("approved candidate"),
        authorization_evidence_digest: Digest::of("fresh submission approval"),
        workload_peer_binding_digest: Digest::of("real TLS peer"),
        identity_vector_digest: Digest::of("current identity vector"),
        handoff_at_ms: 1100,
        expires_at_ms: 2000,
    };
    let proof = signer.sign(claims.clone()).unwrap();
    let verify = |proof: &pc_runtime_types::SignedEnvelope<DeploymentHandoff>, now: u64| {
        VerifiedDeploymentHandoff::verify(
            &signer.verifier().sec1_bytes(),
            proof,
            &prepared,
            &publication,
            &transaction,
            now,
        )
    };
    let verified = verify(&proof, 1101).unwrap();
    assert_eq!(verified.submission().command_id, command);
    assert_eq!(verified.submission().attempt_id, attempt);
    assert_eq!(
        verified.submission().preparation_digest,
        prepared.record_digest().unwrap()
    );
    assert!(verify(&proof, 2000).is_err());
    assert!(verify(&proof, 1099).is_err());
    let mut tampered = proof.clone();
    tampered.claims.candidate_digest = Digest::of("changed bytes");
    assert!(verify(&tampered, 1101).is_err());
    let other = PurposeSigner::from_secret_bytes(HANDOFF_PURPOSE, [22; 32])
        .unwrap()
        .sign(claims.clone())
        .unwrap();
    assert!(verify(&other, 1101).is_err());
    let wrong_purpose =
        PurposeSigner::from_secret_bytes("openpc:runtime-target-bootstrap:v1", [21; 32])
            .unwrap()
            .sign(claims.clone())
            .unwrap();
    assert!(verify(&wrong_purpose, 1101).is_err());
    for counterexample in 0..5 {
        let mut changed = claims.clone();
        match counterexample {
            0 => changed.command_id = attempt.into(),
            1 => changed.attempt_id = command.into(),
            2 => changed.reservation_binding_digest = Digest::of("other reservation"),
            3 => changed.publication_digest = Digest::of("other publication"),
            _ => changed.expires_at_ms += 1,
        }
        assert!(verify(&signer.sign(changed).unwrap(), 1101).is_err());
    }
}

#[test]
fn direct_intent_preserves_c17_fields_and_exact_signing_payload_after_restore() {
    let (publication, signed, context) = fixture();
    let prepared = PreparedDeploymentIntent::prepare_direct(
        &publication,
        signed.unsigned().clone(),
        context.clone(),
        1000,
    )
    .unwrap();
    let source = super::simulation_tests::input("TRANSACTION_CREATE");
    let compiled = pc_policy_core::contract_simulation::compile_document_with_deployments(
        &source.document,
        &source.admitted,
        &source.deployments,
        context.workload_binding_id.as_ref().unwrap(),
        &context.policy_generation_digest,
    )
    .unwrap();
    prepared
        .validate_workload_configuration(
            &compiled.configuration_cbor,
            compiled.configuration_digest.as_str(),
        )
        .unwrap();
    assert!(
        prepared
            .validate_workload_configuration(
                &compiled.configuration_cbor,
                Digest::of("substituted configuration").as_str(),
            )
            .is_err()
    );
    let mut other_context = context.clone();
    other_context.workload_binding_id = Some("workload:other".into());
    let other = PreparedDeploymentIntent::prepare_direct(
        &publication,
        signed.unsigned().clone(),
        other_context,
        1000,
    )
    .unwrap();
    assert!(
        other
            .validate_workload_configuration(
                &compiled.configuration_cbor,
                compiled.configuration_digest.as_str(),
            )
            .is_err()
    );
    let document: serde_json::Value =
        serde_json::from_slice(&prepared.intent_bytes().unwrap()).unwrap();
    let command_id = uuid::Uuid::now_v7().to_string();
    let attempt_id = uuid::Uuid::now_v7().to_string();
    let reservation = prepared
        .reservation_binding(&publication, &signed, &command_id, &attempt_id, 1000)
        .unwrap();
    assert_eq!(reservation["commandId"], command_id);
    assert_eq!(reservation["attemptId"], attempt_id);
    assert_eq!(
        reservation["targetRuntimeId"],
        format!("urn:openpc:resource:{}", context.target_runtime_id)
    );
    assert_eq!(
        reservation["contractAddress"],
        document["expectedContractAddress"]
    );
    assert_eq!(reservation["transactionHash"], hex(signed.hash()));
    assert_eq!(
        reservation["preparedRecordDigest"],
        format!("sha256:{}", prepared.record_digest().unwrap().as_str())
    );
    assert_eq!(reservation["expiresAt"], "1970-01-01T00:00:02.000Z");
    assert!(
        prepared
            .reservation_binding(&publication, &signed, "caller", &attempt_id, 1000)
            .is_err()
    );
    assert!(
        prepared
            .reservation_binding(&publication, &signed, &command_id, &attempt_id, 2000)
            .is_err()
    );
    assert_eq!(document["artifactMode"], "FULL_INIT_CODE_V1");
    assert_eq!(document["destination"], serde_json::Value::Null);
    assert_eq!(document["nonce"], "9");
    assert_eq!(document["valueWei"], "0");
    assert_eq!(document["sender"], hex(signed.signer()));
    assert_eq!(
        document["expectedContractAddress"],
        hex(&crate::signed_transaction::create_address(
            signed.signer(),
            9
        ))
    );
    assert_eq!(
        document["nativeValueAuthorizationDigest"],
        serde_json::Value::Null
    );
    assert_eq!(
        document["semanticDigest"],
        prepared.intent_digest().as_str()
    );
    for forbidden in ["ready", "approved", "grant", "permission", "state"] {
        assert!(document.get(forbidden).is_none());
    }
    let record = prepared.record_bytes().unwrap();
    let restored = PreparedDeploymentIntent::restore(&record, &publication).unwrap();
    assert_eq!(restored.record_bytes().unwrap(), record);
    assert_eq!(
        restored.record_digest().unwrap(),
        prepared.record_digest().unwrap()
    );
    assert_eq!(restored.unsigned().bytes(), signed.unsigned().bytes());
    assert!(
        restored
            .rebind_signed(&publication, &context, &signed, 1500)
            .is_ok()
    );
    assert!(
        restored
            .rebind_signed(&publication, &context, &signed, 2000)
            .is_err()
    );
    // Historical readback remains possible after expiry; it is not active authority.
    assert!(PreparedDeploymentIntent::restore(&record, &publication).is_ok());
}

#[test]
fn intent_rebinding_rejects_changed_owner_generation_route_and_signed_fields() {
    let (publication, signed, context) = fixture();
    let prepared = PreparedDeploymentIntent::prepare_direct(
        &publication,
        signed.unsigned().clone(),
        context.clone(),
        1000,
    )
    .unwrap();
    let changes: Vec<fn(&mut PreparationContext)> = vec![
        |v| v.participant_epoch += 1,
        |v| v.wallet_binding_epoch += 1,
        |v| v.participant_id = "foreign".into(),
        |v| v.privacy_domain_id = "foreign".into(),
        |v| v.actor_subject_id = "foreign".into(),
        |v| v.sender = [7; 20],
        |v| v.workload_binding_id = None,
        |v| v.wallet_binding_id = "different".into(),
        |v| v.target_runtime_id = "different".into(),
        |v| v.chain_environment_id = "different".into(),
        |v| v.policy_generation_digest = Digest::of("new"),
        |v| v.authority_digest = Digest::of("new"),
        |v| v.policy_decision_digest = Digest::of("new"),
        |v| v.entitlement_envelope_digest = Digest::of("new"),
        |v| v.routing_constraint_digest = Digest::of("new"),
        |v| v.approval_set_digest = Digest::of("new"),
        |v| v.expires_at_ms += 1,
    ];
    for change in changes {
        let mut current = context.clone();
        change(&mut current);
        assert!(
            prepared
                .rebind_signed(&publication, &current, &signed, 1500)
                .is_err()
        );
    }
    for changed in [
        test_transaction_to(10, 2, None, INIT),
        test_transaction_to(9, 3, None, INIT),
        test_transaction_to(9, 2, Some([1; 20]), INIT),
        test_transaction_to(9, 2, None, &[0x60, 1]),
    ] {
        assert!(
            prepared
                .rebind_signed(&publication, &context, &changed, 1500)
                .is_err()
        );
    }
    let mut substituted = publication.clone();
    substituted.publication_operation_id = "018f0000-0000-7000-8000-000000000999".into();
    assert!(
        prepared
            .rebind_signed(&substituted, &context, &signed, 1500)
            .is_err()
    );
}

#[test]
fn intent_restore_rejects_tampering_expiry_and_other_creation_profiles() {
    let (publication, signed, context) = fixture();
    let prepared = PreparedDeploymentIntent::prepare_direct(
        &publication,
        signed.unsigned().clone(),
        context.clone(),
        1000,
    )
    .unwrap();
    let record: serde_json::Value =
        serde_json::from_slice(&prepared.record_bytes().unwrap()).unwrap();
    for (path, value) in [
        ("/schemaVersion", serde_json::json!("other")),
        ("/signingHash", serde_json::json!(hex(&[0; 32]))),
        ("/intent/nonce", serde_json::json!("10")),
        ("/intent/participantEpoch", serde_json::json!(2)),
        (
            "/intent/semanticDigest",
            serde_json::json!(Digest::of("bad").as_str()),
        ),
        ("/intent/destination", serde_json::json!(hex(&[1; 20]))),
    ] {
        let mut tampered = record.clone();
        *tampered.pointer_mut(path).unwrap() = value;
        assert!(
            PreparedDeploymentIntent::restore(
                &serde_json::to_vec(&tampered).unwrap(),
                &publication
            )
            .is_err()
        );
    }
    let mut injected = record;
    injected["ready"] = serde_json::json!(true);
    assert!(
        PreparedDeploymentIntent::restore(&serde_json::to_vec(&injected).unwrap(), &publication)
            .is_err()
    );
    for now in [0, 999, 2000] {
        assert!(
            PreparedDeploymentIntent::prepare_direct(
                &publication,
                signed.unsigned().clone(),
                context.clone(),
                now
            )
            .is_err()
        );
    }
    let mut overlong = context.clone();
    overlong.expires_at_ms = 301_001;
    assert!(
        PreparedDeploymentIntent::prepare_direct(
            &publication,
            signed.unsigned().clone(),
            overlong,
            1000
        )
        .is_err()
    );
    let factory = super::simulation_tests::input("CREATE2")
        .deployments
        .remove(0);
    assert!(
        PreparedDeploymentIntent::prepare_direct(
            &factory,
            signed.unsigned().clone(),
            context,
            1000
        )
        .is_err()
    );
}
