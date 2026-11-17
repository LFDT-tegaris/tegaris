//! Decoder component evidence; fixture custody is not public workflow acceptance.
use super::*;
use openpc_multi_rpc::{
    deployment::intent::PreparationContext, signed_transaction::SignedTransaction,
};
use pc_policy_core::{deployment_policy::*, invocation::*};
use pc_runtime_types::{PurposeSigner, canonical_bytes};
use serde_json::{Value, json};
use sha3::{Digest as _, Keccak256};

fn hex(value: &[u8]) -> String {
    format!(
        "0x{}",
        value.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
fn tagged(value: &Value) -> String {
    format!(
        "sha256:{}",
        Digest::of(canonical_bytes(value).unwrap()).as_str()
    )
}

#[test]
fn managed_deployment_decoder_requires_exact_pinned_handoff_and_keeps_rpc_creation_closed() {
    let signed = "0x02f85e827a69090102830186a080808d6001600c60003960016000f300c001a076645ce5742da4093da606f82fdde171ea196fb1c6b133d83c118f05d6ef8b68a01e494cfed272b211acd4c2e3d82f932e042a63820f5f9ca2c6c5111df28777ad";
    let transaction = SignedTransaction::decode(&hex_bytes(signed).unwrap()).unwrap();
    let participant = "018f0000-0000-7000-8000-000000000101";
    let privacy = "018f0000-0000-7000-8000-000000000201";
    let policy_id = "018f0000-0000-7000-8000-000000000401";
    let d = format!("sha256:{}", Digest::of("fixture").as_str());
    let definition = json!({"schemaVersion":"1.0.0", "profileId":"reference:direct", "profileVersion":"1.0.0",
        "assuranceLevel":"A0", "creationEvidence":"COMPLETE_SINGLE_CREATION_CALL_AND_OPCODE_V1",
        "chainId":"31337", "networkId":"local", "genesisDigest":d,
        "abiArtifactId":"urn:openpc:resource:018f0000-0000-7000-8000-000000000501",
        "artifact":{"mode":"EXACT_INIT_CODE", "initCode":hex(transaction.data()), "runtimeCodeHash":hex(&Keccak256::digest([0]))},
        "route":{"mechanism":"TRANSACTION_CREATE"}, "allowedSenders":[hex(transaction.signer())],
        "requiredRoles":["deployer"], "approvalRequirement":"NONE", "webauthnRequired":false,
        "expiresAt":"2030-01-01T00:00:00.000Z",
        "transactionPolicy":{"version":1,"allowedTransactionTypes":[2],"maximumValue":hex(&[0;32]),
            "maximumGasLimit":"100000", "maximumFeePerGas":format!("0x{}02", "00".repeat(31)),
            "maximumPriorityFeePerGas":format!("0x{}01", "00".repeat(31)),
            "maximumRawTransactionBytes":131072,"maximumCalldataBytes":32768,
            "maximumAccessListAddresses":128,"maximumAccessListStorageKeys":1024}});
    let init_hash = hex(&Keccak256::digest(transaction.data()));
    let publication: AdmittedDeploymentPolicy = serde_json::from_value(json!({
        "deploymentPolicyId":policy_id, "participantId":participant, "privacyDomainId":privacy,
        "definition":definition,"definitionDigest":tagged(&definition),
        "initCodeHash":init_hash,"artifactDigest":tagged(&json!({"mode":"EXACT_INIT_CODE",
            "initCodeHash":init_hash,"runtimeCodeHash":definition["artifact"]["runtimeCodeHash"]})),
        "abiDigest":d,"publicationOperationId":"018f0000-0000-7000-8000-000000000601",
        "publicationAuthorityDigest":d,"factoryBinding":null}))
    .unwrap();
    let configuration = ActiveInvocationConfigurationV1 {
        workload_scope: None,
        visibility_resources: Vec::new(),
        schema_version: "1.0".into(),
        assets: vec![],
        resource_artifacts: vec![],
        deployment_policies: vec![ConfiguredDeploymentPolicy {
            publication: publication.clone(),
            workload_id: "workload".into(),
        }],
    };
    let generation = ActiveInvocationPolicyGenerationV1 {
        visibility_policies: Vec::new(),
        fact_conditions: Vec::new(),
        indexer_policies: Vec::new(),
        schema_version: "1.0".into(),
        root_asset_ids: vec![],
        assets: vec![],
        required_facts: vec![],
        deployment_policies: vec![DeploymentPolicyReference {
            deployment_policy_id: policy_id.into(),
            definition_digest: publication.definition_digest.clone(),
        }],
        rpc_policies: vec![],
    };
    let configuration = encode_active_invocation_configuration(&configuration).unwrap();
    let generation = encode_active_invocation_policy_generation(&generation).unwrap();
    let policy_digest = Digest::of("generation");
    let policies = ValidatedDeploymentPolicy::load_active(
        &configuration,
        &Digest::of(&configuration),
        &generation,
        &Digest::of(&generation),
        &ActiveInvocationScope {
            policy_generation_digest: &policy_digest,
            tenant_id: participant,
            privacy_domain_id: privacy,
            workload_id: "workload",
        },
    )
    .unwrap();
    let context = PreparationContext {
        native_value_authorization_bytes: None,
        intent_id: "018f0000-0000-7000-8000-000000000701".into(),
        participant_id: participant.into(),
        privacy_domain_id: privacy.into(),
        participant_epoch: 1,
        actor_subject_id: "executor".into(),
        workload_binding_id: Some("workload".into()),
        wallet_binding_id: "wallet".into(),
        wallet_binding_epoch: 1,
        sender: *transaction.signer(),
        chain_environment_id: "chain".into(),
        target_runtime_id: "018f0000-0000-7000-8000-000000000301".into(),
        policy_generation_digest: policy_digest,
        authority_digest: Digest::of("preparation authorization"),
        policy_decision_digest: Digest::of("decision"),
        entitlement_envelope_digest: Digest::of("envelope"),
        routing_constraint_digest: Digest::of("route"),
        approval_set_digest: Digest::of("none"),
        issued_at_ms: 1000,
        expires_at_ms: 2000,
    };
    let prepared = PreparedDeploymentIntent::prepare_direct(
        &publication,
        transaction.unsigned().clone(),
        context,
        1000,
    )
    .unwrap();
    let command_id = "018f0000-0000-7000-8000-000000000801";
    let attempt_id = "018f0000-0000-7000-8000-000000000901";
    let binding = prepared
        .reservation_binding(&publication, &transaction, command_id, attempt_id, 1100)
        .unwrap();
    let signer = PurposeSigner::from_secret_bytes(
        openpc_multi_rpc::deployment::custody::HANDOFF_PURPOSE,
        [22; 32],
    )
    .unwrap();
    let handoff = signer
        .sign(DeploymentHandoff {
            predecessor_command_id: None,
            command_id: command_id.into(),
            attempt_id: attempt_id.into(),
            reservation_binding_digest: Digest::of(canonical_bytes(&binding).unwrap()),
            publication_digest: Digest::of(
                canonical_bytes(&serde_json::to_value(&publication).unwrap()).unwrap(),
            ),
            candidate_digest: Digest::of("candidate"),
            authorization_evidence_digest: Digest::of("authorization"),
            workload_peer_binding_digest: Digest::of("peer"),
            identity_vector_digest: Digest::of("vector"),
            handoff_at_ms: 1100,
            expires_at_ms: 2000,
        })
        .unwrap();
    let input = json!({"requestId":1,"deploymentPolicyId":policy_id,"preparationBytes":hex(&prepared.record_bytes().unwrap()),"signedTransaction":signed,"handoff":handoff});
    let limits = RequestDecodeLimits {
        maximum_request_bytes: 4 * 1024 * 1024,
        maximum_response_bytes: 4096,
        timeout_ms: 500,
        block_selector: "0x1",
    };
    let decode = |value: &Value, now| {
        DecodedProtectedRequest::decode_deployment(
            &serde_json::to_vec(value).unwrap(),
            &policies,
            &signer.verifier().sec1_bytes(),
            limits,
            now,
        )
    };
    let decoded = decode(&input, 1101).unwrap();
    assert!(decoded.request().invocation.is_none());
    assert_eq!(
        decoded.request().deployment.as_ref().unwrap().intent_digest,
        *prepared.intent_digest()
    );
    assert_eq!(
        decoded
            .deployment()
            .unwrap()
            .handoff()
            .submission()
            .command_id,
        command_id
    );
    assert_eq!(decoded.signed_transaction(), Some(&transaction));
    assert!(DecodedProtectedRequest::decode(decoded.body(), &[], limits, 1101).is_err());
    assert!(decode(&input, 2000).is_err());
    assert_eq!(
        deployment_rpc_body(
            &serde_json::to_vec(&input).unwrap(),
            limits.maximum_request_bytes
        )
        .unwrap(),
        decoded.body()
    );
    for counterexample in 0..5 {
        let mut changed = input.clone();
        match counterexample {
            0 => changed["deploymentPolicyId"] = json!(command_id),
            1 => changed["handoff"]["claims"]["command_id"] = json!(attempt_id),
            2 => changed["handoff"]["ready"] = json!(true),
            3 => changed["signedTransaction"] = json!("0x02abcd"),
            _ => changed["authority"] = json!("APPROVED"),
        }
        assert!(decode(&changed, 1101).is_err());
    }
}
