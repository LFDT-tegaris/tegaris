//! Capability/byte substitution and durable replay at the real Broker/journal join.
use super::*;
use crate::tests::{bindings, decision, digest, request};
use pc_runtime_types::{
    ContractInvocation, PURPOSE_BROKER_CAPABILITY_V1, PurposeSigner, RequestClass,
};
use sha3::{Digest as _, Keccak256};
use std::{fs, path::PathBuf};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("openpc-submission-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn broker(&self) -> SubmissionBroker {
        SubmissionBroker::open(broker(), "target-1", &self.0).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn signer() -> PurposeSigner {
    PurposeSigner::from_secret_bytes(PURPOSE_BROKER_CAPABILITY_V1, [9; 32]).unwrap()
}
fn broker() -> Arc<BrokerService> {
    Arc::new(BrokerService::new(&signer().verifier().sec1_bytes(), 8).unwrap())
}
fn transaction(nonce: u8, fee: u8) -> SignedTransaction {
    transaction_for(nonce, fee, false)
}
fn transaction_for(nonce: u8, fee: u8, direct: bool) -> SignedTransaction {
    transaction_with_value(nonce, fee, direct, 0)
}
fn transaction_with_value(nonce: u8, fee: u8, direct: bool, value: u8) -> SignedTransaction {
    fn list(payload: &[u8]) -> Vec<u8> {
        let mut encoded = if payload.len() < 56 {
            vec![0xc0 + payload.len() as u8]
        } else {
            vec![0xf8, payload.len() as u8]
        };
        encoded.extend(payload);
        encoded
    }
    assert!((1..128).contains(&nonce) && (1..128).contains(&fee));
    let key = k256::ecdsa::SigningKey::from_bytes((&[0x46; 32]).into()).unwrap();
    let mut fields = vec![1, nonce, 1, fee, 0x83, 1, 0x86, 0xa0];
    if direct {
        fields.push(0x80);
    } else {
        fields.push(0x94);
        fields.extend([1; 20]);
    }
    assert!(value < 128);
    fields.extend([
        if value == 0 { 0x80 } else { value },
        0x84,
        0x12,
        0x34,
        0x56,
        0x78,
        0xc0,
    ]);
    let mut unsigned = vec![2];
    unsigned.extend(list(&fields));
    let (signature, parity) = key.sign_prehash_recoverable(&Keccak256::digest(&unsigned));
    fields.push(if parity.to_byte() == 0 { 0x80 } else { 1 });
    for scalar in [signature.r().to_bytes(), signature.s().to_bytes()] {
        let start = scalar.iter().position(|b| *b != 0).unwrap();
        let bytes = &scalar[start..];
        if bytes.len() != 1 || bytes[0] >= 0x80 {
            fields.push(0x80 + bytes.len() as u8);
        }
        fields.extend(bytes);
    }
    let mut raw = vec![2];
    raw.extend(list(&fields));
    SignedTransaction::decode(&raw).unwrap()
}
fn admitted_request(
    tx: &SignedTransaction,
    capability: &str,
) -> (RuntimeRequest, RuntimeDecision, SubmissionAdmission) {
    let mut request = request(RequestClass::Write);
    request.params_digest = governed_write::submission_params_digest(tx).unwrap();
    request.deployment =
        tx.destination()
            .is_none()
            .then(|| pc_runtime_types::DeploymentInvocation {
                deployment_policy_id: "binding-1".into(),
                intent_digest: digest("intent"),
            });
    request.invocation = tx.destination().map(|address| ContractInvocation {
        chain_id: tx.chain_id().to_string(),
        network_id: "1".into(),
        genesis_digest: digest("genesis"),
        contract_address: *address,
        proxy_address: None,
        implementation_address: None,
        code_digest: digest("code"),
        implementation_code_digest: None,
        abi_digest: digest("abi"),
        calldata: tx.data().to_vec(),
        nested_calls: vec![],
    });
    request.request_digest = request.computed_digest().unwrap();
    let mut decision = decision(RequestClass::Write, capability);
    let mut claims = decision.capability.take().unwrap().claims;
    claims.request_digest = request.request_digest.clone();
    decision.capability = Some(signer().sign(claims).unwrap());
    let admission = SubmissionAdmission {
        owner: SubmissionOwner {
            participant_id: "participant-1".into(),
            privacy_domain_id: "privacy-1".into(),
            actor_principal_id: "actor-1".into(),
            workload_id: "workload-1".into(),
        },
        target_runtime_id: "target-1".into(),
        runtime_binding_id: "binding-1".into(),
        risk_class: Some("LOW".into()),
        preflight_witness_digest: None,
        cigl_post_mine: None,
        chain: None,
        workload_peer_binding_digest: Some(pc_runtime_types::Digest::of("verified original peer")),
        wallet_binding_id: "wallet-1".into(),
        wallet_binding_epoch: 1,
        capability_id: capability.into(),
        decision_id: decision.decision_id.clone(),
        decision_digest: decision.decision_digest.clone(),
        identity_vector_digest: digest("identity"),
        capsule_digest: digest("generation"),
        contract_set_manifest_digest: digest("contracts"),
        invocation_profile_digest: digest("invocation"),
        capability_registry_digest: digest("capabilities"),
        request_form_registry_digest: digest("forms"),
        error_registry_digest: digest("errors"),
        policy_generation_digest: digest("policy"),
        transaction_policy_digest: digest("transactions"),
        route_witness_set_digest: digest("witnesses"),
        evidence_admission_profile_digest: digest("evidence"),
        prepared_intent_digest: None,
        contract_address: tx.destination().copied(),
        selector: tx.destination().map(|_| tx.data()[..4].try_into().unwrap()),
        deployment: None,
        admitted_at_ms: 110,
        valid_until_ms: 150,
    };
    (request, decision, admission)
}

// Reservation contents are a component fixture. This proves only Broker's
// exact identity join, never that the global coordinator approved a handoff.
fn deployment_admission(tx: &SignedTransaction, admission: &mut SubmissionAdmission) {
    use openpc_multi_rpc::{
        deployment::{DeploymentArtifact, DeploymentConstraints, DeploymentRoute},
        submission_operation::{DeploymentSubmission, SubmissionChain},
    };
    admission.preflight_witness_digest = Some(digest("actual preflight fixture"));
    admission.chain = Some(SubmissionChain {
        chain_environment_id: "chain-1".into(),
        network_id: "test".into(),
        genesis_digest: digest("genesis"),
    });
    admission.prepared_intent_digest = Some(digest("intent"));
    admission.deployment = Some(DeploymentSubmission {
        predecessor_command_id: None,
        native_value_authorization_digest: None,
        dispatch: None,
        transaction: None,
        command_id: uuid::Uuid::now_v7().to_string(),
        attempt_id: uuid::Uuid::now_v7().to_string(),
        deployment_policy_id: admission.runtime_binding_id.clone(),
        intent_id: "intent-1".into(),
        intent_digest: digest("intent"),
        preparation_digest: digest("preparation"),
        publication_digest: digest("publication"),
        reservation_binding_digest: digest("reserved address identity"),
        preparation_expires_at_ms: 150,
        constraints: DeploymentConstraints {
            chain_id: tx.chain_id(),
            sender: *tx.signer(),
            signing_hash: *tx.signing_hash(),
            profile_digest: digest("profile"),
            artifact: DeploymentArtifact {
                init_code_hash: Keccak256::digest(tx.data()).into(),
                runtime_code_hash: Keccak256::digest([0]).into(),
            },
            route: DeploymentRoute::DirectCreate {
                expected_address: tx.creation_address().unwrap(),
            },
        },
    });
}

#[test]
fn deployment_retains_the_reserved_attempt_without_granting_send_authority() {
    for value in [0, 10] {
        let directory = Directory::new();
        let owner = directory.broker();
        let tx = transaction_with_value(9, 2, true, value);
        let (request, decision, mut admission) = admitted_request(&tx, "deployment-capability");
        deployment_admission(&tx, &mut admission);
        let prepare = |owner: &SubmissionBroker, decision: &RuntimeDecision, admission| {
            owner.prepare(
                &request,
                &bindings(),
                decision,
                &tx,
                admission,
                "instance-1",
                &digest("anchor"),
                "018f47a5-4a58-7b21-8f3a-222222222222",
                110,
            )
        };
        if value != 0 {
            assert!(prepare(&owner, &decision, admission.clone()).is_err());
            let deployment = admission.deployment.as_mut().unwrap();
            deployment.native_value_authorization_digest =
                Some(digest("verified one-use Native Value handoff"));
            assert!(prepare(&owner, &decision, admission.clone()).is_err());
            admission.deployment.as_mut().unwrap().transaction = Some((&tx).into());
            for change in [
                |a: &mut SubmissionAdmission| {
                    a.deployment
                        .as_mut()
                        .unwrap()
                        .native_value_authorization_digest = None
                },
                |a: &mut SubmissionAdmission| {
                    a.deployment
                        .as_mut()
                        .unwrap()
                        .native_value_authorization_digest = Some(Digest::of([]))
                },
                |a: &mut SubmissionAdmission| {
                    a.deployment
                        .as_mut()
                        .unwrap()
                        .transaction
                        .as_mut()
                        .unwrap()
                        .value = [0; 32]
                },
            ] {
                let mut altered = admission.clone();
                change(&mut altered);
                assert!(prepare(&owner, &decision, altered).is_err());
            }
        }
        let mut without_capability = decision.clone();
        without_capability.capability = None;
        assert!(prepare(&owner, &without_capability, admission.clone()).is_err());
        for change in [
            |a: &mut SubmissionAdmission| {
                a.deployment.as_mut().unwrap().command_id = "invalid".into()
            },
            |a: &mut SubmissionAdmission| {
                a.deployment.as_mut().unwrap().attempt_id = "invalid".into()
            },
            |a: &mut SubmissionAdmission| {
                a.deployment.as_mut().unwrap().constraints.sender = [2; 20]
            },
            |a: &mut SubmissionAdmission| a.prepared_intent_digest = Some(digest("other intent")),
        ] {
            let mut altered = admission.clone();
            change(&mut altered);
            assert!(prepare(&owner, &decision, altered).is_err());
        }
        let prepared = prepare(&owner, &decision, admission.clone()).unwrap();
        let reserved = admission.deployment.as_ref().unwrap();
        assert_eq!(prepared.command().command_id, reserved.command_id);
        assert_eq!(prepared.command().attempt_id, reserved.attempt_id);
        assert!(prepare(&owner, &decision, admission.clone()).is_err());
        drop(prepared);
        drop(owner);
        let reopened = directory.broker();
        let (command, retained, state) = reopened
            .lookup(&reserved.command_id, &admission.owner)
            .unwrap()
            .unwrap();
        assert_eq!(command.attempt_id, reserved.attempt_id);
        assert_eq!(retained, admission);
        assert_eq!(state, JournalState::FailedPreStart);
        let status = reopened
            .status(&reserved.command_id, &admission.owner)
            .unwrap()
            .unwrap();
        assert!(!status.automatic_attempt_started);
        assert!(status.automatic_resubmission_prohibited);
        // Neither the original reservation nor fresh IDs authorize replay.
        assert!(prepare(&reopened, &decision, admission.clone()).is_err());
        let mut other = admission;
        deployment_admission(&tx, &mut other);
        assert!(prepare(&reopened, &decision, other).is_err());
    }
}

fn prepare(
    owner: &SubmissionBroker,
    tx: &SignedTransaction,
    capability: &str,
) -> RuntimeResult<PreparedSubmission> {
    let (request, decision, admission) = admitted_request(tx, capability);
    owner.prepare(
        &request,
        &bindings(),
        &decision,
        tx,
        admission,
        "instance-1",
        &digest("anchor"),
        "018f47a5-4a58-7b21-8f3a-222222222222",
        110,
    )
}

#[test]
fn submission_binds_signed_bytes_and_live_context_before_durable_consumption() {
    let directory = Directory::new();
    let owner = directory.broker();
    let tx = transaction(9, 2);
    let (request, decision, admission) = admitted_request(&tx, "cap-1");
    let altered = transaction(9, 3); // Same actor, nonce, target and calldata; different signed fee.
    assert!(matches!(
        owner.prepare(
            &request,
            &bindings(),
            &decision,
            &altered,
            admission.clone(),
            "instance-1",
            &digest("anchor"),
            "018f47a5-4a58-7b21-8f3a-222222222222",
            110
        ),
        Err(RuntimeError::InvalidAuthorization)
    ));
    for change in [
        |a: &mut SubmissionAdmission| a.owner.participant_id = "foreign".into(),
        |a: &mut SubmissionAdmission| a.owner.privacy_domain_id = "foreign".into(),
        |a: &mut SubmissionAdmission| a.owner.workload_id = "foreign".into(),
        |a: &mut SubmissionAdmission| a.target_runtime_id = "foreign".into(),
        |a: &mut SubmissionAdmission| a.capability_id = "foreign".into(),
        |a: &mut SubmissionAdmission| a.decision_digest = digest("foreign"),
        |a: &mut SubmissionAdmission| a.valid_until_ms = 151,
        |a: &mut SubmissionAdmission| a.contract_address = Some([2; 20]),
    ] {
        let mut changed = admission.clone();
        change(&mut changed);
        assert!(matches!(
            owner.prepare(
                &request,
                &bindings(),
                &decision,
                &tx,
                changed,
                "instance-1",
                &digest("anchor"),
                "018f47a5-4a58-7b21-8f3a-222222222222",
                110
            ),
            Err(RuntimeError::InvalidAuthorization)
        ));
    }
    let mut foreign = bindings();
    foreign.provider_profile_digest = digest("foreign");
    assert!(matches!(
        owner.prepare(
            &request,
            &foreign,
            &decision,
            &tx,
            admission.clone(),
            "instance-1",
            &digest("anchor"),
            "018f47a5-4a58-7b21-8f3a-222222222222",
            110
        ),
        Err(RuntimeError::InvalidAuthorization)
    ));
    // All rejected inputs leave the capability and signed identity available.
    let prepared = prepare(&owner, &tx, "cap-1").unwrap();
    assert_eq!(
        owner
            .lookup(&prepared.command().command_id, &admission.owner)
            .unwrap()
            .unwrap()
            .2,
        JournalState::Prepared
    );
}

#[test]
fn restart_closes_a_prepared_operation_without_inventing_an_attempt() {
    let directory = Directory::new();
    let owner = directory.broker();
    let tx = transaction(9, 2);
    let (_, _, admission) = admitted_request(&tx, "abandoned");
    let prepared = prepare(&owner, &tx, "abandoned").unwrap();
    let id = prepared.command().command_id.clone();
    drop(prepared);
    drop(owner);
    let reopened = directory.broker();
    let status = reopened.status(&id, &admission.owner).unwrap().unwrap();
    assert_eq!(
        status.submission,
        openpc_multi_rpc::submission_status::SubmissionDisposition::DefinitelyRejected
    );
    assert!(!status.automatic_attempt_started);
    assert!(status.automatic_resubmission_prohibited);
    assert!(prepare(&reopened, &tx, "new capability").is_err());
}

#[test]
fn submission_replay_and_nonce_custody_survive_restart_and_scope_readback() {
    let directory = Directory::new();
    let owner = directory.broker();
    let tx = transaction(9, 2);
    let (_, _, admission) = admitted_request(&tx, "cap-1");
    let prepared = prepare(&owner, &tx, "cap-1").unwrap();
    let id = prepared.command().command_id.clone();
    let view = owner.view(&id, &admission.owner).unwrap().unwrap();
    assert_eq!(view.operation_id, format!("urn:openpc:operation:{id}"));
    assert_eq!(view.state, "PREPARED");
    assert_eq!(view.truth_state, "UNKNOWN");
    assert_eq!(view.attempt_id, prepared.command().attempt_id);
    assert_eq!(
        view.signed_transaction_hash,
        prepared.command().request_or_transaction_hash
    );
    assert!(matches!(
        prepare(&owner, &transaction(10, 2), "cap-1"),
        Err(RuntimeError::Replay)
    ));
    assert!(prepare(&owner, &transaction(9, 3), "cap-2").is_err());
    for change in [
        |o: &mut SubmissionOwner| o.participant_id = "foreign".into(),
        |o: &mut SubmissionOwner| o.privacy_domain_id = "foreign".into(),
        |o: &mut SubmissionOwner| o.actor_principal_id = "foreign".into(),
        |o: &mut SubmissionOwner| o.workload_id = "foreign".into(),
    ] {
        let mut foreign = admission.owner.clone();
        change(&mut foreign);
        assert!(owner.lookup(&id, &foreign).unwrap().is_none());
        assert!(owner.view(&id, &foreign).unwrap().is_none());
        assert!(owner.lookup_transaction(&tx, &foreign).unwrap().is_none());
    }
    owner.reject(prepared, &RuntimeError::Denied).unwrap();
    drop(owner);
    assert!(matches!(
        SubmissionBroker::open(broker(), "target-2", &directory.0),
        Err(RuntimeError::TargetIdentity)
    ));
    let reopened = directory.broker();
    let (command, retained, state) = reopened.lookup(&id, &admission.owner).unwrap().unwrap();
    assert_eq!(retained, admission);
    assert_eq!(state, JournalState::FailedPreStart);
    let status = reopened.status(&id, &admission.owner).unwrap().unwrap();
    assert_eq!(
        status.submission,
        openpc_multi_rpc::submission_status::SubmissionDisposition::DefinitelyRejected
    );
    assert!(!status.automatic_attempt_started);
    assert!(status.automatic_resubmission_prohibited);
    assert!(!status.provider_acknowledged);
    assert_eq!(
        status.observation,
        openpc_multi_rpc::submission_status::ChainObservation::NotObserved
    );
    assert_eq!(
        status.execution,
        openpc_multi_rpc::submission_status::ExecutionOutcome::Unknown
    );
    assert_eq!(command.command_id, id);
    let rejected = reopened.view(&id, &admission.owner).unwrap().unwrap();
    assert_eq!(rejected.state, "REJECTED");
    assert_eq!(rejected.truth_state, "DENIED");
    assert_ne!(rejected.evidence_digest, view.evidence_digest);
    assert_eq!(rejected.attempt_id, view.attempt_id);
    assert_eq!(
        reopened
            .repeated_submission_view(
                &tx,
                &admission.owner.participant_id,
                &admission.owner.privacy_domain_id,
                &admission.owner.workload_id,
                admission.workload_peer_binding_digest.as_ref().unwrap()
            )
            .unwrap(),
        Some(rejected)
    );
    assert!(prepare(&reopened, &tx, "cap-3").is_err());
    assert!(matches!(
        prepare(&reopened, &transaction(10, 2), "cap-1"),
        Err(RuntimeError::Replay)
    ));
    // A provably pre-start failure releases the nonce, while retaining exact-byte replay history.
    prepare(&reopened, &transaction(9, 3), "cap-4").unwrap();
}
