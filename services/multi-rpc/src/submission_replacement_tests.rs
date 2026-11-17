//! Journal component fixtures, including protocol evidence. The authenticated
//! API/runtime vertical separately exercises the real observer and authority.
use super::*;
use crate::provider_connection::{ConnectionRecord, ConnectionStatus};
use crate::{
    journal::tests::{signed_command, submission_admission, temp_path},
    signed_transaction::test_transaction_with_fees,
};
use pc_policy_core::transaction_policy::TransactionPolicyV1;

fn policy() -> TransactionPolicyV1 {
    TransactionPolicyV1 {
        version: 1,
        allowed_transaction_types: vec![0, 1, 2],
        maximum_value: [255; 32],
        maximum_gas_limit: 100_000,
        maximum_fee_per_gas: [255; 32],
        maximum_priority_fee_per_gas: [255; 32],
        maximum_raw_transaction_bytes: 131_072,
        maximum_calldata_bytes: 32_768,
        maximum_access_list_addresses: 128,
        maximum_access_list_storage_keys: 1024,
    }
}

fn connection(now: u64) -> ConnectionRecord {
    ConnectionRecord {
        provider_id: "provider-profile-a".into(),
        endpoint_id: "endpoint-a".into(),
        endpoint_generation: 1,
        resolution_generation: 1,
        endpoint_content_digest: Digest::of("endpoint"),
        resolution_content_digest: Digest::of("resolution"),
        dispatcher_generation: 1,
        configuration_digest: Digest::of("config"),
        valid_until_ms: now + 30_000,
        status: ConnectionStatus::Prepared,
    }
}
fn pending(
    target: &ObservationTarget,
    connection: &ConnectionRecord,
    now: u64,
) -> VerifiedObservation {
    VerifiedObservation {
        evidence: ObservationEvidence {
            version: Some(2),
            target_head: target.head.clone(),
            operation_id: target.command.command_id.clone(),
            attempt_id: target.command.attempt_id.clone(),
            transaction_hash: target.signed.transaction_hash,
            connection: connection.clone(),
            route_witness_digest: Digest::of("verified recovery witness"),
            state: Some(ObservationState {
                cigl_post_mine: None,
                observation: ChainObservation::MempoolObserved,
                execution: ExecutionOutcome::Unknown,
                block: None,
                creation: None,
            }),
            completed_at_ms: now,
            valid_until_ms: now + 5000,
            exchanges: vec![(Digest::of("exact request"), Digest::of("exact response"))],
        },
    }
}
fn transaction(
    fee: u64,
    priority: u64,
    data: &[u8],
) -> crate::signed_transaction::SignedTransaction {
    test_transaction_with_fees(9, fee, priority, Some([0x35; 20]), data, &[0; 32])
}

#[test]
fn prepared_fee_bump_denies_start_after_predecessor_inclusion() {
    let path = temp_path("fee-bump-predecessor-race");
    let now = crate::provider_connection::now_ms().unwrap();
    let connection = connection(now);
    let policy = policy();
    let old = transaction(2, 1, &[0x12, 0x34, 0x56, 0x78]);
    let new = transaction(4, 2, old.data());
    let mut admission = submission_admission();
    admission.admitted_at_ms = now;
    admission.valid_until_ms = now + 5000;
    admission.transaction_policy_digest = Digest::of(canonical_bytes(&policy).unwrap());
    admission.chain = Some(crate::submission_operation::SubmissionChain {
        chain_environment_id: "chain-1".into(),
        network_id: "network-1".into(),
        genesis_digest: Digest::of("genesis"),
    });
    let mut journal = WriteJournal::create_new(&path).unwrap();
    let original = uuid::Uuid::now_v7().to_string();
    let prepared = journal
        .prepare_submission(signed_command(&original, &old), &old, admission.clone())
        .unwrap();
    let started = journal
        .mark_started(prepared, "original-start".into())
        .unwrap();
    journal
        .mark_acknowledged(&started, "original-ack".into())
        .unwrap();
    let target = journal.observation_target(&original).unwrap().unwrap();
    admission.capability_id = "replacement".into();
    let next = uuid::Uuid::now_v7().to_string();
    let prepared = journal
        .prepare_replacement(
            signed_command(&next, &new),
            &new,
            admission.clone(),
            &target,
            pending(&target, &connection, now),
            &connection,
            &policy,
        )
        .unwrap();
    let mut included = pending(&target, &connection, now);
    included.evidence.state = Some(ObservationState {
        cigl_post_mine: None,
        observation: ChainObservation::Included,
        execution: ExecutionOutcome::Success,
        block: Some(ObservedBlock {
            number: 1,
            hash: Digest::of("original block"),
        }),
        creation: None,
    });
    journal.commit_observation(&target, included, now).unwrap();
    assert!(journal.validate_signed_prepared(&prepared, &new).is_err());
    assert!(
        journal
            .mark_started(prepared, "must-not-start".into())
            .is_err()
    );
    assert!(
        !journal
            .submission_boundary(&next, &admission.owner)
            .unwrap()
            .automatic_attempt_started
    );
    assert!(
        journal
            .replacement_successor(&original, &admission.owner)
            .is_some()
    );
    drop(journal);
    let mut journal = WriteJournal::open(&path).unwrap();
    journal.abandon_prepared_submissions().unwrap();
    assert_eq!(
        journal.submission(&next, &admission.owner).unwrap().2,
        JournalState::FailedPreStart
    );
    assert!(
        journal
            .replacement_successor(&original, &admission.owner)
            .is_some()
    );
    drop(journal);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn fee_bump_has_one_atomic_successor_with_exact_effect_authority_and_pending_proof() {
    fee_bump_custody(false);
}

#[test]
fn deployment_fee_bump_cannot_reopen_a_terminal_reorg() {
    fee_bump_custody(true);
}

fn fee_bump_custody(deployment: bool) {
    let path = temp_path("fee-bump-custody");
    let now = crate::provider_connection::now_ms().unwrap();
    let connection = connection(now);
    let policy = policy();
    let transaction = |fee, priority, data: &[u8]| {
        test_transaction_with_fees(
            9,
            fee,
            priority,
            (!deployment).then_some([0x35; 20]),
            data,
            &[0; 32],
        )
    };
    let old = transaction(2, 1, &[0x12, 0x34, 0x56, 0x78]);
    let new = transaction(4, 2, old.data());
    let mut admission = submission_admission();
    admission.admitted_at_ms = now;
    admission.valid_until_ms = now + 5000;
    admission.transaction_policy_digest = Digest::of(canonical_bytes(&policy).unwrap());
    admission.chain = Some(crate::submission_operation::SubmissionChain {
        chain_environment_id: "chain-1".into(),
        network_id: "network-1".into(),
        genesis_digest: Digest::of("genesis"),
    });
    let owner = admission.owner.clone();
    let mut journal = WriteJournal::create_new(&path).unwrap();
    let old_id = uuid::Uuid::now_v7().to_string();
    let original_command = signed_command(&old_id, &old);
    if deployment {
        use crate::deployment::{DeploymentArtifact, DeploymentConstraints, DeploymentRoute};
        use crate::submission_operation::DeploymentSubmission;
        admission.contract_address = None;
        admission.selector = None;
        admission.preflight_witness_digest = Some(Digest::of("deployment preflight"));
        admission.prepared_intent_digest = Some(Digest::of("original preparation"));
        admission.deployment = Some(DeploymentSubmission {
            predecessor_command_id: None,
            native_value_authorization_digest: None,
            dispatch: None,
            transaction: None,
            command_id: old_id.clone(),
            attempt_id: original_command.attempt_id.clone(),
            deployment_policy_id: admission.runtime_binding_id.clone(),
            intent_id: "original-intent".into(),
            intent_digest: admission.prepared_intent_digest.clone().unwrap(),
            preparation_digest: Digest::of("prepared record"),
            publication_digest: Digest::of("publication"),
            reservation_binding_digest: Digest::of("reservation"),
            preparation_expires_at_ms: admission.valid_until_ms,
            constraints: DeploymentConstraints {
                chain_id: old.chain_id(),
                sender: *old.signer(),
                signing_hash: *old.signing_hash(),
                profile_digest: Digest::of("deployment profile"),
                artifact: DeploymentArtifact {
                    init_code_hash: <sha3::Keccak256 as sha3::Digest>::digest(old.data()).into(),
                    runtime_code_hash: <sha3::Keccak256 as sha3::Digest>::digest([0]).into(),
                },
                route: DeploymentRoute::DirectCreate {
                    expected_address: old.creation_address().unwrap(),
                },
            },
        });
    }
    let handle = journal
        .prepare_submission(original_command, &old, admission.clone())
        .unwrap();
    let started = journal
        .mark_started(handle, "start-original".into())
        .unwrap();
    journal
        .mark_acknowledged(&started, "original-ack".into())
        .unwrap();
    let target = journal.observation_target(&old_id).unwrap().unwrap();
    admission.capability_id = "replacement-capability".into();
    admission.decision_id = "replacement-decision".into();
    let next_id = uuid::Uuid::now_v7().to_string();
    let command = signed_command(&next_id, &new);
    if let Some(deployment) = &mut admission.deployment {
        deployment.command_id.clone_from(&next_id);
        deployment.attempt_id.clone_from(&command.attempt_id);
        deployment.predecessor_command_id = Some(old_id.clone());
        deployment.constraints.signing_hash = *new.signing_hash();
    }

    for change in [
        "tenant", "privacy", "workload", "wallet", "epoch", "chain", "policy", "capsule", "profile",
    ] {
        let mut bad = admission.clone();
        match change {
            "tenant" => bad.owner.participant_id = "foreign".into(),
            "privacy" => bad.owner.privacy_domain_id = "foreign".into(),
            "workload" => bad.owner.workload_id = "foreign".into(),
            "wallet" => bad.wallet_binding_id = "other".into(),
            "epoch" => bad.wallet_binding_epoch += 1,
            "chain" => bad.chain.as_mut().unwrap().genesis_digest = Digest::of("other"),
            "policy" => bad.policy_generation_digest = Digest::of("other"),
            "capsule" => bad.capsule_digest = Digest::of("other"),
            _ => bad.invocation_profile_digest = Digest::of("other"),
        }
        assert!(
            journal
                .prepare_replacement(
                    command.clone(),
                    &new,
                    bad,
                    &target,
                    pending(&target, &connection, now),
                    &connection,
                    &policy
                )
                .is_err(),
            "{change}"
        );
    }
    for bad in [
        transaction(4, 1, old.data()),
        transaction(2, 2, old.data()),
        transaction(4, 2, &[0x12, 0x34, 0x56, 0x78, 1]),
    ] {
        assert!(
            journal
                .prepare_replacement(
                    signed_command(&next_id, &bad),
                    &bad,
                    admission.clone(),
                    &target,
                    pending(&target, &connection, now),
                    &connection,
                    &policy
                )
                .is_err()
        );
    }
    for bad_kind in [
        "missing",
        "included",
        "expired",
        "hash",
        "head",
        "connection",
    ] {
        let mut proof = pending(&target, &connection, now);
        match bad_kind {
            "missing" => proof.evidence.state = None,
            "included" => {
                proof.evidence.state.as_mut().unwrap().observation = ChainObservation::Included
            }
            "expired" => proof.evidence.valid_until_ms = now,
            "hash" => proof.evidence.transaction_hash[0] ^= 1,
            "head" => proof.evidence.target_head = Digest::of("stale head"),
            _ => proof.evidence.connection.dispatcher_generation += 1,
        }
        assert!(
            journal
                .prepare_replacement(
                    command.clone(),
                    &new,
                    admission.clone(),
                    &target,
                    proof,
                    &connection,
                    &policy
                )
                .is_err(),
            "{bad_kind}"
        );
    }
    let mut ceiling = policy.clone();
    ceiling.maximum_fee_per_gas = [0; 32];
    ceiling.maximum_priority_fee_per_gas = [0; 32];
    assert!(
        journal
            .prepare_replacement(
                command.clone(),
                &new,
                admission.clone(),
                &target,
                pending(&target, &connection, now),
                &connection,
                &ceiling
            )
            .is_err()
    );
    let prepared = journal
        .prepare_replacement(
            command.clone(),
            &new,
            admission.clone(),
            &target,
            pending(&target, &connection, now),
            &connection,
            &policy,
        )
        .unwrap();
    assert_eq!(
        journal.replacement_successor(&old_id, &owner),
        Some(command.clone())
    );
    let third = transaction(6, 3, old.data());
    let mut third_admission = admission.clone();
    third_admission.capability_id = "third".into();
    assert!(
        journal
            .prepare_replacement(
                signed_command(&uuid::Uuid::now_v7().to_string(), &third),
                &third,
                third_admission,
                &target,
                pending(&target, &connection, now),
                &connection,
                &policy
            )
            .is_err()
    );
    journal
        .mark_started(prepared, "replacement-start".into())
        .unwrap();
    drop(journal); // Lost response: STARTED must reopen as ambiguity, never resend.
    let mut journal = WriteJournal::open(&path).unwrap();
    assert_eq!(
        journal.submission_for_transaction(&new, &owner).unwrap().0,
        command
    );
    assert_eq!(
        journal.submission(&next_id, &owner).unwrap().2,
        JournalState::Ambiguous
    );
    assert_eq!(journal.pending_observations(64).unwrap().len(), 2);
    assert_eq!(
        journal.replacement_successor(&old_id, &owner),
        Some(command.clone())
    );
    // Exact successor inclusion/finality can be invalidated after restart,
    // while both hashes retain send custody and a third command stays denied.
    let original_projection = serde_json::to_vec(
        &journal
            .submission_projection_view(&old_id, &owner)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let successor = journal.observation_target(&next_id).unwrap().unwrap();
    let at = crate::provider_connection::now_ms().unwrap();
    let mut finality = pending(&successor, &connection, at);
    let block = ObservedBlock {
        number: 10,
        hash: Digest::of("canonical successor block"),
    };
    finality.evidence.state = Some(ObservationState {
        cigl_post_mine: None,
        observation: ChainObservation::Finalized,
        execution: ExecutionOutcome::Success,
        block: Some(block.clone()),
        creation: None,
    });
    journal
        .commit_observation(&successor, finality, at)
        .unwrap();
    assert_eq!(
        journal
            .submission_status(&old_id, &owner)
            .unwrap()
            .observation,
        ChainObservation::Superseded
    );
    assert_eq!(
        journal
            .submission_view(&old_id, &owner)
            .unwrap()
            .unwrap()
            .truth_state,
        "CONFLICTING"
    );
    drop(journal);
    let mut journal = WriteJournal::open(&path).unwrap();
    // Reopening after the successor changes must reproduce the same signed
    // predecessor input at its unchanged sequence, despite live supersession.
    assert_eq!(
        serde_json::to_vec(
            &journal
                .submission_projection_view(&old_id, &owner)
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        original_projection
    );
    let successor = journal.observation_target(&next_id).unwrap().unwrap();
    let mut reorg = pending(&successor, &connection, at);
    reorg.evidence.state = Some(ObservationState {
        cigl_post_mine: None,
        observation: ChainObservation::Reorged,
        execution: ExecutionOutcome::Unknown,
        block: Some(block),
        creation: None,
    });
    journal.commit_observation(&successor, reorg, at).unwrap();
    assert_eq!(
        serde_json::to_vec(
            &journal
                .submission_projection_view(&old_id, &owner)
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        original_projection
    );
    assert_ne!(
        journal
            .submission_status(&old_id, &owner)
            .unwrap()
            .observation,
        ChainObservation::Superseded
    );
    assert_eq!(
        journal
            .submission_status(&next_id, &owner)
            .unwrap()
            .observation,
        ChainObservation::Reorged
    );
    assert!(
        journal
            .submission_boundary(&next_id, &owner)
            .unwrap()
            .automatic_resubmission_prohibited
    );
    assert_eq!(
        journal.pending_observations(64).unwrap().len(),
        if deployment { 1 } else { 2 }
    );
    if deployment {
        assert!(journal.observation_target(&next_id).unwrap().is_none());
        drop(journal);
        journal = WriteJournal::open(&path).unwrap();
        assert!(journal.observation_target(&next_id).unwrap().is_none());
        assert_eq!(
            journal
                .submission_status(&next_id, &owner)
                .unwrap()
                .observation,
            ChainObservation::Reorged
        );
    }
    let mut third_admission = admission.clone();
    third_admission.capability_id = "third-after-reorg".into();
    assert!(
        journal
            .prepare_replacement(
                signed_command(&uuid::Uuid::now_v7().to_string(), &third),
                &third,
                third_admission,
                &target,
                pending(&target, &connection, at),
                &connection,
                &policy
            )
            .is_err()
    );
    let mut foreign = owner;
    foreign.privacy_domain_id = "foreign".into();
    assert!(journal.replacement_successor(&old_id, &foreign).is_none());
    drop(journal);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
