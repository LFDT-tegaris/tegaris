use super::super::witness::{
    canonicalize_provider_order_with_excluded, compare_provider_order_keys,
};
use super::super::*;
use crate::RouteExecutionContractV1;

const ROUTE_REQUEST_FIXTURE_DIGEST: &str =
    "cf9e27c127a6826b74b96228e830ba2be7f50f47752cf3ece02154448b1c2d34";
const ROUTE_REQUEST_FIXTURE_PC_CBOR_HEX: &str = concat!(
    "841955f265312e302e30776f70656e70633a726f7574652d726571756573743a7631af66616e63686f72a768636861696e5f696461316a626c6f636b5f6861736868626c6f636b2d34326a6e6574776f726b5f6964676e6574776f726b6c626c6f636b5f6e756d626572182a6c67656e657369735f686173686767656e657369736d73656c6563746f725f6b696e646650696e6e6564781d70656e64696e675f617574686f72697a65645f62795f70726f66696c65f4666d6574686f64686574685f63616c6c6a646174615f636c6173736b63616c6c2d726573756c746a726571756573745f696467726571756573746b6964656d706f74656e63796e4964656d706f74656e74526561646d616374696f6e5f696e74656e746d726561642d6f722d77726974656f707269766163795f62696e64696e67677072697661637970776f726b6c6f61645f62696e64696e6768776f726b6c6f6164737061727469636970616e745f62696e64696e676b7061727469636970616e74",
    "7765766964656e63655f636f7272656c6174696f6e5f69646b636f7272656c6174696f6e77726571756573745f646561646c696e655f6d696c6c697318647818617574686f726974795f636f6e746578745f64696765737469617574686f72697479781b6e6f726d616c697a65645f706172616d657465725f6469676573746a706172616d6574657273781f6d6178696d756d5f726573706f6e73655f636c617373696669636174696f6e78187061727469636970616e742d636f6e666964656e7469616c782272657175697265645f6361706162696c6974795f70726f66696c655f6469676573746a6361706162696c697479"
);
fn anchor() -> ChainReadAnchorV1 {
    ChainReadAnchorV1 {
        chain_id: "1".into(),
        genesis_hash: "genesis".into(),
        network_id: "network".into(),
        selector_kind: BlockSelectorKind::Pinned,
        block_number: Some(42),
        block_hash: Some("block-42".into()),
        pending_authorized_by_profile: false,
    }
}

fn request(idempotency: IdempotencyClass) -> RouteRequestV1 {
    RouteRequestV1 {
        request_id: "request".into(),
        authority_context_digest: "authority".into(),
        participant_binding: "participant".into(),
        privacy_binding: "privacy".into(),
        workload_binding: "workload".into(),
        action_intent: "read-or-write".into(),
        method: "eth_call".into(),
        data_class: "call-result".into(),
        normalized_parameter_digest: "parameters".into(),
        anchor: anchor(),
        required_capability_profile_digest: "capability".into(),
        maximum_response_classification: "participant-confidential".into(),
        idempotency,
        request_deadline_millis: 100,
        evidence_correlation_id: "correlation".into(),
    }
}

fn method() -> MethodDataClass {
    MethodDataClass {
        method: "eth_call".into(),
        data_class: "call-result".into(),
    }
}

fn profile(
    profile_digest: &str,
    instance: &str,
    idempotency: IdempotencyClass,
    route_plan: RoutePlanDraftV1,
    retry_budget: u8,
) -> ProviderProfileV1 {
    ProviderProfileV1 {
        profile_id: format!("profile-{instance}"),
        profile_version: "1".into(),
        profile_digest: profile_digest.into(),
        provider_instance_id: instance.into(),
        provider_release_digest: format!("release-{instance}"),
        provider_build_digest: format!("build-{instance}"),
        configuration_digest: "configuration".into(),
        chain_id: "1".into(),
        genesis_hash: "genesis".into(),
        network_id: "network".into(),
        tls_credential_identity: format!("credential-{instance}"),
        tls_credential_fingerprint: format!("fingerprint-{instance}"),
        trust_epoch: 1,
        json_rpc_version: "2.0".into(),
        method_data_classes: vec![MethodDataClass {
            method: "eth_call".into(),
            data_class: "call-result".into(),
        }],
        request_schema_digest: "request-schema".into(),
        response_schema_digest: "response-schema".into(),
        normalization_rule_digest: "normalization".into(),
        limits: ProviderLimits {
            max_request_bytes: 1024,
            max_response_bytes: 4096,
            max_range: 100,
            max_batch: 10,
        },
        privacy_behavior_digest: "privacy-policy".into(),
        failure_behavior_digest: "failure-policy".into(),
        rate_limit_contract_digest: "rate-policy".into(),
        capability_profile_digest: "capability".into(),
        maximum_response_classification: "participant-confidential".into(),
        idempotency,
        route_plan,
        read_retry_budget: retry_budget,
        timeout_budget_millis: 100,
        corpus_digest: "corpus".into(),
        conformance_receipt_digest: "receipt".into(),
        lifecycle: ProfileLifecycle::Active,
        evidence_refs: vec!["profile-evidence".into()],
    }
}

fn finalize_fixture(mut value: RequestRouteWitnessDraftV1) -> RequestRouteWitnessDraftV1 {
    canonicalize_provider_order_with_excluded(
        &value.request_digest,
        &mut value.admitted_profiles,
        &mut [],
        &mut value.exclusions,
    );
    let route_ids = match &value.execution {
        RouteExecutionDraftV1::IdempotentRead {
            primary_attempt_ids,
            hedge_attempt_ids,
            ..
        } => primary_attempt_ids
            .iter()
            .chain(hedge_attempt_ids)
            .cloned()
            .collect::<Vec<_>>(),
        RouteExecutionDraftV1::GovernedWrite { attempt_ids, .. } => attempt_ids.clone(),
    };
    for (index, id) in route_ids.iter().enumerate() {
        let profile = &value.admitted_profiles[index];
        let attempt = value
            .attempts
            .iter_mut()
            .find(|attempt| attempt.envelope.attempt_id == *id)
            .expect("fixture route attempt");
        attempt.envelope.profile_digest = profile.profile_digest.clone();
        attempt.envelope.provider_instance_id = profile.provider_instance_id.clone();
        attempt.envelope.ordinal = u8::try_from(index + 1).expect("fixture ordinal");
        if let Some(resolution) = &mut attempt.resolution {
            resolution.profile_digest = profile.profile_digest.clone();
            resolution.provider_instance_id = profile.provider_instance_id.clone();
        }
    }
    if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } = &mut value.execution {
        for recovery in recoveries {
            let prior = value
                .attempts
                .iter()
                .find(|attempt| attempt.envelope.attempt_id == recovery.prior_attempt_id)
                .expect("fixture recovery prior");
            let target = value
                .admitted_profiles
                .iter()
                .find(|profile| {
                    profile.profile_digest != prior.envelope.profile_digest
                        || profile.provider_instance_id != prior.envelope.provider_instance_id
                })
                .expect("fixture failover target");
            recovery.target_profile_digest = target.profile_digest.clone();
            recovery.target_provider_instance_id = target.provider_instance_id.clone();
            let next = value
                .attempts
                .iter_mut()
                .find(|attempt| attempt.envelope.attempt_id == recovery.next_attempt_id)
                .expect("fixture recovery next");
            next.envelope.profile_digest = target.profile_digest.clone();
            next.envelope.provider_instance_id = target.provider_instance_id.clone();
            if let Some(resolution) = &mut next.resolution {
                resolution.profile_digest = target.profile_digest.clone();
                resolution.provider_instance_id = target.provider_instance_id.clone();
            }
        }
    }
    value
}

fn finalize_fixture_with_excluded(
    mut value: RequestRouteWitnessDraftV1,
    excluded_profiles: &mut [ProviderProfileV1],
) -> RequestRouteWitnessDraftV1 {
    canonicalize_provider_order_with_excluded(
        &value.request_digest,
        &mut value.admitted_profiles,
        excluded_profiles,
        &mut value.exclusions,
    );
    let route_ids = match &value.execution {
        RouteExecutionDraftV1::IdempotentRead {
            primary_attempt_ids,
            hedge_attempt_ids,
            ..
        } => primary_attempt_ids
            .iter()
            .chain(hedge_attempt_ids)
            .cloned()
            .collect::<Vec<_>>(),
        RouteExecutionDraftV1::GovernedWrite { attempt_ids, .. } => attempt_ids.clone(),
    };
    for (index, id) in route_ids.iter().enumerate() {
        let profile = &value.admitted_profiles[index];
        let attempt = value
            .attempts
            .iter_mut()
            .find(|attempt| attempt.envelope.attempt_id == *id)
            .expect("fixture route attempt");
        attempt.envelope.profile_digest = profile.profile_digest.clone();
        attempt.envelope.provider_instance_id = profile.provider_instance_id.clone();
        attempt.envelope.ordinal = u8::try_from(index + 1).expect("fixture ordinal");
        if let Some(resolution) = &mut attempt.resolution {
            resolution.profile_digest = profile.profile_digest.clone();
            resolution.provider_instance_id = profile.provider_instance_id.clone();
        }
    }
    value
}

fn envelope(
    identity: (&str, &str, &str, u8),
    state: AttemptState,
    timing: (Option<u64>, Option<u64>),
    deadline: u64,
) -> AttemptEnvelopeDraftV1 {
    let (id, profile, instance, ordinal) = identity;
    let (started, completed) = timing;
    AttemptEnvelopeDraftV1 {
        attempt_id: id.into(),
        request_id: "request".into(),
        authority_context_digest: "authority".into(),
        capability_profile_digest: "capability".into(),
        profile_digest: profile.into(),
        provider_instance_id: instance.into(),
        immutable_request_digest: "request-digest".into(),
        anchor: anchor(),
        ordinal,
        state,
        bytes_started_evidence_digest: started.map(|_| format!("bytes-{id}")),
        started_at_millis: started,
        response_observed_evidence_digest: None,
        observed_at_millis: None,
        completed_at_millis: completed,
        no_bytes_sent_evidence_digest: (state == AttemptState::Failed && started.is_none())
            .then(|| format!("no-bytes-{id}")),
        deadline_millis: deadline,
        correlation_id: format!("correlation-{id}"),
        causation_id: "route".into(),
    }
}

fn resolution(
    truth: ResolutionTruth,
    profile: &str,
    instance: &str,
    digest: Option<&str>,
    eligibility: RecoveryEligibilityV1,
    evidence_ref: &str,
) -> AttemptResolutionDraftV2 {
    let success = matches!(
        truth,
        ResolutionTruth::Success | ResolutionTruth::AuthorizedEmpty
    );
    AttemptResolutionDraftV2 {
        truth,
        normalized_response_digest: digest.map(str::to_owned),
        response_digest: success.then(|| format!("response-{instance}")),
        status_digest: Some(format!("status-{instance}")),
        error_digest: (!success).then(|| format!("error-{instance}")),
        observed_anchor: anchor(),
        capability_profile_digest: "capability".into(),
        profile_digest: profile.into(),
        provider_instance_id: instance.into(),
        recovery_eligibility: eligibility,
        evidence_refs: vec![evidence_ref.into()],
    }
}

fn attempt(
    id: &str,
    profile: &str,
    instance: &str,
    ordinal: u8,
    started: u64,
    completed: u64,
    digest: &str,
) -> RouteAttemptDraftV1 {
    RouteAttemptDraftV1 {
        envelope: envelope(
            (id, profile, instance, ordinal),
            AttemptState::Resolved,
            (Some(started), Some(completed)),
            100,
        ),
        resolution: Some(resolution(
            ResolutionTruth::Success,
            profile,
            instance,
            Some(digest),
            RecoveryEligibilityV1::None,
            &format!("evidence-{id}"),
        )),
    }
}

fn single_read() -> RequestRouteWitnessDraftV1 {
    finalize_fixture(RequestRouteWitnessDraftV1 {
        request: request(IdempotencyClass::IdempotentRead),
        request_digest: "request-digest".into(),
        admitted_profiles: vec![profile(
            "p1",
            "i1",
            IdempotencyClass::IdempotentRead,
            RoutePlanDraftV1::SingleExact,
            1,
        )],
        exclusions: vec![],
        attempts: vec![attempt("a1", "p1", "i1", 1, 1, 2, "digest")],
        execution: RouteExecutionDraftV1::IdempotentRead {
            route_plan: RoutePlanDraftV1::SingleExact,
            primary_attempt_ids: vec!["a1".into()],
            hedge_attempt_ids: vec![],
            recoveries: vec![],
            outcome: RouteOutcomeDraftV1::Selected {
                truth: ResolutionTruth::Success,
                selected_result_digest: "digest".into(),
                agreement_attempt_ids: vec!["a1".into()],
            },
        },
    })
}

fn hedged_single() -> RequestRouteWitnessDraftV1 {
    let law = RoutePlanDraftV1::HedgedSingle {
        hedge_threshold_millis: 5,
    };
    finalize_fixture(RequestRouteWitnessDraftV1 {
        request: request(IdempotencyClass::IdempotentRead),
        request_digest: "request-digest".into(),
        admitted_profiles: vec![
            profile("p1", "i1", IdempotencyClass::IdempotentRead, law.clone(), 0),
            profile("p2", "i2", IdempotencyClass::IdempotentRead, law.clone(), 0),
        ],
        exclusions: vec![],
        attempts: vec![
            attempt("a1", "p1", "i1", 1, 1, 10, "primary"),
            attempt("a2", "p2", "i2", 2, 6, 8, "secondary"),
        ],
        execution: RouteExecutionDraftV1::IdempotentRead {
            route_plan: law,
            primary_attempt_ids: vec!["a1".into()],
            hedge_attempt_ids: vec!["a2".into()],
            recoveries: vec![],
            outcome: RouteOutcomeDraftV1::Selected {
                truth: ResolutionTruth::Success,
                selected_result_digest: "secondary".into(),
                agreement_attempt_ids: vec!["a2".into()],
            },
        },
    })
}

fn recovery_read() -> RequestRouteWitnessDraftV1 {
    let law = RoutePlanDraftV1::HedgedSingle {
        hedge_threshold_millis: 5,
    };
    let first = RouteAttemptDraftV1 {
        envelope: envelope(
            ("a1", "p1", "i1", 1),
            AttemptState::Failed,
            (Some(1), Some(2)),
            100,
        ),
        resolution: Some(resolution(
            ResolutionTruth::Timeout,
            "p1",
            "i1",
            None,
            RecoveryEligibilityV1::FailoverWithinSnapshot,
            "failure-a1",
        )),
    };
    let mut second = attempt("a2", "p2", "i2", 2, 4, 5, "digest");
    second.envelope.deadline_millis = 90;
    finalize_fixture(RequestRouteWitnessDraftV1 {
        request: request(IdempotencyClass::IdempotentRead),
        request_digest: "request-digest".into(),
        admitted_profiles: vec![
            profile("p1", "i1", IdempotencyClass::IdempotentRead, law.clone(), 1),
            profile("p2", "i2", IdempotencyClass::IdempotentRead, law.clone(), 1),
        ],
        exclusions: vec![],
        attempts: vec![first, second],
        execution: RouteExecutionDraftV1::IdempotentRead {
            route_plan: law,
            primary_attempt_ids: vec!["a1".into()],
            hedge_attempt_ids: vec![],
            recoveries: vec![ReadRecoveryDraftV1 {
                prior_attempt_id: "a1".into(),
                next_attempt_id: "a2".into(),
                target_profile_digest: "p2".into(),
                target_provider_instance_id: "i2".into(),
                kind: ReadRecoveryKind::FailoverWithinSnapshot,
                request_id: "request".into(),
                authority_context_digest: "authority".into(),
                immutable_request_digest: "request-digest".into(),
                anchor: anchor(),
                remaining_deadline_millis: 90,
                remaining_rate_budget: 0,
            }],
            outcome: RouteOutcomeDraftV1::Selected {
                truth: ResolutionTruth::Success,
                selected_result_digest: "digest".into(),
                agreement_attempt_ids: vec!["a2".into()],
            },
        },
    })
}

fn quorum_read() -> RequestRouteWitnessDraftV1 {
    let law = RoutePlanDraftV1::QuorumIdentical {
        required_agreement: 2,
    };
    finalize_fixture(RequestRouteWitnessDraftV1 {
        request: request(IdempotencyClass::IdempotentRead),
        request_digest: "request-digest".into(),
        admitted_profiles: vec![
            profile("p1", "i1", IdempotencyClass::IdempotentRead, law.clone(), 0),
            profile("p2", "i2", IdempotencyClass::IdempotentRead, law.clone(), 0),
        ],
        exclusions: vec![],
        attempts: vec![
            attempt("a1", "p1", "i1", 1, 1, 3, "quorum"),
            attempt("a2", "p2", "i2", 2, 1, 4, "quorum"),
        ],
        execution: RouteExecutionDraftV1::IdempotentRead {
            route_plan: law,
            primary_attempt_ids: vec!["a1".into(), "a2".into()],
            hedge_attempt_ids: vec![],
            recoveries: vec![],
            outcome: RouteOutcomeDraftV1::Selected {
                truth: ResolutionTruth::Success,
                selected_result_digest: "quorum".into(),
                agreement_attempt_ids: vec!["a1".into(), "a2".into()],
            },
        },
    })
}

fn single_failed_read(
    retry_budget: u8,
    eligibility: RecoveryEligibilityV1,
) -> RequestRouteWitnessDraftV1 {
    let mut value = single_read();
    value.admitted_profiles[0].read_retry_budget = retry_budget;
    value.attempts[0] = RouteAttemptDraftV1 {
        envelope: envelope(
            ("a1", "p1", "i1", 1),
            AttemptState::Failed,
            (Some(1), Some(2)),
            100,
        ),
        resolution: Some(resolution(
            ResolutionTruth::Timeout,
            "p1",
            "i1",
            None,
            eligibility,
            "failure-a1",
        )),
    };
    value.execution = RouteExecutionDraftV1::IdempotentRead {
        route_plan: RoutePlanDraftV1::SingleExact,
        primary_attempt_ids: vec!["a1".into()],
        hedge_attempt_ids: vec![],
        recoveries: vec![],
        outcome: RouteOutcomeDraftV1::Failed {
            truth: ResolutionTruth::Timeout,
            evidence_refs: vec!["failure-a1".into()],
        },
    };
    value
}

fn write_acknowledged() -> RequestRouteWitnessDraftV1 {
    finalize_fixture(RequestRouteWitnessDraftV1 {
        request: request(IdempotencyClass::GovernedWrite),
        request_digest: "request-digest".into(),
        admitted_profiles: vec![profile(
            "p1",
            "i1",
            IdempotencyClass::GovernedWrite,
            RoutePlanDraftV1::SingleExact,
            0,
        )],
        exclusions: vec![],
        attempts: vec![attempt("a1", "p1", "i1", 1, 1, 2, "ack")],
        execution: RouteExecutionDraftV1::GovernedWrite {
            attempt_ids: vec!["a1".into()],
            reconciliation_observation_profiles: vec![],
            progress: GovernedWriteProgressDraftV1::Acknowledged,
        },
    })
}

fn hedged_quorum() -> RequestRouteWitnessDraftV1 {
    let law = RoutePlanDraftV1::HedgedQuorumIdentical {
        required_agreement: 2,
        hedge_threshold_millis: 5,
        max_hedge_attempts: 1,
    };
    let failed = RouteAttemptDraftV1 {
        envelope: envelope(
            ("a2", "p2", "i2", 2),
            AttemptState::Failed,
            (Some(1), Some(2)),
            100,
        ),
        resolution: Some(resolution(
            ResolutionTruth::Timeout,
            "p2",
            "i2",
            None,
            RecoveryEligibilityV1::None,
            "failure-a2",
        )),
    };
    finalize_fixture(RequestRouteWitnessDraftV1 {
        request: request(IdempotencyClass::IdempotentRead),
        request_digest: "request-digest".into(),
        admitted_profiles: vec![
            profile("p1", "i1", IdempotencyClass::IdempotentRead, law.clone(), 0),
            profile("p2", "i2", IdempotencyClass::IdempotentRead, law.clone(), 0),
            profile("p3", "i3", IdempotencyClass::IdempotentRead, law.clone(), 0),
        ],
        exclusions: vec![],
        attempts: vec![
            attempt("a1", "p1", "i1", 1, 1, 10, "quorum"),
            failed,
            attempt("a3", "p3", "i3", 3, 6, 8, "quorum"),
        ],
        execution: RouteExecutionDraftV1::IdempotentRead {
            route_plan: law,
            primary_attempt_ids: vec!["a1".into(), "a2".into()],
            hedge_attempt_ids: vec!["a3".into()],
            recoveries: vec![],
            outcome: RouteOutcomeDraftV1::Selected {
                truth: ResolutionTruth::Success,
                selected_result_digest: "quorum".into(),
                agreement_attempt_ids: vec!["a1".into(), "a3".into()],
            },
        },
    })
}

fn write_reselection() -> RequestRouteWitnessDraftV1 {
    let first = RouteAttemptDraftV1 {
        envelope: envelope(
            ("a1", "p1", "i1", 1),
            AttemptState::Failed,
            (None, Some(2)),
            100,
        ),
        resolution: Some(resolution(
            ResolutionTruth::Timeout,
            "p1",
            "i1",
            None,
            RecoveryEligibilityV1::None,
            "pre-start-failure",
        )),
    };
    finalize_fixture(RequestRouteWitnessDraftV1 {
        request: request(IdempotencyClass::GovernedWrite),
        request_digest: "request-digest".into(),
        admitted_profiles: vec![
            profile(
                "p1",
                "i1",
                IdempotencyClass::GovernedWrite,
                RoutePlanDraftV1::SingleExact,
                0,
            ),
            profile(
                "p2",
                "i2",
                IdempotencyClass::GovernedWrite,
                RoutePlanDraftV1::SingleExact,
                0,
            ),
        ],
        exclusions: vec![],
        attempts: vec![first, attempt("a2", "p2", "i2", 2, 3, 4, "ack")],
        execution: RouteExecutionDraftV1::GovernedWrite {
            attempt_ids: vec!["a1".into(), "a2".into()],
            reconciliation_observation_profiles: vec![],
            progress: GovernedWriteProgressDraftV1::Acknowledged,
        },
    })
}

fn reconciliation_profile(
    digest: &str,
    instance: &str,
    pair: MethodDataClass,
) -> ProviderProfileV1 {
    let mut value = profile(
        digest,
        instance,
        IdempotencyClass::IdempotentRead,
        RoutePlanDraftV1::SingleExact,
        0,
    );
    value.method_data_classes = vec![pair];
    value
}

fn write_ambiguity() -> RequestRouteWitnessDraftV1 {
    let pair = MethodDataClass {
        method: "eth_getTransactionReceipt".into(),
        data_class: "RECEIPT".into(),
    };
    let mut value = write_acknowledged();
    value.attempts[0].envelope.state = AttemptState::Unknown;
    value.attempts[0].resolution = Some(resolution(
        ResolutionTruth::WriteAmbiguity,
        "p1",
        "i1",
        None,
        RecoveryEligibilityV1::None,
        "ambiguous",
    ));
    value.execution = RouteExecutionDraftV1::GovernedWrite {
        attempt_ids: vec!["a1".into()],
        reconciliation_observation_profiles: vec![reconciliation_profile(
            "reconciliation-profile",
            "reconciliation-instance",
            pair.clone(),
        )],
        progress: GovernedWriteProgressDraftV1::Reconciliation(Box::new(WriteReconciliationV1 {
            request_or_transaction_hash: RequestDigest::new("request-digest").expect("hash"),
            anchor: anchor(),
            provider_attempt_id: AttemptId::new("a1").expect("attempt"),
            observations: vec![ReconciliationObservationV1 {
                method_data_class: pair,
                provider_profile_digest: ProviderProfileDigest::new("reconciliation-profile")
                    .expect("profile digest"),
            }],
            state: WriteReconciliationStateV1::Ambiguous,
            evidence_refs: vec![EvidenceDigest::new("observation").expect("evidence")],
        })),
    };
    value
}

fn set_single_valid_truth(
    value: &mut RequestRouteWitnessDraftV1,
    truth: ResolutionTruth,
    completion: u64,
    timely: bool,
) {
    value.request.request_deadline_millis = 5;
    value.attempts[0].envelope.deadline_millis = 5;
    value.attempts[0].envelope.completed_at_millis = Some(completion);
    value.attempts[0]
        .resolution
        .as_mut()
        .expect("resolution")
        .truth = truth;
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut value.execution {
        *outcome = if timely {
            RouteOutcomeDraftV1::Selected {
                truth,
                selected_result_digest: "digest".into(),
                agreement_attempt_ids: vec!["a1".into()],
            }
        } else {
            RouteOutcomeDraftV1::Failed {
                truth: ResolutionTruth::Timeout,
                evidence_refs: vec!["evidence-a1".into()],
            }
        };
    }
}

#[test]
fn profile_request_and_snapshot_matrix_is_closed() {
    assert!(RequestRouteWitnessV1::try_from(single_read()).is_ok());
    for lifecycle in [ProfileLifecycle::Qualified, ProfileLifecycle::Active] {
        let mut value = single_read();
        value.admitted_profiles[0].lifecycle = lifecycle;
        assert!(RequestRouteWitnessV1::try_from(value).is_ok());
    }
    for lifecycle in [
        ProfileLifecycle::Draft,
        ProfileLifecycle::Validated,
        ProfileLifecycle::Quarantined,
        ProfileLifecycle::Disabled,
        ProfileLifecycle::Retired,
        ProfileLifecycle::Uninstalled,
    ] {
        let mut value = single_read();
        value.admitted_profiles[0].lifecycle = lifecycle;
        assert!(RequestRouteWitnessV1::try_from(value).is_err());
    }
    let mutations: [fn(&mut RequestRouteWitnessDraftV1); 10] = [
        |v| v.admitted_profiles[0].provider_release_digest.clear(),
        |v| v.admitted_profiles[0].configuration_digest.clear(),
        |v| v.admitted_profiles[0].tls_credential_identity.clear(),
        |v| v.admitted_profiles[0].json_rpc_version = "1.0".into(),
        |v| v.request.method = "unknown".into(),
        |v| v.request.anchor.chain_id = "wrong".into(),
        |v| v.admitted_profiles.push(v.admitted_profiles[0].clone()),
        |v| v.attempts[0].envelope.profile_digest = "outside".into(),
        |v| v.attempts[0].envelope.deadline_millis = 101,
        |v| {
            v.admitted_profiles[0]
                .method_data_classes
                .push(MethodDataClass {
                    method: "eth_call".into(),
                    data_class: "call-result".into(),
                });
        },
    ];
    for mutate in mutations {
        let mut value = single_read();
        mutate(&mut value);
        assert!(RequestRouteWitnessV1::try_from(value).is_err());
    }
}

#[test]
fn resolution_truth_and_recovery_eligibility_table_is_closed() {
    let recoverable = [
        ResolutionTruth::Unavailable,
        ResolutionTruth::RateLimited,
        ResolutionTruth::Timeout,
    ];
    for truth in recoverable {
        assert!(
            AttemptResolutionV2::try_from(resolution(
                truth,
                "p1",
                "i1",
                None,
                RecoveryEligibilityV1::RetrySameProvider,
                "evidence",
            ))
            .is_ok()
        );
    }
    for truth in [
        ResolutionTruth::Divergent,
        ResolutionTruth::Invalid,
        ResolutionTruth::WriteAmbiguity,
        ResolutionTruth::Reorg,
        ResolutionTruth::Partial,
        ResolutionTruth::Denied,
    ] {
        assert!(
            AttemptResolutionV2::try_from(resolution(
                truth,
                "p1",
                "i1",
                None,
                RecoveryEligibilityV1::RetrySameProvider,
                "evidence",
            ))
            .is_err()
        );
    }
    let mut success = resolution(
        ResolutionTruth::Success,
        "p1",
        "i1",
        Some("digest"),
        RecoveryEligibilityV1::None,
        "evidence",
    );
    success.recovery_eligibility = RecoveryEligibilityV1::FailoverWithinSnapshot;
    assert!(AttemptResolutionV2::try_from(success).is_err());

    let mut authorized_empty = single_read();
    authorized_empty.attempts[0]
        .resolution
        .as_mut()
        .expect("resolution")
        .truth = ResolutionTruth::AuthorizedEmpty;
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut authorized_empty.execution {
        *outcome = RouteOutcomeDraftV1::Selected {
            truth: ResolutionTruth::AuthorizedEmpty,
            selected_result_digest: "digest".into(),
            agreement_attempt_ids: vec!["a1".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(authorized_empty).is_ok());
}

#[test]
fn terminal_outcome_derivation_table_is_closed() {
    let mut divergent = quorum_read();
    divergent.attempts[1] = attempt("a2", "p2", "i2", 2, 1, 4, "other");
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut divergent.execution {
        *outcome = RouteOutcomeDraftV1::Divergent {
            evidence_refs: vec!["evidence-a1".into(), "evidence-a2".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(divergent).is_ok());

    let mut partial = quorum_read();
    partial.attempts[1] = RouteAttemptDraftV1 {
        envelope: envelope(
            ("a2", "p2", "i2", 2),
            AttemptState::Failed,
            (Some(1), Some(4)),
            100,
        ),
        resolution: Some(resolution(
            ResolutionTruth::Timeout,
            "p2",
            "i2",
            None,
            RecoveryEligibilityV1::None,
            "failure-a2",
        )),
    };
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut partial.execution {
        *outcome = RouteOutcomeDraftV1::Partial {
            evidence_refs: vec!["evidence-a1".into(), "failure-a2".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(partial).is_ok());

    let mut failed = quorum_read();
    for (index, attempt) in failed.attempts.iter_mut().enumerate() {
        let ordinal = u8::try_from(index + 1).expect("ordinal");
        let profile = format!("p{ordinal}");
        let instance = format!("i{ordinal}");
        *attempt = RouteAttemptDraftV1 {
            envelope: envelope(
                (&format!("a{ordinal}"), &profile, &instance, ordinal),
                AttemptState::Failed,
                (Some(1), Some(u64::from(ordinal) + 2)),
                100,
            ),
            resolution: Some(resolution(
                ResolutionTruth::Timeout,
                &profile,
                &instance,
                None,
                RecoveryEligibilityV1::None,
                &format!("failure-a{ordinal}"),
            )),
        };
    }
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut failed.execution {
        *outcome = RouteOutcomeDraftV1::Failed {
            truth: ResolutionTruth::Timeout,
            evidence_refs: vec!["failure-a1".into(), "failure-a2".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(failed.clone()).is_ok());
    failed.attempts[1]
        .resolution
        .as_mut()
        .expect("resolution")
        .truth = ResolutionTruth::Unavailable;
    let mixed = RequestRouteWitnessV1::try_from(failed.clone()).expect("mixed terminal truths");
    assert!(matches!(
        mixed.execution(),
        RouteExecutionV1::IdempotentRead {
            outcome: RouteOutcomeV1::Failed {
                truth: ResolutionTruth::Timeout,
                ..
            },
            ..
        }
    ));
    assert_eq!(
        mixed
            .attempts()
            .iter()
            .map(|attempt| attempt.resolution().expect("terminal resolution").truth())
            .collect::<Vec<_>>(),
        [ResolutionTruth::Timeout, ResolutionTruth::Unavailable]
    );
    assert_eq!(
        mixed.attempts()[0]
            .resolution()
            .expect("a1 resolution")
            .evidence_refs()[0]
            .as_str(),
        "failure-a1"
    );
    assert_eq!(
        mixed.attempts()[1]
            .resolution()
            .expect("a2 resolution")
            .evidence_refs()[0]
            .as_str(),
        "failure-a2"
    );

    failed.attempts[1].envelope.completed_at_millis = Some(2);
    assert!(RequestRouteWitnessV1::try_from(failed.clone()).is_err());
    if let RouteExecutionDraftV1::IdempotentRead {
        outcome: RouteOutcomeDraftV1::Failed { truth, .. },
        ..
    } = &mut failed.execution
    {
        *truth = ResolutionTruth::Unavailable;
    }
    assert!(RequestRouteWitnessV1::try_from(failed).is_ok());

    let mut agreement_tamper = quorum_read();
    if let RouteExecutionDraftV1::IdempotentRead {
        outcome:
            RouteOutcomeDraftV1::Selected {
                agreement_attempt_ids,
                ..
            },
        ..
    } = &mut agreement_tamper.execution
    {
        agreement_attempt_ids.pop();
    }
    assert!(RequestRouteWitnessV1::try_from(agreement_tamper).is_err());
}

#[test]
fn read_mode_and_hedge_transition_table_is_closed() {
    assert!(RequestRouteWitnessV1::try_from(quorum_read()).is_ok());
    let mut quorum_subset = quorum_read();
    if let RouteExecutionDraftV1::IdempotentRead {
        primary_attempt_ids,
        ..
    } = &mut quorum_subset.execution
    {
        primary_attempt_ids.pop();
    }
    assert!(RequestRouteWitnessV1::try_from(quorum_subset).is_err());

    let witness = RequestRouteWitnessV1::try_from(hedged_single()).expect("qualified hedge");
    let RouteExecutionV1::IdempotentRead { outcome, .. } = witness.execution() else {
        panic!("read execution")
    };
    assert!(
        matches!(outcome, RouteOutcomeV1::Selected(value) if value.selected_result_digest().as_str() == "secondary")
    );

    let mutations: [fn(&mut RequestRouteWitnessDraftV1); 4] = [
        |v| v.attempts[1].envelope.started_at_millis = Some(5),
        |v| v.attempts[0].envelope.completed_at_millis = Some(6),
        |v| v.attempts[1].envelope.completed_at_millis = Some(10),
        |v| {
            if let RouteExecutionDraftV1::IdempotentRead {
                hedge_attempt_ids, ..
            } = &mut v.execution
            {
                hedge_attempt_ids.clear();
            }
        },
    ];
    for mutate in mutations {
        let mut value = hedged_single();
        mutate(&mut value);
        assert!(RequestRouteWitnessV1::try_from(value).is_err());
    }
}

#[test]
fn hedged_quorum_wave_table_is_closed() {
    assert!(RequestRouteWitnessV1::try_from(hedged_quorum()).is_ok());
    let mut dissent = hedged_quorum();
    dissent.attempts[1] = attempt("a2", "p2", "i2", 2, 1, 5, "dissent");
    let dissent = finalize_fixture(dissent);
    assert!(RequestRouteWitnessV1::try_from(dissent).is_ok());
    let mutations: [fn(&mut RequestRouteWitnessDraftV1); 3] = [
        |v| v.attempts[2].envelope.started_at_millis = Some(5),
        |v| {
            v.attempts[1] = attempt("a2", "p2", "i2", 2, 1, 5, "quorum");
            v.attempts[0].envelope.completed_at_millis = Some(4);
        },
        |v| {
            if let RouteExecutionDraftV1::IdempotentRead {
                hedge_attempt_ids, ..
            } = &mut v.execution
            {
                hedge_attempt_ids.push("a2".into());
            }
        },
    ];
    for mutate in mutations {
        let mut value = hedged_quorum();
        mutate(&mut value);
        assert!(RequestRouteWitnessV1::try_from(value).is_err());
    }

    let mut two_hedges = hedged_quorum();
    let two_hedge_law = RoutePlanDraftV1::HedgedQuorumIdentical {
        required_agreement: 2,
        hedge_threshold_millis: 5,
        max_hedge_attempts: 2,
    };
    for profile in &mut two_hedges.admitted_profiles {
        profile.route_plan = two_hedge_law.clone();
    }
    two_hedges.admitted_profiles.push(profile(
        "p4",
        "i4",
        IdempotencyClass::IdempotentRead,
        two_hedge_law.clone(),
        0,
    ));
    two_hedges.attempts[2] = RouteAttemptDraftV1 {
        envelope: envelope(
            ("a3", "p3", "i3", 3),
            AttemptState::Failed,
            (Some(6), Some(7)),
            100,
        ),
        resolution: Some(resolution(
            ResolutionTruth::Timeout,
            "p3",
            "i3",
            None,
            RecoveryEligibilityV1::None,
            "failure-a3",
        )),
    };
    two_hedges
        .attempts
        .push(attempt("a4", "p4", "i4", 4, 8, 9, "quorum"));
    two_hedges.execution = RouteExecutionDraftV1::IdempotentRead {
        route_plan: two_hedge_law,
        primary_attempt_ids: vec!["a1".into(), "a2".into()],
        hedge_attempt_ids: vec!["a3".into(), "a4".into()],
        recoveries: vec![],
        outcome: RouteOutcomeDraftV1::Selected {
            truth: ResolutionTruth::Success,
            selected_result_digest: "quorum".into(),
            agreement_attempt_ids: vec!["a1".into(), "a4".into()],
        },
    };
    let mut two_hedges = finalize_fixture(two_hedges);
    assert!(RequestRouteWitnessV1::try_from(two_hedges.clone()).is_ok());

    two_hedges.attempts[0].envelope.completed_at_millis = Some(4);
    two_hedges.attempts[2] = attempt("a3", "p3", "i3", 3, 6, 7, "quorum");
    assert!(RequestRouteWitnessV1::try_from(two_hedges).is_err());
}

#[test]
fn retry_failover_require_observed_eligible_failure_and_remaining_budgets() {
    let witness = RequestRouteWitnessV1::try_from(recovery_read()).expect("valid failover");
    assert_eq!(witness.recoveries().len(), 1);
    assert_eq!(witness.read_retry_budget(), Some(1));
    let mutations: [fn(&mut RequestRouteWitnessDraftV1); 10] = [
        |v| {
            v.attempts[0]
                .resolution
                .as_mut()
                .expect("resolution")
                .recovery_eligibility = RecoveryEligibilityV1::None
        },
        |v| v.attempts[1].envelope.started_at_millis = Some(2),
        |v| {
            if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } = &mut v.execution {
                recoveries[0].remaining_rate_budget = 1;
            }
        },
        |v| {
            if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } = &mut v.execution {
                recoveries.clear();
            }
        },
        |v| {
            if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } = &mut v.execution {
                recoveries[0].anchor.block_hash = Some("drift".into());
            }
        },
        |v| {
            if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } = &mut v.execution {
                recoveries[0].request_id.push_str("-drift");
            }
        },
        |v| {
            if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } = &mut v.execution {
                recoveries[0].authority_context_digest.push_str("-drift");
            }
        },
        |v| {
            if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } = &mut v.execution {
                recoveries[0].immutable_request_digest.push_str("-drift");
            }
        },
        |v| {
            let prior_profile = v.attempts[0].envelope.profile_digest.clone();
            if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } = &mut v.execution {
                recoveries[0].target_profile_digest = prior_profile;
            }
        },
        |v| {
            v.attempts[1]
                .envelope
                .capability_profile_digest
                .push_str("-drift");
        },
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut value = recovery_read();
        mutate(&mut value);
        assert!(
            RequestRouteWitnessV1::try_from(value).is_err(),
            "recovery mutation {index}"
        );
    }

    let mut deadline_mismatch = recovery_read();
    if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } =
        &mut deadline_mismatch.execution
    {
        recoveries[0].remaining_deadline_millis = 89;
    }
    assert!(RequestRouteWitnessV1::try_from(deadline_mismatch).is_err());

    let mut skipped_failover = recovery_read();
    let law = skipped_failover.admitted_profiles[0].route_plan.clone();
    skipped_failover.admitted_profiles.insert(
        1,
        profile("p2", "i2", IdempotencyClass::IdempotentRead, law, 1),
    );
    skipped_failover.attempts[1].envelope.profile_digest = "p3".into();
    skipped_failover.attempts[1].envelope.provider_instance_id = "i3".into();
    skipped_failover.attempts[1]
        .resolution
        .as_mut()
        .expect("resolution")
        .profile_digest = "p3".into();
    skipped_failover.attempts[1]
        .resolution
        .as_mut()
        .expect("resolution")
        .provider_instance_id = "i3".into();
    if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } =
        &mut skipped_failover.execution
    {
        recoveries[0].target_profile_digest = "p3".into();
        recoveries[0].target_provider_instance_id = "i3".into();
    }
    assert!(RequestRouteWitnessV1::try_from(skipped_failover).is_err());

    let zero_budget_claim = single_failed_read(0, RecoveryEligibilityV1::RetrySameProvider);
    assert!(RequestRouteWitnessV1::try_from(zero_budget_claim).is_err());

    let single_failover_claim =
        single_failed_read(1, RecoveryEligibilityV1::FailoverWithinSnapshot);
    assert!(RequestRouteWitnessV1::try_from(single_failover_claim).is_err());
}

#[test]
fn governed_write_progress_and_reselection_table_is_closed() {
    assert!(RequestRouteWitnessV1::try_from(write_acknowledged()).is_ok());
    assert!(RequestRouteWitnessV1::try_from(write_reselection()).is_ok());

    let mut prepared = write_acknowledged();
    prepared.attempts[0].envelope.state = AttemptState::Prepared;
    prepared.attempts[0].envelope.started_at_millis = None;
    prepared.attempts[0].envelope.bytes_started_evidence_digest = None;
    prepared.attempts[0].envelope.completed_at_millis = None;
    prepared.attempts[0].resolution = None;
    prepared.execution = RouteExecutionDraftV1::GovernedWrite {
        attempt_ids: vec!["a1".into()],
        reconciliation_observation_profiles: vec![],
        progress: GovernedWriteProgressDraftV1::Prepared,
    };
    assert!(RequestRouteWitnessV1::try_from(prepared).is_ok());

    let mut started = write_acknowledged();
    started.attempts[0].envelope.state = AttemptState::Started;
    started.attempts[0].envelope.completed_at_millis = None;
    started.attempts[0].resolution = None;
    started.execution = RouteExecutionDraftV1::GovernedWrite {
        attempt_ids: vec!["a1".into()],
        reconciliation_observation_profiles: vec![],
        progress: GovernedWriteProgressDraftV1::Started,
    };
    assert!(RequestRouteWitnessV1::try_from(started).is_ok());

    let mut observed = write_acknowledged();
    observed.attempts[0].envelope.state = AttemptState::ResponseObserved;
    observed.attempts[0]
        .envelope
        .response_observed_evidence_digest = Some("observed-a1".into());
    observed.attempts[0].envelope.observed_at_millis = Some(2);
    observed.attempts[0].envelope.completed_at_millis = None;
    observed.attempts[0].resolution = None;
    observed.execution = RouteExecutionDraftV1::GovernedWrite {
        attempt_ids: vec!["a1".into()],
        reconciliation_observation_profiles: vec![],
        progress: GovernedWriteProgressDraftV1::Started,
    };
    assert!(RequestRouteWitnessV1::try_from(observed).is_ok());

    let mut valid_pre_start = write_acknowledged();
    valid_pre_start.attempts[0].envelope = envelope(
        ("a1", "p1", "i1", 1),
        AttemptState::Failed,
        (None, Some(2)),
        100,
    );
    valid_pre_start.attempts[0].resolution = Some(resolution(
        ResolutionTruth::Denied,
        "p1",
        "i1",
        None,
        RecoveryEligibilityV1::None,
        "denied",
    ));
    valid_pre_start.execution = RouteExecutionDraftV1::GovernedWrite {
        attempt_ids: vec!["a1".into()],
        reconciliation_observation_profiles: vec![],
        progress: GovernedWriteProgressDraftV1::FailedPreStart,
    };
    assert!(RequestRouteWitnessV1::try_from(valid_pre_start).is_ok());

    let mutations: [fn(&mut RequestRouteWitnessDraftV1); 3] = [
        |v| v.attempts[0].envelope.no_bytes_sent_evidence_digest = None,
        |v| v.attempts[0].resolution.as_mut().expect("resolution").truth = ResolutionTruth::Denied,
        |v| v.attempts[0].envelope.started_at_millis = Some(1),
    ];
    for mutate in mutations {
        let mut value = write_reselection();
        mutate(&mut value);
        assert!(RequestRouteWitnessV1::try_from(value).is_err());
    }

    let mut read_eligibility = write_reselection();
    read_eligibility.attempts[0]
        .resolution
        .as_mut()
        .expect("resolution")
        .recovery_eligibility = RecoveryEligibilityV1::RetrySameProvider;
    assert!(RequestRouteWitnessV1::try_from(read_eligibility).is_err());

    let mut causal_overlap = write_reselection();
    causal_overlap.attempts[1].envelope.started_at_millis = Some(2);
    assert!(RequestRouteWitnessV1::try_from(causal_overlap).is_err());

    let ambiguity = write_ambiguity();
    assert!(RequestRouteWitnessV1::try_from(ambiguity.clone()).is_ok());

    let mut timeout_after_start = ambiguity.clone();
    timeout_after_start.attempts[0].envelope.state = AttemptState::Failed;
    timeout_after_start.attempts[0].resolution = Some(resolution(
        ResolutionTruth::Timeout,
        "p1",
        "i1",
        None,
        RecoveryEligibilityV1::None,
        "timeout",
    ));
    assert!(RequestRouteWitnessV1::try_from(timeout_after_start).is_err());

    let mut wrong_hash = ambiguity;
    if let RouteExecutionDraftV1::GovernedWrite {
        progress: GovernedWriteProgressDraftV1::Reconciliation(value),
        ..
    } = &mut wrong_hash.execution
    {
        value.request_or_transaction_hash = RequestDigest::new("wrong").expect("hash");
    }
    assert!(RequestRouteWitnessV1::try_from(wrong_hash).is_err());
}

fn reconciliation_inputs_mut(
    value: &mut RequestRouteWitnessDraftV1,
) -> (&mut Vec<ProviderProfileV1>, &mut WriteReconciliationV1) {
    match &mut value.execution {
        RouteExecutionDraftV1::GovernedWrite {
            reconciliation_observation_profiles,
            progress: GovernedWriteProgressDraftV1::Reconciliation(reconciliation),
            ..
        } => (reconciliation_observation_profiles, reconciliation),
        _ => panic!("reconciliation fixture"),
    }
}

#[test]
fn governed_write_reconciliation_observation_contract_is_closed() {
    let base = write_ambiguity();
    let witness = RequestRouteWitnessV1::try_from(base.clone()).expect("valid reconciliation");
    let RouteExecutionV1::GovernedWrite { progress, .. } = witness.execution() else {
        panic!("governed write execution")
    };
    let GovernedWriteProgressV1::Reconciliation(reconciliation) = progress else {
        panic!("validated reconciliation")
    };
    assert_eq!(
        reconciliation.observations[0].method_data_class.method,
        "eth_getTransactionReceipt"
    );
    assert_eq!(
        reconciliation.observations[0]
            .provider_profile_digest
            .as_str(),
        "reconciliation-profile"
    );

    let mut duplicate = base.clone();
    let (_, reconciliation) = reconciliation_inputs_mut(&mut duplicate);
    let before = reconciliation.observations.len();
    reconciliation
        .observations
        .push(reconciliation.observations[0].clone());
    assert_ne!(reconciliation.observations.len(), before);
    assert_eq!(
        RequestRouteWitnessV1::try_from(duplicate),
        Err(ProviderContractError::Invalid(
            "reconciliation observation canonicality"
        ))
    );

    let mut unsorted = base.clone();
    let (profiles, reconciliation) = reconciliation_inputs_mut(&mut unsorted);
    let earlier_pair = MethodDataClass {
        method: "eth_getBlockByNumber(false)".into(),
        data_class: "BLOCK_HEADER".into(),
    };
    let profiles_before = profiles.len();
    profiles.push(reconciliation_profile(
        "reconciliation-block-profile",
        "reconciliation-block-instance",
        earlier_pair.clone(),
    ));
    let before = reconciliation.observations.len();
    reconciliation
        .observations
        .push(ReconciliationObservationV1 {
            method_data_class: earlier_pair,
            provider_profile_digest: ProviderProfileDigest::new("reconciliation-block-profile")
                .expect("profile digest"),
        });
    assert_ne!(reconciliation.observations.len(), before);
    assert_ne!(profiles.len(), profiles_before);
    assert_eq!(
        RequestRouteWitnessV1::try_from(unsorted),
        Err(ProviderContractError::Invalid(
            "reconciliation observation canonicality"
        ))
    );

    let mut unresolved = base.clone();
    let (_, reconciliation) = reconciliation_inputs_mut(&mut unresolved);
    let before = reconciliation.observations[0]
        .provider_profile_digest
        .clone();
    reconciliation.observations[0].provider_profile_digest =
        ProviderProfileDigest::new("unknown-profile").expect("profile digest");
    assert_ne!(
        reconciliation.observations[0].provider_profile_digest,
        before
    );
    assert_eq!(
        RequestRouteWitnessV1::try_from(unresolved),
        Err(ProviderContractError::Invalid(
            "reconciliation observation profile"
        ))
    );

    let mut unknown_pair = base.clone();
    let (_, reconciliation) = reconciliation_inputs_mut(&mut unknown_pair);
    let before = reconciliation.observations[0].method_data_class.clone();
    reconciliation.observations[0].method_data_class = MethodDataClass {
        method: "eth_getUnknownObservation".into(),
        data_class: "UNKNOWN_OBSERVATION".into(),
    };
    assert_ne!(reconciliation.observations[0].method_data_class, before);
    assert_eq!(
        RequestRouteWitnessV1::try_from(unknown_pair),
        Err(ProviderContractError::Invalid(
            "reconciliation observation profile"
        ))
    );

    let mut write_profile = base.clone();
    let (profiles, _) = reconciliation_inputs_mut(&mut write_profile);
    let before = profiles[0].idempotency;
    profiles[0].idempotency = IdempotencyClass::GovernedWrite;
    assert_ne!(profiles[0].idempotency, before);
    assert_eq!(
        RequestRouteWitnessV1::try_from(write_profile),
        Err(ProviderContractError::Invalid(
            "reconciliation observation must be idempotent read"
        ))
    );

    let mut another_write_pair = base.clone();
    let (profiles, reconciliation) = reconciliation_inputs_mut(&mut another_write_pair);
    let pair = MethodDataClass {
        method: "eth_getBlockByNumber(false)".into(),
        data_class: "BLOCK_HEADER".into(),
    };
    let before_pair = reconciliation.observations[0].method_data_class.clone();
    reconciliation.observations[0].method_data_class = pair.clone();
    let before_idempotency = profiles[0].idempotency;
    let before_methods = profiles[0].method_data_classes.clone();
    profiles[0].method_data_classes = vec![pair];
    profiles[0].idempotency = IdempotencyClass::GovernedWrite;
    assert_ne!(
        reconciliation.observations[0].method_data_class,
        before_pair
    );
    assert_ne!(profiles[0].idempotency, before_idempotency);
    assert_ne!(profiles[0].method_data_classes, before_methods);
    assert_eq!(
        RequestRouteWitnessV1::try_from(another_write_pair),
        Err(ProviderContractError::Invalid(
            "reconciliation observation must be idempotent read"
        ))
    );

    let mut wrong_anchor = base.clone();
    let (profiles, _) = reconciliation_inputs_mut(&mut wrong_anchor);
    let before = profiles[0].chain_id.clone();
    profiles[0].chain_id = "other-chain".into();
    assert_ne!(profiles[0].chain_id, before);
    assert_eq!(
        RequestRouteWitnessV1::try_from(wrong_anchor),
        Err(ProviderContractError::Invalid(
            "reconciliation observation anchor"
        ))
    );

    let mut submission_method = base.clone();
    let submission_pair = MethodDataClass {
        method: submission_method.request.method.clone(),
        data_class: submission_method.request.data_class.clone(),
    };
    let (_, reconciliation) = reconciliation_inputs_mut(&mut submission_method);
    let before = reconciliation.observations[0].method_data_class.clone();
    reconciliation.observations[0].method_data_class = submission_pair;
    assert_ne!(reconciliation.observations[0].method_data_class, before);
    assert_eq!(
        RequestRouteWitnessV1::try_from(submission_method),
        Err(ProviderContractError::Invalid(
            "reconciliation cannot observe submission method"
        ))
    );

    let mut ordinary_write = write_acknowledged();
    let RouteExecutionDraftV1::GovernedWrite {
        reconciliation_observation_profiles,
        ..
    } = &mut ordinary_write.execution
    else {
        panic!("governed write fixture")
    };
    let before = reconciliation_observation_profiles.len();
    reconciliation_observation_profiles.push(reconciliation_profile(
        "unused-profile",
        "unused-instance",
        MethodDataClass {
            method: "eth_getTransactionReceipt".into(),
            data_class: "RECEIPT".into(),
        },
    ));
    assert_ne!(reconciliation_observation_profiles.len(), before);
    assert_eq!(
        RequestRouteWitnessV1::try_from(ordinary_write),
        Err(ProviderContractError::Invalid(
            "reconciliation observation profile"
        ))
    );
}

#[test]
fn governed_write_reconciliation_state_evidence_is_closed() {
    let evidence = |value: &str| EvidenceDigest::new(value).expect("evidence digest");
    let cases = vec![
        (
            WriteReconciliationStateV1::Ambiguous,
            vec![evidence("observation")],
            vec![],
        ),
        (
            WriteReconciliationStateV1::Included {
                inclusion_candidate_digest: evidence("inclusion"),
                receipt_identity_digest: evidence("receipt"),
            },
            vec![
                evidence("inclusion"),
                evidence("observation"),
                evidence("receipt"),
            ],
            vec![evidence("inclusion"), evidence("receipt")],
        ),
        (
            WriteReconciliationStateV1::Executed {
                inclusion_candidate_digest: evidence("inclusion"),
                execution_candidate_digest: evidence("execution"),
                receipt_identity_digest: evidence("receipt"),
            },
            vec![
                evidence("execution"),
                evidence("inclusion"),
                evidence("observation"),
                evidence("receipt"),
            ],
            vec![
                evidence("inclusion"),
                evidence("execution"),
                evidence("receipt"),
            ],
        ),
        (
            WriteReconciliationStateV1::Finalized {
                inclusion_candidate_digest: evidence("inclusion"),
                execution_candidate_digest: evidence("execution"),
                finality_candidate_digest: evidence("finality"),
                receipt_identity_digest: evidence("receipt"),
            },
            vec![
                evidence("execution"),
                evidence("finality"),
                evidence("inclusion"),
                evidence("observation"),
                evidence("receipt"),
            ],
            vec![
                evidence("inclusion"),
                evidence("execution"),
                evidence("finality"),
                evidence("receipt"),
            ],
        ),
        (
            WriteReconciliationStateV1::Reverted {
                receipt_identity_digest: evidence("receipt"),
            },
            vec![evidence("observation"), evidence("receipt")],
            vec![evidence("receipt")],
        ),
        (
            WriteReconciliationStateV1::DroppedConfirmed,
            vec![evidence("observation")],
            vec![],
        ),
    ];
    for (state, evidence_refs, required_state_evidence) in cases {
        let mut value = write_ambiguity();
        let (_, reconciliation) = reconciliation_inputs_mut(&mut value);
        reconciliation.state = state.clone();
        reconciliation.evidence_refs = evidence_refs.clone();
        assert!(RequestRouteWitnessV1::try_from(value).is_ok());

        for required_digest in required_state_evidence {
            let mut missing = write_ambiguity();
            let (_, reconciliation) = reconciliation_inputs_mut(&mut missing);
            reconciliation.state = state.clone();
            reconciliation.evidence_refs = evidence_refs.clone();
            assert!(reconciliation.evidence_refs.contains(&required_digest));
            reconciliation
                .evidence_refs
                .retain(|digest| digest != &required_digest);
            assert!(!reconciliation.evidence_refs.contains(&required_digest));
            assert_eq!(
                RequestRouteWitnessV1::try_from(missing),
                Err(ProviderContractError::Invalid(
                    "reconciliation state evidence"
                ))
            );
        }
    }

    let mut duplicate_state = write_ambiguity();
    let (_, reconciliation) = reconciliation_inputs_mut(&mut duplicate_state);
    let before = reconciliation.state.clone();
    reconciliation.state = WriteReconciliationStateV1::Executed {
        inclusion_candidate_digest: evidence("same"),
        execution_candidate_digest: evidence("same"),
        receipt_identity_digest: evidence("receipt"),
    };
    let evidence_before = reconciliation.evidence_refs.clone();
    reconciliation.evidence_refs = vec![
        evidence("observation"),
        evidence("receipt"),
        evidence("same"),
    ];
    assert_ne!(reconciliation.state, before);
    assert_ne!(reconciliation.evidence_refs, evidence_before);
    assert_eq!(
        RequestRouteWitnessV1::try_from(duplicate_state),
        Err(ProviderContractError::Invalid(
            "reconciliation state evidence"
        ))
    );

    for evidence_refs in [
        vec![],
        vec![evidence("same"), evidence("same")],
        vec![evidence("z"), evidence("a")],
    ] {
        let mut value = write_ambiguity();
        let (_, reconciliation) = reconciliation_inputs_mut(&mut value);
        let before = reconciliation.evidence_refs.clone();
        reconciliation.evidence_refs = evidence_refs;
        assert_ne!(reconciliation.evidence_refs, before);
        assert_eq!(
            RequestRouteWitnessV1::try_from(value),
            Err(ProviderContractError::Invalid("reconciliation evidence"))
        );
    }
}

#[test]
fn valid_completion_truth_deadline_table_is_closed() {
    for truth in [ResolutionTruth::Success, ResolutionTruth::AuthorizedEmpty] {
        for (completion, timely) in [(4, true), (5, true), (6, false)] {
            let mut value = single_read();
            set_single_valid_truth(&mut value, truth, completion, timely);
            let witness = RequestRouteWitnessV1::try_from(value).expect("deadline row");
            assert_eq!(
                witness.attempts()[0]
                    .resolution()
                    .expect("resolution")
                    .truth(),
                truth
            );
            assert_eq!(
                matches!(
                    witness.execution(),
                    RouteExecutionV1::IdempotentRead {
                        outcome: RouteOutcomeV1::Selected(_),
                        ..
                    }
                ),
                timely
            );
        }
    }
}

#[test]
fn valid_completion_deadline_table_covers_every_read_mode() {
    for truth in [ResolutionTruth::Success, ResolutionTruth::AuthorizedEmpty] {
        for (completion, timely) in [(4, true), (5, true), (6, false)] {
            let mut quorum = quorum_read();
            quorum.request.request_deadline_millis = 5;
            for attempt in &mut quorum.attempts {
                attempt.envelope.deadline_millis = 5;
                attempt.resolution.as_mut().expect("resolution").truth = truth;
            }
            quorum.attempts[0].envelope.completed_at_millis = Some(3);
            quorum.attempts[1].envelope.completed_at_millis = Some(completion);
            if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut quorum.execution {
                *outcome = if timely {
                    RouteOutcomeDraftV1::Selected {
                        truth,
                        selected_result_digest: "quorum".into(),
                        agreement_attempt_ids: vec!["a1".into(), "a2".into()],
                    }
                } else {
                    RouteOutcomeDraftV1::Partial {
                        evidence_refs: vec!["evidence-a1".into(), "evidence-a2".into()],
                    }
                };
            }
            assert!(RequestRouteWitnessV1::try_from(quorum).is_ok());

            let mut hedged_single = hedged_single();
            hedged_single.request.request_deadline_millis = 10;
            hedged_single.attempts[0] = RouteAttemptDraftV1 {
                envelope: envelope(
                    ("a1", "p1", "i1", 1),
                    AttemptState::Failed,
                    (Some(1), Some(2)),
                    10,
                ),
                resolution: Some(resolution(
                    ResolutionTruth::Timeout,
                    "p1",
                    "i1",
                    None,
                    RecoveryEligibilityV1::None,
                    "failure-a1",
                )),
            };
            hedged_single.attempts[1].envelope.deadline_millis = 10;
            hedged_single.attempts[1].envelope.completed_at_millis = Some(completion + 5);
            hedged_single.attempts[1]
                .resolution
                .as_mut()
                .expect("resolution")
                .truth = truth;
            if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } =
                &mut hedged_single.execution
            {
                *outcome = if timely {
                    RouteOutcomeDraftV1::Selected {
                        truth,
                        selected_result_digest: "secondary".into(),
                        agreement_attempt_ids: vec!["a2".into()],
                    }
                } else {
                    RouteOutcomeDraftV1::Failed {
                        truth: ResolutionTruth::Timeout,
                        evidence_refs: vec!["failure-a1".into(), "evidence-a2".into()],
                    }
                };
            }
            assert!(RequestRouteWitnessV1::try_from(finalize_fixture(hedged_single)).is_ok());

            let mut hedged_quorum = hedged_quorum();
            hedged_quorum.request.request_deadline_millis = 10;
            for attempt in &mut hedged_quorum.attempts {
                attempt.envelope.deadline_millis = 10;
            }
            hedged_quorum.attempts[0]
                .resolution
                .as_mut()
                .expect("resolution")
                .truth = truth;
            hedged_quorum.attempts[0].envelope.completed_at_millis = Some(4);
            hedged_quorum.attempts[2]
                .resolution
                .as_mut()
                .expect("resolution")
                .truth = truth;
            hedged_quorum.attempts[2].envelope.completed_at_millis = Some(completion + 5);
            if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } =
                &mut hedged_quorum.execution
            {
                *outcome = if timely {
                    RouteOutcomeDraftV1::Selected {
                        truth,
                        selected_result_digest: "quorum".into(),
                        agreement_attempt_ids: vec!["a1".into(), "a3".into()],
                    }
                } else {
                    RouteOutcomeDraftV1::Partial {
                        evidence_refs: vec![
                            "evidence-a1".into(),
                            "failure-a2".into(),
                            "evidence-a3".into(),
                        ],
                    }
                };
            }
            assert!(RequestRouteWitnessV1::try_from(hedged_quorum).is_ok());
        }
    }
}

#[test]
fn fixed_quorum_deadline_and_late_evidence_table_is_closed() {
    for (second_digest, second_completion, expected_selected) in [
        ("quorum", 4, true),
        ("quorum", 5, true),
        ("quorum", 6, false),
        ("dissent", 6, false),
    ] {
        let mut value = quorum_read();
        value.request.request_deadline_millis = 5;
        for attempt in &mut value.attempts {
            attempt.envelope.deadline_millis = 5;
        }
        value.attempts[0].envelope.completed_at_millis = Some(3);
        value.attempts[1] = attempt("a2", "p2", "i2", 2, 1, second_completion, second_digest);
        value.attempts[1].envelope.deadline_millis = 5;
        if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut value.execution {
            *outcome = if expected_selected {
                RouteOutcomeDraftV1::Selected {
                    truth: ResolutionTruth::Success,
                    selected_result_digest: "quorum".into(),
                    agreement_attempt_ids: vec!["a1".into(), "a2".into()],
                }
            } else {
                RouteOutcomeDraftV1::Partial {
                    evidence_refs: vec!["evidence-a1".into(), "evidence-a2".into()],
                }
            };
        }
        assert!(RequestRouteWitnessV1::try_from(value).is_ok());
    }

    let mut quorum_after_deadline = quorum_read();
    quorum_after_deadline.request.request_deadline_millis = 5;
    for attempt in &mut quorum_after_deadline.attempts {
        attempt.envelope.deadline_millis = 5;
        attempt.envelope.completed_at_millis = Some(6);
    }
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } =
        &mut quorum_after_deadline.execution
    {
        *outcome = RouteOutcomeDraftV1::Partial {
            evidence_refs: vec!["evidence-a1".into(), "evidence-a2".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(quorum_after_deadline).is_ok());
}

#[test]
fn all_late_route_mode_outcome_table_is_closed() {
    let mut single = single_read();
    set_single_valid_truth(&mut single, ResolutionTruth::Success, 6, false);
    assert!(RequestRouteWitnessV1::try_from(single).is_ok());

    let mut quorum = quorum_read();
    quorum.request.request_deadline_millis = 5;
    for attempt in &mut quorum.attempts {
        attempt.envelope.deadline_millis = 5;
        attempt.envelope.completed_at_millis = Some(6);
    }
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut quorum.execution {
        *outcome = RouteOutcomeDraftV1::Partial {
            evidence_refs: vec!["evidence-a1".into(), "evidence-a2".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(quorum).is_ok());

    let mut hedged_single = hedged_single();
    hedged_single.request.request_deadline_millis = 7;
    for attempt in &mut hedged_single.attempts {
        attempt.envelope.deadline_millis = 7;
        attempt.envelope.completed_at_millis = Some(8 + u64::from(attempt.envelope.ordinal));
    }
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut hedged_single.execution {
        *outcome = RouteOutcomeDraftV1::Failed {
            truth: ResolutionTruth::Timeout,
            evidence_refs: vec!["evidence-a1".into(), "evidence-a2".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(hedged_single).is_ok());

    let mut hedged_quorum = hedged_quorum();
    hedged_quorum.request.request_deadline_millis = 7;
    for attempt in &mut hedged_quorum.attempts {
        attempt.envelope.deadline_millis = 7;
    }
    hedged_quorum.attempts[0].envelope.completed_at_millis = Some(8);
    hedged_quorum.attempts[2].envelope.completed_at_millis = Some(9);
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut hedged_quorum.execution {
        *outcome = RouteOutcomeDraftV1::Partial {
            evidence_refs: vec![
                "evidence-a1".into(),
                "failure-a2".into(),
                "evidence-a3".into(),
            ],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(hedged_quorum).is_ok());
}

#[test]
fn read_temporal_deadline_boundaries_are_closed() {
    let mut at_deadline = single_read();
    at_deadline.request.request_deadline_millis = 5;
    at_deadline.attempts[0].envelope.deadline_millis = 5;
    at_deadline.attempts[0].envelope.started_at_millis = Some(5);
    at_deadline.attempts[0].envelope.completed_at_millis = Some(5);
    assert!(RequestRouteWitnessV1::try_from(at_deadline).is_ok());

    let mut start_after = single_read();
    start_after.request.request_deadline_millis = 5;
    start_after.attempts[0].envelope.deadline_millis = 5;
    start_after.attempts[0].envelope.started_at_millis = Some(6);
    start_after.attempts[0].envelope.completed_at_millis = Some(6);
    assert!(RequestRouteWitnessV1::try_from(start_after).is_err());

    let mut attempt_deadline_before_request = single_read();
    attempt_deadline_before_request.attempts[0]
        .envelope
        .deadline_millis = 2;
    attempt_deadline_before_request.attempts[0]
        .envelope
        .started_at_millis = Some(1);
    attempt_deadline_before_request.attempts[0]
        .envelope
        .completed_at_millis = Some(2);
    assert!(RequestRouteWitnessV1::try_from(attempt_deadline_before_request).is_ok());

    let mut attempt_deadline_after_request = single_read();
    attempt_deadline_after_request.attempts[0]
        .envelope
        .deadline_millis = 101;
    assert!(RequestRouteWitnessV1::try_from(attempt_deadline_after_request).is_err());
}

#[test]
fn late_valid_read_results_are_retained_but_never_selected() {
    let mut late_single = single_read();
    late_single.request.request_deadline_millis = 5;
    late_single.attempts[0].envelope.deadline_millis = 5;
    late_single.attempts[0].envelope.completed_at_millis = Some(6);
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut late_single.execution {
        *outcome = RouteOutcomeDraftV1::Failed {
            truth: ResolutionTruth::Timeout,
            evidence_refs: vec!["evidence-a1".into()],
        };
    }
    let witness = RequestRouteWitnessV1::try_from(late_single).expect("late result retained");
    assert_eq!(
        witness.attempts()[0]
            .resolution()
            .expect("resolution")
            .truth(),
        ResolutionTruth::Success
    );
    assert!(matches!(
        witness.execution(),
        RouteExecutionV1::IdempotentRead {
            outcome: RouteOutcomeV1::Failed {
                truth: ResolutionTruth::Timeout,
                ..
            },
            ..
        }
    ));

    let mut timely_and_late_quorum = quorum_read();
    timely_and_late_quorum.request.request_deadline_millis = 5;
    for attempt in &mut timely_and_late_quorum.attempts {
        attempt.envelope.deadline_millis = 5;
    }
    timely_and_late_quorum.attempts[1]
        .envelope
        .completed_at_millis = Some(6);
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } =
        &mut timely_and_late_quorum.execution
    {
        *outcome = RouteOutcomeDraftV1::Partial {
            evidence_refs: vec!["evidence-a1".into(), "evidence-a2".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(timely_and_late_quorum).is_ok());

    let mut all_late_hedged = hedged_single();
    all_late_hedged.request.request_deadline_millis = 7;
    for attempt in &mut all_late_hedged.attempts {
        attempt.envelope.deadline_millis = 7;
        attempt.envelope.completed_at_millis = Some(8 + u64::from(attempt.envelope.ordinal));
    }
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut all_late_hedged.execution {
        *outcome = RouteOutcomeDraftV1::Failed {
            truth: ResolutionTruth::Timeout,
            evidence_refs: vec!["evidence-a1".into(), "evidence-a2".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(all_late_hedged).is_ok());

    let mut late_dissent = hedged_quorum();
    late_dissent.request.request_deadline_millis = 8;
    for attempt in &mut late_dissent.attempts {
        attempt.envelope.deadline_millis = 8;
    }
    late_dissent.attempts[0].envelope.completed_at_millis = Some(4);
    late_dissent.attempts[1] = attempt("a2", "p2", "i2", 2, 1, 7, "quorum");
    late_dissent.attempts[1].envelope.deadline_millis = 8;
    late_dissent.attempts[2] = attempt("a3", "p3", "i3", 3, 6, 9, "dissent");
    late_dissent.attempts[2].envelope.deadline_millis = 8;
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut late_dissent.execution {
        *outcome = RouteOutcomeDraftV1::Selected {
            truth: ResolutionTruth::Success,
            selected_result_digest: "quorum".into(),
            agreement_attempt_ids: vec!["a1".into(), "a2".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(finalize_fixture(late_dissent)).is_ok());
}

#[test]
fn recovery_start_requires_positive_remaining_time() {
    let mut before_deadline = recovery_read();
    before_deadline.attempts[1].envelope.started_at_millis = Some(89);
    before_deadline.attempts[1].envelope.completed_at_millis = Some(90);
    assert!(RequestRouteWitnessV1::try_from(before_deadline).is_ok());

    let mut at_deadline = recovery_read();
    at_deadline.attempts[1].envelope.started_at_millis = Some(90);
    at_deadline.attempts[1].envelope.completed_at_millis = Some(90);
    assert!(RequestRouteWitnessV1::try_from(at_deadline).is_err());

    let mut after_deadline = recovery_read();
    after_deadline.attempts[1].envelope.started_at_millis = Some(91);
    after_deadline.attempts[1].envelope.completed_at_millis = Some(91);
    assert!(RequestRouteWitnessV1::try_from(after_deadline).is_err());
}

#[test]
fn hedge_qualification_and_canonical_blocking_table_is_closed() {
    let mut qualified_late = hedged_single();
    qualified_late.request.request_deadline_millis = 7;
    qualified_late.attempts[0] = RouteAttemptDraftV1 {
        envelope: envelope(
            ("a1", "p1", "i1", 1),
            AttemptState::Failed,
            (Some(1), Some(2)),
            7,
        ),
        resolution: Some(resolution(
            ResolutionTruth::Timeout,
            "p1",
            "i1",
            None,
            RecoveryEligibilityV1::None,
            "failure-a1",
        )),
    };
    qualified_late.attempts[1].envelope.deadline_millis = 7;
    qualified_late.attempts[1].envelope.completed_at_millis = Some(8);
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut qualified_late.execution {
        *outcome = RouteOutcomeDraftV1::Failed {
            truth: ResolutionTruth::Timeout,
            evidence_refs: vec!["failure-a1".into(), "evidence-a2".into()],
        };
    }
    assert!(RequestRouteWitnessV1::try_from(finalize_fixture(qualified_late)).is_ok());

    let mut after_timely_canonical = hedged_single();
    after_timely_canonical.attempts[0]
        .envelope
        .completed_at_millis = Some(5);
    after_timely_canonical.attempts[1]
        .envelope
        .started_at_millis = Some(6);
    assert!(RequestRouteWitnessV1::try_from(after_timely_canonical).is_err());
}

#[test]
fn serialized_witness_retains_temporal_ownership_agreement_and_late_evidence() {
    fn assert_serialize<T: serde::Serialize>() {}
    assert_serialize::<RequestRouteWitnessV1>();

    let mut value = hedged_quorum();
    value.request.request_deadline_millis = 8;
    for attempt in &mut value.attempts {
        attempt.envelope.deadline_millis = 8;
    }
    value.attempts[0].envelope.completed_at_millis = Some(4);
    value.attempts[1] = attempt("a2", "p2", "i2", 2, 1, 7, "quorum");
    value.attempts[1].envelope.deadline_millis = 8;
    value.attempts[2] = attempt("a3", "p3", "i3", 3, 6, 9, "late-dissent");
    value.attempts[2].envelope.deadline_millis = 8;
    if let RouteExecutionDraftV1::IdempotentRead { outcome, .. } = &mut value.execution {
        *outcome = RouteOutcomeDraftV1::Selected {
            truth: ResolutionTruth::Success,
            selected_result_digest: "quorum".into(),
            agreement_attempt_ids: vec!["a1".into(), "a2".into()],
        };
    }

    let witness = RequestRouteWitnessV1::try_from(finalize_fixture(value))
        .expect("retained temporal witness");
    let RouteExecutionV1::IdempotentRead {
        primary_attempt_ids,
        hedge_attempt_ids,
        outcome: RouteOutcomeV1::Selected(selected),
        ..
    } = witness.execution()
    else {
        panic!("selected read")
    };
    assert_eq!(
        primary_attempt_ids
            .iter()
            .map(AttemptId::as_str)
            .collect::<Vec<_>>(),
        ["a1", "a2"]
    );
    assert_eq!(
        hedge_attempt_ids
            .iter()
            .map(AttemptId::as_str)
            .collect::<Vec<_>>(),
        ["a3"]
    );
    assert_eq!(
        selected
            .agreement_attempt_ids()
            .iter()
            .map(AttemptId::as_str)
            .collect::<Vec<_>>(),
        ["a1", "a2"]
    );
    let late = &witness.attempts()[2];
    assert_eq!(terminal_completion(late), Some(9));
    assert_eq!(
        late.resolution().expect("late resolution").evidence_refs()[0].as_str(),
        "evidence-a3"
    );
    assert_eq!(
        late.resolution()
            .expect("late resolution")
            .normalized_response_digest()
            .expect("late digest")
            .as_str(),
        "late-dissent"
    );
}

#[test]
fn validated_witness_retains_every_admission_fact() {
    let witness = RequestRouteWitnessV1::try_from(recovery_read()).expect("witness");
    assert_eq!(witness.request().request_id, "request");
    assert_eq!(witness.request_digest().as_str(), "request-digest");
    assert_eq!(witness.eligibility().admitted_profiles().len(), 2);
    assert_eq!(witness.attempts().len(), 2);
    let RouteExecutionV1::IdempotentRead {
        route_plan,
        primary_attempt_ids,
        hedge_attempt_ids,
        recoveries,
        outcome,
    } = witness.execution()
    else {
        panic!("read execution")
    };
    assert!(matches!(
        route_plan,
        RoutePlanV1::HedgedSingle {
            hedge_threshold_millis: 5
        }
    ));
    assert_eq!(primary_attempt_ids[0].as_str(), "a1");
    assert!(hedge_attempt_ids.is_empty());
    assert_eq!(recoveries[0].next_attempt_id.as_str(), "a2");
    assert!(matches!(outcome, RouteOutcomeV1::Selected(_)));
    assert_eq!(
        witness.attempts()[0]
            .resolution()
            .expect("resolution")
            .recovery_eligibility(),
        RecoveryEligibilityV1::FailoverWithinSnapshot
    );
}

#[test]
fn i06_gate2_provider_common_and_identity_drift_table_rejects() {
    let base = profile(
        "p1",
        "i1",
        IdempotencyClass::IdempotentRead,
        RoutePlanDraftV1::SingleExact,
        0,
    );
    assert!(validate_provider_profile(&base).is_ok());
    let route_request = request(IdempotencyClass::IdempotentRead);
    macro_rules! rejects_drift {
        ($name:literal, $mutation:expr) => {{
            let mut drifted = base.clone();
            ($mutation)(&mut drifted);
            assert!(
                validate_profile_request_binding(&route_request, &[base.clone(), drifted]).is_err(),
                "{}",
                $name
            );
        }};
    }
    rejects_drift!("profile_version", |value: &mut ProviderProfileV1| value
        .profile_version =
        "2".into());
    rejects_drift!("configuration", |value: &mut ProviderProfileV1| value
        .configuration_digest =
        "drift".into());
    rejects_drift!("chain", |value: &mut ProviderProfileV1| value.chain_id =
        "2".into());
    rejects_drift!("genesis", |value: &mut ProviderProfileV1| value
        .genesis_hash =
        "other".into());
    rejects_drift!("network", |value: &mut ProviderProfileV1| value
        .network_id =
        "other".into());
    rejects_drift!("trust_epoch", |value: &mut ProviderProfileV1| value
        .trust_epoch =
        2);
    rejects_drift!("json_rpc_version", |value: &mut ProviderProfileV1| value
        .json_rpc_version =
        "2.1".into());
    rejects_drift!("method_data_classes", |value: &mut ProviderProfileV1| value
        .method_data_classes
        .push(MethodDataClass {
            method: "eth_getLogs".into(),
            data_class: "event-log".into()
        }));
    rejects_drift!("request_schema", |value: &mut ProviderProfileV1| value
        .request_schema_digest =
        "drift".into());
    rejects_drift!("response_schema", |value: &mut ProviderProfileV1| value
        .response_schema_digest =
        "drift".into());
    rejects_drift!("normalization", |value: &mut ProviderProfileV1| value
        .normalization_rule_digest =
        "drift".into());
    rejects_drift!("max_request_bytes", |value: &mut ProviderProfileV1| {
        value.limits.max_request_bytes += 1
    });
    rejects_drift!("max_response_bytes", |value: &mut ProviderProfileV1| {
        value.limits.max_response_bytes += 1
    });
    rejects_drift!("max_range", |value: &mut ProviderProfileV1| value
        .limits
        .max_range +=
        1);
    rejects_drift!("max_batch", |value: &mut ProviderProfileV1| value
        .limits
        .max_batch +=
        1);
    rejects_drift!("privacy", |value: &mut ProviderProfileV1| value
        .privacy_behavior_digest =
        "drift".into());
    rejects_drift!("failure", |value: &mut ProviderProfileV1| value
        .failure_behavior_digest =
        "drift".into());
    rejects_drift!("rate", |value: &mut ProviderProfileV1| value
        .rate_limit_contract_digest =
        "drift".into());
    rejects_drift!("capability", |value: &mut ProviderProfileV1| value
        .capability_profile_digest =
        "drift".into());
    rejects_drift!("classification", |value: &mut ProviderProfileV1| value
        .maximum_response_classification =
        "public".into());
    rejects_drift!("idempotency", |value: &mut ProviderProfileV1| value
        .idempotency =
        IdempotencyClass::GovernedWrite);
    rejects_drift!("route_plan", |value: &mut ProviderProfileV1| value
        .route_plan =
        RoutePlanDraftV1::HedgedSingle {
            hedge_threshold_millis: 5
        });
    rejects_drift!("retry_budget", |value: &mut ProviderProfileV1| value
        .read_retry_budget =
        1);
    rejects_drift!("timeout", |value: &mut ProviderProfileV1| value
        .timeout_budget_millis +=
        1);
    rejects_drift!("corpus", |value: &mut ProviderProfileV1| value
        .corpus_digest =
        "drift".into());
    rejects_drift!("receipt", |value: &mut ProviderProfileV1| value
        .conformance_receipt_digest =
        "drift".into());
    rejects_drift!("lifecycle", |value: &mut ProviderProfileV1| value
        .lifecycle =
        ProfileLifecycle::Qualified);
    let mut identity = base.clone();
    identity.profile_id = "profile-i2".into();
    identity.profile_digest = "p2".into();
    identity.provider_instance_id = "i2".into();
    identity.provider_release_digest = "release-i2".into();
    identity.provider_build_digest = "build-i2".into();
    identity.tls_credential_identity = "credential-i2".into();
    identity.tls_credential_fingerprint = "fingerprint-i2".into();
    assert!(
        validate_profile_request_binding(
            &request(IdempotencyClass::IdempotentRead),
            &[base.clone(), identity]
        )
        .is_ok()
    );
    let mut methods = base.clone();
    methods.method_data_classes.push(method());
    assert!(validate_provider_profile(&methods).is_err());
    let mut evidence = base.clone();
    evidence.evidence_refs.push("profile-evidence".into());
    assert!(validate_provider_profile(&evidence).is_err());

    let mut unordered = base;
    unordered.method_data_classes.push(MethodDataClass {
        method: "eth_getLogs".into(),
        data_class: "event-log".into(),
    });
    unordered.method_data_classes.reverse();
    unordered.evidence_refs = vec!["z-evidence".into(), "a-evidence".into()];
    let mut profiles = vec![unordered];
    canonicalize_provider_order_with_excluded("permutation", &mut profiles, &mut [], &mut []);
    assert_eq!(profiles[0].method_data_classes[0].method, "eth_call");
    assert_eq!(profiles[0].evidence_refs, ["a-evidence", "z-evidence"]);
}

#[test]
fn i06_gate2_provider_order_is_constructor_owned_and_permutation_invariant() {
    let canonical = RequestRouteWitnessV1::try_from(hedged_single()).expect("canonical fixture");
    let mut profile_permutation = hedged_single();
    profile_permutation.admitted_profiles.reverse();
    let permuted =
        RequestRouteWitnessV1::try_from(profile_permutation).expect("profile permutation");
    assert_eq!(
        canonical.eligibility().admitted_profiles(),
        permuted.eligibility().admitted_profiles()
    );
    assert!(
        canonical
            .eligibility()
            .order_derivation()
            .starts_with("openpc:provider-order:v1:")
    );
    assert_eq!(
        canonical.eligibility().order_derivation(),
        permuted.eligibility().order_derivation()
    );
    assert_eq!(
        canonical
            .eligibility()
            .admitted_profiles()
            .iter()
            .map(|profile| profile.provider_instance_id.as_str())
            .collect::<Vec<_>>(),
        ["i2", "i1"]
    );

    let mut exclusions_a = hedged_single();
    exclusions_a.exclusions = vec![
        ProviderExclusionV1 {
            profile_digest: "excluded-a".into(),
            provider_instance_id: "excluded-instance-a".into(),
            reason: ProviderExclusionReason::HealthRemoved,
        },
        ProviderExclusionV1 {
            profile_digest: "excluded-b".into(),
            provider_instance_id: "excluded-instance-b".into(),
            reason: ProviderExclusionReason::RateLimited,
        },
    ];
    let excluded_profiles = vec![
        profile(
            "excluded-a",
            "excluded-instance-a",
            IdempotencyClass::IdempotentRead,
            RoutePlanDraftV1::HedgedSingle {
                hedge_threshold_millis: 5,
            },
            0,
        ),
        profile(
            "excluded-b",
            "excluded-instance-b",
            IdempotencyClass::IdempotentRead,
            RoutePlanDraftV1::HedgedSingle {
                hedge_threshold_millis: 5,
            },
            0,
        ),
    ];
    let mut exclusions_b = exclusions_a.exclusions.clone();
    exclusions_b.reverse();
    let mut admitted_a = exclusions_a.admitted_profiles.clone();
    let mut admitted_b = admitted_a.clone();
    let mut excluded_a = excluded_profiles.clone();
    let mut excluded_b = excluded_profiles;
    excluded_b.reverse();
    let order_a = canonicalize_provider_order_with_excluded(
        &exclusions_a.request_digest,
        &mut admitted_a,
        &mut excluded_a,
        &mut exclusions_a.exclusions,
    );
    let order_b = canonicalize_provider_order_with_excluded(
        &exclusions_a.request_digest,
        &mut admitted_b,
        &mut excluded_b,
        &mut exclusions_b,
    );
    assert_eq!(admitted_a, admitted_b);
    assert_eq!(exclusions_a.exclusions, exclusions_b);
    assert_eq!(order_a, order_b);
    assert_eq!(
        compare_provider_order_keys(7, b"a", 7, b"b"),
        std::cmp::Ordering::Less
    );

    let mut coordinated = hedged_single();
    coordinated.admitted_profiles.reverse();
    coordinated.attempts.swap(0, 1);
    coordinated.attempts[0].envelope.ordinal = 1;
    coordinated.attempts[1].envelope.ordinal = 2;
    if let RouteExecutionDraftV1::IdempotentRead {
        primary_attempt_ids,
        hedge_attempt_ids,
        ..
    } = &mut coordinated.execution
    {
        *primary_attempt_ids = vec!["a2".into()];
        *hedge_attempt_ids = vec!["a1".into()];
    }
    assert!(RequestRouteWitnessV1::try_from(coordinated).is_err());
}

#[test]
fn route_request_accepts() {
    let value = request(IdempotencyClass::IdempotentRead);
    assert!(validate_route_request(&value).is_ok());
    for mutate in [
        |v: &mut RouteRequestV1| v.request_id.clear(),
        |v: &mut RouteRequestV1| v.authority_context_digest.clear(),
        |v: &mut RouteRequestV1| v.participant_binding.clear(),
        |v: &mut RouteRequestV1| v.privacy_binding.clear(),
        |v: &mut RouteRequestV1| v.workload_binding.clear(),
        |v: &mut RouteRequestV1| v.action_intent.clear(),
        |v: &mut RouteRequestV1| v.method.clear(),
        |v: &mut RouteRequestV1| v.data_class.clear(),
        |v: &mut RouteRequestV1| v.normalized_parameter_digest.clear(),
        |v: &mut RouteRequestV1| v.required_capability_profile_digest.clear(),
        |v: &mut RouteRequestV1| v.maximum_response_classification.clear(),
        |v: &mut RouteRequestV1| v.request_deadline_millis = 0,
        |v: &mut RouteRequestV1| v.evidence_correlation_id.clear(),
    ] {
        let mut drift = value.clone();
        mutate(&mut drift);
        assert!(validate_route_request(&drift).is_err());
    }
}

#[test]
fn execution_contract_derives_request_digest_and_closes_snapshot() {
    let route_request = request(IdempotencyClass::IdempotentRead);
    let identity_bytes = crate::execution::encode_route_request_identity(&route_request)
        .expect("canonical route request identity bytes");
    let identity_hex = identity_bytes.iter().fold(
        String::with_capacity(identity_bytes.len() * 2),
        |mut output, byte| {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("write to String");
            output
        },
    );
    assert_eq!(identity_hex, ROUTE_REQUEST_FIXTURE_PC_CBOR_HEX);
    let first = profile(
        "p1",
        "i1",
        IdempotencyClass::IdempotentRead,
        RoutePlanDraftV1::SingleExact,
        0,
    );
    let contract =
        RouteExecutionContractV1::try_new(route_request.clone(), vec![first.clone()], vec![], None)
            .expect("closed pre-execution contract");
    assert_eq!(contract.request(), &route_request);
    assert_eq!(contract.original_profiles(), std::slice::from_ref(&first));
    assert_eq!(
        contract.eligibility().admitted_profiles(),
        std::slice::from_ref(&first)
    );
    assert_eq!(contract.effective_deadline_millis(), 100);
    assert_eq!(contract.read_retry_budget(), 0);
    assert_eq!(contract.route_plan(), &RoutePlanV1::SingleExact);
    let key = ProviderKeyV1 {
        profile_digest: ProviderProfileDigest::new("p1").expect("profile digest"),
        provider_instance_id: ProviderInstanceId::new("i1").expect("provider instance"),
    };
    assert_eq!(contract.provider_limits(&key), Some(&first.limits));
    let mut second = profile(
        "p2",
        "i2",
        IdempotencyClass::IdempotentRead,
        RoutePlanDraftV1::HedgedSingle {
            hedge_threshold_millis: 5,
        },
        1,
    );
    let mut third = profile(
        "p3",
        "i3",
        IdempotencyClass::IdempotentRead,
        second.route_plan.clone(),
        1,
    );
    let mut fourth = profile(
        "p4",
        "i4",
        IdempotencyClass::IdempotentRead,
        second.route_plan.clone(),
        1,
    );
    let mut hedged_request = request(IdempotencyClass::IdempotentRead);
    second.timeout_budget_millis = 80;
    third.timeout_budget_millis = 80;
    fourth.timeout_budget_millis = 80;
    hedged_request.request_deadline_millis = 90;
    let exclusion = ProviderExclusionV1 {
        profile_digest: third.profile_digest.clone(),
        provider_instance_id: third.provider_instance_id.clone(),
        reason: ProviderExclusionReason::HealthRemoved,
    };
    let closed = RouteExecutionContractV1::try_new(
        hedged_request.clone(),
        vec![third.clone(), fourth.clone(), second.clone()],
        vec![exclusion.clone()],
        None,
    )
    .expect("closed admitted/excluded snapshot");
    let permuted = RouteExecutionContractV1::try_new(
        hedged_request,
        vec![second.clone(), fourth.clone(), third.clone()],
        vec![exclusion],
        None,
    )
    .expect("permuted closed snapshot");
    assert_eq!(
        closed.original_profiles(),
        &[second.clone(), third.clone(), fourth.clone()]
    );
    assert_eq!(closed.original_profiles(), permuted.original_profiles());
    assert_eq!(
        closed.eligibility().admitted_profiles(),
        permuted.eligibility().admitted_profiles()
    );
    assert_eq!(closed.eligibility().admitted_profiles().len(), 2);
    assert_eq!(closed.eligibility().excluded().len(), 1);
    assert_eq!(
        closed.eligibility().excluded()[0]
            .key
            .profile_digest
            .as_str(),
        "p3"
    );
    assert_eq!(
        closed.eligibility().excluded()[0]
            .key
            .provider_instance_id
            .as_str(),
        "i3"
    );
    assert_eq!(closed.effective_deadline_millis(), 80);
    assert_eq!(closed.read_retry_budget(), 1);
    assert_eq!(
        closed.route_plan(),
        &RoutePlanV1::HedgedSingle {
            hedge_threshold_millis: 5
        }
    );
    assert!(!closed.eligibility().order_derivation().is_empty());
    assert_eq!(
        closed.eligibility().order_derivation(),
        permuted.eligibility().order_derivation()
    );

    assert!(
        RouteExecutionContractV1::try_new(
            route_request.clone(),
            vec![first.clone()],
            vec![],
            Some("caller-controlled-digest"),
        )
        .is_err()
    );
    let mut wrong_request = route_request.clone();
    wrong_request.required_capability_profile_digest = "wrong".into();
    assert!(
        RouteExecutionContractV1::try_new(wrong_request, vec![first.clone()], vec![], None,)
            .is_err()
    );
    let mut duplicate = first.clone();
    duplicate.profile_id = "duplicate".into();
    assert!(
        RouteExecutionContractV1::try_new(route_request, vec![first, duplicate], vec![], None,)
            .is_err()
    );

    let base_request = request(IdempotencyClass::IdempotentRead);
    for mutate in [
        |value: &mut RouteRequestV1| value.request_id.clear(),
        |value: &mut RouteRequestV1| value.authority_context_digest.clear(),
        |value: &mut RouteRequestV1| value.normalized_parameter_digest.clear(),
    ] {
        let mut changed = base_request.clone();
        mutate(&mut changed);
        assert_eq!(
            RouteExecutionContractV1::try_new(
                changed,
                vec![profile(
                    "p1",
                    "i1",
                    IdempotencyClass::IdempotentRead,
                    RoutePlanDraftV1::SingleExact,
                    0,
                )],
                vec![],
                None,
            )
            .expect_err("invalid request must fail before execution"),
            ProviderContractError::Invalid("route execution contract")
        );
    }
    let one = profile(
        "p1",
        "i1",
        IdempotencyClass::IdempotentRead,
        RoutePlanDraftV1::SingleExact,
        0,
    );
    let bad_exclusion = ProviderExclusionV1 {
        profile_digest: "missing".into(),
        provider_instance_id: "missing".into(),
        reason: ProviderExclusionReason::Stale,
    };
    assert!(
        RouteExecutionContractV1::try_new(
            base_request.clone(),
            vec![one.clone()],
            vec![bad_exclusion],
            None,
        )
        .is_err()
    );
    let mut duplicate_instance = one.clone();
    duplicate_instance.profile_id = "other-profile".into();
    duplicate_instance.profile_digest = "other-digest".into();
    assert!(
        RouteExecutionContractV1::try_new(
            base_request.clone(),
            vec![one.clone(), duplicate_instance],
            vec![],
            None,
        )
        .is_err()
    );
    for mutate in [
        |value: &mut ProviderProfileV1| {
            value.route_plan = RoutePlanDraftV1::QuorumIdentical {
                required_agreement: 2,
            }
        },
        |value: &mut ProviderProfileV1| value.timeout_budget_millis = 0,
        |value: &mut ProviderProfileV1| value.limits.max_response_bytes = 0,
    ] {
        let mut inconsistent = one.clone();
        mutate(&mut inconsistent);
        assert!(
            RouteExecutionContractV1::try_new(
                base_request.clone(),
                vec![inconsistent],
                vec![],
                None,
            )
            .is_err()
        );
    }
    assert_eq!(
        contract.request_digest().as_str(),
        ROUTE_REQUEST_FIXTURE_DIGEST
    );
}

#[test]
fn anchor_accepts() {
    assert!(validate_chain_anchor(&anchor()).is_ok());
    let mut pending = anchor();
    pending.selector_kind = BlockSelectorKind::Pending;
    pending.block_number = None;
    pending.block_hash = None;
    pending.pending_authorized_by_profile = true;
    assert!(validate_chain_anchor(&pending).is_ok());
    for mutate in [
        |v: &mut ChainReadAnchorV1| v.chain_id.clear(),
        |v: &mut ChainReadAnchorV1| v.genesis_hash.clear(),
        |v: &mut ChainReadAnchorV1| v.network_id.clear(),
        |v: &mut ChainReadAnchorV1| v.block_number = None,
        |v: &mut ChainReadAnchorV1| v.block_hash = None,
        |v: &mut ChainReadAnchorV1| v.pending_authorized_by_profile = true,
    ] {
        let mut drift = anchor();
        mutate(&mut drift);
        assert!(validate_chain_anchor(&drift).is_err());
    }
}

#[test]
fn distinct_identity_accepts() {
    let first = profile(
        "p1",
        "i1",
        IdempotencyClass::IdempotentRead,
        RoutePlanDraftV1::HedgedSingle {
            hedge_threshold_millis: 5,
        },
        0,
    );
    let mut second = first.clone();
    second.profile_id = "profile-i2".into();
    second.profile_digest = "p2".into();
    second.provider_instance_id = "i2".into();
    second.provider_release_digest = "release-i2".into();
    second.provider_build_digest = "build-i2".into();
    second.tls_credential_identity = "credential-i2".into();
    second.tls_credential_fingerprint = "fingerprint-i2".into();
    assert!(
        validate_profile_request_binding(
            &request(IdempotencyClass::IdempotentRead),
            &[first.clone(), second]
        )
        .is_ok()
    );
    assert!(
        validate_profile_request_binding(
            &request(IdempotencyClass::IdempotentRead),
            &[first.clone(), first]
        )
        .is_ok()
    );
    let mut duplicate = hedged_single();
    duplicate.admitted_profiles[1] = duplicate.admitted_profiles[0].clone();
    assert!(RequestRouteWitnessV1::try_from(duplicate).is_err());
}

#[test]
fn common_equivalence_accepts() {
    i06_gate2_provider_common_and_identity_drift_table_rejects();
}

#[test]
fn request_bound_fields_accept() {
    let value = single_read();
    assert!(RequestRouteWitnessV1::try_from(value.clone()).is_ok());
    for mutate in [
        |v: &mut RequestRouteWitnessDraftV1| v.request.anchor.chain_id = "other".into(),
        |v: &mut RequestRouteWitnessDraftV1| {
            v.request.required_capability_profile_digest = "other".into()
        },
        |v: &mut RequestRouteWitnessDraftV1| {
            v.request.maximum_response_classification = "other".into()
        },
        |v: &mut RequestRouteWitnessDraftV1| v.request.method = "other".into(),
    ] {
        let mut drift = value.clone();
        mutate(&mut drift);
        assert!(RequestRouteWitnessV1::try_from(drift).is_err());
    }
}

#[test]
fn profile_nested_values_accept() {
    let value = profile(
        "p1",
        "i1",
        IdempotencyClass::IdempotentRead,
        RoutePlanDraftV1::SingleExact,
        0,
    );
    assert!(validate_provider_profile(&value).is_ok());
    for mutate in [
        |v: &mut ProviderProfileV1| v.limits.max_request_bytes = 0,
        |v: &mut ProviderProfileV1| v.limits.max_response_bytes = 0,
        |v: &mut ProviderProfileV1| v.limits.max_range = 0,
        |v: &mut ProviderProfileV1| v.limits.max_batch = 0,
        |v: &mut ProviderProfileV1| v.evidence_refs[0].clear(),
        |v: &mut ProviderProfileV1| v.method_data_classes[0].method.clear(),
    ] {
        let mut drift = value.clone();
        mutate(&mut drift);
        assert!(validate_provider_profile(&drift).is_err());
    }
}

#[test]
fn exclusions_accept() {
    let mut value = single_read();
    let mut excluded_profiles = vec![profile(
        "excluded",
        "excluded-instance",
        IdempotencyClass::IdempotentRead,
        RoutePlanDraftV1::SingleExact,
        1,
    )];
    value.exclusions.push(ProviderExclusionV1 {
        profile_digest: "excluded".into(),
        provider_instance_id: "excluded-instance".into(),
        reason: ProviderExclusionReason::HealthRemoved,
    });
    let value = finalize_fixture_with_excluded(value, &mut excluded_profiles);
    let excluded_profile = excluded_profiles[0].clone();
    assert!(RequestRouteWitnessV1::try_from(value.clone()).is_err());
    let accepted = RequestRouteWitnessV1::try_from_with_excluded_profiles(
        value.clone(),
        vec![excluded_profile.clone()],
    );
    assert!(accepted.is_ok(), "{accepted:?}");
    let mut unresolved = value.clone();
    unresolved.exclusions[0].provider_instance_id = "wrong".into();
    assert!(
        RequestRouteWitnessV1::try_from_with_excluded_profiles(
            unresolved,
            vec![excluded_profile.clone()]
        )
        .is_err()
    );
    let mut duplicate = value;
    duplicate.exclusions.push(duplicate.exclusions[0].clone());
    assert!(
        RequestRouteWitnessV1::try_from_with_excluded_profiles(duplicate, vec![excluded_profile])
            .is_err()
    );
}

#[test]
fn four_route_laws_accept() {
    assert!(RequestRouteWitnessV1::try_from(single_read()).is_ok());
    assert!(RequestRouteWitnessV1::try_from(quorum_read()).is_ok());
    assert!(RequestRouteWitnessV1::try_from(hedged_single()).is_ok());
    assert!(RequestRouteWitnessV1::try_from(hedged_quorum()).is_ok());
}

#[test]
fn resolution_truth_matrix_accepts() {
    resolution_truth_and_recovery_eligibility_table_is_closed();
}

#[test]
fn recovery_matrix_accepts() {
    retry_failover_require_observed_eligible_failure_and_remaining_budgets();
}

#[test]
fn outcome_derivation_accepts() {
    terminal_outcome_derivation_table_is_closed();
}

#[test]
fn whole_witness_round_trip_accepts() {
    let witness = RequestRouteWitnessV1::try_from(hedged_quorum()).expect("witness");
    assert_eq!(witness.request().request_id, "request");
    assert_eq!(witness.attempts().len(), 3);
    assert!(matches!(
        witness.execution(),
        RouteExecutionV1::IdempotentRead { .. }
    ));
}

#[test]
fn canonical_order_request_context_vectors() {
    let base = hedged_single();
    let first = RequestRouteWitnessV1::try_from(base.clone()).expect("base vector");
    let mut changed = base;
    changed.request_digest = "request-digest-changed".into();
    for attempt in &mut changed.attempts {
        attempt.envelope.immutable_request_digest = changed.request_digest.clone();
    }
    if let RouteExecutionDraftV1::IdempotentRead { recoveries, .. } = &mut changed.execution {
        for recovery in recoveries {
            recovery.immutable_request_digest = changed.request_digest.clone();
        }
    }
    changed = finalize_fixture(changed);
    let changed = RequestRouteWitnessV1::try_from(changed).expect("changed vector");
    let first_order = first
        .eligibility()
        .admitted_profiles()
        .iter()
        .map(|profile| profile.provider_instance_id.as_str())
        .collect::<Vec<_>>();
    let changed_order = changed
        .eligibility()
        .admitted_profiles()
        .iter()
        .map(|profile| profile.provider_instance_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(first_order, ["i2", "i1"]);
    assert_eq!(changed_order, ["i1", "i2"]);
    assert_eq!(
        first.eligibility().order_derivation(),
        "openpc:provider-order:v1:2ed65005cae3e0f25b4c7cd39e89512d"
    );
    assert_eq!(
        changed.eligibility().order_derivation(),
        "openpc:provider-order:v1:f359b1b904a3db595c14929d2e2cf664"
    );
}

#[test]
fn provider_order_lifecycle_encoding_matches_independent_vectors() {
    // Independently calculated length-framed FNV-128 vectors. The original
    // lifecycle assignments remain fixed; additions get a distinct encoding.
    let vectors = [
        (ProfileLifecycle::Draft, "a2db4193cb2d21a2c252c45c9c73fd6d"),
        (
            ProfileLifecycle::Validated,
            "e74f52b0a8952917089f350f5357e81d",
        ),
        (
            ProfileLifecycle::Qualified,
            "4aeeba113771c45d3afcdb85ff750345",
        ),
        (ProfileLifecycle::Active, "2ed65005cae3e0f25b4c7cd39e89512d"),
        (
            ProfileLifecycle::Quarantined,
            "a05d1a7cbe44f6c5867501ba28ec6245",
        ),
        (
            ProfileLifecycle::Disabled,
            "e8fed8d90b441c9e8a0294e1bb76f915",
        ),
        (
            ProfileLifecycle::Retired,
            "1208bf41bc81c300dea29287229da2a5",
        ),
        (
            ProfileLifecycle::Uninstalled,
            "70210190ae7088377626a900acda07dd",
        ),
        (
            ProfileLifecycle::BoundedQa,
            "74252ea5f194d8674f3d3a0e491910ed",
        ),
    ];
    for (lifecycle, expected) in vectors {
        let mut value = hedged_single();
        for profile in &mut value.admitted_profiles {
            profile.lifecycle = lifecycle;
        }
        let actual = canonicalize_provider_order_with_excluded(
            &value.request_digest,
            &mut value.admitted_profiles,
            &mut [],
            &mut value.exclusions,
        );
        assert_eq!(actual, format!("openpc:provider-order:v1:{expected}"));
    }
}
