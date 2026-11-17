use super::*;

fn validate_write_attempt(attempt: &RouteAttemptV1) -> Result<(), ProviderContractError> {
    if attempt
        .resolution()
        .is_some_and(|resolution| resolution.recovery_eligibility() != RecoveryEligibilityV1::None)
    {
        return Err(invalid("governed write cannot authorize read recovery"));
    }
    match (attempt.envelope().lifecycle(), attempt.resolution()) {
        (AttemptLifecycleV1::Resolved { .. }, Some(AttemptResolutionV2::Success(_)))
        | (AttemptLifecycleV1::Prepared, None)
        | (AttemptLifecycleV1::Started(_), None)
        | (AttemptLifecycleV1::ResponseObserved { .. }, None) => Ok(()),
        (AttemptLifecycleV1::FailedPreStart { .. }, Some(value))
            if matches!(
                value.truth(),
                ResolutionTruth::Unavailable
                    | ResolutionTruth::RateLimited
                    | ResolutionTruth::Timeout
                    | ResolutionTruth::Invalid
                    | ResolutionTruth::Denied
            ) =>
        {
            Ok(())
        }
        (AttemptLifecycleV1::Unknown { .. }, Some(AttemptResolutionV2::TerminalFailure(value)))
            if value.truth == ResolutionTruth::WriteAmbiguity =>
        {
            Ok(())
        }
        _ => Err(invalid("governed write terminal admissibility")),
    }
}

pub(super) fn validate_write_execution(
    context: &WitnessValidationContext<'_>,
    attempt_values: Vec<String>,
    reconciliation_observation_profiles: Vec<ProviderProfileV1>,
    submitted_progress: GovernedWriteProgressDraftV1,
) -> Result<RouteExecutionV1, ProviderContractError> {
    let request = context.request;
    let request_digest = context.request_digest;
    let eligibility = context.eligibility;
    let attempts = context.attempts;
    let attempts_by_id = context.attempts_by_id;
    if request.idempotency != IdempotencyClass::GovernedWrite
        || eligibility
            .admitted_profiles
            .iter()
            .any(|profile| !matches!(profile.route_plan, RoutePlanDraftV1::SingleExact))
    {
        return Err(invalid("closed governed write route"));
    }
    let attempt_ids = typed_attempt_ids(attempt_values, attempts_by_id, "write ownership")?;
    if attempt_ids.is_empty() || attempt_ids.len() != attempts.len() {
        return Err(invalid("write attempt ownership"));
    }
    let admitted_keys = eligibility
        .admitted_profiles
        .iter()
        .map(profile_key_from_profile)
        .collect::<Result<Vec<_>, _>>()?;
    if attempt_ids.len() > admitted_keys.len() {
        return Err(invalid("write reselection outside snapshot"));
    }
    for (index, id) in attempt_ids.iter().enumerate() {
        let attempt = attempts_by_id[id];
        validate_write_attempt(attempt)?;
        if attempt.envelope().identity.provider != admitted_keys[index]
            || usize::from(attempt.envelope().identity.ordinal) != index + 1
        {
            return Err(invalid("ordered write snapshot ownership"));
        }
        if index + 1 < attempt_ids.len()
            && (!matches!(
                attempt.envelope().lifecycle(),
                AttemptLifecycleV1::FailedPreStart { .. }
            ) || !matches!(
                attempt.resolution().map(AttemptResolutionV2::truth),
                Some(
                    ResolutionTruth::Unavailable
                        | ResolutionTruth::RateLimited
                        | ResolutionTruth::Timeout
                )
            ))
        {
            return Err(invalid(
                "write reselection requires safe proven no-byte failure",
            ));
        }
        if let Some(next_id) = attempt_ids.get(index + 1) {
            let prior_completed = terminal_completion(attempt)
                .ok_or_else(|| invalid("write reselection prior completion"))?;
            let next = attempts_by_id[next_id];
            let next_transition = lifecycle_start_millis(next.envelope().lifecycle())
                .or_else(|| terminal_completion(next));
            if next_transition.is_some_and(|time| time <= prior_completed) {
                return Err(invalid("write reselection causal order"));
            }
        }
    }
    let last_id = attempt_ids.last().expect("nonempty checked");
    let last = attempts_by_id[last_id];
    let derived_progress = match (last.envelope().lifecycle(), last.resolution()) {
        (AttemptLifecycleV1::Prepared, None) => GovernedWriteProgressV1::Prepared,
        (AttemptLifecycleV1::Started(_), None)
        | (AttemptLifecycleV1::ResponseObserved { .. }, None) => GovernedWriteProgressV1::Started,
        (AttemptLifecycleV1::Resolved { .. }, Some(AttemptResolutionV2::Success(_))) => {
            GovernedWriteProgressV1::Acknowledged
        }
        (AttemptLifecycleV1::FailedPreStart { .. }, Some(_)) => {
            GovernedWriteProgressV1::FailedPreStart
        }
        (AttemptLifecycleV1::Unknown { .. }, Some(value))
            if value.truth() == ResolutionTruth::WriteAmbiguity =>
        {
            let GovernedWriteProgressDraftV1::Reconciliation(reconciliation) = submitted_progress
            else {
                return Err(invalid("write ambiguity requires reconciliation"));
            };
            if reconciliation.request_or_transaction_hash != *request_digest
                || reconciliation.anchor != request.anchor
                || reconciliation.provider_attempt_id != *last_id
            {
                return Err(invalid("write reconciliation identity binding"));
            }
            validate_write_reconciliation(
                &reconciliation,
                request,
                &reconciliation_observation_profiles,
            )?;
            return Ok(RouteExecutionV1::GovernedWrite {
                attempt_ids,
                progress: GovernedWriteProgressV1::Reconciliation(reconciliation),
            });
        }
        _ => return Err(invalid("governed write progress")),
    };
    if !reconciliation_observation_profiles.is_empty() {
        return Err(invalid("reconciliation observation profile"));
    }
    let progress_matches = matches!(
        (&submitted_progress, &derived_progress),
        (
            GovernedWriteProgressDraftV1::Prepared,
            GovernedWriteProgressV1::Prepared
        ) | (
            GovernedWriteProgressDraftV1::Started,
            GovernedWriteProgressV1::Started
        ) | (
            GovernedWriteProgressDraftV1::Acknowledged,
            GovernedWriteProgressV1::Acknowledged
        ) | (
            GovernedWriteProgressDraftV1::FailedPreStart,
            GovernedWriteProgressV1::FailedPreStart
        )
    );
    if !progress_matches {
        return Err(invalid(
            "submitted write progress differs from derived state",
        ));
    }
    Ok(RouteExecutionV1::GovernedWrite {
        attempt_ids,
        progress: derived_progress,
    })
}

pub fn validate_write_reconciliation(
    value: &WriteReconciliationV1,
    submission: &RouteRequestV1,
    observation_profiles: &[ProviderProfileV1],
) -> Result<(), ProviderContractError> {
    if validate_chain_anchor(&value.anchor).is_err() {
        return Err(invalid("reconciliation observation anchor"));
    }
    if value.observations.is_empty()
        || !value.observations.windows(2).all(|pair| {
            (
                pair[0].method_data_class.method.as_str(),
                pair[0].method_data_class.data_class.as_str(),
                pair[0].provider_profile_digest.as_str(),
            ) < (
                pair[1].method_data_class.method.as_str(),
                pair[1].method_data_class.data_class.as_str(),
                pair[1].provider_profile_digest.as_str(),
            )
        })
    {
        return Err(invalid("reconciliation observation canonicality"));
    }
    if value.observations.iter().any(|observation| {
        observation.method_data_class.method == submission.method
            && observation.method_data_class.data_class == submission.data_class
    }) {
        return Err(invalid("reconciliation cannot observe submission method"));
    }
    if observation_profiles.len() != value.observations.len()
        || observation_profiles.iter().any(|profile| {
            value
                .observations
                .iter()
                .filter(|observation| {
                    observation.provider_profile_digest.as_str() == profile.profile_digest
                })
                .count()
                != 1
        })
    {
        return Err(invalid("reconciliation observation profile"));
    }
    for observation in &value.observations {
        let matching_profiles = observation_profiles
            .iter()
            .filter(|profile| {
                profile.profile_digest == observation.provider_profile_digest.as_str()
            })
            .collect::<Vec<_>>();
        if matching_profiles.len() != 1
            || validate_provider_profile(matching_profiles[0]).is_err()
            || !matching_profiles[0]
                .method_data_classes
                .contains(&observation.method_data_class)
        {
            return Err(invalid("reconciliation observation profile"));
        }
        let profile = matching_profiles[0];
        if profile.idempotency != IdempotencyClass::IdempotentRead {
            return Err(invalid(
                "reconciliation observation must be idempotent read",
            ));
        }
        if profile.chain_id != value.anchor.chain_id
            || profile.genesis_hash != value.anchor.genesis_hash
            || profile.network_id != value.anchor.network_id
        {
            return Err(invalid("reconciliation observation anchor"));
        }
    }
    if value.evidence_refs.is_empty()
        || !value.evidence_refs.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(invalid("reconciliation evidence"));
    }
    let state_evidence = reconciliation_state_evidence(&value.state);
    let mut distinct = BTreeSet::new();
    if !state_evidence
        .iter()
        .all(|digest| distinct.insert(digest.as_str()))
        || state_evidence
            .iter()
            .any(|digest| !value.evidence_refs.contains(digest))
    {
        return Err(invalid("reconciliation state evidence"));
    }
    Ok(())
}

fn reconciliation_state_evidence(state: &WriteReconciliationStateV1) -> Vec<&EvidenceDigest> {
    match state {
        WriteReconciliationStateV1::Ambiguous | WriteReconciliationStateV1::DroppedConfirmed => {
            vec![]
        }
        WriteReconciliationStateV1::Included {
            inclusion_candidate_digest,
            receipt_identity_digest,
        } => vec![inclusion_candidate_digest, receipt_identity_digest],
        WriteReconciliationStateV1::Executed {
            inclusion_candidate_digest,
            execution_candidate_digest,
            receipt_identity_digest,
        } => vec![
            inclusion_candidate_digest,
            execution_candidate_digest,
            receipt_identity_digest,
        ],
        WriteReconciliationStateV1::Finalized {
            inclusion_candidate_digest,
            execution_candidate_digest,
            finality_candidate_digest,
            receipt_identity_digest,
        } => vec![
            inclusion_candidate_digest,
            execution_candidate_digest,
            finality_candidate_digest,
            receipt_identity_digest,
        ],
        WriteReconciliationStateV1::Reverted {
            receipt_identity_digest,
        } => vec![receipt_identity_digest],
    }
}
