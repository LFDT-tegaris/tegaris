use super::*;

pub(super) fn typed_attempt_ids(
    values: Vec<String>,
    attempts_by_id: &BTreeMap<AttemptId, &RouteAttemptV1>,
    reason: &'static str,
) -> Result<Vec<AttemptId>, ProviderContractError> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .map(|value| {
            let id = AttemptId::new(value).map_err(|_| invalid(reason))?;
            if !seen.insert(id.clone()) || !attempts_by_id.contains_key(&id) {
                return Err(invalid(reason));
            }
            Ok(id)
        })
        .collect()
}

fn exact_outcome(
    submitted: RouteOutcomeDraftV1,
    derived: DerivedTerminalRouteState,
) -> Result<RouteOutcomeV1, ProviderContractError> {
    match (submitted, derived) {
        (
            RouteOutcomeDraftV1::Selected {
                truth,
                selected_result_digest,
                agreement_attempt_ids,
            },
            DerivedTerminalRouteState::Selected {
                truth: derived_truth,
                digest,
                agreement_attempt_ids: derived_ids,
            },
        ) => {
            let submitted_digest = NormalizedResponseDigest::new(selected_result_digest)
                .map_err(|_| invalid("selected result digest"))?;
            let submitted_ids = agreement_attempt_ids
                .into_iter()
                .map(|id| AttemptId::new(id).map_err(|_| invalid("agreement attempt")))
                .collect::<Result<Vec<_>, _>>()?;
            if truth != derived_truth || submitted_digest != digest || submitted_ids != derived_ids
            {
                return Err(invalid("selected outcome does not match derived state"));
            }
            Ok(RouteOutcomeV1::Selected(SelectedOutcomeV1 {
                truth,
                selected_result_digest: submitted_digest,
                agreement_attempt_ids: submitted_ids,
            }))
        }
        (
            RouteOutcomeDraftV1::Divergent { evidence_refs },
            DerivedTerminalRouteState::Divergent {
                evidence_refs: derived_refs,
            },
        ) => {
            let submitted_refs = evidence(evidence_refs)?;
            if submitted_refs != derived_refs {
                return Err(invalid("divergent evidence does not match derived state"));
            }
            Ok(RouteOutcomeV1::Divergent {
                evidence_refs: submitted_refs,
            })
        }
        (
            RouteOutcomeDraftV1::Partial { evidence_refs },
            DerivedTerminalRouteState::Partial {
                evidence_refs: derived_refs,
            },
        ) => {
            let submitted_refs = evidence(evidence_refs)?;
            if submitted_refs != derived_refs {
                return Err(invalid("partial evidence does not match derived state"));
            }
            Ok(RouteOutcomeV1::Partial {
                evidence_refs: submitted_refs,
            })
        }
        (
            RouteOutcomeDraftV1::Failed {
                truth,
                evidence_refs,
            },
            DerivedTerminalRouteState::Failed {
                truth: derived_truth,
                evidence_refs: derived_refs,
            },
        ) => {
            let submitted_refs = evidence(evidence_refs)?;
            if truth != derived_truth || submitted_refs != derived_refs {
                return Err(invalid("failed outcome does not match derived state"));
            }
            Ok(RouteOutcomeV1::Failed {
                truth,
                evidence_refs: submitted_refs,
            })
        }
        _ => Err(invalid(
            "submitted outcome does not match derived route state",
        )),
    }
}

fn route_plan(
    value: RoutePlanDraftV1,
    eligible_count: usize,
) -> Result<RoutePlanV1, ProviderContractError> {
    match value {
        RoutePlanDraftV1::SingleExact if eligible_count == 1 => Ok(RoutePlanV1::SingleExact),
        RoutePlanDraftV1::QuorumIdentical { required_agreement }
            if (2..=eligible_count).contains(&usize::from(required_agreement)) =>
        {
            Ok(RoutePlanV1::QuorumIdentical { required_agreement })
        }
        RoutePlanDraftV1::HedgedSingle {
            hedge_threshold_millis,
        } if eligible_count >= 2 && hedge_threshold_millis > 0 => Ok(RoutePlanV1::HedgedSingle {
            hedge_threshold_millis,
        }),
        RoutePlanDraftV1::HedgedQuorumIdentical {
            required_agreement,
            hedge_threshold_millis,
            max_hedge_attempts,
        } if hedge_threshold_millis > 0
            && max_hedge_attempts > 0
            && (2..=eligible_count).contains(&usize::from(required_agreement)) =>
        {
            Ok(RoutePlanV1::HedgedQuorumIdentical {
                required_agreement,
                hedge_threshold_millis,
                max_hedge_attempts,
            })
        }
        _ => Err(invalid("closed route plan")),
    }
}

pub(super) fn validate_read_recoveries(
    context: &WitnessValidationContext<'_>,
    temporal: &ReadTemporalPolicy<'_>,
    route_plan: &RoutePlanV1,
    admitted_keys: &[ProviderKeyV1],
    route_ids: &[AttemptId],
    values: Vec<ReadRecoveryDraftV1>,
    profile_retry_budget: u8,
) -> Result<Vec<ReadRecoveryV1>, ProviderContractError> {
    let request = context.request;
    let request_digest = context.request_digest;
    let attempts_by_id = context.attempts_by_id;
    if values.len() > usize::from(profile_retry_budget) {
        return Err(invalid("signed recovery budget"));
    }
    let count = values.len();
    let mut result = Vec::with_capacity(count);
    let mut previous_next = None;
    let mut previous_deadline = None;
    let mut prior_ids = BTreeSet::new();
    let mut next_ids = BTreeSet::new();
    let mut used_providers = route_ids
        .iter()
        .map(|id| attempts_by_id[id].envelope().identity.provider.clone())
        .collect::<BTreeSet<_>>();
    for (index, recovery) in values.into_iter().enumerate() {
        let expected_budget = profile_retry_budget
            .checked_sub(u8::try_from(index + 1).map_err(|_| invalid("signed recovery budget"))?)
            .ok_or_else(|| invalid("signed recovery budget"))?;
        if recovery.request_id != request.request_id
            || recovery.authority_context_digest != request.authority_context_digest
            || recovery.immutable_request_digest != request_digest.as_str()
            || recovery.anchor != request.anchor
            || recovery.remaining_rate_budget != expected_budget
            || recovery.remaining_deadline_millis == 0
        {
            return Err(invalid("unchanged read recovery"));
        }
        let prior_id = AttemptId::new(recovery.prior_attempt_id)
            .map_err(|_| invalid("prior recovery attempt"))?;
        let next_id = AttemptId::new(recovery.next_attempt_id)
            .map_err(|_| invalid("next recovery attempt"))?;
        if !prior_ids.insert(prior_id.clone())
            || !next_ids.insert(next_id.clone())
            || previous_next.as_ref().is_some_and(|id| id != &prior_id)
            || prior_id == next_id
        {
            return Err(invalid("closed ordered recovery chain"));
        }
        let prior = attempts_by_id
            .get(&prior_id)
            .ok_or_else(|| invalid("dangling prior recovery attempt"))?;
        let next = attempts_by_id
            .get(&next_id)
            .ok_or_else(|| invalid("dangling next recovery attempt"))?;
        let resolution = prior
            .resolution()
            .filter(|value| matches!(value, AttemptResolutionV2::ReadFailure(_)))
            .ok_or_else(|| invalid("recovery requires read failure"))?;
        if !resolution.recovery_eligibility().permits(recovery.kind) {
            return Err(invalid("resolution does not permit recovery kind"));
        }
        let target = provider_key(
            recovery.target_profile_digest,
            recovery.target_provider_instance_id,
        )?;
        temporal.validate_recovery_transition(prior, next)?;
        if !admitted_keys.contains(&target)
            || next.envelope().identity.provider != target
            || next.envelope().identity.ordinal <= prior.envelope().identity.ordinal
            || next.envelope().identity.request_id != prior.envelope().identity.request_id
            || next.envelope().identity.authority_context_digest
                != prior.envelope().identity.authority_context_digest
            || next.envelope().identity.capability_profile_digest
                != prior.envelope().identity.capability_profile_digest
            || next.envelope().identity.immutable_request_digest
                != prior.envelope().identity.immutable_request_digest
            || next.envelope().identity.anchor != prior.envelope().identity.anchor
            || next.envelope().identity.deadline_millis != recovery.remaining_deadline_millis
            || recovery.remaining_deadline_millis >= prior.envelope().identity.deadline_millis
            || previous_deadline
                .is_some_and(|deadline| recovery.remaining_deadline_millis >= deadline)
        {
            return Err(invalid("recovery transition binding"));
        }
        match recovery.kind {
            ReadRecoveryKind::RetrySameProvider if target != prior.envelope().identity.provider => {
                return Err(invalid("retry changed provider"));
            }
            ReadRecoveryKind::FailoverWithinSnapshot
                if target == prior.envelope().identity.provider
                    || route_plan.mode() == RouteMode::SingleExact =>
            {
                return Err(invalid("invalid failover"));
            }
            ReadRecoveryKind::FailoverWithinSnapshot => {
                let expected = admitted_keys
                    .iter()
                    .find(|provider| !used_providers.contains(*provider))
                    .ok_or_else(|| invalid("no deterministic failover target"))?;
                if &target != expected || !used_providers.insert(target.clone()) {
                    return Err(invalid("failover target order"));
                }
            }
            _ => {}
        }
        result.push(ReadRecoveryV1 {
            prior_attempt_id: prior_id,
            next_attempt_id: next_id.clone(),
            target,
            kind: recovery.kind,
            remaining_deadline_millis: recovery.remaining_deadline_millis,
            remaining_rate_budget: recovery.remaining_rate_budget,
        });
        previous_next = Some(next_id);
        previous_deadline = Some(recovery.remaining_deadline_millis);
    }
    Ok(result)
}

pub(super) fn validate_resolution_recovery_claims(
    route_plan: &RoutePlanV1,
    attempts: &[RouteAttemptV1],
    retry_budget: u8,
) -> Result<(), ProviderContractError> {
    for attempt in attempts {
        let Some(resolution) = attempt.resolution() else {
            continue;
        };
        let eligibility = resolution.recovery_eligibility();
        if retry_budget == 0 && eligibility != RecoveryEligibilityV1::None {
            return Err(invalid("zero budget recovery eligibility"));
        }
        if route_plan.mode() == RouteMode::SingleExact
            && matches!(
                eligibility,
                RecoveryEligibilityV1::FailoverWithinSnapshot
                    | RecoveryEligibilityV1::RetryOrFailoverWithinSnapshot
            )
        {
            return Err(invalid("single route failover eligibility"));
        }
        if resolution.truth() == ResolutionTruth::RateLimited
            && matches!(
                eligibility,
                RecoveryEligibilityV1::FailoverWithinSnapshot
                    | RecoveryEligibilityV1::RetryOrFailoverWithinSnapshot
            )
        {
            return Err(invalid("rate-limit failover eligibility"));
        }
    }
    Ok(())
}

pub(super) fn validate_read_execution(
    context: &WitnessValidationContext<'_>,
    route_plan_draft: RoutePlanDraftV1,
    primary_values: Vec<String>,
    hedge_values: Vec<String>,
    recovery_values: Vec<ReadRecoveryDraftV1>,
    outcome_draft: RouteOutcomeDraftV1,
) -> Result<RouteExecutionV1, ProviderContractError> {
    let request = context.request;
    let eligibility = context.eligibility;
    let attempts = context.attempts;
    let attempts_by_id = context.attempts_by_id;
    if request.idempotency != IdempotencyClass::IdempotentRead {
        return Err(invalid("read execution idempotency"));
    }
    let first_profile = &eligibility.admitted_profiles[0];
    if route_plan_draft != first_profile.route_plan {
        return Err(invalid("route law differs from admitted profile"));
    }
    let admitted_keys = eligibility
        .admitted_profiles
        .iter()
        .map(profile_key_from_profile)
        .collect::<Result<Vec<_>, _>>()?;
    let route_plan = route_plan(route_plan_draft, admitted_keys.len())?;
    let primary_ids = typed_attempt_ids(primary_values, attempts_by_id, "primary ownership")?;
    let hedge_ids = typed_attempt_ids(hedge_values, attempts_by_id, "hedge ownership")?;
    let mut route_ids = primary_ids.clone();
    route_ids.extend(hedge_ids.iter().cloned());
    if route_ids.iter().collect::<BTreeSet<_>>().len() != route_ids.len() {
        return Err(invalid("overlapping primary and hedge ownership"));
    }
    let cardinality_ok = match &route_plan {
        RoutePlanV1::SingleExact => primary_ids.len() == 1 && hedge_ids.is_empty(),
        RoutePlanV1::QuorumIdentical { .. } => {
            primary_ids.len() == admitted_keys.len() && hedge_ids.is_empty()
        }
        RoutePlanV1::HedgedSingle { .. } => primary_ids.len() == 1 && hedge_ids.len() <= 1,
        RoutePlanV1::HedgedQuorumIdentical {
            max_hedge_attempts, ..
        } => {
            let max_hedges = usize::from(*max_hedge_attempts);
            max_hedges < admitted_keys.len()
                && primary_ids.len() == admitted_keys.len() - max_hedges
                && hedge_ids.len() <= max_hedges
        }
    };
    if !cardinality_ok || route_ids.len() > admitted_keys.len() {
        return Err(invalid("route-mode wave cardinality"));
    }
    for (index, id) in route_ids.iter().enumerate() {
        let attempt = attempts_by_id[id];
        if attempt.envelope().identity.provider != admitted_keys[index]
            || usize::from(attempt.envelope().identity.ordinal) != index + 1
        {
            return Err(invalid("ordered snapshot wave ownership"));
        }
    }
    let temporal = ReadTemporalPolicy::new(context);
    validate_resolution_recovery_claims(&route_plan, attempts, first_profile.read_retry_budget)?;
    let recoveries = validate_read_recoveries(
        context,
        &temporal,
        &route_plan,
        &admitted_keys,
        &route_ids,
        recovery_values,
        first_profile.read_retry_budget,
    )?;
    let recovery_ids = recoveries
        .iter()
        .map(|recovery| recovery.next_attempt_id.clone())
        .collect::<BTreeSet<_>>();
    if route_ids.iter().any(|id| recovery_ids.contains(id)) {
        return Err(invalid("initial/recovery ownership overlap"));
    }
    let owned = route_ids
        .iter()
        .cloned()
        .chain(recovery_ids)
        .collect::<BTreeSet<_>>();
    let all = attempts
        .iter()
        .map(|attempt| attempt.envelope().identity.attempt_id.clone())
        .collect::<BTreeSet<_>>();
    if owned != all {
        return Err(invalid("attempt ownership is not an exact disjoint union"));
    }
    let evaluation = temporal.evaluate(&route_plan, &primary_ids, &hedge_ids)?;
    let outcome = exact_outcome(outcome_draft, evaluation.terminal_state)?;
    Ok(RouteExecutionV1::IdempotentRead {
        route_plan,
        primary_attempt_ids: primary_ids,
        hedge_attempt_ids: hedge_ids,
        recoveries,
        outcome,
    })
}
