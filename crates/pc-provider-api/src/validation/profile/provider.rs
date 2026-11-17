use super::super::*;
use super::shared::*;

/// Deployment opt-in is exact-source, not a global relaxed-validation mode.
/// Signed artifacts retain BoundedQa, so they cannot claim full qualification.
pub fn provider_profile_admission_enabled(profile: &ProviderProfileV1) -> bool {
    match profile.lifecycle {
        ProfileLifecycle::Qualified | ProfileLifecycle::Active => true,
        ProfileLifecycle::BoundedQa => {
            std::env::var("OPENPC_PROVIDER_BOUNDED_QA_SOURCE_DIGEST")
                .ok()
                .as_deref()
                == Some(profile.configuration_digest.as_str())
        }
        _ => false,
    }
}

pub fn validate_provider_profile(profile: &ProviderProfileV1) -> Result<(), ProviderContractError> {
    for (value, reason) in [
        (&profile.profile_id, "profile id"),
        (&profile.profile_version, "profile version"),
        (&profile.profile_digest, "profile digest"),
        (&profile.provider_instance_id, "provider instance"),
        (&profile.provider_release_digest, "provider release"),
        (&profile.provider_build_digest, "provider build"),
        (&profile.configuration_digest, "configuration"),
        (&profile.chain_id, "chain id"),
        (&profile.genesis_hash, "genesis"),
        (&profile.network_id, "network"),
        (&profile.tls_credential_identity, "credential identity"),
        (
            &profile.tls_credential_fingerprint,
            "credential fingerprint",
        ),
        (&profile.request_schema_digest, "request schema"),
        (&profile.response_schema_digest, "response schema"),
        (&profile.normalization_rule_digest, "normalization"),
        (&profile.privacy_behavior_digest, "privacy behavior"),
        (&profile.failure_behavior_digest, "failure behavior"),
        (&profile.rate_limit_contract_digest, "rate contract"),
        (&profile.capability_profile_digest, "capability profile"),
        (
            &profile.maximum_response_classification,
            "response classification",
        ),
        (&profile.corpus_digest, "corpus"),
        (&profile.conformance_receipt_digest, "conformance receipt"),
    ] {
        nonempty(value, reason)?;
    }
    if profile.trust_epoch == 0
        || profile.json_rpc_version != "2.0"
        || validate_methods(&profile.method_data_classes).is_err()
        || profile.limits.max_request_bytes == 0
        || profile.limits.max_response_bytes == 0
        || profile.limits.max_range == 0
        || profile.limits.max_batch == 0
        || profile.read_retry_budget > 3
        || profile.timeout_budget_millis == 0
        || !provider_profile_admission_enabled(profile)
        || !canonical_set(&profile.evidence_refs)
    {
        return Err(invalid("exact provider profile"));
    }
    validate_route_plan(&profile.route_plan, usize::MAX)
}

pub fn validate_route_request(request: &RouteRequestV1) -> Result<(), ProviderContractError> {
    for (value, reason) in [
        (&request.request_id, "request id"),
        (&request.authority_context_digest, "authority"),
        (&request.participant_binding, "participant"),
        (&request.privacy_binding, "privacy"),
        (&request.workload_binding, "workload"),
        (&request.action_intent, "action intent"),
        (&request.method, "method"),
        (&request.data_class, "data class"),
        (
            &request.normalized_parameter_digest,
            "normalized parameters",
        ),
        (
            &request.required_capability_profile_digest,
            "capability profile",
        ),
        (
            &request.maximum_response_classification,
            "response classification",
        ),
        (&request.evidence_correlation_id, "evidence correlation"),
    ] {
        nonempty(value, reason)?;
    }
    if request.request_deadline_millis == 0 {
        return Err(invalid("request deadline"));
    }
    validate_chain_anchor(&request.anchor)
}

pub(crate) fn profile_key_from_profile(
    profile: &ProviderProfileV1,
) -> Result<ProviderKeyV1, ProviderContractError> {
    provider_key(
        profile.profile_digest.clone(),
        profile.provider_instance_id.clone(),
    )
}

pub(crate) fn validate_profile_request_binding(
    request: &RouteRequestV1,
    profiles: &[ProviderProfileV1],
) -> Result<(), ProviderContractError> {
    let first = profiles
        .first()
        .ok_or_else(|| invalid("eligible provider set"))?;
    for profile in profiles {
        validate_provider_profile(profile)?;
        if profile.chain_id != request.anchor.chain_id
            || profile.genesis_hash != request.anchor.genesis_hash
            || profile.network_id != request.anchor.network_id
            || profile.capability_profile_digest != request.required_capability_profile_digest
            || profile.maximum_response_classification != request.maximum_response_classification
            || profile.idempotency != request.idempotency
            || !profile
                .method_data_classes
                .iter()
                .any(|pair| pair.method == request.method && pair.data_class == request.data_class)
            || !common_equivalent(first, profile)
        {
            return Err(invalid("exact request/profile eligibility tuple"));
        }
    }
    Ok(())
}

fn common_equivalent(first: &ProviderProfileV1, profile: &ProviderProfileV1) -> bool {
    profile.profile_version == first.profile_version
        && profile.configuration_digest == first.configuration_digest
        && profile.trust_epoch == first.trust_epoch
        && profile.json_rpc_version == first.json_rpc_version
        && profile.request_schema_digest == first.request_schema_digest
        && profile.response_schema_digest == first.response_schema_digest
        && profile.normalization_rule_digest == first.normalization_rule_digest
        && profile.limits == first.limits
        && profile.privacy_behavior_digest == first.privacy_behavior_digest
        && profile.failure_behavior_digest == first.failure_behavior_digest
        && profile.rate_limit_contract_digest == first.rate_limit_contract_digest
        && profile.route_plan == first.route_plan
        && profile.read_retry_budget == first.read_retry_budget
        && profile.timeout_budget_millis == first.timeout_budget_millis
        && profile.corpus_digest == first.corpus_digest
        && profile.conformance_receipt_digest == first.conformance_receipt_digest
        && profile.lifecycle == first.lifecycle
        && profile.method_data_classes == first.method_data_classes
}

pub(crate) fn validate_route_plan(
    route_plan: &RoutePlanDraftV1,
    admitted_count: usize,
) -> Result<(), ProviderContractError> {
    match route_plan {
        RoutePlanDraftV1::SingleExact if admitted_count == usize::MAX || admitted_count == 1 => {
            Ok(())
        }
        RoutePlanDraftV1::QuorumIdentical { required_agreement }
            if *required_agreement >= 2
                && (admitted_count == usize::MAX
                    || usize::from(*required_agreement) <= admitted_count) =>
        {
            Ok(())
        }
        RoutePlanDraftV1::HedgedSingle {
            hedge_threshold_millis,
        } if *hedge_threshold_millis > 0
            && (admitted_count == usize::MAX || admitted_count >= 2) =>
        {
            Ok(())
        }
        RoutePlanDraftV1::HedgedQuorumIdentical {
            required_agreement,
            hedge_threshold_millis,
            max_hedge_attempts,
        } if *required_agreement >= 2
            && *hedge_threshold_millis > 0
            && *max_hedge_attempts > 0
            && (admitted_count == usize::MAX
                || (usize::from(*required_agreement) <= admitted_count
                    && usize::from(*max_hedge_attempts) < admitted_count)) =>
        {
            Ok(())
        }
        _ => Err(invalid("route plan cardinality")),
    }
}

pub(in crate::validation) fn canonicalize_provider_collections(profile: &mut ProviderProfileV1) {
    profile.method_data_classes.sort_by(|left, right| {
        (&left.method, &left.data_class).cmp(&(&right.method, &right.data_class))
    });
    profile.evidence_refs.sort();
}
