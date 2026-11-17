use super::profile::canonicalize_provider_collections;
use super::*;

impl RequestRouteWitnessV1 {
    pub fn try_from_with_excluded_profiles(
        mut value: RequestRouteWitnessDraftV1,
        mut excluded_profiles: Vec<ProviderProfileV1>,
    ) -> Result<Self, ProviderContractError> {
        for profile in &mut value.admitted_profiles {
            canonicalize_provider_collections(profile);
        }
        for profile in &mut excluded_profiles {
            canonicalize_provider_collections(profile);
        }
        validate_route_request(&value.request)?;
        let original_profiles = value
            .admitted_profiles
            .iter()
            .chain(&excluded_profiles)
            .cloned()
            .collect::<Vec<_>>();
        validate_profile_request_binding(&value.request, &original_profiles)?;
        let request_id =
            RequestId::new(value.request.request_id.clone()).map_err(|_| invalid("request id"))?;
        let authority = AuthorityContextDigest::new(value.request.authority_context_digest.clone())
            .map_err(|_| invalid("authority"))?;
        let capability =
            CapabilityProfileDigest::new(value.request.required_capability_profile_digest.clone())
                .map_err(|_| invalid("capability profile"))?;
        let request_digest = RequestDigest::new(value.request_digest.clone())
            .map_err(|_| invalid("request digest"))?;
        let mut admitted_profiles = value.admitted_profiles;
        let mut exclusions = value.exclusions;
        let order_derivation = canonicalize_provider_order_with_excluded(
            &value.request_digest,
            &mut admitted_profiles,
            &mut excluded_profiles,
            &mut exclusions,
        );
        let admitted_keys = admitted_profiles
            .iter()
            .map(profile_key_from_profile)
            .collect::<Result<Vec<_>, _>>()?;
        let mut all_keys = BTreeSet::new();
        let mut all_instances = BTreeSet::new();
        for key in &admitted_keys {
            if !all_keys.insert(key.clone())
                || !all_instances.insert(key.provider_instance_id.clone())
            {
                return Err(invalid("duplicate admitted provider"));
            }
        }
        let excluded_profile_keys = excluded_profiles
            .iter()
            .map(profile_key_from_profile)
            .collect::<Result<Vec<_>, _>>()?;
        if excluded_profile_keys.len() != exclusions.len()
            || excluded_profile_keys.iter().any(|key| {
                exclusions
                    .iter()
                    .filter(|item| {
                        item.profile_digest == key.profile_digest.as_str()
                            && item.provider_instance_id == key.provider_instance_id.as_str()
                    })
                    .count()
                    != 1
            })
        {
            return Err(invalid(
                "excluded provider does not resolve original snapshot",
            ));
        }
        let excluded = exclusions
            .into_iter()
            .map(|item| {
                Ok(ExcludedProviderV1 {
                    key: provider_key(item.profile_digest, item.provider_instance_id)?,
                    reason: item.reason,
                })
            })
            .collect::<Result<Vec<_>, ProviderContractError>>()?;
        for item in &excluded {
            if !all_keys.insert(item.key.clone())
                || !all_instances.insert(item.key.provider_instance_id.clone())
            {
                return Err(invalid("admitted/excluded overlap"));
            }
        }
        let eligibility = EligibilitySnapshotV1 {
            admitted_profiles,
            excluded,
            order_derivation,
        };
        let attempts = value
            .attempts
            .into_iter()
            .map(close_terminal_attempt)
            .collect::<Result<Vec<_>, _>>()?;
        if attempts.is_empty() {
            return Err(invalid("empty attempt set"));
        }
        let mut attempts_by_id = BTreeMap::new();
        for (index, attempt) in attempts.iter().enumerate() {
            let identity = &attempt.envelope().identity;
            if identity.request_id != request_id
                || identity.authority_context_digest != authority
                || identity.capability_profile_digest != capability
                || identity.immutable_request_digest != request_digest
                || identity.anchor != value.request.anchor
                || !admitted_keys.contains(&identity.provider)
                || identity.deadline_millis > value.request.request_deadline_millis
                || usize::from(identity.ordinal) != index + 1
                || attempts_by_id
                    .insert(identity.attempt_id.clone(), attempt)
                    .is_some()
            {
                return Err(invalid("attempt witness binding"));
            }
            if let Some(resolution) = attempt.resolution()
                && (resolution.provider() != &identity.provider
                    || resolution.observed_anchor() != &value.request.anchor
                    || resolution.capability_profile_digest() != &capability)
            {
                return Err(invalid("resolution witness binding"));
            }
        }
        let context = WitnessValidationContext {
            request: &value.request,
            request_digest: &request_digest,
            eligibility: &eligibility,
            attempts: &attempts,
            attempts_by_id: &attempts_by_id,
        };
        let execution = match value.execution {
            RouteExecutionDraftV1::IdempotentRead {
                route_plan,
                primary_attempt_ids,
                hedge_attempt_ids,
                recoveries,
                outcome,
            } => validate_read_execution(
                &context,
                route_plan,
                primary_attempt_ids,
                hedge_attempt_ids,
                recoveries,
                outcome,
            )?,
            RouteExecutionDraftV1::GovernedWrite {
                attempt_ids,
                reconciliation_observation_profiles,
                progress,
            } => validate_write_execution(
                &context,
                attempt_ids,
                reconciliation_observation_profiles,
                progress,
            )?,
        };
        Ok(Self {
            request: value.request,
            request_digest,
            eligibility,
            attempts,
            execution,
        })
    }
}

pub(super) fn close_terminal_attempt(
    value: RouteAttemptDraftV1,
) -> Result<RouteAttemptV1, ProviderContractError> {
    if value.envelope.state == AttemptState::Unknown
        && value
            .resolution
            .as_ref()
            .is_some_and(|resolution| resolution.truth == ResolutionTruth::Timeout)
    {
        let envelope = AttemptEnvelopeV1::try_from(value.envelope)?;
        let resolution =
            AttemptResolutionV2::try_from(value.resolution.expect("timeout resolution checked"))?;
        return Ok(RouteAttemptV1::Terminal(Box::new(TerminalRouteAttemptV1 {
            envelope,
            resolution,
        })));
    }
    RouteAttemptV1::try_from(value)
}

impl TryFrom<RequestRouteWitnessDraftV1> for RequestRouteWitnessV1 {
    type Error = ProviderContractError;

    fn try_from(value: RequestRouteWitnessDraftV1) -> Result<Self, Self::Error> {
        Self::try_from_with_excluded_profiles(value, Vec::new())
    }
}

/// OpenPC provider-order v1 is a dependency-free deterministic ordering aid, never an integrity primitive.
pub(crate) fn canonicalize_provider_order_with_excluded(
    request_digest: &str,
    profiles: &mut [ProviderProfileV1],
    excluded_profiles: &mut [ProviderProfileV1],
    exclusions: &mut [ProviderExclusionV1],
) -> String {
    for profile in profiles.iter_mut() {
        canonicalize_provider_collections(profile);
    }
    for profile in excluded_profiles.iter_mut() {
        canonicalize_provider_collections(profile);
    }
    let mut encoded = profiles
        .iter()
        .chain(excluded_profiles.iter())
        .map(profile_encoding)
        .collect::<Vec<_>>();
    encoded.sort();
    let mut context = b"openpc:provider-order:v1\0".to_vec();
    put(&mut context, request_digest.as_bytes());
    for bytes in &encoded {
        put(&mut context, bytes);
    }
    exclusions.sort_by(|left, right| {
        (
            &left.profile_digest,
            &left.provider_instance_id,
            left.reason as u8,
        )
            .cmp(&(
                &right.profile_digest,
                &right.provider_instance_id,
                right.reason as u8,
            ))
    });
    for exclusion in exclusions.iter() {
        put(&mut context, exclusion.profile_digest.as_bytes());
        put(&mut context, exclusion.provider_instance_id.as_bytes());
        context.push(exclusion.reason as u8);
    }
    profiles.sort_by(|left, right| {
        let left_bytes = profile_encoding(left);
        let right_bytes = profile_encoding(right);
        compare_provider_order_keys(
            fnv128(&[context.as_slice(), b"P", left_bytes.as_slice()].concat()),
            &left_bytes,
            fnv128(&[context.as_slice(), b"P", right_bytes.as_slice()].concat()),
            &right_bytes,
        )
    });
    let mut retained_context = context;
    for profile in profiles.iter() {
        put(&mut retained_context, &profile_encoding(profile));
    }
    format!(
        "openpc:provider-order:v1:{:032x}",
        fnv128(&retained_context)
    )
}

pub(super) fn compare_provider_order_keys(
    left_rank: u128,
    left_bytes: &[u8],
    right_rank: u128,
    right_bytes: &[u8],
) -> std::cmp::Ordering {
    left_rank
        .cmp(&right_rank)
        .then_with(|| left_bytes.cmp(right_bytes))
}

fn put(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}
fn profile_encoding(value: &ProviderProfileV1) -> Vec<u8> {
    let mut out = Vec::new();
    for text in [
        &value.profile_id,
        &value.profile_version,
        &value.profile_digest,
        &value.provider_instance_id,
        &value.provider_release_digest,
        &value.provider_build_digest,
        &value.configuration_digest,
        &value.chain_id,
        &value.genesis_hash,
        &value.network_id,
        &value.tls_credential_identity,
        &value.tls_credential_fingerprint,
        &value.json_rpc_version,
        &value.request_schema_digest,
        &value.response_schema_digest,
        &value.normalization_rule_digest,
        &value.privacy_behavior_digest,
        &value.failure_behavior_digest,
        &value.rate_limit_contract_digest,
        &value.capability_profile_digest,
        &value.maximum_response_classification,
        &value.corpus_digest,
        &value.conformance_receipt_digest,
    ] {
        put(&mut out, text.as_bytes());
    }
    out.extend_from_slice(&value.trust_epoch.to_be_bytes());
    let mut methods = value.method_data_classes.clone();
    methods.sort_by(|a, b| (&a.method, &a.data_class).cmp(&(&b.method, &b.data_class)));
    for method in methods {
        put(&mut out, method.method.as_bytes());
        put(&mut out, method.data_class.as_bytes());
    }
    for number in [
        value.limits.max_request_bytes,
        value.limits.max_response_bytes,
        value.limits.max_range,
        u64::from(value.limits.max_batch),
    ] {
        out.extend_from_slice(&number.to_be_bytes());
    }
    out.push(value.idempotency as u8);
    match &value.route_plan {
        RoutePlanDraftV1::SingleExact => out.push(0),
        RoutePlanDraftV1::QuorumIdentical { required_agreement } => {
            out.push(1);
            out.push(*required_agreement);
        }
        RoutePlanDraftV1::HedgedSingle {
            hedge_threshold_millis,
        } => {
            out.push(2);
            out.extend_from_slice(&hedge_threshold_millis.to_be_bytes());
        }
        RoutePlanDraftV1::HedgedQuorumIdentical {
            required_agreement,
            hedge_threshold_millis,
            max_hedge_attempts,
        } => {
            out.push(3);
            out.push(*required_agreement);
            out.extend_from_slice(&hedge_threshold_millis.to_be_bytes());
            out.push(*max_hedge_attempts);
        }
    }
    out.push(value.read_retry_budget);
    out.extend_from_slice(&value.timeout_budget_millis.to_be_bytes());
    out.push(provider_order_lifecycle_tag(value.lifecycle));
    for evidence in &value.evidence_refs {
        put(&mut out, evidence.as_bytes());
    }
    out
}

// These v1 encoding tags must remain stable when lifecycle variants are added
// or reordered. They are independent of Rust's enum discriminants.
fn provider_order_lifecycle_tag(value: ProfileLifecycle) -> u8 {
    match value {
        ProfileLifecycle::Draft => 0,
        ProfileLifecycle::Validated => 1,
        ProfileLifecycle::Qualified => 2,
        ProfileLifecycle::Active => 3,
        ProfileLifecycle::Quarantined => 4,
        ProfileLifecycle::Disabled => 5,
        ProfileLifecycle::Retired => 6,
        ProfileLifecycle::Uninstalled => 7,
        ProfileLifecycle::BoundedQa => 8,
    }
}

fn fnv128(bytes: &[u8]) -> u128 {
    bytes
        .iter()
        .fold(0x6c62272e07bb014262b821756295c58d_u128, |hash, byte| {
            (hash ^ u128::from(*byte)).wrapping_mul(0x0000000001000000000000000000013b_u128)
        })
}
