use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::validation::{
    canonicalize_provider_order_with_excluded, profile_key_from_profile,
    validate_profile_request_binding, validate_route_plan,
};
use crate::{
    EligibilitySnapshotV1, ExcludedProviderV1, ProviderContractError, ProviderExclusionV1,
    ProviderInstanceId, ProviderKeyV1, ProviderLimits, ProviderProfileDigest, ProviderProfileV1,
    ReadRecoveryDraftV1, RequestDigest, RequestRouteWitnessDraftV1, RequestRouteWitnessV1,
    RouteAttemptDraftV1, RouteExecutionDraftV1, RoutePlanDraftV1, RoutePlanV1, RouteRequestV1,
};

/// Opaque, construction-validated permission-neutral input to one route execution.
///
/// The type deliberately implements neither `Serialize` nor `Deserialize`. Terminal attempts,
/// resolutions, recoveries and outcomes can only enter through `finish`, after a runtime has
/// consumed this contract.
#[derive(Debug)]
pub struct RouteExecutionContractV1 {
    request: RouteRequestV1,
    request_digest: RequestDigest,
    original_profiles: Vec<ProviderProfileV1>,
    excluded_profiles: Vec<ProviderProfileV1>,
    exclusions: Vec<ProviderExclusionV1>,
    eligibility: EligibilitySnapshotV1,
    route_plan: RoutePlanV1,
    route_plan_draft: RoutePlanDraftV1,
    effective_deadline_millis: u64,
    read_retry_budget: u8,
    provider_limits: BTreeMap<ProviderKeyV1, ProviderLimits>,
}

impl RouteExecutionContractV1 {
    pub fn try_new(
        request: RouteRequestV1,
        mut original_profiles: Vec<ProviderProfileV1>,
        mut exclusions: Vec<ProviderExclusionV1>,
        asserted_request_digest: Option<&str>,
    ) -> Result<Self, ProviderContractError> {
        let closed = || ProviderContractError::Invalid("route execution contract");
        crate::validate_route_request(&request).map_err(|_| closed())?;
        validate_profile_request_binding(&request, &original_profiles).map_err(|_| closed())?;

        let request_digest_text = derive_request_digest(&request).map_err(|_| closed())?;
        if asserted_request_digest.is_some_and(|value| value != request_digest_text) {
            return Err(closed());
        }
        let request_digest =
            RequestDigest::new(request_digest_text.clone()).map_err(|_| closed())?;

        let mut original_keys = BTreeSet::new();
        let mut original_instances = BTreeSet::new();
        for profile in &original_profiles {
            let key = profile_key_from_profile(profile).map_err(|_| closed())?;
            if !original_keys.insert(key)
                || !original_instances.insert(profile.provider_instance_id.clone())
            {
                return Err(closed());
            }
        }
        let mut exclusion_keys = BTreeSet::new();
        for exclusion in &exclusions {
            let key = (
                exclusion.profile_digest.clone(),
                exclusion.provider_instance_id.clone(),
            );
            if !exclusion_keys.insert(key.clone())
                || !original_profiles.iter().any(|profile| {
                    profile.profile_digest == key.0 && profile.provider_instance_id == key.1
                })
            {
                return Err(closed());
            }
        }

        let mut admitted_profiles = Vec::new();
        let mut excluded_profiles = Vec::new();
        for profile in original_profiles.iter().cloned() {
            if exclusion_keys.contains(&(
                profile.profile_digest.clone(),
                profile.provider_instance_id.clone(),
            )) {
                excluded_profiles.push(profile);
            } else {
                admitted_profiles.push(profile);
            }
        }
        let first = admitted_profiles.first().ok_or_else(closed)?;
        validate_route_plan(&first.route_plan, admitted_profiles.len()).map_err(|_| closed())?;
        let route_plan_draft = first.route_plan.clone();
        let route_plan = close_route_plan(&route_plan_draft);
        let read_retry_budget = first.read_retry_budget;
        let effective_deadline_millis = request
            .request_deadline_millis
            .min(first.timeout_budget_millis);
        if effective_deadline_millis == 0 {
            return Err(closed());
        }

        let order_derivation = canonicalize_provider_order_with_excluded(
            &request_digest_text,
            &mut admitted_profiles,
            &mut excluded_profiles,
            &mut exclusions,
        );
        let excluded = exclusions
            .iter()
            .map(|value| {
                Ok(ExcludedProviderV1 {
                    key: ProviderKeyV1 {
                        profile_digest: ProviderProfileDigest::new(value.profile_digest.clone())
                            .map_err(|_| closed())?,
                        provider_instance_id: ProviderInstanceId::new(
                            value.provider_instance_id.clone(),
                        )
                        .map_err(|_| closed())?,
                    },
                    reason: value.reason,
                })
            })
            .collect::<Result<Vec<_>, ProviderContractError>>()?;
        let provider_limits = admitted_profiles
            .iter()
            .map(|profile| {
                Ok((
                    profile_key_from_profile(profile).map_err(|_| closed())?,
                    profile.limits.clone(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ProviderContractError>>()?;
        let eligibility = EligibilitySnapshotV1 {
            admitted_profiles,
            excluded,
            order_derivation,
        };

        original_profiles.sort_by(|left, right| {
            (&left.profile_digest, &left.provider_instance_id)
                .cmp(&(&right.profile_digest, &right.provider_instance_id))
        });
        Ok(Self {
            request,
            request_digest,
            original_profiles,
            excluded_profiles,
            exclusions,
            eligibility,
            route_plan,
            route_plan_draft,
            effective_deadline_millis,
            read_retry_budget,
            provider_limits,
        })
    }

    pub fn request(&self) -> &RouteRequestV1 {
        &self.request
    }
    pub fn request_digest(&self) -> &RequestDigest {
        &self.request_digest
    }
    pub fn original_profiles(&self) -> &[ProviderProfileV1] {
        &self.original_profiles
    }
    pub fn eligibility(&self) -> &EligibilitySnapshotV1 {
        &self.eligibility
    }
    pub fn route_plan(&self) -> &RoutePlanV1 {
        &self.route_plan
    }
    pub fn effective_deadline_millis(&self) -> u64 {
        self.effective_deadline_millis
    }
    pub fn read_retry_budget(&self) -> u8 {
        self.read_retry_budget
    }
    pub fn provider_limits(&self, key: &ProviderKeyV1) -> Option<&ProviderLimits> {
        self.provider_limits.get(key)
    }

    pub fn finish(
        self,
        attempts: Vec<RouteAttemptDraftV1>,
        execution: RouteExecutionDraftV1,
    ) -> Result<RequestRouteWitnessV1, ProviderContractError> {
        let draft = RequestRouteWitnessDraftV1 {
            request: self.request,
            request_digest: self.request_digest.as_str().to_owned(),
            admitted_profiles: self.eligibility.admitted_profiles,
            exclusions: self.exclusions,
            attempts,
            execution,
        };
        RequestRouteWitnessV1::try_from_with_excluded_profiles(draft, self.excluded_profiles)
    }

    /// Closes one runtime read by deriving its terminal state from the complete attempt trace.
    ///
    /// Runtime callers cannot submit a competing outcome: the same temporal/quorum owner used by
    /// witness validation constructs the retained terminal state.
    pub fn finish_derived_read(
        self,
        attempts: Vec<RouteAttemptDraftV1>,
        primary_attempt_ids: Vec<String>,
        hedge_attempt_ids: Vec<String>,
        recoveries: Vec<ReadRecoveryDraftV1>,
    ) -> Result<RequestRouteWitnessV1, ProviderContractError> {
        let outcome = crate::validation::derive_terminal_outcome_draft(
            &self.request,
            &self.route_plan,
            &attempts,
            &primary_attempt_ids,
            &hedge_attempt_ids,
        )?;
        let draft = RequestRouteWitnessDraftV1 {
            request: self.request,
            request_digest: self.request_digest.as_str().to_owned(),
            admitted_profiles: self.eligibility.admitted_profiles,
            exclusions: self.exclusions,
            attempts,
            execution: RouteExecutionDraftV1::IdempotentRead {
                route_plan: self.route_plan_draft,
                primary_attempt_ids,
                hedge_attempt_ids,
                recoveries,
                outcome,
            },
        };
        RequestRouteWitnessV1::try_from_with_excluded_profiles(draft, self.excluded_profiles)
    }

    pub fn route_plan_draft(&self) -> &RoutePlanDraftV1 {
        &self.route_plan_draft
    }
}

fn close_route_plan(value: &RoutePlanDraftV1) -> RoutePlanV1 {
    match value {
        RoutePlanDraftV1::SingleExact => RoutePlanV1::SingleExact,
        RoutePlanDraftV1::QuorumIdentical { required_agreement } => RoutePlanV1::QuorumIdentical {
            required_agreement: *required_agreement,
        },
        RoutePlanDraftV1::HedgedSingle {
            hedge_threshold_millis,
        } => RoutePlanV1::HedgedSingle {
            hedge_threshold_millis: *hedge_threshold_millis,
        },
        RoutePlanDraftV1::HedgedQuorumIdentical {
            required_agreement,
            hedge_threshold_millis,
            max_hedge_attempts,
        } => RoutePlanV1::HedgedQuorumIdentical {
            required_agreement: *required_agreement,
            hedge_threshold_millis: *hedge_threshold_millis,
            max_hedge_attempts: *max_hedge_attempts,
        },
    }
}

fn derive_request_digest(request: &RouteRequestV1) -> Result<String, crate::ProviderContractError> {
    let bytes = encode_route_request_identity(request)?;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write to String");
    }
    Ok(out)
}

pub(crate) fn encode_route_request_identity(
    request: &RouteRequestV1,
) -> Result<Vec<u8>, crate::ProviderContractError> {
    crate::validation::encode_canonical_cbor(
        &(22002_u64, "1.0.0", "openpc:route-request:v1", request),
        "route request PC-CBOR",
    )
}
