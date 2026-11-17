#[cfg(test)]
use crate::error::JournalError;
use crate::error::{MultiRpcError, RpcCondition};
use crate::event::{EventKind, terminal_read_event_kind};
#[cfg(test)]
use crate::journal::{JournalState, PreparedCommand, StartedCommand, WriteJournal};
use crate::normalization::{
    LocalNormalizedResponseV1, TransportCompletionV1, normalize_local_eth_get_logs,
    parse_strict_json, rfc8785_canonical_bytes, validate_local_eth_get_logs_request,
};
use crate::state::{LiveRouteState, RecoveryObservation, TerminalObservation};
use pc_provider_api::{
    AttemptEnvelopeDraftV1, AttemptResolutionDraftV2, AttemptState, BlockSelectorKind,
    ChainReadAnchorV1, IdempotencyClass, MethodDataClass, ProfileLifecycle, ProviderExclusionV1,
    ProviderLimits, ProviderProfileV1, ReadRecoveryDraftV1, RecoveryEligibilityV1,
    RequestRouteWitnessV1, ResolutionTruth, RouteAttemptDraftV1, RouteExecutionContractV1,
    RoutePlanDraftV1, RouteRequestV1,
};
#[cfg(test)]
use pc_provider_api::{ProviderInstanceId, ProviderKeyV1, ProviderProfileDigest};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time::Instant;

const LOCAL_FIXTURE_MAX_JSON_DEPTH: u32 = 8;
const LOCAL_FIXTURE_CONFIGURATION_GENERATION: u64 = 1;
const LOCAL_FIXTURE_GENESIS_HASH: &str =
    "0xe1b0d01b8f92d7d758477e85fcb4c0b8a9ec5be2084e19d1a7aa25a4f09bd3c8";
const LOCAL_FIXTURE_BLOCK_HASH: &str =
    "0x3333333333333333333333333333333333333333333333333333333333333333";
const LOCAL_FIXTURE_REORG_BLOCK_HASH: &str =
    "0xfefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe";
const LOCAL_FIXTURE_EMPTY_REORG_BLOCK_HASH: &str =
    "0xfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfb";
const LOCAL_FIXTURE_REORG_GENESIS_HASH: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";

#[derive(Debug)]
pub(crate) struct ProviderEndpointBinding {
    profile_digest: String,
    provider_instance_id: String,
    endpoint: SecretString,
    secret_reference: String,
    resolved_secret_version: String,
    resolved_secret_fingerprint: String,
    max_json_depth: u32,
}

impl ProviderEndpointBinding {
    #[cfg(test)]
    pub(crate) fn new(
        profile_digest: impl Into<String>,
        provider_instance_id: impl Into<String>,
        endpoint: SecretString,
        secret_reference: impl Into<String>,
        resolved_secret_version: impl Into<String>,
        resolved_secret_fingerprint: impl Into<String>,
        max_json_depth: u32,
    ) -> Result<Self, MultiRpcError> {
        let parsed = reqwest::Url::parse(endpoint.expose_secret())
            .map_err(|_| MultiRpcError::Contract("private endpoint binding"))?;
        let profile_digest = profile_digest.into();
        let provider_instance_id = provider_instance_id.into();
        let secret_reference = secret_reference.into();
        let resolved_secret_version = resolved_secret_version.into();
        let resolved_secret_fingerprint = resolved_secret_fingerprint.into();
        if profile_digest.is_empty()
            || provider_instance_id.is_empty()
            || !matches!(parsed.scheme(), "http" | "https")
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || secret_reference.is_empty()
            || resolved_secret_version.is_empty()
            || !is_sha256_hex(&resolved_secret_fingerprint)
            || max_json_depth == 0
        {
            return Err(MultiRpcError::Contract("private endpoint binding"));
        }
        Ok(Self {
            profile_digest,
            provider_instance_id,
            endpoint: SecretString::from(parsed.to_string()),
            secret_reference,
            resolved_secret_version,
            resolved_secret_fingerprint,
            max_json_depth,
        })
    }
}

#[derive(Debug)]
struct QualifiedProviderRouteV1 {
    endpoint: SecretString,
    configuration_digest: String,
    max_json_depth: u32,
}

impl QualifiedProviderRouteV1 {
    fn try_new(
        profile: &pc_provider_api::ProviderProfileV1,
        binding: ProviderEndpointBinding,
        configuration_digest: &str,
    ) -> Result<Self, MultiRpcError> {
        if binding.profile_digest != profile.profile_digest
            || binding.provider_instance_id != profile.provider_instance_id
        {
            return Err(MultiRpcError::Contract("qualified provider route"));
        }
        Ok(Self {
            endpoint: binding.endpoint,
            configuration_digest: configuration_digest.to_owned(),
            max_json_depth: binding.max_json_depth,
        })
    }
}

fn derive_provider_configuration_digest(
    request: &RouteRequestV1,
    admitted_profiles: &[ProviderProfileV1],
    excluded_profiles: &[ProviderProfileV1],
    exclusions: &[ProviderExclusionV1],
    bindings: &[ProviderEndpointBinding],
    configuration_generation: u64,
) -> Result<String, MultiRpcError> {
    let mut binding_by_key = BTreeMap::new();
    for binding in bindings {
        let key = (
            binding.profile_digest.clone(),
            binding.provider_instance_id.clone(),
        );
        if binding_by_key.insert(key, binding).is_some() {
            return Err(MultiRpcError::Contract("exact endpoint bindings"));
        }
    }
    let profile_keys = admitted_profiles
        .iter()
        .map(|profile| {
            (
                profile.profile_digest.clone(),
                profile.provider_instance_id.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    if profile_keys.len() != admitted_profiles.len()
        || profile_keys != binding_by_key.keys().cloned().collect()
    {
        return Err(MultiRpcError::Contract("exact endpoint bindings"));
    }
    let mut profile_projection = Vec::with_capacity(admitted_profiles.len());
    for profile in admitted_profiles {
        let binding = binding_by_key
            .get(&(
                profile.profile_digest.clone(),
                profile.provider_instance_id.clone(),
            ))
            .ok_or(MultiRpcError::Contract("exact endpoint bindings"))?;
        let mut profile_value = serde_json::to_value(profile)
            .map_err(|_| MultiRpcError::Contract("qualified provider configuration"))?;
        profile_value
            .as_object_mut()
            .ok_or(MultiRpcError::Contract("qualified provider configuration"))?
            .remove("configuration_digest");
        profile_projection.push((
            profile.profile_digest.clone(),
            profile.provider_instance_id.clone(),
            serde_json::json!({
                "endpointFingerprint": hex_sha256(binding.endpoint.expose_secret().as_bytes()),
                "maxJsonDepth": binding.max_json_depth,
                "profile": profile_value,
                "resolvedSecretFingerprint": binding.resolved_secret_fingerprint,
                "resolvedSecretVersion": binding.resolved_secret_version,
                "secretReference": binding.secret_reference,
            }),
        ));
    }
    profile_projection.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    let profile_projection = profile_projection
        .into_iter()
        .map(|(_, _, value)| value)
        .collect::<Vec<_>>();
    let mut excluded_profile_projection = excluded_profiles
        .iter()
        .map(|profile| {
            let mut value = serde_json::to_value(profile)
                .map_err(|_| MultiRpcError::Contract("qualified provider configuration"))?;
            value
                .as_object_mut()
                .ok_or(MultiRpcError::Contract("qualified provider configuration"))?
                .remove("configuration_digest");
            Ok((
                profile.profile_digest.clone(),
                profile.provider_instance_id.clone(),
                value,
            ))
        })
        .collect::<Result<Vec<_>, MultiRpcError>>()?;
    excluded_profile_projection
        .sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    let excluded_profile_keys = excluded_profile_projection
        .iter()
        .map(|(profile, provider, _)| (profile.clone(), provider.clone()))
        .collect::<BTreeSet<_>>();
    let excluded_profile_projection = excluded_profile_projection
        .into_iter()
        .map(|(_, _, value)| value)
        .collect::<Vec<_>>();
    let exclusion_keys = exclusions
        .iter()
        .map(|value| {
            (
                value.profile_digest.clone(),
                value.provider_instance_id.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut exclusion_projection = exclusions
        .iter()
        .map(|value| {
            (
                value.profile_digest.as_str(),
                value.provider_instance_id.as_str(),
                serde_json::json!({
                    "profileDigest": value.profile_digest.as_str(),
                    "providerInstanceId": value.provider_instance_id.as_str(),
                    "reason": value.reason,
                }),
            )
        })
        .collect::<Vec<_>>();
    exclusion_projection.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
    let exclusion_projection = exclusion_projection
        .into_iter()
        .map(|(_, _, value)| value)
        .collect::<Vec<_>>();
    if excluded_profile_keys.len() != excluded_profiles.len()
        || exclusion_keys.len() != exclusions.len()
        || excluded_profile_keys != exclusion_keys
        || !profile_keys.is_disjoint(&excluded_profile_keys)
    {
        return Err(MultiRpcError::Contract("exact excluded provider bindings"));
    }
    let projection = serde_json::json!({
        "authorityContextDigest": request.authority_context_digest,
        "configurationGeneration": configuration_generation,
        "dataClass": request.data_class,
        "excludedProfileDefinitions": excluded_profile_projection,
        "excludedProviders": exclusion_projection,
        "method": request.method,
        "participantBinding": request.participant_binding,
        "privacyBinding": request.privacy_binding,
        "profiles": profile_projection,
    });
    Ok(hex_sha256(&rfc8785_canonical_bytes(&projection)?))
}

#[derive(Debug)]
struct LocalTechnicalOnlyV1 {
    configuration_digest: String,
}

#[derive(Debug)]
pub struct ReadExecutionResult {
    witness: RequestRouteWitnessV1,
    selected_responses: BTreeMap<String, SelectedProviderResponseV1>,
}

#[derive(Debug)]
struct SelectedProviderResponseV1 {
    normalized: LocalNormalizedResponseV1,
    response_evidence_digest: String,
    local_authority: LocalTechnicalOnlyV1,
}

/// Borrowed, opaque source material for a selected canonical read result.
///
/// Values are constructible only from a completed `RouteExecutor` result. This prevents adapters
/// from assembling selected response, evidence, and anchor identities independently.
#[derive(Clone, Copy, Debug)]
pub struct SelectedCanonicalReadV1<'a> {
    request: &'a pc_provider_api::RouteRequestV1,
    normalized: &'a LocalNormalizedResponseV1,
    response_evidence_digest: &'a str,
    local_authority: &'a LocalTechnicalOnlyV1,
}

impl SelectedCanonicalReadV1<'_> {
    pub fn request(&self) -> &pc_provider_api::RouteRequestV1 {
        self.request
    }

    pub fn normalized_response(&self) -> &LocalNormalizedResponseV1 {
        self.normalized
    }

    pub fn response_evidence_digest(&self) -> &str {
        self.response_evidence_digest
    }

    pub fn local_configuration_digest(&self) -> &str {
        &self.local_authority.configuration_digest
    }
}

impl ReadExecutionResult {
    pub fn witness(&self) -> &RequestRouteWitnessV1 {
        &self.witness
    }

    pub fn truth(&self) -> ResolutionTruth {
        match self.witness.execution() {
            pc_provider_api::RouteExecutionV1::IdempotentRead { outcome, .. } => match outcome {
                pc_provider_api::RouteOutcomeV1::Selected(selected) => selected.truth(),
                pc_provider_api::RouteOutcomeV1::Divergent { .. } => ResolutionTruth::Divergent,
                pc_provider_api::RouteOutcomeV1::Partial { .. } => ResolutionTruth::Partial,
                pc_provider_api::RouteOutcomeV1::Failed { truth, .. } => *truth,
            },
            pc_provider_api::RouteExecutionV1::GovernedWrite { .. } => {
                unreachable!("read executor only emits idempotent-read witnesses")
            }
        }
    }

    pub fn normalized_response_digest(&self) -> Option<&str> {
        match self.witness.execution() {
            pc_provider_api::RouteExecutionV1::IdempotentRead {
                outcome: pc_provider_api::RouteOutcomeV1::Selected(selected),
                ..
            } => Some(selected.selected_result_digest().as_str()),
            _ => None,
        }
    }

    pub fn agreement_attempt_ids(&self) -> Vec<&str> {
        match self.witness.execution() {
            pc_provider_api::RouteExecutionV1::IdempotentRead {
                outcome: pc_provider_api::RouteOutcomeV1::Selected(selected),
                ..
            } => selected
                .agreement_attempt_ids()
                .iter()
                .map(|value| value.as_str())
                .collect(),
            _ => Vec::new(),
        }
    }

    pub fn selected_normalized_bytes(&self, attempt_id: &str) -> Option<&[u8]> {
        self.selected_responses
            .get(attempt_id)
            .map(|value| value.normalized.bytes())
    }

    pub fn selected_normalized_digest(&self, attempt_id: &str) -> Option<&str> {
        self.selected_responses
            .get(attempt_id)
            .map(|value| value.normalized.digest())
    }

    pub fn selected_provider_observed_anchor(
        &self,
        attempt_id: &str,
    ) -> Option<&pc_provider_api::ChainReadAnchorV1> {
        self.selected_responses
            .get(attempt_id)
            .and_then(|value| value.normalized.provider_observed_anchor())
    }

    pub fn selected_canonical_read(&self) -> Option<SelectedCanonicalReadV1<'_>> {
        let pc_provider_api::RouteExecutionV1::IdempotentRead {
            outcome: pc_provider_api::RouteOutcomeV1::Selected(selected),
            ..
        } = self.witness.execution()
        else {
            return None;
        };
        let first = selected.agreement_attempt_ids().first()?;
        let response = self.selected_responses.get(first.as_str())?;
        Some(SelectedCanonicalReadV1 {
            request: self.witness.request(),
            normalized: &response.normalized,
            response_evidence_digest: &response.response_evidence_digest,
            local_authority: &response.local_authority,
        })
    }

    pub(crate) fn terminal_event_kind(&self) -> EventKind {
        terminal_read_event_kind(&self.witness)
    }
}

pub(crate) struct RouteExecutor {
    client: Client,
    contract: RouteExecutionContractV1,
    endpoints: BTreeMap<(String, String), QualifiedProviderRouteV1>,
    local_authority: LocalTechnicalOnlyV1,
}

impl RouteExecutor {
    fn from_contract_and_bindings(
        contract: RouteExecutionContractV1,
        bindings: Vec<ProviderEndpointBinding>,
        configuration_digest: &str,
    ) -> Result<Self, MultiRpcError> {
        if contract.request().idempotency != IdempotencyClass::IdempotentRead {
            return Err(MultiRpcError::Contract("idempotent read contract required"));
        }
        if contract
            .eligibility()
            .admitted_profiles()
            .iter()
            .any(|profile| profile.configuration_digest != configuration_digest)
        {
            return Err(MultiRpcError::Contract(
                "qualified provider configuration digest",
            ));
        }
        let admitted = contract
            .eligibility()
            .admitted_profiles()
            .iter()
            .map(|profile| {
                (
                    profile.profile_digest.clone(),
                    profile.provider_instance_id.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        let mut endpoints = BTreeMap::new();
        for binding in bindings {
            let key = (
                binding.profile_digest.clone(),
                binding.provider_instance_id.clone(),
            );
            let profile = contract
                .eligibility()
                .admitted_profiles()
                .iter()
                .find(|profile| {
                    profile.profile_digest == key.0 && profile.provider_instance_id == key.1
                })
                .ok_or(MultiRpcError::Contract("exact endpoint bindings"))?;
            let qualified =
                QualifiedProviderRouteV1::try_new(profile, binding, configuration_digest)?;
            if !admitted.contains(&key) || endpoints.insert(key, qualified).is_some() {
                return Err(MultiRpcError::Contract("exact endpoint bindings"));
            }
        }
        if admitted != endpoints.keys().cloned().collect() {
            return Err(MultiRpcError::condition(RpcCondition::NoEligibleProvider));
        }
        Ok(Self {
            client: Client::new(),
            contract,
            endpoints,
            local_authority: LocalTechnicalOnlyV1 {
                configuration_digest: configuration_digest.to_owned(),
            },
        })
    }

    fn local_configuration_digest(
        &self,
        profile_digest: &str,
        provider_instance_id: &str,
    ) -> Option<&str> {
        self.endpoints
            .get(&(profile_digest.to_owned(), provider_instance_id.to_owned()))
            .map(|value| value.configuration_digest.as_str())
    }

    pub async fn execute_read(
        self,
        canonical_json_rpc_request: &[u8],
    ) -> Result<ReadExecutionResult, MultiRpcError> {
        for profile in self.contract.eligibility().admitted_profiles() {
            let (_, max_json_depth) = endpoint_for(&self.endpoints, profile)?;
            validate_local_eth_get_logs_request(
                self.contract.request(),
                canonical_json_rpc_request,
                &profile.limits,
                max_json_depth,
            )?;
        }

        let started = Instant::now();
        let route_state = LiveRouteState::try_new(&self.contract)
            .map_err(|_| MultiRpcError::Contract("live route state"))?;
        let profiles = self.contract.eligibility().admitted_profiles().to_vec();
        let body = canonical_json_rpc_request.to_vec();
        let request = self.contract.request().clone();
        let request_digest = self.contract.request_digest().as_str().to_owned();
        let mut tasks = JoinSet::new();
        let mut observations = Vec::new();
        let mut primary_ids = Vec::new();
        let mut hedge_ids = Vec::new();

        for schedule in route_state
            .initial_wave()
            .map_err(|_| MultiRpcError::Contract("initial route wave"))?
        {
            let profile = profiles[schedule.provider_index].clone();
            let (endpoint, max_json_depth) = endpoint_for(&self.endpoints, &profile)?;
            primary_ids.push(schedule.attempt_id.clone());
            spawn_attempt(
                &mut tasks,
                LiveAttemptInput {
                    client: self.client.clone(),
                    endpoint,
                    max_json_depth,
                    body: body.clone(),
                    request: request.clone(),
                    profile,
                    attempt_id: schedule.attempt_id,
                    ordinal: schedule.ordinal,
                    started_at_millis: elapsed_millis(started),
                    deadline_millis: schedule.deadline_millis,
                    clock: started,
                },
            );
        }

        if let Some(threshold) = route_state.hedge_threshold_millis() {
            let timer = tokio::time::sleep(Duration::from_millis(threshold));
            tokio::pin!(timer);
            loop {
                if route_state.has_agreement(&terminal_observations(&observations)) {
                    break;
                }
                if elapsed_millis(started) >= threshold {
                    break;
                }
                if tasks.is_empty() {
                    (&mut timer).await;
                    break;
                }
                tokio::select! {
                    biased;
                    joined = tasks.join_next() => {
                        observations.push(joined
                            .ok_or(MultiRpcError::Contract("live route task"))?
                            .map_err(|_| MultiRpcError::condition(RpcCondition::ReadUnavailable))?);
                    }
                    _ = &mut timer => break,
                }
            }
            for schedule in route_state
                .hedge_wave(
                    elapsed_millis(started),
                    &terminal_observations(&observations),
                )
                .map_err(|_| MultiRpcError::Contract("hedge route wave"))?
            {
                let profile = profiles[schedule.provider_index].clone();
                let (endpoint, max_json_depth) = endpoint_for(&self.endpoints, &profile)?;
                hedge_ids.push(schedule.attempt_id.clone());
                spawn_attempt(
                    &mut tasks,
                    LiveAttemptInput {
                        client: self.client.clone(),
                        endpoint,
                        max_json_depth,
                        body: body.clone(),
                        request: request.clone(),
                        profile,
                        attempt_id: schedule.attempt_id,
                        ordinal: schedule.ordinal,
                        started_at_millis: elapsed_millis(started),
                        deadline_millis: schedule.deadline_millis,
                        clock: started,
                    },
                );
            }
        }

        while let Some(joined) = tasks.join_next().await {
            observations
                .push(joined.map_err(|_| MultiRpcError::condition(RpcCondition::ReadUnavailable))?);
        }
        observations.sort_by_key(|value| value.ordinal);

        let mut recoveries = Vec::new();
        let mut next_ordinal = u8::try_from(observations.len() + 1)
            .map_err(|_| MultiRpcError::Contract("attempt ordinal"))?;
        let mut recovery_slots_remaining = self.contract.read_retry_budget();
        let mut preceding_recovery_attempt_id = None;
        let mut used_providers = observations
            .iter()
            .map(|value| {
                (
                    value.profile.profile_digest.clone(),
                    value.profile.provider_instance_id.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        while recovery_slots_remaining > 0 {
            let now = elapsed_millis(started);
            let Some(decision) = route_state
                .next_recovery(
                    &recovery_observations(&observations),
                    preceding_recovery_attempt_id.as_deref(),
                    &used_providers,
                    recovery_slots_remaining,
                    now,
                    next_ordinal,
                )
                .map_err(|_| MultiRpcError::Contract("read recovery state"))?
            else {
                break;
            };
            observations[decision.prior_index].recovery_eligibility = decision.eligibility;
            let prior_attempt_id = observations[decision.prior_index].attempt_id.clone();
            let prior_completed_at = observations[decision.prior_index].completed_at_millis;
            let recovery_started_at = if now <= prior_completed_at {
                tokio::time::sleep(Duration::from_millis(
                    prior_completed_at
                        .checked_add(1)
                        .ok_or(MultiRpcError::Contract("recovery start time"))?
                        .saturating_sub(now),
                ))
                .await;
                elapsed_millis(started)
            } else {
                now
            };
            let profile = profiles[decision.schedule.provider_index].clone();
            let next_id = decision.schedule.attempt_id.clone();
            recoveries.push(ReadRecoveryDraftV1 {
                prior_attempt_id,
                next_attempt_id: next_id.clone(),
                target_profile_digest: profile.profile_digest.clone(),
                target_provider_instance_id: profile.provider_instance_id.clone(),
                kind: decision.kind,
                request_id: request.request_id.clone(),
                authority_context_digest: request.authority_context_digest.clone(),
                immutable_request_digest: request_digest.clone(),
                anchor: request.anchor.clone(),
                remaining_deadline_millis: decision.schedule.deadline_millis,
                remaining_rate_budget: decision.remaining_rate_budget,
            });
            let (endpoint, max_json_depth) = endpoint_for(&self.endpoints, &profile)?;
            let observation = execute_live_attempt(LiveAttemptInput {
                client: self.client.clone(),
                endpoint,
                max_json_depth,
                body: body.clone(),
                request: request.clone(),
                profile,
                attempt_id: next_id,
                ordinal: next_ordinal,
                started_at_millis: recovery_started_at,
                deadline_millis: decision.schedule.deadline_millis,
                clock: started,
            })
            .await;
            used_providers.insert((
                observation.profile.profile_digest.clone(),
                observation.profile.provider_instance_id.clone(),
            ));
            preceding_recovery_attempt_id = Some(observation.attempt_id.clone());
            observations.push(observation);
            recovery_slots_remaining = decision.remaining_rate_budget;
            next_ordinal = next_ordinal
                .checked_add(1)
                .ok_or(MultiRpcError::Contract("attempt ordinal"))?;
        }

        observations.sort_by_key(|value| value.ordinal);
        let attempts = observations
            .iter()
            .map(|value| value.to_draft(&request, &request_digest))
            .collect::<Result<Vec<_>, _>>()?;
        let witness = self
            .contract
            .finish_derived_read(attempts, primary_ids, hedge_ids, recoveries)
            .map_err(|_| MultiRpcError::Contract("terminal route witness"))?;
        let selected_responses = retain_selected_responses(
            &witness,
            &observations,
            &self.local_authority.configuration_digest,
        )?;
        let result = ReadExecutionResult {
            witness,
            selected_responses,
        };
        match result.terminal_event_kind() {
            EventKind::RouteDiverged | EventKind::RouteCompleted => Ok(result),
            _ => Err(MultiRpcError::Contract("terminal read event projection")),
        }
    }
}

fn retain_selected_responses(
    witness: &RequestRouteWitnessV1,
    attempts: &[LiveAttempt],
    local_configuration_digest: &str,
) -> Result<BTreeMap<String, SelectedProviderResponseV1>, MultiRpcError> {
    let pc_provider_api::RouteExecutionV1::IdempotentRead { outcome, .. } = witness.execution()
    else {
        return Err(MultiRpcError::Contract("read execution result"));
    };
    let pc_provider_api::RouteOutcomeV1::Selected(selected) = outcome else {
        return Ok(BTreeMap::new());
    };
    let mut retained = BTreeMap::new();
    let mut canonical: Option<&LocalNormalizedResponseV1> = None;
    for attempt_id in selected.agreement_attempt_ids() {
        let mut matches = attempts
            .iter()
            .filter(|attempt| attempt.attempt_id == attempt_id.as_str());
        let attempt = matches
            .next()
            .ok_or(MultiRpcError::Contract("selected provider observation"))?;
        let normalized = attempt
            .normalized
            .as_ref()
            .ok_or(MultiRpcError::Contract("selected provider observation"))?;
        let response_evidence_digest =
            attempt
                .response_digest
                .as_ref()
                .ok_or(MultiRpcError::Contract(
                    "selected provider response evidence",
                ))?;
        if matches.next().is_some()
            || attempt.truth != selected.truth()
            || normalized.truth() != selected.truth()
            || normalized.digest() != selected.selected_result_digest().as_str()
            || canonical.is_some_and(|value| {
                value.truth() != normalized.truth()
                    || value.digest() != normalized.digest()
                    || value.bytes() != normalized.bytes()
                    || value.provider_observed_anchor() != normalized.provider_observed_anchor()
            })
            || retained
                .insert(
                    attempt_id.as_str().to_owned(),
                    SelectedProviderResponseV1 {
                        normalized: normalized.clone(),
                        response_evidence_digest: response_evidence_digest.clone(),
                        local_authority: LocalTechnicalOnlyV1 {
                            configuration_digest: local_configuration_digest.to_owned(),
                        },
                    },
                )
                .is_some()
        {
            return Err(MultiRpcError::Contract("selected provider observation"));
        }
        canonical.get_or_insert(normalized);
    }
    if retained.len() != selected.agreement_attempt_ids().len() {
        return Err(MultiRpcError::Contract("selected provider observation"));
    }
    Ok(retained)
}

/// The sole externally constructible I06 route executor.
///
/// All semantic configuration is compiled into this constructor. Callers provide only the exact
/// request bytes and loopback resources used by the deterministic local fixture; they cannot
/// author a provider profile, route plan, limit, identity, or authority label.
pub struct LocalFixtureRouteExecutorV1 {
    inner: RouteExecutor,
    request_bytes: Vec<u8>,
    _secret_resource: SecretString,
}

impl LocalFixtureRouteExecutorV1 {
    pub fn for_i06_eth_get_logs(
        request_bytes: &[u8],
        loopback_endpoint: &str,
        secret_resource: &str,
    ) -> Result<Self, MultiRpcError> {
        Self::local_fixture(request_bytes, loopback_endpoint, secret_resource, false)
    }

    /// The candidate-store proof's fixed UUIDv7 scope, with the same loopback-only transport.
    pub fn for_i06_candidate_store_eth_get_logs(
        request_bytes: &[u8],
        loopback_endpoint: &str,
        secret_resource: &str,
    ) -> Result<Self, MultiRpcError> {
        Self::local_fixture(request_bytes, loopback_endpoint, secret_resource, true)
    }

    fn local_fixture(
        request_bytes: &[u8],
        loopback_endpoint: &str,
        secret_resource: &str,
        candidate_store_scope: bool,
    ) -> Result<Self, MultiRpcError> {
        let endpoint = reqwest::Url::parse(loopback_endpoint)
            .map_err(|_| MultiRpcError::Contract("local fixture endpoint"))?;
        if endpoint.scheme() != "http"
            || !endpoint
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"))
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || secret_resource.is_empty()
        {
            return Err(MultiRpcError::Contract("local fixture endpoint"));
        }
        let mut request = local_fixture_request(request_bytes)?;
        if candidate_store_scope {
            request.participant_binding = "018f47a5-4a58-7b21-8f3a-111111111111".into();
            request.privacy_binding = "018f47a5-4a58-7b21-8f3a-222222222222".into();
        }
        let mut profile = local_fixture_profile(&request);
        let binding = ProviderEndpointBinding {
            profile_digest: profile.profile_digest.clone(),
            provider_instance_id: profile.provider_instance_id.clone(),
            endpoint: SecretString::from(endpoint.to_string()),
            secret_reference: "local://i06/multi-rpc/provider-token".to_owned(),
            resolved_secret_version: "fixture-v1".to_owned(),
            resolved_secret_fingerprint: hex_sha256(secret_resource.as_bytes()),
            max_json_depth: LOCAL_FIXTURE_MAX_JSON_DEPTH,
        };
        let configuration_digest = derive_provider_configuration_digest(
            &request,
            std::slice::from_ref(&profile),
            &[],
            &[],
            std::slice::from_ref(&binding),
            LOCAL_FIXTURE_CONFIGURATION_GENERATION,
        )?;
        profile.configuration_digest = configuration_digest.clone();
        validate_local_eth_get_logs_request(
            &request,
            request_bytes,
            &profile.limits,
            LOCAL_FIXTURE_MAX_JSON_DEPTH,
        )?;
        let contract = RouteExecutionContractV1::try_new(request, vec![profile], vec![], None)
            .map_err(|_| MultiRpcError::Contract("local fixture route contract"))?;
        let inner = RouteExecutor::from_contract_and_bindings(
            contract,
            vec![binding],
            &configuration_digest,
        )?;
        Ok(Self {
            inner,
            request_bytes: request_bytes.to_vec(),
            _secret_resource: SecretString::from(secret_resource.to_owned()),
        })
    }

    pub async fn execute(self) -> Result<ReadExecutionResult, MultiRpcError> {
        let Self {
            inner,
            request_bytes,
            _secret_resource,
        } = self;
        inner.execute_read(&request_bytes).await
    }

    pub fn local_configuration_digest(&self) -> &str {
        self.inner
            .local_configuration_digest(
                &self.inner.contract.eligibility().admitted_profiles()[0].profile_digest,
                &self.inner.contract.eligibility().admitted_profiles()[0].provider_instance_id,
            )
            .expect("local fixture owns exactly one provider")
    }
}

fn local_fixture_request(request_bytes: &[u8]) -> Result<RouteRequestV1, MultiRpcError> {
    let request_value = parse_strict_json(request_bytes, LOCAL_FIXTURE_MAX_JSON_DEPTH)?;
    let pinned_block = request_value
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_object)
        .and_then(|filter| filter.get("fromBlock"))
        .and_then(serde_json::Value::as_str)
        .ok_or(MultiRpcError::Contract("local fixture pinned block"))?;
    let (block_number, block_hash, chain_id, genesis_hash) = match pinned_block {
        "0x8" => (
            8,
            LOCAL_FIXTURE_REORG_BLOCK_HASH,
            "1",
            LOCAL_FIXTURE_REORG_GENESIS_HASH,
        ),
        "0x10" => (
            16,
            LOCAL_FIXTURE_BLOCK_HASH,
            "openpc-local-evm-1",
            LOCAL_FIXTURE_GENESIS_HASH,
        ),
        "0x28" => (
            40,
            LOCAL_FIXTURE_EMPTY_REORG_BLOCK_HASH,
            "1",
            LOCAL_FIXTURE_REORG_GENESIS_HASH,
        ),
        _ => return Err(MultiRpcError::Contract("local fixture pinned block")),
    };
    Ok(RouteRequestV1 {
        request_id: "openpc-local-eth-getlogs-1".into(),
        authority_context_digest: digest_label("OPENPC-LOCAL-AUTHORITY-CONTEXT-V1"),
        participant_binding: "participant".into(),
        privacy_binding: "privacy".into(),
        workload_binding: "workload".into(),
        action_intent: "candidate-projection".into(),
        method: "eth_getLogs".into(),
        data_class: "EVENT_LOG".into(),
        normalized_parameter_digest:
            crate::normalization::derive_normalized_parameter_digest_from_request(
                request_bytes,
                LOCAL_FIXTURE_MAX_JSON_DEPTH,
            )?,
        anchor: ChainReadAnchorV1 {
            chain_id: chain_id.into(),
            genesis_hash: genesis_hash.into(),
            network_id: "openpc-local".into(),
            selector_kind: BlockSelectorKind::Pinned,
            block_number: Some(block_number),
            block_hash: Some(block_hash.into()),
            pending_authorized_by_profile: false,
        },
        required_capability_profile_digest: digest_label("OPENPC-LOCAL-CAPABILITY-V1"),
        maximum_response_classification: "participant-confidential".into(),
        idempotency: IdempotencyClass::IdempotentRead,
        request_deadline_millis: 1_000,
        evidence_correlation_id: "openpc-local-i06-correlation-1".into(),
    })
}

fn local_fixture_profile(request: &RouteRequestV1) -> ProviderProfileV1 {
    ProviderProfileV1 {
        profile_id: "openpc-local-i06-provider-profile".into(),
        profile_version: "1.0.0".into(),
        profile_digest: digest_label("OPENPC-LOCAL-I06-PROVIDER-PROFILE"),
        provider_instance_id: "openpc-local-i06-provider".into(),
        provider_release_digest: digest_label("OPENPC-LOCAL-I06-PROVIDER-RELEASE"),
        provider_build_digest: digest_label("OPENPC-LOCAL-I06-PROVIDER-BUILD"),
        configuration_digest: String::new(),
        chain_id: request.anchor.chain_id.clone(),
        genesis_hash: request.anchor.genesis_hash.clone(),
        network_id: request.anchor.network_id.clone(),
        tls_credential_identity: "openpc-local-i06-credential".into(),
        tls_credential_fingerprint: digest_label("OPENPC-LOCAL-I06-CREDENTIAL"),
        trust_epoch: 1,
        json_rpc_version: "2.0".into(),
        method_data_classes: vec![MethodDataClass {
            method: request.method.clone(),
            data_class: request.data_class.clone(),
        }],
        request_schema_digest: digest_label("OPENPC-LOCAL-I06-REQUEST-SCHEMA"),
        response_schema_digest: "ResponseM10V1".into(),
        normalization_rule_digest: "OPENPC-LOCAL-ETH_GETLOGS-EVENT_LOG-NORM-V1".into(),
        limits: ProviderLimits {
            max_request_bytes: 1_024,
            max_response_bytes: 4_096,
            max_range: 1,
            max_batch: 10,
        },
        privacy_behavior_digest: digest_label("OPENPC-LOCAL-I06-PRIVACY"),
        failure_behavior_digest: digest_label("OPENPC-LOCAL-I06-FAILURE"),
        rate_limit_contract_digest: digest_label("OPENPC-LOCAL-I06-RATE"),
        capability_profile_digest: request.required_capability_profile_digest.clone(),
        maximum_response_classification: request.maximum_response_classification.clone(),
        idempotency: IdempotencyClass::IdempotentRead,
        route_plan: RoutePlanDraftV1::SingleExact,
        read_retry_budget: 0,
        timeout_budget_millis: 1_000,
        corpus_digest: digest_label("OPENPC-LOCAL-I06-PROVIDER-CORPUS"),
        conformance_receipt_digest: digest_label("OPENPC-LOCAL-I06-PROVIDER-RECEIPT"),
        lifecycle: ProfileLifecycle::Active,
        evidence_refs: vec![digest_label("OPENPC-LOCAL-I06-PROVIDER-EVIDENCE")],
    }
}

#[derive(Clone, Debug)]
struct LiveAttempt {
    profile: pc_provider_api::ProviderProfileV1,
    attempt_id: String,
    ordinal: u8,
    started_at_millis: u64,
    completed_at_millis: u64,
    deadline_millis: u64,
    normalized: Option<LocalNormalizedResponseV1>,
    response_digest: Option<String>,
    status_digest: Option<String>,
    truth: ResolutionTruth,
    error_digest: Option<String>,
    evidence_refs: Vec<String>,
    recovery_eligibility: RecoveryEligibilityV1,
}

impl LiveAttempt {
    fn to_draft(
        &self,
        request: &pc_provider_api::RouteRequestV1,
        request_digest: &str,
    ) -> Result<RouteAttemptDraftV1, MultiRpcError> {
        let success = self.normalized.is_some();
        let state = if success {
            AttemptState::Resolved
        } else if self.truth == ResolutionTruth::Timeout {
            AttemptState::Unknown
        } else {
            AttemptState::Failed
        };
        let observed_anchor = match (&self.normalized, self.truth) {
            (Some(normalized), ResolutionTruth::Success) => normalized
                .provider_observed_anchor()
                .cloned()
                .ok_or(MultiRpcError::Contract(
                    "successful normalized response has no provider-observed anchor",
                ))?,
            _ => request.anchor.clone(),
        };
        Ok(RouteAttemptDraftV1 {
            envelope: AttemptEnvelopeDraftV1 {
                attempt_id: self.attempt_id.clone(),
                request_id: request.request_id.clone(),
                authority_context_digest: request.authority_context_digest.clone(),
                capability_profile_digest: request.required_capability_profile_digest.clone(),
                profile_digest: self.profile.profile_digest.clone(),
                provider_instance_id: self.profile.provider_instance_id.clone(),
                immutable_request_digest: request_digest.to_owned(),
                anchor: request.anchor.clone(),
                ordinal: self.ordinal,
                state,
                bytes_started_evidence_digest: Some(digest_label(&format!(
                    "bytes-started:{}",
                    self.attempt_id
                ))),
                started_at_millis: Some(self.started_at_millis),
                response_observed_evidence_digest: None,
                observed_at_millis: None,
                completed_at_millis: Some(self.completed_at_millis),
                no_bytes_sent_evidence_digest: None,
                deadline_millis: self.deadline_millis,
                correlation_id: request.evidence_correlation_id.clone(),
                causation_id: request.request_id.clone(),
            },
            resolution: Some(AttemptResolutionDraftV2 {
                truth: self.truth,
                normalized_response_digest: self
                    .normalized
                    .as_ref()
                    .map(|value| value.digest().to_owned()),
                response_digest: self.response_digest.clone(),
                status_digest: self.status_digest.clone(),
                error_digest: self.error_digest.clone(),
                observed_anchor,
                capability_profile_digest: request.required_capability_profile_digest.clone(),
                profile_digest: self.profile.profile_digest.clone(),
                provider_instance_id: self.profile.provider_instance_id.clone(),
                recovery_eligibility: self.recovery_eligibility,
                evidence_refs: self.evidence_refs.clone(),
            }),
        })
    }
}

struct LiveAttemptInput {
    client: Client,
    endpoint: String,
    max_json_depth: u32,
    body: Vec<u8>,
    request: pc_provider_api::RouteRequestV1,
    profile: pc_provider_api::ProviderProfileV1,
    attempt_id: String,
    ordinal: u8,
    started_at_millis: u64,
    deadline_millis: u64,
    clock: Instant,
}

fn spawn_attempt(tasks: &mut JoinSet<LiveAttempt>, input: LiveAttemptInput) {
    tasks.spawn(execute_live_attempt(input));
}

async fn execute_live_attempt(input: LiveAttemptInput) -> LiveAttempt {
    let LiveAttemptInput {
        client,
        endpoint,
        max_json_depth,
        body,
        request,
        profile,
        attempt_id,
        ordinal,
        started_at_millis,
        deadline_millis,
        clock,
    } = input;
    let remaining = deadline_millis.saturating_sub(started_at_millis);
    let sent = tokio::time::timeout(
        Duration::from_millis(remaining),
        client
            .post(endpoint)
            .header("content-type", "application/json")
            .body(body)
            .send(),
    )
    .await;
    let mut base = LiveAttempt {
        profile: profile.clone(),
        attempt_id: attempt_id.clone(),
        ordinal,
        started_at_millis,
        completed_at_millis: elapsed_millis(clock).min(deadline_millis),
        deadline_millis,
        normalized: None,
        response_digest: None,
        status_digest: None,
        truth: ResolutionTruth::Unavailable,
        error_digest: Some(digest_label("transport-unavailable")),
        evidence_refs: vec![digest_label(&format!("attempt-evidence:{attempt_id}"))],
        recovery_eligibility: RecoveryEligibilityV1::None,
    };
    let mut response = match sent {
        Err(_) => {
            base.completed_at_millis = deadline_millis;
            base.truth = ResolutionTruth::Timeout;
            base.error_digest = Some(digest_label("deadline-expired"));
            return base;
        }
        Ok(Err(_)) => return base,
        Ok(Ok(value)) => value,
    };
    let status = response.status().as_u16();
    base.status_digest = Some(digest_label(&format!("http-status:{status}")));
    if status == 429 {
        base.truth = ResolutionTruth::RateLimited;
        base.error_digest = Some(digest_label("rate-limited"));
        base.completed_at_millis = elapsed_millis(clock).min(deadline_millis);
        return base;
    }
    if !response.status().is_success() {
        base.truth = ResolutionTruth::Invalid;
        base.error_digest = Some(digest_label("http-status-invalid"));
        base.completed_at_millis = elapsed_millis(clock).min(deadline_millis);
        return base;
    }
    let completion = match response
        .headers()
        .get("x-openpc-completeness")
        .and_then(|value| value.to_str().ok())
    {
        Some("complete-non-partial") => TransportCompletionV1::CompleteNonPartial,
        Some("partial") => TransportCompletionV1::Partial,
        _ => TransportCompletionV1::UnknownCompleteness,
    };
    let byte_limit = profile.limits.max_response_bytes;
    if response
        .content_length()
        .is_some_and(|length| length > byte_limit)
    {
        base.truth = ResolutionTruth::Invalid;
        base.error_digest = Some(digest_label("response-oversized"));
        return base;
    }
    let mut response_bytes = Vec::new();
    loop {
        let remaining = deadline_millis.saturating_sub(elapsed_millis(clock));
        if remaining == 0 {
            base.completed_at_millis = deadline_millis;
            base.truth = ResolutionTruth::Timeout;
            base.error_digest = Some(digest_label("deadline-expired"));
            return base;
        }
        let chunk =
            match tokio::time::timeout(Duration::from_millis(remaining), response.chunk()).await {
                Err(_) => {
                    base.completed_at_millis = deadline_millis;
                    base.truth = ResolutionTruth::Timeout;
                    base.error_digest = Some(digest_label("deadline-expired"));
                    return base;
                }
                Ok(Err(_)) => return base,
                Ok(Ok(value)) => value,
            };
        let Some(chunk) = chunk else { break };
        let next_size = response_bytes
            .len()
            .checked_add(chunk.len())
            .and_then(|size| u64::try_from(size).ok());
        if next_size.is_none_or(|size| size > byte_limit) {
            base.truth = ResolutionTruth::Invalid;
            base.error_digest = Some(digest_label("response-oversized"));
            return base;
        }
        response_bytes.extend_from_slice(&chunk);
    }
    base.completed_at_millis = elapsed_millis(clock).min(deadline_millis);
    base.response_digest = Some(hex_sha256(&response_bytes));
    match normalize_local_eth_get_logs(
        &response_bytes,
        &request,
        &profile.response_schema_digest,
        &profile.normalization_rule_digest,
        &profile.limits,
        max_json_depth,
        completion,
    ) {
        Ok(normalized) => {
            base.truth = normalized.truth();
            base.error_digest = None;
            base.evidence_refs = vec![digest_label(&format!(
                "normalized:{}:{}",
                attempt_id,
                normalized.digest()
            ))];
            base.normalized = Some(normalized);
        }
        Err(MultiRpcError::Condition {
            code: "PC-OPS-9004",
            ..
        }) => {
            base.truth = ResolutionTruth::Partial;
            base.response_digest = None;
            base.error_digest = Some(digest_label("partial-response"));
        }
        Err(_) => {
            base.truth = ResolutionTruth::Invalid;
            base.response_digest = None;
            base.error_digest = Some(digest_label("invalid-response"));
        }
    }
    base
}

fn terminal_observations(attempts: &[LiveAttempt]) -> Vec<TerminalObservation> {
    attempts
        .iter()
        .map(|attempt| TerminalObservation {
            ordinal: attempt.ordinal,
            completed_at_millis: attempt.completed_at_millis,
            truth: attempt.truth,
            normalized_digest: attempt
                .normalized
                .as_ref()
                .map(|value| value.digest().to_owned()),
        })
        .collect()
}

fn recovery_observations(attempts: &[LiveAttempt]) -> Vec<RecoveryObservation> {
    attempts
        .iter()
        .map(|attempt| RecoveryObservation {
            attempt_id: attempt.attempt_id.clone(),
            profile_digest: attempt.profile.profile_digest.clone(),
            provider_instance_id: attempt.profile.provider_instance_id.clone(),
            ordinal: attempt.ordinal,
            completed_at_millis: attempt.completed_at_millis,
            deadline_millis: attempt.deadline_millis,
            truth: attempt.truth,
            normalized_digest: attempt
                .normalized
                .as_ref()
                .map(|value| value.digest().to_owned()),
        })
        .collect()
}

fn endpoint_for(
    endpoints: &BTreeMap<(String, String), QualifiedProviderRouteV1>,
    profile: &pc_provider_api::ProviderProfileV1,
) -> Result<(String, u32), MultiRpcError> {
    endpoints
        .get(&(
            profile.profile_digest.clone(),
            profile.provider_instance_id.clone(),
        ))
        .map(|value| {
            (
                value.endpoint.expose_secret().to_owned(),
                value.max_json_depth,
            )
        })
        .ok_or_else(|| MultiRpcError::condition(RpcCondition::NoEligibleProvider))
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn digest_label(value: &str) -> String {
    hex_sha256(value.as_bytes())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    render_sha256(&digest)
}

#[cfg(test)]
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn render_sha256(digest: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write to String");
    }
    out
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GovernedWriteSubmissionV1 {
    method: String,
    immutable_request_digest: String,
    request_or_transaction_hash: String,
    provider_profile_digest: String,
    provider_instance_id: String,
    anchor_digest: String,
    canonical_bytes: Vec<u8>,
}

#[cfg(test)]
impl GovernedWriteSubmissionV1 {
    pub(crate) fn try_new(
        identity: (&str, &str, &str, &str, &str, &str),
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, MultiRpcError> {
        let (
            method,
            immutable_request_digest,
            request_or_transaction_hash,
            provider_profile_digest,
            provider_instance_id,
            anchor_digest,
        ) = identity;
        let value = Self {
            method: method.to_owned(),
            immutable_request_digest: immutable_request_digest.to_owned(),
            request_or_transaction_hash: request_or_transaction_hash.to_owned(),
            provider_profile_digest: provider_profile_digest.to_owned(),
            provider_instance_id: provider_instance_id.to_owned(),
            anchor_digest: anchor_digest.to_owned(),
            canonical_bytes,
        };
        if value.canonical_bytes.is_empty()
            || [
                &value.method,
                &value.immutable_request_digest,
                &value.request_or_transaction_hash,
                &value.provider_profile_digest,
                &value.provider_instance_id,
                &value.anchor_digest,
            ]
            .into_iter()
            .any(|field| field.is_empty())
        {
            return Err(MultiRpcError::Contract("governed write submission"));
        }
        Ok(value)
    }
}

#[cfg(test)]
pub(crate) struct GovernedWriteExecutor {
    client: Client,
    contract: RouteExecutionContractV1,
    provider_key: ProviderKeyV1,
    max_response_bytes: u64,
    endpoint: SecretString,
    journal: WriteJournal,
}

#[cfg(test)]
impl GovernedWriteExecutor {
    fn new_test_qualified(
        contract: RouteExecutionContractV1,
        endpoint: SecretString,
        journal: WriteJournal,
    ) -> Result<Self, MultiRpcError> {
        if contract.request().idempotency != IdempotencyClass::GovernedWrite
            || contract.eligibility().admitted_profiles().len() != 1
        {
            return Err(MultiRpcError::Contract(
                "single governed write contract required",
            ));
        }
        let profile = &contract.eligibility().admitted_profiles()[0];
        let provider_key = ProviderKeyV1 {
            profile_digest: ProviderProfileDigest::new(profile.profile_digest.clone())
                .map_err(|_| MultiRpcError::Contract("governed write provider identity"))?,
            provider_instance_id: ProviderInstanceId::new(profile.provider_instance_id.clone())
                .map_err(|_| MultiRpcError::Contract("governed write provider identity"))?,
        };
        let max_response_bytes = contract
            .provider_limits(&provider_key)
            .ok_or(MultiRpcError::Contract("governed write provider limits"))?
            .max_response_bytes;
        let parsed = reqwest::Url::parse(endpoint.expose_secret())
            .map_err(|_| MultiRpcError::Contract("private endpoint binding"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(MultiRpcError::Contract("private endpoint binding"));
        }
        Ok(Self {
            client: Client::new(),
            contract,
            provider_key,
            max_response_bytes,
            endpoint,
            journal,
        })
    }

    pub async fn submit(
        &mut self,
        prepared: PreparedCommand,
        submission: GovernedWriteSubmissionV1,
        started_evidence_digest: String,
        expected_acknowledgement_digest: String,
    ) -> Result<JournalState, MultiRpcError> {
        let command = prepared.command();
        let contract_anchor_digest = hex_sha256(
            &serde_json::to_vec(&self.contract.request().anchor)
                .map_err(|_| MultiRpcError::Contract("governed write anchor"))?,
        );
        if command.method != self.contract.request().method
            || command.immutable_request_digest != self.contract.request_digest().as_str()
            || command.provider_profile_digest != self.provider_key.profile_digest.as_str()
            || command.provider_instance_id != self.provider_key.provider_instance_id.as_str()
            || command.method != submission.method
            || command.immutable_request_digest != submission.immutable_request_digest
            || command.request_or_transaction_hash != submission.request_or_transaction_hash
            || command.provider_profile_digest != submission.provider_profile_digest
            || command.provider_instance_id != submission.provider_instance_id
            || command.anchor_digest != submission.anchor_digest
            || command.anchor_digest != contract_anchor_digest
            || command.submitted_bytes_digest != hex_sha256(&submission.canonical_bytes)
            || started_evidence_digest.is_empty()
            || expected_acknowledgement_digest.is_empty()
        {
            return Err(JournalError::IdentityMismatch.into());
        }
        let started_command = self
            .journal
            .mark_started(prepared, started_evidence_digest)?;
        let deadline = Duration::from_millis(self.contract.effective_deadline_millis());
        let started = Instant::now();
        let response = tokio::time::timeout(
            deadline,
            self.client
                .post(self.endpoint.expose_secret())
                .header("content-type", "application/json")
                .body(submission.canonical_bytes)
                .send(),
        )
        .await;
        let response = match response {
            Ok(Ok(value)) => value,
            Ok(Err(_)) => {
                return self.mark_ambiguous(&started_command, "transport-ended-after-start");
            }
            Err(_) => return self.mark_ambiguous(&started_command, "deadline-expired-after-start"),
        };
        if !response.status().is_success() {
            return self.mark_ambiguous(&started_command, "status-after-start");
        }
        let declared_length = response.content_length();
        if declared_length.is_some_and(|length| length > self.max_response_bytes) {
            return self.mark_ambiguous(&started_command, "acknowledgement-oversized-after-start");
        }
        let mut response = response;
        let mut acknowledgement_size = 0_u64;
        let mut acknowledgement_digest = Sha256::new();
        loop {
            let remaining = match deadline.checked_sub(started.elapsed()) {
                Some(value) => value,
                None => {
                    return self.mark_ambiguous(&started_command, "deadline-expired-after-start");
                }
            };
            let chunk = match tokio::time::timeout(remaining, response.chunk()).await {
                Ok(Ok(value)) => value,
                Ok(Err(_)) => {
                    return self.mark_ambiguous(&started_command, "response-ended-after-start");
                }
                Err(_) => {
                    return self.mark_ambiguous(&started_command, "deadline-expired-after-start");
                }
            };
            let Some(chunk) = chunk else { break };
            acknowledgement_size = match acknowledgement_size
                .checked_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX))
            {
                Some(size) if size <= self.max_response_bytes => size,
                _ => {
                    return self
                        .mark_ambiguous(&started_command, "acknowledgement-oversized-after-start");
                }
            };
            acknowledgement_digest.update(&chunk);
        }
        if declared_length.is_some_and(|length| length != acknowledgement_size) {
            return self.mark_ambiguous(&started_command, "response-truncated-after-start");
        }
        let acknowledgement_digest = acknowledgement_digest.finalize();
        if render_sha256(&acknowledgement_digest) != expected_acknowledgement_digest {
            return self.mark_ambiguous(&started_command, "acknowledgement-digest-mismatch");
        }
        self.journal
            .mark_acknowledged(&started_command, expected_acknowledgement_digest)?;
        Ok(JournalState::Acknowledged)
    }

    fn mark_ambiguous<T>(
        &mut self,
        started: &StartedCommand,
        reason: &str,
    ) -> Result<T, MultiRpcError> {
        self.journal.mark_ambiguous(started, reason.to_owned())?;
        Err(MultiRpcError::condition(RpcCondition::WriteAmbiguity))
    }

    pub fn journal(&self) -> &WriteJournal {
        &self.journal
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::journal::GovernedCommand;
    use pc_provider_api::{
        BlockSelectorKind, ChainReadAnchorV1, MethodDataClass, ProfileLifecycle, ProviderLimits,
        ProviderProfileV1, RoutePlanDraftV1, RouteRequestV1,
    };
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn runtime_permission_surface_accepts_no_terminal_witness() {
        let _: fn(&[u8], &str, &str) -> Result<LocalFixtureRouteExecutorV1, MultiRpcError> =
            LocalFixtureRouteExecutorV1::for_i06_eth_get_logs;
        let _: for<'a> fn(&'a [u8]) -> _ = |_: &[u8]| async {};
    }

    pub(crate) fn qualified_executor(
        contract: RouteExecutionContractV1,
        bindings: Vec<ProviderEndpointBinding>,
    ) -> Result<RouteExecutor, MultiRpcError> {
        let configuration_digest = contract
            .eligibility()
            .admitted_profiles()
            .first()
            .ok_or(MultiRpcError::Contract("test provider"))?
            .configuration_digest
            .clone();
        RouteExecutor::from_contract_and_bindings(contract, bindings, &configuration_digest)
    }

    fn journal_path(name: &str) -> PathBuf {
        PathBuf::from(
            std::env::var("OPENPC_TEST_TMP_ROOT")
                .expect("OPENPC_TEST_TMP_ROOT must name the approved Agents/tmp root"),
        )
        .join(format!("openpc-i06-{name}-{}", uuid::Uuid::now_v7()))
        .join("journal.bin")
    }

    #[tokio::test]
    async fn submitted_bytes_match_prepared_identity_before_any_send() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let sends = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&sends);
        let server = tokio::spawn(async move {
            while let Ok((_, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });
        let bytes = br#"{"jsonrpc":"2.0","method":"eth_sendRawTransaction"}"#.to_vec();
        for drift in 0_u8..9 {
            let path = journal_path(&format!("pre-send-identity-{drift}"));
            let contract = governed_contract();
            let request_digest = contract.request_digest().as_str().to_owned();
            let anchor_digest = governed_anchor_digest(&contract);
            let command_id = format!("command-{drift}");
            let command = GovernedCommand {
                command_id: command_id.clone(),
                method: "eth_sendRawTransaction".into(),
                immutable_request_digest: request_digest.clone(),
                request_or_transaction_hash: "transaction-hash".into(),
                submitted_bytes_digest: hex_sha256(&bytes),
                provider_profile_digest: "profile".into(),
                provider_instance_id: "provider".into(),
                attempt_id: "attempt".into(),
                anchor_digest: anchor_digest.clone(),
                participant_id: "participant".into(),
                privacy_domain_id: "privacy".into(),
                correlation_id: "018f47a5-4a58-7b21-8f3a-222222222222".into(),
                occurred_at: "2026-09-02T00:00:00.000000Z".into(),
            };
            let mut journal = WriteJournal::create_new(&path).expect("journal");
            let prepared = journal.prepare(command).expect("prepared");
            let mut submission = GovernedWriteSubmissionV1::try_new(
                (
                    "eth_sendRawTransaction",
                    &request_digest,
                    "transaction-hash",
                    "profile",
                    "provider",
                    &anchor_digest,
                ),
                bytes.clone(),
            )
            .expect("submission fixture");
            let mut started = "started-evidence".to_owned();
            let mut acknowledgement = "ack-evidence".to_owned();
            match drift {
                0 => submission.canonical_bytes.push(b' '),
                1 => submission.method.push_str("-drift"),
                2 => submission.immutable_request_digest.push_str("-drift"),
                3 => submission.request_or_transaction_hash.push_str("-drift"),
                4 => submission.provider_profile_digest.push_str("-drift"),
                5 => submission.provider_instance_id.push_str("-drift"),
                6 => submission.anchor_digest.push_str("-drift"),
                7 => started.clear(),
                8 => acknowledgement.clear(),
                _ => unreachable!("closed drift inventory"),
            }
            let mut executor = GovernedWriteExecutor::new_test_qualified(
                contract,
                SecretString::from(format!("http://{address}")),
                journal,
            )
            .expect("executor");
            assert!(matches!(
                executor
                    .submit(prepared, submission, started, acknowledgement)
                    .await,
                Err(MultiRpcError::Journal(JournalError::IdentityMismatch))
            ));
            assert_eq!(
                executor.journal().latest_state(&command_id),
                Some(JournalState::Prepared)
            );
            assert_eq!(executor.journal().frame_count(), 1);
            drop(executor);
            std::fs::remove_dir_all(path.parent().expect("parent")).expect("cleanup");
        }
        tokio::task::yield_now().await;
        assert_eq!(sends.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn acknowledgement_digest_mismatch_after_started_is_durably_ambiguous() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await.expect("read");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await
                .expect("response");
        });
        let path = journal_path("ack-mismatch");
        let bytes = br#"{"jsonrpc":"2.0","method":"eth_sendRawTransaction"}"#.to_vec();
        let contract = governed_contract();
        let request_digest = contract.request_digest().as_str().to_owned();
        let anchor_digest = governed_anchor_digest(&contract);
        let command = GovernedCommand {
            command_id: "command-2".into(),
            method: "eth_sendRawTransaction".into(),
            immutable_request_digest: request_digest.clone(),
            request_or_transaction_hash: "transaction-hash".into(),
            submitted_bytes_digest: hex_sha256(&bytes),
            provider_profile_digest: "profile".into(),
            provider_instance_id: "provider".into(),
            attempt_id: "attempt".into(),
            anchor_digest: anchor_digest.clone(),
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            correlation_id: "018f47a5-4a58-7b21-8f3a-222222222222".into(),
            occurred_at: "2026-09-02T00:00:00.000000Z".into(),
        };
        let mut journal = WriteJournal::create_new(&path).expect("journal");
        let prepared = journal.prepare(command).expect("prepared");
        let submission = GovernedWriteSubmissionV1::try_new(
            (
                "eth_sendRawTransaction",
                &request_digest,
                "transaction-hash",
                "profile",
                "provider",
                &anchor_digest,
            ),
            bytes,
        )
        .expect("submission");
        let mut executor = GovernedWriteExecutor::new_test_qualified(
            contract,
            SecretString::from(format!("http://{address}")),
            journal,
        )
        .expect("executor");
        assert!(matches!(
            executor
                .submit(
                    prepared,
                    submission,
                    "started".into(),
                    "not-the-response-digest".into(),
                )
                .await,
            Err(MultiRpcError::Condition {
                code: "PC-RUNTIME-3005",
                ..
            })
        ));
        assert_eq!(
            executor.journal().latest_state("command-2"),
            Some(JournalState::Ambiguous)
        );
        assert_eq!(executor.journal().frame_count(), 3);
        server.await.expect("server");
        drop(executor);
        std::fs::remove_dir_all(path.parent().expect("parent")).expect("cleanup");
    }

    #[tokio::test]
    async fn provider_observed_anchor_is_derived_from_decoded_result_before_terminal_witness() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 1_024];
            let _ = stream.read(&mut request).await.expect("read");
            let body = br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[{"address":"0x1111111111111111111111111111111111111111","blockHash":"0x3333333333333333333333333333333333333333333333333333333333333333","blockNumber":"0x10","data":"0x4444444444444444444444444444444444444444444444444444444444444444","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],"transactionHash":"0x5555555555555555555555555555555555555555555555555555555555555555","transactionIndex":"0x0"}]}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nx-openpc-completeness: complete-non-partial\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("header");
            stream.write_all(body).await.expect("body");
        });
        let contract = crate::state::tests::read_contract();
        let expected_anchor = contract.request().anchor.clone();
        let profile = contract.eligibility().admitted_profiles()[0].clone();
        let result = qualified_executor(
            contract,
            vec![
                ProviderEndpointBinding::new(
                    profile.profile_digest,
                    profile.provider_instance_id,
                    SecretString::from(format!("http://{address}")),
                    "ref:provider",
                    "v1",
                    "ab".repeat(32),
                    8,
                )
                .expect("binding"),
            ],
        )
        .expect("executor")
        .execute_read(read_request_bytes())
        .await
        .expect("provider-derived terminal witness");
        assert_eq!(result.truth(), ResolutionTruth::Success);
        let selected_attempt_id = result.agreement_attempt_ids()[0];
        assert!(
            result
                .selected_normalized_bytes(selected_attempt_id)
                .is_some()
        );
        assert_eq!(
            result.selected_normalized_digest(selected_attempt_id),
            result.normalized_response_digest()
        );
        assert_eq!(
            result.selected_provider_observed_anchor(selected_attempt_id),
            Some(&expected_anchor)
        );
        assert!(
            result
                .selected_normalized_bytes("caller-fabricated-attempt")
                .is_none()
        );
        let resolution = result.witness().attempts()[0]
            .resolution()
            .expect("successful resolution");
        assert_eq!(resolution.observed_anchor(), &expected_anchor);
        assert_eq!(
            resolution
                .normalized_response_digest()
                .map(|digest| digest.as_str()),
            result.normalized_response_digest()
        );
        server.await.expect("server");
    }

    #[test]
    fn local_fixture_configuration_is_construction_and_resource_bound() {
        let baseline = LocalFixtureRouteExecutorV1::for_i06_eth_get_logs(
            read_request_bytes(),
            "http://127.0.0.1:8545/",
            "fixture-secret",
        )
        .expect("compiled local fixture");
        let baseline_digest = baseline.local_configuration_digest().to_owned();
        assert!(!baseline_digest.is_empty());

        let equivalent = LocalFixtureRouteExecutorV1::for_i06_eth_get_logs(
            read_request_bytes(),
            "http://127.0.0.1:8545",
            "fixture-secret",
        )
        .expect("canonical endpoint spelling");
        assert_eq!(equivalent.local_configuration_digest(), baseline_digest);

        let changed_endpoint = LocalFixtureRouteExecutorV1::for_i06_eth_get_logs(
            read_request_bytes(),
            "http://127.0.0.1:8546",
            "fixture-secret",
        )
        .expect("alternate loopback resource");
        assert_ne!(
            changed_endpoint.local_configuration_digest(),
            baseline_digest
        );

        let changed_secret = LocalFixtureRouteExecutorV1::for_i06_eth_get_logs(
            read_request_bytes(),
            "http://127.0.0.1:8545",
            "rotated-fixture-secret",
        )
        .expect("rotated local secret resource");
        assert_ne!(changed_secret.local_configuration_digest(), baseline_digest);

        for endpoint in [
            "https://provider.invalid/rpc",
            "http://user@127.0.0.1:8545/",
            "http://127.0.0.1:8545/?callerProfile=forged",
        ] {
            assert!(
                LocalFixtureRouteExecutorV1::for_i06_eth_get_logs(
                    read_request_bytes(),
                    endpoint,
                    "fixture-secret",
                )
                .is_err(),
                "non-local or authority-bearing endpoint must reject: {endpoint}"
            );
        }
        let duplicate_request = String::from_utf8(read_request_bytes().to_vec())
            .expect("request text")
            .replacen("\"method\":", "\"method\":\"false\",\"method\":", 1);
        assert!(
            LocalFixtureRouteExecutorV1::for_i06_eth_get_logs(
                duplicate_request.as_bytes(),
                "http://127.0.0.1:8545",
                "fixture-secret",
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn invalid_and_partial_transport_results_close_terminal_witness() {
        for (body, completeness, expected_truth) in [
            (
                br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[]}"#.as_slice(),
                Some("partial"),
                ResolutionTruth::Partial,
            ),
            (
                br#"{"extra":true,"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[]}"#
                    .as_slice(),
                Some("complete-non-partial"),
                ResolutionTruth::Invalid,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let address = listener.local_addr().expect("address");
            let response_body = body.to_vec();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = [0_u8; 1_024];
                let _ = stream.read(&mut request).await.expect("read");
                let completeness_header = completeness
                    .map(|value| format!("x-openpc-completeness: {value}\r\n"))
                    .unwrap_or_default();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n{}connection: close\r\n\r\n",
                            response_body.len(),
                            completeness_header,
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("header");
                stream.write_all(&response_body).await.expect("body");
            });
            let executor = qualified_executor(
                crate::state::tests::read_contract(),
                vec![
                    ProviderEndpointBinding::new(
                        "profile-read",
                        "provider-read",
                        SecretString::from(format!("http://{address}")),
                        "ref:provider-read",
                        "v1",
                        "ab".repeat(32),
                        8,
                    )
                    .expect("binding"),
                ],
            )
            .expect("executor");
            let result = executor
                .execute_read(br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","method":"eth_getLogs","params":[{"address":"0x1111111111111111111111111111111111111111","fromBlock":"0x10","toBlock":"0x10","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]}]}"#)
                .await
                .expect("terminal failure witness");
            assert_eq!(result.truth(), expected_truth);
            let attempt = &result.witness().attempts()[0];
            assert!(matches!(
                attempt.envelope().lifecycle(),
                pc_provider_api::AttemptLifecycleV1::FailedAfterStart { .. }
            ));
            assert!(
                attempt
                    .resolution()
                    .expect("resolution")
                    .normalized_response_digest()
                    .is_none()
            );
            server.await.expect("server");
        }
    }

    #[tokio::test]
    async fn route_timeout_is_unknown_and_terminal_event_projection_uses_complete_trace() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 1_024];
            let _ = stream.read(&mut request).await.expect("read");
            tokio::time::sleep(Duration::from_millis(250)).await;
        });
        let contract = recovery_contract(RoutePlanDraftV1::SingleExact, 0, 1);
        let profile = contract.eligibility().admitted_profiles()[0].clone();
        let result = qualified_executor(
            contract,
            vec![
                ProviderEndpointBinding::new(
                    profile.profile_digest,
                    profile.provider_instance_id,
                    SecretString::from(format!("http://{address}")),
                    "ref:provider",
                    "v1",
                    "ab".repeat(32),
                    8,
                )
                .expect("binding"),
            ],
        )
        .expect("executor")
        .execute_read(read_request_bytes())
        .await
        .expect("timeout witness");
        assert_eq!(result.truth(), ResolutionTruth::Timeout);
        let attempt = &result.witness().attempts()[0];
        assert!(matches!(
            attempt.envelope().lifecycle(),
            pc_provider_api::AttemptLifecycleV1::Unknown { .. }
        ));
        let resolution = attempt.resolution().expect("timeout resolution");
        assert_eq!(resolution.truth(), ResolutionTruth::Timeout);
        assert!(resolution.normalized_response_digest().is_none());
        assert_eq!(result.normalized_response_digest(), None);
        assert_eq!(result.terminal_event_kind(), EventKind::RouteCompleted);
        server.abort();

        let contract = recovery_contract(
            RoutePlanDraftV1::HedgedSingle {
                hedge_threshold_millis: 5,
            },
            0,
            2,
        );
        let profiles = contract.eligibility().admitted_profiles().to_vec();
        let mut addresses = Vec::new();
        let mut servers = Vec::new();
        for provider_index in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            addresses.push(listener.local_addr().expect("address"));
            servers.push(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = [0_u8; 1_024];
                let _ = stream.read(&mut request).await.expect("read");
                tokio::time::sleep(Duration::from_millis(20)).await;
                let body = if provider_index == 0 {
                    br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[{"address":"0x1111111111111111111111111111111111111111","blockHash":"0x3333333333333333333333333333333333333333333333333333333333333333","blockNumber":"0x10","data":"0x4444444444444444444444444444444444444444444444444444444444444444","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],"transactionHash":"0x5555555555555555555555555555555555555555555555555555555555555555","transactionIndex":"0x0"}]}"#.as_slice()
                } else {
                    br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[]}"#.as_slice()
                };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nx-openpc-completeness: complete-non-partial\r\nconnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("header");
                stream.write_all(body).await.expect("body");
            }));
        }
        let bindings = profiles
            .iter()
            .zip(addresses)
            .map(|(profile, address)| {
                ProviderEndpointBinding::new(
                    profile.profile_digest.clone(),
                    profile.provider_instance_id.clone(),
                    SecretString::from(format!("http://{address}")),
                    "ref:provider",
                    "v1",
                    "ab".repeat(32),
                    8,
                )
                .expect("binding")
            })
            .collect();
        let result = qualified_executor(contract, bindings)
            .expect("executor")
            .execute_read(read_request_bytes())
            .await
            .expect("hedged dissent witness");
        assert!(matches!(
            result.truth(),
            ResolutionTruth::Success | ResolutionTruth::AuthorizedEmpty
        ));
        assert_eq!(result.witness().attempts().len(), 2);
        assert_eq!(result.terminal_event_kind(), EventKind::RouteDiverged);
        for server in servers {
            server.await.expect("server");
        }
    }

    #[tokio::test]
    async fn retry_failover_require_observed_eligible_failure_and_remaining_budgets() {
        let contract = recovery_contract(
            RoutePlanDraftV1::HedgedSingle {
                hedge_threshold_millis: 5,
            },
            2,
            3,
        );
        let state = LiveRouteState::try_new(&contract).expect("state");
        let first = state.initial_wave().expect("primary").remove(0);
        let unavailable = RecoveryObservation {
            attempt_id: first.attempt_id.clone(),
            profile_digest: "read-profile-1".into(),
            provider_instance_id: "read-provider-1".into(),
            ordinal: 1,
            completed_at_millis: 10,
            deadline_millis: 100,
            truth: ResolutionTruth::Unavailable,
            normalized_digest: None,
        };
        let used = BTreeSet::from([("read-profile-1".into(), "read-provider-1".into())]);
        let failover = state
            .next_recovery(std::slice::from_ref(&unavailable), None, &used, 2, 10, 2)
            .expect("decision")
            .expect("failover");
        assert_eq!(
            failover.kind,
            pc_provider_api::ReadRecoveryKind::FailoverWithinSnapshot
        );
        let failover_profile =
            &contract.eligibility().admitted_profiles()[failover.schedule.provider_index];
        assert_ne!(
            (
                &failover_profile.profile_digest,
                &failover_profile.provider_instance_id
            ),
            (
                &unavailable.profile_digest,
                &unavailable.provider_instance_id
            )
        );
        assert_eq!(
            failover.schedule.provider_index,
            contract
                .eligibility()
                .admitted_profiles()
                .iter()
                .position(|profile| {
                    !used.contains(&(
                        profile.profile_digest.clone(),
                        profile.provider_instance_id.clone(),
                    ))
                })
                .expect("first unused provider")
        );
        assert_eq!(failover.schedule.deadline_millis, 99);
        assert_eq!(failover.remaining_rate_budget, 1);

        let mut rate_limited = unavailable.clone();
        rate_limited.truth = ResolutionTruth::RateLimited;
        let retry = state
            .next_recovery(&[rate_limited], None, &used, 2, 10, 2)
            .expect("decision")
            .expect("same-provider retry");
        assert_eq!(
            retry.kind,
            pc_provider_api::ReadRecoveryKind::RetrySameProvider
        );
        assert_eq!(
            retry.schedule.provider_index,
            contract
                .eligibility()
                .admitted_profiles()
                .iter()
                .position(|profile| profile.profile_digest == unavailable.profile_digest)
                .expect("same provider")
        );
        assert!(
            state
                .next_recovery(std::slice::from_ref(&unavailable), None, &used, 0, 10, 2)
                .expect("exhausted rate budget")
                .is_none()
        );
        assert!(
            state
                .next_recovery(std::slice::from_ref(&unavailable), None, &used, 2, 99, 2)
                .expect("exhausted deadline")
                .is_none()
        );
        for truth in [
            ResolutionTruth::Success,
            ResolutionTruth::AuthorizedEmpty,
            ResolutionTruth::Invalid,
            ResolutionTruth::Partial,
            ResolutionTruth::Denied,
            ResolutionTruth::Divergent,
            ResolutionTruth::Reorg,
            ResolutionTruth::WriteAmbiguity,
        ] {
            let mut ineligible = unavailable.clone();
            ineligible.truth = truth;
            assert!(
                state
                    .next_recovery(&[ineligible], None, &used, 2, 10, 2)
                    .expect("ineligible truth")
                    .is_none()
            );
        }

        let second = RecoveryObservation {
            attempt_id: failover.schedule.attempt_id.clone(),
            profile_digest: failover_profile.profile_digest.clone(),
            provider_instance_id: failover_profile.provider_instance_id.clone(),
            ordinal: 2,
            completed_at_millis: 20,
            deadline_millis: failover.schedule.deadline_millis,
            truth: ResolutionTruth::Timeout,
            normalized_digest: None,
        };
        let used = BTreeSet::from([
            (
                unavailable.profile_digest.clone(),
                unavailable.provider_instance_id.clone(),
            ),
            (
                second.profile_digest.clone(),
                second.provider_instance_id.clone(),
            ),
        ]);
        let chained = state
            .next_recovery(
                &[unavailable, second.clone()],
                Some(&second.attempt_id),
                &used,
                1,
                20,
                3,
            )
            .expect("decision")
            .expect("chained recovery");
        assert_eq!(chained.prior_index, 1);
        assert_eq!(
            chained.schedule.provider_index,
            contract
                .eligibility()
                .admitted_profiles()
                .iter()
                .position(|profile| {
                    !used.contains(&(
                        profile.profile_digest.clone(),
                        profile.provider_instance_id.clone(),
                    ))
                })
                .expect("next unused provider")
        );
        assert!(chained.schedule.deadline_millis < second.deadline_millis);

        assert!(
            GovernedWriteSubmissionV1::try_new(("", "r", "t", "p", "i", "a"), vec![1]).is_err()
        );
        assert!(
            GovernedWriteSubmissionV1::try_new(("m", "r", "t", "p", "i", "a"), vec![]).is_err()
        );

        let contract = recovery_contract(
            RoutePlanDraftV1::HedgedSingle {
                hedge_threshold_millis: 5,
            },
            2,
            3,
        );
        let profiles = contract.eligibility().admitted_profiles().to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            for provider_index in 0..3 {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = [0_u8; 1_024];
                let _ = stream.read(&mut request).await.expect("read");
                if provider_index == 2 {
                    let body =
                        br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[]}"#;
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nx-openpc-completeness: complete-non-partial\r\nconnection: close\r\n\r\n",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .expect("header");
                    stream.write_all(body).await.expect("body");
                }
            }
        });
        let bindings = profiles
            .iter()
            .map(|profile| {
                ProviderEndpointBinding::new(
                    profile.profile_digest.clone(),
                    profile.provider_instance_id.clone(),
                    SecretString::from(format!("http://{address}")),
                    "ref:provider",
                    "v1",
                    "ab".repeat(32),
                    8,
                )
                .expect("binding")
            })
            .collect();
        let result = qualified_executor(contract, bindings)
            .expect("executor")
            .execute_read(read_request_bytes())
            .await
            .expect("failover witness");
        assert_eq!(result.truth(), ResolutionTruth::AuthorizedEmpty);
        assert_eq!(result.witness().attempts().len(), 3);
        assert_eq!(result.witness().recoveries().len(), 1);
        let recovery = &result.witness().recoveries()[0];
        assert_eq!(
            recovery.kind,
            pc_provider_api::ReadRecoveryKind::FailoverWithinSnapshot
        );
        assert_eq!(
            &recovery.target,
            &result
                .witness()
                .attempts()
                .last()
                .expect("recovery attempt")
                .envelope()
                .identity()
                .provider
        );
        assert_eq!(recovery.remaining_rate_budget, 1);
        assert!(recovery.remaining_deadline_millis < 100);
        server.await.expect("server");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            for response_index in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = [0_u8; 1_024];
                let _ = stream.read(&mut request).await.expect("read");
                if response_index == 0 {
                    stream
                        .write_all(
                            b"HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await
                        .expect("rate limited");
                } else {
                    let body =
                        br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[]}"#;
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nx-openpc-completeness: complete-non-partial\r\nconnection: close\r\n\r\n",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .expect("header");
                    stream.write_all(body).await.expect("body");
                }
            }
        });
        let contract = recovery_contract(RoutePlanDraftV1::SingleExact, 1, 1);
        let profile = contract.eligibility().admitted_profiles()[0].clone();
        let result = qualified_executor(
            contract,
            vec![
                ProviderEndpointBinding::new(
                    profile.profile_digest.clone(),
                    profile.provider_instance_id.clone(),
                    SecretString::from(format!("http://{address}")),
                    "ref:provider",
                    "v1",
                    "ab".repeat(32),
                    8,
                )
                .expect("binding"),
            ],
        )
        .expect("executor")
        .execute_read(read_request_bytes())
        .await
        .expect("same-provider retry witness");
        assert_eq!(result.witness().recoveries().len(), 1);
        assert_eq!(
            result.witness().recoveries()[0].kind,
            pc_provider_api::ReadRecoveryKind::RetrySameProvider
        );
        assert_eq!(
            result.witness().recoveries()[0]
                .target
                .profile_digest
                .as_str(),
            profile.profile_digest
        );
        server.await.expect("server");
    }

    fn recovery_contract(
        route_plan: RoutePlanDraftV1,
        retry_budget: u8,
        provider_count: u8,
    ) -> RouteExecutionContractV1 {
        let base = crate::state::tests::read_contract();
        let request = base.request().clone();
        let base_profile = base.original_profiles()[0].clone();
        let profiles = (1..=provider_count)
            .map(|index| {
                let mut profile = base_profile.clone();
                profile.profile_id = format!("read-profile-id-{index}");
                profile.profile_digest = format!("read-profile-{index}");
                profile.provider_instance_id = format!("read-provider-{index}");
                profile.provider_release_digest = format!("release-{index}");
                profile.provider_build_digest = format!("build-{index}");
                profile.tls_credential_identity = format!("credential-{index}");
                profile.tls_credential_fingerprint = format!("fingerprint-{index}");
                profile.route_plan = route_plan.clone();
                profile.read_retry_budget = retry_budget;
                profile
            })
            .collect();
        RouteExecutionContractV1::try_new(request, profiles, vec![], None)
            .expect("recovery contract")
    }

    pub(crate) fn read_request_bytes() -> &'static [u8] {
        br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","method":"eth_getLogs","params":[{"address":"0x1111111111111111111111111111111111111111","fromBlock":"0x10","toBlock":"0x10","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]}]}"#
    }

    fn normalized_result(
        contract: &RouteExecutionContractV1,
        response: &[u8],
    ) -> LocalNormalizedResponseV1 {
        normalize_local_eth_get_logs(
            response,
            contract.request(),
            "ResponseM10V1",
            "OPENPC-LOCAL-ETH_GETLOGS-EVENT_LOG-NORM-V1",
            &contract.original_profiles()[0].limits,
            8,
            TransportCompletionV1::CompleteNonPartial,
        )
        .expect("normalized route result")
    }

    fn derived_attempt(
        profile: pc_provider_api::ProviderProfileV1,
        schedule: crate::state::ScheduledAttempt,
        normalized: LocalNormalizedResponseV1,
        response: &[u8],
        completed_at_millis: u64,
    ) -> LiveAttempt {
        let truth = normalized.truth();
        LiveAttempt {
            profile,
            attempt_id: schedule.attempt_id,
            ordinal: schedule.ordinal,
            started_at_millis: 1,
            completed_at_millis,
            deadline_millis: schedule.deadline_millis,
            normalized: Some(normalized),
            response_digest: Some(hex_sha256(response)),
            status_digest: Some(digest_label("http-status:200")),
            truth,
            error_digest: None,
            evidence_refs: vec![digest_label(&format!(
                "derived-attempt-evidence:{}",
                schedule.ordinal
            ))],
            recovery_eligibility: RecoveryEligibilityV1::None,
        }
    }

    #[test]
    fn shared_terminal_derivation_closes_conflicting_quorums_and_equal_time_hedges() {
        const SUCCESS: &[u8] = br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[{"address":"0x1111111111111111111111111111111111111111","blockHash":"0x3333333333333333333333333333333333333333333333333333333333333333","blockNumber":"0x10","data":"0x4444444444444444444444444444444444444444444444444444444444444444","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],"transactionHash":"0x5555555555555555555555555555555555555555555555555555555555555555","transactionIndex":"0x0"}]}"#;
        const EMPTY: &[u8] = br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[]}"#;

        for (pattern, completions) in [
            ([false, false, true, true], [20, 30, 40, 100]),
            ([false, true, true, false], [100, 40, 30, 20]),
        ] {
            let contract = recovery_contract(
                RoutePlanDraftV1::QuorumIdentical {
                    required_agreement: 2,
                },
                0,
                4,
            );
            let state = LiveRouteState::try_new(&contract).expect("quorum state");
            let schedules = state.initial_wave().expect("quorum schedules");
            let profiles = contract.eligibility().admitted_profiles().to_vec();
            let attempts = schedules
                .into_iter()
                .enumerate()
                .map(|(index, schedule)| {
                    let response = if pattern[index] { EMPTY } else { SUCCESS };
                    derived_attempt(
                        profiles[index].clone(),
                        schedule,
                        normalized_result(&contract, response),
                        response,
                        completions[index],
                    )
                })
                .collect::<Vec<_>>();
            let primary_ids = attempts
                .iter()
                .map(|attempt| attempt.attempt_id.clone())
                .collect::<Vec<_>>();
            let drafts = attempts
                .iter()
                .map(|attempt| {
                    attempt.to_draft(contract.request(), contract.request_digest().as_str())
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("attempt drafts");
            let witness = contract
                .finish_derived_read(drafts, primary_ids, vec![], vec![])
                .expect("derived divergent witness");
            let pc_provider_api::RouteExecutionV1::IdempotentRead {
                outcome: pc_provider_api::RouteOutcomeV1::Divergent { evidence_refs },
                ..
            } = witness.execution()
            else {
                panic!("multiple qualifying groups must diverge")
            };
            assert_eq!(evidence_refs.len(), 4);
            let result = ReadExecutionResult {
                witness,
                selected_responses: BTreeMap::new(),
            };
            assert_eq!(result.terminal_event_kind(), EventKind::RouteDiverged);
            assert_eq!(RpcCondition::Divergent.mapping().code, "PC-RUNTIME-3011");
        }

        let contract = recovery_contract(
            RoutePlanDraftV1::HedgedQuorumIdentical {
                required_agreement: 2,
                hedge_threshold_millis: 5,
                max_hedge_attempts: 1,
            },
            0,
            4,
        );
        let state = LiveRouteState::try_new(&contract).expect("hedged quorum state");
        let mut schedules = state.initial_wave().expect("hedged quorum primaries");
        let primary_count = schedules.len();
        schedules.extend(state.hedge_wave(5, &[]).expect("hedged quorum hedge"));
        let profiles = contract.eligibility().admitted_profiles().to_vec();
        let pattern = [false, true, true, false];
        let mut attempts = schedules
            .into_iter()
            .enumerate()
            .map(|(index, schedule)| {
                let response = if pattern[index] { EMPTY } else { SUCCESS };
                derived_attempt(
                    profiles[index].clone(),
                    schedule,
                    normalized_result(&contract, response),
                    response,
                    10 + u64::try_from(index).expect("bounded index"),
                )
            })
            .collect::<Vec<_>>();
        attempts[primary_count].started_at_millis = 6;
        let primary_ids = attempts[..primary_count]
            .iter()
            .map(|attempt| attempt.attempt_id.clone())
            .collect::<Vec<_>>();
        let hedge_ids = attempts[primary_count..]
            .iter()
            .map(|attempt| attempt.attempt_id.clone())
            .collect::<Vec<_>>();
        let drafts = attempts
            .iter()
            .map(|attempt| attempt.to_draft(contract.request(), contract.request_digest().as_str()))
            .collect::<Result<Vec<_>, _>>()
            .expect("hedged quorum drafts");
        let witness = contract
            .finish_derived_read(drafts, primary_ids, hedge_ids, vec![])
            .expect("derived hedged quorum witness");
        assert!(matches!(
            witness.execution(),
            pc_provider_api::RouteExecutionV1::IdempotentRead {
                outcome: pc_provider_api::RouteOutcomeV1::Divergent { .. },
                ..
            }
        ));
        assert_eq!(
            ReadExecutionResult {
                witness,
                selected_responses: BTreeMap::new(),
            }
            .terminal_event_kind(),
            EventKind::RouteDiverged
        );

        let contract = recovery_contract(
            RoutePlanDraftV1::HedgedSingle {
                hedge_threshold_millis: 5,
            },
            0,
            2,
        );
        let state = LiveRouteState::try_new(&contract).expect("hedged state");
        let primary = state.initial_wave().expect("primary").remove(0);
        let hedge = state.hedge_wave(5, &[]).expect("hedge").remove(0);
        let profiles = contract.eligibility().admitted_profiles().to_vec();
        let mut attempts = [
            derived_attempt(
                profiles[0].clone(),
                primary,
                normalized_result(&contract, SUCCESS),
                SUCCESS,
                10,
            ),
            derived_attempt(
                profiles[1].clone(),
                hedge,
                normalized_result(&contract, EMPTY),
                EMPTY,
                10,
            ),
        ];
        attempts[1].started_at_millis = 6;
        let primary_ids = vec![attempts[0].attempt_id.clone()];
        let hedge_ids = vec![attempts[1].attempt_id.clone()];
        let drafts = attempts
            .iter()
            .map(|attempt| attempt.to_draft(contract.request(), contract.request_digest().as_str()))
            .collect::<Result<Vec<_>, _>>()
            .expect("hedged drafts");
        let witness = contract
            .finish_derived_read(drafts, primary_ids, hedge_ids, vec![])
            .expect("derived equal-time witness");
        assert!(matches!(
            witness.execution(),
            pc_provider_api::RouteExecutionV1::IdempotentRead {
                outcome: pc_provider_api::RouteOutcomeV1::Divergent { .. },
                ..
            }
        ));
        let result = ReadExecutionResult {
            witness,
            selected_responses: BTreeMap::new(),
        };
        assert_eq!(result.terminal_event_kind(), EventKind::RouteDiverged);
    }

    fn governed_contract() -> RouteExecutionContractV1 {
        let request = RouteRequestV1 {
            request_id: "request".into(),
            authority_context_digest: "authority".into(),
            participant_binding: "participant".into(),
            privacy_binding: "privacy".into(),
            workload_binding: "workload".into(),
            action_intent: "governed-write".into(),
            method: "eth_sendRawTransaction".into(),
            data_class: "transaction".into(),
            normalized_parameter_digest: "parameters".into(),
            anchor: ChainReadAnchorV1 {
                chain_id: "1".into(),
                genesis_hash: "genesis".into(),
                network_id: "network".into(),
                selector_kind: BlockSelectorKind::Pinned,
                block_number: Some(42),
                block_hash: Some("block-42".into()),
                pending_authorized_by_profile: false,
            },
            required_capability_profile_digest: "capability".into(),
            maximum_response_classification: "participant-confidential".into(),
            idempotency: IdempotencyClass::GovernedWrite,
            request_deadline_millis: 100,
            evidence_correlation_id: "correlation".into(),
        };
        let profile = ProviderProfileV1 {
            profile_id: "profile-id".into(),
            profile_version: "1".into(),
            profile_digest: "profile".into(),
            provider_instance_id: "provider".into(),
            provider_release_digest: "release".into(),
            provider_build_digest: "build".into(),
            configuration_digest: "configuration".into(),
            chain_id: "1".into(),
            genesis_hash: "genesis".into(),
            network_id: "network".into(),
            tls_credential_identity: "credential".into(),
            tls_credential_fingerprint: "fingerprint".into(),
            trust_epoch: 1,
            json_rpc_version: "2.0".into(),
            method_data_classes: vec![MethodDataClass {
                method: "eth_sendRawTransaction".into(),
                data_class: "transaction".into(),
            }],
            request_schema_digest: "request-schema".into(),
            response_schema_digest: "response-schema".into(),
            normalization_rule_digest: "normalization".into(),
            limits: ProviderLimits {
                max_request_bytes: 1024,
                max_response_bytes: 4096,
                max_range: 1,
                max_batch: 1,
            },
            privacy_behavior_digest: "privacy-policy".into(),
            failure_behavior_digest: "failure-policy".into(),
            rate_limit_contract_digest: "rate-policy".into(),
            capability_profile_digest: "capability".into(),
            maximum_response_classification: "participant-confidential".into(),
            idempotency: IdempotencyClass::GovernedWrite,
            route_plan: RoutePlanDraftV1::SingleExact,
            read_retry_budget: 0,
            timeout_budget_millis: 100,
            corpus_digest: "corpus".into(),
            conformance_receipt_digest: "receipt".into(),
            lifecycle: ProfileLifecycle::Active,
            evidence_refs: vec!["profile-evidence".into()],
        };
        RouteExecutionContractV1::try_new(request, vec![profile], vec![], None)
            .expect("governed write contract")
    }

    fn governed_anchor_digest(contract: &RouteExecutionContractV1) -> String {
        hex_sha256(&serde_json::to_vec(&contract.request().anchor).expect("anchor JSON"))
    }
}
