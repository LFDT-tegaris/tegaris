//! Private live route state. No caller-authored schedule, resolution or outcome enters here.

use std::collections::BTreeSet;

use pc_provider_api::{
    ReadRecoveryKind, RecoveryEligibilityV1, ResolutionTruth, RouteExecutionContractV1, RoutePlanV1,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TerminalObservation {
    pub(crate) ordinal: u8,
    pub(crate) completed_at_millis: u64,
    pub(crate) truth: ResolutionTruth,
    pub(crate) normalized_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryObservation {
    pub(crate) attempt_id: String,
    pub(crate) profile_digest: String,
    pub(crate) provider_instance_id: String,
    pub(crate) ordinal: u8,
    pub(crate) completed_at_millis: u64,
    pub(crate) deadline_millis: u64,
    pub(crate) truth: ResolutionTruth,
    pub(crate) normalized_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScheduledAttempt {
    pub(crate) provider_index: usize,
    pub(crate) attempt_id: String,
    pub(crate) ordinal: u8,
    pub(crate) deadline_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryDecision {
    pub(crate) prior_index: usize,
    pub(crate) schedule: ScheduledAttempt,
    pub(crate) kind: ReadRecoveryKind,
    pub(crate) eligibility: RecoveryEligibilityV1,
    pub(crate) remaining_rate_budget: u8,
}

/// Single production scheduler/recovery owner consumed by `RouteExecutor`.
pub(crate) struct LiveRouteState {
    route_plan: RoutePlanV1,
    providers: Vec<(String, String)>,
    request_digest: String,
    primary_count: usize,
    hedge_limit: usize,
    hedge_threshold_millis: Option<u64>,
    required_agreement: usize,
    effective_deadline_millis: u64,
}

impl LiveRouteState {
    pub(crate) fn try_new(contract: &RouteExecutionContractV1) -> Result<Self, &'static str> {
        let providers = contract
            .eligibility()
            .admitted_profiles()
            .iter()
            .map(|profile| {
                (
                    profile.profile_digest.clone(),
                    profile.provider_instance_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        Self::from_parts(
            contract.route_plan().clone(),
            providers,
            contract.request_digest().as_str().to_owned(),
            contract.effective_deadline_millis(),
        )
    }

    fn from_parts(
        route_plan: RoutePlanV1,
        providers: Vec<(String, String)>,
        request_digest: String,
        effective_deadline_millis: u64,
    ) -> Result<Self, &'static str> {
        let (primary_count, hedge_limit, hedge_threshold_millis) = match &route_plan {
            RoutePlanV1::SingleExact => (1, 0, None),
            RoutePlanV1::QuorumIdentical { .. } => (providers.len(), 0, None),
            RoutePlanV1::HedgedSingle {
                hedge_threshold_millis,
            } => (1, 1, Some(*hedge_threshold_millis)),
            RoutePlanV1::HedgedQuorumIdentical {
                hedge_threshold_millis,
                max_hedge_attempts,
                ..
            } => (
                providers
                    .len()
                    .checked_sub(usize::from(*max_hedge_attempts))
                    .ok_or("hedge count")?,
                usize::from(*max_hedge_attempts),
                Some(*hedge_threshold_millis),
            ),
        };
        if providers.is_empty()
            || primary_count == 0
            || primary_count + hedge_limit > providers.len()
            || effective_deadline_millis == 0
        {
            return Err("closed live route state");
        }
        Ok(Self {
            required_agreement: route_plan.required_agreement(),
            route_plan,
            providers,
            request_digest,
            primary_count,
            hedge_limit,
            hedge_threshold_millis,
            effective_deadline_millis,
        })
    }

    pub(crate) fn initial_wave(&self) -> Result<Vec<ScheduledAttempt>, &'static str> {
        (0..self.primary_count)
            .map(|provider_index| {
                self.schedule(
                    provider_index,
                    provider_index + 1,
                    self.effective_deadline_millis,
                )
            })
            .collect()
    }

    pub(crate) fn hedge_threshold_millis(&self) -> Option<u64> {
        self.hedge_threshold_millis
    }

    pub(crate) fn hedge_wave(
        &self,
        elapsed_millis: u64,
        observations: &[TerminalObservation],
    ) -> Result<Vec<ScheduledAttempt>, &'static str> {
        let Some(threshold) = self.hedge_threshold_millis else {
            return Ok(Vec::new());
        };
        if elapsed_millis < threshold || self.has_agreement(observations) {
            return Ok(Vec::new());
        }
        (0..self.hedge_limit)
            .map(|offset| {
                let provider_index = self.primary_count + offset;
                self.schedule(
                    provider_index,
                    provider_index + 1,
                    self.effective_deadline_millis,
                )
            })
            .collect()
    }

    pub(crate) fn has_agreement(&self, observations: &[TerminalObservation]) -> bool {
        observations.iter().enumerate().any(|(index, candidate)| {
            candidate.normalized_digest.as_ref().is_some_and(|digest| {
                observations[..=index]
                    .iter()
                    .filter(|value| {
                        value.truth == candidate.truth
                            && value.normalized_digest.as_ref() == Some(digest)
                    })
                    .count()
                    >= self.required_agreement
            })
        })
    }

    pub(crate) fn next_recovery(
        &self,
        observations: &[RecoveryObservation],
        preceding_recovery_attempt_id: Option<&str>,
        used_providers: &BTreeSet<(String, String)>,
        recovery_slots_remaining: u8,
        now_millis: u64,
        next_ordinal: u8,
    ) -> Result<Option<RecoveryDecision>, &'static str> {
        if recovery_slots_remaining == 0
            || self.has_agreement(
                &observations
                    .iter()
                    .map(RecoveryObservation::terminal)
                    .collect::<Vec<_>>(),
            )
        {
            return Ok(None);
        }
        let prior_index = match preceding_recovery_attempt_id {
            Some(id) => observations
                .iter()
                .position(|observation| observation.attempt_id == id)
                .ok_or("preceding recovery attempt")?,
            None => match observations
                .iter()
                .enumerate()
                .filter(|(_, observation)| recoverable_truth(observation.truth))
                .min_by_key(|(_, observation)| {
                    (observation.completed_at_millis, observation.ordinal)
                }) {
                Some((index, _)) => index,
                None => return Ok(None),
            },
        };
        let prior = &observations[prior_index];
        if !recoverable_truth(prior.truth) || prior.normalized_digest.is_some() {
            return Ok(None);
        }
        let next_deadline = match prior.deadline_millis.checked_sub(1) {
            Some(deadline) if now_millis < deadline => deadline,
            _ => return Ok(None),
        };
        let prior_key = (
            prior.profile_digest.clone(),
            prior.provider_instance_id.clone(),
        );
        let unused = self
            .providers
            .iter()
            .enumerate()
            .find(|(_, provider)| !used_providers.contains(*provider));
        let (provider_index, kind, eligibility) = match prior.truth {
            ResolutionTruth::RateLimited => (
                self.provider_index(&prior_key)?,
                ReadRecoveryKind::RetrySameProvider,
                RecoveryEligibilityV1::RetrySameProvider,
            ),
            ResolutionTruth::Unavailable | ResolutionTruth::Timeout
                if !matches!(self.route_plan, RoutePlanV1::SingleExact) && unused.is_some() =>
            {
                (
                    unused.expect("checked").0,
                    ReadRecoveryKind::FailoverWithinSnapshot,
                    RecoveryEligibilityV1::FailoverWithinSnapshot,
                )
            }
            ResolutionTruth::Unavailable | ResolutionTruth::Timeout => (
                self.provider_index(&prior_key)?,
                ReadRecoveryKind::RetrySameProvider,
                RecoveryEligibilityV1::RetrySameProvider,
            ),
            _ => return Ok(None),
        };
        Ok(Some(RecoveryDecision {
            prior_index,
            schedule: self.schedule(provider_index, usize::from(next_ordinal), next_deadline)?,
            kind,
            eligibility,
            remaining_rate_budget: recovery_slots_remaining - 1,
        }))
    }

    fn provider_index(&self, key: &(String, String)) -> Result<usize, &'static str> {
        self.providers
            .iter()
            .position(|provider| provider == key)
            .ok_or("recovery provider")
    }

    fn schedule(
        &self,
        provider_index: usize,
        ordinal: usize,
        deadline_millis: u64,
    ) -> Result<ScheduledAttempt, &'static str> {
        let provider = self.providers.get(provider_index).ok_or("provider index")?;
        let ordinal = u8::try_from(ordinal).map_err(|_| "attempt ordinal")?;
        Ok(ScheduledAttempt {
            provider_index,
            attempt_id: attempt_id(&self.request_digest, &provider.0, &provider.1, ordinal),
            ordinal,
            deadline_millis,
        })
    }
}

impl RecoveryObservation {
    fn terminal(&self) -> TerminalObservation {
        TerminalObservation {
            ordinal: self.ordinal,
            completed_at_millis: self.completed_at_millis,
            truth: self.truth,
            normalized_digest: self.normalized_digest.clone(),
        }
    }
}

fn recoverable_truth(truth: ResolutionTruth) -> bool {
    matches!(
        truth,
        ResolutionTruth::Unavailable | ResolutionTruth::RateLimited | ResolutionTruth::Timeout
    )
}

#[cfg(test)]
pub(crate) fn earliest_valid(values: &[TerminalObservation]) -> Option<&TerminalObservation> {
    values
        .iter()
        .filter(|value| value.normalized_digest.is_some())
        .min_by_key(|value| (value.completed_at_millis, value.ordinal))
}

fn attempt_id(
    request_digest: &str,
    profile_digest: &str,
    provider_instance_id: &str,
    ordinal: u8,
) -> String {
    let mut material = b"openpc:route-attempt:v1\0".to_vec();
    material.extend_from_slice(request_digest.as_bytes());
    material.push(0);
    material.extend_from_slice(profile_digest.as_bytes());
    material.push(0);
    material.extend_from_slice(provider_instance_id.as_bytes());
    material.push(ordinal);
    let digest = Sha256::digest(material);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write to String");
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::runtime::ProviderEndpointBinding;
    use pc_provider_api::{
        BlockSelectorKind, ChainReadAnchorV1, IdempotencyClass, MethodDataClass, ProfileLifecycle,
        ProviderLimits, ProviderProfileV1, RoutePlanDraftV1, RouteRequestV1,
    };
    use secrecy::SecretString;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn state(route_plan: RoutePlanV1, providers: usize) -> LiveRouteState {
        LiveRouteState::from_parts(
            route_plan,
            (1..=providers)
                .map(|index| (format!("profile-{index}"), format!("provider-{index}")))
                .collect(),
            "request-digest".into(),
            100,
        )
        .expect("state")
    }

    fn terminal(
        ordinal: u8,
        completed_at_millis: u64,
        truth: ResolutionTruth,
        digest: Option<&str>,
    ) -> TerminalObservation {
        TerminalObservation {
            ordinal,
            completed_at_millis,
            truth,
            normalized_digest: digest.map(str::to_owned),
        }
    }

    pub(crate) fn read_contract() -> RouteExecutionContractV1 {
        let request = RouteRequestV1 {
            request_id: "openpc-local-eth-getlogs-1".into(),
            authority_context_digest: "authority".into(),
            participant_binding: "participant".into(),
            privacy_binding: "privacy".into(),
            workload_binding: "workload".into(),
            action_intent: "read".into(),
            method: "eth_getLogs".into(),
            data_class: "EVENT_LOG".into(),
            normalized_parameter_digest:
                crate::normalization::derive_normalized_parameter_digest_from_request(
                    crate::runtime::tests::read_request_bytes(),
                    8,
                )
                .expect("actual read request parameter digest"),
            anchor: ChainReadAnchorV1 {
                chain_id: "1".into(),
                genesis_hash: "11".repeat(32),
                network_id: "openpc-local".into(),
                selector_kind: BlockSelectorKind::Pinned,
                block_number: Some(16),
                block_hash: Some(format!("0x{}", "33".repeat(32))),
                pending_authorized_by_profile: false,
            },
            required_capability_profile_digest: "capability".into(),
            maximum_response_classification: "participant-confidential".into(),
            idempotency: IdempotencyClass::IdempotentRead,
            request_deadline_millis: 100,
            evidence_correlation_id: "correlation".into(),
        };
        let profile = ProviderProfileV1 {
            profile_id: "profile-read".into(),
            profile_version: "1".into(),
            profile_digest: "profile-read".into(),
            provider_instance_id: "provider-read".into(),
            provider_release_digest: "release".into(),
            provider_build_digest: "build".into(),
            configuration_digest: "configuration".into(),
            chain_id: "1".into(),
            genesis_hash: "11".repeat(32),
            network_id: "openpc-local".into(),
            tls_credential_identity: "credential".into(),
            tls_credential_fingerprint: "fingerprint".into(),
            trust_epoch: 1,
            json_rpc_version: "2.0".into(),
            method_data_classes: vec![MethodDataClass {
                method: "eth_getLogs".into(),
                data_class: "EVENT_LOG".into(),
            }],
            request_schema_digest: "request-schema".into(),
            response_schema_digest: "ResponseM10V1".into(),
            normalization_rule_digest: "OPENPC-LOCAL-ETH_GETLOGS-EVENT_LOG-NORM-V1".into(),
            limits: ProviderLimits {
                max_request_bytes: 1_024,
                max_response_bytes: 4_096,
                max_range: 1,
                max_batch: 1,
            },
            privacy_behavior_digest: "privacy-policy".into(),
            failure_behavior_digest: "failure-policy".into(),
            rate_limit_contract_digest: "rate-policy".into(),
            capability_profile_digest: "capability".into(),
            maximum_response_classification: "participant-confidential".into(),
            idempotency: IdempotencyClass::IdempotentRead,
            route_plan: RoutePlanDraftV1::SingleExact,
            read_retry_budget: 0,
            timeout_budget_millis: 100,
            corpus_digest: "corpus".into(),
            conformance_receipt_digest: "receipt".into(),
            lifecycle: ProfileLifecycle::Active,
            evidence_refs: vec!["profile-evidence".into()],
        };
        RouteExecutionContractV1::try_new(request, vec![profile], vec![], None)
            .expect("read contract")
    }

    #[tokio::test(start_paused = true)]
    async fn live_route_state_machine_is_time_deterministic_and_trace_complete() {
        let hedged = state(
            RoutePlanV1::HedgedSingle {
                hedge_threshold_millis: 5,
            },
            2,
        );
        let primary = hedged.initial_wave().expect("initial wave");
        assert_eq!(primary.len(), 1);
        assert_eq!(primary[0].ordinal, 1);
        assert_eq!(primary[0].attempt_id.len(), 64);

        tokio::time::advance(std::time::Duration::from_millis(4)).await;
        let early_failure = vec![terminal(1, 2, ResolutionTruth::Unavailable, None)];
        assert!(
            hedged
                .hedge_wave(4, &early_failure)
                .expect("before threshold")
                .is_empty()
        );
        tokio::time::advance(std::time::Duration::from_millis(1)).await;
        let hedge = hedged
            .hedge_wave(5, &early_failure)
            .expect("threshold hedge");
        assert_eq!(hedge.len(), 1);
        assert_eq!(hedge[0].ordinal, 2);

        for completion in [4, 5] {
            let success = vec![terminal(
                1,
                completion,
                ResolutionTruth::Success,
                Some("same"),
            )];
            assert!(
                hedged
                    .hedge_wave(5, &success)
                    .expect("success blocks hedge")
                    .is_empty()
            );
        }
        let slow_primary_fast_hedge = vec![
            terminal(1, 10, ResolutionTruth::Success, Some("primary")),
            terminal(2, 7, ResolutionTruth::Success, Some("hedge")),
        ];
        assert_eq!(
            earliest_valid(&slow_primary_fast_hedge).map(|value| value.ordinal),
            Some(2)
        );
        let mut permuted = slow_primary_fast_hedge.clone();
        permuted.reverse();
        assert_eq!(
            earliest_valid(&permuted).map(|value| value.ordinal),
            Some(2)
        );
        let equal_time = vec![
            terminal(2, 7, ResolutionTruth::Success, Some("second")),
            terminal(1, 7, ResolutionTruth::Success, Some("first")),
        ];
        assert_eq!(
            earliest_valid(&equal_time).map(|value| value.ordinal),
            Some(1)
        );
        let hedged_dissent = [
            terminal(1, 8, ResolutionTruth::Success, Some("left")),
            terminal(2, 9, ResolutionTruth::Success, Some("dissent")),
        ];
        assert!(hedged.has_agreement(&hedged_dissent));
        assert_eq!(
            earliest_valid(&hedged_dissent).map(|value| value.ordinal),
            Some(1)
        );

        let quorum = state(
            RoutePlanV1::HedgedQuorumIdentical {
                required_agreement: 2,
                hedge_threshold_millis: 5,
                max_hedge_attempts: 1,
            },
            3,
        );
        assert_eq!(quorum.initial_wave().expect("quorum primaries").len(), 2);
        let reached = vec![
            terminal(1, 3, ResolutionTruth::Success, Some("same")),
            terminal(2, 4, ResolutionTruth::Success, Some("same")),
        ];
        assert!(quorum.has_agreement(&reached));
        assert!(
            quorum
                .hedge_wave(5, &reached)
                .expect("closed quorum")
                .is_empty()
        );
        let unreached = vec![
            terminal(1, 3, ResolutionTruth::Success, Some("left")),
            terminal(2, 4, ResolutionTruth::Success, Some("right")),
        ];
        assert_eq!(
            quorum
                .hedge_wave(5, &unreached)
                .expect("quorum hedge")
                .len(),
            1
        );
        assert_eq!(primary.len() + hedge.len(), slow_primary_fast_hedge.len());

        tokio::time::resume();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 1_024];
            let _ = stream.read(&mut request).await.expect("read");
            let body = br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[]}"#;
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
        let contract = read_contract();
        let executor = crate::runtime::tests::qualified_executor(
            contract,
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
            .expect("production route executor");
        assert_eq!(result.truth(), ResolutionTruth::AuthorizedEmpty);
        assert_eq!(result.witness().attempts().len(), 1);
        server.await.expect("server");
    }
}
