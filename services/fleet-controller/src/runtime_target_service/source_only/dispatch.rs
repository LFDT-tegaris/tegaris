//! Dedicated COM-016 source reads. This owner never emits a Broker capability
//! and cannot use invocation permission in place of an exact source-read grant.
use super::*;
use crate::indexer_publication::{self, source_current};
use openpc_indexer_adapter::{AcquisitionConfiguration, DecodedAcquisitionRequest};
use openpc_multi_rpc::source_header::SourceBlockHeader;
use openpc_pds::{EvaluationInput, LocalDecisionLease, LocalDecisionOwner};
use openpc_runtime_agent::{ActiveCapsuleLease, decision_evidence::SourceReadEvidenceInput};
use pc_policy_core::{
    indexer_policy::{IndexerDataClass, IndexerPolicyRequest},
    invocation::ConfigurationArtifactKind,
};
use pc_runtime_types::{RuntimeDecision, RuntimeRequest, canonical_bytes};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::time::Duration;

pub(super) async fn control_reader() -> TargetResult<Option<PgPool>> {
    let Some(path) = env::var_os("OPENPC_TARGET_SOURCE_CONTROL_PASSWORD_FILE") else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err("source Control secret path rejected".into());
    }
    let password = fs::read_to_string(path).map_err(|_| "source Control secret unavailable")?;
    if password.trim().is_empty() || password.len() > 4096 {
        return Err("source Control secret oversized".into());
    }
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(
            sqlx::postgres::PgConnectOptions::new()
                .host(&required("OPENPC_TARGET_SOURCE_CONTROL_HOST")?)
                .port(
                    required("OPENPC_TARGET_SOURCE_CONTROL_PORT")?
                        .parse()
                        .map_err(|_| "source Control port rejected")?,
                )
                .database("openpc_control")
                .username(&required("OPENPC_TARGET_SOURCE_CONTROL_USER")?)
                .password(password.trim()),
        )
        .await
        .map_err(|_| "source Control reader unavailable")?;
    let safe: bool = sqlx::query_scalar("select current_database()='openpc_control' and pg_has_role(current_user,'openpc_control_reader','MEMBER') and not has_table_privilege(current_user,'control.runtime_target','UPDATE') and not has_table_privilege(current_user,'control.indexer_profile','UPDATE')")
        .fetch_one(&pool).await.map_err(|_| "source Control identity unavailable")?;
    if !safe {
        return Err("source Control requires its read-only identity".into());
    }
    Ok(Some(pool))
}

fn report_unavailable(error: &RuntimeError, stage: &'static str, trace: &RequestTraceId) {
    if matches!(error, RuntimeError::RuntimeUnavailable) {
        eprintln!(
            "{}",
            serde_json::json!({
                "boundary": "source-read-unavailable",
                "stage": stage,
                "traceId": trace.as_str(),
            })
        );
    }
}

pub(super) struct SourceRequest {
    owner: SourceTransportOwner,
    peer: WorkloadPeer,
    generation: EnvoyGeneration,
    trace: RequestTraceId,
    id: Option<String>,
}

impl SourceRequest {
    pub(super) fn new(
        owner: SourceTransportOwner,
        peer: &WorkloadPeer,
        generation: &EnvoyGeneration,
        trace: &RequestTraceId,
    ) -> Self {
        Self {
            owner,
            peer: peer.clone(),
            generation: generation.clone(),
            trace: trace.clone(),
            id: None,
        }
    }
}

struct AdmittedSourceRequest {
    owner: SourceTransportOwner,
    peer: WorkloadPeer,
    generation: EnvoyGeneration,
    trace: RequestTraceId,
    capsule_digest: Digest,
    target: String,
    id: Option<String>,
}

struct PreparedSourceRead {
    response: Vec<u8>,
    facts: Option<FactLease>,
    valid_until: u64,
}

impl AdmittedSourceRequest {
    fn capture(
        owner: SourceTransportOwner,
        peer: &WorkloadPeer,
        generation: &EnvoyGeneration,
        trace: &RequestTraceId,
    ) -> RuntimeResult<Self> {
        let (capsule_digest, target) = {
            let active = owner
                .agent
                .acquire_observed_capsule(&owner.classes, generation, wall_clock_ns()?)
                .inspect_err(|error| report_unavailable(error, "capture-current-custody", trace))?;
            let (policies, _facts) = owner
                .policies
                .acquire(&active, peer)
                .inspect_err(|error| report_unavailable(error, "capture-policy-custody", trace))?;
            policies.restrictions_for(peer, &owner.privacy, active.capsule())?;
            (
                active.capsule().digest()?,
                active.capsule().target_runtime_id.clone(),
            )
        };
        Ok(Self {
            owner,
            peer: peer.clone(),
            generation: generation.clone(),
            trace: trace.clone(),
            capsule_digest,
            target,
            id: None,
        })
    }
    fn active(&self) -> RuntimeResult<ActiveCapsuleLease<'_>> {
        let active = self
            .owner
            .agent
            .acquire_observed_capsule(&self.owner.classes, &self.generation, wall_clock_ns()?)
            .inspect_err(|error| report_unavailable(error, "current-custody", &self.trace))?;
        if active.capsule().digest()? != self.capsule_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(active)
    }

    fn unavailable(&self, stage: &'static str) -> RuntimeError {
        // Report only an internal stage and correlation ID, never source bytes,
        // endpoint details, credentials or raw database/provider errors.
        report_unavailable(&RuntimeError::RuntimeUnavailable, stage, &self.trace);
        RuntimeError::RuntimeUnavailable
    }

    async fn execute(
        &mut self,
        body: &[u8],
        permit: &mut openpc_runtime_agent::target_disposition::SourceReadPermit<'_>,
    ) -> RuntimeResult<Vec<u8>> {
        let pool = self
            .owner
            .control
            .as_ref()
            .ok_or_else(|| self.unavailable("control-reader"))?;
        permit.begin_io();
        let admission = super::dispatch_read::begin(
            pool,
            self.peer.participant_id(),
            &self.owner.privacy,
            &self.target,
            &format!("sha256:{}", self.capsule_digest.as_str()),
        )
        .await
        .inspect_err(|error| {
            if matches!(error, RuntimeError::RuntimeUnavailable) {
                self.unavailable("source-lock-admission");
            }
        })?;
        let Some((mut tx, plan_id)) = admission else {
            permit.complete_io();
            return Err(self.unavailable("source-lock-admission"));
        };
        let prepared = match self.prepare(&mut tx, &plan_id, body).await {
            Ok(prepared) => prepared,
            Err(error) => {
                tx.rollback()
                    .await
                    .map_err(|_| self.unavailable("source-read-rollback"))?;
                permit.complete_io();
                return Err(error);
            }
        };
        tx.commit()
            .await
            .map_err(|_| self.unavailable("source-read-commit"))?;
        permit.complete_io();
        if let Some(lease) = &prepared.facts {
            lease
                .revalidate()
                .map_err(|_| RuntimeError::ResponseWithheld)?;
        }
        // The source/provider deadline may be shorter than capsule currentness.
        if wall_clock_ns()? >= prepared.valid_until {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        self.active().map_err(|_| RuntimeError::ResponseWithheld)?;
        Ok(prepared.response)
    }

    async fn prepare(
        &mut self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan_id: &str,
        body: &[u8],
    ) -> RuntimeResult<PreparedSourceRead> {
        let rows = source_current::load(
            tx,
            self.peer.participant_id(),
            &self.owner.privacy,
            Some(plan_id),
            false,
        )
        .await
        .map_err(|_| self.unavailable("source-materialization"))?;
        if rows.len() != 1 {
            return Err(RuntimeError::GenerationMismatch);
        }
        let digest: String = rows[0]
            .try_get("active_configuration_digest")
            .map_err(|_| RuntimeError::InvalidInput)?;
        let source =
            indexer_publication::prepare(&rows[0], self.peer.participant_id(), &self.owner.privacy)
                .map_err(|_| RuntimeError::InvalidAuthorization)?
                .ok_or(RuntimeError::InvalidAuthorization)?;
        if source.target_id != self.target {
            return Err(RuntimeError::TargetIdentity);
        }
        let source_digest = format!("sha256:{}", Digest::of(&source.input.profile_cbor).as_str());
        let plan_digest = format!("sha256:{}", Digest::of(&source.input.plan_cbor).as_str());
        let profile = openpc_indexer_adapter::admit_scoped_client_indexer_profile(
            &source.input.profile_cbor,
            &source_digest,
            self.peer.participant_id(),
            &self.owner.privacy,
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
        let plan = openpc_indexer_adapter::validate_projection_admission(
            &source.input.profile_cbor,
            &source.input.plan_cbor,
            &plan_digest,
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
        let decoded = DecodedAcquisitionRequest::decode(
            &profile,
            &plan,
            &source.input.acquisition_configuration_cbor,
            body,
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
        self.id = Some(decoded.request_id().into());
        if decoded.target_id() != self.target || profile.workload_binding != self.peer.workload_id()
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let maximum_bytes = profile
            .limits
            .max_response_bytes
            .min(plan.limits.max_response_bytes)
            .min(131_072);
        let maximum_depth = profile.limits.max_depth.min(plan.limits.max_depth).min(64);
        if maximum_bytes == 0
            || maximum_depth == 0
            || profile.limits.max_resource == 0
            || plan.limits.max_resource == 0
        {
            return Err(RuntimeError::BudgetExhausted);
        }
        let acquisition = AcquisitionConfiguration::resolve(
            &profile,
            &source.input.acquisition_configuration_cbor,
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
        let rate = acquisition
            .rate_limit
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let rate_digest = rate.digest().map_err(|_| RuntimeError::InvalidInput)?;
        if rate_digest != profile.limits.rate_limit_contract_digest
            || rate_digest != plan.limits.rate_limit_contract_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let source_id = source.input.indexer_profile_id.to_string();
        let policy_request = IndexerPolicyRequest {
            indexer_profile_id: &source_id,
            profile_artifact_digest: &source_digest,
            projection_plan_id: plan_id,
            plan_artifact_digest: &plan_digest,
            acquisition_configuration_digest: &profile.configuration_digest,
            data_class: IndexerDataClass::for_profile_method(&decoded.method_class().method)
                .ok_or(RuntimeError::InvalidInput)?,
            range_start: decoded.block(),
            range_end: decoded.block(),
            maximum_response_bytes: maximum_bytes as u32,
        };
        // The selected primary provider is the one in the exact locked active
        // generation. A client cannot supply an endpoint, provider or credential.
        let (provider_id, endpoint_ref, input_digest): (String, String, String) = sqlx::query_as("select g.provider_profile_id::text,p.endpoint_secret_ref,w.configuration_digest from control.runtime_activation_observation o join control.runtime_configuration_generation g on g.runtime_configuration_generation_id=o.runtime_configuration_generation_id join control.provider_profile p on p.provider_profile_id=g.provider_profile_id join control.configuration_work w on w.configuration_work_id=o.configuration_work_id where o.runtime_target_id=$1::text::uuid and o.capsule_digest=$2 and g.state='ACTIVE'")
            .bind(&self.target).bind(format!("sha256:{}",self.capsule_digest.as_str())).fetch_one(&mut **tx).await.map_err(|_| RuntimeError::GenerationMismatch)?;
        // Activation fences its original governed input. The capsule contains
        // the compiler's narrowed configuration, whose digest is different;
        // source authorization below separately verifies its exact typed tuple.
        if input_digest != format!("sha256:{digest}") {
            return Err(RuntimeError::GenerationMismatch);
        }
        let artifact = source
            .configuration
            .resource_artifacts
            .iter()
            .find(|a| {
                a.artifact_kind == ConfigurationArtifactKind::ProviderProfile
                    && a.artifact_id == provider_id
            })
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let provider_digest = format!("sha256:{}", artifact.artifact_digest.as_str());
        if !source
            .rule
            .canonical_provider_digests
            .contains(&provider_digest)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let provider =
            openpc_multi_rpc::qualify_provider_profile(&artifact.payload_cbor, &provider_digest)
                .map_err(|_| RuntimeError::InvalidAuthorization)?;
        if provider.rate_limit_contract_digest != rate_digest
            || !provider
                .method_data_classes
                .contains(decoded.method_class())
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let provider_until = indexer_publication::provider_qualification_deadline(
            tx,
            &provider_id,
            &provider_digest,
        )
        .await
        .map_err(|_| self.unavailable("provider-qualification"))?
        .ok_or(RuntimeError::ExpiredAuthorization)?;
        let prepared = provider_probe_source::prepare(
            &self.owner.providers,
            &endpoint_ref,
            &provider,
            self.peer.participant_id(),
            &self.owner.privacy,
            self.generation.generation(),
        )
        .map_err(|_| self.unavailable("provider-preparation"))?;
        // Each class needs its own live corpus. A historical state-only receipt
        // cannot authorize headers, even if the profile declares that class.
        let live_state = (matches!(
            decoded.method_class().data_class.as_str(),
            "STATE_CALL" | "EXTERNAL_OBSERVATION"
        ) || (decoded.method_class().data_class == "EVENT_LOG"
            && prepared.plan.event_log.is_some()))
            && prepared.plan.block_header.is_some()
            && profile.method_data_classes.iter().any(|pair| {
                matches!(
                    pair.method.as_str(),
                    "eth_getBlockByNumber" | "eth_getBlockByNumber(false)"
                ) && pair.data_class == "BLOCK_HEADER"
            });
        let header_request = if live_state {
            let id: serde_json::Value = serde_json::from_str(decoded.request_id())
                .map_err(|_| RuntimeError::InvalidInput)?;
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": "eth_getBlockByNumber",
                "params": [format!("0x{:x}", decoded.block()), false]
            }))
            .map_err(|_| RuntimeError::InvalidInput)?;
            let request = DecodedAcquisitionRequest::decode(
                &profile,
                &plan,
                &source.input.acquisition_configuration_cbor,
                &body,
            )
            .map_err(|_| RuntimeError::InvalidInput)?;
            if !provider
                .method_data_classes
                .contains(request.method_class())
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            Some(request)
        } else {
            None
        };
        let mut dispatch_body = match decoded.method_class().data_class.as_str() {
            "BLOCK_HEADER" if prepared.plan.block_header.is_some() => decoded.body().to_vec(),
            "STATE_CALL" | "EVENT_LOG" | "EXTERNAL_OBSERVATION" if live_state => {
                decoded.body().to_vec()
            }
            "STATE_CALL" => decoded
                .hash_pinned_state_call(
                    prepared.plan.block_number,
                    prepared.plan.block_hash.as_str(),
                )
                .map_err(|_| RuntimeError::InvalidAuthorization)?,
            _ => return Err(RuntimeError::InvalidAuthorization),
        };
        if dispatch_body.len() as u64 > profile.limits.max_request_bytes {
            return Err(RuntimeError::BudgetExhausted);
        }
        let request_digest = Digest::of(&dispatch_body);
        let source_scope = Digest::of(canonical_bytes(&(
            self.peer.participant_id(),
            &self.owner.privacy,
            &source_id,
        ))?);
        let authorize = |active: &ActiveCapsuleLease<'_>| {
            let (policies, facts) = self.owner.policies.acquire(active, &self.peer)?;
            let mut authorization = policies
                .authorize_source_policy(
                    &self.owner.identity,
                    active,
                    &self.peer,
                    &policy_request,
                    wall_clock_ns()?,
                )
                .inspect_err(|error| report_unavailable(error, "source-authority", &self.trace))?;
            if live_state {
                let header_policy = IndexerPolicyRequest {
                    data_class: IndexerDataClass::BlockHeader,
                    ..policy_request
                };
                let header_authorization = policies.authorize_source_policy(
                    &self.owner.identity,
                    active,
                    &self.peer,
                    &header_policy,
                    wall_clock_ns()?,
                )?;
                authorization.valid_until_ns = authorization
                    .valid_until_ns
                    .min(header_authorization.valid_until_ns);
            }
            Ok::<_, RuntimeError>((authorization, facts))
        };
        let (evidence_id, binding, valid_until, participant_epoch) = {
            let active = self.active()?;
            let (authorization, _facts) = authorize(&active)?;
            let now = wall_clock_ns()?;
            let valid_until = authorization
                .valid_until_ns
                .min(provider_until)
                .min(now.saturating_add(5_000_000_000));
            if now >= valid_until {
                return Err(RuntimeError::ExpiredAuthorization);
            }
            let binding = Digest::of(canonical_bytes(&(
                &self.capsule_digest,
                &source_digest,
                &plan_digest,
                &provider_digest,
                &request_digest,
                authorization.authorization.facts(),
            ))?);
            let id = self
                .owner
                .decisions
                .start_source_read(
                    &active,
                    &self.trace,
                    &SourceReadEvidenceInput {
                        request_digest,
                        source_scope_digest: source_scope.clone(),
                        authority_binding_digest: binding.clone(),
                        valid_until_ns: valid_until,
                        rate_window_ms: rate.window_ms,
                        maximum_requests: rate.maximum_requests,
                    },
                    now,
                )
                .inspect_err(|error| {
                    report_unavailable(error, "source-evidence-start", &self.trace)
                })?;
            (
                id,
                binding,
                valid_until,
                authorization.participant_authority_epoch().ok(),
            )
        };
        // A source read is one bounded logical request. Its canonicality
        // checks share the same persisted rate reservation, authority and
        // deadline; neither a probe's historical hash nor provider "latest"
        // determines the requested block. Failed checks never release a result.
        let observe_header = async || -> RuntimeResult<Option<SourceBlockHeader>> {
            let Some(request) = &header_request else {
                return Ok(None);
            };
            {
                let active = self.active()?;
                authorize(&active)?;
                if wall_clock_ns()? >= valid_until {
                    return Err(RuntimeError::ExpiredAuthorization);
                }
            }
            let remaining = valid_until
                .checked_sub(wall_clock_ns()?)
                .ok_or(RuntimeError::ExpiredAuthorization)?;
            let bytes = prepared
                .connection
                .post_json_with_response_limit(
                    request.body().to_vec(),
                    tokio::time::Instant::now() + Duration::from_nanos(remaining),
                    maximum_bytes as usize,
                )
                .await
                .map_err(|_| self.unavailable("provider-header-read"))?;
            let bytes = request
                .validate_response(&bytes, maximum_bytes as usize, maximum_depth as usize)
                .map_err(|_| RuntimeError::InvalidInput)?;
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| RuntimeError::InvalidInput)?;
            let header = SourceBlockHeader::decode(&value["result"], decoded.block())
                .map_err(|_| RuntimeError::ResponseWithheld)?;
            if header.timestamp_seconds > wall_clock_ns()? / 1_000_000_000 {
                return Err(RuntimeError::ResponseWithheld);
            }
            Ok(Some(header))
        };
        let anchor = observe_header().await?;
        if let Some(header) = &anchor {
            dispatch_body = match decoded.method_class().data_class.as_str() {
                "STATE_CALL" => decoded.hash_pinned_state_call(header.number, &header.hash),
                "EVENT_LOG" => decoded.hash_pinned_event_logs(header.number, &header.hash),
                "EXTERNAL_OBSERVATION" => Ok(decoded.body().to_vec()),
                _ => return Err(RuntimeError::InvalidAuthorization),
            }
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
            if dispatch_body.len() as u64 > profile.limits.max_request_bytes {
                return Err(RuntimeError::BudgetExhausted);
            }
            let active = self.active()?;
            authorize(&active)?;
        }
        let remaining = valid_until
            .checked_sub(wall_clock_ns()?)
            .ok_or(RuntimeError::ExpiredAuthorization)?;
        let response = if decoded.method_class().data_class == "EXTERNAL_OBSERVATION" {
            use openpc_multi_rpc::external_decision::{
                AdapterCallContextV1, acquire_prepared_observation,
            };
            let header = anchor.as_ref().ok_or(RuntimeError::InvalidAuthorization)?;
            let request = acquisition
                .external_request(&profile, header.number, &header.hash)
                .map_err(|_| RuntimeError::InvalidInput)?;
            let fact_profile = pc_policy_core::fact_profile::StateFactProfile::resolve(
                &source.configuration,
                plan_id,
            )?;
            if request.provider_id != provider_id
                || request.provider_version != provider.profile_version
                || request.provider_configuration_digest != artifact.artifact_digest
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            match &fact_profile.mapping {
                pc_policy_core::fact_profile::StateFactMapping::ExternalDecisionAdapterV1 {
                    provider_id,
                    provider_version,
                    provider_configuration_digest,
                    condition,
                } if provider_id == &request.provider_id
                    && provider_version == &request.provider_version
                    && provider_configuration_digest == &request.provider_configuration_digest
                    && condition == &request.condition => {}
                _ => return Err(RuntimeError::InvalidAuthorization),
            }
            let cancelled = std::sync::atomic::AtomicBool::new(false);
            let access = vec!["ACCESS-LOW".into()];
            let revalidate = || {
                self.active().and_then(|active| authorize(&active)).is_ok()
                    && wall_clock_ns().is_ok_and(|now| now < valid_until)
            };
            let context = AdapterCallContextV1 {
                authorization_digest: &binding,
                profile_digest: &artifact.artifact_digest,
                scope_digest: &source_scope,
                authorization_context_id: self.peer.participant_id(),
                authorization_context_epoch: participant_epoch
                    .ok_or(RuntimeError::InvalidAuthorization)?,
                access_class_ids: &access,
                occurrence_id: &evidence_id,
                audit_correlation_id: &evidence_id,
                deadline: tokio::time::Instant::now() + Duration::from_nanos(remaining),
                profile_timeout_ms: provider.timeout_budget_millis,
                maximum_age_ms: fact_profile.maximum_staleness_ms,
                cancelled: &cancelled,
                revalidate: &revalidate,
            };
            let observation =
                acquire_prepared_observation(&prepared.connection, &request, &context)
                    .await
                    .map_err(|_| RuntimeError::ResponseWithheld)?;
            let id: serde_json::Value = serde_json::from_str(decoded.request_id())
                .map_err(|_| RuntimeError::InvalidInput)?;
            serde_json::to_vec(
                &serde_json::json!({"jsonrpc":"2.0","id":id,"result":observation.observation()}),
            )
            .map_err(|_| RuntimeError::InvalidInput)?
        } else {
            prepared
                .connection
                .post_json_with_response_limit(
                    dispatch_body,
                    tokio::time::Instant::now() + Duration::from_nanos(remaining),
                    maximum_bytes as usize,
                )
                .await
                .map_err(|_| self.unavailable("provider-data-read"))?
        };
        let response = decoded
            .validate_response(&response, maximum_bytes as usize, maximum_depth as usize)
            .map_err(|_| RuntimeError::InvalidInput)?;
        if let (Some(before), Some(after)) = (anchor, observe_header().await?)
            && (before.hash != after.hash
                || before.parent_hash != after.parent_hash
                || before.state_root != after.state_root
                || before.timestamp_seconds != after.timestamp_seconds)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let release_facts = {
            let active = self.active()?;
            let (_, facts) = authorize(&active)?;
            if let Some(lease) = &facts {
                lease
                    .revalidate()
                    .map_err(|_| RuntimeError::ResponseWithheld)?;
            }
            let now = wall_clock_ns()?;
            if now >= valid_until {
                return Err(RuntimeError::ExpiredAuthorization);
            }
            self.owner
                .decisions
                .release_source_read(&active, &evidence_id, &binding, &response, now)
                .inspect_err(|error| {
                    report_unavailable(error, "source-evidence-release", &self.trace)
                })?;
            facts
        };
        Ok(PreparedSourceRead {
            response,
            facts: release_facts,
            valid_until,
        })
    }
}

// These fallback methods deliberately cannot produce invocation authority. The
// selected source handler either returns its validated response or a denial.
impl LocalDecisionOwner for SourceRequest {
    fn acquire(&self, _: &RuntimeRequest) -> RuntimeResult<Box<dyn LocalDecisionLease + '_>> {
        Err(RuntimeError::Denied)
    }
}
impl ProtectedRequest for SourceRequest {
    fn request_id(&self) -> Option<&str> {
        self.id.as_deref()
    }
    fn decision_owner(&self) -> &dyn LocalDecisionOwner {
        self
    }
    fn evaluation(&mut self, _: &[u8]) -> RuntimeResult<EvaluationInput> {
        Err(RuntimeError::Denied)
    }
    fn prepare_local_response<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> openpc_runtime_agent::ext_proc::LocalResponseFuture<'a> {
        Box::pin(async move {
            let mut admitted = None;
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                let agent = self.owner.agent.clone();
                let mut permit = agent.coordinate_source_read().await?;
                admitted = Some(AdmittedSourceRequest::capture(
                    self.owner.clone(),
                    &self.peer,
                    &self.generation,
                    &self.trace,
                )?);
                admitted
                    .as_mut()
                    .ok_or(RuntimeError::RuntimeUnavailable)?
                    .execute(body, &mut permit)
                    .await
            })
            .await
            .unwrap_or(Err(RuntimeError::BudgetExhausted));
            self.id = admitted.and_then(|request| request.id);
            result.map(Some)
        })
    }
    fn authorize(&mut self, _: &RuntimeDecision) -> RuntimeResult<String> {
        Err(RuntimeError::Denied)
    }
    fn record_denial(&mut self, _: &RuntimeDecision, trace: &RequestTraceId) -> RuntimeResult<()> {
        self.owner.evidence.record(
            "source-invocation-denied",
            &RuntimeError::Denied,
            Some(trace.as_str()),
        )
    }
    fn response_headers(
        &mut self,
        _: &[(String, Vec<u8>)],
    ) -> RuntimeResult<Vec<(String, Vec<u8>)>> {
        Err(RuntimeError::Denied)
    }
    fn release_response(&mut self, _: &[u8]) -> RuntimeResult<Vec<u8>> {
        Err(RuntimeError::Denied)
    }
}
