use serde::{Deserialize, Serialize};

macro_rules! contract_text {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
                let value = value.into();
                if value.is_empty() {
                    Err(concat!(stringify!($name), " must not be empty"))
                } else {
                    Ok(Self(value))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

contract_text!(RequestId);
contract_text!(AttemptId);
contract_text!(AuthorityContextDigest);
contract_text!(RequestDigest);
contract_text!(CapabilityProfileDigest);
contract_text!(ProviderProfileDigest);
contract_text!(ProviderInstanceId);
contract_text!(NormalizedResponseDigest);
contract_text!(ResponseDigest);
contract_text!(StatusDigest);
contract_text!(ErrorDigest);
contract_text!(EvidenceDigest);
contract_text!(CorrelationId);
contract_text!(CausationId);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProfileV1 {
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub provider_instance_id: String,
    pub provider_release_digest: String,
    pub provider_build_digest: String,
    pub configuration_digest: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub network_id: String,
    pub tls_credential_identity: String,
    pub tls_credential_fingerprint: String,
    pub trust_epoch: u64,
    pub json_rpc_version: String,
    pub method_data_classes: Vec<MethodDataClass>,
    pub request_schema_digest: String,
    pub response_schema_digest: String,
    pub normalization_rule_digest: String,
    pub limits: ProviderLimits,
    pub privacy_behavior_digest: String,
    pub failure_behavior_digest: String,
    pub rate_limit_contract_digest: String,
    pub capability_profile_digest: String,
    pub maximum_response_classification: String,
    pub idempotency: IdempotencyClass,
    pub route_plan: RoutePlanDraftV1,
    pub read_retry_budget: u8,
    pub timeout_budget_millis: u64,
    pub corpus_digest: String,
    pub conformance_receipt_digest: String,
    pub lifecycle: ProfileLifecycle,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodDataClass {
    pub method: String,
    pub data_class: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLimits {
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_range: u64,
    pub max_batch: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRequestV1 {
    pub request_id: String,
    pub authority_context_digest: String,
    pub participant_binding: String,
    pub privacy_binding: String,
    pub workload_binding: String,
    pub action_intent: String,
    pub method: String,
    pub data_class: String,
    pub normalized_parameter_digest: String,
    pub anchor: ChainReadAnchorV1,
    pub required_capability_profile_digest: String,
    pub maximum_response_classification: String,
    pub idempotency: IdempotencyClass,
    pub request_deadline_millis: u64,
    pub evidence_correlation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainReadAnchorV1 {
    pub chain_id: String,
    pub genesis_hash: String,
    pub network_id: String,
    pub selector_kind: BlockSelectorKind,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub pending_authorized_by_profile: bool,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProviderKeyV1 {
    pub profile_digest: ProviderProfileDigest,
    pub provider_instance_id: ProviderInstanceId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EligibleProviderV1 {
    pub profile_digest: String,
    pub provider_instance_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProviderExclusionReason {
    Unknown,
    Stale,
    Revoked,
    RateLimited,
    Quarantined,
    Unsupported,
    EvidenceIncomplete,
    HealthRemoved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExclusionV1 {
    pub profile_digest: String,
    pub provider_instance_id: String,
    pub reason: ProviderExclusionReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExcludedProviderV1 {
    pub key: ProviderKeyV1,
    pub reason: ProviderExclusionReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EligibilitySnapshotV1 {
    pub(crate) admitted_profiles: Vec<ProviderProfileV1>,
    pub(crate) excluded: Vec<ExcludedProviderV1>,
    pub(crate) order_derivation: String,
}

impl EligibilitySnapshotV1 {
    pub fn admitted_profiles(&self) -> &[ProviderProfileV1] {
        &self.admitted_profiles
    }

    pub fn excluded(&self) -> &[ExcludedProviderV1] {
        &self.excluded
    }

    pub fn order_derivation(&self) -> &str {
        &self.order_derivation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RouteMode {
    SingleExact,
    QuorumIdentical,
    HedgedSingle,
    HedgedQuorumIdentical,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum RoutePlanV1 {
    SingleExact,
    QuorumIdentical {
        required_agreement: u8,
    },
    HedgedSingle {
        hedge_threshold_millis: u64,
    },
    HedgedQuorumIdentical {
        required_agreement: u8,
        hedge_threshold_millis: u64,
        max_hedge_attempts: u8,
    },
}

impl RoutePlanV1 {
    pub fn mode(&self) -> RouteMode {
        match self {
            Self::SingleExact => RouteMode::SingleExact,
            Self::QuorumIdentical { .. } => RouteMode::QuorumIdentical,
            Self::HedgedSingle { .. } => RouteMode::HedgedSingle,
            Self::HedgedQuorumIdentical { .. } => RouteMode::HedgedQuorumIdentical,
        }
    }

    pub fn required_agreement(&self) -> usize {
        match self {
            Self::SingleExact | Self::HedgedSingle { .. } => 1,
            Self::QuorumIdentical { required_agreement }
            | Self::HedgedQuorumIdentical {
                required_agreement, ..
            } => usize::from(*required_agreement),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RoutePlanDraftV1 {
    SingleExact,
    QuorumIdentical {
        required_agreement: u8,
    },
    HedgedSingle {
        hedge_threshold_millis: u64,
    },
    HedgedQuorumIdentical {
        required_agreement: u8,
        hedge_threshold_millis: u64,
        max_hedge_attempts: u8,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AttemptIdentityV1 {
    pub attempt_id: AttemptId,
    pub request_id: RequestId,
    pub authority_context_digest: AuthorityContextDigest,
    pub capability_profile_digest: CapabilityProfileDigest,
    pub provider: ProviderKeyV1,
    pub immutable_request_digest: RequestDigest,
    pub anchor: ChainReadAnchorV1,
    pub ordinal: u8,
    pub deadline_millis: u64,
    pub correlation_id: CorrelationId,
    pub causation_id: CausationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StartEvidenceV1 {
    pub bytes_started_evidence_digest: EvidenceDigest,
    pub started_at_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum AttemptLifecycleV1 {
    Prepared,
    Started(StartEvidenceV1),
    ResponseObserved {
        start: StartEvidenceV1,
        response_observed_evidence_digest: EvidenceDigest,
        observed_at_millis: u64,
    },
    Resolved {
        start: StartEvidenceV1,
        completed_at_millis: u64,
    },
    Unknown {
        start: StartEvidenceV1,
        completed_at_millis: u64,
    },
    FailedPreStart {
        completed_at_millis: u64,
        no_bytes_sent_evidence_digest: EvidenceDigest,
    },
    FailedAfterStart {
        start: StartEvidenceV1,
        completed_at_millis: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AttemptEnvelopeV1 {
    pub(crate) identity: AttemptIdentityV1,
    pub(crate) lifecycle: AttemptLifecycleV1,
}

impl AttemptEnvelopeV1 {
    pub fn identity(&self) -> &AttemptIdentityV1 {
        &self.identity
    }

    pub fn lifecycle(&self) -> &AttemptLifecycleV1 {
        &self.lifecycle
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptEnvelopeDraftV1 {
    pub attempt_id: String,
    pub request_id: String,
    pub authority_context_digest: String,
    pub capability_profile_digest: String,
    pub profile_digest: String,
    pub provider_instance_id: String,
    pub immutable_request_digest: String,
    pub anchor: ChainReadAnchorV1,
    pub ordinal: u8,
    pub state: AttemptState,
    pub bytes_started_evidence_digest: Option<String>,
    pub started_at_millis: Option<u64>,
    pub response_observed_evidence_digest: Option<String>,
    pub observed_at_millis: Option<u64>,
    pub completed_at_millis: Option<u64>,
    pub no_bytes_sent_evidence_digest: Option<String>,
    pub deadline_millis: u64,
    pub correlation_id: String,
    pub causation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SuccessfulResolutionV2 {
    pub(crate) normalized_response_digest: NormalizedResponseDigest,
    pub(crate) response_digest: ResponseDigest,
    pub(crate) status_digest: StatusDigest,
    pub(crate) observed_anchor: ChainReadAnchorV1,
    pub(crate) capability_profile_digest: CapabilityProfileDigest,
    pub(crate) provider: ProviderKeyV1,
    pub(crate) evidence_refs: Vec<EvidenceDigest>,
}

impl SuccessfulResolutionV2 {
    pub fn normalized_response_digest(&self) -> &NormalizedResponseDigest {
        &self.normalized_response_digest
    }

    pub fn provider(&self) -> &ProviderKeyV1 {
        &self.provider
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FailureResolutionV2 {
    pub(crate) truth: ResolutionTruth,
    pub(crate) status_digest: Option<StatusDigest>,
    pub(crate) error_digest: ErrorDigest,
    pub(crate) observed_anchor: ChainReadAnchorV1,
    pub(crate) capability_profile_digest: CapabilityProfileDigest,
    pub(crate) provider: ProviderKeyV1,
    pub(crate) recovery_eligibility: RecoveryEligibilityV1,
    pub(crate) evidence_refs: Vec<EvidenceDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum AttemptResolutionV2 {
    Success(SuccessfulResolutionV2),
    AuthorizedEmpty(SuccessfulResolutionV2),
    ReadFailure(FailureResolutionV2),
    TerminalFailure(FailureResolutionV2),
}

impl AttemptResolutionV2 {
    pub fn truth(&self) -> ResolutionTruth {
        match self {
            Self::Success(_) => ResolutionTruth::Success,
            Self::AuthorizedEmpty(_) => ResolutionTruth::AuthorizedEmpty,
            Self::ReadFailure(value) | Self::TerminalFailure(value) => value.truth,
        }
    }

    pub fn provider(&self) -> &ProviderKeyV1 {
        match self {
            Self::Success(value) | Self::AuthorizedEmpty(value) => &value.provider,
            Self::ReadFailure(value) | Self::TerminalFailure(value) => &value.provider,
        }
    }

    pub fn observed_anchor(&self) -> &ChainReadAnchorV1 {
        match self {
            Self::Success(value) | Self::AuthorizedEmpty(value) => &value.observed_anchor,
            Self::ReadFailure(value) | Self::TerminalFailure(value) => &value.observed_anchor,
        }
    }

    pub fn capability_profile_digest(&self) -> &CapabilityProfileDigest {
        match self {
            Self::Success(value) | Self::AuthorizedEmpty(value) => &value.capability_profile_digest,
            Self::ReadFailure(value) | Self::TerminalFailure(value) => {
                &value.capability_profile_digest
            }
        }
    }

    pub fn normalized_response_digest(&self) -> Option<&NormalizedResponseDigest> {
        match self {
            Self::Success(value) | Self::AuthorizedEmpty(value) => {
                Some(&value.normalized_response_digest)
            }
            Self::ReadFailure(_) | Self::TerminalFailure(_) => None,
        }
    }

    pub fn evidence_refs(&self) -> &[EvidenceDigest] {
        match self {
            Self::Success(value) | Self::AuthorizedEmpty(value) => &value.evidence_refs,
            Self::ReadFailure(value) | Self::TerminalFailure(value) => &value.evidence_refs,
        }
    }

    pub fn recovery_eligibility(&self) -> RecoveryEligibilityV1 {
        match self {
            Self::Success(_) | Self::AuthorizedEmpty(_) => RecoveryEligibilityV1::None,
            Self::ReadFailure(value) | Self::TerminalFailure(value) => value.recovery_eligibility,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RecoveryEligibilityV1 {
    None,
    RetrySameProvider,
    FailoverWithinSnapshot,
    RetryOrFailoverWithinSnapshot,
}

impl RecoveryEligibilityV1 {
    pub fn permits(self, kind: ReadRecoveryKind) -> bool {
        matches!(
            (self, kind),
            (Self::RetrySameProvider, ReadRecoveryKind::RetrySameProvider)
                | (
                    Self::FailoverWithinSnapshot,
                    ReadRecoveryKind::FailoverWithinSnapshot
                )
                | (Self::RetryOrFailoverWithinSnapshot, _)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptResolutionDraftV2 {
    pub truth: ResolutionTruth,
    pub normalized_response_digest: Option<String>,
    pub response_digest: Option<String>,
    pub status_digest: Option<String>,
    pub error_digest: Option<String>,
    pub observed_anchor: ChainReadAnchorV1,
    pub capability_profile_digest: String,
    pub profile_digest: String,
    pub provider_instance_id: String,
    pub recovery_eligibility: RecoveryEligibilityV1,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAttemptDraftV1 {
    pub envelope: AttemptEnvelopeDraftV1,
    pub resolution: Option<AttemptResolutionDraftV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InFlightRouteAttemptV1 {
    pub(crate) envelope: AttemptEnvelopeV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TerminalRouteAttemptV1 {
    pub(crate) envelope: AttemptEnvelopeV1,
    pub(crate) resolution: AttemptResolutionV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum RouteAttemptV1 {
    InFlight(Box<InFlightRouteAttemptV1>),
    Terminal(Box<TerminalRouteAttemptV1>),
}

impl RouteAttemptV1 {
    pub fn envelope(&self) -> &AttemptEnvelopeV1 {
        match self {
            Self::InFlight(value) => &value.envelope,
            Self::Terminal(value) => &value.envelope,
        }
    }

    pub fn resolution(&self) -> Option<&AttemptResolutionV2> {
        match self {
            Self::InFlight(_) => None,
            Self::Terminal(value) => Some(&value.resolution),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReadRecoveryKind {
    RetrySameProvider,
    FailoverWithinSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRecoveryDraftV1 {
    pub prior_attempt_id: String,
    pub next_attempt_id: String,
    pub target_profile_digest: String,
    pub target_provider_instance_id: String,
    pub kind: ReadRecoveryKind,
    pub request_id: String,
    pub authority_context_digest: String,
    pub immutable_request_digest: String,
    pub anchor: ChainReadAnchorV1,
    pub remaining_deadline_millis: u64,
    pub remaining_rate_budget: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReadRecoveryV1 {
    pub prior_attempt_id: AttemptId,
    pub next_attempt_id: AttemptId,
    pub target: ProviderKeyV1,
    pub kind: ReadRecoveryKind,
    pub remaining_deadline_millis: u64,
    pub remaining_rate_budget: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RouteOutcomeDraftV1 {
    Selected {
        truth: ResolutionTruth,
        selected_result_digest: String,
        agreement_attempt_ids: Vec<String>,
    },
    Divergent {
        evidence_refs: Vec<String>,
    },
    Partial {
        evidence_refs: Vec<String>,
    },
    Failed {
        truth: ResolutionTruth,
        evidence_refs: Vec<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedOutcomeV1 {
    pub(crate) truth: ResolutionTruth,
    pub(crate) selected_result_digest: NormalizedResponseDigest,
    pub(crate) agreement_attempt_ids: Vec<AttemptId>,
}

impl SelectedOutcomeV1 {
    pub fn truth(&self) -> ResolutionTruth {
        self.truth
    }

    pub fn selected_result_digest(&self) -> &NormalizedResponseDigest {
        &self.selected_result_digest
    }

    pub fn agreement_attempt_ids(&self) -> &[AttemptId] {
        &self.agreement_attempt_ids
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum RouteOutcomeV1 {
    Selected(SelectedOutcomeV1),
    Divergent {
        evidence_refs: Vec<EvidenceDigest>,
    },
    Partial {
        evidence_refs: Vec<EvidenceDigest>,
    },
    Failed {
        truth: ResolutionTruth,
        evidence_refs: Vec<EvidenceDigest>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestRouteWitnessDraftV1 {
    pub request: RouteRequestV1,
    pub request_digest: String,
    pub admitted_profiles: Vec<ProviderProfileV1>,
    pub exclusions: Vec<ProviderExclusionV1>,
    pub attempts: Vec<RouteAttemptDraftV1>,
    pub execution: RouteExecutionDraftV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RequestRouteWitnessV1 {
    pub(crate) request: RouteRequestV1,
    pub(crate) request_digest: RequestDigest,
    pub(crate) eligibility: EligibilitySnapshotV1,
    pub(crate) attempts: Vec<RouteAttemptV1>,
    pub(crate) execution: RouteExecutionV1,
}

impl RequestRouteWitnessV1 {
    pub fn idempotency(&self) -> IdempotencyClass {
        self.request.idempotency
    }

    pub fn request(&self) -> &RouteRequestV1 {
        &self.request
    }

    pub fn request_digest(&self) -> &RequestDigest {
        &self.request_digest
    }

    pub fn eligibility(&self) -> &EligibilitySnapshotV1 {
        &self.eligibility
    }

    pub fn attempts(&self) -> &[RouteAttemptV1] {
        &self.attempts
    }

    pub fn execution(&self) -> &RouteExecutionV1 {
        &self.execution
    }

    pub fn route_plan(&self) -> Option<&RoutePlanV1> {
        match &self.execution {
            RouteExecutionV1::IdempotentRead { route_plan, .. } => Some(route_plan),
            RouteExecutionV1::GovernedWrite { .. } => None,
        }
    }

    pub fn recoveries(&self) -> &[ReadRecoveryV1] {
        match &self.execution {
            RouteExecutionV1::IdempotentRead { recoveries, .. } => recoveries,
            RouteExecutionV1::GovernedWrite { .. } => &[],
        }
    }

    pub fn read_retry_budget(&self) -> Option<u8> {
        match &self.execution {
            RouteExecutionV1::IdempotentRead { .. } => self
                .eligibility
                .admitted_profiles
                .first()
                .map(|profile| profile.read_retry_budget),
            RouteExecutionV1::GovernedWrite { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteExecutionDraftV1 {
    IdempotentRead {
        route_plan: RoutePlanDraftV1,
        primary_attempt_ids: Vec<String>,
        hedge_attempt_ids: Vec<String>,
        recoveries: Vec<ReadRecoveryDraftV1>,
        outcome: RouteOutcomeDraftV1,
    },
    GovernedWrite {
        attempt_ids: Vec<String>,
        reconciliation_observation_profiles: Vec<ProviderProfileV1>,
        progress: GovernedWriteProgressDraftV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum RouteExecutionV1 {
    IdempotentRead {
        route_plan: RoutePlanV1,
        primary_attempt_ids: Vec<AttemptId>,
        hedge_attempt_ids: Vec<AttemptId>,
        recoveries: Vec<ReadRecoveryV1>,
        outcome: RouteOutcomeV1,
    },
    GovernedWrite {
        attempt_ids: Vec<AttemptId>,
        progress: GovernedWriteProgressV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernedWriteProgressDraftV1 {
    Prepared,
    Started,
    Acknowledged,
    FailedPreStart,
    Reconciliation(Box<WriteReconciliationV1>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum GovernedWriteProgressV1 {
    Prepared,
    Started,
    Acknowledged,
    FailedPreStart,
    Reconciliation(Box<WriteReconciliationV1>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum WriteReconciliationStateV1 {
    Ambiguous,
    Included {
        inclusion_candidate_digest: EvidenceDigest,
        receipt_identity_digest: EvidenceDigest,
    },
    Executed {
        inclusion_candidate_digest: EvidenceDigest,
        execution_candidate_digest: EvidenceDigest,
        receipt_identity_digest: EvidenceDigest,
    },
    Finalized {
        inclusion_candidate_digest: EvidenceDigest,
        execution_candidate_digest: EvidenceDigest,
        finality_candidate_digest: EvidenceDigest,
        receipt_identity_digest: EvidenceDigest,
    },
    Reverted {
        receipt_identity_digest: EvidenceDigest,
    },
    DroppedConfirmed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WriteReconciliationV1 {
    pub request_or_transaction_hash: RequestDigest,
    pub anchor: ChainReadAnchorV1,
    pub provider_attempt_id: AttemptId,
    pub observations: Vec<ReconciliationObservationV1>,
    pub state: WriteReconciliationStateV1,
    pub evidence_refs: Vec<EvidenceDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReconciliationObservationV1 {
    pub method_data_class: MethodDataClass,
    pub provider_profile_digest: ProviderProfileDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedDigestV1 {
    pub name: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusiveRangeV1 {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRangeV1 {
    pub start: u64,
    pub end: RangeEndV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyV1 {
    pub name: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexerLimitsV1 {
    pub max_request_bytes: u64,
    pub max_range: u64,
    pub max_batch: u64,
    pub max_response_bytes: u64,
    pub max_depth: u64,
    pub max_resource: u64,
    pub rate_limit_contract_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRecordV1 {
    pub sequence: u64,
    pub record_id: String,
    pub schema_digest: String,
    pub normalized_digest: String,
    pub block_number: u64,
    pub canonical_block_hash: String,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientIndexerProfileV1 {
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub client_family: ClientIndexerFamily,
    pub engine_or_runtime: String,
    pub engine_version: String,
    pub dependencies: Vec<DependencyV1>,
    pub configuration_digest: String,
    pub participant_binding: String,
    pub privacy_binding: String,
    pub workload_binding: String,
    pub deployment_owner: String,
    pub boundary_declaration_digest: String,
    pub protocol_kind: IndexerProtocolKind,
    pub protocol_version: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub network_id: String,
    pub capability_profiles: Vec<IndexerCapability>,
    pub method_data_classes: Vec<MethodDataClass>,
    pub source_range: SourceRangeV1,
    pub finality_rule_digest: String,
    pub reorg_behavior_digest: String,
    pub removed_event_behavior_digest: String,
    pub checkpoint_semantics_digest: String,
    pub completed_watermark_semantics_digest: String,
    pub artifact_digests: Vec<NamedDigestV1>,
    pub limits: IndexerLimitsV1,
    pub behavior: IndexerBehaviorV1,
    pub candidate_store_contract_digest: String,
    pub outbox_contract_digest: String,
    pub fact_bridge_contract_digest: String,
    pub security_evidence_digest: String,
    pub privacy_evidence_digest: String,
    pub licensing_digest: String,
    pub supply_chain_digest: String,
    pub telemetry_classification_digest: String,
    pub rollback_digest: String,
    pub uninstall_digest: String,
    pub corpus_digest: String,
    pub conformance_receipt_digest: String,
    pub lifecycle: ClientIndexerLifecycle,
    pub source_authority: SourceAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexerBehaviorV1 {
    pub visibility_miss_digest: String,
    pub empty_digest: String,
    pub partial_digest: String,
    pub error_digest: String,
    pub retry_digest: String,
    pub recovery_digest: String,
    pub retirement_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionPlanV1 {
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub plan_digest: String,
    pub workload_identity: WorkloadIdentityV1,
    pub partitions: Vec<ProjectionPartitionV1>,
    pub source_range: SourceRangeV1,
    pub finality_rule_digest: String,
    pub extractor_digests: Vec<NamedDigestV1>,
    pub candidate_schema_digests: Vec<NamedDigestV1>,
    pub limits: IndexerLimitsV1,
    pub secret_references: Vec<SecretReferenceV1>,
    pub lifecycle_generation: u64,
    pub desired_state: DesiredState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WorkloadIdentityV1 {
    ExternalOwner {
        owner: String,
        boundary_digest: String,
    },
    ImageBuild {
        image_digest: String,
        build_digest: String,
        sbom_digest: String,
        provenance_digest: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretReferenceV1 {
    pub purpose: SecretPurposeV1,
    pub reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionPartitionV1 {
    pub partition_id: String,
    pub source_id: String,
    pub range: SourceRangeV1,
    pub state: PartitionState,
    pub finality_digest: String,
    pub checkpoint_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProjectionBatchV1 {
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub plan_digest: String,
    pub source_id: String,
    pub source_profile_digest: String,
    pub partition_id: String,
    pub batch_id: String,
    pub batch_sequence: u64,
    pub range: InclusiveRangeV1,
    pub observations: Vec<SequencedObservationV1>,
    pub records: Vec<CandidateRecordV1>,
    pub decode_failures: Vec<DecodeFailureV1>,
    pub missing_intervals: Vec<InclusiveRangeV1>,
    pub completed_watermark: CompletedWatermarkV1,
    pub predecessor_batch_digest: String,
    pub evidence_refs: Vec<String>,
    pub source_authority: SourceAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequencedObservationV1 {
    pub sequence: u64,
    pub anchor: ChainReadAnchorV1,
    pub normalized_digest: String,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeFailureV1 {
    pub sequence: u64,
    pub source_id: String,
    pub anchor: ChainReadAnchorV1,
    pub error_digest: String,
    pub evidence_digest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedWatermarkV1 {
    pub block_number: u64,
    pub canonical_block_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorerFactSourceProfileV1 {
    pub adapter_contract_id: String,
    pub adapter_contract_version: String,
    pub adapter_schema_digest: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub product_id: String,
    pub instance_id: String,
    pub release_digest: String,
    pub build_digest: String,
    pub api_digest: String,
    pub current_receipt_digest: String,
    pub participant_binding: String,
    pub privacy_binding: String,
    pub source_trust_binding: String,
    pub supported_fact_profiles: Vec<String>,
    pub dynamic_event_schemas: Vec<NamedDigestV1>,
    pub allowed_operations: Vec<String>,
    pub allowed_data_classes: Vec<String>,
    pub allowed_fields: Vec<String>,
    pub allowed_filters: Vec<String>,
    pub limits: IndexerLimitsV1,
    pub page_limits: ExplorerPageLimitsV1,
    pub checkpoint_protocol_digest: String,
    pub resume_protocol_digest: String,
    pub response_schema_digests: Vec<NamedDigestV1>,
    pub chain_id: String,
    pub genesis_hash: String,
    pub network_id: String,
    pub source_partitions: Vec<ProjectionPartitionV1>,
    pub scope_digests: Vec<NamedDigestV1>,
    pub canonicality_digest: String,
    pub finality_digest: String,
    pub reorg_digest: String,
    pub removal_digest: String,
    pub completeness_digest: String,
    pub watermark_digest: String,
    pub freshness_digest: String,
    pub trust_digest: String,
    pub revocation_digest: String,
    pub provenance_digest: String,
    pub conflict_digest: String,
    pub privacy_projection_digest: String,
    pub redaction_digest: String,
    pub hmac_key_version: String,
    pub privacy_evidence_digest: String,
    pub telemetry_classifications: Vec<String>,
    pub rate_law_digest: String,
    pub timeout_law_digest: String,
    pub retry_law_digest: String,
    pub lifecycle: ExplorerLifecycle,
    pub upgrade_digest: String,
    pub rollback_digest: String,
    pub disable_digest: String,
    pub uninstall_digest: String,
    pub corpus_digest: String,
    pub conformance_receipt_digest: String,
    pub source_authority: SourceAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorerPageLimitsV1 {
    pub max_page_items: u64,
    pub max_page_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorerCandidatePageV1 {
    pub request_id: String,
    pub participant_binding: String,
    pub privacy_binding: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub source_instance_id: String,
    pub authorized_scope_digest: String,
    pub range: InclusiveRangeV1,
    pub page_id: String,
    pub resume_cursor: ExplorerCursorV1,
    pub response_digest: String,
    pub records: Vec<CandidateRecordV1>,
    pub missing_intervals: Vec<InclusiveRangeV1>,
    pub completed_watermark: CompletedWatermarkV1,
    pub reorg_observations: Vec<SequencedObservationV1>,
    pub removal_observations: Vec<SequencedObservationV1>,
    pub derivation_digest: String,
    pub provenance_digest: String,
    pub evidence_refs: Vec<String>,
    pub next_cursor: ExplorerCursorV1,
    pub source_authority: SourceAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TheGraphManifestProfileV1 {
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub client_profile_id: String,
    pub client_profile_version: String,
    pub client_profile_digest: String,
    pub projection_plan_digest: String,
    pub manifest_digest: String,
    pub referenced_files: Vec<NamedDigestV1>,
    pub spec_version: String,
    pub features: Vec<String>,
    pub network: String,
    pub range: SourceRangeV1,
    pub data_sources: Vec<GraphDataSourceV1>,
    pub mappings: Vec<GraphMappingV1>,
    pub handlers: Vec<GraphHandlerV1>,
    pub dynamic_templates: Vec<GraphTemplateV1>,
    pub state_read_dependencies: Vec<MethodDataClass>,
    pub entity_projection_schemas: Vec<NamedDigestV1>,
    pub source_authority: SourceAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphDataSourceV1 {
    pub data_source_id: String,
    pub kind: String,
    pub name: String,
    pub network: String,
    pub address: String,
    pub abi_digest: String,
    pub start_block: u64,
    pub mapping_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphMappingV1 {
    pub mapping_id: String,
    pub data_source_id: String,
    pub language: String,
    pub api_version: String,
    pub file_digest: String,
    pub entities: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphHandlerV1 {
    pub handler_id: String,
    pub data_source_id: String,
    pub mapping_id: String,
    pub kind: GraphHandlerKind,
    pub signature: String,
    pub filter: String,
    pub function: String,
    pub required_method_data: Vec<MethodDataClass>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphTemplateV1 {
    pub template_id: String,
    pub mapping_id: String,
    pub digest: String,
    pub creation_binding: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TheGraphCandidateBatchV1 {
    pub base: CandidateProjectionBatchV1,
    pub manifest_profile_id: String,
    pub manifest_profile_version: String,
    pub manifest_profile_digest: String,
    pub manifest_digest: String,
    pub data_source_id: String,
    pub handler_id: String,
    pub template_use: GraphTemplateUse,
    pub observations: Vec<SequencedObservationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubQueryClientProfileV1 {
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub client_profile_id: String,
    pub client_profile_version: String,
    pub client_profile_digest: String,
    pub plan_digest: String,
    pub project_id: String,
    pub manifest_spec_version: String,
    pub manifest_digest: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub network_id: String,
    pub runner: DependencyV1,
    pub node: DependencyV1,
    pub query_service: DependencyV1,
    pub package_manager: DependencyV1,
    pub dependencies: Vec<DependencyV1>,
    pub data_sources: Vec<SubQueryDataSourceV1>,
    pub mappings: Vec<NamedDigestV1>,
    pub processors: Vec<NamedDigestV1>,
    pub assets: Vec<NamedDigestV1>,
    pub handlers: Vec<SubQueryHandlerV1>,
    pub filters: Vec<TypedSelectorV1>,
    pub abi_schema_code_digests: Vec<NamedDigestV1>,
    pub project_schema_digests: Vec<String>,
    pub data_node_surface: SubQueryDataNodeSurfaceV1,
    pub checkpoint_digest: String,
    pub finality_digest: String,
    pub reorg_digest: String,
    pub limits: IndexerLimitsV1,
    pub privacy_law_digest: String,
    pub lifecycle: ClientIndexerLifecycle,
    pub managed_lifecycle: ManagedSubqueryLifecycle,
    pub current_receipt_digest: String,
    pub source_authority: SourceAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubQueryDataSourceV1 {
    pub data_source_id: String,
    pub kind: String,
    pub start: u64,
    pub end: RangeEndV1,
    pub mapping_digest: String,
    pub asset_digests: Vec<String>,
    pub abi_digests: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubQueryHandlerV1 {
    pub handler_id: String,
    pub data_source_id: String,
    pub processor_id: String,
    pub filter_id: String,
    pub required_method_data: Vec<MethodDataClass>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubQueryCandidateBatchV1 {
    pub base: CandidateProjectionBatchV1,
    pub subquery_profile_id: String,
    pub subquery_profile_version: String,
    pub subquery_profile_digest: String,
    pub project_id: String,
    pub data_source_id: String,
    pub handler_id: String,
    pub operation: SubQueryOperationV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum IdempotencyClass {
    IdempotentRead,
    GovernedWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BlockSelectorKind {
    Pinned,
    Pending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AttemptState {
    Prepared,
    Started,
    ResponseObserved,
    Resolved,
    Unknown,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ResolutionTruth {
    Success,
    AuthorizedEmpty,
    Unavailable,
    RateLimited,
    Timeout,
    Divergent,
    Invalid,
    WriteAmbiguity,
    Reorg,
    Partial,
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProfileLifecycle {
    /// Exact-source local QA opt-in, never full external conformance.
    BoundedQa,
    Draft,
    Validated,
    Qualified,
    Active,
    Quarantined,
    Disabled,
    Retired,
    Uninstalled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SourceAuthority {
    NonAuthoritativeCandidateOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ClientIndexerFamily {
    TheGraphEvmJsonRpc,
    SubQueryEvmJsonRpc,
    SubQueryDataNode,
    CustomEvmIndexer,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum IndexerProtocolKind {
    JsonRpc,
    GraphQl,
    Http,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum IndexerCapability {
    ProjectSessionCore,
    EventOnly,
    StateRead,
    TransactionReceiptFullBlock,
    TraceCallHandler,
    DynamicTemplate,
    SubQueryDataNodeProfile,
    FirehoseSubstreams,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PartitionState {
    Bootstrap,
    CatchingUp,
    Complete,
    GapBlocked,
    ReorgFenced,
    Quarantined,
    Recovering,
    Disabled,
    Retired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DesiredState {
    Active,
    Retired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GraphHandlerKind {
    Event,
    Call,
    Block,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GraphTemplateUse {
    Static,
    Dynamic {
        template_id: String,
        creation_binding: String,
        creation_anchor: ChainReadAnchorV1,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SubQueryDataNodeSurfaceV1 {
    NotDeclared,
    Exact {
        protocol_version: String,
        schema_version: String,
        allowed_fields: Vec<String>,
        allowed_selectors: Vec<TypedSelectorV1>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SubQueryOperationV1 {
    JsonRpc(MethodDataClass),
    DataNodeCapabilities,
    DataNodeFilterBlocks(TypedSelectorV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RangeEndV1 {
    Open,
    Inclusive(u64),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SecretPurposeV1 {
    SourceCredential,
    ApiToken,
    HmacKey,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ClientIndexerLifecycle {
    Draft,
    Validated,
    Qualified,
    Approved,
    Active,
    Degraded,
    Recovering,
    Disabled,
    Retired,
    Uninstalled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExplorerLifecycle {
    DesignTarget,
    ProfileDraft,
    Validated,
    Qualified,
    Active,
    Degraded,
    Disabled,
    Retired,
    Uninstalled,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedSelectorV1 {
    pub field_id: String,
    pub schema_digest: String,
    pub selector_digest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExplorerCursorV1 {
    Initial,
    Resume { digest: String },
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ManagedSubqueryLifecycle {
    FutureAbsent,
}
