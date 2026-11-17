use super::super::*;
use serde::de::DeserializeOwned;
use serde::de::value::{Error as ValueError, MapDeserializer, StrDeserializer};

fn rejects_empty_map<T: DeserializeOwned>() {
    let empty = std::iter::empty::<(String, String)>();
    assert!(T::deserialize(MapDeserializer::<_, ValueError>::new(empty)).is_err());
}

fn rejects_unknown_map<T: DeserializeOwned>() {
    let unknown = std::iter::once(("unknown_field".to_owned(), "value".to_owned()));
    assert!(T::deserialize(MapDeserializer::<_, ValueError>::new(unknown)).is_err());
}

fn rejects_unknown_variant<T: DeserializeOwned>() {
    assert!(T::deserialize(StrDeserializer::<ValueError>::new("UnknownVariant")).is_err());
}

fn anchor() -> ChainReadAnchorV1 {
    ChainReadAnchorV1 {
        chain_id: "1".into(),
        genesis_hash: "genesis".into(),
        network_id: "network".into(),
        selector_kind: BlockSelectorKind::Pinned,
        block_number: Some(1),
        block_hash: Some("block-1".into()),
        pending_authorized_by_profile: false,
    }
}

#[test]
fn attempt_envelope_accepts() {
    let value = AttemptEnvelopeDraftV1 {
        attempt_id: "attempt".into(),
        request_id: "request".into(),
        authority_context_digest: "authority".into(),
        capability_profile_digest: "capability".into(),
        profile_digest: "profile".into(),
        provider_instance_id: "provider".into(),
        immutable_request_digest: "request-digest".into(),
        anchor: anchor(),
        ordinal: 1,
        state: AttemptState::Prepared,
        bytes_started_evidence_digest: None,
        started_at_millis: None,
        response_observed_evidence_digest: None,
        observed_at_millis: None,
        completed_at_millis: None,
        no_bytes_sent_evidence_digest: None,
        deadline_millis: 10,
        correlation_id: "correlation".into(),
        causation_id: "causation".into(),
    };
    assert!(AttemptEnvelopeV1::try_from(value.clone()).is_ok());
    for mutate in [
        |v: &mut AttemptEnvelopeDraftV1| v.attempt_id.clear(),
        |v: &mut AttemptEnvelopeDraftV1| v.request_id.clear(),
        |v: &mut AttemptEnvelopeDraftV1| v.authority_context_digest.clear(),
        |v: &mut AttemptEnvelopeDraftV1| v.capability_profile_digest.clear(),
        |v: &mut AttemptEnvelopeDraftV1| v.profile_digest.clear(),
        |v: &mut AttemptEnvelopeDraftV1| v.provider_instance_id.clear(),
        |v: &mut AttemptEnvelopeDraftV1| v.immutable_request_digest.clear(),
        |v: &mut AttemptEnvelopeDraftV1| v.ordinal = 0,
        |v: &mut AttemptEnvelopeDraftV1| v.deadline_millis = 0,
        |v: &mut AttemptEnvelopeDraftV1| v.correlation_id.clear(),
        |v: &mut AttemptEnvelopeDraftV1| v.causation_id.clear(),
    ] {
        let mut drift = value.clone();
        mutate(&mut drift);
        assert!(AttemptEnvelopeV1::try_from(drift).is_err());
    }
}

#[test]
fn route_attempt_accepts() {
    let envelope = AttemptEnvelopeDraftV1 {
        attempt_id: "attempt".into(),
        request_id: "request".into(),
        authority_context_digest: "authority".into(),
        capability_profile_digest: "capability".into(),
        profile_digest: "profile".into(),
        provider_instance_id: "provider".into(),
        immutable_request_digest: "request-digest".into(),
        anchor: anchor(),
        ordinal: 1,
        state: AttemptState::Prepared,
        bytes_started_evidence_digest: None,
        started_at_millis: None,
        response_observed_evidence_digest: None,
        observed_at_millis: None,
        completed_at_millis: None,
        no_bytes_sent_evidence_digest: None,
        deadline_millis: 10,
        correlation_id: "correlation".into(),
        causation_id: "causation".into(),
    };
    assert!(
        RouteAttemptV1::try_from(RouteAttemptDraftV1 {
            envelope: envelope.clone(),
            resolution: None,
        })
        .is_ok()
    );
    let mut terminal_without_resolution = envelope;
    terminal_without_resolution.state = AttemptState::Resolved;
    terminal_without_resolution.bytes_started_evidence_digest = Some("bytes".into());
    terminal_without_resolution.started_at_millis = Some(1);
    terminal_without_resolution.completed_at_millis = Some(2);
    assert!(
        RouteAttemptV1::try_from(RouteAttemptDraftV1 {
            envelope: terminal_without_resolution,
            resolution: None,
        })
        .is_err()
    );
}

#[test]
fn provider_enums_accept() {
    rejects_unknown_variant::<IdempotencyClass>();
    rejects_unknown_variant::<BlockSelectorKind>();
    rejects_unknown_variant::<AttemptState>();
    rejects_unknown_variant::<ResolutionTruth>();
    rejects_unknown_variant::<ProfileLifecycle>();
    rejects_unknown_variant::<RouteMode>();
    rejects_unknown_variant::<ProviderExclusionReason>();
    rejects_unknown_variant::<RecoveryEligibilityV1>();
    rejects_unknown_variant::<ReadRecoveryKind>();
    rejects_unknown_variant::<RoutePlanDraftV1>();
    rejects_unknown_variant::<RouteOutcomeDraftV1>();
}

#[test]
fn indexer_enums_accept() {
    rejects_unknown_variant::<SourceAuthority>();
    rejects_unknown_variant::<ClientIndexerFamily>();
    rejects_unknown_variant::<IndexerProtocolKind>();
    rejects_unknown_variant::<IndexerCapability>();
    rejects_unknown_variant::<PartitionState>();
    rejects_unknown_variant::<DesiredState>();
    rejects_unknown_variant::<GraphHandlerKind>();
    rejects_unknown_variant::<RangeEndV1>();
    rejects_unknown_variant::<SecretPurposeV1>();
    rejects_unknown_variant::<ClientIndexerLifecycle>();
    rejects_unknown_variant::<ExplorerLifecycle>();
    rejects_unknown_variant::<ManagedSubqueryLifecycle>();
    rejects_unknown_variant::<WorkloadIdentityV1>();
    rejects_unknown_variant::<GraphTemplateUse>();
    rejects_unknown_variant::<SubQueryDataNodeSurfaceV1>();
    rejects_unknown_variant::<SubQueryOperationV1>();
    rejects_unknown_variant::<ExplorerCursorV1>();
}

#[test]
fn every_deserializable_contract_owner_is_closed() {
    macro_rules! closed {
        ($($value:ty),+ $(,)?) => {
            $(rejects_empty_map::<$value>(); rejects_unknown_map::<$value>();)+
        };
    }
    closed!(
        ProviderProfileV1,
        MethodDataClass,
        ProviderLimits,
        RouteRequestV1,
        ChainReadAnchorV1,
        EligibleProviderV1,
        ProviderExclusionV1,
        AttemptEnvelopeDraftV1,
        AttemptResolutionDraftV2,
        RouteAttemptDraftV1,
        ReadRecoveryDraftV1,
        ClientIndexerProfileV1,
        IndexerBehaviorV1,
        ProjectionPlanV1,
        SecretReferenceV1,
        ProjectionPartitionV1,
        CandidateProjectionBatchV1,
        SequencedObservationV1,
        CandidateRecordV1,
        DecodeFailureV1,
        CompletedWatermarkV1,
        ExplorerFactSourceProfileV1,
        ExplorerPageLimitsV1,
        ExplorerCandidatePageV1,
        TheGraphManifestProfileV1,
        GraphDataSourceV1,
        GraphMappingV1,
        GraphHandlerV1,
        GraphTemplateV1,
        TheGraphCandidateBatchV1,
        SubQueryClientProfileV1,
        SubQueryDataSourceV1,
        SubQueryHandlerV1,
        SubQueryCandidateBatchV1,
        TypedSelectorV1,
        DependencyV1,
        NamedDigestV1,
        InclusiveRangeV1,
        SourceRangeV1,
        IndexerLimitsV1
    );
}
