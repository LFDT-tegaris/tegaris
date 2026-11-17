use pc_provider_api::{RequestRouteWitnessV1, RouteExecutionV1, RouteOutcomeV1, RoutePlanV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use uuid::Uuid;

const DATA_SCHEMA: &str = "https://schemas.openpc.local/event-envelope.schema.json";
const ALLOWED_DATA_KEYS: [&str; 11] = [
    "attempt_id",
    "evidence_digest",
    "method",
    "provider_instance_id",
    "provider_profile_digest",
    "request_digest",
    "request_id",
    "resolution_digest",
    "state",
    "submitted_bytes_digest",
    "transaction_digest",
];
const FORBIDDEN_FRAGMENTS: [&str; 8] = [
    "endpoint",
    "credential",
    "raw_request",
    "raw_response",
    "private",
    "hidden",
    "calldata",
    "payload",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EventKind {
    RoutePrepared,
    AttemptStarted,
    AttemptResolved,
    RouteDiverged,
    RouteCompleted,
    WriteAmbiguous,
    WriteReconciled,
}

impl EventKind {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 7] = [
        Self::RoutePrepared,
        Self::AttemptStarted,
        Self::AttemptResolved,
        Self::RouteDiverged,
        Self::RouteCompleted,
        Self::WriteAmbiguous,
        Self::WriteReconciled,
    ];

    pub(crate) const fn event_type(self) -> &'static str {
        match self {
            Self::RoutePrepared => "io.openpc.integration.route.prepared.v1",
            Self::AttemptStarted => "io.openpc.integration.attempt.started.v1",
            Self::AttemptResolved => "io.openpc.integration.attempt.resolved.v1",
            Self::RouteDiverged => "io.openpc.integration.route.diverged.v1",
            Self::RouteCompleted => "io.openpc.integration.route.completed.v1",
            Self::WriteAmbiguous => "io.openpc.integration.write.ambiguous.v1",
            Self::WriteReconciled => "io.openpc.integration.write.reconciled.v1",
        }
    }
}

/// Closed read-terminal projection consumed from the retained production witness.
pub(crate) fn terminal_read_event_kind(witness: &RequestRouteWitnessV1) -> EventKind {
    let RouteExecutionV1::IdempotentRead {
        route_plan,
        outcome,
        ..
    } = witness.execution()
    else {
        return EventKind::RouteCompleted;
    };
    if matches!(outcome, RouteOutcomeV1::Divergent { .. }) {
        return EventKind::RouteDiverged;
    }
    if matches!(route_plan, RoutePlanV1::HedgedSingle { .. }) {
        let valid_digests = witness
            .attempts()
            .iter()
            .filter_map(|attempt| attempt.resolution()?.normalized_response_digest())
            .map(|digest| digest.as_str())
            .collect::<BTreeSet<_>>();
        if valid_digests.len() > 1 {
            return EventKind::RouteDiverged;
        }
    }
    EventKind::RouteCompleted
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventContext {
    pub(crate) id: String,
    pub(crate) source: String,
    pub(crate) subject: String,
    pub(crate) time: String,
    pub(crate) participant_id: String,
    pub(crate) privacy_domain_id: String,
    pub(crate) correlation_id: String,
    pub(crate) causation_id: Option<String>,
    pub(crate) sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenPcEventEnvelopeV1 {
    specversion: String,
    pub(crate) id: String,
    source: String,
    #[serde(rename = "type")]
    event_type: String,
    subject: String,
    pub(crate) time: String,
    datacontenttype: String,
    dataschema: String,
    pub(crate) participantid: String,
    pub(crate) privacydomainid: String,
    pub(crate) correlationid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    causationid: Option<String>,
    sequence: String,
    datadigest: String,
    data: BTreeMap<String, String>,
}

impl OpenPcEventEnvelopeV1 {
    pub(crate) fn new(
        kind: EventKind,
        context: EventContext,
        data: BTreeMap<String, String>,
    ) -> Result<Self, &'static str> {
        validate_context(&context)?;
        validate_data(&data)?;
        let data_bytes = serde_json::to_vec(&data).map_err(|_| "event data encoding")?;
        Ok(Self {
            specversion: "1.0".to_owned(),
            id: context.id,
            source: context.source,
            event_type: kind.event_type().to_owned(),
            subject: context.subject,
            time: context.time,
            datacontenttype: "application/json".to_owned(),
            dataschema: DATA_SCHEMA.to_owned(),
            participantid: context.participant_id,
            privacydomainid: context.privacy_domain_id,
            correlationid: context.correlation_id,
            causationid: context.causation_id,
            sequence: context.sequence.to_string(),
            datadigest: hex_digest(&data_bytes),
            data,
        })
    }

    pub(crate) fn digest(&self) -> Result<String, serde_json::Error> {
        serde_json::to_vec(self).map(|bytes| hex_digest(&bytes))
    }

    #[cfg(test)]
    pub(crate) fn event_type(&self) -> &str {
        &self.event_type
    }
}

fn validate_context(value: &EventContext) -> Result<(), &'static str> {
    for id in [&value.id, &value.correlation_id] {
        let parsed = Uuid::parse_str(id).map_err(|_| "event UUID")?;
        if parsed.get_version_num() != 7 {
            return Err("event UUID must be v7");
        }
    }
    if let Some(causation_id) = &value.causation_id {
        let parsed = Uuid::parse_str(causation_id).map_err(|_| "event causation UUID")?;
        if parsed.get_version_num() != 7 {
            return Err("event causation UUID must be v7");
        }
    }
    if !value.source.starts_with("urn:openpc:")
        || !value.subject.starts_with("urn:openpc:")
        || value.participant_id.is_empty()
        || value.privacy_domain_id.is_empty()
        || value.sequence == 0
        || !value.time.ends_with('Z')
        || !value.time.contains('.')
    {
        return Err("event context");
    }
    Ok(())
}

fn validate_data(data: &BTreeMap<String, String>) -> Result<(), &'static str> {
    let allowed = ALLOWED_DATA_KEYS.into_iter().collect::<BTreeSet<_>>();
    if data.is_empty()
        || data
            .iter()
            .any(|(key, value)| !allowed.contains(key.as_str()) || value.is_empty())
    {
        return Err("event data allowlist");
    }
    let encoded = serde_json::to_string(data)
        .map_err(|_| "event data encoding")?
        .to_ascii_lowercase();
    if FORBIDDEN_FRAGMENTS
        .iter()
        .any(|fragment| encoded.contains(fragment))
    {
        return Err("event data privacy");
    }
    Ok(())
}

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write to String");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(sequence: u64) -> EventContext {
        EventContext {
            id: "018f47a5-4a58-7b21-8f3a-111111111111".into(),
            source: "urn:openpc:service:multi-rpc".into(),
            subject: "urn:openpc:request:request-1".into(),
            time: "2026-09-02T00:00:00.000000Z".into(),
            participant_id: "participant-1".into(),
            privacy_domain_id: "privacy-1".into(),
            correlation_id: "018f47a5-4a58-7b21-8f3a-222222222222".into(),
            causation_id: Some("018f47a5-4a58-7b21-8f3a-333333333333".into()),
            sequence,
        }
    }

    #[test]
    fn seven_events_are_closed_and_privacy_safe() {
        let mut seen = BTreeSet::new();
        for (index, kind) in EventKind::ALL.into_iter().enumerate() {
            let event = OpenPcEventEnvelopeV1::new(
                kind,
                context(u64::try_from(index + 1).expect("small index")),
                BTreeMap::from([
                    ("request_id".into(), "request-1".into()),
                    ("request_digest".into(), "digest-1".into()),
                ]),
            )
            .expect("valid event");
            assert!(seen.insert(event.event_type().to_owned()));
            assert_eq!(event.datadigest.len(), 64);
            assert_eq!(event.dataschema, DATA_SCHEMA);
        }
        assert_eq!(seen.len(), 7);
        for forbidden in [
            "endpoint",
            "credential",
            "raw_request",
            "raw_response",
            "private",
            "hidden",
            "calldata",
            "payload",
        ] {
            let result = OpenPcEventEnvelopeV1::new(
                EventKind::RoutePrepared,
                context(1),
                BTreeMap::from([("request_digest".into(), forbidden.into())]),
            );
            assert_eq!(result, Err("event data privacy"));
        }
        assert!(
            OpenPcEventEnvelopeV1::new(
                EventKind::RoutePrepared,
                context(1),
                BTreeMap::from([("endpoint".into(), "safe".into())]),
            )
            .is_err()
        );
    }
}
