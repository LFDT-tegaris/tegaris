//! Frozen off-path ExternalDecisionAdapterV1. Transport observations confer no
//! fact authority: the caller retains governed profile and admission custody.
use crate::provider_connection::ConnectionLease;
use pc_runtime_types::{Digest, canonical_bytes};
use serde::{Deserialize, Serialize};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalDecisionRequestV1 {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_configuration_digest: Digest,
    pub source_occurrence: Digest,
    pub condition: String,
    pub input_digest: Digest,
}
impl ExternalDecisionRequestV1 {
    pub fn digest(&self) -> Result<Digest, SafeProblemV1> {
        if [&self.participant_id, &self.privacy_domain_id]
            .iter()
            .any(|v| uuid::Uuid::parse_str(v).is_err())
            || [&self.provider_id, &self.provider_version, &self.condition]
                .iter()
                .any(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
            || [
                &self.provider_configuration_digest,
                &self.source_occurrence,
                &self.input_digest,
            ]
            .iter()
            .any(|v| Digest::parse(v.as_str()).as_ref() != Ok(*v))
        {
            return Err(SafeProblemV1::Rejected);
        }
        canonical_bytes(&("openpc:external-decision-request:v1", self))
            .map(Digest::of)
            .map_err(|_| SafeProblemV1::Rejected)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalDecisionObservationV1 {
    pub request_digest: Digest,
    pub source_occurrence: Digest,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_configuration_digest: Digest,
    pub condition: String,
    pub satisfied: bool,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub response_digest: Digest,
}
impl ExternalDecisionObservationV1 {
    pub fn response_digest(&self) -> Result<Digest, SafeProblemV1> {
        canonical_bytes(&(
            "openpc:external-decision-observation:v1",
            &self.request_digest,
            &self.source_occurrence,
            &self.participant_id,
            &self.privacy_domain_id,
            &self.provider_id,
            &self.provider_version,
            &self.provider_configuration_digest,
            &self.condition,
            self.satisfied,
            self.observed_at_ms,
            self.expires_at_ms,
        ))
        .map(Digest::of)
        .map_err(|_| SafeProblemV1::Rejected)
    }
    pub fn validate(
        &self,
        request: &ExternalDecisionRequestV1,
        now: u64,
        maximum_age_ms: u64,
    ) -> Result<(), SafeProblemV1> {
        if self.request_digest != request.digest()?
            || self.source_occurrence != request.source_occurrence
            || self.participant_id != request.participant_id
            || self.privacy_domain_id != request.privacy_domain_id
            || self.provider_id != request.provider_id
            || self.provider_version != request.provider_version
            || self.provider_configuration_digest != request.provider_configuration_digest
            || self.condition != request.condition
            || self.observed_at_ms > now
            || self.expires_at_ms <= now
            || self.expires_at_ms <= self.observed_at_ms
            || self.expires_at_ms - self.observed_at_ms > maximum_age_ms
            || self.response_digest != self.response_digest()?
        {
            return Err(SafeProblemV1::Rejected);
        }
        Ok(())
    }
}

/// Actual current owner context; never derived from the external response.
pub struct AdapterCallContextV1<'a> {
    pub authorization_digest: &'a Digest,
    pub profile_digest: &'a Digest,
    pub scope_digest: &'a Digest,
    pub authorization_context_id: &'a str,
    pub authorization_context_epoch: u64,
    pub access_class_ids: &'a [String],
    pub occurrence_id: &'a str,
    pub audit_correlation_id: &'a str,
    pub deadline: Instant,
    pub profile_timeout_ms: u64,
    pub maximum_age_ms: u64,
    pub cancelled: &'a AtomicBool,
    pub revalidate: &'a (dyn Fn() -> bool + Sync),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum SafeProblemV1 {
    #[error("PC-INTEGRATION-5001")]
    Unavailable,
    #[error("PC-INTEGRATION-5002")]
    Rejected,
    #[error("PC-AUTH-0005")]
    Denied,
}

/// Private verified transport result. Durable admission separately reconciles
/// the stable request/occurrence and rejects conflicting observations.
pub struct VerifiedExternalObservation {
    observation: ExternalDecisionObservationV1,
    request_digest: Digest,
    idempotency_digest: Digest,
}
impl VerifiedExternalObservation {
    pub fn observation(&self) -> &ExternalDecisionObservationV1 {
        &self.observation
    }
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    pub fn idempotency_digest(&self) -> &Digest {
        &self.idempotency_digest
    }
}

pub async fn acquire_observation(
    connection: &ConnectionLease,
    request: &ExternalDecisionRequestV1,
    context: &AdapterCallContextV1<'_>,
) -> Result<VerifiedExternalObservation, SafeProblemV1> {
    if connection
        .record()
        .map_err(|_| SafeProblemV1::Denied)?
        .provider_id
        != request.provider_id
    {
        return Err(SafeProblemV1::Denied);
    }
    let current = || connection.record().is_ok() && (context.revalidate)();
    let context = AdapterCallContextV1 {
        revalidate: &current,
        ..*context
    };
    let result = acquire_prepared_observation(
        connection.connection().map_err(|_| SafeProblemV1::Denied)?,
        request,
        &context,
    )
    .await?;
    connection.record().map_err(|_| SafeProblemV1::Denied)?;
    Ok(result)
}

/// For the existing source dispatcher, whose prepared connection and current
/// signed provider profile remain under its retained authorization fence.
pub async fn acquire_prepared_observation(
    connection: &crate::provider_connection::ProviderConnection,
    request: &ExternalDecisionRequestV1,
    context: &AdapterCallContextV1<'_>,
) -> Result<VerifiedExternalObservation, SafeProblemV1> {
    let request_digest = request.digest()?;
    let idempotency_digest = canonical_bytes(&(
        "openpc:external-decision-idempotency:v1",
        &request_digest,
        &request.source_occurrence,
    ))
    .map(Digest::of)
    .map_err(|_| SafeProblemV1::Rejected)?;
    if context.profile_timeout_ms == 0
        || context.maximum_age_ms == 0
        || context.profile_digest != &request.provider_configuration_digest
        || [
            context.occurrence_id,
            context.audit_correlation_id,
            context.authorization_context_id,
        ]
        .iter()
        .any(|v| uuid::Uuid::parse_str(v).is_err())
        || context.authorization_context_epoch > 9_007_199_254_740_991
        || context.access_class_ids.is_empty()
        || context.access_class_ids.len() > 32
        || context.access_class_ids.iter().any(|v| {
            !v.starts_with("ACCESS-")
                || v.len() > 71
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(SafeProblemV1::Denied);
    }
    let deadline = context
        .deadline
        .min(Instant::now() + Duration::from_millis(context.profile_timeout_ms));
    let expires = time::OffsetDateTime::now_utc()
        + time::Duration::milliseconds(
            i64::try_from(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .map_err(|_| SafeProblemV1::Rejected)?,
        );
    let deadline_at = expires
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| SafeProblemV1::Rejected)?;
    let request_body=crate::rfc8785_canonical_bytes(&serde_json::json!({"method":"acquireObservation","request":request,
        "context":{"authorizationDigest":context.authorization_digest,"profileDigest":context.profile_digest,
        "authorizationContextId":context.authorization_context_id,"authorizationContextEpoch":context.authorization_context_epoch,
        "accessClassIds":context.access_class_ids,"deadlineAt":deadline_at,
        "scopeDigest":context.scope_digest,"idempotencyDigest":idempotency_digest,"occurrenceId":context.occurrence_id,
        "auditCorrelationId":context.audit_correlation_id,"cancellation":{"mode":"NO_NEW_EFFECT_AFTER_CANCELLATION","occurrenceId":context.occurrence_id},
        "reconciliation":{"mode":"EXACT_OCCURRENCE","occurrenceId":context.occurrence_id}}})).map_err(|_|SafeProblemV1::Rejected)?;
    // Retry only transport failures, with identical bytes and one deadline.
    // Malformed and rejected output never retries or becomes an observation.
    for attempt in 0..2 {
        if context.cancelled.load(Ordering::Acquire) || !(context.revalidate)() {
            return Err(SafeProblemV1::Denied);
        }
        if Instant::now() >= deadline {
            return Err(SafeProblemV1::Unavailable);
        }
        let result = connection
            .post_json_with_response_limit(request_body.clone(), deadline, 16384)
            .await;
        if context.cancelled.load(Ordering::Acquire) || !(context.revalidate)() {
            return Err(SafeProblemV1::Denied);
        }
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(_) if attempt == 0 && Instant::now() < deadline => {
                tokio::time::sleep_until(
                    (Instant::now() + Duration::from_millis(10)).min(deadline),
                )
                .await;
                continue;
            }
            Err(_) => return Err(SafeProblemV1::Unavailable),
        };
        let value = crate::parse_strict_json(&bytes, 8).map_err(|_| SafeProblemV1::Rejected)?;
        let observation: ExternalDecisionObservationV1 =
            serde_json::from_value(value).map_err(|_| SafeProblemV1::Rejected)?;
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| SafeProblemV1::Unavailable)?
                .as_millis(),
        )
        .map_err(|_| SafeProblemV1::Unavailable)?;
        observation.validate(request, now, context.maximum_age_ms)?;
        return Ok(VerifiedExternalObservation {
            observation,
            request_digest,
            idempotency_digest,
        });
    }
    Err(SafeProblemV1::Unavailable)
}
