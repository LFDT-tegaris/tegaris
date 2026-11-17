use super::*;
use openpc_multi_rpc::{
    fact_observation::{
        VerifiedFactStateObservation, observe_fact_event, observe_fact_external, observe_fact_state,
    },
    provider_connection::ConnectionRegistry,
};
use pc_runtime_types::RuntimeError;
use std::path::Path;
use tokio::time::Instant;

/// A live observation made through the exact current provider's committed
/// deployment input and credential. No public constructor or deserializer.
pub struct BoundFactObservation {
    pub(super) observation: VerifiedFactStateObservation,
    pub(super) publication_digest: Vec<u8>,
    pub(super) provider_artifact_digest: Digest,
    pub(super) provider_profile_version: String,
}
impl BoundFactObservation {
    pub(crate) fn expires_at_ms(&self) -> u64 {
        self.observation.valid_until_ms()
    }
}
impl CurrentFactContract<'_> {
    pub async fn observe_provider(
        &self,
        index: usize,
        directory: &Path,
        registry: &ConnectionRegistry,
        deadline: Instant,
        workload: Option<&crate::workload_authority::FactWorkloadAdmission>,
    ) -> Result<BoundFactObservation> {
        self.assert_fresh()?;
        let provider = self
            .providers()
            .get(index)
            .ok_or(SourceAuthorityError::Binding)?;
        let profile = openpc_multi_rpc::qualify_provider_profile(
            &provider.profile_cbor,
            &format!("sha256:{}", provider.artifact_digest.as_str()),
        )
        .map_err(|_| SourceAuthorityError::Binding)?;
        let deadline = deadline
            .min(Instant::now() + std::time::Duration::from_millis(profile.timeout_budget_millis));
        let required = if self.event_signature.is_some() {
            vec![
                ("eth_getLogs", "EVENT_LOG"),
                ("eth_getTransactionReceipt", "RECEIPT"),
                ("eth_getCode", "STATE_CALL"),
            ]
        } else if self.external_request.is_some() {
            vec![
                ("acquireObservation", "EXTERNAL_OBSERVATION"),
                ("eth_getCode", "STATE_CALL"),
            ]
        } else {
            vec![("eth_call", "STATE_CALL"), ("eth_getCode", "STATE_CALL")]
        };
        for (method, class) in required {
            if !profile
                .method_data_classes
                .iter()
                .any(|pair| pair.method == method && pair.data_class == class)
            {
                return Err(SourceAuthorityError::Binding);
            }
        }
        if !profile.method_data_classes.iter().any(|pair| {
            matches!(
                pair.method.as_str(),
                "eth_getBlockByNumber(false)" | "eth_getBlockByNumber"
            ) && pair.data_class == "BLOCK_HEADER"
        }) {
            return Err(SourceAuthorityError::Binding);
        }
        let connection = self
            .source
            .provider_connection(
                index,
                directory,
                registry,
                deadline,
                true,
                self.event_signature.as_ref(),
            )
            .await?;
        let record = connection
            .record()
            .map_err(|_| SourceAuthorityError::Binding)?;
        let revalidate = || {
            self.assert_fresh()
                .map_err(|_| RuntimeError::GenerationMismatch)
        };
        let observation = if let Some(request) = &self.external_request {
            use openpc_multi_rpc::external_decision::AdapterCallContextV1;
            let workload = workload.ok_or(SourceAuthorityError::Binding)?;
            if request.provider_id != provider.provider_id
                || request.provider_version != profile.profile_version
                || request.provider_configuration_digest != provider.artifact_digest
            {
                return Err(SourceAuthorityError::Binding);
            }
            let authorization_digest = Digest::of(
                pc_runtime_types::canonical_bytes(workload)
                    .map_err(|_| SourceAuthorityError::Binding)?,
            );
            let scope_digest = Digest::of(
                pc_runtime_types::canonical_bytes(&(
                    &self.source.participant,
                    &self.source.privacy,
                    &workload.resource_id,
                ))
                .map_err(|_| SourceAuthorityError::Binding)?,
            );
            let context_id = workload.participant_id.to_string();
            let occurrence_id = self
                .candidate_id
                .ok_or(SourceAuthorityError::Binding)?
                .to_string();
            let access = vec!["ACCESS-STANDARD".into()];
            let cancelled = std::sync::atomic::AtomicBool::new(false);
            let current = || revalidate().is_ok();
            let context = AdapterCallContextV1 {
                authorization_digest: &authorization_digest,
                profile_digest: &provider.artifact_digest,
                scope_digest: &scope_digest,
                authorization_context_id: &context_id,
                authorization_context_epoch: workload
                    .participant_epoch
                    .parse()
                    .map_err(|_| SourceAuthorityError::Binding)?,
                access_class_ids: &access,
                occurrence_id: &occurrence_id,
                audit_correlation_id: &occurrence_id,
                deadline,
                profile_timeout_ms: profile.timeout_budget_millis,
                maximum_age_ms: self.admission_profile.maximum_staleness_ms,
                cancelled: &cancelled,
                revalidate: &current,
            };
            observe_fact_external(&connection, &self.query, request, &context, &revalidate).await
        } else {
            match &self.event_signature {
                Some(signature) => {
                    observe_fact_event(&connection, &self.query, signature, deadline, &revalidate)
                        .await
                }
                None => observe_fact_state(&connection, &self.query, deadline, &revalidate).await,
            }
        }
        .map_err(|_| SourceAuthorityError::Binding)?;
        if let Some(request) = &self.external_request {
            observation.validate_external(&self.query, request, record, now_ns()? / 1_000_000)
        } else {
            match &self.event_signature {
                Some(signature) => observation.validate_event(
                    &self.query,
                    signature,
                    record,
                    now_ns()? / 1_000_000,
                ),
                None => observation.validate(&self.query, record, now_ns()? / 1_000_000),
            }
        }
        .map_err(|_| SourceAuthorityError::Binding)?;
        Ok(BoundFactObservation {
            observation,
            publication_digest: self.source.publication_digest.clone(),
            provider_artifact_digest: provider.artifact_digest.clone(),
            provider_profile_version: profile.profile_version,
        })
    }
}
