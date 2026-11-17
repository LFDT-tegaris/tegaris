//! Current provider preparation and connection generation are shared by state
//! admission and independent reorg observation, never policy reads.
use super::*;
use openpc_multi_rpc::{
    provider_connection::{ConnectionError, ConnectionLease, ConnectionRegistry},
    provider_probe_source,
};
use std::path::Path;
use tokio::time::{Instant, timeout_at};
impl CurrentFactSource {
    pub(super) async fn provider_connection(
        &self,
        index: usize,
        directory: &Path,
        registry: &ConnectionRegistry,
        deadline: Instant,
        require_headers: bool,
        event_signature: Option<&Digest>,
    ) -> Result<ConnectionLease> {
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
        let prepare = |generation| {
            provider_probe_source::prepare(
                directory,
                &provider.endpoint_secret_ref,
                &profile,
                &self.participant.to_string(),
                &self.privacy.to_string(),
                generation,
            )
            .map_err(|_| SourceAuthorityError::Binding)
        };
        let generation = now_ns()? / 1_000_000;
        let mut prepared = prepare(generation)?;
        let prior = match registry.readback(&prepared.endpoint_id).await {
            Ok(record) => Some(record),
            Err(ConnectionError::NotInstalled) => None,
            Err(_) => return Err(SourceAuthorityError::Binding),
        };
        if let Some(previous) = &prior
            && previous.resolution_generation >= generation
        {
            prepared = prepare(
                previous
                    .resolution_generation
                    .checked_add(1)
                    .ok_or(SourceAuthorityError::Binding)?,
            )?;
        }
        // The qualification corpus establishes supported bounded header I/O.
        // Canonicality of the requested anchor is established by the actual
        // independent observation, not a historical qualification block hash.
        if require_headers && prepared.plan.block_header.is_none() {
            return Err(SourceAuthorityError::Binding);
        }
        if event_signature.is_some_and(|signature| {
            prepared
                .plan
                .event_log
                .as_ref()
                .is_none_or(|corpus| &corpus.event_signature != signature)
        }) {
            return Err(SourceAuthorityError::Binding);
        }
        let record = timeout_at(
            deadline,
            registry.install(
                &provider.provider_id,
                prior
                    .as_ref()
                    .map_or(0, |value| value.dispatcher_generation),
                prepared.connection,
            ),
        )
        .await
        .map_err(|_| SourceAuthorityError::Expired)?
        .map_err(|_| SourceAuthorityError::Binding)?;
        registry
            .acquire(
                &provider.provider_id,
                &record.endpoint_id,
                record.dispatcher_generation,
            )
            .map_err(|_| SourceAuthorityError::Binding)
    }
}
