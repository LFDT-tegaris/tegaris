//! Verify candidate fork observations under current Control/provider custody.
//! No collector credential or policy-read-time external lookup participates.
use super::*;
use crate::candidate_feed::reorg::SourceReorg;
use openpc_multi_rpc::{
    fact_observation::{FactReorgQuery, observe_fact_reorg},
    provider_connection::ConnectionRegistry,
};
use std::path::Path;
use tokio::time::Instant;

pub(crate) struct VerifiedSourceReorg {
    pub event: SourceReorg,
    pub authority_digest: [u8; 32],
    pub observed_through: u64,
    source: CurrentFactSource,
}
impl VerifiedSourceReorg {
    pub async fn confirm(&mut self) -> Result<()> {
        self.source.confirm_live().await
    }
}
impl FactSourceAuthority {
    pub(crate) async fn verify_reorg(
        &self,
        event: SourceReorg,
        directory: &Path,
        registry: &ConnectionRegistry,
    ) -> Result<VerifiedSourceReorg> {
        let mut source = self.acquire(&event.scope, &event.source).await?;
        let profile = event.source.inputs.profile();
        let rule = event.source.inputs.finality_rule();
        let openpc_indexer_adapter::FinalityMode::Confirmations { count } = rule.mode else {
            return Err(SourceAuthorityError::Binding);
        };
        let as_digest = |bytes: &[u8]| {
            Digest::parse(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
                .map_err(|_| SourceAuthorityError::Binding)
        };
        let query = FactReorgQuery {
            chain_id: profile
                .chain_id
                .parse()
                .map_err(|_| SourceAuthorityError::Binding)?,
            genesis_hash: digest(&profile.genesis_hash)?,
            start: event.start,
            end: event.end,
            old_hash: as_digest(&event.old_hash)?,
            new_hash: as_digest(&event.new_hash)?,
            confirmations: count,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut observations = Vec::new();
        for (index, provider) in source.providers().iter().enumerate() {
            let current = openpc_multi_rpc::qualify_provider_profile(
                &provider.profile_cbor,
                &format!("sha256:{}", provider.artifact_digest.as_str()),
            )
            .map_err(|_| SourceAuthorityError::Binding)?;
            if !current.method_data_classes.iter().any(|v| {
                matches!(
                    v.method.as_str(),
                    "eth_getBlockByNumber" | "eth_getBlockByNumber(false)"
                ) && v.data_class == "BLOCK_HEADER"
            }) {
                return Err(SourceAuthorityError::Binding);
            }
            let connection = source
                .provider_connection(index, directory, registry, deadline, true, None)
                .await?;
            let revalidate = || {
                source
                    .assert_fresh()
                    .map_err(|_| pc_runtime_types::RuntimeError::GenerationMismatch)
            };
            let observed = observe_fact_reorg(&connection, &query, deadline, &revalidate)
                .await
                .map_err(|_| SourceAuthorityError::Binding)?;
            observations.push((provider.artifact_digest.clone(), observed));
        }
        if observations.len() < usize::from(rule.required_observations) {
            return Err(SourceAuthorityError::Binding);
        }
        source.confirm_live().await?;
        let evidence=crate::state_value::canonical(&serde_json::json!({"purpose":"openpc:fact-reorg-authority:v1",
            "participantId":event.scope.participant,"privacyDomainId":event.scope.privacy,"eventId":event.event.event_id,
            "eventDigest":crate::signing::shard::digest_text(&event.event.payload_digest),
            "publicationDigest":crate::signing::shard::digest_text(&event.source.inputs.published().publication_digest),
            "query":query,"observations":observations})).map_err(|_|SourceAuthorityError::Binding)?;
        let observed_through = event
            .end
            .checked_add(u64::from(count))
            .ok_or(SourceAuthorityError::Binding)?;
        Ok(VerifiedSourceReorg {
            event,
            authority_digest: pc_facts_core::sha256(&evidence),
            observed_through,
            source,
        })
    }
}
