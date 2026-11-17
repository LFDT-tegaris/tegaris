//! Real COM-017 -> COM-018 state-call admission. This owner can persist an
//! independently verified fact and closing receipt, but cannot mint readiness.
use crate::{
    DurableAdmissionOutcome, FactStore, FactStoreError, PurposeBoundFactSigner,
    candidate_feed::{CandidateFeedError, CandidateFeedReader, CandidateReadScope},
    source_authority::{FactSourceAuthority, SourceAuthorityError},
    workload_authority::{FactIdentityTrust, FactWorkloadAuthenticator, WorkloadAuthorityError},
};
use openpc_multi_rpc::provider_connection::ConnectionRegistry;
use pc_policy_core::identity_context::RuntimeIdentityContext;
use std::{path::Path, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum StateAdmissionError {
    #[error(transparent)]
    Candidate(#[from] CandidateFeedError),
    #[error(transparent)]
    Source(#[from] SourceAuthorityError),
    #[error(transparent)]
    Workload(#[from] WorkloadAuthorityError),
    #[error(transparent)]
    Store(#[from] FactStoreError),
}

/// Real owners and deployment inputs, not substitutes for internal services.
/// The serving process owns their lifetimes and supplies its installed signer,
/// read-only credentials, pinned Identity transport and provider input directory.
pub struct StateFactBridge<'a> {
    pub candidates: &'a CandidateFeedReader,
    pub sources: &'a FactSourceAuthority,
    pub authenticator: &'a FactWorkloadAuthenticator,
    pub identity_trust: &'a FactIdentityTrust,
    pub facts: &'a FactStore,
    pub signer: &'a PurposeBoundFactSigner,
    pub providers: &'a ConnectionRegistry,
    pub provider_directory: &'a Path,
}

impl StateFactBridge<'_> {
    pub async fn consume(
        &self,
        context: RuntimeIdentityContext,
        operation: Uuid,
        partition: Uuid,
        candidate_sequence: u64,
    ) -> Result<DurableAdmissionOutcome, StateAdmissionError> {
        self.consume_with_operation(context, operation, partition, candidate_sequence, None)
            .await
    }

    pub(crate) async fn consume_with_operation(
        &self,
        context: RuntimeIdentityContext,
        operation: Uuid,
        partition: Uuid,
        candidate_sequence: u64,
        binding: Option<&crate::FactOperationBinding>,
    ) -> Result<DurableAdmissionOutcome, StateAdmissionError> {
        let participant =
            Uuid::parse_str(&context.participant_id).map_err(|_| CandidateFeedError::Scope)?;
        let privacy =
            Uuid::parse_str(&context.privacy_domain_id).map_err(|_| CandidateFeedError::Scope)?;
        let scope = || CandidateReadScope::new(participant, privacy, operation);
        let mut feed = self.candidates.read_partition(scope()?, partition).await?;
        if let Some(empty) = feed.empty_checkpoint(candidate_sequence).await? {
            if binding.is_some() {
                return Err(FactStoreError::Feed.into());
            }
            let authentication = self.authenticator.authenticate(context.clone()).await?;
            let mut source = self.sources.acquire(&scope()?, &empty.source).await?;
            source
                .authorize_candidate(
                    authentication,
                    self.identity_trust,
                    &format!("urn:openpc:resource:{}", empty.event.batch.checkpoint_id),
                )
                .await?;
            if self.facts.replay_feed_receipt(&empty.event).await? {
                source.confirm_live().await?;
                feed.close().await?;
                return Ok(DurableAdmissionOutcome::IdempotentReplay);
            }
            let mut evidence = Vec::new();
            let mut profile_binding = None;
            let mut expires_at_ms = u64::MAX;
            for block in &empty.blocks {
                let mut contract = source
                    .contract_at(
                        &empty.source,
                        block.number,
                        &block.hash,
                        empty.event.batch.range_end,
                        None,
                    )
                    .await?;
                let mut observations = Vec::new();
                for index in 0..contract.providers().len() {
                    observations.push(
                        contract
                            .observe_provider(
                                index,
                                self.provider_directory,
                                self.providers,
                                Instant::now() + Duration::from_secs(20),
                                None,
                            )
                            .await?,
                    );
                }
                let current_profile = contract.relationship_checkpoint_profile()?;
                if profile_binding
                    .as_ref()
                    .is_some_and(|prior| prior != &current_profile)
                {
                    return Err(FactStoreError::Feed.into());
                }
                profile_binding = Some(current_profile);
                expires_at_ms = expires_at_ms.min(
                    observations
                        .iter()
                        .map(|o| o.expires_at_ms())
                        .min()
                        .ok_or(FactStoreError::Feed)?,
                );
                evidence.extend(contract.verify_empty_event_block(
                    &observations,
                    block.head_number,
                    &block.head_hash,
                )?);
                contract.confirm_live().await?;
            }
            let (fact_profile_id, profile_digest) = profile_binding.ok_or(FactStoreError::Feed)?;
            let claims = serde_json::json!({"schemaId":21104,"schemaVersion":"1.0.0","participantId":participant,"privacyDomainId":privacy,
                "partitionId":partition,"checkpointId":empty.event.batch.checkpoint_id,"checkpointDigest":crate::signing::shard::digest_text(&empty.event.batch.checkpoint_digest),
                "candidateEventDigest":crate::signing::shard::digest_text(&pc_facts_core::sha256(&empty.event.payload_cbor)),
                "rangeStart":empty.event.batch.range_start.to_string(),"completedWatermark":empty.event.batch.range_end.to_string(),"entryCount":"0","independentObservations":evidence,
                "factProfileId":fact_profile_id,"profileDigest":profile_digest,"expiresAtMs":expires_at_ms.to_string(),"observedAtMs":(crate::source_authority::now_ns()? / 1_000_000).to_string(),
                "blocks":empty.blocks.iter().map(|b|serde_json::json!({"number":b.number.to_string(),"hash":crate::signing::shard::digest_text(&b.hash),"parentHash":crate::signing::shard::digest_text(&b.parent)})).collect::<Vec<_>>()});
            self.facts
                .complete_empty_checkpoint(&empty.event, &claims, self.signer, &mut source)
                .await?;
            feed.close().await?;
            return Ok(DurableAdmissionOutcome::CheckpointAdvanced);
        }
        let (batch, closing) = feed.batch(candidate_sequence).await?;
        if batch.is_empty() {
            return Err(CandidateFeedError::Material.into());
        }
        let state_batch = batch
            .iter()
            .all(|(material, _)| material.record_kind == "STATE_CALL");
        let external_batch = batch
            .iter()
            .all(|(material, _)| material.record_kind == "EXTERNAL_OBSERVATION");
        let relationship_batch = batch
            .iter()
            .all(|(material, _)| material.record_kind == "EVENT_LOG");
        if (!state_batch && !relationship_batch && !external_batch)
            || ((state_batch || external_batch)
                && (closing
                    .batch
                    .range_end
                    .checked_sub(closing.batch.range_start)
                    .and_then(|n| n.checked_add(1))
                    != Some(closing.batch.record_count)
                    || batch.iter().any(|(material, event)| {
                        closing
                            .batch
                            .range_start
                            .checked_add(event.record_ordinal - 1)
                            != Some(material.block_number)
                    })))
            || (relationship_batch
                && batch.windows(2).any(|values| {
                    let left = &values[0].0;
                    let right = &values[1].0;
                    (left.block_number, left.transaction_index, left.log_index)
                        >= (right.block_number, right.transaction_index, right.log_index)
                }))
        {
            return Err(CandidateFeedError::Material.into());
        }
        if let Some(binding) = binding
            && (!binding.valid()
                || binding.candidate_id != batch[0].0.candidate_id
                || binding.expected_revision != candidate_sequence.to_string())
        {
            return Err(FactStoreError::Feed.into());
        }
        let events: Vec<_> = batch.iter().map(|(_, event)| event.clone()).collect();
        // Identity authenticates under its own authority fence. Complete the
        // real transport handshakes before taking Control's exclusive fence;
        // authorize every proof against current state once that fence is held.
        let mut authentications = Vec::with_capacity(batch.len());
        for _ in &batch {
            authentications.push(self.authenticator.authenticate(context.clone()).await?);
        }
        let mut source = self.sources.acquire(&scope()?, &batch[0].0.source).await?;
        let replay = self.facts.replay_feed_batch(&events, &closing).await?;
        let position = self
            .facts
            .feed_position(
                &participant.to_string(),
                &privacy.to_string(),
                partition,
                &batch[0].0.source.source_profile_id.to_string(),
            )
            .await?;
        if !replay && position.last_event_sequence.checked_add(1) != Some(candidate_sequence) {
            return Err(FactStoreError::SequenceRace.into());
        }
        let mut observed = Vec::with_capacity(batch.len());
        // One lease retains current source and Control custody for the full
        // batch. Every exact resource still requires real mTLS authorization.
        for (index, ((material, event), authentication)) in
            batch.iter().zip(authentications).enumerate()
        {
            let workload = source
                .authorize_candidate(
                    authentication,
                    self.identity_trust,
                    &format!("urn:openpc:resource:{}", material.candidate_id),
                )
                .await?;
            if replay {
                continue;
            }
            let fact_sequence = position
                .last_fact_sequence
                .checked_add(index as u64 + 1)
                .ok_or(FactStoreError::SequenceRace)?;
            let mut contract = source.contract(material).await?;
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut observations = Vec::new();
            for provider in 0..contract.providers().len() {
                observations.push(
                    contract
                        .observe_provider(
                            provider,
                            self.provider_directory,
                            self.providers,
                            deadline,
                            Some(&workload),
                        )
                        .await?,
                );
            }
            contract.verify_complete_event_block(
                &batch
                    .iter()
                    .filter(|(candidate, _)| candidate.block_number == material.block_number)
                    .map(|(candidate, _)| candidate)
                    .collect::<Vec<_>>(),
                &observations,
            )?;
            observed.push(contract.admission(
                material,
                &observations,
                &workload,
                event,
                fact_sequence,
            )?);
            contract.confirm_live().await?;
        }
        if relationship_batch && !replay {
            let blocks = feed
                .checkpoint_blocks(
                    closing.batch.checkpoint_id,
                    closing.batch.range_start,
                    closing.batch.range_end,
                )
                .await?;
            for block in blocks {
                if batch.iter().any(|(m, _)| m.block_number == block.number) {
                    continue;
                }
                let mut contract = source
                    .contract_at(
                        &batch[0].0.source,
                        block.number,
                        &block.hash,
                        closing.batch.range_end,
                        None,
                    )
                    .await?;
                let mut observations = Vec::new();
                for index in 0..contract.providers().len() {
                    observations.push(
                        contract
                            .observe_provider(
                                index,
                                self.provider_directory,
                                self.providers,
                                Instant::now() + Duration::from_secs(20),
                                None,
                            )
                            .await?,
                    );
                }
                contract.verify_empty_event_block(
                    &observations,
                    block.head_number,
                    &block.head_hash,
                )?;
                contract.confirm_live().await?;
            }
        }
        if replay {
            source.confirm_live().await?;
            if let Some(binding) = binding {
                self.facts
                    .bind_feed_operation(&participant.to_string(), &privacy.to_string(), binding)
                    .await?;
            }
            return Ok(DurableAdmissionOutcome::IdempotentReplay);
        }
        let result = self
            .facts
            .admit_feed_batch(
                observed,
                &events,
                &closing,
                self.signer,
                &mut source,
                binding,
            )
            .await;
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(FactStoreError::SequenceRace | FactStoreError::ReplayDigestMismatch)
                if self.facts.replay_feed_batch(&events, &closing).await? =>
            {
                if let Some(binding) = binding {
                    self.facts
                        .bind_feed_operation(
                            &participant.to_string(),
                            &privacy.to_string(),
                            binding,
                        )
                        .await?;
                }
                DurableAdmissionOutcome::IdempotentReplay
            }
            Err(error) => return Err(error.into()),
        };
        source.confirm_live().await?;
        feed.close().await?;
        Ok(outcome)
    }
}
