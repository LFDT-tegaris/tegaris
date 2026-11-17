//! Native restoration: original crypto custody plus current relational/CIGL
//! source admission. Admission commits before the single-use signing permit.
//! Signing and delivery commit share the second source transaction;
//! no network call or target effect occurs while those fences are held.
use super::*;
use openpc_runtime_agent::{RuntimeCapsule, authority_artifact::AuthoritySourceBinding};
use pc_runtime_types::target_disposition::{TargetDispositionAction, TargetDispositionSource};
use serde_json::{Value, json};
use std::collections::BTreeMap;

impl TargetDispositionStore {
    /// A scheduler selector only. The publisher independently verifies custody,
    /// current authority and the same failed cause before it can sign anything.
    pub async fn unstarted_restore_cause(
        &self,
        peer: &crate::TargetIdentity,
    ) -> Result<Option<String>> {
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        self.context(&mut tx).await?;
        let cause=sqlx::query_scalar(r#"select cause.configuration_work_id::text
          from (select a.binding,a.revision from control.runtime_target_disposition_admission a
           where a.participant_id=openpc.current_participant_id() and a.privacy_domain_id=openpc.current_privacy_domain_id()
            and a.runtime_target_id=$1::text::uuid order by a.revision desc limit 1) head
          join control.configuration_work cause on cause.participant_id=openpc.current_participant_id()
           and cause.privacy_domain_id=openpc.current_privacy_domain_id()
           and cause.configuration_work_id::text=head.binding->'cause'->>'work_id'
          where head.binding->>'action' in ('Withdraw','Restore') and head.binding->'cause'->>'kind'='Activation'
           and cause.runtime_target_id=$1::text::uuid and cause.work_kind='RUNTIME_ACTIVATION'
           and cause.state='FAILED' and cause.completed_at is not null
           and cause.execution_started_at is null and cause.execution_attempt_id is null"#)
            .bind(&peer.target_id).fetch_optional(&mut *tx).await.map_err(|_| unavailable())?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(cause)
    }

    pub(super) async fn lock_restore_sources(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        target: &str,
        source: &Value,
        proof: &Value,
    ) -> Result<()> {
        self.lock_current_sources(tx, target, source, proof, "RESTORE")
            .await
    }

    pub(super) async fn lock_current_sources(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        target: &str,
        source: &Value,
        proof: &Value,
        operation: &str,
    ) -> Result<()> {
        let source: TargetDispositionSource =
            serde_json::from_value(source.clone()).map_err(|_| unavailable())?;
        source.validate().map_err(|_| unavailable())?;
        // The existing owner provides the actual profile/grant/source oracle.
        // Acquire its fail-fast interface before the legacy reentrant read path.
        sqlx::query("select openpc.lock_cigl_grant_sources(true)")
            .execute(&mut **tx)
            .await
            .map_err(|error| {
                self.source_failure(target, &source, proof, "grant_lock", &error);
                database_error(error)
            })?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
            .bind(&self.participant).bind(&self.privacy).execute(&mut **tx).await.map_err(|_| unavailable())?;
        if crate::cigl_publication::profile_invalidation::generation_is_invalidated(
            tx,
            target,
            &source.runtime_configuration_generation_id,
            &source.capsule_digest,
        )
        .await
        .map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        self.context(tx).await?;
        sqlx::query("select openpc.lock_runtime_target_current_sources($1::text::uuid,$2,$3,$4)")
            .bind(target)
            .bind(serde_json::to_value(&source).map_err(|_| unavailable())?)
            .bind(proof)
            .bind(operation)
            .execute(&mut **tx)
            .await
            .map_err(|error| {
                self.source_failure(target, &source, proof, "current_source_lock", &error);
                database_error(error)
            })?;
        if let Ok(mut diagnostics) = self.source_diagnostics.lock() {
            diagnostics.clear(target);
        }
        Ok(())
    }

    /// First operation gate: a terminal successor with no started effect. Fact-
    /// bearing and confirmed-no-effect restoration retain their separate gates.
    /// A true result only acknowledges this delivery, never reference clearance.
    pub async fn publish_unstarted_restore(
        &self,
        peer: &crate::TargetIdentity,
        capsule: &RuntimeCapsule,
        signed_token: &[u8],
        signed_receipt: &[u8],
        artifacts: &BTreeMap<Digest, Vec<u8>>,
        installed_authority_signer_id: &str,
    ) -> Result<bool> {
        self.publish_unstarted_restore_in(
            OriginalTargetActivation {
                peer,
                capsule,
                signed_token,
                signed_receipt,
                artifacts,
            },
            DispositionSource::FactFree(installed_authority_signer_id),
        )
        .await
    }

    /// Fact-bearing counterpart of the existing provably-unstarted operation.
    /// This cannot settle a started/unknown successor or create observations.
    pub async fn publish_fact_unstarted_restore(
        &self,
        original: OriginalTargetActivation<'_>,
        reader: &openpc_fact_service::PolicyFactReader,
        trust: TargetFactTrust<'_>,
    ) -> Result<bool> {
        self.publish_unstarted_restore_in(original, DispositionSource::FactBound { reader, trust })
            .await
    }

    async fn publish_unstarted_restore_in(
        &self,
        original: OriginalTargetActivation<'_>,
        selection: DispositionSource<'_>,
    ) -> Result<bool> {
        let OriginalTargetActivation {
            peer,
            capsule,
            signed_token,
            signed_receipt,
            artifacts: _,
        } = original;
        let current = self
            .current_for_installed_peer(peer)
            .await?
            .ok_or_else(unavailable)?;
        let wire = current.signed_delivery.as_ref().ok_or_else(unavailable)?;
        let envelope: pc_runtime_types::SignedEnvelope<TargetDispositionDelivery> =
            serde_json::from_slice(wire).map_err(|_| unavailable())?;
        if envelope.claims.action == TargetDispositionAction::Restore {
            // Ambiguous prior commit is reconciled solely from original bytes.
            // No re-sign, replacement nonce/intent, or new activation occurs.
            let target_key = self
                .target_keys
                .lock()
                .map_err(|_| unavailable())?
                .get(&peer.target_id)
                .cloned()
                .ok_or_else(unavailable)?;
            let verifier = TargetDispositionVerifier::from_host_keys(
                envelope.claims.target.clone(),
                &self.control_signer.verifier().sec1_bytes(),
                &target_key,
            )
            .map_err(|_| unavailable())?;
            let delivery = verifier
                .verify_delivery(wire, &envelope.claims.source)
                .map_err(|_| unavailable())?;
            if delivery.claims().source.capsule_digest
                != capsule.digest().map_err(|_| unavailable())?
                || delivery.claims().revision != current.revision
                || delivery.claims().committed_admission_digest != current.admission_digest
            {
                return Err(unavailable());
            }
            // Fact-free replay retains its existing public behavior. Fact-bound
            // replay additionally reacquires the original current custody and
            // checks the persisted exact proof; it never emits a new signature.
            if matches!(&selection, DispositionSource::FactBound { .. }) {
                self.prepare_disposition_source(&original, selection)
                    .await?
                    .revalidate_replay(self, &original, delivery.claims(), &current)
                    .await?;
            }
            return match current.signed_acknowledgement {
                None => Ok(false),
                Some(bytes) => {
                    verifier
                        .verify_acknowledgement(&bytes, &delivery)
                        .map_err(|_| unavailable())?;
                    Ok(true)
                }
            };
        }
        let custody = self
            .verify_original_restore_custody(peer, capsule, signed_token, signed_receipt)
            .await?;
        let prepared = self
            .prepare_disposition_source(&original, selection)
            .await?;
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        self.context(&mut tx).await?;
        let mut sources = prepared.lock(self, &mut tx, &peer.target_id).await?;
        let identity = self.bootstrap_identity(sources.transaction(), peer).await?;
        if identity != custody.withdrawal.claims().target {
            return Err(unavailable());
        }
        let transaction_id: String = sqlx::query_scalar("select pg_current_xact_id()::text")
            .fetch_one(&mut **sources.transaction())
            .await
            .map_err(|_| unavailable())?;
        let mut proof = json!({
            "version":1,"transactionId":transaction_id,"targetId":peer.target_id,
            "withdrawalDigest":custody.withdrawal.signed_digest().as_str(),
            "capsuleDigest":custody.source().capsule_digest.as_str(),
            "capsuleValidUntilNs":capsule.hard_expiry_ns.to_string(),
            "policyGenerationDigest":capsule.policy_bundle_digest.as_str(),
            "workloadId":prepared.workload(),"identityManifestDigest":capsule.identity_snapshot_manifest_digest.as_str(),
            "sourceMode":"FACT_FREE","originalReceiptDigest":custody.receipt_digest.as_str(),
            "originalTokenDigest":custody.token_digest.as_str()
        });
        sources.bind_proof(&mut proof)?;
        let source = serde_json::to_value(custody.source()).map_err(|_| unavailable())?;
        self.lock_restore_sources(sources.transaction(), &peer.target_id, &source, &proof)
            .await?;
        let mut live = sources.acquire().await?;
        let proof_wire = fact_custody::issuer_proof_bytes(&proof)?;
        let mut nonce = [0; 32];
        nonce[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        nonce[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.commit_key)
            .map_err(|_| unavailable())?;
        mac.update(b"OPENPC_TARGET_DISPOSITION_RESTORE_ADMISSION_V1");
        mac.update(&Sha256::digest(&proof_wire));
        mac.update(&nonce);
        let row=sqlx::query("select binding,admission_digest from openpc.begin_runtime_target_unstarted_restore($1,$2,$3)")
            .bind(&proof_wire).bind(nonce.as_slice()).bind(mac.finalize().into_bytes().as_slice())
            .fetch_one(&mut **live.transaction()).await.map_err(database_error)?;
        let mut binding: Value = row.try_get("binding").map_err(|_| unavailable())?;
        let digest: String = row.try_get("admission_digest").map_err(|_| unavailable())?;
        let digest = Digest::parse(digest.strip_prefix("sha256:").ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
        if Digest::of(
            canonical_bytes(&json!({"binding":binding,"restorationProof":proof}))
                .map_err(|_| unavailable())?,
        ) != digest
        {
            return Err(unavailable());
        }
        binding
            .as_object_mut()
            .ok_or_else(unavailable)?
            .insert("committed_admission_digest".into(), json!(digest));
        let claims: TargetDispositionDelivery =
            serde_json::from_value(binding).map_err(|_| unavailable())?;
        claims.validate().map_err(|_| unavailable())?;
        if claims.action != TargetDispositionAction::Restore
            || claims.target != identity
            || claims.source != *custody.source()
            || claims.cause != custody.withdrawal.claims().cause
            || claims.previous_revision != custody.withdrawal.claims().revision
            || claims.previous_delivery_digest.as_ref() != Some(custody.withdrawal.signed_digest())
        {
            return Err(unavailable());
        }
        live.revalidate().await?;
        let fence = live.into_commit_fence().await?;
        // The immutable admission is now durable before the first signature.
        // SQL only returns a NEW INSERT here; a pending head cannot be retried.
        let permit = issuance::FirstIssuePermit::commit_new(tx, fence, claims).await?;
        self.issue_prepared(&original, &prepared, &proof, permit)
            .await
    }

    pub(super) fn fact_free_restore_workload(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
        signer: &str,
    ) -> Result<String> {
        use openpc_runtime_agent::indexer_custody::NO_FACT_PUBLICATION;
        const CONFIGURATION_ARTIFACT_ID: &str = "openpc.invocation.configuration";
        const CONFIGURATION_DEFINITION: &[u8] = b"openpc.invocation.configuration-source.v1";
        const POLICY_ARTIFACT_ID: &str = "openpc.invocation.policy";
        const POLICY_DEFINITION: &[u8] = b"openpc.invocation.policy-source.v1";
        let has = |id: &str| {
            capsule
                .artifact_components
                .iter()
                .any(|c| c.component_id == id)
        };
        let source_policy = has(openpc_runtime_agent::indexer_custody::POLICY_ARTIFACT_ID)
            || has(openpc_runtime_agent::indexer_custody::CONFIGURATION_ARTIFACT_ID);
        if source_policy {
            // A source-only capsule cannot acquire invocation authority through
            // disposition confirmation. Its own owner verifies both signed
            // sources, their exact scope and the absence of Fact dependencies.
            if has(POLICY_ARTIFACT_ID) || has(CONFIGURATION_ARTIFACT_ID) {
                return Err(unavailable());
            }
            return crate::runtime_target::source_policy_workload(
                self.runtime_control.clone(),
                &self.participant,
                &self.privacy,
                signer,
                capsule,
                artifacts,
            )
            .map_err(|_| unavailable());
        }
        let source = |id: &str, definition: &[u8]| -> Result<&[u8]> {
            let binding = AuthoritySourceBinding {
                artifact_id: id.into(),
                artifact_class: 1,
                source_media_type: "application/cbor".into(),
                definition_digest: Digest::of(definition),
                signer_id: signer.into(),
                maximum_source_bytes: 4 * 1024 * 1024,
            };
            let selected = binding
                .in_capsule(&self.runtime_control, capsule, artifacts)
                .map(|(_, _, bytes)| bytes)
                .map_err(|_| unavailable());
            eprintln!(
                "{}",
                serde_json::json!({"boundary":"target_activation_confirmation","stage":"fact_free_source_binding","artifact_id":id,"found":selected.is_ok(),"capsule_component_count":capsule.artifact_components.len()})
            );
            selected
        };
        let policy_bytes = source(POLICY_ARTIFACT_ID, POLICY_DEFINITION)?;
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_activation_confirmation","stage":"fact_free_policy_parser_input","bytes":policy_bytes.len(),"semantic_model_digest":capsule.semantic_model_digest})
        );
        let policy = pc_policy_core::invocation::decode_active_invocation_policy_generation(
            policy_bytes,
            &capsule.semantic_model_digest,
        )
        .map_err(|_| {
            eprintln!(
                "{}",
                serde_json::json!({"boundary":"target_activation_confirmation","stage":"fact_free_policy_parser_rejected"})
            );
            unavailable()
        })?;
        if capsule.policy_fact_state_digest != Digest::of(NO_FACT_PUBLICATION)
            || !policy.required_facts.is_empty()
            || !policy.deployment_policies.is_empty()
            || (policy.assets.is_empty()
                && policy.indexer_policies.is_empty()
                && policy.visibility_policies.is_empty())
        {
            eprintln!(
                "{}",
                serde_json::json!({"boundary":"target_activation_confirmation","stage":"fact_free_policy_rejected","has_required_facts":!policy.required_facts.is_empty(),"asset_count":policy.assets.len(),"deployment_policy_count":policy.deployment_policies.len(),"indexer_policy_count":policy.indexer_policies.len(),"visibility_policy_count":policy.visibility_policies.len()})
            );
            return Err(unavailable());
        }
        let configuration_bytes = source(CONFIGURATION_ARTIFACT_ID, CONFIGURATION_DEFINITION)?;
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_activation_confirmation","stage":"fact_free_configuration_parser_input","bytes":configuration_bytes.len(),"named_set_registry_digest":capsule.named_set_registry_digest})
        );
        pc_policy_core::invocation::active_invocation_workload(
            configuration_bytes,
            &capsule.named_set_registry_digest,
            &self.participant,
            &self.privacy,
        )
        .map_err(|_| {
            eprintln!(
                "{}",
                serde_json::json!({"boundary":"target_activation_confirmation","stage":"fact_free_configuration_parser_rejected"})
            );
            unavailable()
        })
    }
}

#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;
