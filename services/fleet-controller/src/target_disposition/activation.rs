//! Native confirmation of an observed activation. The original effect is never
//! replayed; durable first admission precedes signing under reacquired sources.
use super::*;
use openpc_runtime_agent::{RuntimeCapsule, RuntimeWireVerifier};
use pc_runtime_types::target_disposition::TargetDispositionAction;
use serde_json::{Value, json};
use std::collections::BTreeMap;

impl TargetDispositionStore {
    /// First confirmation gate is the fact-free source journey. Fact-bearing
    /// capsules require their separate current Fact authority owner.
    pub async fn publish_activation_confirmation(
        &self,
        peer: &crate::TargetIdentity,
        capsule: &RuntimeCapsule,
        signed_token: &[u8],
        signed_receipt: &[u8],
        artifacts: &BTreeMap<Digest, Vec<u8>>,
        installed_authority_signer_id: &str,
    ) -> Result<bool> {
        self.publish_activation_confirmation_in(
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

    /// Separate native entrypoint: original artifacts are authenticated here;
    /// callers supply neither a proof, source-mode flag nor asserted readiness.
    pub async fn publish_fact_activation_confirmation(
        &self,
        original: OriginalTargetActivation<'_>,
        reader: &openpc_fact_service::PolicyFactReader,
        trust: TargetFactTrust<'_>,
    ) -> Result<bool> {
        self.publish_activation_confirmation_in(
            original,
            DispositionSource::FactBound { reader, trust },
        )
        .await
    }

    async fn publish_activation_confirmation_in(
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
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"input","target_id":peer.target_id,"capsule_id":capsule.capsule_id,"token_bytes":signed_token.len(),"receipt_bytes":signed_receipt.len()})
        );
        let bootstrap = self.bootstrap_for_activation(peer, capsule).await?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"bootstrap_validated"})
        );
        let target_key = self
            .runtime_target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(&peer.target_id)
            .cloned()
            .ok_or_else(unavailable)?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"target_key_resolved"})
        );
        let token = self
            .runtime_control
            .verify_activation_token(signed_token)
            .map_err(|_| unavailable())?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"token_verified","occurrence_id":token.occurrence_id})
        );
        let receipt = RuntimeWireVerifier::from_public_key_bytes(&target_key)
            .and_then(|v| v.verify_receipt(signed_receipt))
            .map_err(|_| unavailable())?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"receipt_verified"})
        );
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| unavailable())?
                .as_nanos(),
        )
        .map_err(|_| unavailable())?;
        restore_custody::require_original_custody(
            capsule,
            &token,
            &receipt,
            &bootstrap.source,
            &peer.target_id,
            now,
        )?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"original_custody_validated"})
        );
        let prepared = self
            .prepare_disposition_source(&original, selection)
            .await?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"source_prepared"})
        );
        if let Some(current) = self.current_for_installed_peer(peer).await? {
            eprintln!(
                "{}",
                json!({"boundary":"target_activation_confirmation","stage":"current_head_found"})
            );
            let wire = current.signed_delivery.as_ref().ok_or_else(unavailable)?;
            let envelope: pc_runtime_types::SignedEnvelope<TargetDispositionDelivery> =
                serde_json::from_slice(wire).map_err(|_| unavailable())?;
            if envelope.claims.action == TargetDispositionAction::ConfirmActivation
                && envelope.claims.source == bootstrap.source
            {
                // Ambiguous commit recovery consumes the original delivery and
                // ACK only. A second signature/nonce cannot replace either.
                let ack_key = self
                    .target_keys
                    .lock()
                    .map_err(|_| unavailable())?
                    .get(&peer.target_id)
                    .cloned()
                    .ok_or_else(unavailable)?;
                let verifier = TargetDispositionVerifier::from_host_keys(
                    bootstrap.target.clone(),
                    &self.control_signer.verifier().sec1_bytes(),
                    &ack_key,
                )
                .map_err(|_| unavailable())?;
                let delivery = verifier
                    .verify_delivery(wire, &bootstrap.source)
                    .map_err(|_| unavailable())?;
                if delivery.claims().revision != current.revision
                    || delivery.claims().committed_admission_digest != current.admission_digest
                {
                    return Err(unavailable());
                }
                prepared
                    .revalidate_replay(self, &original, delivery.claims(), &current)
                    .await?;
                return match current.signed_acknowledgement {
                    None => Ok(false),
                    Some(ack) => {
                        verifier
                            .verify_acknowledgement(&ack, &delivery)
                            .map_err(|_| unavailable())?;
                        Ok(true)
                    }
                };
            }
        }
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"new_admission"})
        );
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        self.context(&mut tx).await?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"context"})
        );
        let mut sources = prepared.lock(self, &mut tx, &peer.target_id).await?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"sources_locked"})
        );
        let identity = self.bootstrap_identity(sources.transaction(), peer).await?;
        if identity != bootstrap.target {
            return Err(unavailable());
        }
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"identity_revalidated"})
        );
        let transaction: String = sqlx::query_scalar("select pg_current_xact_id()::text")
            .fetch_one(&mut **sources.transaction())
            .await
            .map_err(|_| unavailable())?;
        let mut proof = json!({"version":1,"transactionId":transaction,"targetId":peer.target_id,
            "target":identity,"source":bootstrap.source,"capsuleDigest":bootstrap.source.capsule_digest,
            "capsuleValidUntilNs":capsule.hard_expiry_ns.to_string(),"policyGenerationDigest":capsule.policy_bundle_digest,
            "workloadId":prepared.workload(),"identityManifestDigest":capsule.identity_snapshot_manifest_digest,
            "sourceMode":"FACT_FREE","originalReceiptDigest":Digest::of(signed_receipt),
            "originalTokenDigest":Digest::of(signed_token),"occurrenceId":token.occurrence_id});
        sources.bind_proof(&mut proof)?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"proof_bound"})
        );
        self.lock_current_sources(
            sources.transaction(),
            &peer.target_id,
            &proof["source"],
            &proof,
            "CONFIRM",
        )
        .await?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"current_sources_locked"})
        );
        let mut live = sources.acquire().await?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"sources_acquired"})
        );
        let proof_wire = fact_custody::issuer_proof_bytes(&proof)?;
        let mut nonce = [0; 32];
        nonce[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        nonce[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.commit_key)
            .map_err(|_| unavailable())?;
        mac.update(b"OPENPC_TARGET_DISPOSITION_ACTIVATION_ADMISSION_V1");
        mac.update(&Sha256::digest(&proof_wire));
        mac.update(&nonce);
        let row = sqlx::query("select binding,admission_digest from openpc.begin_runtime_target_activation_confirmation($1,$2,$3)")
            .bind(&proof_wire).bind(nonce.as_slice()).bind(mac.finalize().into_bytes().as_slice())
            .fetch_one(&mut **live.transaction()).await.map_err(|error| {
                if let sqlx::Error::Database(database) = &error {
                    eprintln!(
                        "{}",
                        json!({
                            "boundary": "target_activation_confirmation",
                            "stage": "admission_database_error",
                            "code": database.code().as_deref(),
                            "message": database.message(),
                            "constraint": database.constraint(),
                        })
                    );
                }
                database_error(error)
            })?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"admission_inserted"})
        );
        let mut binding: Value = row.try_get("binding").map_err(|_| unavailable())?;
        let digest: String = row.try_get("admission_digest").map_err(|_| unavailable())?;
        let digest = Digest::parse(digest.strip_prefix("sha256:").ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
        if Digest::of(
            canonical_bytes(&json!({"binding":binding,"activationProof":proof}))
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
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"admission_validated"})
        );
        if claims.action != TargetDispositionAction::ConfirmActivation
            || claims.target != identity
            || claims.source != bootstrap.source
        {
            return Err(unavailable());
        }
        live.revalidate().await?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"sources_revalidated"})
        );
        let fence = live.into_commit_fence().await?;
        // The immutable admission is now durable before the first signature.
        // SQL only returns a NEW INSERT here; a pending head cannot be retried.
        let permit = issuance::FirstIssuePermit::commit_new(tx, fence, claims).await?;
        eprintln!(
            "{}",
            json!({"boundary":"target_activation_confirmation","stage":"admission_committed"})
        );
        self.issue_prepared(&original, &prepared, &proof, permit)
            .await
    }
}
