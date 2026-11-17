use super::*;
use crate::signing::shard::{FactShardManifest, digest_text};
use std::path::Path;

impl FactStore {
    /// Reconcile the existing durable admission into immutable publication. The
    /// mutation fence is retained across finalization, artifact verification and
    /// readiness, so invalidation cannot race a stale publication into use.
    pub async fn publish_candidate(
        &self,
        participant: &str,
        privacy: &str,
        candidate: &str,
        signer: &PurposeBoundFactSigner,
        artifact_directory: &Path,
    ) -> Result<bool, FactStoreError> {
        let mut tx = self.pool.begin().await?;
        let ready = self
            .publish_candidate_in_transaction(
                &mut tx,
                participant,
                privacy,
                candidate,
                signer,
                artifact_directory,
            )
            .await?;
        tx.commit().await?;
        Ok(ready)
    }

    pub(crate) async fn publish_candidate_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        participant: &str,
        privacy: &str,
        candidate: &str,
        signer: &PurposeBoundFactSigner,
        artifact_directory: &Path,
    ) -> Result<bool, FactStoreError> {
        set_context(tx, participant, privacy).await?;
        let generation: String = sqlx::query_scalar("select generation_id from facts.canonical_fact where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3")
            .bind(participant).bind(privacy).bind(candidate).fetch_one(&mut **tx).await?;
        let rows =
            super::signed_record::load_generation(tx, participant, privacy, &generation).await?;
        for row in rows {
            let id: String = row.try_get("candidate_id")?;
            let anchor: [u8; 32] = row
                .try_get::<Vec<u8>, _>("finality_anchor")?
                .try_into()
                .map_err(|_| FactStoreError::Lifecycle)?;
            let capability = self
                .capabilities
                .finalize(participant, privacy, &id, &anchor);
            let _: bool = sqlx::query_scalar("select facts.finalize_fact($1,$2,$3,$4,$5,$6)")
                .bind(participant)
                .bind(privacy)
                .bind(&id)
                .bind(anchor.as_slice())
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut **tx)
                .await?;
        }
        let rows =
            super::signed_record::load_generation(tx, participant, privacy, &generation).await?;
        let verifier = signer.verifier();
        let mut records = Vec::with_capacity(rows.len());
        let mut signed_records = Vec::with_capacity(rows.len());
        for row in &rows {
            if row.try_get::<String, _>("lifecycle_state")? != "FINALIZED" {
                return Err(FactStoreError::Lifecycle);
            }
            records.push(
                super::signed_record::verify(row, &verifier, participant, privacy)?
                    .ok_or(FactStoreError::Lifecycle)?,
            );
            signed_records.push(row.try_get::<Vec<u8>, _>("cose_sign1")?);
        }
        pc_facts_core::FactRecord::validate_batch(&records)?;
        let mut content = crate::signing::shard::content_bytes(&signed_records)?;
        // Preserve exact replay of the earlier immutable single-record artifact.
        // New publications always use the ordered content container.
        if signed_records.len() == 1 {
            let existing: Option<Vec<u8>> = sqlx::query_scalar(
                "select shard_cose_sign1 from facts.readiness_gate
                where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3",
            )
            .bind(participant)
            .bind(privacy)
            .bind(&generation)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
            if let Some(existing) = existing {
                let old = verifier.verify_shard_cose(&existing)?;
                if old
                    .manifest
                    .as_ref()
                    .is_some_and(|m| m.matches(&records, &signed_records[0]))
                {
                    content.clone_from(&signed_records[0]);
                }
            }
        }
        let record = &records[0];
        let predecessor: Option<Vec<u8>> = if record.identity.canonical_generation > 1 {
            sqlx::query_scalar(
                "select gate.shard_cose_sign1 from facts.canonical_generation previous
                join facts.readiness_gate gate using(participant_id,privacy_domain_id,generation_id)
                where previous.participant_id=$1 and previous.privacy_domain_id=$2
                  and previous.fact_profile_id=$3 and previous.canonical_generation=$4::numeric-1",
            )
            .bind(participant)
            .bind(privacy)
            .bind(&record.identity.fact_profile_id)
            .bind(record.identity.canonical_generation.to_string())
            .fetch_optional(&mut **tx)
            .await?
            .flatten()
        } else {
            None
        };
        if record.identity.canonical_generation > 1 && predecessor.is_none() {
            return Err(FactStoreError::Lifecycle);
        }
        let mut manifest = FactShardManifest::from_records(
            &records,
            &content,
            &generation,
            predecessor
                .as_deref()
                .map(|v| digest_text(&pc_facts_core::sha256(v))),
        )?;
        if matches!(
            record.identity.typed_subject,
            pc_facts_core::FactSubject::Relationship { .. }
        ) {
            let mut anchors = std::collections::BTreeMap::new();
            for row in &rows {
                let bytes: Vec<u8> = row.try_get("canonical_provenance")?;
                let value: serde_json::Value = ciborium::de::from_reader(bytes.as_slice())
                    .map_err(|_| FactStoreError::Lifecycle)?;
                if let Some(providers) = value["providerObservations"].as_array() {
                    for provider in providers {
                        let blocks: Vec<(u64, String)> =
                            serde_json::from_value(provider["canonicalBlocks"].clone())
                                .map_err(|_| FactStoreError::Lifecycle)?;
                        for (height, hash) in blocks {
                            if height >= record.completeness_scope.range_start
                                && height <= record.completeness_scope.range_end
                                && anchors
                                    .insert(height, hash.clone())
                                    .is_some_and(|prior| prior != hash)
                            {
                                return Err(FactStoreError::Lifecycle);
                            }
                        }
                    }
                }
            }
            manifest.canonical_blocks = anchors.into_iter().collect();
        }
        let signed = signer.sign_complete_shard(&manifest)?;
        let verified = verifier.verify_shard_cose(&signed.cose_sign1)?;
        if !verified
            .manifest
            .as_ref()
            .is_some_and(|m| m.matches(&records, &content))
        {
            return Err(FactStoreError::Lifecycle);
        }
        let publication =
            crate::shard_publication::publish(artifact_directory, &content, &verified)?;
        let ready = rows.iter().all(|row| row.get::<bool, _>("fresh"));
        if ready {
            let capability = self
                .capabilities
                .mark_signed_shard_ready(publication.shard());
            let mut supersessions = Vec::new();
            let mut candidates = Vec::new();
            for (row, record) in rows.iter().zip(&records) {
                let id: String = row.try_get("candidate_id")?;
                if let Some(supersession) = self
                    .prepare_supersession(tx, record, participant, privacy, &id, signer)
                    .await?
                {
                    supersessions.push(supersession);
                }
                candidates.push(id);
            }
            let predecessors: Vec<_> = supersessions
                .iter()
                .map(|s| s.predecessor.clone())
                .collect();
            let actions: Vec<_> = supersessions.iter().map(|s| s.action).collect();
            let authorities: Vec<_> = supersessions.iter().map(|s| s.authority.to_vec()).collect();
            let lineages: Vec<_> = supersessions.iter().map(|s| s.cose.clone()).collect();
            let nonces: Vec<_> = supersessions
                .iter()
                .map(|s| s.capability.nonce.to_vec())
                .collect();
            let macs: Vec<_> = supersessions
                .iter()
                .map(|s| s.capability.mac.to_vec())
                .collect();
            let checkpoints: Vec<_> = supersessions
                .iter()
                .map(|s| s.recovery_checkpoint.clone())
                .collect();
            let changed: bool = sqlx::query_scalar("select facts.commit_verified_publication($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)")
                .bind(participant).bind(privacy).bind(&generation).bind(verified.shard_digest().as_slice())
                .bind(verified.cose_sign1()).bind(capability.nonce.as_slice()).bind(capability.mac.as_slice())
                .bind(&candidates).bind(&predecessors).bind(&actions).bind(&authorities).bind(&lineages).bind(&nonces).bind(&macs).bind(&checkpoints)
                .fetch_one(&mut **tx).await?;
            if !changed {
                return Err(FactStoreError::Lifecycle);
            }
        }
        Ok(ready)
    }
}
