//! Historical producer completion: original publication custody and both
//! immutable consumer ACKs. This never changes readiness or lifecycle authority.
use super::*;
use crate::signing::shard::{content_bytes, digest_text};
use std::path::Path;

#[cfg(test)]
pub(super) mod tests;

impl FactStore {
    pub(crate) async fn reconcile_producer_deliveries(
        &self,
        participant: &str,
        privacy: &str,
        verifier: &FactSignatureVerifier,
        artifact_directory: &Path,
    ) -> Result<u64, FactStoreError> {
        let mut tx = self.pool.begin().await?;
        set_context(&mut tx, participant, privacy).await?;
        sqlx::query("set local statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        let generations: Vec<String> = sqlx::query_scalar("select p.generation_id from facts.shard_publication p
            where p.participant_id=$1 and p.privacy_domain_id=$2 and p.delivery_state='PENDING'
              and not exists(select 1 from facts.canonical_fact f
                left join facts.control_admission_custody_ack c using(candidate_id,participant_id,privacy_domain_id)
                left join facts.fleet_admission_ack a using(candidate_id,participant_id,privacy_domain_id)
                where f.participant_id=p.participant_id and f.privacy_domain_id=p.privacy_domain_id
                  and f.generation_id=p.generation_id and (c.candidate_id is null or a.candidate_id is null))
            order by p.published_at,p.generation_id limit 16")
            .bind(participant).bind(privacy).fetch_all(&mut *tx).await?;
        tx.rollback().await?;
        let mut changed = 0;
        for generation in generations {
            changed += u64::from(
                self.complete_producer_delivery(
                    participant,
                    privacy,
                    &generation,
                    verifier,
                    artifact_directory,
                )
                .await?,
            );
        }
        Ok(changed)
    }

    async fn complete_producer_delivery(
        &self,
        participant: &str,
        privacy: &str,
        generation: &str,
        verifier: &FactSignatureVerifier,
        artifact_directory: &Path,
    ) -> Result<bool, FactStoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("set transaction isolation level repeatable read")
            .execute(&mut *tx)
            .await?;
        set_context(&mut tx, participant, privacy).await?;
        sqlx::query("set local statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local lock_timeout='2s'")
            .execute(&mut *tx)
            .await?;
        let original: Vec<u8> = sqlx::query_scalar(
            "select g.shard_cose_sign1 from facts.readiness_gate g
            join facts.shard_publication p using(participant_id,privacy_domain_id,generation_id)
            where g.participant_id=$1 and g.privacy_domain_id=$2 and g.generation_id=$3",
        )
        .bind(participant)
        .bind(privacy)
        .bind(generation)
        .fetch_one(&mut *tx)
        .await?;
        let shard = verifier.verify_shard_cose(&original)?;
        if shard.participant_id() != participant
            || shard.privacy_domain_id() != privacy
            || shard.generation_id() != generation
        {
            return Err(FactStoreError::Lifecycle);
        }
        let rows = super::signed_record::load_generation(&mut tx, participant, privacy, generation)
            .await?;
        let mut records = Vec::with_capacity(rows.len());
        let mut signed = Vec::with_capacity(rows.len());
        for row in &rows {
            records.push(
                super::signed_record::verify(row, verifier, participant, privacy)?
                    .ok_or(FactStoreError::Lifecycle)?,
            );
            signed.push(row.try_get::<Vec<u8>, _>("cose_sign1")?);
        }
        pc_facts_core::FactRecord::validate_batch(&records)?;
        let mut content = content_bytes(&signed)?;
        let manifest = shard.manifest.as_ref().ok_or(FactStoreError::Lifecycle)?;
        // Historical single-record publications retain their original encoding.
        if signed.len() == 1 && manifest.matches(&records, &signed[0]) {
            content.clone_from(&signed[0]);
        }
        if !manifest.matches(&records, &content) {
            return Err(FactStoreError::Lifecycle);
        }
        let publication =
            crate::shard_publication::read_published(artifact_directory, &content, &shard)?;
        let material = publication_material(&publication)?;
        let capability = self.capabilities.producer_delivery(&material);
        let changed: bool = sqlx::query_scalar("select facts.complete_producer_delivery($1,$2,$3)")
            .bind(material)
            .bind(capability.nonce.as_slice())
            .bind(capability.mac.as_slice())
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(changed)
    }
}

fn publication_material(
    publication: &crate::shard_publication::VerifiedPublication<'_>,
) -> Result<Vec<u8>, FactStoreError> {
    let shard = publication.shard();
    serde_json::to_vec(&serde_json::json!({
        "participantId":shard.participant_id(), "privacyDomainId":shard.privacy_domain_id(),
        "generationId":shard.generation_id(), "contentDigest":digest_text(shard.shard_digest()),
        "manifestDigest":digest_text(&pc_facts_core::sha256(shard.cose_sign1())),
    }))
    .map_err(|_| FactStoreError::Lifecycle)
}
