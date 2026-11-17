use super::*;
use crate::signing::shard::digest_text;
use crate::{
    candidate_feed::withdrawal::SourceFence, source_authority::withdrawal::VerifiedSourceWithdrawal,
};
use pc_facts_core::{encode_pc_cbor, sha256};
use uuid::Uuid;

mod checkpoint;

impl FactStore {
    pub(crate) async fn pending_source_events(
        &self,
        participant: &str,
        privacy: &str,
    ) -> Result<Vec<(Uuid, u64)>, FactStoreError> {
        let mut tx = self.pool.begin().await?;
        set_context(&mut tx, participant, privacy).await?;
        let rows: Vec<(Uuid,i64)> = sqlx::query_as("select r.partition_id,max(r.candidate_sequence)
            from facts.candidate_feed_receipt r where r.participant_id=$1 and r.privacy_domain_id=$2
              and exists(select 1 from facts.candidate_feed_receipt admitted
                join facts.canonical_fact f using(candidate_id,participant_id,privacy_domain_id)
                join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
                join facts.source_checkpoint c on c.participant_id=admitted.participant_id
                  and c.privacy_domain_id=admitted.privacy_domain_id and c.source_profile_id=admitted.source_profile_id
                where admitted.participant_id=r.participant_id and admitted.privacy_domain_id=r.privacy_domain_id
                  and admitted.partition_id=r.partition_id and (f.state in ('ADMITTED','FINALIZED')
                    or (f.state='RETIRED' and f.complete and f.finality_verified and f.finalized_at is not null and c.state='GAP_BLOCKED')))
            group by r.partition_id order by r.partition_id")
            .bind(participant).bind(privacy).fetch_all(&mut *tx).await?;
        tx.rollback().await?;
        rows.into_iter()
            .map(|(partition, last)| {
                Ok((
                    partition,
                    u64::try_from(last)
                        .map_err(|_| FactStoreError::Feed)?
                        .checked_add(1)
                        .ok_or(FactStoreError::Feed)?,
                ))
            })
            .collect()
    }

    pub(crate) async fn apply_source_withdrawal(
        &self,
        proof: &mut VerifiedSourceWithdrawal,
        signer: &PurposeBoundFactSigner,
    ) -> Result<u64, FactStoreError> {
        let fence = &proof.fence;
        let participant = fence.participant.to_string();
        let privacy = fence.privacy.to_string();
        let mut tx = self.pool.begin().await?;
        set_context(&mut tx, &participant, &privacy).await?;
        let candidates: Vec<String> = sqlx::query_scalar("select f.candidate_id from facts.canonical_fact f
            join facts.candidate_feed_receipt r using(candidate_id,participant_id,privacy_domain_id)
            join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
            where f.participant_id=$1 and f.privacy_domain_id=$2 and r.partition_id=$3 and r.source_generation_id=$4
              and f.state in ('ADMITTED','FINALIZED','RETIRED') order by f.candidate_id")
            .bind(&participant).bind(&privacy).bind(fence.partition).bind(fence.generation.to_string()).fetch_all(&mut *tx).await?;
        let mut changed = 0u64;
        let mut verified = Vec::new();
        for candidate in candidates {
            let row =
                super::signed_record::load(&mut tx, &participant, &privacy, &candidate).await?;
            let record =
                super::signed_record::verify(&row, &signer.verifier(), &participant, &privacy)?
                    .ok_or(FactStoreError::Lifecycle)?;
            let provenance: ciborium::Value = ciborium::de::from_reader(
                row.try_get::<Vec<u8>, _>("canonical_provenance")?
                    .as_slice(),
            )
            .map_err(|_| FactStoreError::Lifecycle)?;
            let publication = provenance
                .as_map()
                .and_then(|fields| {
                    fields
                        .iter()
                        .find(|(k, _)| k.as_text() == Some("publicationDigest"))
                })
                .and_then(|(_, v)| v.as_text());
            if publication != Some(digest_text(&fence.publication_digest).as_str())
                || row.try_get::<Uuid, _>("partition_id")? != fence.partition
                || row.try_get::<String, _>("source_generation_id")? != fence.generation.to_string()
            {
                return Err(FactStoreError::Lifecycle);
            }
            if row.try_get::<String, _>("lifecycle_state")? == "RETIRED" {
                verified.push((candidate, record));
                continue;
            }
            let action = Uuid::now_v7();
            let effective: String=sqlx::query_scalar("select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')").fetch_one(&mut *tx).await?;
            let claims=ciborium::Value::serialized(&serde_json::json!({
                "schemaId":21004,"schemaVersion":pc_facts_core::FACT_SCHEMA_VERSION_V1,
                "schemaDigest":digest_text(&pc_facts_core::FACT_BRIDGE_SCHEMA_DIGEST_V1),"purpose":"openpc:fact-lineage-action:v1",
                "lineageActionId":action,"action":"RETIRE","targetFactId":record.identity.fact_id,
                "targetGeneration":record.identity.canonical_generation,"reasonCode":"SOURCE_QUALIFICATION_WITHDRAWN",
                "effectiveAt":effective,"actorServiceId":crate::LOGICAL_SERVICE_ID,
                "authorityContextDigest":digest_text(&proof.authority_digest),"predecessorDigest":record.identity.local_fact_digest,
                "replacementFactId":null,"reorgReplacementOf":null,
                "evidenceRefs":[digest_text(&sha256(&fence.payload)),record.provenance_digest],
                "correlationId":fence.correlation_id,"causationId":fence.event_id,
                "participantId":record.identity.participant_id,"privacyDomainId":record.identity.privacy_domain_id,
                "affectedRange":record.completeness_scope,"signingKeyId":signer.record_key_id()?,
            })).map_err(|_|FactStoreError::Lifecycle)?;
            let cose = signer.sign_lineage(&claims)?;
            if encode_pc_cbor(signer.verifier().verified_stored_claims(21004, &cose)?)?
                != encode_pc_cbor(claims)?
            {
                return Err(FactStoreError::Lifecycle);
            }
            let binding =
                lineage_binding(fence, &candidate, action, &proof.authority_digest, &cose);
            let cap = self.capabilities.lineage(&binding);
            let applied: bool=sqlx::query_scalar("select facts.retire_for_source_withdrawal($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
                .bind(&participant).bind(&privacy).bind(&candidate).bind(fence.partition).bind(fence.generation.to_string())
                .bind(fence.event_id).bind(i64::try_from(fence.sequence).map_err(|_|FactStoreError::Feed)?)
                .bind(sha256(&fence.payload).as_slice()).bind(action).bind(proof.authority_digest.as_slice()).bind(cose)
                .bind(cap.nonce.as_slice()).bind(cap.mac.as_slice()).fetch_one(&mut *tx).await?;
            changed += u64::from(applied);
            verified.push((candidate, record));
        }
        proof
            .confirm()
            .await
            .map_err(|_| FactStoreError::Lifecycle)?;
        tx.commit().await?;
        // Loss of source authority must retire the Fact even if optional
        // completeness closure is unavailable. Retry closure from the original
        // immutable lineage; never roll that retirement back or resign it.
        if proof.fence.terminal_prefix.is_some() && !verified.is_empty() {
            let mut closure = self.pool.begin().await?;
            set_context(&mut closure, &participant, &privacy).await?;
            checkpoint::close(self, &mut closure, proof, signer, &verified).await?;
            proof
                .confirm()
                .await
                .map_err(|_| FactStoreError::Lifecycle)?;
            closure.commit().await?;
        }
        Ok(changed)
    }
}

fn lineage_binding(
    fence: &SourceFence,
    candidate: &str,
    action: Uuid,
    authority: &[u8; 32],
    cose: &[u8],
) -> [u8; 32] {
    let owned = [
        fence.participant.to_string(),
        fence.privacy.to_string(),
        candidate.into(),
        fence.partition.to_string(),
        fence.generation.to_string(),
        fence.event_id.to_string(),
        fence.sequence.to_string(),
    ];
    let payload = sha256(&fence.payload);
    let action = action.to_string();
    let signed = sha256(cose);
    let mut fields: Vec<&[u8]> = owned.iter().map(|s| s.as_bytes()).collect();
    fields.extend([
        payload.as_slice(),
        action.as_bytes(),
        authority.as_slice(),
        signed.as_slice(),
    ]);
    let mut bytes = Vec::new();
    for (i, field) in fields.into_iter().enumerate() {
        bytes.extend_from_slice(&u16::try_from(i + 1).expect("11 fields").to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    sha256(&bytes)
}
