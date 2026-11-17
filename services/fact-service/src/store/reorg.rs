//! A verified canonical mismatch invalidates immutable facts before replacement.
use super::*;
use crate::{signing::shard::digest_text, source_authority::reorg::VerifiedSourceReorg};
use pc_facts_core::{encode_pc_cbor, sha256};
use uuid::Uuid;

impl FactStore {
    pub(crate) async fn apply_source_reorg(
        &self,
        proof: &mut VerifiedSourceReorg,
        signer: &PurposeBoundFactSigner,
    ) -> Result<u64, FactStoreError> {
        let event = &proof.event;
        let participant = event.scope.participant.to_string();
        let privacy = event.scope.privacy.to_string();
        let mut tx = self.pool.begin().await?;
        set_context(&mut tx, &participant, &privacy).await?;
        let candidates:Vec<String>=sqlx::query_scalar("select f.candidate_id from facts.canonical_fact f
            join facts.candidate_feed_receipt r using(candidate_id,participant_id,privacy_domain_id)
            join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
            where f.participant_id=$1 and f.privacy_domain_id=$2 and r.partition_id=$3 and r.source_generation_id=$4
              and r.range_start<=$6::numeric and r.range_end>=$5::numeric and f.state in ('ADMITTED','FINALIZED') order by f.candidate_id")
            .bind(&participant).bind(&privacy).bind(event.partition).bind(event.event.generation_id.to_string()).bind(event.start.to_string()).bind(event.end.to_string()).fetch_all(&mut *tx).await?;
        let mut changed = 0;
        for candidate in candidates {
            let candidate_id =
                Uuid::parse_str(&candidate).map_err(|_| FactStoreError::Lifecycle)?;
            let (block, hash) = event
                .candidates
                .get(&candidate_id)
                .ok_or(FactStoreError::Lifecycle)?;
            let row =
                super::signed_record::load(&mut tx, &participant, &privacy, &candidate).await?;
            let record =
                super::signed_record::verify(&row, &signer.verifier(), &participant, &privacy)?
                    .ok_or(FactStoreError::Lifecycle)?;
            let provenance: serde_json::Value = ciborium::de::from_reader(
                row.try_get::<Vec<u8>, _>("canonical_provenance")?
                    .as_slice(),
            )
            .map_err(|_| FactStoreError::Lifecycle)?;
            if provenance["publicationDigest"]
                != digest_text(&event.source.inputs.published().publication_digest)
                || record.identity.chain_anchor.block_height != *block
                || record.identity.chain_anchor.block_hash
                    != format!("0x{}", &digest_text(hash)[7..])
                || record.completeness_scope.partition_id
                    != format!("urn:openpc:candidate-partition:{}", event.partition)
                || record.completeness_scope.range_start > event.end
                || record.completeness_scope.range_end < event.start
            {
                return Err(FactStoreError::Lifecycle);
            }
            let action = Uuid::now_v7();
            let effective:String=sqlx::query_scalar("select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')").fetch_one(&mut *tx).await?;
            let claims=ciborium::Value::serialized(&serde_json::json!({
                "schemaId":21004,"schemaVersion":pc_facts_core::FACT_SCHEMA_VERSION_V1,
                "schemaDigest":digest_text(&pc_facts_core::FACT_BRIDGE_SCHEMA_DIGEST_V1),"purpose":"openpc:fact-lineage-action:v1",
                "lineageActionId":action,"action":"INVALIDATE","targetFactId":record.identity.fact_id,
                "targetGeneration":record.identity.canonical_generation,"reasonCode":"CANONICAL_CHAIN_REORG",
                "effectiveAt":effective,"actorServiceId":crate::LOGICAL_SERVICE_ID,
                "authorityContextDigest":digest_text(&proof.authority_digest),"predecessorDigest":record.identity.local_fact_digest,
                "replacementFactId":null,"reorgReplacementOf":null,
                "evidenceRefs":[digest_text(&event.event.payload_digest),record.provenance_digest],
                "correlationId":event.correlation,"causationId":event.event.event_id,
                "participantId":record.identity.participant_id,"privacyDomainId":record.identity.privacy_domain_id,
                "affectedRange":{"partitionId":record.completeness_scope.partition_id,"rangeStart":event.start,"rangeEnd":event.end},
                "observedCanonicalThrough":proof.observed_through,
                "retainedTailBlocks":provenance["factAdmissionProfile"]["reorgRetainedTailBlocks"],
                "signingKeyId":signer.record_key_id()?,
            })).map_err(|_|FactStoreError::Lifecycle)?;
            let cose = signer.sign_lineage(&claims)?;
            if encode_pc_cbor(signer.verifier().verified_stored_claims(21004, &cose)?)?
                != encode_pc_cbor(claims)?
            {
                return Err(FactStoreError::Lifecycle);
            }
            let owned = [
                participant.clone(),
                privacy.clone(),
                candidate.clone(),
                event.partition.to_string(),
                event.event.generation_id.to_string(),
                event.event.event_id.to_string(),
                event.event.sequence.to_string(),
                action.to_string(),
                event.start.to_string(),
                event.end.to_string(),
            ];
            let signed = sha256(&cose);
            let fields: [&[u8]; 14] = [
                owned[0].as_bytes(),
                owned[1].as_bytes(),
                owned[2].as_bytes(),
                owned[3].as_bytes(),
                owned[4].as_bytes(),
                owned[5].as_bytes(),
                owned[6].as_bytes(),
                &event.event.payload_digest,
                owned[7].as_bytes(),
                &proof.authority_digest,
                &signed,
                owned[8].as_bytes(),
                owned[9].as_bytes(),
                b"REORG",
            ];
            let mut binding = Vec::new();
            for (index, field) in fields.iter().enumerate() {
                binding.extend_from_slice(&(index as u16 + 1).to_be_bytes());
                binding.push(1);
                binding.extend_from_slice(&(field.len() as u64).to_be_bytes());
                binding.extend_from_slice(field);
            }
            let cap = self.capabilities.lineage(&sha256(&binding));
            let applied:bool=sqlx::query_scalar("select facts.tombstone_for_source_reorg($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::numeric,$13::numeric,$14,$15)")
                .bind(&participant).bind(&privacy).bind(&candidate).bind(event.partition).bind(event.event.generation_id.to_string()).bind(event.event.event_id)
                .bind(i64::try_from(event.event.sequence).map_err(|_|FactStoreError::Feed)?).bind(&event.event.payload_digest).bind(action).bind(proof.authority_digest.as_slice()).bind(cose)
                .bind(event.start.to_string()).bind(event.end.to_string()).bind(cap.nonce.as_slice()).bind(cap.mac.as_slice()).fetch_one(&mut *tx).await?;
            changed += u64::from(applied);
        }
        proof
            .confirm()
            .await
            .map_err(|_| FactStoreError::Lifecycle)?;
        tx.commit().await?;
        Ok(changed)
    }
}
