//! Local immutable bindings shared by publication and policy reads. Admission
//! semantics are not reconstructed here and no external service is consulted.
use super::*;
use crate::signing::shard::digest_text;
use pc_facts_core::{FactRecord, encode_pc_cbor, fact_timestamp_from_ms, sha256};

pub(super) async fn load_generation(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
    generation: &str,
) -> Result<Vec<sqlx::postgres::PgRow>, FactStoreError> {
    let candidates: Vec<String> = sqlx::query_scalar("select candidate_id from facts.canonical_identity_allocation
        where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3 order by delta_sequence limit 1000001")
        .bind(participant).bind(privacy).bind(generation).fetch_all(&mut **tx).await?;
    if candidates.is_empty() || candidates.len() > 1_000_000 {
        return Err(FactStoreError::Lifecycle);
    }
    let mut records = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        records.push(load(tx, participant, privacy, &candidate).await?);
    }
    Ok(records)
}

pub(super) fn verify(
    row: &sqlx::postgres::PgRow,
    verifier: &FactSignatureVerifier,
    participant: &str,
    privacy: &str,
) -> Result<Option<FactRecord>, FactStoreError> {
    let cose: Vec<u8> = row.try_get("cose_sign1")?;
    let claims = match verifier.verified_stored_claims(
        u32::try_from(row.try_get::<i64, _>("schema_id")?).unwrap_or(0),
        &cose,
    ) {
        Ok(claims) => claims,
        Err(_) => return Ok(None),
    };
    let record = match FactRecord::from_cbor(&encode_pc_cbor(claims)?) {
        Ok(record) => record,
        Err(_) => return Ok(None),
    };
    let identity = &record.identity;
    let Some(fact_id) = row.try_get::<Option<uuid::Uuid>, _>("record_fact_id")? else {
        return Ok(None);
    };
    let payload: Vec<u8> = row.try_get("canonical_payload")?;
    let provenance: Vec<u8> = row.try_get("canonical_provenance")?;
    let anchor: Vec<u8> = row.try_get("finality_anchor")?;
    let provenance_value: ciborium::Value = match ciborium::de::from_reader(provenance.as_slice()) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let recorded_anchor = provenance_value
        .as_map()
        .and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_text() == Some("finalityAnchor"))
        })
        .and_then(|(_, v)| v.as_text());
    let bound = identity.fact_id == format!("urn:openpc:fact:{fact_id}")
        && identity.participant_id == format!("urn:openpc:participant:{participant}")
        && identity.privacy_domain_id.as_deref()
            == Some(format!("urn:openpc:privacy-domain:{privacy}").as_str())
        && Some(identity.fact_profile_id.as_str())
            == row.try_get::<Option<&str>, _>("record_profile_id")?
        && Some(identity.canonical_generation.to_string().as_str())
            == row.try_get::<Option<&str>, _>("record_generation")?
        && Some(record.delta_sequence.to_string().as_str())
            == row.try_get::<Option<&str>, _>("record_sequence")?
        && identity.local_fact_digest == digest_text(&row.try_get::<Vec<u8>, _>("fact_digest")?)
        && record.derivation_digest == digest_text(&sha256(&payload))
        && record.provenance_digest == digest_text(&sha256(&provenance))
        && record.provenance_digest
            == digest_text(&row.try_get::<Vec<u8>, _>("provenance_digest")?)
        && recorded_anchor == Some(&digest_text(&anchor)[7..])
        && record.not_before == fact_timestamp_from_ms(row.try_get("observed_at_ms")?)?
        && record.expires_at == fact_timestamp_from_ms(row.try_get("fresh_until_ms")?)?
        && identity.fact_schema_id
            == u32::try_from(row.try_get::<i64, _>("schema_id")?).unwrap_or(0)
        && identity.fact_schema_version == row.try_get::<String, _>("schema_version")?
        && identity.fact_schema_digest == digest_text(&row.try_get::<Vec<u8>, _>("schema_digest")?);
    Ok(bound.then_some(record))
}

pub(super) async fn load(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
    candidate: &str,
) -> Result<sqlx::postgres::PgRow, FactStoreError> {
    let row = sqlx::query("select f.*,f.state::text lifecycle_state,
            r.canonical_provenance,r.partition_id,r.candidate_sequence,r.source_generation_id,
            l.provenance_digest,a.fact_id record_fact_id,
            a.fact_profile_id record_profile_id,a.delta_sequence::text record_sequence,
            g.canonical_generation::text record_generation,
            f.fresh_until_ms>floor(extract(epoch from clock_timestamp())*1000)::bigint fresh,
            (select count(*) from facts.canonical_fact sibling where sibling.participant_id=f.participant_id
              and sibling.privacy_domain_id=f.privacy_domain_id and sibling.generation_id=f.generation_id) entry_count
            from facts.canonical_fact f join facts.candidate_feed_receipt r using(candidate_id,participant_id,privacy_domain_id)
            join facts.fact_lineage l using(candidate_id,participant_id,privacy_domain_id)
            join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
            join facts.canonical_generation g on g.participant_id=a.participant_id and g.privacy_domain_id=a.privacy_domain_id
              and g.fact_profile_id=a.fact_profile_id and g.generation_id=a.generation_id
            where f.participant_id=$1 and f.privacy_domain_id=$2 and f.candidate_id=$3")
            .bind(participant).bind(privacy).bind(candidate).fetch_one(&mut **tx).await?;
    Ok(row)
}
