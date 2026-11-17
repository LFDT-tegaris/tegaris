//! Immutable CloudEvent identity over the original admitted Fact. This is
//! producer custody only; no materialization call marks a consumer delivered.
use super::*;
use pc_facts_core::FactSubject;
use serde_json::{Value, json};
use uuid::Uuid;

#[cfg(test)]
pub(super) mod tests;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Material<'a> {
    participant_id: &'a str,
    privacy_domain_id: &'a str,
    candidate_id: &'a str,
    generation_id: String,
    fact_type: &'static str,
    event_id: Uuid,
    signed_fact_digest: String,
    source_profile_digest: String,
    source_payload_digest: String,
    authority_generation: String,
    occurred_at: String,
    correlation_id: &'a str,
}

fn digest(value: &Value, field: &str) -> Result<String, FactStoreError> {
    let text = value[field].as_str().ok_or(FactStoreError::Feed)?;
    let raw = text.strip_prefix("sha256:").unwrap_or(text);
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(FactStoreError::Feed);
    }
    Ok(format!("sha256:{raw}"))
}

impl FactStore {
    /// Resume populated upgrades through original signed admissions. This only
    /// creates missing immutable transport identities; it never marks delivery,
    /// renews readiness, re-observes a source or replaces a candidate.
    pub(crate) async fn materialize_pending_admissions(
        &self,
        participant: &str,
        privacy: &str,
        verifier: &FactSignatureVerifier,
    ) -> Result<bool, FactStoreError> {
        let mut selection = self.pool.begin().await?;
        set_context(&mut selection, participant, privacy).await?;
        sqlx::query("select set_config('statement_timeout','5000ms',true)")
            .execute(&mut *selection)
            .await?;
        let candidates:Vec<String>=sqlx::query_scalar("select f.candidate_id from facts.canonical_fact f
          join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
          join facts.outbox o using(candidate_id,participant_id,privacy_domain_id)
          left join facts.admission_delivery_event e using(candidate_id,participant_id,privacy_domain_id)
          where f.participant_id=$1 and f.privacy_domain_id=$2 and o.delivery_state='PENDING'
            and e.candidate_id is null order by f.admitted_at,f.candidate_id limit 128")
            .bind(participant).bind(privacy).fetch_all(&mut *selection).await?;
        selection.rollback().await?;
        for candidate in &candidates {
            let mut tx = self.pool.begin().await?;
            set_context(&mut tx, participant, privacy).await?;
            sqlx::query("select set_config('lock_timeout','2000ms',true),set_config('statement_timeout','5000ms',true)")
                .execute(&mut *tx).await?;
            self.record_admission_delivery(&mut tx, participant, privacy, candidate, verifier)
                .await?;
            tx.commit().await?;
        }
        Ok(candidates.len() < 128)
    }

    /// The caller holds the same transaction and scope fence as admission.
    /// Complete signed records are mandatory; legacy unsupported records stay
    /// pending and cannot acquire a fabricated canonical transport identity.
    pub(crate) async fn record_admission_delivery(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        participant: &str,
        privacy: &str,
        candidate: &str,
        verifier: &FactSignatureVerifier,
    ) -> Result<Value, FactStoreError> {
        let (material, data) =
            source_material(tx, participant, privacy, candidate, verifier).await?;
        let material = serde_json::to_vec(&material).map_err(|_| FactStoreError::Feed)?;
        let capability = self.capabilities.admission_delivery(&material, &data);
        let event: Value =
            sqlx::query_scalar("select facts.materialize_admission_delivery($1,$2,$3,$4)")
                .bind(material)
                .bind(data)
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut **tx)
                .await?;
        Ok(event)
    }
}

/// Derive producer and readback bindings through the same original signature
/// owner. Neither call renews freshness or claims a consumer acknowledgement.
async fn source_material<'a>(
    tx: &mut Transaction<'_, Postgres>,
    participant: &'a str,
    privacy: &'a str,
    candidate: &'a str,
    verifier: &FactSignatureVerifier,
) -> Result<(Material<'a>, Vec<u8>), FactStoreError> {
    for id in [participant, privacy, candidate] {
        if Uuid::parse_str(id)
            .map_err(|_| FactStoreError::Feed)?
            .get_version_num()
            != 7
        {
            return Err(FactStoreError::Feed);
        }
    }
    let stored = super::signed_record::load(tx, participant, privacy, candidate).await?;
    let record = super::signed_record::verify(&stored, verifier, participant, privacy)?
        .ok_or(FactStoreError::Lifecycle)?;
    let provenance: Value = ciborium::de::from_reader(
        stored
            .try_get::<Vec<u8>, _>("canonical_provenance")?
            .as_slice(),
    )
    .map_err(|_| FactStoreError::Feed)?;
    let event_id = Uuid::parse_str(
        record
            .identity
            .fact_id
            .strip_prefix("urn:openpc:fact:")
            .ok_or(FactStoreError::Feed)?,
    )
    .map_err(|_| FactStoreError::Feed)?;
    let occurred_at: String = sqlx::query_scalar("select to_char(admitted_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') from facts.retained_fact_identity where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3")
            .bind(participant).bind(privacy).bind(candidate).fetch_one(&mut **tx).await?;
    let material = Material {
        participant_id: participant,
        privacy_domain_id: privacy,
        candidate_id: candidate,
        generation_id: stored.try_get("generation_id")?,
        fact_type: match record.identity.typed_subject {
            FactSubject::ContractStateCall { .. } => "CONTRACT_STATE_CALL",
            FactSubject::Relationship { .. } => "RELATIONSHIP",
            FactSubject::ExternalDecision { .. } => "EXTERNAL_DECISION",
        },
        event_id,
        signed_fact_digest: crate::signing::shard::digest_text(&pc_facts_core::sha256(
            &stored.try_get::<Vec<u8>, _>("cose_sign1")?,
        )),
        source_profile_digest: digest(&provenance, "sourceProfileDigest")?,
        source_payload_digest: digest(&provenance, "sourcePayloadDigest")?,
        authority_generation: digest(&provenance, "configurationDigest")?,
        occurred_at,
        correlation_id: candidate,
    };
    let data = serde_json::to_vec(&json!({
        "candidateId":format!("urn:openpc:resource:{candidate}"),
        "factArtifactId":format!("urn:openpc:resource:{candidate}"),
        "artifactDigest":material.source_payload_digest,
        "sourceProfileDigest":material.source_profile_digest,
        "sourceNeutral":true,
    }))
    .map_err(|_| FactStoreError::Feed)?;
    Ok((material, data))
}

/// Read only the already committed event; never create one while reading custody.
/// The consumer receives the original producer ID, ordering and data digest.
pub(super) async fn read_verified(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
    candidate: &str,
    verifier: &FactSignatureVerifier,
) -> Result<Option<Value>, FactStoreError> {
    let row = sqlx::query("select source_material,source_material_digest,data_bytes,envelope,sequence,event_id,generation_id,fact_type from facts.admission_delivery_event where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3")
        .bind(participant).bind(privacy).bind(candidate).fetch_optional(&mut **tx).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let (material, data) = source_material(tx, participant, privacy, candidate, verifier).await?;
    let source = serde_json::to_vec(&material).map_err(|_| FactStoreError::Feed)?;
    let sequence: i64 = row.try_get("sequence")?;
    let event: Value = row.try_get("envelope")?;
    if sequence <= 0
        || row.try_get::<Vec<u8>, _>("source_material")? != source
        || row.try_get::<Vec<u8>, _>("source_material_digest")? != pc_facts_core::sha256(&source)
        || row.try_get::<Vec<u8>, _>("data_bytes")? != data
        || row.try_get::<Uuid, _>("event_id")? != material.event_id
        || row.try_get::<String, _>("generation_id")? != material.generation_id
        || row.try_get::<String, _>("fact_type")? != material.fact_type
    {
        return Err(FactStoreError::Feed);
    }
    let expected = json!({
        "specversion":"1.0", "id":material.event_id,
        "source":"urn:openpc:service:LS-FACT-BRIDGE",
        "type":"io.openpc.fact.candidate.admitted.v1",
        "subject":format!("urn:openpc:resource:{candidate}"),
        "time":material.occurred_at, "datacontenttype":"application/json",
        "dataschema":"https://schemas.openpc.local/event-payloads.schema.json#/$defs/FactCandidateAdmitted",
        "participantid":format!("urn:openpc:participant:{participant}"),
        "privacydomainid":format!("urn:openpc:privacy-domain:{privacy}"),
        "correlationid":material.correlation_id, "authoritygeneration":material.authority_generation,
        "sequence":sequence.to_string(),
        "datadigest":crate::signing::shard::digest_text(&pc_facts_core::sha256(&data)),
        "data":serde_json::from_slice::<Value>(&data).map_err(|_| FactStoreError::Feed)?
    });
    if event != expected {
        return Err(FactStoreError::Feed);
    }
    Ok(Some(event))
}
