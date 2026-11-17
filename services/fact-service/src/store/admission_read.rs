//! Durable admission effect readback. A receipt does not establish current
//! source authority, freshness, verified shard readiness or policy eligibility.
use super::*;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FactAdmissionReadback {
    pub candidate_id: String,
    pub partition_id: Uuid,
    pub candidate_sequence: String,
    pub event_id: Uuid,
    pub source_profile_id: String,
    pub source_generation_id: String,
    pub generation_id: String,
    pub fact_digest: String,
    pub receipt_digest: String,
    pub state: String,
    pub occurrence_digest: Option<String>,
    pub occurrence_state: String,
    pub observed_at_ms: i64,
    pub fresh_until_ms: i64,
    pub committed_at: String,
    pub authority: &'static str,
}

impl FactStore {
    pub async fn admission_readback(
        &self,
        participant: Uuid,
        privacy: Uuid,
        candidate: Uuid,
    ) -> Result<Option<FactAdmissionReadback>, FactStoreError> {
        let mut tx = self.pool.begin().await?;
        set_context(&mut tx, &participant.to_string(), &privacy.to_string()).await?;
        let row = sqlx::query("select f.candidate_id,r.partition_id,r.candidate_sequence::text,r.event_id,
            r.source_profile_id,r.source_generation_id,f.generation_id,
            encode(f.fact_digest,'hex') fact_digest,encode(r.receipt_digest,'hex') receipt_digest,
            case when retired.candidate_id is not null then 'RETIRED' else live.state::text end state,
            f.observed_at_ms,f.fresh_until_ms,
            encode(s.occurrence_digest,'hex') occurrence_digest,
            case when c.conflict_id is not null then 'CONFLICTING'
              when s.candidate_id is null then 'UNTRACKED' else 'CONSISTENT' end occurrence_state,
            to_char(r.committed_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') committed_at
            from facts.candidate_feed_receipt r join facts.retained_fact_identity f
              on f.candidate_id=r.candidate_id and f.participant_id=r.participant_id
              and f.privacy_domain_id=r.privacy_domain_id
            left join facts.canonical_fact live on live.candidate_id=f.candidate_id
              and live.participant_id=f.participant_id and live.privacy_domain_id=f.privacy_domain_id
            left join facts.retired_fact_payload retired on retired.candidate_id=f.candidate_id
              and retired.participant_id=f.participant_id and retired.privacy_domain_id=f.privacy_domain_id
            left join facts.semantic_occurrence s on s.candidate_id=f.candidate_id
              and s.participant_id=f.participant_id and s.privacy_domain_id=f.privacy_domain_id
            left join facts.occurrence_conflict c on c.participant_id=s.participant_id
              and c.privacy_domain_id=s.privacy_domain_id and c.occurrence_digest=s.occurrence_digest
            where r.participant_id=$1 and r.privacy_domain_id=$2 and r.candidate_id=$3")
            .bind(participant.to_string()).bind(privacy.to_string()).bind(candidate.to_string())
            .fetch_optional(&mut *tx).await?;
        let result = row
            .map(|row| -> Result<_, sqlx::Error> {
                Ok(FactAdmissionReadback {
                    candidate_id: row.try_get("candidate_id")?,
                    partition_id: row.try_get("partition_id")?,
                    candidate_sequence: row.try_get("candidate_sequence")?,
                    event_id: row.try_get("event_id")?,
                    source_profile_id: row.try_get("source_profile_id")?,
                    source_generation_id: row.try_get("source_generation_id")?,
                    generation_id: row.try_get("generation_id")?,
                    fact_digest: format!("sha256:{}", row.try_get::<String, _>("fact_digest")?),
                    receipt_digest: format!(
                        "sha256:{}",
                        row.try_get::<String, _>("receipt_digest")?
                    ),
                    state: row.try_get("state")?,
                    occurrence_digest: row
                        .try_get::<Option<String>, _>("occurrence_digest")?
                        .map(|value| format!("sha256:{value}")),
                    occurrence_state: row.try_get("occurrence_state")?,
                    observed_at_ms: row.try_get("observed_at_ms")?,
                    fresh_until_ms: row.try_get("fresh_until_ms")?,
                    committed_at: row.try_get("committed_at")?,
                    authority: "HISTORICAL_RECEIPT_ONLY",
                })
            })
            .transpose()?;
        tx.commit().await?;
        Ok(result)
    }
}
