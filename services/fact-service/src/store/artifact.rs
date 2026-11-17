//! Frozen FactArtifact projections from local admission, invalidation and
//! signed-readiness owners. Protected fact reads never contact a source.
use super::*;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FactArtifact {
    pub fact_artifact_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub artifact_digest: String,
    pub authority_generation: String,
    pub state: String,
    pub source_neutral: bool,
    pub revision: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactPageRequest {
    pub limit: u16,
    pub filter: Option<ArtifactFilter>,
    pub sort: String,
    pub snapshot_at: String,
    pub snapshot_revision: String,
    pub after: Option<ArtifactPagePosition>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFilter {
    pub field: String,
    pub operator: String,
    pub value: String,
}
#[derive(serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactPagePosition {
    pub updated_at: String,
    pub id: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactPage {
    pub items: Vec<FactArtifact>,
    pub next: Option<ArtifactPagePosition>,
    pub total: String,
    pub snapshot_revision: String,
}

const PROJECTION: &str = r#"with projected as (
 select f.candidate_id,r.candidate_sequence::text revision,r.canonical_provenance,
   f.admitted_at created_at,
   greatest(f.admitted_at,f.finalized_at,i.invalidated_at,replacement.finalized_at,
     case when f.fresh_until_ms <= floor(extract(epoch from statement_timestamp())*1000)::bigint
       then to_timestamp(f.fresh_until_ms::double precision/1000) else null end) updated_at,
   case when f.state in ('RETIRED','SUPERSEDED') then 'INVALIDATED'
     when f.state='REORG_TOMBSTONED' or g.state='REORG' then 'REORG'
     when exists(select 1 from facts.semantic_occurrence s join facts.occurrence_conflict c
       using(participant_id,privacy_domain_id,occurrence_digest) where s.candidate_id=f.candidate_id)
       or g.state='FAILED' then 'QUARANTINED'
     when f.state='FINALIZED' and g.state='READY' and g.shard_verified
       and f.fresh_until_ms>floor(extract(epoch from statement_timestamp())*1000)::bigint
       and f.observed_at_ms<=floor(extract(epoch from statement_timestamp())*1000)::bigint then 'ADMITTED'
     else 'STALE' end state, false physical_retired
 from facts.canonical_fact f join facts.candidate_feed_receipt r
   on r.candidate_id=f.candidate_id and r.participant_id=f.participant_id and r.privacy_domain_id=f.privacy_domain_id
 join facts.readiness_gate g on g.participant_id=f.participant_id and g.privacy_domain_id=f.privacy_domain_id and g.generation_id=f.generation_id
 left join facts.fact_invalidation i on i.candidate_id=f.candidate_id and i.participant_id=f.participant_id and i.privacy_domain_id=f.privacy_domain_id
 left join facts.canonical_fact replacement on replacement.candidate_id=i.replacement_candidate_id
   and replacement.participant_id=f.participant_id and replacement.privacy_domain_id=f.privacy_domain_id
 where f.participant_id=$1 and f.privacy_domain_id=$2
 union all
 select f.candidate_id,r.candidate_sequence::text,r.canonical_provenance,f.admitted_at,
   to_timestamp(a.completed_at_ms::double precision/1000),'INVALIDATED',true
 from facts.retained_fact_identity f
 join facts.retired_fact_payload retired using(candidate_id,participant_id,privacy_domain_id)
 join facts.store_retirement_attempt a using(participant_id,privacy_domain_id,attempt_id,outcome_digest)
 join facts.candidate_feed_receipt r using(candidate_id,participant_id,privacy_domain_id)
 where f.participant_id=$1 and f.privacy_domain_id=$2 and a.state='APPLIED'
), filtered as (select * from projected where ($3::text is null
 or case $4 when 'eq' then case $3 when 'state' then state else 'urn:openpc:resource:'||candidate_id end=$5
   when 'ne' then case $3 when 'state' then state else 'urn:openpc:resource:'||candidate_id end<>$5
   when 'prefix' then starts_with(case $3 when 'state' then state else 'urn:openpc:resource:'||candidate_id end,$5)
   else false end)) "#;

impl FactStore {
    pub async fn artifact_page(
        &self,
        participant: &str,
        privacy: &str,
        request: &ArtifactPageRequest,
        verifier: &FactSignatureVerifier,
    ) -> Result<ArtifactPage, FactStoreError> {
        if request.limit == 0
            || request.limit > 200
            || !matches!(request.sort.as_str(), "updatedAt" | "-updatedAt")
            || request.filter.as_ref().is_some_and(|f| {
                !matches!(f.field.as_str(), "state" | "factArtifactId")
                    || !matches!(f.operator.as_str(), "eq" | "ne" | "prefix")
                    || f.value.is_empty()
                    || f.value.len() > 256
            })
        {
            return Err(FactStoreError::Feed);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("set transaction isolation level repeatable read read only")
            .execute(&mut *tx)
            .await?;
        set_context(&mut tx, participant, privacy).await?;
        let mut count_query = sqlx::QueryBuilder::<Postgres>::new(PROJECTION);
        count_query.push(
            " select (select count(*)::text from filtered) total,
          exists(select 1 from projected where updated_at>$6::timestamptz) changed",
        );
        let counts = count_query
            .build()
            .bind(participant)
            .bind(privacy)
            .bind(request.filter.as_ref().map(|v| v.field.as_str()))
            .bind(request.filter.as_ref().map(|v| v.operator.as_str()))
            .bind(request.filter.as_ref().map(|v| v.value.as_str()))
            .bind(&request.snapshot_at)
            .fetch_one(&mut *tx)
            .await?;
        if request.after.is_some() && counts.try_get::<bool, _>("changed")? {
            return Err(FactStoreError::SequenceRace);
        }
        let direction = if request.sort.starts_with('-') {
            "desc"
        } else {
            "asc"
        };
        let comparison = if direction == "desc" { "<" } else { ">" };
        let mut query = sqlx::QueryBuilder::<Postgres>::new(PROJECTION);
        query.push(" select *, to_char(created_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') created,
          to_char(updated_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') updated
          from filtered where ($6::text is null or (updated_at,candidate_id) ");
        query
            .push(comparison)
            .push(" ($6::timestamptz,$7)) order by updated_at ")
            .push(direction)
            .push(",candidate_id ")
            .push(direction)
            .push(" limit $8");
        let rows = query
            .build()
            .bind(participant)
            .bind(privacy)
            .bind(request.filter.as_ref().map(|v| v.field.as_str()))
            .bind(request.filter.as_ref().map(|v| v.operator.as_str()))
            .bind(request.filter.as_ref().map(|v| v.value.as_str()))
            .bind(request.after.as_ref().map(|v| v.updated_at.as_str()))
            .bind(request.after.as_ref().map(|v| v.id.as_str()))
            .bind(i64::from(request.limit) + 1)
            .fetch_all(&mut *tx)
            .await?;
        let more = rows.len() > usize::from(request.limit);
        let mut items = Vec::new();
        let reader = PolicyFactReader::new(self.pool.clone(), verifier.clone());
        for row in rows.iter().take(usize::from(request.limit)) {
            let candidate: String = row.try_get("candidate_id")?;
            let state: String = row.try_get("state")?;
            if row.try_get::<bool, _>("physical_retired")? {
                super::retirement::verify_retired_identity(
                    &mut tx,
                    verifier,
                    participant,
                    privacy,
                    &candidate,
                )
                .await?;
                if state != "INVALIDATED" {
                    return Err(FactStoreError::Lifecycle);
                }
            } else {
                let snapshot = reader
                    .read_in(&mut tx, participant, privacy, &candidate)
                    .await?
                    .ok_or(FactStoreError::Lifecycle)?;
                if (state == "ADMITTED")
                    != (snapshot.outcome == pc_facts_core::FactQueryOutcome::Present)
                {
                    return Err(FactStoreError::Lifecycle);
                }
            }
            let provenance: serde_json::Value = ciborium::de::from_reader(
                row.try_get::<Vec<u8>, _>("canonical_provenance")?
                    .as_slice(),
            )
            .map_err(|_| FactStoreError::Feed)?;
            let digest = |field| -> Result<String, FactStoreError> {
                let value = provenance
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .ok_or(FactStoreError::Feed)?;
                let value = value.strip_prefix("sha256:").unwrap_or(value);
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                {
                    return Err(FactStoreError::Feed);
                }
                Ok(format!("sha256:{value}"))
            };
            items.push(FactArtifact {
                fact_artifact_id: format!("urn:openpc:resource:{candidate}"),
                participant_id: format!("urn:openpc:participant:{participant}"),
                privacy_domain_id: format!("urn:openpc:privacy-domain:{privacy}"),
                artifact_digest: digest("sourcePayloadDigest")?,
                authority_generation: digest("configurationDigest")?,
                state,
                source_neutral: true,
                revision: row.try_get("revision")?,
                created_at: row.try_get("created")?,
                updated_at: row.try_get("updated")?,
            });
        }
        let next = if more {
            items.last().map(|v| ArtifactPagePosition {
                updated_at: v.updated_at.clone(),
                id: v.fact_artifact_id.rsplit(':').next().unwrap().into(),
            })
        } else {
            None
        };
        tx.commit().await?;
        Ok(ArtifactPage {
            items,
            next,
            total: counts.try_get("total")?,
            snapshot_revision: request.snapshot_revision.clone(),
        })
    }
}
