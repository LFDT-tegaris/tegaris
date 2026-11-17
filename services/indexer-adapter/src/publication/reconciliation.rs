//! Remove-only reconciliation against the complete locked Control snapshot.
//! Candidate currentness is not fact authority or acquisition permission.
use super::*;

pub(super) async fn lock_scope(
    tx: &mut Transaction<'_, Postgres>,
    participant: Uuid,
    privacy: Uuid,
) -> Result<(), CandidateStoreError> {
    // Serialize first publication and removal as well as existing generations.
    // A hash collision only adds contention, never cross-scope visibility.
    sqlx::query("select pg_advisory_xact_lock(hashtextextended('openpc:candidate-publication:' || $1::text || ':' || $2::text,0))")
        .bind(participant).bind(privacy).execute(&mut **tx).await?;
    Ok(())
}

impl CandidatePublicationStore {
    /// Fence every published tuple absent from the manager's complete current
    /// Control snapshot for this scope, before publishing any replacement.
    /// The caller must hold the current Control owners across this commit.
    /// Empty current input deliberately fences all published tuples in scope.
    /// No historical bytes, candidate rows or signed fact generations change.
    pub async fn fence_obsolete(
        &self,
        participant_id: Uuid,
        privacy_domain_id: Uuid,
        operation_id: Uuid,
        current: &[&GovernedSourcePublication],
    ) -> Result<Vec<Uuid>, CandidateStoreError> {
        if [participant_id, privacy_domain_id, operation_id]
            .iter()
            .any(|id| id.get_version_num() != 7)
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        // Validate the entire snapshot before changing anything. Foreign or
        // malformed inputs cannot make an incomplete snapshot look complete.
        let mut digests = std::collections::BTreeSet::new();
        for input in current {
            if input.participant_id != participant_id
                || input.privacy_domain_id != privacy_domain_id
                || !digests.insert(input.prepare()?.digest)
            {
                return Err(CandidateStoreError::InvalidBinding);
            }
        }
        let digests: Vec<Vec<u8>> = digests.into_iter().collect();
        let mut tx = self.pool.begin().await?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-CANDIDATE_WRITE-V1',true)")
            .bind(participant_id).bind(privacy_domain_id).bind(operation_id)
            .execute(&mut *tx).await?;
        lock_scope(&mut tx, participant_id, privacy_domain_id).await?;
        // Generation locks also serialize with candidate writes. Once this
        // commit returns, the old generation cannot advance its checkpoint.
        let obsolete: Vec<Uuid> = sqlx::query_scalar(r#"
            select g.projection_generation_id from candidate.projection_generation g
            join candidate.source_publication p using(projection_generation_id,participant_id,privacy_domain_id)
            where g.participant_id=$1 and g.privacy_domain_id=$2
              and p.state='PUBLISHED' and not (p.publication_digest=any($3::bytea[]))
            order by g.projection_generation_id for update of g
        "#).bind(participant_id).bind(privacy_domain_id).bind(&digests)
            .fetch_all(&mut *tx).await?;
        sqlx::query("update candidate.projection_generation set state='STALE' where projection_generation_id=any($1::uuid[]) and state in ('CREATED','BACKFILLING','SHADOW','READY','ACTIVE')")
            .bind(&obsolete).execute(&mut *tx).await?;
        sqlx::query("update candidate.source_publication set state='FENCED' where projection_generation_id=any($1::uuid[]) and state='PUBLISHED'")
            .bind(&obsolete).execute(&mut *tx).await?;
        emit_pending_fences(&mut tx, participant_id, privacy_domain_id, operation_id).await?;
        tx.commit().await?;
        Ok(obsolete)
    }
}

/// Includes pre-upgrade fences as newly observed withdrawal occurrences. It
/// never invents their historical event time or rewrites publication bytes.
pub(super) async fn emit_pending_fences(
    tx: &mut Transaction<'_, Postgres>,
    participant: Uuid,
    privacy: Uuid,
    operation: Uuid,
) -> Result<(), CandidateStoreError> {
    let rows = sqlx::query("select part.candidate_partition_id,pub.projection_generation_id,pub.publication_digest
        from candidate.source_publication pub join candidate.candidate_partition part
          using(participant_id,privacy_domain_id,projection_generation_id)
        where pub.participant_id=$1 and pub.privacy_domain_id=$2 and pub.state in ('FENCED','RETIRED')
          and not exists(select 1 from candidate.outbox_event event where event.participant_id=pub.participant_id
            and event.privacy_domain_id=pub.privacy_domain_id and event.aggregate_type='candidate-partition'
            and event.aggregate_id=part.candidate_partition_id and event.event_type='io.openpc.indexer.projection.source.fenced.v1')
        order by pub.projection_generation_id,part.candidate_partition_id")
        .bind(participant).bind(privacy).fetch_all(&mut **tx).await?;
    for row in rows {
        let partition: Uuid = sqlx::Row::try_get(&row, "candidate_partition_id")?;
        let generation: Uuid = sqlx::Row::try_get(&row, "projection_generation_id")?;
        let digest: Vec<u8> = sqlx::Row::try_get(&row, "publication_digest")?;
        let payload = serde_json::json!({
            "candidatePartitionId":format!("urn:openpc:candidate-partition:{partition}"),
            "projectionGenerationId":format!("urn:openpc:projection-generation:{generation}"),
            "publicationDigest":format!("sha256:{}",digest.iter().map(|b|format!("{b:02x}")).collect::<String>()),
            "reasonCode":"GOVERNED_SOURCE_NOT_CURRENT","authority":"CANDIDATE_ONLY",
        });
        let _: Uuid =
            sqlx::query_scalar("select candidate.emit_source_fence($1,$2,$3,$4,$5,$6,$7)")
                .bind(participant)
                .bind(privacy)
                .bind(partition)
                .bind(generation)
                .bind(operation)
                .bind(canonical_cbor(&payload))
                .bind(payload)
                .fetch_one(&mut **tx)
                .await?;
    }
    Ok(())
}
