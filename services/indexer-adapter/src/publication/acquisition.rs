//! Immutable inputs read by the candidate writer from the manager's publication.
//! This snapshot never substitutes current workload/policy/source authorization.
use super::*;

pub struct PublishedAcquisitionInputs {
    source: GovernedSourcePublication,
    published: PublishedSource,
    prepared: PreparedPublication,
}

impl PublishedAcquisitionInputs {
    /// Reconstruct the exact immutable publication and all referenced inputs.
    /// This proves byte/identity consistency only. In particular, material read
    /// by FactBridge remains untrusted until current authority and independent
    /// source observations have been verified by their respective owners.
    pub fn reconstruct(
        source: GovernedSourcePublication,
        published: PublishedSource,
        publication_cbor: &[u8],
    ) -> Result<Self, CandidateStoreError> {
        let prepared = source.prepare()?;
        if published.projection_generation_id.get_version_num() != 7
            || published.generation_digest != prepared.generation_digest
            || published.publication_digest != prepared.digest
            || publication_cbor != prepared.cbor
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        Ok(Self {
            source,
            published,
            prepared,
        })
    }

    pub fn source(&self) -> &GovernedSourcePublication {
        &self.source
    }
    pub fn published(&self) -> &PublishedSource {
        &self.published
    }
    pub fn profile(&self) -> &ClientIndexerProfileV1 {
        &self.prepared.profile
    }
    pub fn plan(&self) -> &ProjectionPlanV1 {
        &self.prepared.plan
    }
    pub fn finality_rule(&self) -> &FinalityRule {
        &self.prepared.finality
    }
    pub fn acquisition(&self) -> &AcquisitionConfiguration {
        &self.prepared.acquisition
    }
}

pub(crate) async fn load_acquisition_inputs(
    pool: &PgPool,
    binding: &CandidatePersistenceBinding,
) -> Result<PublishedAcquisitionInputs, CandidateStoreError> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-CANDIDATE_WRITE-V1',true)",
    )
    .bind(binding.participant_id())
    .bind(binding.privacy_domain_id())
    .bind(binding.operation_id())
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query(r#"
      select pub.source_revision,pub.qualification_operation_id,pub.projection_revision,
        pub.validation_operation_id,encode(pub.configuration_digest,'hex') as configuration_digest,
        pub.finality_rule_cbor,pub.acquisition_configuration_cbor,pub.publication_cbor,pub.publication_digest,
        g.generation_digest,g.source_profile_digest,g.projection_schema_digest,
        s.indexer_profile_id,s.source_profile_cbor,s.source_profile_digest as profile_digest,
        p.projection_plan_id,p.mapping_cbor,p.mapping_digest,p.schema_digest
      from candidate.source_publication pub
      join candidate.projection_generation g using(projection_generation_id,participant_id,privacy_domain_id)
      join candidate.projection_profile p using(projection_profile_id,participant_id,privacy_domain_id)
      join candidate.source_profile s using(source_profile_id,participant_id,privacy_domain_id)
      where pub.projection_generation_id=$1 and pub.state='PUBLISHED'
        and g.state in ('READY','ACTIVE') and s.state='QUALIFIED' and p.state='QUALIFIED'
      for share of g
    "#).bind(binding.projection_generation_id()).fetch_optional(&mut *tx).await?
        .ok_or(CandidateStoreError::InvalidBinding)?;
    let publication_cbor: Vec<u8> = row.try_get("publication_cbor")?;
    let publication: serde_json::Value = ciborium::de::from_reader(publication_cbor.as_slice())
        .map_err(|_| CandidateStoreError::InvalidBinding)?;
    let action = publication
        .get("actionIntentId")
        .and_then(serde_json::Value::as_str)
        .ok_or(CandidateStoreError::InvalidBinding)?;
    let source = GovernedSourcePublication {
        participant_id: binding.participant_id(),
        privacy_domain_id: binding.privacy_domain_id(),
        indexer_profile_id: row.try_get("indexer_profile_id")?,
        source_revision: row.try_get("source_revision")?,
        qualification_operation_id: row.try_get("qualification_operation_id")?,
        projection_plan_id: row.try_get("projection_plan_id")?,
        projection_revision: row.try_get("projection_revision")?,
        validation_operation_id: row.try_get("validation_operation_id")?,
        action_intent_id: action.into(),
        configuration_digest: format!(
            "sha256:{}",
            row.try_get::<String, _>("configuration_digest")?
        ),
        profile_cbor: row.try_get("source_profile_cbor")?,
        plan_cbor: row.try_get("mapping_cbor")?,
        finality_rule_cbor: row.try_get("finality_rule_cbor")?,
        acquisition_configuration_cbor: row.try_get("acquisition_configuration_cbor")?,
    };
    let prepared = source.prepare()?;
    for (column, expected) in [
        ("publication_digest", &prepared.digest),
        ("generation_digest", &prepared.generation_digest),
        ("source_profile_digest", &prepared.profile_digest),
        ("profile_digest", &prepared.profile_digest),
        ("mapping_digest", &prepared.plan_digest),
        ("projection_schema_digest", &prepared.schema_digest),
        ("schema_digest", &prepared.schema_digest),
    ] {
        if row.try_get::<Vec<u8>, _>(column)? != *expected {
            return Err(CandidateStoreError::InvalidBinding);
        }
    }
    if publication_cbor != prepared.cbor {
        return Err(CandidateStoreError::InvalidBinding);
    }
    let published = PublishedSource {
        projection_generation_id: binding.projection_generation_id(),
        generation_digest: prepared.generation_digest.clone(),
        publication_digest: prepared.digest.clone(),
    };
    tx.commit().await?;
    Ok(PublishedAcquisitionInputs {
        source,
        published,
        prepared,
    })
}
