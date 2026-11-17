//! Original target Fact custody. Preparation is a verified description, not a
//! lease or readiness grant. Control sources must be locked before reacquisition.
use super::*;
use pc_policy_core::semantics::{FactReference, validate_fact_references};
use pc_runtime_types::Digest;
use uuid::Uuid;

/// No public constructor, deserializer or clone: callers cannot supply verified
/// provenance or turn a saved read into current publication authority.
pub struct PreparedTargetFacts {
    pub(crate) participant: String,
    pub(crate) privacy: String,
    pub(crate) records: Vec<RetainedFactRecord>,
    pub(crate) valid_until_ns: u64,
    shard: VerifiedShard,
    required: Vec<FactReference>,
    dependency_digest: Digest,
    original_records_digest: Digest,
}
impl PreparedTargetFacts {
    pub fn participant_id(&self) -> &str {
        &self.participant
    }
    pub fn privacy_domain_id(&self) -> &str {
        &self.privacy
    }
    /// An upper bound only. It never renews an original Fact's signed expiry.
    pub fn valid_until_ns(&self) -> u64 {
        self.valid_until_ns
    }
    /// Immutable evidence commitments only; neither getter establishes liveness.
    pub fn dependency_digest(&self) -> &Digest {
        &self.dependency_digest
    }
    pub fn original_records_digest(&self) -> &Digest {
        &self.original_records_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedFactSource {
    pub(crate) source_profile: Uuid,
    pub(crate) plan: Uuid,
    pub(crate) source_revision: i64,
    pub(crate) projection_revision: i64,
    pub(crate) qualification: Uuid,
    pub(crate) validation: Uuid,
    pub(crate) configuration: Digest,
    pub(crate) profile: Digest,
    pub(crate) mapping: Digest,
    pub(crate) publication: Digest,
    pub(crate) source_generation: Uuid,
    pub(crate) partition: Uuid,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedFactRecord {
    pub(crate) candidate: String,
    pub(crate) fact_id: String,
    pub(crate) fact_digest: Vec<u8>,
    pub(crate) signed_digest: Digest,
    pub(crate) provenance_digest: Digest,
    pub(crate) observed_at_ms: i64,
    pub(crate) fresh_until_ms: i64,
    pub(crate) source: RetainedFactSource,
}

pub(crate) struct TargetFactCustody {
    lease: PolicyFactLease,
    valid_until_ns: u64,
}
impl TargetFactCustody {
    pub(crate) async fn revalidate(&mut self) -> Result<(), FactStoreError> {
        self.lease.revalidate().await?;
        require_time(&mut self.lease, self.valid_until_ns).await
    }
    pub(crate) async fn release(self) -> Result<(), FactStoreError> {
        self.lease.release().await
    }
    pub(crate) async fn revalidate_until(&mut self, until: u64) -> Result<(), FactStoreError> {
        self.revalidate().await?;
        require_time(&mut self.lease, until.min(self.valid_until_ns)).await
    }
}

impl PolicyFactReader {
    /// Read exact original rows under the existing mutation fence, then release
    /// it before any Control source lock. References and shard are selectors;
    /// the database's verified rows establish their current binding.
    pub async fn prepare_target_custody(
        &self,
        shard: &VerifiedShard,
        required: &[FactReference],
        capsule_valid_until_ns: u64,
        maximum_wait_ms: u64,
    ) -> Result<PreparedTargetFacts, FactStoreError> {
        validate_inputs(shard, required, capsule_valid_until_ns, maximum_wait_ms)?;
        tokio::time::timeout(std::time::Duration::from_millis(maximum_wait_ms), async {
            let mut lease = self.target_lease(shard, required, maximum_wait_ms).await?;
            let records = self.target_records(&mut lease, shard, required).await?;
            let valid_until_ns = original_deadline(capsule_valid_until_ns, &records)?;
            let (dependency_digest, original_records_digest) =
                original_commitments(shard, required, &records)?;
            lease.revalidate().await?;
            require_time(&mut lease, valid_until_ns).await?;
            lease.release().await?;
            Ok(PreparedTargetFacts {
                participant: shard.participant_id().into(),
                privacy: shard.privacy_domain_id().into(),
                records,
                valid_until_ns,
                shard: shard.clone(),
                required: required.to_vec(),
                dependency_digest,
                original_records_digest,
            })
        })
        .await
        .map_err(|_| FactStoreError::Lifecycle)?
    }

    /// Only the Control-source guard invokes this after taking its locks. A
    /// changed original, expired read, disconnected lease or retirement denies.
    pub(crate) async fn retain_prepared_target(
        &self,
        prepared: &PreparedTargetFacts,
        maximum_wait_ms: u64,
    ) -> Result<TargetFactCustody, FactStoreError> {
        validate_inputs(
            &prepared.shard,
            &prepared.required,
            prepared.valid_until_ns,
            maximum_wait_ms,
        )?;
        tokio::time::timeout(std::time::Duration::from_millis(maximum_wait_ms), async {
            let mut lease = self
                .target_lease(&prepared.shard, &prepared.required, maximum_wait_ms)
                .await?;
            let actual = self
                .target_records(&mut lease, &prepared.shard, &prepared.required)
                .await?;
            if actual != prepared.records {
                return Err(FactStoreError::Lifecycle);
            }
            let mut custody = TargetFactCustody {
                lease,
                valid_until_ns: prepared.valid_until_ns,
            };
            custody.revalidate().await?;
            Ok(custody)
        })
        .await
        .map_err(|_| FactStoreError::Lifecycle)?
    }

    async fn target_lease(
        &self,
        shard: &VerifiedShard,
        required: &[FactReference],
        budget: u64,
    ) -> Result<PolicyFactLease, FactStoreError> {
        let candidates = required
            .iter()
            .map(|fact| fact.candidate_id.clone())
            .collect::<Vec<_>>();
        let mut lease = self
            .lease_many(
                shard.participant_id(),
                shard.privacy_domain_id(),
                &candidates,
                budget,
            )
            .await?
            .ok_or(FactStoreError::Lifecycle)?;
        let safe: bool = sqlx::query_scalar("select current_database()='openpc_facts' and current_setting('transaction_read_only')='on' and pg_has_role(current_user,'openpc_policy_fact_reader','MEMBER') and not rolsuper and not rolbypassrls from pg_roles where rolname=current_user")
            .fetch_one(&mut *lease.transaction).await?;
        if !safe {
            return Err(FactStoreError::Lifecycle);
        }
        lease.revalidate().await?;
        match_snapshots(shard, required, lease.snapshots())?;
        Ok(lease)
    }

    async fn target_records(
        &self,
        lease: &mut PolicyFactLease,
        shard: &VerifiedShard,
        required: &[FactReference],
    ) -> Result<Vec<RetainedFactRecord>, FactStoreError> {
        match_snapshots(shard, required, lease.snapshots())?;
        let mut records = Vec::with_capacity(required.len());
        for (index, reference) in required.iter().enumerate() {
            let row = super::super::signed_record::load(
                &mut lease.transaction,
                shard.participant_id(),
                shard.privacy_domain_id(),
                &reference.candidate_id,
            )
            .await?;
            let record = super::super::signed_record::verify(
                &row,
                &self.verifier,
                shard.participant_id(),
                shard.privacy_domain_id(),
            )?
            .ok_or(FactStoreError::Lifecycle)?;
            let provenance: Vec<u8> = row.try_get("canonical_provenance")?;
            let source_profile: String = sqlx::query_scalar("select source_profile_id from facts.admission_inbox where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3 and generation_id=$4")
                .bind(shard.participant_id()).bind(shard.privacy_domain_id()).bind(&reference.candidate_id).bind(&reference.generation_id)
                .fetch_one(&mut *lease.transaction).await?;
            let source = parse_source(
                &provenance,
                &reference.candidate_id,
                &source_profile,
                row.try_get("source_generation_id")?,
                row.try_get("partition_id")?,
            )?;
            let snapshot = &lease.snapshots()[index];
            let fact_digest: Vec<u8> = row.try_get("fact_digest")?;
            let observed_at_ms: i64 = row.try_get("observed_at_ms")?;
            let fresh_until_ms: i64 = row.try_get("fresh_until_ms")?;
            if fact_digest != snapshot.fact_digest
                || observed_at_ms != snapshot.observed_at_ms
                || fresh_until_ms != snapshot.fresh_until_ms
                || row.try_get::<String, _>("lifecycle_state")? != "FINALIZED"
            {
                return Err(FactStoreError::Lifecycle);
            }
            records.push(RetainedFactRecord {
                candidate: reference.candidate_id.clone(),
                fact_id: record.identity.fact_id,
                fact_digest,
                signed_digest: Digest::of(row.try_get::<Vec<u8>, _>("cose_sign1")?),
                provenance_digest: Digest::of(&provenance),
                observed_at_ms,
                fresh_until_ms,
                source,
            });
        }
        Ok(records)
    }
}

/// Both preimages are canonical JSON arrays, with domain, participant, privacy,
/// generation, bare lowercase shard digest, then a candidate-ID-sorted array.
/// Timestamps/revisions use canonical decimal strings (no JSON rounding).
fn original_commitments(
    shard: &VerifiedShard,
    required: &[FactReference],
    records: &[RetainedFactRecord],
) -> Result<(Digest, Digest), FactStoreError> {
    use serde_json::json;
    validate_fact_references(required).map_err(|_| FactStoreError::Lifecycle)?;
    let required: BTreeMap<_, _> = required
        .iter()
        .map(|value| (&value.candidate_id, value))
        .collect();
    let ordered: BTreeMap<_, _> = records
        .iter()
        .map(|record| (&record.candidate, record))
        .collect();
    if records.len() != ordered.len()
        || ordered.len() != required.len()
        || ordered.keys().ne(required.keys())
    {
        return Err(FactStoreError::Lifecycle);
    }
    let hex = |value: &[u8]| {
        value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let record_values = ordered.values().map(|record| {
        let source = &record.source;
        json!({
            "candidateId":record.candidate,"factId":record.fact_id,"factDigest":hex(&record.fact_digest),
            "signedDigest":record.signed_digest,"provenanceDigest":record.provenance_digest,
            "observedAtMs":record.observed_at_ms.to_string(),"freshUntilMs":record.fresh_until_ms.to_string(),
            "source":{"sourceProfileId":source.source_profile,"projectionPlanId":source.plan,
                "sourceRevision":source.source_revision.to_string(),"projectionRevision":source.projection_revision.to_string(),
                "qualificationOperationId":source.qualification,"validationOperationId":source.validation,
                "configurationDigest":source.configuration,"sourceProfileDigest":source.profile,"mappingManifestDigest":source.mapping,
                "publicationDigest":source.publication,"sourceGenerationId":source.source_generation,"partitionId":source.partition}
        })
    }).collect::<Vec<_>>();
    let commit = |domain, values: serde_json::Value| {
        let bytes = pc_runtime_types::canonical_bytes(&json!([
            domain,
            shard.participant_id(),
            shard.privacy_domain_id(),
            shard.generation_id(),
            hex(shard.shard_digest()),
            values
        ]))
        .map_err(|_| FactStoreError::Lifecycle)?;
        if bytes.len() > 1_048_576 {
            return Err(FactStoreError::Lifecycle);
        }
        Ok(Digest::of(bytes))
    };
    Ok((
        commit(
            "openpc:target-fact-dependencies:v1",
            json!(required.into_values().collect::<Vec<_>>()),
        )?,
        commit(
            "openpc:target-fact-original-records:v1",
            json!(record_values),
        )?,
    ))
}

fn validate_inputs(
    shard: &VerifiedShard,
    required: &[FactReference],
    deadline: u64,
    budget: u64,
) -> Result<(), FactStoreError> {
    validate_fact_references(required).map_err(|_| FactStoreError::Lifecycle)?;
    for id in [
        shard.participant_id(),
        shard.privacy_domain_id(),
        shard.generation_id(),
    ]
    .into_iter()
    .chain(
        required
            .iter()
            .flat_map(|fact| [fact.candidate_id.as_str(), fact.generation_id.as_str()]),
    ) {
        canonical_uuid(id)?;
    }
    if deadline == 0
        || !(1..=5000).contains(&budget)
        || required
            .iter()
            .any(|fact| fact.generation_id != shard.generation_id())
    {
        return Err(FactStoreError::Lifecycle);
    }
    Ok(())
}
fn match_snapshots(
    shard: &VerifiedShard,
    required: &[FactReference],
    snapshots: &[PolicyFactSnapshot],
) -> Result<(), FactStoreError> {
    if required.len() != snapshots.len() || required.is_empty() {
        return Err(FactStoreError::Lifecycle);
    }
    for (reference, snapshot) in required.iter().zip(snapshots) {
        let digest = reference
            .parsed_digest()
            .map_err(|_| FactStoreError::Lifecycle)?;
        if snapshot.outcome != FactQueryOutcome::Present
            || snapshot.participant_id != shard.participant_id()
            || snapshot.privacy_domain_id != shard.privacy_domain_id()
            || snapshot.candidate_id != reference.candidate_id
            || snapshot.generation_id != reference.generation_id
            || snapshot.generation_id != shard.generation_id()
            || snapshot.shard_digest.as_deref() != Some(shard.shard_digest().as_slice())
            || Digest::parse(
                snapshot
                    .fact_digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
            .ok()
            .as_ref()
                != Some(&digest)
            || snapshot.observed_at_ms < 0
            || snapshot.snapshot_at_ms < snapshot.observed_at_ms
            || snapshot.snapshot_at_ms >= snapshot.fresh_until_ms
        {
            return Err(FactStoreError::Lifecycle);
        }
    }
    Ok(())
}
async fn require_time(lease: &mut PolicyFactLease, until: u64) -> Result<(), FactStoreError> {
    let now: String =
        sqlx::query_scalar("select floor(extract(epoch from clock_timestamp())*1000000000)::text")
            .fetch_one(&mut *lease.transaction)
            .await?;
    if now.parse::<u64>().map_err(|_| FactStoreError::Lifecycle)? >= until {
        return Err(FactStoreError::Lifecycle);
    }
    Ok(())
}
fn canonical_uuid(value: &str) -> Result<Uuid, FactStoreError> {
    let id = Uuid::parse_str(value).map_err(|_| FactStoreError::Lifecycle)?;
    if id.get_version_num() != 7 || id.to_string() != value {
        return Err(FactStoreError::Lifecycle);
    }
    Ok(id)
}
fn original_deadline(
    capsule_until: u64,
    records: &[RetainedFactRecord],
) -> Result<u64, FactStoreError> {
    if capsule_until == 0 || records.is_empty() {
        return Err(FactStoreError::Lifecycle);
    }
    records.iter().try_fold(capsule_until, |until, record| {
        let expiry = u64::try_from(record.fresh_until_ms)
            .ok()
            .and_then(|value| value.checked_mul(1_000_000))
            .ok_or(FactStoreError::Lifecycle)?;
        if record.observed_at_ms < 0 || record.fresh_until_ms <= record.observed_at_ms {
            return Err(FactStoreError::Lifecycle);
        }
        Ok(until.min(expiry))
    })
}
fn parse_source(
    bytes: &[u8],
    candidate: &str,
    source_profile: &str,
    generation: &str,
    partition: Uuid,
) -> Result<RetainedFactSource, FactStoreError> {
    if bytes.is_empty()
        || bytes.len() > 1_048_576
        || pc_facts_core::validate_pc_cbor(bytes).is_err()
    {
        return Err(FactStoreError::Lifecycle);
    }
    let value: serde_json::Value =
        ciborium::de::from_reader(bytes).map_err(|_| FactStoreError::Lifecycle)?;
    let text = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(FactStoreError::Lifecycle)
    };
    let digest = |key: &str, prefixed: bool| {
        let value = text(key)?;
        let payload = if prefixed {
            value
                .strip_prefix("sha256:")
                .ok_or(FactStoreError::Lifecycle)?
        } else {
            value
        };
        let digest = Digest::parse(payload).map_err(|_| FactStoreError::Lifecycle)?;
        if digest.as_str() != payload {
            return Err(FactStoreError::Lifecycle);
        }
        Ok(digest)
    };
    let revision = |key: &str| {
        let value = text(key)?;
        let parsed = value
            .parse::<i64>()
            .map_err(|_| FactStoreError::Lifecycle)?;
        if parsed <= 0 || parsed.to_string() != value {
            return Err(FactStoreError::Lifecycle);
        }
        Ok(parsed)
    };
    let profile = canonical_uuid(source_profile)?;
    if text("purpose")? != "openpc:independent-state-admission:v1"
        || text("sourceCandidateId")? != candidate
        || canonical_uuid(text("sourceProfileId")?)? != profile
        || partition.get_version_num() != 7
    {
        return Err(FactStoreError::Lifecycle);
    }
    Ok(RetainedFactSource {
        source_profile: profile,
        plan: canonical_uuid(text("projectionPlanId")?)?,
        source_revision: revision("sourceRevision")?,
        projection_revision: revision("projectionRevision")?,
        qualification: canonical_uuid(text("qualificationOperationId")?)?,
        validation: canonical_uuid(text("validationOperationId")?)?,
        configuration: digest("configurationDigest", true)?,
        profile: digest("sourceProfileDigest", false)?,
        mapping: digest("mappingManifestDigest", false)?,
        publication: digest("publicationDigest", true)?,
        source_generation: canonical_uuid(generation)?,
        partition,
    })
}

#[cfg(test)]
#[path = "target_custody/tests.rs"]
mod tests;
