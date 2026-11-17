//! Current source custody for an original target's Facts. Control locks belong
//! to the disposition owner's existing transaction; no second Control snapshot,
//! new observation, authority renewal, signing or publication happens here.
use super::*;
use crate::PolicyFactReader;
use crate::store::policy_read::target_custody::{
    PreparedTargetFacts, RetainedFactSource, TargetFactCustody,
};
use std::collections::{BTreeMap, BTreeSet};

/// Preparation releases its Fact transaction before these Control locks are
/// taken. This guard alone has no Fact lease and grants no readiness.
pub struct RetainedFactSources<'a, 'connection> {
    transaction: &'a mut Transaction<'connection, Postgres>,
    prepared: &'a PreparedTargetFacts,
    transaction_id: String,
    valid_until_ns: u64,
}

/// Two live database fences, not an atomic cross-store publication. The caller
/// must retain this guard through its native proof/signing/Control commit path,
/// revalidate at that boundary and fence every loss or ambiguous result UNKNOWN.
/// It must still establish the original capsule/target/disposition and all
/// other authority through their owners. No method signs or clears a target.
pub struct RetainedTargetFactLease<'a, 'connection> {
    sources: RetainedFactSources<'a, 'connection>,
    facts: TargetFactCustody,
}

/// Keeps the actual Fact fence alive while the caller consumes its Control
/// transaction in commit. This is not a commit receipt or publication grant.
pub struct RetainedFactCommitFence {
    facts: TargetFactCustody,
    valid_until_ns: u64,
}
impl RetainedFactCommitFence {
    pub async fn revalidate(&mut self) -> Result<()> {
        self.facts
            .revalidate_until(self.valid_until_ns)
            .await
            .map_err(|_| SourceAuthorityError::Binding)
    }
    pub async fn release(self) -> Result<()> {
        self.facts
            .release()
            .await
            .map_err(|_| SourceAuthorityError::Binding)
    }
}

/// Caller must already have the Fact-source request context on its existing
/// Control transaction and the established root-lock order. This function does
/// not install context, grant roles, start a transaction, or commit one. Errors
/// require the caller to roll back; partial locks are not successful custody.
pub async fn lock_sources_in<'a, 'connection>(
    transaction: &'a mut Transaction<'connection, Postgres>,
    prepared: &'a PreparedTargetFacts,
    maximum_wait_ms: u64,
) -> Result<RetainedFactSources<'a, 'connection>> {
    if !(1..=5000).contains(&maximum_wait_ms) {
        return Err(SourceAuthorityError::Binding);
    }
    let sources = source_set(prepared)?;
    let (transaction_id, valid_until_ns) =
        tokio::time::timeout(Duration::from_millis(maximum_wait_ms), async {
            let transaction_id = control_identity(transaction, prepared, None).await?;
            let action: String = sqlx::query_scalar("select openpc.current_action_intent_id()")
                .fetch_one(&mut **transaction)
                .await?;
            if action != "ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1" {
                return Err(SourceAuthorityError::Identity);
            }
            let mut valid_until_ns = prepared.valid_until_ns;
            // Deterministic order inside the established Participant/module fence.
            for source in sources.values() {
                sqlx::query("select openpc.lock_fact_candidate_source($1)")
                    .bind(source.plan)
                    .execute(&mut **transaction)
                    .await?;
                let rows = control_source::load(
                    transaction,
                    &prepared.participant,
                    &prepared.privacy,
                    Some(&source.plan.to_string()),
                    false,
                )
                .await
                .map_err(|_| SourceAuthorityError::Binding)?;
                let [row] = rows.as_slice() else {
                    return Err(SourceAuthorityError::Binding);
                };
                let current = CurrentSource::read(row)?;
                current.matches(source)?;
                valid_until_ns = lock_providers(
                    transaction,
                    prepared,
                    source,
                    &current,
                    row.try_get("configuration_cbor")?,
                    valid_until_ns,
                )
                .await?;
            }
            require_control_time(transaction, valid_until_ns).await?;
            Ok::<_, SourceAuthorityError>((transaction_id, valid_until_ns))
        })
        .await
        .map_err(|_| SourceAuthorityError::Expired)??;
    Ok(RetainedFactSources {
        transaction,
        prepared,
        transaction_id,
        valid_until_ns,
    })
}

impl<'a, 'connection> RetainedFactSources<'a, 'connection> {
    /// Current source locks only; the native issuer must finish all other
    /// Control source reads before acquiring the separate Fact transaction.
    pub fn transaction(&mut self) -> &mut Transaction<'connection, Postgres> {
        self.transaction
    }
    pub fn valid_until_ns(&self) -> u64 {
        self.valid_until_ns
    }
    /// Reconciliation may retain a stricter deadline from its original native
    /// attestation. It can never use that historical proof to extend custody.
    pub fn shorten_to(&mut self, until: u64) -> Result<()> {
        self.valid_until_ns = shortened_deadline(self.valid_until_ns, until)?;
        Ok(())
    }
    /// Reacquire the original Fact fence only after all current Control source
    /// locks. A changed row or any non-Present result rejects the whole set.
    pub async fn acquire(
        mut self,
        reader: &PolicyFactReader,
        maximum_wait_ms: u64,
    ) -> Result<RetainedTargetFactLease<'a, 'connection>> {
        self.revalidate().await?;
        let facts = reader
            .retain_prepared_target(self.prepared, maximum_wait_ms)
            .await
            .map_err(|_| SourceAuthorityError::Binding)?;
        let mut lease = RetainedTargetFactLease {
            sources: self,
            facts,
        };
        lease.revalidate().await?;
        Ok(lease)
    }
    async fn revalidate(&mut self) -> Result<()> {
        control_identity(self.transaction, self.prepared, Some(&self.transaction_id)).await?;
        require_control_time(self.transaction, self.valid_until_ns).await
    }
}
impl<'connection> RetainedTargetFactLease<'_, 'connection> {
    pub fn valid_until_ns(&self) -> u64 {
        self.sources.valid_until_ns
    }
    /// Borrow the SAME transaction for the canonical native issuer. Restoring
    /// its request action is that owner's responsibility; scope and transaction
    /// identity must not change. This does not make two databases atomic.
    pub fn transaction(&mut self) -> &mut Transaction<'connection, Postgres> {
        self.sources.transaction
    }
    pub async fn revalidate(&mut self) -> Result<()> {
        self.sources.revalidate().await?;
        self.facts
            .revalidate()
            .await
            .map_err(|_| SourceAuthorityError::Binding)?;
        require_control_time(self.sources.transaction, self.sources.valid_until_ns).await
    }
    /// Final same-transaction check before the caller commits Control. Return
    /// the live Fact fence separately so SQLx can consume the caller's Control
    /// transaction without releasing Facts first. Commit/connection ambiguity,
    /// expiry or post-commit revalidation failure remains UNKNOWN at the issuer.
    pub async fn into_commit_fence(mut self) -> Result<RetainedFactCommitFence> {
        self.revalidate().await?;
        Ok(RetainedFactCommitFence {
            facts: self.facts,
            valid_until_ns: self.sources.valid_until_ns,
        })
    }
    /// Release only the Fact transaction; the caller owns Control commit/abort.
    pub async fn release(self) -> Result<()> {
        self.facts
            .release()
            .await
            .map_err(|_| SourceAuthorityError::Binding)
    }
}

fn source_set(prepared: &PreparedTargetFacts) -> Result<BTreeMap<Uuid, &RetainedFactSource>> {
    let mut sources = BTreeMap::new();
    if prepared.records.is_empty() || prepared.records.len() > 256 {
        return Err(SourceAuthorityError::Binding);
    }
    for record in &prepared.records {
        if let Some(prior) = sources.insert(record.source.plan, &record.source) {
            // A single source can feed different candidate partitions and
            // generations. Those immutable identities remain in Fact rereads;
            // current Control authority must agree on the original publication.
            require_same_source(prior, &record.source)?;
        }
    }
    Ok(sources)
}
fn require_same_source(a: &RetainedFactSource, b: &RetainedFactSource) -> Result<()> {
    if a.source_profile != b.source_profile
        || a.plan != b.plan
        || a.source_revision != b.source_revision
        || a.projection_revision != b.projection_revision
        || a.qualification != b.qualification
        || a.validation != b.validation
        || a.configuration != b.configuration
        || a.profile != b.profile
        || a.mapping != b.mapping
        || a.publication != b.publication
    {
        return Err(SourceAuthorityError::Binding);
    }
    Ok(())
}

struct CurrentSource {
    indexer: Uuid,
    plan: Uuid,
    source_revision: i64,
    projection_revision: i64,
    qualification: Uuid,
    validation: Uuid,
    profile: Digest,
    mapping: Digest,
    validation_configuration: Digest,
    active_configuration: Digest,
}
impl CurrentSource {
    fn read(row: &sqlx::postgres::PgRow) -> Result<Self> {
        let id = |column| -> Result<Uuid> {
            let value: &str = row.try_get(column)?;
            let id = Uuid::parse_str(value).map_err(|_| SourceAuthorityError::Binding)?;
            if id.get_version_num() != 7 || id.to_string() != value {
                return Err(SourceAuthorityError::Binding);
            }
            Ok(id)
        };
        Ok(Self {
            indexer: id("indexer_profile_id")?,
            plan: id("projection_plan_id")?,
            source_revision: row.try_get("source_revision")?,
            projection_revision: row.try_get("projection_revision")?,
            qualification: id("qualification_operation_id")?,
            validation: id("validation_operation_id")?,
            profile: digest(row.try_get("method_profile_digest")?)?,
            mapping: digest(row.try_get("plan_digest")?)?,
            validation_configuration: digest(row.try_get("configuration_digest")?)?,
            active_configuration: digest(row.try_get("active_configuration_digest")?)?,
        })
    }
    fn matches(&self, original: &RetainedFactSource) -> Result<()> {
        // source_profile identifies the candidate-store source, not this
        // Control indexer. Derive the indexer only through the locked plan.
        if self.plan != original.plan
            || self.source_revision != original.source_revision
            || self.projection_revision != original.projection_revision
            || self.qualification != original.qualification
            || self.validation != original.validation
            || self.profile != original.profile
            || self.mapping != original.mapping
            || self.validation_configuration != original.configuration
            || self.active_configuration != original.configuration
        {
            return Err(SourceAuthorityError::Binding);
        }
        Ok(())
    }
}

async fn lock_providers(
    tx: &mut Transaction<'_, Postgres>,
    prepared: &PreparedTargetFacts,
    source: &RetainedFactSource,
    current: &CurrentSource,
    bytes: Vec<u8>,
    until: u64,
) -> Result<u64> {
    let active = &current.active_configuration;
    let configuration = decode_active_invocation_configuration(&bytes, active)
        .map_err(|_| SourceAuthorityError::Binding)?;
    let artifact = |id: Uuid, kind, expected: &Digest| {
        load_active_configuration_artifact(&bytes, active, &id.to_string(), kind, expected)
            .map_err(|_| SourceAuthorityError::Binding)
    };
    let profile_bytes = artifact(
        current.indexer,
        ConfigurationArtifactKind::ClientIndexerProfile,
        &source.profile,
    )?;
    let profile = openpc_indexer_adapter::admit_scoped_client_indexer_profile(
        &profile_bytes,
        &format!("sha256:{}", source.profile.as_str()),
        &prepared.participant,
        &prepared.privacy,
    )
    .map_err(|_| SourceAuthorityError::Binding)?;
    if profile.workload_binding
        != active_invocation_workload(&bytes, active, &prepared.participant, &prepared.privacy)
            .map_err(|_| SourceAuthorityError::Binding)?
    {
        return Err(SourceAuthorityError::Binding);
    }
    let plan_bytes = artifact(
        source.plan,
        ConfigurationArtifactKind::ProjectionPlan,
        &source.mapping,
    )?;
    openpc_indexer_adapter::validate_projection_admission(
        &profile_bytes,
        &plan_bytes,
        &format!("sha256:{}", source.mapping.as_str()),
    )
    .map_err(|_| SourceAuthorityError::Binding)?;
    let rule_bytes = artifact(
        current.indexer,
        ConfigurationArtifactKind::IndexerFinalityRule,
        &digest(&profile.finality_rule_digest)?,
    )?;
    let rule = openpc_indexer_adapter::FinalityRule::resolve(&profile, &rule_bytes)
        .map_err(|_| SourceAuthorityError::Binding)?;
    let acquisition = artifact(
        current.indexer,
        ConfigurationArtifactKind::IndexerAcquisitionConfiguration,
        &digest(&profile.configuration_digest)?,
    )?;
    openpc_indexer_adapter::AcquisitionConfiguration::resolve(&profile, &acquisition)
        .map_err(|_| SourceAuthorityError::Binding)?;
    let mut identities = BTreeSet::new();
    let mut expiries = Vec::new();
    for expected in &rule.canonical_provider_digests {
        let expected_digest = digest(expected)?;
        let mut matches = configuration.resource_artifacts.iter().filter(|artifact| {
            artifact.artifact_kind == ConfigurationArtifactKind::ProviderProfile
                && artifact.artifact_digest == expected_digest
        });
        let provider = matches.next().ok_or(SourceAuthorityError::Binding)?;
        if matches.next().is_some() || !identities.insert(&provider.artifact_id) {
            return Err(SourceAuthorityError::Binding);
        }
        let qualified =
            openpc_multi_rpc::qualify_provider_profile(&provider.payload_cbor, expected)
                .map_err(|_| SourceAuthorityError::Binding)?;
        if qualified.chain_id != profile.chain_id
            || qualified.network_id != profile.network_id
            || digest(&qualified.genesis_hash)? != digest(&profile.genesis_hash)?
        {
            return Err(SourceAuthorityError::Binding);
        }
        let expiry: Option<i64> =
            sqlx::query_scalar("select openpc.lock_indexer_qualified_provider($1::text::uuid,$2)")
                .bind(&provider.artifact_id)
                .bind(expected)
                .fetch_one(&mut **tx)
                .await?;
        if let Some(expiry) = expiry {
            expiries.push(expiry);
        }
    }
    qualified_deadline(until, usize::from(rule.required_observations), &expiries)
}
fn qualified_deadline(original_until: u64, required: usize, expiries: &[i64]) -> Result<u64> {
    if original_until == 0 || required == 0 || expiries.len() < required {
        return Err(SourceAuthorityError::Binding);
    }
    expiries.iter().try_fold(original_until, |until, expiry| {
        Ok(until.min(
            u64::try_from(*expiry)
                .ok()
                .filter(|v| *v > 0)
                .ok_or(SourceAuthorityError::Expired)?,
        ))
    })
}
fn shortened_deadline(current: u64, original: u64) -> Result<u64> {
    if original == 0 || original > current {
        return Err(SourceAuthorityError::Expired);
    }
    Ok(original)
}
async fn control_identity(
    tx: &mut Transaction<'_, Postgres>,
    prepared: &PreparedTargetFacts,
    expected: Option<&str>,
) -> Result<String> {
    let row = sqlx::query("select current_database()='openpc_control' and current_setting('transaction_isolation')='read committed' and current_setting('transaction_read_only')='off' and not rolsuper and not rolbypassrls and openpc.current_participant_id()::text=$1 and openpc.current_privacy_domain_id()::text=$2 as safe, pg_current_xact_id()::text as transaction_id from pg_roles where rolname=current_user")
        .bind(&prepared.participant).bind(&prepared.privacy).fetch_one(&mut **tx).await?;
    let id: String = row.try_get("transaction_id")?;
    if row.try_get::<Option<bool>, _>("safe")? != Some(true)
        || expected.is_some_and(|expected| expected != id)
    {
        return Err(SourceAuthorityError::Identity);
    }
    Ok(id)
}
async fn require_control_time(tx: &mut Transaction<'_, Postgres>, until: u64) -> Result<()> {
    let now: String =
        sqlx::query_scalar("select floor(extract(epoch from clock_timestamp())*1000000000)::text")
            .fetch_one(&mut **tx)
            .await?;
    if now
        .parse::<u64>()
        .map_err(|_| SourceAuthorityError::Expired)?
        >= until
    {
        return Err(SourceAuthorityError::Expired);
    }
    Ok(())
}

#[cfg(test)]
#[path = "retained/tests.rs"]
mod tests;
