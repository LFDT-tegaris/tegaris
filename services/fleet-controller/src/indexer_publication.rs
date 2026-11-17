//! Reconcile publicly qualified sources into the non-authoritative candidate
//! store. Current Control owners stay locked across the idempotent publication;
//! a lost observation is recovered by replaying the same committed identities.
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use openpc_indexer_adapter::{
    AcquisitionConfiguration, CandidatePublicationStore, CandidateStoreError, FinalityRule,
    GovernedSourcePublication, admit_scoped_client_indexer_profile,
};
use pc_policy_core::invocation::{
    ActiveInvocationConfigurationV1, ConfigurationArtifactKind, active_invocation_workload,
    decode_active_invocation_configuration, load_active_configuration_artifact,
};
use pc_runtime_types::Digest;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

pub(crate) mod source_current;
#[cfg(test)]
mod tests;

pub struct IndexerPublicationWorker {
    store: CandidatePublicationStore,
    next_poll: Instant,
}

pub(crate) struct CurrentPublication {
    pub(crate) input: GovernedSourcePublication,
    pub(crate) configuration: ActiveInvocationConfigurationV1,
    pub(crate) rule: FinalityRule,
    pub(crate) target_id: String,
}

impl IndexerPublicationWorker {
    pub async fn from_environment() -> Result<Option<Self>, String> {
        let Some(path) = std::env::var_os("OPENPC_INDEXER_MANAGER_DATABASE_URL_FILE") else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err("indexer manager secret path rejected".into());
        }
        let url =
            std::fs::read_to_string(path).map_err(|_| "indexer manager secret unavailable")?;
        if url.len() > 4096 {
            return Err("indexer manager secret oversized".into());
        }
        let store = CandidatePublicationStore::connect(url.trim())
            .await
            .map_err(|_| "indexer manager database identity rejected")?;
        Ok(Some(Self {
            store,
            next_poll: Instant::now(),
        }))
    }

    pub async fn tick(
        &mut self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
    ) -> Result<(), String> {
        if Instant::now() < self.next_poll {
            return Ok(());
        }
        self.next_poll = Instant::now() + Duration::from_secs(2);
        let Some(mut tx) = begin_publication_observation(pool, participant, privacy).await? else {
            // Another lifecycle transaction owns this scope. Leave all candidate
            // state untouched and retry the ordinary tick after its poll delay.
            return Ok(());
        };
        let rows = source_current::load(&mut tx, participant, privacy, None, true).await?;
        let mut current_publications = Vec::new();
        for row in rows {
            let Some(current) = prepare(&row, participant, privacy)? else {
                continue;
            };
            let target: Option<String> = sqlx::query_scalar("select runtime_target_id::text from control.runtime_target where runtime_target_id=$1::text::uuid and participant_id=$2::text::uuid and privacy_domain_id=$3::text::uuid for share")
                .bind(&current.target_id).bind(participant).bind(privacy).fetch_optional(&mut *tx).await
                .map_err(|_| "indexer target scope unavailable")?;
            if target.is_none()
                || !validate_providers(&mut tx, &current.configuration, &current.rule).await?
            {
                // Expired qualification prevents publication while the same
                // worker remains available to complete fresh qualification.
                continue;
            }
            current_publications.push(current);
        }
        // Complete the remove-only pass before adding any replacement. A
        // crash between commits leaves candidates fenced; retry never revives
        // an old generation or edits its historical publication bytes.
        let current_inputs: Vec<_> = current_publications.iter().map(|v| &v.input).collect();
        confirm_publication_observation(&mut tx).await?;
        self.store
            .fence_obsolete(
                uuid(participant)?,
                uuid(privacy)?,
                Uuid::now_v7(),
                &current_inputs,
            )
            .await
            .map_err(|_| "obsolete candidate source fence unavailable")?;
        for current in current_publications {
            // A failed Control connection must not start another candidate
            // operation using the earlier source read. Already committed native
            // effects remain original effects and require normal reconciliation.
            confirm_publication_observation(&mut tx).await?;
            match self.store.publish(&current.input).await {
                Ok(_) | Err(CandidateStoreError::InvalidBinding) => {}
                // A fenced or already-bound generation requires a governed
                // replacement. It must not stop unrelated public operations.
                Err(_) => return Err("candidate source publication unavailable".into()),
            }
        }
        tx.commit()
            .await
            .map_err(|_| "indexer publication observation failed".into())
    }
}

/// Match the lifecycle/runtime-input owner: the scoped module fence precedes
/// source/configuration row reads. The live Control transaction retains it
/// across native commits; connection loss is not cross-store atomicity.
/// A busy lifecycle writer defers this tick before even remove-only work. This
/// is scheduling contention, not publication success or a lifecycle predicate.
async fn begin_publication_observation(
    pool: &PgPool,
    participant: &str,
    privacy: &str,
) -> Result<Option<Transaction<'static, Postgres>>, String> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "indexer publication transaction unavailable")?;
    // The connection's default must not pin a pre-fence MVCC snapshot when the
    // context setter runs. Read source owners afresh after the fence is acquired.
    sqlx::query("set transaction isolation level read committed")
        .execute(&mut *tx)
        .await
        .map_err(|_| "indexer publication isolation unavailable")?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CANDIDATE_WRITE-V1',true)")
        .bind(participant).bind(privacy).execute(&mut *tx).await
        .map_err(|_| "indexer publication context rejected")?;
    sqlx::query("select openpc.assert_request_context(true)")
        .execute(&mut *tx)
        .await
        .map_err(|_| "indexer publication context rejected")?;
    // Use the resolved UUID scope, not unnormalized caller text, for exactly
    // the same key as the module writer's exclusive transaction fence.
    let acquired: bool = sqlx::query_scalar("select pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))")
        .fetch_one(&mut *tx).await
        .map_err(|_| "indexer publication module fence unavailable")?;
    if !acquired {
        tx.rollback()
            .await
            .map_err(|_| "indexer publication rollback unavailable")?;
        return Ok(None);
    }
    // The current-input view also takes the participant's evidence lifecycle
    // fence. Admit it before reading sources or starting any candidate effect;
    // an ordinary conflict must defer this poll, not terminate the scheduler.
    let lifecycle: bool = sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0))")
        .fetch_one(&mut *tx).await
        .map_err(|_| "indexer publication lifecycle fence unavailable")?;
    if !lifecycle {
        tx.rollback()
            .await
            .map_err(|_| "indexer publication rollback unavailable")?;
        return Ok(None);
    }
    Ok(Some(tx))
}

async fn confirm_publication_observation(tx: &mut Transaction<'_, Postgres>) -> Result<(), String> {
    sqlx::query("select 1")
        .execute(&mut **tx)
        .await
        .map_err(|_| "indexer publication observation lost".to_owned())?;
    Ok(())
}

pub(crate) fn prepare(
    row: &PgRow,
    participant: &str,
    privacy: &str,
) -> Result<Option<CurrentPublication>, String> {
    let bytes: Vec<u8> = row
        .try_get("configuration_cbor")
        .map_err(|_| "indexer configuration missing")?;
    let digest = parse_digest(
        row.try_get("active_configuration_digest")
            .map_err(|_| "indexer configuration digest missing")?,
    )?;
    let configuration = decode_active_invocation_configuration(&bytes, &digest)
        .map_err(|_| "indexer configuration rejected")?;
    let source_id: String = row
        .try_get("indexer_profile_id")
        .map_err(|_| "indexer resource missing")?;
    // Legacy structural qualification has no acquisition inputs. It remains
    // unusable for acquisition; it is not retroactively relabeled as proof.
    if ![
        ConfigurationArtifactKind::IndexerFinalityRule,
        ConfigurationArtifactKind::IndexerAcquisitionConfiguration,
    ]
    .iter()
    .all(|kind| {
        configuration
            .resource_artifacts
            .iter()
            .any(|artifact| artifact.artifact_id == source_id && artifact.artifact_kind == *kind)
    }) {
        return Ok(None);
    }
    let source_digest: String = row
        .try_get("method_profile_digest")
        .map_err(|_| "indexer digest missing")?;
    let profile_cbor = load_active_configuration_artifact(
        &bytes,
        &digest,
        &source_id,
        ConfigurationArtifactKind::ClientIndexerProfile,
        &parse_digest(&source_digest)?,
    )
    .map_err(|_| "current indexer artifact rejected")?;
    let profile =
        admit_scoped_client_indexer_profile(&profile_cbor, &source_digest, participant, privacy)
            .map_err(|_| "current indexer scope rejected")?;
    let workload = active_invocation_workload(&bytes, &digest, participant, privacy)
        .map_err(|_| "current indexer workload unavailable")?;
    if profile.workload_binding != workload {
        return Err("current indexer workload rejected".into());
    }
    let finality_rule_cbor = load_active_configuration_artifact(
        &bytes,
        &digest,
        &source_id,
        ConfigurationArtifactKind::IndexerFinalityRule,
        &parse_digest(&profile.finality_rule_digest)?,
    )
    .map_err(|_| "current indexer finality configuration rejected")?;
    let rule = FinalityRule::resolve(&profile, &finality_rule_cbor)
        .map_err(|_| "current indexer finality rule rejected")?;
    for expected in &rule.canonical_provider_digests {
        let artifact = configuration
            .resource_artifacts
            .iter()
            .find(|artifact| {
                artifact.artifact_kind == ConfigurationArtifactKind::ProviderProfile
                    && format!("sha256:{}", artifact.artifact_digest.as_str()) == *expected
            })
            .ok_or("canonical finality provider missing")?;
        let provider = openpc_multi_rpc::qualify_provider_profile(&artifact.payload_cbor, expected)
            .map_err(|_| "canonical finality provider rejected")?;
        if provider.chain_id != profile.chain_id
            || provider.network_id != profile.network_id
            || provider.genesis_hash.trim_start_matches("0x")
                != profile.genesis_hash.trim_start_matches("0x")
        {
            return Err("canonical finality provider chain mismatch".into());
        }
    }
    let acquisition_configuration_cbor = load_active_configuration_artifact(
        &bytes,
        &digest,
        &source_id,
        ConfigurationArtifactKind::IndexerAcquisitionConfiguration,
        &parse_digest(&profile.configuration_digest)?,
    )
    .map_err(|_| "current indexer acquisition configuration rejected")?;
    let acquisition = AcquisitionConfiguration::resolve(&profile, &acquisition_configuration_cbor)
        .map_err(|_| "current indexer acquisition input rejected")?;
    let projection_id: String = row
        .try_get("projection_plan_id")
        .map_err(|_| "projection resource missing")?;
    let plan_digest: String = row
        .try_get("plan_digest")
        .map_err(|_| "projection digest missing")?;
    let plan_cbor = load_active_configuration_artifact(
        &bytes,
        &digest,
        &projection_id,
        ConfigurationArtifactKind::ProjectionPlan,
        &parse_digest(&plan_digest)?,
    )
    .map_err(|_| "current projection artifact rejected")?;
    let receipt: Value = row
        .try_get("result_receipt")
        .map_err(|_| "projection receipt missing")?;
    let qualified: Value = row
        .try_get("qualification_receipt")
        .map_err(|_| "qualification receipt missing")?;
    for (receipt, key, expected) in [
        (&receipt, "artifactCbor", &plan_cbor),
        (&receipt, "profileArtifactCbor", &profile_cbor),
        (&qualified, "artifactCbor", &profile_cbor),
    ] {
        let actual: Vec<u8> = serde_json::from_value(
            receipt
                .get(key)
                .cloned()
                .ok_or("source receipt bytes missing")?,
        )
        .map_err(|_| "source receipt bytes invalid")?;
        if actual != *expected {
            return Err("source receipt bytes substituted".into());
        }
    }
    let input = GovernedSourcePublication {
        participant_id: uuid(participant)?,
        privacy_domain_id: uuid(privacy)?,
        indexer_profile_id: uuid(&source_id)?,
        projection_plan_id: uuid(&projection_id)?,
        source_revision: row
            .try_get("source_revision")
            .map_err(|_| "source revision missing")?,
        projection_revision: row
            .try_get("projection_revision")
            .map_err(|_| "projection revision missing")?,
        qualification_operation_id: uuid(
            row.try_get("qualification_operation_id")
                .map_err(|_| "qualification identity missing")?,
        )?,
        validation_operation_id: uuid(
            row.try_get("validation_operation_id")
                .map_err(|_| "validation identity missing")?,
        )?,
        action_intent_id: "ACT-CANDIDATE_WRITE-V1".into(),
        configuration_digest: format!(
            "sha256:{}",
            parse_digest(
                row.try_get("configuration_digest")
                    .map_err(|_| "validation configuration missing")?
            )?
            .as_str()
        ),
        profile_cbor,
        plan_cbor,
        finality_rule_cbor,
        acquisition_configuration_cbor,
    };
    Ok(Some(CurrentPublication {
        input,
        configuration,
        rule,
        target_id: acquisition.runtime_target_id,
    }))
}

async fn validate_providers(
    tx: &mut Transaction<'_, Postgres>,
    configuration: &ActiveInvocationConfigurationV1,
    rule: &FinalityRule,
) -> Result<bool, String> {
    let mut qualified = 0;
    for expected in &rule.canonical_provider_digests {
        let provider = configuration
            .resource_artifacts
            .iter()
            .find(|artifact| {
                artifact.artifact_kind == ConfigurationArtifactKind::ProviderProfile
                    && format!("sha256:{}", artifact.artifact_digest.as_str()) == *expected
            })
            .ok_or("canonical finality provider missing")?;
        let current = provider_qualification_deadline(tx, &provider.artifact_id, expected).await?;
        if current.is_some() {
            qualified += 1;
        }
    }
    Ok(qualified >= usize::from(rule.required_observations))
}

/// Returns a live deadline while retaining the store owner's row fences. The
/// SQL function is also available to the source reader without table writes.
pub(crate) async fn provider_qualification_deadline(
    tx: &mut Transaction<'_, Postgres>,
    provider_id: &str,
    artifact_digest: &str,
) -> Result<Option<u64>, String> {
    let expiry: Option<i64> =
        sqlx::query_scalar("select openpc.lock_indexer_qualified_provider($1::text::uuid,$2)")
            .bind(provider_id)
            .bind(artifact_digest)
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| "canonical finality provider observation unavailable")?;
    expiry
        .map(|value| u64::try_from(value).map_err(|_| "canonical provider expiry rejected".into()))
        .transpose()
}

fn parse_digest(value: &str) -> Result<Digest, String> {
    Digest::parse(value.strip_prefix("sha256:").unwrap_or(value))
        .map_err(|_| "indexer digest invalid".into())
}

fn uuid(value: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value).map_err(|_| "indexer identifier invalid".into())
}
