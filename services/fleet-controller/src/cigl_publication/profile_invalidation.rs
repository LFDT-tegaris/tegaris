//! Current-source invalidation for an observed, approved profile generation.
//! This owner can only request a deny; it cannot publish permission or lift one.
//! A recorded real local effect is also protected while convergence is pending;
//! queued work without an immutable activation observation remains insufficient.
use super::{profile_activation::Selection, reviewed_profile::source_snapshot};
use pc_policy_core::cigl::profile::{
    ConfiguredMethodProfile,
    publication::{MethodSourceVersion, grant_sources_digest},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};

pub async fn generation_is_invalidated(
    tx: &mut Transaction<'_, Postgres>,
    target_id: &str,
    generation_id: &str,
    capsule_digest: &Digest,
) -> RuntimeResult<bool> {
    lock_sources(tx).await?;
    // The first observed activation has no predecessor. Preserve that exact
    // absence during reconciliation; NULL equality must not strand its effect.
    let row = sqlx::query(r#"select generation.cigl_profile_selection,
      generation.participant_id::text participant,generation.privacy_domain_id::text privacy
      from control.runtime_target target
      join control.runtime_activation_observation observation on observation.runtime_target_id=target.runtime_target_id
       and observation.participant_id=target.participant_id and observation.privacy_domain_id=target.privacy_domain_id
       and observation.capsule_digest=$3
      join control.runtime_configuration_generation generation
       on generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
        and generation.participant_id=target.participant_id and generation.privacy_domain_id=target.privacy_domain_id
        and generation.runtime_target_id=target.runtime_target_id and generation.generation_digest=observation.generation_digest
        and generation.state in ('ACTIVE','ACTIVATING')
      join control.configuration_work work on work.configuration_work_id=observation.configuration_work_id
       and work.participant_id=generation.participant_id and work.privacy_domain_id=generation.privacy_domain_id
       and work.runtime_configuration_generation_id=generation.runtime_configuration_generation_id
       and work.runtime_target_id=target.runtime_target_id and work.generation_digest=generation.generation_digest
       and work.operation_id=observation.operation_id and work.execution_attempt_id=observation.execution_attempt_id
       and work.xds_version_digest=observation.xds_version_digest
       and work.work_kind='RUNTIME_ACTIVATION' and work.execution_started_at is not null
      where target.runtime_target_id=$1::text::uuid and generation.runtime_configuration_generation_id=$2::text::uuid
       and ((generation.state='ACTIVE' and work.state='COMPLETED'
             and target.active_generation_digest=$3 and work.result_receipt_digest=observation.activation_receipt_digest)
         or (generation.state='ACTIVATING' and work.state in ('LEASED','RECONCILING')
             and target.active_generation_digest is not distinct from work.predecessor_digest))
       and target.participant_id=openpc.current_participant_id() and target.privacy_domain_id=openpc.current_privacy_domain_id()
      for share of target,generation"#)
        .bind(target_id).bind(generation_id).bind(format!("sha256:{}",capsule_digest.as_str()))
        .fetch_optional(&mut **tx).await.map_err(|_| RuntimeError::RuntimeUnavailable)?
        .ok_or(RuntimeError::GenerationMismatch)?;
    let Some(selection) = row
        .try_get::<Option<Value>, _>("cigl_profile_selection")
        .map_err(|_| RuntimeError::InvalidInput)?
    else {
        return Ok(false);
    };
    let participant: String = row
        .try_get("participant")
        .map_err(|_| RuntimeError::InvalidInput)?;
    let privacy: String = row
        .try_get("privacy")
        .map_err(|_| RuntimeError::InvalidInput)?;
    Ok(!selection_is_current(tx, &participant, &privacy, selection).await?)
}

/// Keep Participant, grant and registration lock ordering consistent with the
/// governance owner, including when liveness itself causes the invalidation.
pub async fn lock_sources(tx: &mut Transaction<'_, Postgres>) -> RuntimeResult<()> {
    sqlx::query("select openpc.lock_cigl_invalidation_participant()")
        .execute(&mut **tx)
        .await
        .map_err(|_| RuntimeError::InvalidAuthorization)?;
    let isolation: String = sqlx::query_scalar(
        "select current_setting('transaction_isolation') from openpc.lock_cigl_grant_sources()",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if isolation != "read committed" {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(())
}

pub(in crate::cigl_publication) async fn selection_is_current(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
    selection: Value,
) -> RuntimeResult<bool> {
    lock_sources(tx).await?;
    let selection: Selection =
        serde_json::from_value(selection).map_err(|_| RuntimeError::InvalidInput)?;
    if selection.profiles.is_empty() || selection.profiles.len() > 64 {
        return Err(RuntimeError::BudgetExhausted);
    }
    let current: bool = sqlx::query_scalar("select exists(select 1 from control.participant where participant_id=$1::text::uuid and state='ACTIVE' and archived_at is null and authority_epoch::text=$2)")
        .bind(participant).bind(&selection.participant_epoch).fetch_one(&mut **tx).await.map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if !current {
        return Ok(false);
    }
    let mut last = "";
    for selected in &selection.profiles {
        if selected.profile_id.as_str() <= last {
            return Err(RuntimeError::InvalidInput);
        }
        last = &selected.profile_id;
        let id = selected
            .profile_id
            .strip_prefix("urn:openpc:resource:")
            .ok_or(RuntimeError::InvalidInput)?;
        let bytes: Option<Vec<u8>> = sqlx::query_scalar(r#"select profile_cbor from control.cigl_profile_version
          where profile_id=$1::text::uuid and revision=$2::text::bigint
           and participant_id=$3::text::uuid and privacy_domain_id=$4::text::uuid and state='COMPILED'
           and profile_digest=$5 and artifact_digest=$6"#)
            .bind(id).bind(&selected.profile_revision).bind(participant).bind(privacy)
            .bind(&selected.profile_digest).bind(&selected.compilation_artifact_digest)
            .fetch_optional(&mut **tx).await.map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let Some(bytes) = bytes else {
            return Ok(false);
        };
        if format!("sha256:{}", Digest::of(&bytes).as_str()) != selected.compilation_artifact_digest
        {
            return Ok(false);
        }
        let configured = ConfiguredMethodProfile::from_cbor(&bytes)?;
        if configured.definition.profile_id != id
            || configured.definition.participant_id != participant
            || configured.definition.privacy_domain_id != privacy
            || configured.definition.revision.to_string() != selected.profile_revision
            || format!("sha256:{}", configured.definition.digest()?.as_str())
                != selected.profile_digest
        {
            return Ok(false);
        }
        let rows=sqlx::query(r#"select contract_method_policy_id::text method_id,runtime_binding_id::text binding_id,
          method_revision::text,binding_revision::text from control.cigl_profile_method_source
          where profile_id=$1::text::uuid and profile_revision=$2::text::bigint
           and participant_id=$3::text::uuid and privacy_domain_id=$4::text::uuid order by contract_method_policy_id limit 2050"#)
            .bind(id).bind(&selected.profile_revision).bind(participant).bind(privacy)
            .fetch_all(&mut **tx).await.map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let methods = rows
            .into_iter()
            .map(|row| {
                let text = |key| {
                    row.try_get::<String, _>(key)
                        .map_err(|_| RuntimeError::InvalidInput)
                };
                Ok(MethodSourceVersion {
                    method_id: text("method_id")?,
                    runtime_binding_id: text("binding_id")?,
                    method_revision: text("method_revision")?
                        .parse()
                        .map_err(|_| RuntimeError::InvalidInput)?,
                    binding_revision: text("binding_revision")?
                        .parse()
                        .map_err(|_| RuntimeError::InvalidInput)?,
                })
            })
            .collect::<RuntimeResult<Vec<_>>>()?;
        let current =
            match source_snapshot::load_retained(tx, &configured.definition, methods).await {
                Ok(current) => current,
                Err(RuntimeError::GenerationMismatch | RuntimeError::InvalidDigest) => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            };
        if format!(
            "sha256:{}",
            grant_sources_digest(&current.versions)?.as_str()
        ) != selected.grant_sources_digest
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a real publicly activated first-policy fixture"]
    async fn postgres_first_activation_reconciliation_accepts_only_exact_observed_scope() {
        let root =
            std::path::PathBuf::from(std::env::var("OPENPC_FIRST_POLICY_FIXTURE_ROOT").unwrap());
        let input: Value =
            serde_json::from_slice(&std::fs::read(root.join("policy-set-input.json")).unwrap())
                .unwrap();
        let discovery: Value = serde_json::from_slice(
            &std::fs::read(root.join("discovery-credential-input.json")).unwrap(),
        )
        .unwrap();
        let participant = input["participantId"].as_str().unwrap();
        let privacy = input["privacyDomainId"].as_str().unwrap();
        let target = discovery["targetId"].as_str().unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("OPENPC_CIGL_COMPILATION_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
            .bind(participant).bind(privacy).execute(&mut *tx).await.unwrap();
        let row = sqlx::query("select work.runtime_configuration_generation_id::text generation_id, observation.capsule_digest, work.predecessor_digest, target.active_generation_digest from control.configuration_work work join control.runtime_activation_observation observation using(configuration_work_id) join control.runtime_target target on target.runtime_target_id=work.runtime_target_id where work.runtime_target_id=$1::text::uuid and work.work_kind='RUNTIME_ACTIVATION' and work.state='RECONCILING' and work.predecessor_digest is null")
            .bind(target).fetch_one(&mut *tx).await.unwrap();
        assert!(row.get::<Option<String>, _>("predecessor_digest").is_none());
        assert!(
            row.get::<Option<String>, _>("active_generation_digest")
                .is_none()
        );
        let generation: String = row.get("generation_id");
        let capsule: String = row.get("capsule_digest");
        let capsule = Digest::parse(capsule.strip_prefix("sha256:").unwrap()).unwrap();
        assert!(
            !generation_is_invalidated(&mut tx, target, &generation, &capsule)
                .await
                .unwrap()
        );
        for (wrong_target, wrong_generation, wrong_capsule) in [
            (
                uuid::Uuid::now_v7().to_string(),
                generation.clone(),
                capsule.clone(),
            ),
            (
                target.to_owned(),
                uuid::Uuid::now_v7().to_string(),
                capsule.clone(),
            ),
            (
                target.to_owned(),
                generation.clone(),
                Digest::of(b"unobserved capsule"),
            ),
        ] {
            assert!(
                generation_is_invalidated(
                    &mut tx,
                    &wrong_target,
                    &wrong_generation,
                    &wrong_capsule
                )
                .await
                .is_err()
            );
        }
        tx.rollback().await.unwrap();
        for (other_participant, other_privacy) in [
            (participant.to_owned(), uuid::Uuid::now_v7().to_string()),
            (uuid::Uuid::now_v7().to_string(), privacy.to_owned()),
        ] {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
                .bind(other_participant).bind(other_privacy).execute(&mut *tx).await.unwrap();
            assert!(
                generation_is_invalidated(&mut tx, target, &generation, &capsule)
                    .await
                    .is_err()
            );
            tx.rollback().await.unwrap();
        }
        pool.close().await;
    }
}
