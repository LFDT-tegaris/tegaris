//! Existing configuration-work queue consumer for immutable CIGL candidates.
//! All effects are one database transaction; a crash before commit is retryable
//! without producing a profile, dispatching a transaction or activating policy.
use super::reviewed_profile::{
    InstalledAnalysisSources, ReviewCompilationRequest, compile_reviewed_profile,
};
use crate::configuration_result::{
    WorkResultIdentity, append_result_event, update_operation_result,
};
use crate::runtime_configuration_input::{RUNTIME_ARTIFACT_BUSY, runtime_artifact_database_error};
use pc_policy_core::cigl::profile::publication::{
    ProfileCompilationReceipt, grant_sources_digest, method_sources_digest,
};
use pc_runtime_types::{Digest, PurposeSigner, RuntimeError, RuntimeResult, canonical_bytes};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};

#[cfg(test)]
#[path = "profile_store_tests.rs"]
mod tests;

pub struct CompilationWork {
    pub work_id: String,
    pub operation_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub analysis_id: String,
    pub profile_id: String,
    pub profile_revision: u64,
    pub target_runtime_id: String,
    pub capsule_digest: Digest,
    pub review_digest: Digest,
    pub analysis_digest: Digest,
    pub policy_generation_digest: Digest,
    pub worker_id: String,
    pub attempt_count: i64,
}
impl CompilationWork {
    fn identity(&self) -> WorkResultIdentity<'_> {
        WorkResultIdentity {
            participant_id: &self.participant_id,
            privacy_domain_id: &self.privacy_domain_id,
            operation_id: &self.operation_id,
            work_id: &self.work_id,
            resource_id: &self.analysis_id,
        }
    }
}
fn text(row: &PgRow, key: &str) -> RuntimeResult<String> {
    row.try_get(key).map_err(|_| RuntimeError::InvalidInput)
}
fn digest(row: &PgRow, key: &str) -> RuntimeResult<Digest> {
    let value = text(row, key)?;
    Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or(RuntimeError::InvalidDigest)?,
    )
}
pub async fn context(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
) -> RuntimeResult<()> {
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1',true),openpc.assert_request_context(true)")
        .bind(participant).bind(privacy).execute(&mut **tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?;
    Ok(())
}
pub async fn claim_next(
    pool: &PgPool,
    participant: &str,
    privacy: &str,
    worker: &str,
) -> RuntimeResult<Option<CompilationWork>> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    context(&mut tx, participant, privacy).await?;
    let row=sqlx::query(r#"with candidate as (
       select work.configuration_work_id from control.configuration_work work
       join control.cigl_profile_version version on version.configuration_work_id=work.configuration_work_id
         and version.participant_id=work.participant_id and version.privacy_domain_id=work.privacy_domain_id and version.state='PENDING'
       where work.participant_id=$1::text::uuid and work.privacy_domain_id=$2::text::uuid and work.work_kind='CIGL_PROFILE_COMPILATION'
         and (work.state='PENDING' or (work.state='LEASED' and work.lease_until<=clock_timestamp()))
       order by work.created_at,work.configuration_work_id for update of work skip locked limit 1
      ), claimed as (
       update control.configuration_work work set state='LEASED',attempt_count=attempt_count+1,lease_owner=$3,
         lease_until=clock_timestamp()+interval '30 seconds',last_error_code=null,updated_at=clock_timestamp()
       from candidate where work.configuration_work_id=candidate.configuration_work_id returning work.*)
      select claimed.configuration_work_id::text,claimed.operation_id::text,claimed.attempt_count,
       version.profile_id::text,version.revision::text,analysis.analysis_id::text,analysis.runtime_target_id::text,
       analysis.capsule_digest,analysis.review_digest,analysis.analysis_digest,analysis.policy_generation_digest
      from claimed join control.cigl_profile_version version on version.configuration_work_id=claimed.configuration_work_id
      join control.cigl_analysis analysis on analysis.analysis_id=version.analysis_id
       and analysis.participant_id=claimed.participant_id and analysis.privacy_domain_id=claimed.privacy_domain_id
      where analysis.state='REVIEWED' and analysis.revision=3"#)
        .bind(participant).bind(privacy).bind(worker).fetch_optional(&mut *tx).await.map_err(runtime_artifact_database_error);
    let row = match row {
        Ok(row) => row,
        Err(error) if error == RUNTIME_ARTIFACT_BUSY => {
            // The statement fence rejected the claim before any lease/effect.
            // Roll back explicitly; cleanup failure must still stop this worker.
            tx.rollback()
                .await
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            return Ok(None);
        }
        Err(_) => return Err(RuntimeError::RuntimeUnavailable),
    };
    let result = row
        .map(|row| {
            Ok(CompilationWork {
                work_id: text(&row, "configuration_work_id")?,
                operation_id: text(&row, "operation_id")?,
                participant_id: participant.into(),
                privacy_domain_id: privacy.into(),
                analysis_id: text(&row, "analysis_id")?,
                profile_id: text(&row, "profile_id")?,
                profile_revision: text(&row, "revision")?
                    .parse()
                    .map_err(|_| RuntimeError::InvalidInput)?,
                target_runtime_id: text(&row, "runtime_target_id")?,
                capsule_digest: digest(&row, "capsule_digest")?,
                review_digest: digest(&row, "review_digest")?,
                analysis_digest: digest(&row, "analysis_digest")?,
                policy_generation_digest: digest(&row, "policy_generation_digest")?,
                worker_id: worker.into(),
                attempt_count: row
                    .try_get("attempt_count")
                    .map_err(|_| RuntimeError::InvalidInput)?,
            })
        })
        .transpose()?;
    tx.commit()
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    Ok(result)
}
async fn require_lease(
    tx: &mut Transaction<'_, Postgres>,
    work: &CompilationWork,
) -> RuntimeResult<()> {
    let valid=sqlx::query("select 1 from control.configuration_work where configuration_work_id=$1::text::uuid and participant_id=$2::text::uuid and privacy_domain_id=$3::text::uuid and operation_id=$4::text::uuid and resource_id=$5::text::uuid and work_kind='CIGL_PROFILE_COMPILATION' and state='LEASED' and lease_owner=$6 and lease_until>clock_timestamp() for update")
        .bind(&work.work_id).bind(&work.participant_id).bind(&work.privacy_domain_id).bind(&work.operation_id).bind(&work.analysis_id).bind(&work.worker_id)
        .fetch_optional(&mut **tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?;
    if valid.is_none() {
        return Err(RuntimeError::GenerationMismatch);
    }
    Ok(())
}

pub async fn compile_and_commit(
    pool: &PgPool,
    work: &CompilationWork,
    sources: &InstalledAnalysisSources<'_>,
    signer: &PurposeSigner,
) -> RuntimeResult<()> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    context(&mut tx, &work.participant_id, &work.privacy_domain_id).await?;
    require_lease(&mut tx, work).await?;
    let compiled = compile_reviewed_profile(
        &mut tx,
        sources,
        &ReviewCompilationRequest {
            analysis_id: &work.analysis_id,
            review_digest: &work.review_digest,
            profile_id: &work.profile_id,
            revision: work.profile_revision,
        },
    )
    .await?;
    let profile = compiled.configured();
    let profile_bytes = profile.to_cbor()?;
    let compiled_at: String =
        sqlx::query_scalar("select floor(extract(epoch from clock_timestamp())*1000)::text")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let receipt = ProfileCompilationReceipt {
        schema_version: "1.0".into(),
        configuration_work_id: work.work_id.clone(),
        operation_id: work.operation_id.clone(),
        analysis_id: work.analysis_id.clone(),
        profile_id: work.profile_id.clone(),
        profile_revision: work.profile_revision,
        participant_id: work.participant_id.clone(),
        privacy_domain_id: work.privacy_domain_id.clone(),
        target_runtime_id: work.target_runtime_id.clone(),
        capsule_digest: work.capsule_digest.clone(),
        review_digest: work.review_digest.clone(),
        analysis_digest: work.analysis_digest.clone(),
        policy_generation_digest: work.policy_generation_digest.clone(),
        profile_digest: profile.definition.digest()?,
        artifact_digest: Digest::of(&profile_bytes),
        method_sources_digest: method_sources_digest(compiled.methods())?,
        grant_sources_digest: grant_sources_digest(compiled.grants())?,
        dependency_paths_digest: Some(
            pc_policy_core::cigl::grants::dependencies::dependency_paths_digest(
                compiled.dependencies(),
            )?,
        ),
        compiled_at_ms: compiled_at
            .parse()
            .map_err(|_| RuntimeError::InvalidInput)?,
        signer_id: work.worker_id.clone(),
    };
    let signed = receipt.sign(signer)?;
    ProfileCompilationReceipt::verify(
        &signed,
        &signer.verifier().sec1_bytes(),
        &receipt,
        &profile_bytes,
        compiled.methods(),
        compiled.grants(),
    )?;
    receipt.verify_dependency_paths(compiled.dependencies())?;
    sqlx::query("insert into control.cigl_profile_method_source(profile_id,profile_revision,participant_id,privacy_domain_id,contract_method_policy_id,runtime_binding_id,method_revision,binding_revision) select $1::text::uuid,$2::text::bigint,$3::text::uuid,$4::text::uuid,(source->>'methodId')::uuid,(source->>'runtimeBindingId')::uuid,(source->>'methodRevision')::bigint,(source->>'bindingRevision')::bigint from jsonb_array_elements($5::jsonb) source")
        .bind(&work.profile_id).bind(work.profile_revision.to_string()).bind(&work.participant_id).bind(&work.privacy_domain_id)
        .bind(serde_json::to_value(compiled.methods()).map_err(|_|RuntimeError::InvalidInput)?)
        .execute(&mut *tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?;
    sqlx::query("insert into control.cigl_profile_grant_source(profile_id,profile_revision,participant_id,privacy_domain_id,grant_id,grant_revision,grant_digest) select $1::text::uuid,$2::text::bigint,$3::text::uuid,$4::text::uuid,(source->>'grantId')::uuid,(source->>'revision')::numeric,'sha256:'||(source->>'digest') from jsonb_array_elements($5::jsonb) source")
        .bind(&work.profile_id).bind(work.profile_revision.to_string()).bind(&work.participant_id).bind(&work.privacy_domain_id)
        .bind(serde_json::to_value(compiled.grants()).map_err(|_|RuntimeError::InvalidInput)?)
        .execute(&mut *tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?;
    sqlx::query("insert into control.cigl_profile_dependency_path(profile_id,profile_revision,participant_id,privacy_domain_id,ordinal,document) select $1::text::uuid,$2::text::bigint,$3::text::uuid,$4::text::uuid,(path->>'ordinal')::integer,path from jsonb_array_elements($5::jsonb) path")
        .bind(&work.profile_id).bind(work.profile_revision.to_string()).bind(&work.participant_id).bind(&work.privacy_domain_id)
        .bind(serde_json::to_value(compiled.dependencies()).map_err(|_|RuntimeError::InvalidInput)?)
        .execute(&mut *tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?;
    let changed=sqlx::query("update control.cigl_profile_version set state='COMPILED',profile_cbor=$3,profile_digest=$4,artifact_digest=$5,compilation_receipt=$6,compilation_signer_id=$7,compiled_at=to_timestamp($8::text::numeric/1000),dependency_paths_digest=$9 where profile_id=$1::text::uuid and revision=$2::text::bigint and state='PENDING'")
        .bind(&work.profile_id).bind(work.profile_revision.to_string()).bind(profile_bytes)
        .bind(format!("sha256:{}",receipt.profile_digest.as_str())).bind(format!("sha256:{}",receipt.artifact_digest.as_str())).bind(&signed)
        .bind(&work.worker_id).bind(compiled_at).bind(receipt.dependency_paths_digest.as_ref().map(|digest| format!("sha256:{}",digest.as_str())))
        .execute(&mut *tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?.rows_affected();
    if changed != 1 {
        return Err(RuntimeError::GenerationMismatch);
    }
    let result = serde_json::json!({"state":"COMPILED","runtimePermission":"NONE","profileId":work.profile_id,
        "profileRevision":work.profile_revision.to_string(),"compilationReceiptDigest":format!("sha256:{}",Digest::of(signed).as_str())});
    finish_work(&mut tx, work, result, None).await?;
    tx.commit()
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)
}

async fn finish_work(
    tx: &mut Transaction<'_, Postgres>,
    work: &CompilationWork,
    result: Value,
    error: Option<&str>,
) -> RuntimeResult<()> {
    let payload = canonical_bytes(&result)?;
    let digest = Digest::of(&payload);
    let event_id = uuid::Uuid::now_v7().to_string();
    let (state, truth, event) = if error.is_some() {
        (
            "FAILED",
            "FAILED",
            "openpc.cigl.profile.compilation-failed.v1",
        )
    } else {
        ("COMPLETED", "SUCCESS", "openpc.cigl.profile.compiled.v1")
    };
    let changed=sqlx::query("update control.configuration_work set state=$3,lease_owner=null,lease_until=null,result_receipt=$4,result_receipt_digest=$5,result_event_id=$6::text::uuid,last_error_code=$7,completed_at=clock_timestamp(),updated_at=clock_timestamp() where configuration_work_id=$1::text::uuid and state='LEASED' and lease_owner=$2")
        .bind(&work.work_id).bind(&work.worker_id).bind(state).bind(result).bind(format!("sha256:{}",digest.as_str())).bind(&event_id).bind(error)
        .execute(&mut **tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?.rows_affected();
    if changed != 1 {
        return Err(RuntimeError::GenerationMismatch);
    }
    append_result_event(
        tx,
        &work.identity(),
        &event_id,
        event,
        "cigl-analysis",
        &payload,
        &digest,
    )
    .await
    .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    update_operation_result(
        tx,
        &work.identity(),
        if error.is_some() {
            "FAILED"
        } else {
            "SUCCEEDED"
        },
        truth,
        3,
    )
    .await
    .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    Ok(())
}

/// Only infrastructure unavailability gets a bounded retry. Stale/denied or
/// malformed inputs fail once; no repeated compile can turn them into authority.
pub async fn fail_or_retry(
    pool: &PgPool,
    work: &CompilationWork,
    error: RuntimeError,
) -> RuntimeResult<()> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    context(&mut tx, &work.participant_id, &work.privacy_domain_id).await?;
    require_lease(&mut tx, work).await?;
    if error == RuntimeError::RuntimeUnavailable && work.attempt_count < 3 {
        sqlx::query("update control.configuration_work set state='PENDING',lease_owner=null,lease_until=null,last_error_code='PC-FACT-4001',updated_at=clock_timestamp() where configuration_work_id=$1::text::uuid and state='LEASED' and lease_owner=$2")
            .bind(&work.work_id).bind(&work.worker_id).execute(&mut *tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?;
    } else {
        finish_work(&mut tx,work,serde_json::json!({"state":"FAILED","runtimePermission":"NONE","errorCode":error.pc_code()}),Some(error.pc_code())).await?;
    }
    tx.commit()
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)
}
