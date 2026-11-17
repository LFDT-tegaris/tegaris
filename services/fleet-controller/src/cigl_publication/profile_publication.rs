//! Publication inputs retain the reviewed definition and independently pin the
//! complete current grant snapshot. Neither compilation nor this preparation
//! activates a target; the existing activation transaction must retain its fence.
use super::reviewed_profile::{InstalledAnalysisSources, source_snapshot};
use pc_policy_core::{
    cigl::{
        grants::GrantStatus,
        profile::{
            ConfiguredMethodProfile,
            publication::{
                GrantSourceVersion, MethodSourceVersion, ProfileCompilationReceipt,
                grant_sources_digest, method_sources_digest,
            },
        },
    },
    invocation::{ActiveInvocationScope, ValidatedInvocationPolicy},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};

pub struct ProfilePublicationRequest<'a> {
    pub profile_id: &'a str,
    pub revision: u64,
    pub profile_digest: &'a Digest,
    pub compilation_artifact_digest: &'a Digest,
    pub current_grants_digest: &'a Digest,
    pub participant_epoch: u64,
}

/// Only the scoped database owner can construct this value. Its artifact is a
/// publication candidate with the original reviewed definition, never an edit
/// to historical compilation or to the global shared grant owner.
pub struct VerifiedProfilePublication {
    configured: ConfiguredMethodProfile,
    compilation_receipt_digest: Digest,
    methods: Vec<MethodSourceVersion>,
    grants: Vec<GrantSourceVersion>,
}
impl VerifiedProfilePublication {
    pub fn configured(&self) -> &ConfiguredMethodProfile {
        &self.configured
    }
    pub fn compilation_receipt_digest(&self) -> &Digest {
        &self.compilation_receipt_digest
    }
    pub fn methods(&self) -> &[MethodSourceVersion] {
        &self.methods
    }
    pub fn grants(&self) -> &[GrantSourceVersion] {
        &self.grants
    }
}

fn source_values<T: serde::de::DeserializeOwned>(rows: Vec<PgRow>) -> RuntimeResult<Vec<T>> {
    rows.into_iter()
        .map(|row| {
            let value: Value = row
                .try_get("source")
                .map_err(|_| RuntimeError::InvalidInput)?;
            serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)
        })
        .collect()
}

/// Read committed is required because a snapshot taken before the grant fence
/// could omit a newly committed DENY. All source locks remain with the caller.
pub async fn prepare_publication(
    tx: &mut Transaction<'_, Postgres>,
    installed: &InstalledAnalysisSources<'_>,
    compilation_verification_key: &[u8],
    request: &ProfilePublicationRequest<'_>,
) -> RuntimeResult<VerifiedProfilePublication> {
    prepare(tx, installed, compilation_verification_key, request, None).await
}

pub(super) async fn prepare_queued_publication(
    tx: &mut Transaction<'_, Postgres>,
    installed: &InstalledAnalysisSources<'_>,
    compilation_verification_key: &[u8],
    request: &ProfilePublicationRequest<'_>,
    activation_work_id: &str,
) -> RuntimeResult<VerifiedProfilePublication> {
    prepare(
        tx,
        installed,
        compilation_verification_key,
        request,
        Some(activation_work_id),
    )
    .await
}

async fn prepare(
    tx: &mut Transaction<'_, Postgres>,
    installed: &InstalledAnalysisSources<'_>,
    compilation_verification_key: &[u8],
    request: &ProfilePublicationRequest<'_>,
    activation_work_id: Option<&str>,
) -> RuntimeResult<VerifiedProfilePublication> {
    sqlx::query("select openpc.lock_cigl_publication_participant()")
        .execute(&mut **tx)
        .await
        .map_err(|_| RuntimeError::InvalidAuthorization)?;
    let isolation: String = sqlx::query_scalar(
        "select current_setting('transaction_isolation') from openpc.lock_cigl_grant_sources()",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if isolation != "read committed" || request.participant_epoch == 0 {
        return Err(RuntimeError::InvalidInput);
    }
    let (participant, privacy) = installed.invocation.source_scope();
    let capsule_digest = installed.capsule.digest()?;
    let row = sqlx::query(r#"select version.profile_cbor,version.compilation_receipt,
      work.result_receipt->>'compilationReceiptDigest' receipt_digest,
      jsonb_build_object('schemaVersion','1.0','configurationWorkId',work.configuration_work_id::text,
        'operationId',work.operation_id::text,'analysisId',analysis.analysis_id::text,'profileId',version.profile_id::text,
        'profileRevision',version.revision::text,'participantId',version.participant_id::text,'privacyDomainId',version.privacy_domain_id::text,
        'targetRuntimeId',analysis.runtime_target_id::text,'capsuleDigest',substring(analysis.capsule_digest from 8),
        'reviewDigest',substring(version.review_digest from 8),'analysisDigest',substring(analysis.analysis_digest from 8),
        'policyGenerationDigest',substring(analysis.policy_generation_digest from 8),'profileDigest',substring(version.profile_digest from 8),
        'artifactDigest',substring(version.artifact_digest from 8),'dependencyPathsDigest',substring(version.dependency_paths_digest from 8),
        'compiledAtMs',floor(extract(epoch from version.compiled_at)*1000),'signerId',version.compilation_signer_id) expected
      from control.cigl_profile_version version
      join control.cigl_analysis analysis on analysis.analysis_id=version.analysis_id
        and analysis.participant_id=version.participant_id and analysis.privacy_domain_id=version.privacy_domain_id
      join control.configuration_work work on work.configuration_work_id=version.configuration_work_id
        and work.participant_id=version.participant_id and work.privacy_domain_id=version.privacy_domain_id
      join control.runtime_target target on target.runtime_target_id=analysis.runtime_target_id
        and target.participant_id=analysis.participant_id and target.privacy_domain_id=analysis.privacy_domain_id
      join control.participant participant on participant.participant_id=version.participant_id
      where version.profile_id=$1::text::uuid and version.revision=$2::text::bigint
        and version.participant_id=$3::text::uuid and version.privacy_domain_id=$4::text::uuid
        and version.state='COMPILED' and work.state='COMPLETED' and work.work_kind='CIGL_PROFILE_COMPILATION'
        and analysis.state='REVIEWED' and analysis.revision=3 and analysis.runtime_target_id=$5::text::uuid
        and target.active_generation_digest=$6
        and openpc.cigl_profile_has_installed_lineage(version.profile_id,version.revision,
          target.runtime_target_id,$6,$9)
        and participant.state='ACTIVE' and participant.archived_at is null and participant.authority_epoch=$7::text::bigint
        and (($8::text is null and target.state='ACTIVE_MATCHED' and target.active_generation_digest=target.desired_generation_digest)
          or ($8::text is not null and target.state='STAGING' and exists(select 1 from control.configuration_work activation
            join control.runtime_configuration_generation generation on generation.runtime_configuration_generation_id=activation.runtime_configuration_generation_id
             and generation.participant_id=activation.participant_id and generation.privacy_domain_id=activation.privacy_domain_id
            where activation.configuration_work_id=$8::text::uuid and activation.participant_id=target.participant_id
              and activation.privacy_domain_id=target.privacy_domain_id and activation.runtime_target_id=target.runtime_target_id
              and activation.work_kind='RUNTIME_ACTIVATION' and activation.state in ('PENDING','LEASED')
              and activation.predecessor_digest=target.active_generation_digest and activation.generation_digest=target.desired_generation_digest
              and generation.generation_digest=activation.generation_digest and generation.predecessor_digest=activation.predecessor_digest
              and generation.state='ACTIVATING' and generation.cigl_profile_selection is not null)))
      for share of target"#)
        .bind(request.profile_id).bind(request.revision.to_string()).bind(participant).bind(privacy)
        .bind(&installed.capsule.target_runtime_id).bind(format!("sha256:{}",capsule_digest.as_str()))
        .bind(request.participant_epoch.to_string())
        .bind(activation_work_id)
        .bind(format!("sha256:{}", installed.capsule.policy_bundle_digest.as_str()))
        .fetch_optional(&mut **tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?
        .ok_or(RuntimeError::GenerationMismatch)?;
    let methods: Vec<MethodSourceVersion> = source_values(sqlx::query(r#"select jsonb_build_object(
      'methodId',contract_method_policy_id::text,'runtimeBindingId',runtime_binding_id::text,
      'methodRevision',method_revision::text,'bindingRevision',binding_revision::text) source
      from control.cigl_profile_method_source where profile_id=$1::text::uuid and profile_revision=$2::text::bigint
        and participant_id=$3::text::uuid and privacy_domain_id=$4::text::uuid order by contract_method_policy_id limit 2050"#)
      .bind(request.profile_id).bind(request.revision.to_string()).bind(participant).bind(privacy)
      .fetch_all(&mut **tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?)?;
    let grants: Vec<GrantSourceVersion> = source_values(sqlx::query(r#"select jsonb_build_object(
      'grantId',grant_id::text,'revision',grant_revision::text,'digest',substring(grant_digest from 8)) source
      from control.cigl_profile_grant_source where profile_id=$1::text::uuid and profile_revision=$2::text::bigint
        and participant_id=$3::text::uuid and privacy_domain_id=$4::text::uuid order by grant_id limit 4097"#)
      .bind(request.profile_id).bind(request.revision.to_string()).bind(participant).bind(privacy)
      .fetch_all(&mut **tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?)?;
    let mut expected: Value = row
        .try_get("expected")
        .map_err(|_| RuntimeError::InvalidInput)?;
    expected["methodSourcesDigest"] = serde_json::to_value(method_sources_digest(&methods)?)
        .map_err(|_| RuntimeError::InvalidInput)?;
    expected["grantSourcesDigest"] = serde_json::to_value(grant_sources_digest(&grants)?)
        .map_err(|_| RuntimeError::InvalidInput)?;
    let expected: ProfileCompilationReceipt =
        serde_json::from_value(expected).map_err(|_| RuntimeError::InvalidInput)?;
    if expected.profile_digest != *request.profile_digest
        || expected.artifact_digest != *request.compilation_artifact_digest
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    let receipt: Vec<u8> = row
        .try_get("compilation_receipt")
        .map_err(|_| RuntimeError::InvalidInput)?;
    let bytes: Vec<u8> = row
        .try_get("profile_cbor")
        .map_err(|_| RuntimeError::InvalidInput)?;
    let compilation_receipt_digest = Digest::of(&receipt);
    if row
        .try_get::<String, _>("receipt_digest")
        .map_err(|_| RuntimeError::InvalidInput)?
        != format!("sha256:{}", compilation_receipt_digest.as_str())
    {
        return Err(RuntimeError::InvalidDigest);
    }
    let mut configured = ProfileCompilationReceipt::verify(
        &receipt,
        compilation_verification_key,
        &expected,
        &bytes,
        &methods,
        &grants,
    )?;
    let (configuration, policy) = installed
        .invocation
        .analysis_source_bytes(installed.capsule, installed.artifacts)?;
    let policies = ValidatedInvocationPolicy::load_active(
        configuration,
        &Digest::of(configuration),
        policy,
        &Digest::of(policy),
        &ActiveInvocationScope {
            tenant_id: participant,
            privacy_domain_id: privacy,
            policy_generation_digest: &installed.capsule.policy_bundle_digest,
            workload_id: &pc_policy_core::invocation::active_invocation_workload(
                configuration,
                &Digest::of(configuration),
                participant,
                privacy,
            )?,
        },
    )?;
    let current = source_snapshot::load(
        tx,
        &configured.definition,
        &policies,
        source_snapshot::MethodState::Active,
    )
    .await?;
    if current.methods != methods
        || grant_sources_digest(&current.versions)? != *request.current_grants_digest
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    configured.grants.status = GrantStatus::Active;
    configured.grants.grants = current.grants;
    configured.validate()?;
    Ok(VerifiedProfilePublication {
        configured,
        compilation_receipt_digest,
        methods,
        grants: current.versions,
    })
}
