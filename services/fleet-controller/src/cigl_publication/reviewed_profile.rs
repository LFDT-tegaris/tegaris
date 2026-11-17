//! Compile only an exact public review of an installed target's signed analysis.
//! The result is a candidate, not publication, activation or send authority.
use openpc_multi_rpc::cigl::analysis::receipt::{AnalysisJobExpectation, MethodAnalysisReceipt};
use openpc_runtime_agent::{RuntimeCapsule, invocation_custody::InvocationArtifactAdmission};
use pc_policy_core::{
    cigl::{
        analysis::review::MethodAnalysisReview,
        grants::dependencies::{NestedDependency, derive_nested_dependencies},
        grants::{GrantStatus, InteractionGrant, InteractionGrantSet},
        profile::ConfiguredMethodProfile,
    },
    invocation::{ActiveInvocationScope, ValidatedInvocationPolicy},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use std::collections::BTreeMap;

pub(super) mod source_snapshot;

#[cfg(test)]
mod tests;

/// Deployment-owned trust and actual capsule material. The receipt pins the
/// capsule's digest; the invocation owner verifies its signed source headers.
pub struct InstalledAnalysisSources<'a> {
    pub capsule: &'a RuntimeCapsule,
    pub artifacts: &'a BTreeMap<Digest, Vec<u8>>,
    pub invocation: &'a InvocationArtifactAdmission,
    pub target_verification_key: &'a [u8],
}
pub struct ReviewCompilationRequest<'a> {
    pub analysis_id: &'a str,
    pub review_digest: &'a Digest,
    pub profile_id: &'a str,
    pub revision: u64,
}

pub use pc_policy_core::cigl::profile::publication::{GrantSourceVersion, MethodSourceVersion};
pub struct CompiledReviewedProfile {
    configured: ConfiguredMethodProfile,
    methods: Vec<MethodSourceVersion>,
    grants: Vec<GrantSourceVersion>,
    dependencies: Vec<NestedDependency>,
}
impl CompiledReviewedProfile {
    pub fn configured(&self) -> &ConfiguredMethodProfile {
        &self.configured
    }
    pub fn methods(&self) -> &[MethodSourceVersion] {
        &self.methods
    }
    pub fn grants(&self) -> &[GrantSourceVersion] {
        &self.grants
    }
    pub fn dependencies(&self) -> &[NestedDependency] {
        &self.dependencies
    }
}

fn text(row: &PgRow, key: &str) -> RuntimeResult<String> {
    row.try_get(key).map_err(|_| RuntimeError::InvalidInput)
}
fn number(row: &PgRow, key: &str) -> RuntimeResult<u64> {
    text(row, key)?
        .parse()
        .map_err(|_| RuntimeError::InvalidInput)
}
fn digest(value: &str) -> RuntimeResult<Digest> {
    Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or(RuntimeError::InvalidDigest)?,
    )
}
fn bytes<const N: usize>(value: &str) -> RuntimeResult<[u8; N]> {
    let value = value.strip_prefix("0x").ok_or(RuntimeError::InvalidInput)?;
    if value.len() != 2 * N || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RuntimeError::InvalidInput);
    }
    let mut result = [0; N];
    for (i, b) in result.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)
            .map_err(|_| RuntimeError::InvalidInput)?;
    }
    Ok(result)
}
fn field<'a>(value: &'a Value, key: &str) -> RuntimeResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(RuntimeError::InvalidInput)
}
fn public_review(mut value: Value, expected: &Digest) -> RuntimeResult<MethodAnalysisReview> {
    if Digest::of(canonical_bytes(&value)?) != *expected {
        return Err(RuntimeError::InvalidDigest);
    }
    value["analysisDigest"] =
        Value::String(digest(field(&value, "analysisDigest")?)?.as_str().into());
    for action in value
        .get_mut("actions")
        .and_then(Value::as_array_mut)
        .ok_or(RuntimeError::InvalidInput)?
    {
        action["actionDigest"] =
            Value::String(digest(field(action, "actionDigest")?)?.as_str().into());
    }
    serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)
}

/// Call from the existing scoped worker transaction. The scoped database fence
/// prevents grant insert/update phantoms until commit, including new DENYs.
/// A committed snapshot still requires durable publication/invalidation; this
/// method deliberately supplies no active-profile or transaction capability.
pub async fn compile_reviewed_profile(
    tx: &mut Transaction<'_, Postgres>,
    installed: &InstalledAnalysisSources<'_>,
    request: &ReviewCompilationRequest<'_>,
) -> RuntimeResult<CompiledReviewedProfile> {
    let isolation: String = sqlx::query_scalar(
        "select current_setting('transaction_isolation') from openpc.lock_cigl_grant_sources()",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    // A snapshot taken before waiting for the grant fence could miss a newly
    // committed DENY. Each read must observe the state after fence acquisition.
    if isolation != "read committed" {
        return Err(RuntimeError::InvalidInput);
    }
    let capsule = installed.capsule;
    let (participant, privacy) = installed.invocation.source_scope();
    let row = sqlx::query(r#"select a.*,floor(extract(epoch from a.created_at)*1000)::text created_ms,
      floor(extract(epoch from a.expires_at)*1000)::text expires_ms,
      floor(extract(epoch from clock_timestamp())*1000)::text now_ms
      from control.cigl_analysis a
      join control.runtime_target target on target.runtime_target_id=a.runtime_target_id
        and target.participant_id=a.participant_id and target.privacy_domain_id=a.privacy_domain_id
      join control.contract_runtime_binding binding on binding.runtime_binding_id=a.runtime_binding_id
        and binding.participant_id=a.participant_id and binding.privacy_domain_id=a.privacy_domain_id
      join control.contract_method_policy method on method.contract_method_policy_id=a.contract_method_policy_id
        and method.runtime_binding_id=binding.runtime_binding_id and method.participant_id=a.participant_id
        and method.privacy_domain_id=a.privacy_domain_id
      where a.analysis_id=$1::text::uuid and a.participant_id=$2::text::uuid and a.privacy_domain_id=$3::text::uuid
        and a.state='REVIEWED' and a.revision=3 and a.expires_at>clock_timestamp()
        and target.state='ACTIVE_MATCHED' and target.active_generation_digest=target.desired_generation_digest
        and target.active_generation_digest=a.definition->>'expectedGenerationDigest'
        and target.policy_generation_digest=a.policy_generation_digest
        and binding.state='BOUND' and binding.revision::text=a.definition->>'expectedRuntimeBindingRevision'
        and method.state in ('PREPARED','ACTIVE') and method.revision::text=a.definition->>'expectedMethodRevision'
        and openpc.cigl_subject_current(a.participant_id,jsonb_build_object('kind','WORKLOAD','id',a.definition->>'workloadId'))
        and exists(select 1 from control.runtime_activation_observation observation
          where observation.participant_id=a.participant_id and observation.privacy_domain_id=a.privacy_domain_id
          and observation.runtime_target_id=a.runtime_target_id and observation.capsule_digest=target.active_generation_digest
          and observation.capsule_digest=a.capsule_digest)
      for share of target,binding,method"#)
        .bind(request.analysis_id).bind(participant).bind(privacy)
        .fetch_optional(&mut **tx).await.map_err(|_| RuntimeError::RuntimeUnavailable)?
        .ok_or(RuntimeError::InvalidAuthorization)?;
    let definition: Value = row
        .try_get("definition")
        .map_err(|_| RuntimeError::InvalidInput)?;
    let now_ms = number(&row, "now_ms")?;
    let expected = AnalysisJobExpectation {
        analysis_id: request.analysis_id.into(),
        target_runtime_id: capsule.target_runtime_id.clone(),
        capsule_digest: digest(&text(&row, "capsule_digest")?)?,
        transaction_hash: bytes(field(&definition, "transactionHash")?)?,
        participant_id: participant.into(),
        privacy_domain_id: privacy.into(),
        workload_id: field(&definition, "workloadId")?.into(),
        root_runtime_binding_id: field(&definition, "runtimeBindingId")?
            .strip_prefix("urn:openpc:resource:")
            .ok_or(RuntimeError::InvalidInput)?
            .into(),
        root_contract_method_policy_id: field(&definition, "contractMethodPolicyId")?
            .strip_prefix("urn:openpc:resource:")
            .ok_or(RuntimeError::InvalidInput)?
            .into(),
        policy_generation_digest: digest(&text(&row, "policy_generation_digest")?)?,
        created_at_ms: number(&row, "created_ms")?,
        expires_at_ms: number(&row, "expires_ms")?,
    };
    if capsule.digest()? != expected.capsule_digest
        || capsule.policy_bundle_digest != expected.policy_generation_digest
        || capsule.hard_expiry_ns / 1_000_000 <= now_ms
        || digest(&text(&row, "review_digest")?)? != *request.review_digest
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    let signed: Vec<u8> = row
        .try_get("signed_receipt")
        .map_err(|_| RuntimeError::InvalidInput)?;
    let receipt = MethodAnalysisReceipt::verify_for_job(
        &signed,
        installed.target_verification_key,
        &expected,
        now_ms,
    )?;
    let analysis = receipt.analysis();
    if receipt.digest() != &digest(&text(&row, "receipt_digest")?)?
        || analysis.digest()? != digest(&text(&row, "analysis_digest")?)?
    {
        return Err(RuntimeError::InvalidDigest);
    }
    let review = public_review(
        row.try_get("review_definition")
            .map_err(|_| RuntimeError::InvalidInput)?,
        request.review_digest,
    )?;
    let (configuration, policy) = installed
        .invocation
        .analysis_source_bytes(capsule, installed.artifacts)?;
    let definition = review.compile_candidate(
        analysis,
        configuration,
        policy,
        request.profile_id,
        request.revision,
    )?;
    let policies = ValidatedInvocationPolicy::load_active(
        configuration,
        &analysis.configuration_digest,
        policy,
        &analysis.policy_artifact_digest,
        &ActiveInvocationScope {
            policy_generation_digest: &analysis.policy_generation_digest,
            tenant_id: &analysis.participant_id,
            privacy_domain_id: &analysis.privacy_domain_id,
            workload_id: &analysis.workload_id,
        },
    )?;
    let snapshot = source_snapshot::load(
        tx,
        &definition,
        &policies,
        source_snapshot::MethodState::PreparedOrActive,
    )
    .await?;
    let dependencies = derive_nested_dependencies(analysis, &definition)?;
    let configured = ConfiguredMethodProfile {
        grants: InteractionGrantSet {
            profile_id: definition.profile_id.clone(),
            profile_revision: definition.revision,
            profile_digest: definition.digest()?,
            participant_id: definition.participant_id.clone(),
            privacy_domain_id: definition.privacy_domain_id.clone(),
            status: GrantStatus::Active,
            grants: snapshot.grants,
        },
        definition,
    };
    configured.validate()?;
    Ok(CompiledReviewedProfile {
        configured,
        methods: snapshot.methods,
        grants: snapshot.versions,
        dependencies,
    })
}
