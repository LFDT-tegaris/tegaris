//! Composition of an exact approved queued selection. This prepares signed
//! installation inputs; the existing target activation/ACK owner produces effect.
use super::{
    profile_publication::{
        ProfilePublicationRequest, VerifiedProfilePublication, prepare_queued_publication,
    },
    reviewed_profile::InstalledAnalysisSources,
};
use pc_policy_core::{
    cigl::profile::ValidatedMethodProfile,
    contract_policy::CompiledContractPolicyBundle,
    invocation::{
        ActiveInvocationScope, ConfigurationArtifactKind, ConfigurationArtifactV1,
        ValidatedInvocationPolicy, active_invocation_workload,
        decode_active_invocation_configuration, decode_active_invocation_policy_generation,
        encode_active_invocation_configuration, encode_active_invocation_policy_generation,
    },
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Selection {
    pub(super) participant_epoch: String,
    pub(super) profiles: Vec<SelectedProfile>,
    #[serde(default)]
    pub(super) policy_renewal: Option<PolicyRenewal>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PolicyRenewal {
    activation_occurrence_ref: String,
    expected_revision: String,
    policy_generation_digest: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SelectedProfile {
    pub(super) profile_id: String,
    pub(super) profile_revision: String,
    pub(super) profile_digest: String,
    pub(super) compilation_artifact_digest: String,
    pub(super) grant_sources_digest: String,
}

fn digest(value: &str) -> RuntimeResult<Digest> {
    Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or(RuntimeError::InvalidDigest)?,
    )
}

fn base_policy_digest(policy: &ValidatedInvocationPolicy) -> RuntimeResult<Digest> {
    comparable_policy_digest(policy, false)
}

fn comparable_policy_digest(
    policy: &ValidatedInvocationPolicy,
    renewal: bool,
) -> RuntimeResult<Digest> {
    let mut artifact = policy.artifact().clone();
    // Root/profile binding is composed independently of the base selector,
    // roles, arguments, approval, MFA, RPC and configured source version.
    artifact.nested_call_set_digest = None;
    // load_active attaches the enclosing encoded policy digest to every node.
    // Composing a reviewed graph changes those bytes without changing the base
    // authority. Erase only that derived identity in this comparison-only copy;
    // the semantic generation, version and every authorization field remain.
    fn clear_encoded_identity(
        artifact: &mut pc_policy_core::invocation::InvocationPolicy,
        renewal: bool,
    ) {
        artifact.policy_artifact_digest = Digest::of([]);
        // Only the independently approved renewal can change the enclosing
        // generation. Method versions and every authorization field stay exact.
        if renewal {
            artifact.policy_generation_digest = Digest::of([]);
        }
        for nested in &mut artifact.nested_policies {
            clear_encoded_identity(nested, renewal);
        }
    }
    clear_encoded_identity(&mut artifact, renewal);
    Ok(Digest::of(canonical_bytes(&artifact)?))
}

/// Constructed only from the scoped approved work and its current signed
/// predecessor. Callers retain the source transaction through publication.
pub struct VerifiedProfileActivation {
    work_id: String,
    generation_digest: Digest,
    predecessor_digest: Digest,
    policy_generation_digest: Digest,
    participant_id: String,
    privacy_domain_id: String,
    workload_id: String,
    profiles: Vec<VerifiedProfilePublication>,
    base_policies: BTreeMap<String, Digest>,
    policy_renewal: bool,
}
impl VerifiedProfileActivation {
    pub fn require_profile_artifacts(
        &self,
        configuration: &pc_policy_core::invocation::ActiveInvocationConfigurationV1,
    ) -> RuntimeResult<()> {
        let supplied: Vec<_> = configuration
            .resource_artifacts
            .iter()
            .filter(|artifact| artifact.artifact_kind == ConfigurationArtifactKind::CiglProfile)
            .collect();
        if supplied.len() != self.profiles.len() {
            return Err(RuntimeError::GenerationMismatch);
        }
        for (artifact, profile) in supplied.into_iter().zip(&self.profiles) {
            let bytes = profile.configured().to_cbor()?;
            if artifact.artifact_id != profile.configured().definition.profile_id
                || artifact.artifact_digest != Digest::of(&bytes)
                || artifact.payload_cbor != bytes
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        Ok(())
    }

    pub fn require_work(
        &self,
        work_id: &str,
        generation: &Digest,
        predecessor: &Digest,
    ) -> RuntimeResult<()> {
        if self.work_id != work_id
            || &self.generation_digest != generation
            || &self.predecessor_digest != predecessor
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }

    /// Add reviewed graph bindings without modifying base policy versions or
    /// any shared grant. Input bytes remain caller-owned until every check passes.
    pub fn bind_invocation(
        &self,
        mut bundle: CompiledContractPolicyBundle,
    ) -> RuntimeResult<CompiledContractPolicyBundle> {
        let mut configuration = decode_active_invocation_configuration(
            &bundle.configuration_cbor,
            &bundle.configuration_digest,
        )?;
        let mut generation =
            decode_active_invocation_policy_generation(&bundle.policy_cbor, &bundle.policy_digest)?;
        if configuration
            .resource_artifacts
            .iter()
            .any(|artifact| artifact.artifact_kind == ConfigurationArtifactKind::CiglProfile)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let scope = ActiveInvocationScope {
            tenant_id: &self.participant_id,
            privacy_domain_id: &self.privacy_domain_id,
            workload_id: &self.workload_id,
            policy_generation_digest: &self.policy_generation_digest,
        };
        let policies = ValidatedInvocationPolicy::load_active(
            &bundle.configuration_cbor,
            &bundle.configuration_digest,
            &bundle.policy_cbor,
            &bundle.policy_digest,
            &scope,
        )?;
        for (id, expected) in &self.base_policies {
            let mut matching = policies.iter().filter(|policy| {
                policy
                    .configured_identity()
                    .is_ok_and(|identity| identity.contract_method_policy_id() == id)
            });
            let policy = matching.next().ok_or(RuntimeError::GenerationMismatch)?;
            if matching.next().is_some()
                || (if self.policy_renewal {
                    comparable_policy_digest(policy, true)?
                } else {
                    base_policy_digest(policy)?
                }) != *expected
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        for profile in &self.profiles {
            let configured = profile.configured();
            let mut roots = generation.assets.iter_mut().filter(|asset| {
                asset.asset_id == configured.definition.root_contract_method_policy_id
            });
            let root = roots.next().ok_or(RuntimeError::GenerationMismatch)?;
            if roots.next().is_some() || !root.active || root.method_required_roles.is_none() {
                return Err(RuntimeError::GenerationMismatch);
            }
            root.nested_call_set_digest = Some(configured.definition.digest()?);
            let bytes = configured.to_cbor()?;
            configuration
                .resource_artifacts
                .push(ConfigurationArtifactV1 {
                    artifact_id: configured.definition.profile_id.clone(),
                    artifact_kind: ConfigurationArtifactKind::CiglProfile,
                    artifact_digest: Digest::of(&bytes),
                    payload_cbor: bytes,
                });
        }
        bundle.configuration_cbor = encode_active_invocation_configuration(&configuration)?;
        bundle.configuration_digest = Digest::of(&bundle.configuration_cbor);
        bundle.policy_cbor = encode_active_invocation_policy_generation(&generation)?;
        bundle.policy_digest = Digest::of(&bundle.policy_cbor);
        bundle.policies = ValidatedInvocationPolicy::load_active(
            &bundle.configuration_cbor,
            &bundle.configuration_digest,
            &bundle.policy_cbor,
            &bundle.policy_digest,
            &scope,
        )?;
        let admitted = ValidatedMethodProfile::load_active(
            &bundle.configuration_cbor,
            &bundle.configuration_digest,
            &bundle.policy_cbor,
            &bundle.policy_digest,
            &scope,
        )?;
        if admitted.len() != self.profiles.len() {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(bundle)
    }
}

/// Preparation accepts the exact existing PENDING/LEASED work only. It does not
/// lease work, install artifacts, complete the operation or acknowledge a target.
pub async fn prepare_activation(
    tx: &mut Transaction<'_, Postgres>,
    installed: &InstalledAnalysisSources<'_>,
    compilation_verification_key: &[u8],
    work_id: &str,
) -> RuntimeResult<VerifiedProfileActivation> {
    sqlx::query("select openpc.lock_cigl_publication_participant()")
        .execute(&mut **tx)
        .await
        .map_err(|_| RuntimeError::InvalidAuthorization)?;
    sqlx::query("select openpc.lock_cigl_grant_sources()")
        .execute(&mut **tx)
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let (participant, privacy) = installed.invocation.source_scope();
    let predecessor_digest = installed.capsule.digest()?;
    let row = sqlx::query(r#"select generation.cigl_profile_selection,generation.generation_digest,generation.policy_generation_digest
      from control.configuration_work work
      join control.runtime_configuration_generation generation on generation.runtime_configuration_generation_id=work.runtime_configuration_generation_id
       and generation.participant_id=work.participant_id and generation.privacy_domain_id=work.privacy_domain_id
      join control.runtime_target target on target.runtime_target_id=generation.runtime_target_id
       and target.participant_id=work.participant_id and target.privacy_domain_id=work.privacy_domain_id
      join control.runtime_activation_observation observation on observation.runtime_target_id=target.runtime_target_id
       and observation.participant_id=work.participant_id and observation.privacy_domain_id=work.privacy_domain_id
       and observation.capsule_digest=target.active_generation_digest
      join control.runtime_configuration_generation previous on previous.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
       and previous.participant_id=work.participant_id and previous.privacy_domain_id=work.privacy_domain_id
       and previous.generation_digest=observation.generation_digest and previous.state='ACTIVE'
       and previous.policy_generation_digest=$6
       and (previous.policy_generation_digest=generation.policy_generation_digest
         or (generation.cigl_profile_selection ? 'policyRenewal' and exists(
          select 1 from control.policy_activation_occurrence occurrence
          join control.policy_activation_occurrence_target cohort on cohort.activation_occurrence_id=occurrence.activation_occurrence_id
           and cohort.participant_id=occurrence.participant_id and cohort.privacy_domain_id=occurrence.privacy_domain_id
          join control.policy_activation activation on activation.policy_activation_id=occurrence.activation_occurrence_id
           and activation.participant_id=occurrence.participant_id and activation.privacy_domain_id=occurrence.privacy_domain_id
           and activation.policy_generation_id=occurrence.policy_generation_id and activation.state='PREPARED'
          where occurrence.participant_id=work.participant_id and occurrence.privacy_domain_id=work.privacy_domain_id
           and cohort.configuration_work_id=work.configuration_work_id and cohort.runtime_target_id=work.runtime_target_id
           and cohort.runtime_configuration_generation_id=generation.runtime_configuration_generation_id and cohort.phase='FORWARD'
           and occurrence.state in ('STAGING','PARTIAL') and occurrence.total_target_count=1
           and 'urn:openpc:resource:'||occurrence.activation_occurrence_id::text=generation.cigl_profile_selection->'policyRenewal'->>'activationOccurrenceRef'
           and 'sha256:'||encode(occurrence.target_generation_digest,'hex')=generation.policy_generation_digest)))
       and previous.provider_profile_id=generation.provider_profile_id and previous.projection_plan_id=generation.projection_plan_id
      join control.configuration_work previous_work on previous_work.configuration_work_id=observation.configuration_work_id
       and previous_work.runtime_configuration_generation_id=previous.runtime_configuration_generation_id
       and previous_work.participant_id=work.participant_id and previous_work.privacy_domain_id=work.privacy_domain_id
       and previous_work.generation_digest=previous.generation_digest and previous_work.state='COMPLETED'
       and previous_work.configuration_digest=work.configuration_digest
      where work.configuration_work_id=$1::text::uuid and work.participant_id=$2::text::uuid and work.privacy_domain_id=$3::text::uuid
       and work.runtime_target_id=$4::text::uuid and work.resource_id=work.runtime_target_id
       and work.work_kind='RUNTIME_ACTIVATION' and work.state in ('PENDING','LEASED') and generation.state='ACTIVATING'
       and work.predecessor_digest=$5 and generation.predecessor_digest=$5 and target.active_generation_digest=$5
       and work.generation_digest=generation.generation_digest and target.desired_generation_digest=generation.generation_digest
       and work.policy_generation_digest=generation.policy_generation_digest and target.policy_generation_digest=generation.policy_generation_digest
       and target.state='STAGING' and generation.cigl_profile_selection is not null
       and exists(select 1 from control.mutation_candidate candidate join control.mutation_evidence evidence
         on evidence.operation_id=candidate.consumed_operation_id and evidence.participant_id=candidate.participant_id
          and evidence.privacy_domain_id=candidate.privacy_domain_id and evidence.candidate_digest=candidate.candidate_digest
          and evidence.catalog_operation_id=candidate.catalog_operation_id
         where candidate.consumed_operation_id=work.operation_id and candidate.participant_id=work.participant_id
          and candidate.privacy_domain_id=work.privacy_domain_id and candidate.resource_id=work.runtime_target_id
          and candidate.catalog_operation_id='CFG-OP-ACTIVATE-CIGL-PROFILES' and candidate.action_intent_id='ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1'
          and candidate.state='CONSUMED' and evidence.action_intent_id=candidate.action_intent_id
          and evidence.aggregate_id=work.runtime_target_id and evidence.aggregate_type='runtime-targets'
          and evidence.aggregate_version=candidate.expected_revision+1 and target.revision=evidence.aggregate_version
          and work.input_digest='sha256:'||encode(candidate.candidate_digest,'hex')
          and candidate.candidate_document->>'expectedGenerationDigest'=$5
          and (jsonb_build_object('participantEpoch',candidate.candidate_document->'participantEpoch','profiles',candidate.candidate_document->'profiles') || CASE WHEN candidate.candidate_document ? 'policyRenewal' THEN jsonb_build_object('policyRenewal',candidate.candidate_document->'policyRenewal') ELSE '{}'::jsonb END)=generation.cigl_profile_selection
          and generation.generation_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
            'purpose','openpc.runtime.cigl-profile-selection.v1','baseCapsuleDigest',$5,'selection',generation.cigl_profile_selection)),'UTF8')),'hex'))
       for share of generation,target"#)
        .bind(work_id).bind(participant).bind(privacy).bind(&installed.capsule.target_runtime_id)
        .bind(format!("sha256:{}", predecessor_digest.as_str()))
        .bind(format!("sha256:{}", installed.capsule.policy_bundle_digest.as_str()))
        .fetch_optional(&mut **tx).await.map_err(|_| RuntimeError::RuntimeUnavailable)?
        .ok_or(RuntimeError::GenerationMismatch)?;
    let selection: Selection = serde_json::from_value(
        row.try_get::<Value, _>("cigl_profile_selection")
            .map_err(|_| RuntimeError::InvalidInput)?,
    )
    .map_err(|_| RuntimeError::InvalidInput)?;
    if selection.profiles.is_empty() || selection.profiles.len() > 64 {
        return Err(RuntimeError::BudgetExhausted);
    }
    let participant_epoch = selection
        .participant_epoch
        .parse::<u64>()
        .map_err(|_| RuntimeError::InvalidInput)?;
    if let Some(renewal) = &selection.policy_renewal
        && (!renewal
            .activation_occurrence_ref
            .starts_with("urn:openpc:resource:")
            || renewal
                .expected_revision
                .parse::<u64>()
                .map_err(|_| RuntimeError::InvalidInput)?
                == 0
            || renewal.policy_generation_digest
                != row
                    .try_get::<String, _>("policy_generation_digest")
                    .map_err(|_| RuntimeError::InvalidInput)?)
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    let policy_renewal = selection.policy_renewal.is_some();
    let mut profiles = Vec::with_capacity(selection.profiles.len());
    let mut roots = BTreeSet::new();
    let mut last = "";
    for selected in &selection.profiles {
        if selected.profile_id.as_str() <= last {
            return Err(RuntimeError::InvalidInput);
        }
        last = &selected.profile_id;
        let profile = prepare_queued_publication(
            tx,
            installed,
            compilation_verification_key,
            &ProfilePublicationRequest {
                profile_id: selected
                    .profile_id
                    .strip_prefix("urn:openpc:resource:")
                    .ok_or(RuntimeError::InvalidInput)?,
                revision: selected
                    .profile_revision
                    .parse()
                    .map_err(|_| RuntimeError::InvalidInput)?,
                profile_digest: &digest(&selected.profile_digest)?,
                compilation_artifact_digest: &digest(&selected.compilation_artifact_digest)?,
                current_grants_digest: &digest(&selected.grant_sources_digest)?,
                participant_epoch,
            },
            work_id,
        )
        .await?;
        if !roots.insert(
            profile
                .configured()
                .definition
                .root_contract_method_policy_id
                .clone(),
        ) {
            return Err(RuntimeError::InvalidInput);
        }
        profiles.push(profile);
    }
    let (configuration, policy) = installed
        .invocation
        .analysis_source_bytes(installed.capsule, installed.artifacts)?;
    let configuration_digest = Digest::of(configuration);
    let workload_id =
        active_invocation_workload(configuration, &configuration_digest, participant, privacy)?;
    let policy_generation_digest = digest(
        &row.try_get::<String, _>("policy_generation_digest")
            .map_err(|_| RuntimeError::InvalidInput)?,
    )?;
    let policies = ValidatedInvocationPolicy::load_active(
        configuration,
        &configuration_digest,
        policy,
        &Digest::of(policy),
        &ActiveInvocationScope {
            tenant_id: participant,
            privacy_domain_id: privacy,
            workload_id: &workload_id,
            policy_generation_digest: &installed.capsule.policy_bundle_digest,
        },
    )?;
    let mut base_policies = BTreeMap::new();
    for profile in &profiles {
        for method in profile.methods() {
            if base_policies.contains_key(&method.method_id) {
                continue;
            }
            let source = policies
                .iter()
                .find(|policy| {
                    policy.configured_identity().is_ok_and(|identity| {
                        identity.contract_method_policy_id() == method.method_id
                    })
                })
                .ok_or(RuntimeError::GenerationMismatch)?;
            base_policies.insert(
                method.method_id.clone(),
                if policy_renewal {
                    comparable_policy_digest(source, true)?
                } else {
                    base_policy_digest(source)?
                },
            );
        }
    }
    Ok(VerifiedProfileActivation {
        work_id: work_id.into(),
        generation_digest: digest(
            &row.try_get::<String, _>("generation_digest")
                .map_err(|_| RuntimeError::InvalidInput)?,
        )?,
        predecessor_digest,
        policy_generation_digest,
        participant_id: participant.into(),
        privacy_domain_id: privacy.into(),
        workload_id,
        profiles,
        base_policies,
        policy_renewal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_authority_survives_reviewed_binding_but_rejects_semantic_changes() {
        let fixture = crate::local_fixture::build_local_configuration_fixture(
            None,
            None,
            None,
            Some("cigl-renewal-workload"),
        )
        .unwrap();
        let bytes = |hex: &str| {
            (0..hex.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let configuration = bytes(&fixture.configuration_cbor_hex);
        let original = bytes(&fixture.policy_cbor_hex);
        let configuration_digest = Digest::of(&configuration);
        let configured =
            decode_active_invocation_configuration(&configuration, &configuration_digest).unwrap();
        let identity = &configured.assets[0];
        let generation = digest(&fixture.policy_generation_digest).unwrap();
        let scope = ActiveInvocationScope {
            tenant_id: &identity.tenant_id,
            privacy_domain_id: &identity.privacy_domain_id,
            workload_id: &identity.workload_id,
            policy_generation_digest: &generation,
        };
        let load = |encoded: &[u8]| {
            ValidatedInvocationPolicy::load_active(
                &configuration,
                &configuration_digest,
                encoded,
                &Digest::of(encoded),
                &scope,
            )
            .unwrap()
            .remove(0)
        };
        let before = load(&original);
        let mut composed =
            decode_active_invocation_policy_generation(&original, &Digest::of(&original)).unwrap();
        composed.assets[0].nested_call_set_digest = Some(Digest::of("reviewed profile"));
        let installed = load(&encode_active_invocation_policy_generation(&composed).unwrap());
        assert_ne!(
            before.artifact().policy_artifact_digest,
            installed.artifact().policy_artifact_digest
        );
        assert_eq!(
            base_policy_digest(&before).unwrap(),
            base_policy_digest(&installed).unwrap(),
            "a reviewed graph changes encoded artifact identity, not base authority"
        );
        let mut parent = before.artifact().clone();
        let mut child = parent.clone();
        child.canonical_signature = "nestedRead(uint256)".into();
        child.selector = [2, 3, 4, 5];
        parent.nested_policies.push(child);
        let nested_before =
            base_policy_digest(&ValidatedInvocationPolicy::try_new(parent.clone()).unwrap())
                .unwrap();
        parent.policy_artifact_digest = installed.artifact().policy_artifact_digest.clone();
        parent.nested_policies[0].policy_artifact_digest = parent.policy_artifact_digest.clone();
        assert_eq!(
            base_policy_digest(&ValidatedInvocationPolicy::try_new(parent.clone()).unwrap())
                .unwrap(),
            nested_before
        );
        parent.nested_policies[0]
            .required_roles
            .push("unreviewed-nested-role".into());
        assert_ne!(
            base_policy_digest(&ValidatedInvocationPolicy::try_new(parent).unwrap()).unwrap(),
            nested_before
        );
        let expected = base_policy_digest(&installed).unwrap();
        let original = installed.artifact();
        let mut changes = Vec::new();
        let mut changed = original.clone();
        changed.required_roles.push("unreviewed-role".into());
        changes.push(changed);
        let mut changed = original.clone();
        changed.webauthn_required = !changed.webauthn_required;
        changes.push(changed);
        let mut changed = original.clone();
        changed.approval = pc_policy_core::invocation::ApprovalRequirement::MakerChecker;
        changes.push(changed);
        let mut changed = original.clone();
        changed.code_digest = Digest::of("other deployed code");
        changes.push(changed);
        let mut changed = original.clone();
        changed.policy_generation_digest = Digest::of("other semantic generation");
        assert_eq!(
            comparable_policy_digest(
                &ValidatedInvocationPolicy::try_new(changed.clone()).unwrap(),
                true
            )
            .unwrap(),
            comparable_policy_digest(&installed, true).unwrap(),
            "only a governed renewal may compare across independently approved generations"
        );
        changes.push(changed);
        let mut changed = original.clone();
        changed.policy_version = "2.0.0".into();
        changes.push(changed);
        for changed in changes {
            if changed.policy_generation_digest == original.policy_generation_digest {
                assert_ne!(
                    comparable_policy_digest(
                        &ValidatedInvocationPolicy::try_new(changed.clone()).unwrap(),
                        true
                    )
                    .unwrap(),
                    comparable_policy_digest(&installed, true).unwrap(),
                    "renewal must reject changed method authority, versions and code"
                );
            }
            assert_ne!(
                base_policy_digest(&ValidatedInvocationPolicy::try_new(changed).unwrap()).unwrap(),
                expected
            );
        }
    }
}
