//! Dedicated source-policy custody, independent of invocation and fact serving.
//! A signed source policy is a restriction, never a source grant or Fact shard.
use crate::{
    ActiveCapsuleLease, ArtifactAdmission, ArtifactComponent, RuntimeCapsule, RuntimeWireVerifier,
    WorkloadPeer,
    authority_artifact::AuthoritySourceBinding,
    identity_custody::IdentityArtifactAdmission,
    identity_state::{RuntimeAuthorityRequest, WorkloadAuthorization},
};
use pc_policy_core::{
    indexer_policy::{IndexerPolicy, IndexerPolicyRequest, evaluate_indexer_policies},
    invocation::{
        ActiveInvocationScope, ValidatedInvocationPolicy, active_invocation_workload,
        decode_active_invocation_policy_generation,
    },
    rpc_policy::RpcSurfacePolicy,
    semantics::FactReference,
    visibility_policy::VisibilityPolicy,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub const CONFIGURATION_ARTIFACT_ID: &str = "openpc.indexer.configuration";
pub const CONFIGURATION_DEFINITION: &[u8] = b"openpc.indexer.configuration-source.v1";
pub const POLICY_ARTIFACT_ID: &str = "openpc.indexer.policy";
pub const POLICY_DEFINITION: &[u8] = b"openpc.indexer.policy-source.v1";
/// No Fact publication is carried by this custody mode. This marker can never
/// satisfy FactArtifactAdmission or a required fact.
pub const NO_FACT_PUBLICATION: &[u8] = b"openpc.indexer.no-fact-publication.v1";

pub struct IndexerArtifactAdmission {
    verifier: RuntimeWireVerifier,
    participant_id: String,
    privacy_domain_id: String,
    configuration: AuthoritySourceBinding,
    policy: AuthoritySourceBinding,
    remaining: Arc<dyn ArtifactAdmission>,
}

/// Exact restrictions from an admitted capsule. This object does
/// not authorize I/O: the dispatcher must also hold current identity, scoped
/// source permission, source qualification and any required Fact dependencies.
pub struct InstalledIndexerPolicies {
    pub(crate) participant_id: String,
    pub(crate) privacy_domain_id: String,
    pub(crate) workload_id: String,
    pub(crate) capsule_digest: Digest,
    pub(crate) policy_generation_digest: Digest,
    pub(crate) policies: Vec<IndexerPolicy>,
    pub(crate) visibility_policies: Vec<VisibilityPolicy>,
    pub(crate) rpc_policies: Vec<RpcSurfacePolicy>,
    pub(crate) required_facts: Vec<FactReference>,
}

pub struct IndexerRestrictions<'a> {
    pub policies: &'a [IndexerPolicy],
    /// These restrictions never supply a source-read grant. A visibility
    /// consumer must separately evaluate its exact resource and Fact inputs.
    pub visibility_policies: &'a [VisibilityPolicy],
    pub rpc_policies: &'a [RpcSurfacePolicy],
    pub required_facts: &'a [FactReference],
}

impl InstalledIndexerPolicies {
    /// Workload bound by the authenticated configuration and policy sources.
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    /// Intersect the actual workload's scoped source-read grant with the
    /// installed restrictions. Identity is re-derived from this same capsule,
    /// never supplied as caller roles or a prior authorization result. The
    /// dispatcher must separately fence current source qualification, generation
    /// and the exact decoded provider request through I/O and response release.
    pub fn authorize_source_policy(
        &self,
        identity: &IdentityArtifactAdmission,
        active: &ActiveCapsuleLease<'_>,
        peer: &WorkloadPeer,
        request: &IndexerPolicyRequest<'_>,
        now_ns: u64,
    ) -> RuntimeResult<WorkloadAuthorization> {
        active.revalidate(now_ns)?;
        let capsule = active.capsule();
        let restrictions = self.restrictions_for(peer, &self.privacy_domain_id, capsule)?;
        let (identities, _) = identity.admit_identity(capsule, active.artifacts()?)?;
        let mut authorization = identities.authorize(
            peer,
            &RuntimeAuthorityRequest {
                action_intent_id: "ACT-RUNTIME_READ_RPC-V1",
                resource_id: request.indexer_profile_id,
                risk_class: "LOW",
            },
            now_ns,
        )?;
        let scopes = [
            format!("urn:openpc:participant:{}", self.participant_id),
            format!("urn:openpc:privacy-domain:{}", self.privacy_domain_id),
            format!(
                "urn:openpc:principal:{}",
                authorization.authorization.facts().actor_principal_id
            ),
            self.workload_id.clone(),
            format!("urn:openpc:resource:{}", request.indexer_profile_id),
            format!("urn:openpc:resource:{}", request.projection_plan_id),
        ];
        if active.denies_any_scope(scopes.iter().map(String::as_str)) {
            return Err(RuntimeError::Denied);
        }
        evaluate_indexer_policies(
            restrictions.policies,
            request,
            &authorization.authorization,
            restrictions.rpc_policies,
        )?;
        authorization.valid_until_ns = authorization.valid_until_ns.min(active.expires_at_ns());
        Ok(authorization)
    }

    pub fn restrictions_for(
        &self,
        peer: &WorkloadPeer,
        privacy_domain_id: &str,
        capsule: &RuntimeCapsule,
    ) -> RuntimeResult<IndexerRestrictions<'_>> {
        if peer.participant_id() != self.participant_id
            || peer.workload_id() != self.workload_id
            || privacy_domain_id != self.privacy_domain_id
            || capsule.digest()? != self.capsule_digest
            || capsule.policy_bundle_digest != self.policy_generation_digest
        {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok(IndexerRestrictions {
            policies: &self.policies,
            visibility_policies: &self.visibility_policies,
            rpc_policies: &self.rpc_policies,
            required_facts: &self.required_facts,
        })
    }
}

impl IndexerArtifactAdmission {
    pub fn new(
        verifier: RuntimeWireVerifier,
        participant_id: String,
        privacy_domain_id: String,
        configuration: AuthoritySourceBinding,
        policy: AuthoritySourceBinding,
        remaining: Arc<dyn ArtifactAdmission>,
    ) -> RuntimeResult<Self> {
        if participant_id.is_empty()
            || privacy_domain_id.is_empty()
            || configuration.artifact_id == policy.artifact_id
            || configuration.source_media_type != "application/cbor"
            || policy.source_media_type != "application/cbor"
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            verifier,
            participant_id,
            privacy_domain_id,
            configuration,
            policy,
            remaining,
        })
    }

    pub fn admit_policies(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<(InstalledIndexerPolicies, BTreeSet<Digest>)> {
        let (configuration_component, configuration, configuration_bytes) = self
            .configuration
            .in_capsule(&self.verifier, capsule, artifacts)?;
        let (policy_component, policy, policy_bytes) =
            self.policy.in_capsule(&self.verifier, capsule, artifacts)?;
        if policy.source_content_sha256 != capsule.semantic_model_digest
            || configuration.source_content_sha256 != capsule.named_set_registry_digest
        {
            return Err(RuntimeError::InvalidDigest);
        }
        let workload_id = active_invocation_workload(
            configuration_bytes,
            &configuration.source_content_sha256,
            &self.participant_id,
            &self.privacy_domain_id,
        )?;
        let scope = ActiveInvocationScope {
            policy_generation_digest: &capsule.policy_bundle_digest,
            tenant_id: &self.participant_id,
            privacy_domain_id: &self.privacy_domain_id,
            workload_id: &workload_id,
        };
        let invocation = ValidatedInvocationPolicy::load_active(
            configuration_bytes,
            &configuration.source_content_sha256,
            policy_bytes,
            &policy.source_content_sha256,
            &scope,
        )?;
        let generation = decode_active_invocation_policy_generation(
            policy_bytes,
            &policy.source_content_sha256,
        )?;
        if !invocation.is_empty()
            || !generation.assets.is_empty()
            || !generation.root_asset_ids.is_empty()
            || !generation.deployment_policies.is_empty()
            || (generation.indexer_policies.is_empty() && generation.visibility_policies.is_empty())
            || !generation.required_facts.is_empty()
            || capsule.policy_fact_state_digest != Digest::of(NO_FACT_PUBLICATION)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok((
            InstalledIndexerPolicies {
                participant_id: self.participant_id.clone(),
                privacy_domain_id: self.privacy_domain_id.clone(),
                workload_id,
                capsule_digest: capsule.digest()?,
                policy_generation_digest: capsule.policy_bundle_digest.clone(),
                policies: generation.indexer_policies,
                visibility_policies: generation.visibility_policies,
                rpc_policies: generation.rpc_policies,
                required_facts: generation.required_facts,
            },
            BTreeSet::from([
                configuration_component.content_digest.clone(),
                configuration.source_content_sha256,
                policy_component.content_digest.clone(),
                policy.source_content_sha256,
            ]),
        ))
    }
}

impl ArtifactAdmission for IndexerArtifactAdmission {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        if component.component_id == self.configuration.artifact_id
            || component.component_id == self.policy.artifact_id
        {
            return Err(RuntimeError::InvalidInput);
        }
        self.remaining.validate(component, bytes)
    }
    fn validate_component_in_bundle(
        &self,
        capsule: &RuntimeCapsule,
        component: &ArtifactComponent,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        if component.component_id == self.configuration.artifact_id
            || component.component_id == self.policy.artifact_id
        {
            self.admit_policies(capsule, artifacts)
                .map(|(_, closure)| closure)
        } else {
            self.remaining
                .validate_component_in_bundle(capsule, component, artifacts)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeWireSigner, authority_artifact::AuthorityArtifact};
    use pc_policy_core::invocation::{
        ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1,
        encode_active_invocation_configuration, encode_active_invocation_policy_generation,
    };

    #[test]
    fn signed_source_and_visibility_custody_binds_exact_compilation_scope() {
        let participant = "018f0000-0000-7000-8000-000000000101";
        let privacy = "018f0000-0000-7000-8000-000000000201";
        let workload = "urn:openpc:workload:018f0000-0000-7000-8000-000000000191";
        let selector = serde_json::json!({"kind":"TRANSACTION", "runtimeBindingId":"018f0000-0000-7000-8000-000000000501", "bindingRevision":"1"});
        let visibility: VisibilityPolicy = serde_json::from_value(serde_json::json!({
            "policyId":"018f0000-0000-7000-8000-000000000901", "selector":selector,
            "mode":"STATIC", "effect":"ALLOW", "subject":{"kind":"PRINCIPAL", "principalId":"018f0000-0000-7000-8000-000000000301"},
            "purpose":"AUDIT", "requiredRoles":["reader"], "dimensions":["EXISTENCE","PAYLOAD"], "fields":["from"], "conditions":[]
        })).unwrap();
        let configuration = ActiveInvocationConfigurationV1 {
            workload_scope: Some(pc_policy_core::invocation::InvocationConfigurationScope {
                participant_id: participant.into(),
                privacy_domain_id: privacy.into(),
                workload_id: workload.into(),
            }),
            visibility_resources: vec![
                pc_policy_core::visibility_policy::AdmittedVisibilityResource {
                    state_output_types: None,
                    contract_binding: None,
                    participant_id: participant.into(),
                    privacy_domain_id: privacy.into(),
                    selector: visibility.selector.clone(),
                    available_fields: vec!["from".into()],
                },
            ],
            schema_version: "1.0".into(),
            assets: vec![],
            resource_artifacts: vec![],
            deployment_policies: vec![],
        };
        let generation = ActiveInvocationPolicyGenerationV1 {
            visibility_policies: vec![visibility],
            fact_conditions: vec![],
            indexer_policies: vec![],
            schema_version: "1.0".into(),
            root_asset_ids: vec![],
            assets: vec![],
            rpc_policies: vec![],
            required_facts: vec![],
            deployment_policies: vec![],
        };
        struct RejectOther;
        impl ArtifactAdmission for RejectOther {
            fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
                Err(RuntimeError::InvalidInput)
            }
        }
        let signer = RuntimeWireSigner::from_secret_bytes([37; 32]).unwrap();
        for mutation in 0..6 {
            let mut configuration = configuration.clone();
            let mut generation = generation.clone();
            if mutation == 5 {
                generation.required_facts.push(FactReference {
                    candidate_id: "018f0000-0000-7000-8000-000000000801".into(),
                    generation_id: "018f0000-0000-7000-8000-000000000802".into(),
                    fact_digest: format!("sha256:{}", Digest::of("fact").as_str()),
                });
            }
            match mutation {
                1 => {
                    configuration
                        .workload_scope
                        .as_mut()
                        .unwrap()
                        .participant_id = "foreign".into()
                }
                2 => {
                    configuration
                        .workload_scope
                        .as_mut()
                        .unwrap()
                        .privacy_domain_id = "foreign".into()
                }
                3 => configuration.workload_scope = None,
                _ => {}
            }
            let mut capsule = crate::wire_tests::capsule();
            capsule.artifact_components.clear();
            capsule.policy_fact_state_digest = Digest::of(NO_FACT_PUBLICATION);
            let mut artifacts = BTreeMap::new();
            let mut add = |id: &str, definition: &[u8], bytes: Vec<u8>| {
                let header = AuthorityArtifact {
                    artifact_id: id.into(),
                    artifact_version: 1,
                    artifact_class: 1,
                    source_media_type: "application/cbor".into(),
                    source_content_sha256: Digest::of(&bytes),
                    definition_digest: Digest::of(definition),
                    issued_at_ns: capsule.issued_at_ns,
                    signer_id: "fixture-source-owner".into(),
                };
                let signed = signer.sign_authority_artifact(&header).unwrap();
                capsule.artifact_components.push(ArtifactComponent {
                    component_id: id.into(),
                    component_type: "canonical-authority".into(),
                    content_digest: Digest::of(&signed),
                    semantic_digest: header.semantic_digest().unwrap(),
                    schema_id: 1010,
                    schema_version: 1,
                    size_bytes: signed.len() as u64,
                    required: true,
                });
                artifacts.insert(header.source_content_sha256.clone(), bytes);
                artifacts.insert(Digest::of(&signed), signed);
                (
                    AuthoritySourceBinding {
                        artifact_id: id.into(),
                        artifact_class: 1,
                        source_media_type: header.source_media_type,
                        definition_digest: header.definition_digest,
                        signer_id: header.signer_id,
                        maximum_source_bytes: 1024 * 1024,
                    },
                    header.source_content_sha256,
                )
            };
            let (configuration_binding, configuration_digest) = add(
                CONFIGURATION_ARTIFACT_ID,
                CONFIGURATION_DEFINITION,
                encode_active_invocation_configuration(&configuration).unwrap(),
            );
            let (policy_binding, policy_digest) = add(
                POLICY_ARTIFACT_ID,
                POLICY_DEFINITION,
                encode_active_invocation_policy_generation(&generation).unwrap(),
            );
            capsule.named_set_registry_digest = configuration_digest;
            capsule.semantic_model_digest = policy_digest;
            capsule
                .artifact_components
                .sort_by_key(|component| component.canonical_bytes().unwrap());
            if mutation == 4 {
                capsule.policy_fact_state_digest = Digest::of(b"foreign fact publication");
            }
            let copy_binding = |binding: &AuthoritySourceBinding| AuthoritySourceBinding {
                artifact_id: binding.artifact_id.clone(),
                artifact_class: binding.artifact_class,
                source_media_type: binding.source_media_type.clone(),
                definition_digest: binding.definition_digest.clone(),
                signer_id: binding.signer_id.clone(),
                maximum_source_bytes: binding.maximum_source_bytes,
            };
            let invocation = crate::invocation_custody::InvocationArtifactAdmission::new(
                signer.verifier(),
                participant.into(),
                privacy.into(),
                copy_binding(&configuration_binding),
                copy_binding(&policy_binding),
                Arc::new(RejectOther),
            )
            .unwrap();
            let mixed = invocation.admit_policies(&capsule, &artifacts);
            if matches!(mutation, 0 | 4 | 5) {
                let projected = mixed.unwrap().0.into_indexer_policies();
                assert_eq!(projected.workload_id, workload);
                assert_eq!(projected.capsule_digest, capsule.digest().unwrap());
                assert_eq!(
                    projected.policy_generation_digest,
                    capsule.policy_bundle_digest
                );
                assert_eq!(projected.policies, generation.indexer_policies);
                assert_eq!(
                    projected.visibility_policies,
                    generation.visibility_policies
                );
                assert_eq!(projected.required_facts, generation.required_facts);
                let mut tampered = artifacts.clone();
                tampered
                    .get_mut(&capsule.semantic_model_digest)
                    .unwrap()
                    .push(0);
                assert!(invocation.admit_policies(&capsule, &tampered).is_err());
            } else {
                assert!(mixed.is_err(), "mixed scope mutation {mutation}");
            }
            let admission = IndexerArtifactAdmission::new(
                signer.verifier(),
                participant.into(),
                privacy.into(),
                configuration_binding,
                policy_binding,
                Arc::new(RejectOther),
            )
            .unwrap();
            let result = admission.admit_policies(&capsule, &artifacts);
            if mutation == 0 {
                let (installed, _) = result.unwrap();
                assert_eq!(installed.workload_id, workload);
                assert_eq!(
                    installed.visibility_policies,
                    generation.visibility_policies
                );
                assert_eq!(installed.policies, generation.indexer_policies);
                assert!(installed.rpc_policies.is_empty());
                assert!(installed.required_facts.is_empty());
            } else {
                assert!(result.is_err(), "mutation {mutation}");
            }
        }
    }
}
