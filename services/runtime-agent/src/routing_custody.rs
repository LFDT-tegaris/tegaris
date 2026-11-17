//! Target-local admission of the routing and certification publishers' source
//! documents. Both sources remain distinct primary 1010 authorities. A request
//! witness cannot supply assignments, qualification, risk, or current facts.
use crate::{
    ArtifactAdmission, ArtifactComponent, RuntimeCapsule, RuntimeWireVerifier,
    authority_artifact::AuthoritySourceBinding,
};
use openpc_multi_rpc::{provider_connection::ConnectionRecord, route_witness::RequestRouteWitness};
use pc_policy_core::{
    pc_cbor_1,
    semantics::{FactReference, validate_fact_references},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeRequest, RuntimeResult};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Publisher source format, not a new primary wire identity. The routing
/// publisher derives these rows from the governed assignment and method owners.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingSnapshotSource {
    pub version: u32,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub target_id: String,
    pub runtime_generation: u64,
    pub policy_generation_digest: Digest,
    pub mrpc_runtime_profile_digest: Digest,
    pub assignments: Vec<RoutingAssignment>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingAssignment {
    pub runtime_binding_id: String,
    pub method: String,
    pub risk_class: String,
    pub provider_profile_id: String,
    pub endpoint_id: String,
    pub endpoint_role: u64,
    pub purpose: u64,
    pub chain_environment_id: String,
    pub canonical_generation: u64,
    pub invalidation_generation: u64,
    pub coherence_group_digest: Digest,
    pub valid_until_ns: u64,
    pub required_facts: Vec<FactReference>,
}

/// Only independently approved certifications are published here. A target's
/// prepared socket or a successful probe is never sufficient to create a row.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCertificationSource {
    pub version: u32,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub target_id: String,
    pub runtime_generation: u64,
    pub policy_generation_digest: Digest,
    pub mrpc_runtime_profile_digest: Digest,
    pub certifications: Vec<ProviderCertification>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCertification {
    pub provider_profile_id: String,
    pub provider_artifact_digest: Digest,
    pub provider_profile_cbor: Vec<u8>,
    pub endpoint_id: String,
    pub connection_configuration_digest: Digest,
    pub valid_from_ns: u64,
    pub valid_until_ns: u64,
    pub required_facts: Vec<FactReference>,
}
pub struct RoutingArtifactAdmission {
    verifier: RuntimeWireVerifier,
    routing: AuthoritySourceBinding,
    certification: AuthoritySourceBinding,
    participant: String,
    privacy: String,
    remaining: Arc<dyn ArtifactAdmission>,
}
pub struct InstalledRoutingAuthority {
    routing: RoutingSnapshotSource,
    certification: ProviderCertificationSource,
}
pub struct AdmittedRequestRoute<'a> {
    pub assignment: &'a RoutingAssignment,
    pub certification: &'a ProviderCertification,
}
fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> RuntimeResult<T> {
    let value: T = ciborium::de::from_reader(bytes).map_err(|_| RuntimeError::InvalidInput)?;
    if pc_cbor_1(&value) != bytes {
        return Err(RuntimeError::CanonicalEncoding);
    }
    Ok(value)
}
impl RoutingArtifactAdmission {
    pub fn new(
        verifier: RuntimeWireVerifier,
        routing: AuthoritySourceBinding,
        certification: AuthoritySourceBinding,
        participant: String,
        privacy: String,
        remaining: Arc<dyn ArtifactAdmission>,
    ) -> RuntimeResult<Self> {
        if routing.artifact_id == certification.artifact_id
            || routing.source_media_type != "application/cbor"
            || certification.source_media_type != "application/cbor"
        {
            return Err(RuntimeError::InvalidInput);
        }
        crate::capsule::text(&participant, 160)?;
        crate::capsule::text(&privacy, 160)?;
        Ok(Self {
            verifier,
            routing,
            certification,
            participant,
            privacy,
            remaining,
        })
    }
    pub fn admit(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<(InstalledRoutingAuthority, BTreeSet<Digest>)> {
        let (rc, rh, rb) = self
            .routing
            .in_capsule(&self.verifier, capsule, artifacts)
            .inspect_err(|error| {
                eprintln!("runtime_routing_admission stage=routing_binding reason={error:?}")
            })?;
        let (cc, ch, cb) = self
            .certification
            .in_capsule(&self.verifier, capsule, artifacts)
            .inspect_err(|error| {
                eprintln!("runtime_routing_admission stage=certification_binding reason={error:?}")
            })?;
        if rc.semantic_digest != capsule.routing_snapshot_digest
            || cc.semantic_digest != capsule.provider_certification_registry_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let routing: RoutingSnapshotSource = decode(rb).inspect_err(|error| {
            eprintln!("runtime_routing_admission stage=routing_source reason={error:?}")
        })?;
        let certification: ProviderCertificationSource = decode(cb).inspect_err(|error| {
            eprintln!("runtime_routing_admission stage=certification_source reason={error:?}")
        })?;
        if routing.version != 1
            || certification.version != 1
            || routing.participant_id != self.participant
            || certification.participant_id != self.participant
            || routing.privacy_domain_id != self.privacy
            || certification.privacy_domain_id != self.privacy
            || routing.target_id != capsule.target_runtime_id
            || certification.target_id != capsule.target_runtime_id
            || routing.runtime_generation != capsule.generation
            || certification.runtime_generation != capsule.generation
            || routing.policy_generation_digest != capsule.policy_bundle_digest
            || certification.policy_generation_digest != capsule.policy_bundle_digest
            || routing.mrpc_runtime_profile_digest != capsule.mrpc_runtime_profile_digest
            || certification.mrpc_runtime_profile_digest != capsule.mrpc_runtime_profile_digest
            || routing.assignments.is_empty()
            || routing.assignments.len() > 256
            || certification.certifications.is_empty()
            || certification.certifications.len() > 256
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let mut assignment_keys = BTreeSet::new();
        for a in &routing.assignments {
            if !uuid::Uuid::parse_str(&a.runtime_binding_id)
                .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == a.runtime_binding_id)
                || !matches!(
                    (a.method.as_str(), a.purpose, a.endpoint_role),
                    ("eth_call", 1, 1..=3)
                        | (
                            "eth_getTransactionByHash"
                                | "eth_getTransactionReceipt"
                                | "eth_getLogs",
                            1,
                            1..=3
                        )
                        | ("eth_sendRawTransaction", 3, 4)
                        | ("eth_getTransactionReceipt", 4, 1..=4)
                )
                || !matches!(
                    a.risk_class.as_str(),
                    "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
                )
                || a.canonical_generation == 0
                || a.invalidation_generation == 0
                || a.valid_until_ns <= capsule.not_before_ns
                || !assignment_keys.insert((&a.runtime_binding_id, &a.method))
            {
                eprintln!(
                    "runtime_routing_admission stage=assignment_constraints index={} reason=InvalidAuthorization",
                    assignment_keys.len()
                );
                return Err(RuntimeError::InvalidAuthorization);
            }
            for value in [
                &a.provider_profile_id,
                &a.endpoint_id,
                &a.chain_environment_id,
            ] {
                crate::capsule::text(value, 160)?;
            }
            if !a.required_facts.is_empty() {
                validate_fact_references(&a.required_facts)
                    .map_err(|_| RuntimeError::InvalidAuthorization)?;
            }
        }
        let mut certification_keys = BTreeSet::new();
        for c in &certification.certifications {
            if c.valid_from_ns >= c.valid_until_ns
                || c.valid_until_ns <= capsule.not_before_ns
                || !certification_keys.insert((&c.provider_profile_id, &c.endpoint_id))
            {
                eprintln!(
                    "runtime_routing_admission stage=certification_constraints index={} reason=InvalidAuthorization",
                    certification_keys.len()
                );
                return Err(RuntimeError::InvalidAuthorization);
            }
            crate::capsule::text(&c.provider_profile_id, 160)?;
            crate::capsule::text(&c.endpoint_id, 160)?;
            openpc_multi_rpc::qualify_provider_profile(
                &c.provider_profile_cbor,
                &format!("sha256:{}", c.provider_artifact_digest.as_str()),
            )
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
            if !c.required_facts.is_empty() {
                validate_fact_references(&c.required_facts)
                    .map_err(|_| RuntimeError::InvalidAuthorization)?;
            }
        }
        Ok((
            InstalledRoutingAuthority {
                routing,
                certification,
            },
            BTreeSet::from([
                rc.content_digest.clone(),
                rh.source_content_sha256,
                cc.content_digest.clone(),
                ch.source_content_sha256,
            ]),
        ))
    }
}
impl InstalledRoutingAuthority {
    pub(crate) fn source_digest(&self) -> Digest {
        Digest::of(pc_cbor_1(&self.routing))
    }
    /// A started operation has independent observation-route custody. Original
    /// invocation permission or a matching write endpoint cannot supply it.
    pub fn select_observation(
        &self,
        target: &openpc_multi_rpc::journal::ObservationTarget,
    ) -> RuntimeResult<AdmittedRequestRoute<'_>> {
        let admission = target.admission();
        let chain = admission
            .chain
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if admission.owner.participant_id != self.routing.participant_id
            || admission.owner.privacy_domain_id != self.routing.privacy_domain_id
            || admission.target_runtime_id != self.routing.target_id
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let assignment = self
            .routing
            .assignments
            .iter()
            .find(|a| {
                a.runtime_binding_id == admission.runtime_binding_id
                    && a.method == "eth_getTransactionReceipt"
                    && a.purpose == 4
                    && a.chain_environment_id == chain.chain_environment_id
            })
            .ok_or(RuntimeError::Denied)?;
        let certification = self
            .certification
            .certifications
            .iter()
            .find(|c| {
                c.provider_profile_id == assignment.provider_profile_id
                    && c.endpoint_id == assignment.endpoint_id
            })
            .ok_or(RuntimeError::Denied)?;
        let admitted = AdmittedRequestRoute {
            assignment,
            certification,
        };
        let profile = admitted.provider_profile()?;
        let required = [
            ("eth_chainId", "CHAIN_METADATA"),
            ("eth_getBlockByNumber", "BLOCK_HEADER"),
            ("eth_getTransactionByHash", "TRANSACTION"),
            ("eth_getTransactionReceipt", "RECEIPT"),
        ];
        // A submission may observe through the same exact qualified write
        // profile only under a separate signed observation-purpose assignment.
        // Pin both artifact and instance to the journal's original selection.
        // This branch grants no request route, retry or provider switch.
        let original_write_profile = profile.idempotency
            == pc_provider_api::IdempotencyClass::GovernedWrite
            && assignment.endpoint_role == 4
            && target.command().provider_profile_digest
                == certification.provider_artifact_digest.as_str()
            && target.command().provider_instance_id == profile.provider_instance_id;
        if profile.chain_id != target.chain_id().to_string()
            || profile.network_id != chain.network_id
            || profile.genesis_hash != format!("sha256:{}", chain.genesis_digest.as_str())
            || (profile.idempotency != pc_provider_api::IdempotencyClass::IdempotentRead
                && !original_write_profile)
            || (admission.deployment.is_some()
                && !profile
                    .method_data_classes
                    .iter()
                    .any(|pair| pair.method == "eth_getCode"))
            || profile.route_plan != pc_provider_api::RoutePlanDraftV1::SingleExact
            || profile.read_retry_budget != 0
            || !pc_provider_api::provider_profile_admission_enabled(&profile)
            || required.iter().any(|(method, class)| {
                !profile
                    .method_data_classes
                    .iter()
                    .any(|pair| pair.method == *method && pair.data_class == *class)
            })
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(admitted)
    }

    pub fn select(
        &self,
        binding: &str,
        request: &RuntimeRequest,
    ) -> RuntimeResult<AdmittedRequestRoute<'_>> {
        let invocation = request.invocation.as_ref().ok_or(RuntimeError::Denied)?;
        if request.deployment.is_some() {
            return Err(RuntimeError::Denied);
        }
        self.select_chain(
            binding,
            request,
            &invocation.chain_id,
            &invocation.network_id,
            &format!("sha256:{}", invocation.genesis_digest.as_str()),
        )
    }

    pub(crate) fn select_deployment(
        &self,
        request: &RuntimeRequest,
        policy: &pc_policy_core::deployment_policy::ValidatedDeploymentPolicy,
    ) -> RuntimeResult<AdmittedRequestRoute<'_>> {
        let publication = policy.publication();
        if request.invocation.is_some()
            || request.deployment.as_ref().is_none_or(|identity| {
                identity.deployment_policy_id != publication.deployment_policy_id
            })
            || request.class != pc_runtime_types::RequestClass::Write
        {
            return Err(RuntimeError::Denied);
        }
        self.select_chain(
            &publication.deployment_policy_id,
            request,
            &publication.definition.chain_id,
            &publication.definition.network_id,
            &publication.definition.genesis_digest,
        )
    }

    pub(crate) fn select_visibility(
        &self,
        resource: &pc_policy_core::visibility_policy::AdmittedVisibilityResource,
        request: &RuntimeRequest,
    ) -> RuntimeResult<AdmittedRequestRoute<'_>> {
        let binding = resource
            .contract_binding
            .as_ref()
            .ok_or(RuntimeError::Denied)?;
        pc_policy_core::visibility_policy::read_resource(std::slice::from_ref(resource), request)?;
        self.select_chain(
            resource.selector.resource_id(),
            request,
            &binding.chain_id,
            &binding.network_id,
            &binding.genesis_digest,
        )
    }

    fn select_chain(
        &self,
        binding: &str,
        request: &RuntimeRequest,
        chain_id: &str,
        network_id: &str,
        genesis_digest: &str,
    ) -> RuntimeResult<AdmittedRequestRoute<'_>> {
        request.validate_digest()?;
        let assignment = self
            .routing
            .assignments
            .iter()
            .find(|a| a.runtime_binding_id == binding && a.method == request.method)
            .ok_or(RuntimeError::Denied)?;
        let certification = self
            .certification
            .certifications
            .iter()
            .find(|c| {
                c.provider_profile_id == assignment.provider_profile_id
                    && c.endpoint_id == assignment.endpoint_id
            })
            .ok_or(RuntimeError::Denied)?;
        let profile = openpc_multi_rpc::qualify_provider_profile(
            &certification.provider_profile_cbor,
            &format!("sha256:{}", certification.provider_artifact_digest.as_str()),
        )
        .map_err(|_| RuntimeError::InvalidAuthorization)?;
        // Exact form and effect select the retry law. A signed write can never
        // borrow a read profile even when its endpoint and chain are identical.
        let (idempotency, data_class) = match (request.method.as_str(), request.class) {
            ("eth_call", pc_runtime_types::RequestClass::Read) => (
                pc_provider_api::IdempotencyClass::IdempotentRead,
                "STATE_CALL",
            ),
            ("eth_getTransactionByHash", pc_runtime_types::RequestClass::Read) => (
                pc_provider_api::IdempotencyClass::IdempotentRead,
                "TRANSACTION",
            ),
            ("eth_getTransactionReceipt", pc_runtime_types::RequestClass::Read) => {
                (pc_provider_api::IdempotencyClass::IdempotentRead, "RECEIPT")
            }
            ("eth_getLogs", pc_runtime_types::RequestClass::Read) => (
                pc_provider_api::IdempotencyClass::IdempotentRead,
                "EVENT_LOG",
            ),
            ("eth_sendRawTransaction", pc_runtime_types::RequestClass::Write) => (
                pc_provider_api::IdempotencyClass::GovernedWrite,
                "transaction",
            ),
            _ => return Err(RuntimeError::Denied),
        };
        if profile.chain_id != chain_id
            || profile.network_id != network_id
            || profile.genesis_hash != genesis_digest
            || profile.idempotency != idempotency
            || !pc_provider_api::provider_profile_admission_enabled(&profile)
            || profile.route_plan != pc_provider_api::RoutePlanDraftV1::SingleExact
            || profile.read_retry_budget != 0
            || !profile
                .method_data_classes
                .iter()
                .any(|m| m.method == request.method && m.data_class == data_class)
            || request.response_budget_bytes > profile.limits.max_response_bytes
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(AdmittedRequestRoute {
            assignment,
            certification,
        })
    }
}
impl AdmittedRequestRoute<'_> {
    pub(crate) fn validate_emergency(
        &self,
        active: &crate::ActiveCapsuleLease<'_>,
    ) -> RuntimeResult<()> {
        if active.denies_any_scope([
            self.assignment.endpoint_id.as_str(),
            self.certification.provider_profile_id.as_str(),
        ]) {
            return Err(RuntimeError::Denied);
        }
        Ok(())
    }

    pub(crate) fn provider_profile(&self) -> RuntimeResult<pc_provider_api::ProviderProfileV1> {
        openpc_multi_rpc::qualify_provider_profile(
            &self.certification.provider_profile_cbor,
            &format!(
                "sha256:{}",
                self.certification.provider_artifact_digest.as_str()
            ),
        )
        .map_err(|_| RuntimeError::InvalidAuthorization)
    }

    pub fn valid_until_ns(&self) -> u64 {
        self.assignment
            .valid_until_ns
            .min(self.certification.valid_until_ns)
    }
    /// Bind a selected live route to an installed connection before discovery.
    /// This does not replace witness, policy or submission authorization.
    pub fn validate_connection(
        &self,
        connection: &ConnectionRecord,
        now_ns: u64,
    ) -> RuntimeResult<()> {
        let c = self.certification;
        if now_ns < c.valid_from_ns || now_ns >= self.valid_until_ns() {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        if connection.provider_id != c.provider_profile_id
            || connection.endpoint_id != c.endpoint_id
            || connection.configuration_digest != c.connection_configuration_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }
    pub fn validate_witness(
        &self,
        witness: &RequestRouteWitness,
        connection: &ConnectionRecord,
        now_ns: u64,
    ) -> RuntimeResult<()> {
        let a = self.assignment;
        self.validate_connection(connection, now_ns)?;
        if witness.endpoint_id != a.endpoint_id
            || witness.endpoint_role != a.endpoint_role
            || witness.purpose != a.purpose
            || witness.coherence_group_digest != a.coherence_group_digest
            || witness.invalidation_generation != a.invalidation_generation
            || witness.chain_anchor.chain_environment_id != a.chain_environment_id
            || witness.chain_anchor.canonical_generation != a.canonical_generation
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }
}
impl ArtifactAdmission for RoutingArtifactAdmission {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        if component.component_id == self.routing.artifact_id
            || component.component_id == self.certification.artifact_id
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
        if component.component_id == self.routing.artifact_id
            || component.component_id == self.certification.artifact_id
        {
            self.admit(capsule, artifacts).map(|(_, closure)| closure)
        } else {
            self.remaining
                .validate_component_in_bundle(capsule, component, artifacts)
        }
    }
}

#[cfg(test)]
#[path = "routing_custody_tests.rs"]
mod tests;
