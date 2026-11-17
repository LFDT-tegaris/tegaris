use pc_module_sdk::ManifestDigest;
use serde::{Deserialize, Serialize};

/// Immutable input to the deterministic policy compiler.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyCompilationInput {
    pub policy_version_id: String,
    pub semantic_digest: [u8; 32],
    pub module_manifests: Vec<ManifestDigest>,
    pub target_profile: String,
    pub input_digest: [u8; 32],
}

/// Content-addressed compiler result. This type carries no activation authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyGenerationArtifact {
    pub generation_digest: [u8; 32],
    pub artifact_digest: [u8; 32],
    pub compiler_manifest_digest: [u8; 32],
}

/// Side-effect-free simulator input bound to the same immutable evaluator data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimulationInput {
    pub compilation: PolicyCompilationInput,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub authority_epoch: u64,
    pub delegation_epoch: u64,
    pub fact_generation_digest: [u8; 32],
}

/// A marker that makes non-authoritative simulation status unforgeable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SimulationAuthority {
    SimulationOnly,
}

/// A non-authoritative simulation projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimulationResult {
    pub input_digest: [u8; 32],
    pub result_digest: [u8; 32],
    pub truth_state: String,
    pub explanation_codes: Vec<String>,
    pub authority: SimulationAuthority,
}
