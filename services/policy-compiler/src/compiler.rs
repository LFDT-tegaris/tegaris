use pc_policy_core::{
    EvaluationInput, EvaluationResult, PolicyCompilationInput, PolicyGenerationArtifact,
    SimulationAuthority, evaluate, pc_cbor_1_digest,
};
use serde::{Deserialize, Serialize};

/// Deterministic content-addressed compilation. The artifact contains no activation handle.
pub fn compile(
    input: &PolicyCompilationInput,
    compiler_manifest_digest: [u8; 32],
) -> PolicyGenerationArtifact {
    let generation_digest = pc_cbor_1_digest(input);
    let artifact_digest = pc_cbor_1_digest(&(
        generation_digest,
        compiler_manifest_digest,
        "OPENPC_POLICY_ARTIFACT_V1",
    ));
    PolicyGenerationArtifact {
        generation_digest,
        artifact_digest,
        compiler_manifest_digest,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimulationEnvelope {
    pub authority: SimulationAuthority,
    pub evaluation: EvaluationResult,
}

/// Simulation has exactly the shared production evaluator and no side-effect capability.
pub fn simulate(input: &EvaluationInput) -> SimulationEnvelope {
    SimulationEnvelope {
        authority: SimulationAuthority::SimulationOnly,
        evaluation: evaluate(input),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_module_sdk::ManifestDigest;

    #[test]
    fn compilation_is_deterministic_and_non_authoritative() {
        let input = PolicyCompilationInput {
            policy_version_id: "v1".into(),
            semantic_digest: [1; 32],
            module_manifests: vec![ManifestDigest([2; 32])],
            target_profile: "test.yaml".into(),
            input_digest: [3; 32],
        };
        assert_eq!(compile(&input, [4; 32]), compile(&input, [4; 32]));
    }

    // Cross-entrypoint equality is exercised by the shared evaluator corpus through the CLI.
}
