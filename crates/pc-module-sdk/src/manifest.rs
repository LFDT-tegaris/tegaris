use serde::{Deserialize, Serialize};

/// An exact SHA-256 manifest identity. Unbound names or floating versions are
/// intentionally not representable by this contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestDigest(pub [u8; 32]);

/// Immutable identity for one admitted module version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleVersionRef {
    pub module_id: String,
    pub semantic_version: String,
    pub manifest_digest: ManifestDigest,
}

/// Exact five-part dependency tuple from the frozen install DAG.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleDependencyRef {
    pub edge_id: String,
    pub provider: ModuleVersionRef,
    pub capability_id: String,
}
