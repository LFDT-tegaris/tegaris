use super::ArtifactBundle;
use pc_runtime_types::{
    ActivationReceipt, DesiredGeneration, Digest, PreparedGeneration, SignedEnvelope,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) type JournalStore = pc_runtime_types::LocalJournal<Journal>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedRecord {
    pub signed: SignedEnvelope<DesiredGeneration>,
    pub prepared: PreparedGeneration,
    pub bundle: ArtifactBundle,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub version: u32,
    pub target_id: String,
    pub sequence: u64,
    #[serde(default)]
    pub canonical: Option<crate::activation::CanonicalJournal>,
    pub active: Option<Digest>,
    pub xds_version: Option<Digest>,
    pub prepared: BTreeMap<String, PreparedRecord>,
    pub consumed: BTreeMap<String, u64>,
    pub receipts: BTreeMap<String, SignedEnvelope<ActivationReceipt>>,
}

impl Journal {
    pub fn empty(target_id: String) -> Self {
        Self {
            version: 1,
            target_id,
            sequence: 0,
            canonical: None,
            active: None,
            xds_version: None,
            prepared: BTreeMap::new(),
            consumed: BTreeMap::new(),
            receipts: BTreeMap::new(),
        }
    }
}
