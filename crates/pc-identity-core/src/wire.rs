use serde::{Deserialize, Serialize};

/// Metadata shared by persisted identity aggregate contracts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntityMetadata {
    pub id: String,
    pub version: String,
    pub created_at: String,
    pub updated_at: String,
    pub trace_set_id: String,
}
