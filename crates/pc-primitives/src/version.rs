use serde::{Deserialize, Serialize};

/// A contract version carried as source data without prescribing domain semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContractVersion(pub String);
