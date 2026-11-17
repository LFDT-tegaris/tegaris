use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrincipalContractType {
    #[serde(rename = "Principal")]
    Principal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalStatus {
    Provisioned,
    Active,
    Suspended,
    Revoked,
    Offboarded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalAssurance {
    Oidc,
    OidcWebauthn,
    WorkloadMtls,
    RecoveryPrincipal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Principal {
    pub contract_type: PrincipalContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: PrincipalStatus,
    pub principal_id: String,
    pub identity_epoch: String,
    pub assurance: PrincipalAssurance,
}
