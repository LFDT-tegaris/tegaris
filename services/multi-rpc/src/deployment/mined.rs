//! Minimized complete mined-creation evidence. Only the pinned protocol observer
//! produces this value; neither persistence nor deserialization grants authority.
use super::{CreationInspection, DeploymentConstraints, DeploymentRoute, FactoryMechanism};
use crate::signed_transaction::create_address;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MinedCreationEvidence {
    pub(crate) address: [u8; 20],
    pub(super) runtime_code_hash: [u8; 32],
    inspection_digest: Digest,
    factory_nonce: Option<u64>,
}
impl MinedCreationEvidence {
    pub(crate) fn from_inspection(
        inspection: &CreationInspection,
        constraints: &DeploymentConstraints,
        factory_nonce: Option<u64>,
    ) -> RuntimeResult<Self> {
        let evidence = Self {
            address: *inspection.address(),
            runtime_code_hash: inspection.runtime_code_hash(),
            inspection_digest: inspection.digest()?,
            factory_nonce,
        };
        evidence.validate(constraints)?;
        Ok(evidence)
    }

    pub(crate) fn validate(&self, constraints: &DeploymentConstraints) -> RuntimeResult<()> {
        let address = match (&constraints.route, self.factory_nonce) {
            (DeploymentRoute::DirectCreate { expected_address }, None) => *expected_address,
            (DeploymentRoute::Factory(factory), nonce) => match (&factory.mechanism, nonce) {
                (FactoryMechanism::Create, Some(nonce)) => create_address(&factory.address, nonce),
                (
                    FactoryMechanism::Create2 {
                        expected_address, ..
                    },
                    None,
                ) => *expected_address,
                (
                    FactoryMechanism::Create3 {
                        expected_helper_address,
                        expected_address,
                        salt,
                        salt_transform,
                        ..
                    },
                    None,
                ) => {
                    let pair = super::solady_create3_addresses(
                        &factory.address,
                        &salt_transform.apply(&constraints.sender, salt),
                    )?;
                    if pair != (*expected_helper_address, *expected_address) {
                        return Err(RuntimeError::InvalidAuthorization);
                    }
                    *expected_address
                }
                _ => return Err(RuntimeError::InvalidAuthorization),
            },
            _ => return Err(RuntimeError::InvalidAuthorization),
        };
        if address != self.address
            || self.runtime_code_hash != constraints.artifact.runtime_code_hash
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        super::valid_digest(&self.inspection_digest)
    }
}
