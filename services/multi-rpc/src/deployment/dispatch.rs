//! Original trusted dispatch identity. Captured before STARTED and retained in
//! the existing journal; a recovery connection can never replace these values.
use crate::{provider_connection::ConnectionLease, route_witness::VerifiedRouteWitness};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentDispatchBinding {
    pub(super) routing_snapshot_digest: Digest,
    pub(super) route_witness_digest: Digest,
    pub(super) dispatcher_binding_digest: Digest,
}
impl DeploymentDispatchBinding {
    pub(crate) fn same_route_and_connection(&self, other: &Self) -> bool {
        self.routing_snapshot_digest == other.routing_snapshot_digest
            && self.dispatcher_binding_digest == other.dispatcher_binding_digest
    }
    pub fn capture(
        witness: &VerifiedRouteWitness,
        connection: &ConnectionLease,
    ) -> RuntimeResult<Self> {
        let record = connection
            .record()
            .map_err(|_| RuntimeError::GenerationMismatch)?;
        let route = witness.witness();
        if record.endpoint_id != route.endpoint_id || route.purpose != 3 {
            return Err(RuntimeError::GenerationMismatch);
        }
        let binding = Self {
            routing_snapshot_digest: route.routing_snapshot_digest.clone(),
            route_witness_digest: route.semantic_digest()?,
            dispatcher_binding_digest: connection
                .binding_digest(&route.routing_snapshot_digest)
                .map_err(|_| RuntimeError::GenerationMismatch)?,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(crate) fn validate(&self) -> RuntimeResult<()> {
        for digest in [
            &self.routing_snapshot_digest,
            &self.route_witness_digest,
            &self.dispatcher_binding_digest,
        ] {
            super::valid_digest(digest)?;
        }
        Ok(())
    }
}
