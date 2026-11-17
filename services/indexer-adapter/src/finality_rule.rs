//! Resolved configuration referenced by ClientIndexerProfileV1's immutable
//! finality_rule_digest. This is configuration, never a source observation or
//! an admission receipt. Admission must independently verify its receipt and
//! canonical provider observations; candidates cannot supply their own rule.
use pc_provider_api::{ClientIndexerProfileV1, validate_canonical_pc_cbor_bytes};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CandidateStoreError, candidate::decode_digest, store::canonical_cbor};
use sha2::{Digest, Sha256};

const PURPOSE: &str = "openpc:indexer-finality-rule-configuration:v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FinalityMode {
    Confirmations { count: u32 },
    SafeTag,
    FinalizedTag,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityRule {
    pub rule_id: String,
    pub receipt_digest: String,
    pub mode: FinalityMode,
    /// Exact governed ProviderProfile artifact digests. Distinct provider
    /// instances and independent observations are checked by the consumer.
    pub canonical_provider_digests: Vec<String>,
    pub required_observations: u16,
}

impl FinalityRule {
    pub fn encode(&self) -> Result<Vec<u8>, CandidateStoreError> {
        self.validate()?;
        let value = serde_json::to_value((PURPOSE, self))
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        Ok(canonical_cbor(&value))
    }

    pub fn resolve(
        profile: &ClientIndexerProfileV1,
        bytes: &[u8],
    ) -> Result<Self, CandidateStoreError> {
        if bytes.is_empty()
            || bytes.len() > 8192
            || Sha256::digest(bytes).as_slice() != decode_digest(&profile.finality_rule_digest)?
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        validate_canonical_pc_cbor_bytes(bytes).map_err(|_| CandidateStoreError::InvalidBinding)?;
        let (purpose, rule): (String, Self) =
            ciborium::de::from_reader(bytes).map_err(|_| CandidateStoreError::InvalidBinding)?;
        if purpose != PURPOSE || rule.encode()? != bytes {
            return Err(CandidateStoreError::InvalidBinding);
        }
        Ok(rule)
    }

    fn validate(&self) -> Result<(), CandidateStoreError> {
        let id = self
            .rule_id
            .strip_prefix("urn:openpc:finality-rule:")
            .and_then(|value| Uuid::parse_str(value).ok());
        let canonical_id = id.is_some_and(|id| {
            id.get_version_num() == 7 && self.rule_id == format!("urn:openpc:finality-rule:{id}")
        });
        if !canonical_id
            || !canonical_digest(&self.receipt_digest)
            || self.canonical_provider_digests.is_empty()
            || self.canonical_provider_digests.len() > 16
            || self.required_observations == 0
            || usize::from(self.required_observations) > self.canonical_provider_digests.len()
            || self
                .canonical_provider_digests
                .iter()
                .any(|digest| !canonical_digest(digest))
            || self
                .canonical_provider_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || matches!(self.mode, FinalityMode::Confirmations { count } if count == 0 || count > i32::MAX as u32)
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        Ok(())
    }

    pub fn database_mode(&self) -> (&'static str, Option<i64>) {
        match self.mode {
            FinalityMode::Confirmations { count } => ("CONFIRMATIONS", Some(i64::from(count))),
            FinalityMode::SafeTag => ("SAFE_TAG", None),
            FinalityMode::FinalizedTag => ("FINALIZED_TAG", None),
        }
    }
}

fn canonical_digest(value: &str) -> bool {
    value.starts_with("sha256:") && value.len() == 71 && decode_digest(value).is_ok()
}
