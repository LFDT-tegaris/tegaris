//! Complete COM-019 manifest. Its projection is derived from the
//! already verified immutable record, never from caller-supplied readiness.
use super::*;
use pc_facts_core::{FactCompletenessScope, FactRecord};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) const MANIFEST_MEDIA_TYPE: &str = "application/vnd.openpc.fact-shard-manifest.v1+cbor";

pub(crate) fn digest_text(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// Internal FactShardContentV1; records are COSE byte strings in delta order.
pub(crate) fn content_bytes(records: &[Vec<u8>]) -> Result<Vec<u8>, FactSigningError> {
    if records.is_empty() || records.len() > 1_000_000 {
        return Err(FactSigningError::Verification);
    }
    Ok(encode_pc_cbor(Value::Array(vec![
        Value::Text("openpc:fact-shard-content:v1".into()),
        Value::Array(records.iter().cloned().map(Value::Bytes).collect()),
    ]))?)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FactShardManifest {
    schema_id: u32,
    schema_version: String,
    schema_digest: String,
    purpose: String,
    shard_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub generation_id: String,
    pub(crate) fact_profile_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) relationship_profile_digest: Option<String>,
    fact_schema_id: u32,
    fact_schema_version: String,
    fact_schema_digest: String,
    pub(crate) canonical_generation: u64,
    pub(crate) canonical_range: FactCompletenessScope,
    completed_watermark: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) canonical_blocks: Vec<(u64, String)>,
    snapshot_root: String,
    pub(crate) entry_count: u64,
    completeness_digest: String,
    pub shard_content_digest: String,
    signing_key_id: String,
    pub predecessor_shard_digest: Option<String>,
    replacement_generation: Option<u64>,
    reorg_replacement_of: Option<String>,
    created_at: String,
    pub(crate) not_before: String,
    pub(crate) expires_at: String,
    max_age_ms: u64,
    media_type: String,
}

impl FactShardManifest {
    pub(super) fn purpose(&self) -> &str {
        &self.purpose
    }
    pub(crate) fn from_records(
        records: &[FactRecord],
        content: &[u8],
        generation: &str,
        predecessor_shard_digest: Option<String>,
    ) -> Result<Self, FactSigningError> {
        FactRecord::validate_batch(records)?;
        validate_pc_cbor(content)?;
        let value = decode_value(content)?;
        let entries = match value {
            Value::Array(mut fields)
                if fields.first() == Some(&Value::Text("openpc:fact-shard-content:v1".into()))
                    && fields.len() == 2 =>
            {
                let Value::Array(entries) = fields.remove(1) else {
                    return Err(FactSigningError::Verification);
                };
                entries
            }
            // Read-only compatibility with the retained single-record artifact.
            Value::Array(_) if records.len() == 1 => vec![Value::Bytes(content.to_vec())],
            _ => return Err(FactSigningError::Verification),
        };
        if entries.len() != records.len() {
            return Err(FactSigningError::Verification);
        }
        for (entry, record) in entries.iter().zip(records) {
            let Value::Bytes(cose) = entry else {
                return Err(FactSigningError::Verification);
            };
            let Value::Array(fields) = decode_value(cose)? else {
                return Err(FactSigningError::Verification);
            };
            if fields.len() != 4 || fields.get(2) != Some(&Value::Bytes(record.to_cbor()?)) {
                return Err(FactSigningError::Verification);
            }
        }
        let record = &records[0];
        let identity = &record.identity;
        for next in records {
            let next_identity = &next.identity;
            if next_identity.fact_schema_id != identity.fact_schema_id
                || next_identity.fact_schema_version != identity.fact_schema_version
                || next_identity.fact_schema_digest != identity.fact_schema_digest
                || next_identity.fact_semantic_version != identity.fact_semantic_version
                || next_identity.admission_policy_digest != identity.admission_policy_digest
                || next_identity.local_signing_key_id != identity.local_signing_key_id
                || next_identity.chain_anchor.chain_id != identity.chain_anchor.chain_id
                || next_identity.chain_anchor.genesis_hash != identity.chain_anchor.genesis_hash
                || next_identity.chain_anchor.network_id != identity.chain_anchor.network_id
                || next.gap_state != record.gap_state
                || next.replacement_generation != record.replacement_generation
                || next.reorg_replacement_of.is_some() != record.reorg_replacement_of.is_some()
            {
                return Err(FactSigningError::Verification);
            }
        }
        let not_before = records.iter().map(|r| &r.not_before).max().unwrap().clone();
        let expires_at = records.iter().map(|r| &r.expires_at).min().unwrap().clone();
        if not_before >= expires_at {
            return Err(FactSigningError::Verification);
        }
        let participant_id = identity
            .participant_id
            .strip_prefix("urn:openpc:participant:")
            .ok_or(FactSigningError::Verification)?
            .to_owned();
        let privacy_domain_id = identity
            .privacy_domain_id
            .as_deref()
            .and_then(|v| v.strip_prefix("urn:openpc:privacy-domain:"))
            .ok_or(FactSigningError::Verification)?
            .to_owned();
        if Uuid::parse_str(generation).is_err()
            || record.gap_state != pc_facts_core::FactGapState::Complete
        {
            return Err(FactSigningError::Verification);
        }
        let relationship = identity.fact_schema_id == pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID;
        let schema_id = if relationship {
            pc_facts_core::RELATIONSHIP_SHARD_SCHEMA_ID
        } else {
            FACT_SHARD_MANIFEST_SCHEMA_ID
        };
        let schema = fact_schema_identity(schema_id).expect("registered shard schema");
        Ok(Self {
            schema_id,
            schema_version: FACT_SCHEMA_VERSION_V1.into(),
            schema_digest: digest_text(pc_facts_core::record_schema_digest(relationship)),
            purpose: schema.purpose_separator.into(),
            shard_id: format!("urn:openpc:fact-shard:{generation}"),
            participant_id,
            privacy_domain_id,
            generation_id: generation.into(),
            fact_profile_id: identity.fact_profile_id.clone(),
            relationship_profile_digest: match &identity.typed_subject {
                pc_facts_core::FactSubject::Relationship { profile_digest, .. } => {
                    Some(profile_digest.clone())
                }
                _ => None,
            },
            fact_schema_id: identity.fact_schema_id,
            fact_schema_version: identity.fact_schema_version.clone(),
            fact_schema_digest: identity.fact_schema_digest.clone(),
            canonical_generation: identity.canonical_generation,
            canonical_range: record.completeness_scope.clone(),
            completed_watermark: record.completeness_scope.range_end,
            canonical_blocks: if relationship {
                let anchors = records
                    .iter()
                    .map(|r| {
                        (
                            r.identity.chain_anchor.block_height,
                            r.identity
                                .chain_anchor
                                .block_hash
                                .trim_start_matches("0x")
                                .to_owned(),
                        )
                    })
                    .collect::<std::collections::BTreeMap<_, _>>();
                if record
                    .completeness_scope
                    .range_end
                    .checked_sub(record.completeness_scope.range_start)
                    .and_then(|n| n.checked_add(1))
                    == Some(anchors.len() as u64)
                {
                    anchors.into_iter().collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            },
            snapshot_root: record.snapshot_root.clone(),
            entry_count: records.len() as u64,
            completeness_digest: digest_text(&sha256(&crate::state_value::canonical(
                &record.completeness_scope,
            )?)),
            shard_content_digest: digest_text(&sha256(content)),
            signing_key_id: identity.local_signing_key_id.clone(),
            predecessor_shard_digest,
            replacement_generation: record.replacement_generation,
            reorg_replacement_of: record.reorg_replacement_of.clone(),
            created_at: records
                .iter()
                .map(|r| &r.admitted_at)
                .max()
                .unwrap()
                .clone(),
            not_before,
            expires_at,
            max_age_ms: records.iter().map(|r| r.max_age_ms).min().unwrap(),
            media_type: MANIFEST_MEDIA_TYPE.into(),
        })
    }

    pub(crate) fn matches(&self, records: &[FactRecord], content: &[u8]) -> bool {
        Self::from_records(
            records,
            content,
            &self.generation_id,
            self.predecessor_shard_digest.clone(),
        )
        .is_ok_and(|mut expected| {
            expected.canonical_blocks = self.canonical_blocks.clone();
            expected == *self && self.valid_blocks()
        })
    }

    fn valid_blocks(&self) -> bool {
        self.canonical_blocks.is_empty()
            || (self.fact_schema_id == pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID
                && self.canonical_blocks.len() <= 64
                && self
                    .canonical_range
                    .range_end
                    .checked_sub(self.canonical_range.range_start)
                    .and_then(|n| n.checked_add(1))
                    == Some(self.canonical_blocks.len() as u64)
                && self
                    .canonical_blocks
                    .iter()
                    .enumerate()
                    .all(|(i, (height, hash))| {
                        *height == self.canonical_range.range_start + i as u64
                            && pc_runtime_types::Digest::parse(hash).is_ok()
                    }))
    }
    pub(crate) fn from_cbor(bytes: &[u8], key: &[u8]) -> Result<Self, FactSigningError> {
        let value: Self =
            ciborium::de::from_reader(bytes).map_err(|_| FactSigningError::InvalidCose)?;
        let relationship = value.fact_schema_id == pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID;
        let schema_id = if relationship {
            pc_facts_core::RELATIONSHIP_SHARD_SCHEMA_ID
        } else {
            FACT_SHARD_MANIFEST_SCHEMA_ID
        };
        let schema = fact_schema_identity(schema_id).expect("registered shard schema");
        let digest_valid = |v: &str| {
            v.strip_prefix("sha256:").is_some_and(|v| {
                v.len() == 64
                    && v.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
        };
        let empty_content = encode_pc_cbor(Value::Array(vec![
            Value::Text("openpc:fact-shard-content:v1".into()),
            Value::Array(Vec::new()),
        ]))?;
        let empty_digest = digest_text(&sha256(&empty_content));
        if (value.entry_count == 0
            && (value.shard_content_digest != empty_digest
                || value.snapshot_root != empty_digest
                || value.completeness_digest
                    != digest_text(&sha256(&crate::state_value::canonical(
                        &value.canonical_range,
                    )?))))
            || !value.valid_blocks()
            || crate::state_value::canonical(&value)? != bytes
            || value.schema_id != schema_id
            || value.schema_version != FACT_SCHEMA_VERSION_V1
            || value.schema_digest != digest_text(pc_facts_core::record_schema_digest(relationship))
            || value.purpose != schema.purpose_separator
            || value.signing_key_id != record_key_id(key)?
            || value.media_type != MANIFEST_MEDIA_TYPE
            || (value.entry_count == 0
                && (!relationship
                    || value.canonical_blocks.is_empty()
                    || value
                        .relationship_profile_digest
                        .as_ref()
                        .is_none_or(|v| !digest_valid(v))
                    || (value.predecessor_shard_digest.is_none()
                        && value.canonical_generation != 1)))
            || value.entry_count > 1_000_000
            || value.canonical_range.record_count != value.entry_count
            || value.canonical_range.range_start > value.canonical_range.range_end
            || value.completed_watermark != value.canonical_range.range_end
            || value.canonical_generation == 0
            || value.max_age_ms == 0
            || value.shard_id != format!("urn:openpc:fact-shard:{}", value.generation_id)
            || [
                &value.participant_id,
                &value.privacy_domain_id,
                &value.generation_id,
            ]
            .iter()
            .any(|v| Uuid::parse_str(v).is_err())
            || [
                &value.shard_content_digest,
                &value.snapshot_root,
                &value.completeness_digest,
            ]
            .iter()
            .any(|v| !digest_valid(v))
            || value
                .predecessor_shard_digest
                .as_deref()
                .is_some_and(|v| !digest_valid(v))
        {
            return Err(FactSigningError::Verification);
        }
        Ok(value)
    }
}

impl PurposeBoundFactSigner {
    /// A zero-entry RelationshipShardV1 records a verified empty canonical
    /// interval. It preserves the prior state through the signed predecessor;
    /// it never invents a membership FactRecord.
    pub(crate) fn sign_empty_relationship_shard(
        &self,
        event: &crate::FactFeedEvent,
        claims: &serde_json::Value,
        predecessor: Option<&VerifiedShard>,
    ) -> Result<SignedShard, FactSigningError> {
        let text = |key: &str| claims[key].as_str().ok_or(FactSigningError::Verification);
        let number = |key: &str| {
            text(key)?
                .parse::<u64>()
                .map_err(|_| FactSigningError::Verification)
        };
        let blocks = claims["blocks"]
            .as_array()
            .ok_or(FactSigningError::Verification)?;
        let mut anchors = Vec::new();
        for block in blocks {
            let n = block["number"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or(FactSigningError::Verification)?;
            let hash = block["hash"]
                .as_str()
                .and_then(|s| s.strip_prefix("sha256:"))
                .ok_or(FactSigningError::Verification)?;
            let parent = block["parentHash"]
                .as_str()
                .and_then(|s| s.strip_prefix("sha256:"))
                .ok_or(FactSigningError::Verification)?;
            if pc_runtime_types::Digest::parse(hash).is_err()
                || anchors
                    .last()
                    .is_some_and(|prior: &(u64, String)| prior.1 != parent)
            {
                return Err(FactSigningError::Verification);
            }
            anchors.push((n, hash.into()));
        }
        let range = FactCompletenessScope {
            partition_id: format!(
                "urn:openpc:candidate-partition:{}",
                event.batch.partition_id
            ),
            range_start: event.batch.range_start,
            range_end: event.batch.range_end,
            record_count: 0,
            checkpoint_id: format!("urn:openpc:fact-checkpoint:{}", event.batch.checkpoint_id),
            checkpoint_digest: digest_text(&event.batch.checkpoint_digest),
        };
        let prior = predecessor.and_then(|p| p.manifest.as_ref());
        if event.candidate_id.is_some()
            || event.batch.record_count != 0
            || anchors.is_empty()
            || claims["participantId"] != event.batch.participant_id
            || claims["privacyDomainId"] != event.batch.privacy_domain_id
            || prior.is_some_and(|p| {
                p.fact_schema_id != pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID
                    || p.fact_profile_id != text("factProfileId").unwrap_or("")
                    || p.relationship_profile_digest.as_deref()
                        != Some(text("profileDigest").unwrap_or(""))
                    || p.participant_id != event.batch.participant_id
                    || p.privacy_domain_id != event.batch.privacy_domain_id
                    || p.canonical_range.partition_id != range.partition_id
                    || p.completed_watermark.checked_add(1) != Some(range.range_start)
                    || p.canonical_blocks
                        .last()
                        .is_none_or(|(_, hash)| blocks[0]["parentHash"] != format!("sha256:{hash}"))
            })
        {
            return Err(FactSigningError::Verification);
        }
        let content = encode_pc_cbor(Value::Array(vec![
            Value::Text("openpc:fact-shard-content:v1".into()),
            Value::Array(Vec::new()),
        ]))?;
        let schema = fact_schema_identity(pc_facts_core::RELATIONSHIP_SHARD_SCHEMA_ID)
            .ok_or(FactSigningError::Verification)?;
        let now = number("observedAtMs")?;
        let expiry = number("expiresAtMs")?;
        let not_before = pc_facts_core::fact_timestamp_from_ms(
            i64::try_from(now).map_err(|_| FactSigningError::Verification)?,
        )?;
        let expires_at = pc_facts_core::fact_timestamp_from_ms(
            i64::try_from(expiry).map_err(|_| FactSigningError::Verification)?,
        )?;
        if expiry <= now {
            return Err(FactSigningError::Verification);
        }
        let manifest = FactShardManifest {
            schema_id: pc_facts_core::RELATIONSHIP_SHARD_SCHEMA_ID,
            schema_version: FACT_SCHEMA_VERSION_V1.into(),
            schema_digest: digest_text(&pc_facts_core::RELATIONSHIP_SCHEMA_DIGEST_V1),
            purpose: schema.purpose_separator.into(),
            shard_id: format!("urn:openpc:fact-shard:{}", event.batch.fact_generation_id),
            participant_id: event.batch.participant_id.clone(),
            privacy_domain_id: event.batch.privacy_domain_id.clone(),
            generation_id: event.batch.fact_generation_id.clone(),
            fact_profile_id: text("factProfileId")?.into(),
            relationship_profile_digest: Some(text("profileDigest")?.into()),
            fact_schema_id: pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID,
            fact_schema_version: FACT_SCHEMA_VERSION_V1.into(),
            fact_schema_digest: digest_text(&pc_facts_core::RELATIONSHIP_SCHEMA_DIGEST_V1),
            canonical_generation: prior
                .map_or(Some(1), |p| p.canonical_generation.checked_add(1))
                .ok_or(FactSigningError::Verification)?,
            canonical_range: range.clone(),
            completed_watermark: range.range_end,
            canonical_blocks: anchors,
            snapshot_root: digest_text(&sha256(&content)),
            entry_count: 0,
            completeness_digest: digest_text(&sha256(&crate::state_value::canonical(&range)?)),
            shard_content_digest: digest_text(&sha256(&content)),
            signing_key_id: record_key_id(&self.key_id)?,
            predecessor_shard_digest: predecessor.map(|p| digest_text(&sha256(p.cose_sign1()))),
            replacement_generation: None,
            reorg_replacement_of: None,
            created_at: not_before.clone(),
            not_before,
            expires_at,
            max_age_ms: expiry - now,
            media_type: MANIFEST_MEDIA_TYPE.into(),
        };
        self.sign_complete_shard(&manifest)
    }
    pub(crate) fn sign_complete_shard(
        &self,
        manifest: &FactShardManifest,
    ) -> Result<SignedShard, FactSigningError> {
        let claims_cbor = crate::state_value::canonical(manifest)?;
        FactShardManifest::from_cbor(&claims_cbor, &self.key_id)?;
        let digest = pc_runtime_types::Digest::parse(
            manifest.shard_content_digest.trim_start_matches("sha256:"),
        )
        .map_err(|_| FactSigningError::Verification)?;
        let mut shard_digest = [0; 32];
        for (i, byte) in shard_digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digest.as_str()[i * 2..i * 2 + 2], 16)
                .map_err(|_| FactSigningError::Verification)?;
        }
        let cose_sign1 = self.sign_cose(&manifest.purpose, &claims_cbor)?;
        Ok(SignedShard {
            participant_id: manifest.participant_id.clone(),
            privacy_domain_id: manifest.privacy_domain_id.clone(),
            generation_id: manifest.generation_id.clone(),
            shard_digest,
            claims_cbor,
            cose_sign1,
        })
    }
}
