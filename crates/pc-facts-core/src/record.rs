//! Immutable record contents. A valid record is still historical evidence;
//! current identity, lifecycle, coverage and verified shard custody decide use.
use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::identity::{digest, digest_text, urn};
use crate::{
    AdmissionError, CanonicalFactIdentity, FactLifecycleState, FactObject, encode_pc_cbor, sha256,
    validate_pc_cbor,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactCompletenessScope {
    pub partition_id: String,
    pub range_start: u64,
    pub range_end: u64,
    pub record_count: u64,
    pub checkpoint_id: String,
    pub checkpoint_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactGapState {
    Complete,
    GapBlocked,
    ReorgFenced,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactRecord {
    pub identity: CanonicalFactIdentity,
    pub value: FactObject,
    pub not_before: String,
    pub expires_at: String,
    pub max_age_ms: u64,
    pub completeness_scope: FactCompletenessScope,
    pub gap_state: FactGapState,
    pub source_digest: String,
    pub derivation_digest: String,
    pub provenance_digest: String,
    pub predecessor_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_predecessor_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_candidate_cose: Option<Vec<u8>>,
    pub snapshot_root: String,
    pub delta_sequence: u64,
    pub replacement_generation: Option<u64>,
    pub reorg_replacement_of: Option<String>,
    pub admitted_at: String,
    pub finalized_at: Option<String>,
}

fn time(value: &str) -> Result<OffsetDateTime, AdmissionError> {
    if value.len() != 27 || value.as_bytes()[19] != b'.' || !value.ends_with('Z') {
        return Err(AdmissionError::SchemaOrEncoding);
    }
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AdmissionError::SchemaOrEncoding)
}

pub fn fact_timestamp_from_ms(value: i64) -> Result<String, AdmissionError> {
    let value = OffsetDateTime::from_unix_timestamp_nanos(i128::from(value) * 1_000_000)
        .map_err(|_| AdmissionError::SchemaOrEncoding)?;
    let format = time::format_description::parse_borrowed::<3>(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z",
    )
    .map_err(|_| AdmissionError::SchemaOrEncoding)?;
    value
        .format(&format)
        .map_err(|_| AdmissionError::SchemaOrEncoding)
}

impl FactRecord {
    /// The historical one-entry projection remains the leaf of every snapshot.
    pub fn with_single_entry_root(mut self) -> Result<Self, AdmissionError> {
        if self.completeness_scope.record_count != 1 {
            return Err(AdmissionError::CompletenessOrSequence);
        }
        self.snapshot_root = self.single_entry_root()?;
        self.validate()?;
        Ok(self)
    }
    fn single_entry_root(&self) -> Result<String, AdmissionError> {
        Ok(digest_text(&self.snapshot_leaf()?))
    }

    fn snapshot_leaf(&self) -> Result<[u8; 32], AdmissionError> {
        let Value::Map(mut fields) =
            Value::serialized(&self).map_err(|_| AdmissionError::SchemaOrEncoding)?
        else {
            return Err(AdmissionError::SchemaOrEncoding);
        };
        fields.retain(|(name, _)| name != &Value::Text("snapshotRoot".into()));
        Ok(sha256(&encode_pc_cbor(Value::Map(fields))?))
    }

    pub fn batch_root(records: &[Self]) -> Result<String, AdmissionError> {
        let first = records
            .first()
            .ok_or(AdmissionError::CompletenessOrSequence)?;
        if records.len() as u64 != first.completeness_scope.record_count {
            return Err(AdmissionError::CompletenessOrSequence);
        }
        let mut leaves = Vec::with_capacity(records.len());
        for (index, record) in records.iter().enumerate() {
            if record.delta_sequence != index as u64 + 1
                || record.completeness_scope != first.completeness_scope
                || record.identity.fact_profile_id != first.identity.fact_profile_id
                || record.identity.canonical_generation != first.identity.canonical_generation
                || record.identity.participant_id != first.identity.participant_id
                || record.identity.privacy_domain_id != first.identity.privacy_domain_id
                || (index > 0
                    && record.reorg_replacement_of.is_none()
                    && record.predecessor_digest.as_ref()
                        != Some(&records[index - 1].identity.local_fact_digest))
            {
                return Err(AdmissionError::CompletenessOrSequence);
            }
            leaves.push(record.snapshot_leaf()?);
        }
        fn root(leaves: &[[u8; 32]]) -> Result<[u8; 32], AdmissionError> {
            if leaves.len() == 1 {
                return Ok(leaves[0]);
            }
            let split = 1usize << (usize::BITS - (leaves.len() - 1).leading_zeros() - 1);
            let value = Value::Array(vec![
                Value::Text("openpc:fact-snapshot-node:v1".into()),
                Value::Bytes(root(&leaves[..split])?.to_vec()),
                Value::Bytes(root(&leaves[split..])?.to_vec()),
            ]);
            Ok(sha256(&encode_pc_cbor(value)?))
        }
        Ok(digest_text(&root(&leaves)?))
    }

    pub fn validate_batch(records: &[Self]) -> Result<(), AdmissionError> {
        let root = Self::batch_root(records)?;
        for record in records {
            record.validate()?;
            if record.snapshot_root != root {
                return Err(AdmissionError::CompletenessOrSequence);
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AdmissionError> {
        self.identity.validate()?;
        let start = time(&self.not_before)?;
        let end = time(&self.expires_at)?;
        let admitted = time(&self.admitted_at)?;
        let finalized = self.finalized_at.as_deref().map(time).transpose()?;
        let scope = &self.completeness_scope;
        if self.value != self.identity.typed_object
            || self.max_age_ms == 0
            || start > admitted
            || admitted >= end
            || end <= start
            || (end - start).whole_nanoseconds() > i128::from(self.max_age_ms) * 1_000_000
            || !urn(&scope.partition_id, "candidate-partition")
            || !urn(&scope.checkpoint_id, "fact-checkpoint")
            || scope.range_start > scope.range_end
            || scope.record_count == 0
            || self.identity.chain_anchor.block_height < scope.range_start
            || self.identity.chain_anchor.block_height > scope.range_end
            || !digest(&scope.checkpoint_digest)
            || self.delta_sequence == 0
            || self.delta_sequence > scope.record_count
            || [
                &self.source_digest,
                &self.derivation_digest,
                &self.provenance_digest,
                &self.snapshot_root,
            ]
            .iter()
            .any(|value| !digest(value))
            || self
                .predecessor_digest
                .as_ref()
                .is_some_and(|value| !digest(value))
            || self
                .relationship_predecessor_digest
                .as_ref()
                .is_some_and(|value| {
                    !digest(value) || !matches!(self.value, FactObject::RelationshipInterval { .. })
                })
            || ((self.delta_sequence == 1 && self.reorg_replacement_of.is_none())
                != self.predecessor_digest.is_none())
            || (scope.record_count == 1 && self.snapshot_root != self.single_entry_root()?)
            || self.replacement_generation == Some(0)
            || self
                .reorg_replacement_of
                .as_ref()
                .is_some_and(|value| !urn(value, "fact"))
            || finalized.is_some_and(|value| value < admitted || value >= end)
            || (self.identity.fact_status == FactLifecycleState::Finalized && finalized.is_none())
        {
            return Err(AdmissionError::SemanticOrPrivacy);
        }
        Ok(())
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, AdmissionError> {
        self.validate()?;
        encode_pc_cbor(Value::serialized(self).map_err(|_| AdmissionError::SchemaOrEncoding)?)
    }
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, AdmissionError> {
        if bytes.len() > 1_048_576 {
            return Err(AdmissionError::SchemaOrEncoding);
        }
        validate_pc_cbor(bytes)?;
        let value: Self =
            ciborium::de::from_reader(bytes).map_err(|_| AdmissionError::SchemaOrEncoding)?;
        if value.to_cbor()? != bytes {
            return Err(AdmissionError::SchemaOrEncoding);
        }
        Ok(value)
    }
    pub(crate) fn temporal_millis(&self) -> Result<(i64, i64), AdmissionError> {
        let millis = |value: &str| {
            i64::try_from(time(value)?.unix_timestamp_nanos() / 1_000_000)
                .map_err(|_| AdmissionError::SchemaOrEncoding)
        };
        Ok((millis(&self.not_before)?, millis(&self.expires_at)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> FactRecord {
        let identity = crate::identity::tests::identity();
        FactRecord {
            value: identity.typed_object.clone(),
            identity,
            not_before: fact_timestamp_from_ms(1_000).unwrap(),
            expires_at: fact_timestamp_from_ms(10_000).unwrap(),
            max_age_ms: 9_000,
            completeness_scope: FactCompletenessScope {
                partition_id: "urn:openpc:candidate-partition:018f0000-0000-7000-8000-000000000101"
                    .into(),
                range_start: 10,
                range_end: 10,
                record_count: 1,
                checkpoint_id: "urn:openpc:fact-checkpoint:018f0000-0000-7000-8000-000000000102"
                    .into(),
                checkpoint_digest: digest_text(&[1; 32]),
            },
            gap_state: FactGapState::Complete,
            source_digest: digest_text(&[2; 32]),
            derivation_digest: digest_text(&[3; 32]),
            provenance_digest: digest_text(&[4; 32]),
            predecessor_digest: None,
            relationship_predecessor_digest: None,
            relationship_candidate_cose: None,
            snapshot_root: String::new(),
            delta_sequence: 1,
            replacement_generation: None,
            reorg_replacement_of: None,
            admitted_at: fact_timestamp_from_ms(2_000).unwrap(),
            finalized_at: None,
        }
        .with_single_entry_root()
        .unwrap()
    }

    #[test]
    fn complete_batch_roots_bind_order_count_and_every_leaf() {
        fn records(count: usize) -> Vec<FactRecord> {
            let mut result: Vec<FactRecord> = Vec::new();
            for index in 0..count {
                let mut value = record();
                value.identity.fact_id = format!(
                    "urn:openpc:fact:018f0000-0000-7000-8000-{:012}",
                    200 + index
                );
                value.identity.chain_anchor.block_height = 10 + index as u64;
                value.identity = value.identity.with_derived_digest().unwrap();
                value.completeness_scope.record_count = count as u64;
                value.completeness_scope.range_end = 9 + count as u64;
                value.delta_sequence = index as u64 + 1;
                value.predecessor_digest =
                    result.last().map(|r| r.identity.local_fact_digest.clone());
                result.push(value);
            }
            let root = FactRecord::batch_root(&result).unwrap();
            for value in &mut result {
                value.snapshot_root = root.clone();
            }
            result
        }
        let single = record();
        assert_eq!(
            FactRecord::batch_root(std::slice::from_ref(&single)).unwrap(),
            single.snapshot_root
        );
        let node = |left: [u8; 32], right: [u8; 32]| {
            sha256(
                &encode_pc_cbor(Value::Array(vec![
                    Value::Text("openpc:fact-snapshot-node:v1".into()),
                    Value::Bytes(left.to_vec()),
                    Value::Bytes(right.to_vec()),
                ]))
                .unwrap(),
            )
        };
        for count in [2, 3] {
            let original = records(count);
            FactRecord::validate_batch(&original).unwrap();
            let left = node(
                original[0].snapshot_leaf().unwrap(),
                original[1].snapshot_leaf().unwrap(),
            );
            let expected = if count == 2 {
                left
            } else {
                node(left, original[2].snapshot_leaf().unwrap())
            };
            assert_eq!(original[0].snapshot_root, digest_text(&expected));
            let mut changed = original.clone();
            changed.swap(0, 1);
            assert!(FactRecord::validate_batch(&changed).is_err());
            let mut changed = original.clone();
            changed[1].provenance_digest = digest_text(&[42; 32]);
            assert!(FactRecord::validate_batch(&changed).is_err());
            let mut changed = original.clone();
            changed[0].snapshot_root = digest_text(&[43; 32]);
            assert!(FactRecord::validate_batch(&changed).is_err());
            assert!(FactRecord::validate_batch(&original[..count - 1]).is_err());
        }
    }

    #[test]
    fn first_reorg_delta_binds_immutable_predecessor() {
        let mut replacement = record();
        replacement.reorg_replacement_of =
            Some("urn:openpc:fact:018f0000-0000-7000-8000-000000000103".into());
        assert!(replacement.clone().with_single_entry_root().is_err());
        replacement.predecessor_digest = Some(digest_text(&[7; 32]));
        let replacement = replacement.with_single_entry_root().unwrap();
        assert_eq!(replacement.delta_sequence, 1);
        let bytes = replacement.to_cbor().unwrap();
        assert_eq!(
            FactRecord::from_cbor(&bytes).unwrap().to_cbor().unwrap(),
            bytes
        );
        let mut unlinked = replacement;
        unlinked.reorg_replacement_of = None;
        assert!(unlinked.with_single_entry_root().is_err());
    }

    #[test]
    fn record_root_binds_temporal_scope_and_lineage() {
        let original = record();
        let bytes = original.to_cbor().unwrap();
        assert_eq!(
            FactRecord::from_cbor(&bytes).unwrap().to_cbor().unwrap(),
            bytes
        );
        let mut tampered = original.clone();
        tampered.completeness_scope.range_end += 1;
        assert!(tampered.validate().is_err());
        let mut tampered = original.clone();
        tampered.provenance_digest = digest_text(&[5; 32]);
        assert!(tampered.validate().is_err());
        let mut invalid = original.clone();
        invalid.admitted_at = invalid.expires_at.clone();
        assert!(invalid.with_single_entry_root().is_err());
        let mut invalid = original.clone();
        invalid.delta_sequence = 2;
        assert!(invalid.with_single_entry_root().is_err());
        let mut invalid = original.clone();
        invalid.identity.fact_status = FactLifecycleState::Finalized;
        assert!(invalid.with_single_entry_root().is_err());
        let mut invalid = original;
        invalid.not_before = "1970-01-01T00:00:01Z".into();
        assert!(invalid.with_single_entry_root().is_err());
    }

    #[test]
    fn complete_record_requires_explicit_null_and_rejects_unknown_fields() {
        let original = record();
        let Value::Map(fields) = Value::serialized(&original).unwrap() else {
            panic!("record map")
        };
        for name in [
            "predecessorDigest",
            "replacementGeneration",
            "reorgReplacementOf",
            "finalizedAt",
        ] {
            let mut incomplete = fields.clone();
            incomplete.retain(|(k, _)| *k != Value::Text(name.into()));
            assert!(
                FactRecord::from_cbor(&encode_pc_cbor(Value::Map(incomplete)).unwrap()).is_err()
            );
        }
        let mut extra = fields;
        extra.push((Value::Text("ready".into()), Value::Bool(true)));
        assert!(FactRecord::from_cbor(&encode_pc_cbor(Value::Map(extra)).unwrap()).is_err());
    }
}
