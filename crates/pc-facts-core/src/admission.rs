use std::io::Cursor;

use ciborium::value::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    FACT_ADMISSION_CANDIDATE_SCHEMA_ID, FACT_BRIDGE_SCHEMA_DIGEST_V1, FACT_RECORD_SCHEMA_ID,
    FACT_SCHEMA_VERSION_V1, fact_schema_identity,
};

const MAX_CANONICAL_PAYLOAD_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactAdmissionCandidate {
    pub candidate_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub source_profile_id: String,
    pub generation_id: String,
    pub schema_id: u32,
    pub schema_version: String,
    pub schema_digest: [u8; 32],
    pub schema_purpose: String,
    pub sequence: u64,
    pub observed_at_ms: i64,
    pub canonical_payload: Vec<u8>,
    pub declared_payload_digest: [u8; 32],
    pub canonical_provenance: Vec<u8>,
    pub declared_provenance_digest: [u8; 32],
    pub finality_anchor: [u8; 32],
    pub complete: bool,
    pub semantic_valid: bool,
    pub conflict_detected: bool,
    pub terminal_denial: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedAdmissionContext {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub source_profile_id: String,
    pub generation_id: String,
    pub expected_sequence: u64,
    pub now_ms: i64,
    pub maximum_age_ms: i64,
    pub independently_derived_provenance_digest: [u8; 32],
    pub trusted_finality_anchor: [u8; 32],
    pub profile_active: bool,
    pub generation_fenced: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAdmission {
    candidate_id: String,
    participant_id: String,
    privacy_domain_id: String,
    source_profile_id: String,
    generation_id: String,
    sequence: u64,
    observed_at_ms: i64,
    fresh_until_ms: i64,
    canonical_payload: Vec<u8>,
    finality_anchor: [u8; 32],
    payload_digest: [u8; 32],
    provenance_digest: [u8; 32],
    canonical_fact_digest: [u8; 32],
    canonical_record: Option<Vec<u8>>,
    relationship: bool,
}

impl ValidatedAdmission {
    /// The real admission owner binds the complete independently constructed
    /// record only after FactStore has allocated its immutable ID/generation.
    pub fn bind_complete_record(
        mut self,
        record: crate::FactRecord,
    ) -> Result<Self, AdmissionError> {
        record.validate()?;
        let identity = &record.identity;
        if identity.fact_schema_id != self.schema_id()
            || identity.participant_id != format!("urn:openpc:participant:{}", self.participant_id)
            || identity.privacy_domain_id.as_deref()
                != Some(format!("urn:openpc:privacy-domain:{}", self.privacy_domain_id).as_str())
            || record.derivation_digest != crate::identity::digest_text(&self.payload_digest)
            || record.provenance_digest != crate::identity::digest_text(&self.provenance_digest)
            || record.temporal_millis()? != (self.observed_at_ms, self.fresh_until_ms)
            || identity.fact_status != crate::FactLifecycleState::Admitted
        {
            return Err(AdmissionError::SemanticOrPrivacy);
        }
        let digest = identity
            .local_fact_digest
            .strip_prefix("sha256:")
            .ok_or(AdmissionError::SchemaOrEncoding)?;
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)
                .map_err(|_| AdmissionError::SchemaOrEncoding)?;
        }
        self.canonical_fact_digest = bytes;
        self.canonical_record = Some(record.to_cbor()?);
        Ok(self)
    }

    pub fn canonical_record(&self) -> Option<&[u8]> {
        self.canonical_record.as_deref()
    }
    #[must_use]
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    #[must_use]
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    #[must_use]
    pub fn privacy_domain_id(&self) -> &str {
        &self.privacy_domain_id
    }

    #[must_use]
    pub fn source_profile_id(&self) -> &str {
        &self.source_profile_id
    }

    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    #[must_use]
    pub const fn schema_id(&self) -> u32 {
        crate::record_schema(self.relationship)
    }

    #[must_use]
    pub const fn schema_version(&self) -> &'static str {
        FACT_SCHEMA_VERSION_V1
    }

    #[must_use]
    pub const fn schema_digest(&self) -> &[u8; 32] {
        crate::record_schema_digest(self.relationship)
    }

    #[must_use]
    pub fn schema_purpose(&self) -> &'static str {
        fact_schema_identity(self.schema_id())
            .expect("frozen FactRecordV1 schema identity exists")
            .purpose_separator
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }

    #[must_use]
    pub const fn fresh_until_ms(&self) -> i64 {
        self.fresh_until_ms
    }

    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }

    #[must_use]
    pub const fn finality_anchor(&self) -> &[u8; 32] {
        &self.finality_anchor
    }

    #[must_use]
    pub const fn payload_digest(&self) -> &[u8; 32] {
        &self.payload_digest
    }

    #[must_use]
    pub const fn provenance_digest(&self) -> &[u8; 32] {
        &self.provenance_digest
    }

    #[must_use]
    pub const fn canonical_fact_digest(&self) -> &[u8; 32] {
        &self.canonical_fact_digest
    }

    pub fn signed_fact_claims_cbor(&self) -> Result<Vec<u8>, AdmissionError> {
        if let Some(record) = &self.canonical_record {
            return Ok(record.clone());
        }
        if self.relationship {
            return Err(AdmissionError::SchemaOrEncoding);
        }
        encode_pc_cbor(Value::Map(vec![
            (
                Value::Text("candidateId".into()),
                Value::Text(self.candidate_id.clone()),
            ),
            (
                Value::Text("participantId".into()),
                Value::Text(self.participant_id.clone()),
            ),
            (
                Value::Text("privacyDomainId".into()),
                Value::Text(self.privacy_domain_id.clone()),
            ),
            (
                Value::Text("sourceProfileId".into()),
                Value::Text(self.source_profile_id.clone()),
            ),
            (
                Value::Text("generationId".into()),
                Value::Text(self.generation_id.clone()),
            ),
            (
                Value::Text("schemaId".into()),
                Value::Integer(u64::from(self.schema_id()).into()),
            ),
            (
                Value::Text("schemaVersion".into()),
                Value::Text(self.schema_version().into()),
            ),
            (
                Value::Text("schemaDigest".into()),
                Value::Bytes(self.schema_digest().to_vec()),
            ),
            (
                Value::Text("purpose".into()),
                Value::Text(self.schema_purpose().into()),
            ),
            (
                Value::Text("sequence".into()),
                Value::Integer(self.sequence.into()),
            ),
            (
                Value::Text("observedAtMs".into()),
                Value::Integer(self.observed_at_ms.into()),
            ),
            (
                Value::Text("freshUntilMs".into()),
                Value::Integer(self.fresh_until_ms.into()),
            ),
            (
                Value::Text("payloadDigest".into()),
                Value::Bytes(self.payload_digest.to_vec()),
            ),
            (
                Value::Text("provenanceDigest".into()),
                Value::Bytes(self.provenance_digest.to_vec()),
            ),
            (
                Value::Text("finalityAnchor".into()),
                Value::Bytes(self.finality_anchor.to_vec()),
            ),
            (
                Value::Text("canonicalPayload".into()),
                Value::Bytes(self.canonical_payload.clone()),
            ),
        ]))
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AdmissionError {
    #[error("FBC-4000 authority or scope mismatch")]
    Authority,
    #[error("FBC-4001 closed schema or canonical payload rejected")]
    SchemaOrEncoding,
    #[error("FBC-4002 independently derived provenance mismatch")]
    Provenance,
    #[error("FBC-4003 finality anchor rejected or generation fenced")]
    FinalityOrFence,
    #[error("FBC-4004 semantic or privacy bounds rejected")]
    SemanticOrPrivacy,
    #[error("FBC-4005 candidate incomplete or sequence non-contiguous")]
    CompletenessOrSequence,
    #[error("FBC-4006 candidate stale, future issued, or profile inactive")]
    FreshnessOrProfile,
    #[error("FBC-4007 conflict or terminal denial")]
    ConflictOrTerminalDenial,
    #[error("FBC-4008 PC-CBOR-1 encoding is invalid or non-canonical")]
    NonCanonicalCbor,
}

#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn canonicalize_pc_cbor(value: Value) -> Result<Value, AdmissionError> {
    match value {
        Value::Integer(_) | Value::Bytes(_) | Value::Text(_) | Value::Bool(_) | Value::Null => {
            Ok(value)
        }
        Value::Array(values) => values
            .into_iter()
            .map(canonicalize_pc_cbor)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Map(entries) => {
            let mut encoded = entries
                .into_iter()
                .map(|(key, value)| {
                    let key = canonicalize_pc_cbor(key)?;
                    let value = canonicalize_pc_cbor(value)?;
                    let mut key_bytes = Vec::new();
                    ciborium::ser::into_writer(&key, &mut key_bytes)
                        .map_err(|_| AdmissionError::NonCanonicalCbor)?;
                    Ok((key_bytes, key, value))
                })
                .collect::<Result<Vec<_>, AdmissionError>>()?;
            encoded.sort_by(|left, right| {
                left.0
                    .len()
                    .cmp(&right.0.len())
                    .then_with(|| left.0.cmp(&right.0))
            });
            if encoded.windows(2).any(|rows| rows[0].0 == rows[1].0) {
                return Err(AdmissionError::NonCanonicalCbor);
            }
            Ok(Value::Map(
                encoded
                    .into_iter()
                    .map(|(_, key, value)| (key, value))
                    .collect(),
            ))
        }
        Value::Float(_) | Value::Tag(_, _) => Err(AdmissionError::NonCanonicalCbor),
        _ => Err(AdmissionError::NonCanonicalCbor),
    }
}

pub fn encode_pc_cbor(value: Value) -> Result<Vec<u8>, AdmissionError> {
    let value = canonicalize_pc_cbor(value)?;
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).map_err(|_| AdmissionError::NonCanonicalCbor)?;
    Ok(bytes)
}

pub fn validate_pc_cbor(bytes: &[u8]) -> Result<(), AdmissionError> {
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| AdmissionError::NonCanonicalCbor)?;
    if cursor.position() != bytes.len() as u64 || encode_pc_cbor(value)? != bytes {
        return Err(AdmissionError::NonCanonicalCbor);
    }
    Ok(())
}

pub fn validate_admission(
    candidate: FactAdmissionCandidate,
    trusted: &TrustedAdmissionContext,
) -> Result<ValidatedAdmission, AdmissionError> {
    if candidate.participant_id != trusted.participant_id
        || candidate.privacy_domain_id != trusted.privacy_domain_id
        || candidate.source_profile_id != trusted.source_profile_id
        || candidate.generation_id != trusted.generation_id
    {
        return Err(AdmissionError::Authority);
    }

    let relationship = candidate.schema_id == crate::RELATIONSHIP_CANDIDATE_SCHEMA_ID;
    let expected_id = if relationship {
        crate::RELATIONSHIP_CANDIDATE_SCHEMA_ID
    } else {
        FACT_ADMISSION_CANDIDATE_SCHEMA_ID
    };
    let expected_schema = fact_schema_identity(expected_id)
        .expect("frozen FactAdmissionCandidateV1 schema identity exists");
    if candidate.schema_id != expected_schema.numeric_schema_id
        || candidate.schema_version != FACT_SCHEMA_VERSION_V1
        || candidate.schema_digest != *crate::record_schema_digest(relationship)
        || candidate.schema_purpose != expected_schema.purpose_separator
        || candidate.candidate_id.is_empty()
        || candidate.canonical_payload.is_empty()
        || candidate.canonical_payload.len() > MAX_CANONICAL_PAYLOAD_BYTES
        || sha256(&candidate.canonical_payload) != candidate.declared_payload_digest
    {
        return Err(AdmissionError::SchemaOrEncoding);
    }
    validate_pc_cbor(&candidate.canonical_payload)?;

    let provenance_digest = sha256(&candidate.canonical_provenance);
    if candidate.canonical_provenance.is_empty()
        || provenance_digest != candidate.declared_provenance_digest
        || provenance_digest != trusted.independently_derived_provenance_digest
    {
        return Err(AdmissionError::Provenance);
    }

    if candidate.finality_anchor != trusted.trusted_finality_anchor || trusted.generation_fenced {
        return Err(AdmissionError::FinalityOrFence);
    }

    if !candidate.semantic_valid {
        return Err(AdmissionError::SemanticOrPrivacy);
    }

    if !candidate.complete || candidate.sequence != trusted.expected_sequence {
        return Err(AdmissionError::CompletenessOrSequence);
    }

    let age_ms = trusted
        .now_ms
        .checked_sub(candidate.observed_at_ms)
        .ok_or(AdmissionError::FreshnessOrProfile)?;
    if !trusted.profile_active
        || trusted.maximum_age_ms < 0
        || age_ms < 0
        || age_ms > trusted.maximum_age_ms
    {
        return Err(AdmissionError::FreshnessOrProfile);
    }

    if candidate.conflict_detected || candidate.terminal_denial {
        return Err(AdmissionError::ConflictOrTerminalDenial);
    }

    let payload_digest = candidate.declared_payload_digest;

    Ok(ValidatedAdmission {
        candidate_id: candidate.candidate_id,
        participant_id: candidate.participant_id,
        privacy_domain_id: candidate.privacy_domain_id,
        source_profile_id: candidate.source_profile_id,
        generation_id: candidate.generation_id,
        sequence: candidate.sequence,
        observed_at_ms: candidate.observed_at_ms,
        fresh_until_ms: candidate
            .observed_at_ms
            .checked_add(trusted.maximum_age_ms)
            .ok_or(AdmissionError::FreshnessOrProfile)?,
        canonical_payload: candidate.canonical_payload,
        finality_anchor: candidate.finality_anchor,
        payload_digest,
        provenance_digest,
        canonical_fact_digest: canonical_fact_digest(
            &payload_digest,
            &provenance_digest,
            &candidate.finality_anchor,
            candidate.sequence,
        ),
        canonical_record: None,
        relationship,
    })
}

/// Shared immutable fact identity for admission and verified durable readback.
#[must_use]
pub fn canonical_fact_digest(
    payload_digest: &[u8; 32],
    provenance_digest: &[u8; 32],
    finality_anchor: &[u8; 32],
    sequence: u64,
) -> [u8; 32] {
    let record_schema = fact_schema_identity(FACT_RECORD_SCHEMA_ID)
        .expect("frozen FactRecordV1 schema identity exists");
    let mut fact_preimage = Vec::with_capacity(32 * 4 + 64);
    fact_preimage.extend_from_slice(&FACT_RECORD_SCHEMA_ID.to_be_bytes());
    fact_preimage.extend_from_slice(FACT_SCHEMA_VERSION_V1.as_bytes());
    fact_preimage.extend_from_slice(&FACT_BRIDGE_SCHEMA_DIGEST_V1);
    fact_preimage.extend_from_slice(record_schema.purpose_separator.as_bytes());
    fact_preimage.extend_from_slice(payload_digest);
    fact_preimage.extend_from_slice(provenance_digest);
    fact_preimage.extend_from_slice(finality_anchor);
    fact_preimage.extend_from_slice(&sequence.to_be_bytes());
    sha256(&fact_preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    type AdmissionMutation = (
        AdmissionError,
        Box<dyn Fn(&mut FactAdmissionCandidate, &mut TrustedAdmissionContext)>,
    );

    fn valid() -> (FactAdmissionCandidate, TrustedAdmissionContext) {
        let payload = encode_pc_cbor(Value::Map(vec![
            (
                Value::Text("factType".into()),
                Value::Text("membership".into()),
            ),
            (Value::Text("member".into()), Value::Bytes(vec![1, 2, 3])),
        ]))
        .unwrap();
        let provenance = b"canonical-lineage-v1".to_vec();
        let anchor = sha256(b"finalized-block");
        (
            FactAdmissionCandidate {
                candidate_id: "candidate-1".into(),
                participant_id: "participant-1".into(),
                privacy_domain_id: "privacy-1".into(),
                source_profile_id: "profile-1".into(),
                generation_id: "generation-1".into(),
                schema_id: FACT_ADMISSION_CANDIDATE_SCHEMA_ID,
                schema_version: FACT_SCHEMA_VERSION_V1.into(),
                schema_digest: FACT_BRIDGE_SCHEMA_DIGEST_V1,
                schema_purpose: fact_schema_identity(FACT_ADMISSION_CANDIDATE_SCHEMA_ID)
                    .unwrap()
                    .purpose_separator
                    .into(),
                sequence: 7,
                observed_at_ms: 9_900,
                declared_payload_digest: sha256(&payload),
                canonical_payload: payload,
                declared_provenance_digest: sha256(&provenance),
                canonical_provenance: provenance,
                finality_anchor: anchor,
                complete: true,
                semantic_valid: true,
                conflict_detected: false,
                terminal_denial: false,
            },
            TrustedAdmissionContext {
                participant_id: "participant-1".into(),
                privacy_domain_id: "privacy-1".into(),
                source_profile_id: "profile-1".into(),
                generation_id: "generation-1".into(),
                expected_sequence: 7,
                now_ms: 10_000,
                maximum_age_ms: 1_000,
                independently_derived_provenance_digest: sha256(b"canonical-lineage-v1"),
                trusted_finality_anchor: anchor,
                profile_active: true,
                generation_fenced: false,
            },
        )
    }

    #[test]
    fn exact_candidate_is_validated_and_digest_is_deterministic() {
        let (candidate, trusted) = valid();
        let first = validate_admission(candidate.clone(), &trusted).unwrap();
        let second = validate_admission(candidate, &trusted).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.sequence(), 7);
    }

    #[test]
    fn every_ordered_admission_boundary_fails_closed() {
        let cases: Vec<AdmissionMutation> = vec![
            (
                AdmissionError::Authority,
                Box::new(|candidate, _| candidate.participant_id = "other".into()),
            ),
            (
                AdmissionError::SchemaOrEncoding,
                Box::new(|candidate, _| candidate.schema_id = 99),
            ),
            (
                AdmissionError::SchemaOrEncoding,
                Box::new(|candidate, _| candidate.schema_version = "2.0.0".into()),
            ),
            (
                AdmissionError::SchemaOrEncoding,
                Box::new(|candidate, _| candidate.schema_digest = [0; 32]),
            ),
            (
                AdmissionError::SchemaOrEncoding,
                Box::new(|candidate, _| candidate.schema_purpose = "openpc:wrong:v1".into()),
            ),
            (
                AdmissionError::SchemaOrEncoding,
                Box::new(|candidate, _| candidate.canonical_payload.push(0)),
            ),
            (
                AdmissionError::Provenance,
                Box::new(|candidate, _| candidate.canonical_provenance.push(0)),
            ),
            (
                AdmissionError::FinalityOrFence,
                Box::new(|candidate, _| candidate.finality_anchor = [0; 32]),
            ),
            (
                AdmissionError::FinalityOrFence,
                Box::new(|_, trusted| trusted.generation_fenced = true),
            ),
            (
                AdmissionError::SemanticOrPrivacy,
                Box::new(|candidate, _| candidate.semantic_valid = false),
            ),
            (
                AdmissionError::CompletenessOrSequence,
                Box::new(|candidate, _| candidate.complete = false),
            ),
            (
                AdmissionError::CompletenessOrSequence,
                Box::new(|candidate, _| candidate.sequence += 1),
            ),
            (
                AdmissionError::FreshnessOrProfile,
                Box::new(|candidate, _| candidate.observed_at_ms = 11_000),
            ),
            (
                AdmissionError::FreshnessOrProfile,
                Box::new(|candidate, _| candidate.observed_at_ms = 1),
            ),
            (
                AdmissionError::FreshnessOrProfile,
                Box::new(|_, trusted| trusted.profile_active = false),
            ),
            (
                AdmissionError::ConflictOrTerminalDenial,
                Box::new(|candidate, _| candidate.conflict_detected = true),
            ),
            (
                AdmissionError::ConflictOrTerminalDenial,
                Box::new(|candidate, _| candidate.terminal_denial = true),
            ),
        ];

        for (expected, mutate) in cases {
            let (mut candidate, mut trusted) = valid();
            mutate(&mut candidate, &mut trusted);
            assert_eq!(validate_admission(candidate, &trusted), Err(expected));
        }
    }

    #[test]
    fn pc_cbor_rejects_noncanonical_map_order_duplicate_keys_indefinite_and_float() {
        let canonical = encode_pc_cbor(Value::Map(vec![
            (Value::Text("b".into()), Value::Integer(2.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
        ]))
        .unwrap();
        validate_pc_cbor(&canonical).unwrap();

        assert_eq!(
            validate_pc_cbor(&[0xa2, 0x61, b'b', 0x02, 0x61, b'a', 0x01]),
            Err(AdmissionError::NonCanonicalCbor)
        );
        assert_eq!(
            validate_pc_cbor(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]),
            Err(AdmissionError::NonCanonicalCbor)
        );
        assert_eq!(
            validate_pc_cbor(&[0x9f, 0x01, 0xff]),
            Err(AdmissionError::NonCanonicalCbor)
        );
        assert_eq!(
            validate_pc_cbor(&[0xf9, 0x3c, 0x00]),
            Err(AdmissionError::NonCanonicalCbor)
        );
    }
}
