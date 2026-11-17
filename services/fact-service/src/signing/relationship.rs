//! Registered candidate signature carried by its canonical fact, in the same
//! immutable storage and signing lineage as other acquired facts.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelationshipCandidate {
    schema_id: u32,
    schema_version: String,
    schema_digest: Vec<u8>,
    candidate_id: String,
    participant_id: String,
    privacy_domain_id: String,
    source_profile_id: String,
    generation_id: String,
    canonical_payload: Vec<u8>,
    payload_digest: Vec<u8>,
    provenance_digest: Vec<u8>,
    finality_anchor: Vec<u8>,
    observed_at_ms: i64,
    fresh_until_ms: i64,
}

impl PurposeBoundFactSigner {
    pub(crate) fn sign_relationship_candidate(
        &self,
        admission: &ValidatedAdmission,
    ) -> Result<Vec<u8>, FactSigningError> {
        if admission.schema_id() != pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID {
            return Err(FactSigningError::Verification);
        }
        let candidate = RelationshipCandidate {
            schema_id: pc_facts_core::RELATIONSHIP_CANDIDATE_SCHEMA_ID,
            schema_version: FACT_SCHEMA_VERSION_V1.into(),
            schema_digest: pc_facts_core::RELATIONSHIP_SCHEMA_DIGEST_V1.to_vec(),
            candidate_id: admission.candidate_id().into(),
            participant_id: admission.participant_id().into(),
            privacy_domain_id: admission.privacy_domain_id().into(),
            source_profile_id: admission.source_profile_id().into(),
            generation_id: admission.generation_id().into(),
            canonical_payload: admission.canonical_payload().to_vec(),
            payload_digest: admission.payload_digest().to_vec(),
            provenance_digest: admission.provenance_digest().to_vec(),
            finality_anchor: admission.finality_anchor().to_vec(),
            observed_at_ms: admission.observed_at_ms(),
            fresh_until_ms: admission.fresh_until_ms(),
        };
        let schema =
            fact_schema_identity(candidate.schema_id).ok_or(FactSigningError::Verification)?;
        self.sign_cose(
            schema.purpose_separator,
            &crate::state_value::canonical(&candidate)?,
        )
    }
}

impl FactSignatureVerifier {
    pub(super) fn verify_relationship_record(
        &self,
        payload: &[u8],
    ) -> Result<(), FactSigningError> {
        let value = decode_value(payload)?;
        if !matches!(&value,Value::Map(fields) if fields.iter().any(|(k,_)|k.as_text()==Some("identity")))
        {
            return Ok(());
        }
        let record = pc_facts_core::FactRecord::from_cbor(payload)?;
        if record.identity.fact_schema_id != pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID {
            return if record.relationship_candidate_cose.is_none() {
                Ok(())
            } else {
                Err(FactSigningError::Verification)
            };
        }
        let cose = record
            .relationship_candidate_cose
            .as_ref()
            .ok_or(FactSigningError::Verification)?;
        let claims =
            self.verified_stored_claims(pc_facts_core::RELATIONSHIP_CANDIDATE_SCHEMA_ID, cose)?;
        let candidate: RelationshipCandidate = claims
            .deserialized()
            .map_err(|_| FactSigningError::Verification)?;
        let candidate_value = crate::state_value::StateFactValue::from_payload(
            &candidate.canonical_payload,
            &candidate.participant_id,
            &candidate.privacy_domain_id,
        )?;
        if candidate.schema_id != pc_facts_core::RELATIONSHIP_CANDIDATE_SCHEMA_ID
            || candidate.schema_version != FACT_SCHEMA_VERSION_V1
            || candidate.schema_digest != pc_facts_core::RELATIONSHIP_SCHEMA_DIGEST_V1
            || candidate.payload_digest != sha256(&candidate.canonical_payload)
            || shard::digest_text(&candidate.payload_digest) != record.derivation_digest
            || shard::digest_text(&candidate.provenance_digest) != record.provenance_digest
            || record.identity.participant_id
                != format!("urn:openpc:participant:{}", candidate.participant_id)
            || record.identity.privacy_domain_id
                != Some(format!(
                    "urn:openpc:privacy-domain:{}",
                    candidate.privacy_domain_id
                ))
            || candidate_value.specialization
                != Some((record.identity.typed_subject.clone(), record.value.clone()))
            || pc_facts_core::fact_timestamp_from_ms(candidate.observed_at_ms)? != record.not_before
            || pc_facts_core::fact_timestamp_from_ms(candidate.fresh_until_ms)? != record.expires_at
        {
            return Err(FactSigningError::Verification);
        }
        Ok(())
    }
}
