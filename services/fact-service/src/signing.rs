use std::io::Cursor;

use ciborium::value::Value;
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use p256::elliptic_curve::Generate;
use pc_facts_core::{
    AdmissionError, FACT_BRIDGE_SCHEMA_DIGEST_V1, FACT_SCHEMA_VERSION_V1,
    FACT_SHARD_MANIFEST_SCHEMA_ID, ValidatedAdmission, encode_pc_cbor, fact_schema_identity,
    sha256, validate_pc_cbor,
};
use thiserror::Error;

mod local;
mod relationship;
pub(crate) mod shard;
pub use local::{LocalFactContext, VerifiedLocalFacts};

#[derive(Debug, Error)]
pub enum FactSigningError {
    #[error("invalid signing key")]
    InvalidKey,
    #[error("invalid or noncanonical COSE Sign1")]
    InvalidCose,
    #[error("COSE purpose, key, payload or signature mismatch")]
    Verification,
    #[error(transparent)]
    Admission(#[from] AdmissionError),
}

fn record_key_id(key: &[u8]) -> Result<String, FactSigningError> {
    if key.len() != 32 {
        return Err(FactSigningError::InvalidKey);
    }
    Ok(format!(
        "sha256:{}",
        key.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

fn check_record_key(payload: &[u8], key: &[u8]) -> Result<(), FactSigningError> {
    let value = decode_value(payload)?;
    if matches!(&value,Value::Map(fields) if fields.iter().any(|(k,_)|*k==Value::Text("identity".into())))
    {
        let record = pc_facts_core::FactRecord::from_cbor(payload)?;
        if record.identity.local_signing_key_id != record_key_id(key)? {
            return Err(FactSigningError::Verification);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedFact {
    pub(crate) claims_cbor: Vec<u8>,
    pub(crate) cose_sign1: Vec<u8>,
    pub(crate) signer_key_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedShard {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub generation_id: String,
    pub shard_digest: [u8; 32],
    pub claims_cbor: Vec<u8>,
    pub cose_sign1: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedShard {
    participant_id: String,
    privacy_domain_id: String,
    generation_id: String,
    shard_digest: [u8; 32],
    cose_sign1: Vec<u8>,
    pub(crate) manifest: Option<shard::FactShardManifest>,
    pub(crate) local_content: Option<Vec<u8>>,
    pub(crate) checkpoint_proofs: Vec<Vec<u8>>,
}

impl VerifiedShard {
    pub fn checkpoint_proofs(&self) -> &[Vec<u8>] {
        &self.checkpoint_proofs
    }
    pub fn local_content(&self) -> Option<&[u8]> {
        self.local_content.as_deref()
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
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    #[must_use]
    pub const fn shard_digest(&self) -> &[u8; 32] {
        &self.shard_digest
    }

    #[must_use]
    pub fn cose_sign1(&self) -> &[u8] {
        &self.cose_sign1
    }
}

#[derive(Clone)]
pub struct PurposeBoundFactSigner {
    key: SigningKey,
    key_id: Vec<u8>,
}

impl PurposeBoundFactSigner {
    /// The installed signing-key identifier is an explicit 32-byte digest label.
    /// Legacy COSE labels remain readable but cannot create a complete record.
    pub(crate) fn record_key_id(&self) -> Result<String, FactSigningError> {
        record_key_id(&self.key_id)
    }
    pub fn generate_ephemeral_local(key_id: Vec<u8>) -> Result<Self, FactSigningError> {
        if key_id.is_empty() || key_id.len() > 64 {
            return Err(FactSigningError::InvalidKey);
        }
        Ok(Self {
            key: SigningKey::generate(),
            key_id,
        })
    }

    /// The local deployment and its real-runtime fixtures share one canonical
    /// key identifier, including complete records that require a 32-byte ID.
    pub fn for_local_runtime(bytes: [u8; 32]) -> Result<Self, FactSigningError> {
        Self::from_secret_bytes(sha256(b"openpc-local-fact-signer-v1").to_vec(), bytes)
    }

    pub fn from_secret_bytes(key_id: Vec<u8>, bytes: [u8; 32]) -> Result<Self, FactSigningError> {
        if key_id.is_empty() || key_id.len() > 64 {
            return Err(FactSigningError::InvalidKey);
        }
        let key =
            SigningKey::from_bytes((&bytes).into()).map_err(|_| FactSigningError::InvalidKey)?;
        Ok(Self { key, key_id })
    }

    #[must_use]
    pub fn verifier(&self) -> FactSignatureVerifier {
        FactSignatureVerifier {
            key: *self.key.verifying_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn sign_admission(
        &self,
        admission: &ValidatedAdmission,
    ) -> Result<SignedFact, FactSigningError> {
        let claims_cbor = admission.signed_fact_claims_cbor()?;
        check_record_key(&claims_cbor, &self.key_id)?;
        self.verifier().verify_relationship_record(&claims_cbor)?;
        let cose_sign1 = self.sign_cose(admission.schema_purpose(), &claims_cbor)?;
        Ok(SignedFact {
            claims_cbor,
            cose_sign1,
            signer_key_id: self.key_id.clone(),
        })
    }

    pub fn sign_shard(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        generation_id: &str,
        shard_digest: [u8; 32],
    ) -> Result<SignedShard, FactSigningError> {
        let shard_schema = fact_schema_identity(FACT_SHARD_MANIFEST_SCHEMA_ID)
            .expect("frozen FactShardManifestV1 schema identity exists");
        let claims_cbor = encode_pc_cbor(Value::Map(vec![
            (
                Value::Text("schemaId".into()),
                Value::Integer(u64::from(shard_schema.numeric_schema_id).into()),
            ),
            (
                Value::Text("schemaVersion".into()),
                Value::Text(FACT_SCHEMA_VERSION_V1.into()),
            ),
            (
                Value::Text("schemaDigest".into()),
                Value::Bytes(FACT_BRIDGE_SCHEMA_DIGEST_V1.to_vec()),
            ),
            (
                Value::Text("purpose".into()),
                Value::Text(shard_schema.purpose_separator.into()),
            ),
            (
                Value::Text("participantId".into()),
                Value::Text(participant_id.into()),
            ),
            (
                Value::Text("privacyDomainId".into()),
                Value::Text(privacy_domain_id.into()),
            ),
            (
                Value::Text("generationId".into()),
                Value::Text(generation_id.into()),
            ),
            (
                Value::Text("shardDigest".into()),
                Value::Bytes(shard_digest.to_vec()),
            ),
        ]))?;
        let cose_sign1 = self.sign_cose(shard_schema.purpose_separator, &claims_cbor)?;
        Ok(SignedShard {
            participant_id: participant_id.into(),
            privacy_domain_id: privacy_domain_id.into(),
            generation_id: generation_id.into(),
            shard_digest,
            claims_cbor,
            cose_sign1,
        })
    }

    fn sign_cose(&self, purpose: &str, payload: &[u8]) -> Result<Vec<u8>, FactSigningError> {
        let protected = protected_header(purpose, &self.key_id)?;
        let signature_structure = signature_structure(&protected, payload)?;
        let signature: Signature = self.key.sign(&signature_structure);
        encode_pc_cbor(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))
        .map_err(FactSigningError::from)
    }

    pub(crate) fn sign_checkpoint(&self, claims: &Value) -> Result<Vec<u8>, FactSigningError> {
        let schema = fact_schema_identity(21008).expect("frozen FactCheckpointV1");
        self.sign_cose(schema.purpose_separator, &encode_pc_cbor(claims.clone())?)
    }

    pub(crate) fn sign_lineage(&self, claims: &Value) -> Result<Vec<u8>, FactSigningError> {
        let schema = fact_schema_identity(21004).expect("frozen FactLineageActionV1");
        self.sign_cose(schema.purpose_separator, &encode_pc_cbor(claims.clone())?)
    }
}

#[derive(Clone)]
pub struct FactSignatureVerifier {
    key: VerifyingKey,
    key_id: Vec<u8>,
}

impl FactSignatureVerifier {
    pub fn from_key_identifier(key_id: &str, bytes: &[u8]) -> Result<Self, FactSigningError> {
        let key_id = match key_id.strip_prefix("sha256:") {
            Some(hex) if hex.len() == 64 => {
                let mut decoded = Vec::with_capacity(32);
                for index in (0..hex.len()).step_by(2) {
                    decoded.push(
                        u8::from_str_radix(&hex[index..index + 2], 16)
                            .map_err(|_| FactSigningError::InvalidKey)?,
                    );
                }
                decoded
            }
            Some(_) => return Err(FactSigningError::InvalidKey),
            None => key_id.as_bytes().to_vec(),
        };
        Self::from_sec1_bytes(key_id, bytes)
    }

    pub(crate) fn verified_stored_claims(
        &self,
        schema_id: u32,
        cose_sign1: &[u8],
    ) -> Result<Value, FactSigningError> {
        let schema = fact_schema_identity(schema_id).ok_or(FactSigningError::Verification)?;
        let Value::Array(fields) = decode_value(cose_sign1)? else {
            return Err(FactSigningError::InvalidCose);
        };
        let Some(Value::Bytes(payload)) = fields.get(2) else {
            return Err(FactSigningError::InvalidCose);
        };
        self.verify_cose(schema.purpose_separator, payload, cose_sign1)?;
        validate_pc_cbor(payload)?;
        if matches!(
            schema_id,
            pc_facts_core::FACT_RECORD_SCHEMA_ID | pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID
        ) {
            check_record_key(payload, &self.key_id)?;
            let value = decode_value(payload)?;
            if matches!(&value,Value::Map(fields) if fields.iter().any(|(k,_)|k.as_text()==Some("identity")))
            {
                let record = pc_facts_core::FactRecord::from_cbor(payload)?;
                if record.identity.fact_schema_id != schema_id {
                    return Err(FactSigningError::Verification);
                }
                self.verify_relationship_record(payload)?;
            }
        }
        decode_value(payload)
    }

    pub fn from_sec1_bytes(key_id: Vec<u8>, bytes: &[u8]) -> Result<Self, FactSigningError> {
        if key_id.is_empty() || key_id.len() > 64 {
            return Err(FactSigningError::InvalidKey);
        }
        let key = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| FactSigningError::InvalidKey)?;
        Ok(Self { key, key_id })
    }

    #[must_use]
    pub fn sec1_bytes(&self) -> Vec<u8> {
        self.key.to_sec1_point(true).as_bytes().to_vec()
    }

    pub fn verify_fact(
        &self,
        admission: &ValidatedAdmission,
        signed: &SignedFact,
    ) -> Result<(), FactSigningError> {
        if signed.signer_key_id != self.key_id
            || signed.claims_cbor != admission.signed_fact_claims_cbor()?
        {
            return Err(FactSigningError::Verification);
        }
        check_record_key(&signed.claims_cbor, &self.key_id)?;
        self.verify_cose(
            admission.schema_purpose(),
            &signed.claims_cbor,
            &signed.cose_sign1,
        )
    }

    /// Admit a published manifest using only its signed bytes. Extracted claims
    /// are untrusted until the existing closed manifest verifier accepts them.
    pub fn verify_shard_cose(&self, cose_sign1: &[u8]) -> Result<VerifiedShard, FactSigningError> {
        if cose_sign1.is_empty() || cose_sign1.len() > 16_384 {
            return Err(FactSigningError::InvalidCose);
        }
        validate_pc_cbor(cose_sign1)?;
        let Value::Array(fields) = decode_value(cose_sign1)? else {
            return Err(FactSigningError::InvalidCose);
        };
        let Some(Value::Bytes(payload)) = fields.get(2) else {
            return Err(FactSigningError::InvalidCose);
        };
        let decoded = decode_value(payload)?;
        if matches!(&decoded, Value::Map(claims) if claims.iter().any(|(k,_)| k.as_text()==Some("shardContentDigest")))
        {
            let manifest = shard::FactShardManifest::from_cbor(payload, &self.key_id)?;
            self.verify_cose(manifest.purpose(), payload, cose_sign1)?;
            let mut digest = [0; 32];
            let hex = manifest.shard_content_digest.trim_start_matches("sha256:");
            for (i, byte) in digest.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                    .map_err(|_| FactSigningError::Verification)?;
            }
            return Ok(VerifiedShard {
                participant_id: manifest.participant_id.clone(),
                privacy_domain_id: manifest.privacy_domain_id.clone(),
                generation_id: manifest.generation_id.clone(),
                shard_digest: digest,
                cose_sign1: cose_sign1.to_vec(),
                manifest: Some(manifest),
                local_content: None,
                checkpoint_proofs: Vec::new(),
            });
        }
        let Value::Map(claims) = decode_value(payload)? else {
            return Err(FactSigningError::InvalidCose);
        };
        let claim = |name: &str| {
            claims
                .iter()
                .find(|(key, _)| *key == Value::Text(name.into()))
                .map(|(_, value)| value)
                .ok_or(FactSigningError::InvalidCose)
        };
        let text = |name: &str| match claim(name)? {
            Value::Text(value) => Ok(value.clone()),
            _ => Err(FactSigningError::InvalidCose),
        };
        let Value::Bytes(shard_digest) = claim("shardDigest")? else {
            return Err(FactSigningError::InvalidCose);
        };
        self.verify_shard(&SignedShard {
            participant_id: text("participantId")?,
            privacy_domain_id: text("privacyDomainId")?,
            generation_id: text("generationId")?,
            shard_digest: shard_digest
                .as_slice()
                .try_into()
                .map_err(|_| FactSigningError::InvalidCose)?,
            claims_cbor: payload.clone(),
            cose_sign1: cose_sign1.to_vec(),
        })
    }

    pub fn verify_shard(&self, signed: &SignedShard) -> Result<VerifiedShard, FactSigningError> {
        let shard_schema = fact_schema_identity(FACT_SHARD_MANIFEST_SCHEMA_ID)
            .expect("frozen FactShardManifestV1 schema identity exists");
        self.verify_cose(
            shard_schema.purpose_separator,
            &signed.claims_cbor,
            &signed.cose_sign1,
        )?;
        let expected = encode_pc_cbor(Value::Map(vec![
            (
                Value::Text("schemaId".into()),
                Value::Integer(u64::from(shard_schema.numeric_schema_id).into()),
            ),
            (
                Value::Text("schemaVersion".into()),
                Value::Text(FACT_SCHEMA_VERSION_V1.into()),
            ),
            (
                Value::Text("schemaDigest".into()),
                Value::Bytes(FACT_BRIDGE_SCHEMA_DIGEST_V1.to_vec()),
            ),
            (
                Value::Text("purpose".into()),
                Value::Text(shard_schema.purpose_separator.into()),
            ),
            (
                Value::Text("participantId".into()),
                Value::Text(signed.participant_id.clone()),
            ),
            (
                Value::Text("privacyDomainId".into()),
                Value::Text(signed.privacy_domain_id.clone()),
            ),
            (
                Value::Text("generationId".into()),
                Value::Text(signed.generation_id.clone()),
            ),
            (
                Value::Text("shardDigest".into()),
                Value::Bytes(signed.shard_digest.to_vec()),
            ),
        ]))?;
        if expected != signed.claims_cbor {
            return Err(FactSigningError::Verification);
        }
        Ok(VerifiedShard {
            participant_id: signed.participant_id.clone(),
            privacy_domain_id: signed.privacy_domain_id.clone(),
            generation_id: signed.generation_id.clone(),
            shard_digest: signed.shard_digest,
            cose_sign1: signed.cose_sign1.clone(),
            manifest: None,
            local_content: None,
            checkpoint_proofs: Vec::new(),
        })
    }

    fn verify_cose(
        &self,
        purpose: &str,
        expected_payload: &[u8],
        cose_sign1: &[u8],
    ) -> Result<(), FactSigningError> {
        validate_pc_cbor(cose_sign1).map_err(|_| FactSigningError::InvalidCose)?;
        let value = decode_value(cose_sign1)?;
        let Value::Array(fields) = value else {
            return Err(FactSigningError::InvalidCose);
        };
        if fields.len() != 4 {
            return Err(FactSigningError::InvalidCose);
        }
        let Value::Bytes(protected) = &fields[0] else {
            return Err(FactSigningError::InvalidCose);
        };
        if fields[1] != Value::Map(Vec::new()) {
            return Err(FactSigningError::InvalidCose);
        }
        let Value::Bytes(payload) = &fields[2] else {
            return Err(FactSigningError::InvalidCose);
        };
        let Value::Bytes(signature_bytes) = &fields[3] else {
            return Err(FactSigningError::InvalidCose);
        };
        if payload != expected_payload || *protected != protected_header(purpose, &self.key_id)? {
            return Err(FactSigningError::Verification);
        }
        let signature =
            Signature::from_slice(signature_bytes).map_err(|_| FactSigningError::Verification)?;
        self.key
            .verify(&signature_structure(protected, payload)?, &signature)
            .map_err(|_| FactSigningError::Verification)
    }
}

fn protected_header(purpose: &str, key_id: &[u8]) -> Result<Vec<u8>, FactSigningError> {
    encode_pc_cbor(Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer((-7).into())),
        (Value::Integer(3.into()), Value::Text(purpose.into())),
        (Value::Integer(4.into()), Value::Bytes(key_id.to_vec())),
    ]))
    .map_err(FactSigningError::from)
}

fn signature_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, FactSigningError> {
    encode_pc_cbor(Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
    .map_err(FactSigningError::from)
}

fn decode_value(bytes: &[u8]) -> Result<Value, FactSigningError> {
    let mut cursor = Cursor::new(bytes);
    let value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| FactSigningError::InvalidCose)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(FactSigningError::InvalidCose);
    }
    Ok(value)
}

#[must_use]
pub fn signed_fact_digest(signed: &SignedFact) -> [u8; 32] {
    sha256(&signed.cose_sign1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_facts_core::{
        FACT_ADMISSION_CANDIDATE_SCHEMA_ID, FactAdmissionCandidate, TrustedAdmissionContext,
        fact_schema_identity, sha256, validate_admission,
    };

    fn admission() -> ValidatedAdmission {
        let payload = encode_pc_cbor(Value::Map(vec![(
            Value::Text("fact".into()),
            Value::Text("exact".into()),
        )]))
        .unwrap();
        let provenance = b"lineage".to_vec();
        let anchor = sha256(b"block");
        validate_admission(
            FactAdmissionCandidate {
                candidate_id: "candidate".into(),
                participant_id: "participant".into(),
                privacy_domain_id: "privacy".into(),
                source_profile_id: "profile".into(),
                generation_id: "generation".into(),
                schema_id: FACT_ADMISSION_CANDIDATE_SCHEMA_ID,
                schema_version: FACT_SCHEMA_VERSION_V1.into(),
                schema_digest: FACT_BRIDGE_SCHEMA_DIGEST_V1,
                schema_purpose: fact_schema_identity(FACT_ADMISSION_CANDIDATE_SCHEMA_ID)
                    .unwrap()
                    .purpose_separator
                    .into(),
                sequence: 1,
                observed_at_ms: 1_000,
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
            &TrustedAdmissionContext {
                participant_id: "participant".into(),
                privacy_domain_id: "privacy".into(),
                source_profile_id: "profile".into(),
                generation_id: "generation".into(),
                expected_sequence: 1,
                now_ms: 1_100,
                maximum_age_ms: 1_000,
                independently_derived_provenance_digest: sha256(b"lineage"),
                trusted_finality_anchor: anchor,
                profile_active: true,
                generation_fenced: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn exact_cose_sign1_round_trip_and_every_binding_tamper_fail() {
        let admission = admission();
        let signer =
            PurposeBoundFactSigner::from_secret_bytes(b"local-test-key".to_vec(), [7; 32]).unwrap();
        let verifier = signer.verifier();
        let signed = signer.sign_admission(&admission).unwrap();
        verifier.verify_fact(&admission, &signed).unwrap();
        let Value::Map(claims) = decode_value(&signed.claims_cbor).unwrap() else {
            panic!("signed fact claims must be a map");
        };
        let claim = |name: &str| {
            claims
                .iter()
                .find_map(|(key, value)| (key == &Value::Text(name.into())).then_some(value))
                .expect("required signed fact claim")
        };
        assert_eq!(
            claim("schemaId"),
            &Value::Integer(u64::from(admission.schema_id()).into())
        );
        assert_eq!(
            claim("schemaVersion"),
            &Value::Text(FACT_SCHEMA_VERSION_V1.into())
        );
        assert_eq!(
            claim("schemaDigest"),
            &Value::Bytes(FACT_BRIDGE_SCHEMA_DIGEST_V1.to_vec())
        );
        assert_eq!(
            claim("purpose"),
            &Value::Text(admission.schema_purpose().into())
        );

        let mut wrong_purpose = signed.clone();
        wrong_purpose.cose_sign1 = signer
            .sign_cose("openpc:wrong:v1", &wrong_purpose.claims_cbor)
            .unwrap();
        assert!(verifier.verify_fact(&admission, &wrong_purpose).is_err());

        let mut altered = signed.clone();
        altered.cose_sign1.push(0);
        assert!(verifier.verify_fact(&admission, &altered).is_err());
        let mut invalid_signature = signed.clone();
        *invalid_signature.cose_sign1.last_mut().unwrap() ^= 1;
        assert!(
            verifier
                .verify_fact(&admission, &invalid_signature)
                .is_err()
        );
        let Value::Array(mut fields) = decode_value(&signed.cose_sign1).unwrap() else {
            panic!("COSE Sign1 must be an array");
        };
        fields[2] = Value::Bytes(b"altered-payload".to_vec());
        altered = signed.clone();
        altered.cose_sign1 = encode_pc_cbor(Value::Array(fields)).unwrap();
        assert!(verifier.verify_fact(&admission, &altered).is_err());
        assert!(
            PurposeBoundFactSigner::from_secret_bytes(b"other".to_vec(), [8; 32])
                .unwrap()
                .verifier()
                .verify_fact(&admission, &signed)
                .is_err()
        );
        let shard = signer
            .sign_shard("participant", "privacy", "generation", sha256(b"shard"))
            .unwrap();
        verifier.verify_shard(&shard).unwrap();
        assert!(
            verifier
                .verify_cose(
                    admission.schema_purpose(),
                    &shard.claims_cbor,
                    &shard.cose_sign1,
                )
                .is_err()
        );
    }
    #[test]
    fn published_shard_bytes_require_exact_manifest_claims_and_trust() {
        let signer =
            PurposeBoundFactSigner::from_secret_bytes(b"shard-owner".to_vec(), [6; 32]).unwrap();
        let verifier = signer.verifier();
        let shard = signer
            .sign_shard("participant", "privacy", "generation", sha256(b"shard"))
            .unwrap();
        assert_eq!(
            verifier.verify_shard_cose(&shard.cose_sign1).unwrap(),
            verifier.verify_shard(&shard).unwrap()
        );
        assert!(
            PurposeBoundFactSigner::from_secret_bytes(b"shard-owner".to_vec(), [7; 32])
                .unwrap()
                .verifier()
                .verify_shard_cose(&shard.cose_sign1)
                .is_err()
        );
        let mut trailing = shard.cose_sign1.clone();
        trailing.push(0);
        assert!(verifier.verify_shard_cose(&trailing).is_err());
        let schema = fact_schema_identity(FACT_SHARD_MANIFEST_SCHEMA_ID).unwrap();
        for change in 0..4 {
            let Value::Map(mut fields) = decode_value(&shard.claims_cbor).unwrap() else {
                panic!("manifest map");
            };
            match change {
                0 => fields.push((Value::Text("extra".into()), Value::Integer(1.into()))),
                1 => {
                    fields
                        .iter_mut()
                        .find(|(key, _)| *key == Value::Text("schemaVersion".into()))
                        .unwrap()
                        .1 = Value::Text("foreign".into())
                }
                2 => {
                    fields
                        .iter_mut()
                        .find(|(key, _)| *key == Value::Text("generationId".into()))
                        .unwrap()
                        .1 = Value::Integer(1.into())
                }
                _ => {
                    fields
                        .iter_mut()
                        .find(|(key, _)| *key == Value::Text("shardDigest".into()))
                        .unwrap()
                        .1 = Value::Bytes(vec![0; 31])
                }
            }
            let payload = encode_pc_cbor(Value::Map(fields)).unwrap();
            let signed = signer
                .sign_cose(schema.purpose_separator, &payload)
                .unwrap();
            assert!(verifier.verify_shard_cose(&signed).is_err());
        }
    }
}
