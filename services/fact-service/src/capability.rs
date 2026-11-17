use std::sync::Arc;

mod retirement;

use hmac::{Hmac, KeyInit, Mac};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use pc_facts_core::{FACT_SHARD_MANIFEST_SCHEMA_ID, ValidatedAdmission, fact_schema_identity};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{SignedFact, VerifiedShard, signed_fact_digest};

pub(crate) const CAPABILITY_DOMAIN: &str = "OPENPC_FACTSTORE_DATABASE_MUTATION_CAPABILITY_V1";
const CAPABILITY_VERSION: u16 = 1;
const FACT_PURPOSE: &str = "openpc:fact-record:v1";
const ADMIT_INTENT: &str = "ADMIT_NOT_READY";
const FINALIZE_INTENT: &str = "ADMITTED_TO_FINALIZED";
const SHARD_READY_INTENT: &str = "FINALIZED_GENERATION_TO_SIGNED_SHARD_READY";
const INVALIDATE_INTENT: &str = "FINALIZED_TO_REORG_TOMBSTONED";
const REPLACEMENT_INTENT: &str = "ADMIT_REORG_REPLACEMENT";

type HmacSha256 = Hmac<Sha256>;

struct CapabilitySecret([u8; 32]);

impl Drop for CapabilitySecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone)]
pub(crate) struct CapabilityIssuer {
    secret: Arc<CapabilitySecret>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MutationCapability {
    pub(crate) nonce: [u8; 32],
    pub(crate) mac: [u8; 32],
}

#[derive(Clone, Copy)]
struct CapabilityFields<'a> {
    operation: &'static str,
    participant_id: &'a str,
    privacy_domain_id: &'a str,
    candidate_id: Option<&'a str>,
    predecessor_candidate_id: Option<&'a str>,
    source_profile_id: Option<&'a str>,
    generation_id: Option<&'a str>,
    source_sequence: Option<i64>,
    payload_digest: Option<&'a [u8]>,
    schema_id: Option<i64>,
    schema_version: Option<&'a str>,
    schema_digest: Option<&'a [u8]>,
    canonical_payload: Option<&'a [u8]>,
    fact_digest: Option<&'a [u8]>,
    finality_anchor: Option<&'a [u8]>,
    observed_at_ms: Option<i64>,
    fresh_until_ms: Option<i64>,
    fact_cose_sign1: Option<&'a [u8]>,
    signed_fact_digest: Option<&'a [u8]>,
    signer_key_id: Option<&'a [u8]>,
    signed_fact_purpose: Option<&'a str>,
    provenance_digest: Option<&'a [u8]>,
    shard_digest: Option<&'a [u8]>,
    shard_cose_sign1: Option<&'a [u8]>,
    shard_purpose: Option<&'a str>,
    invalidation_reason: Option<&'a str>,
    lifecycle_intent: &'static str,
}

impl CapabilityIssuer {
    pub(crate) fn new(secret: [u8; 32]) -> Self {
        Self {
            secret: Arc::new(CapabilitySecret(secret)),
        }
    }

    pub(crate) fn candidate_feed(&self, receipt_digest: &[u8; 32]) -> MutationCapability {
        self.issue_digest(
            b"OPENPC_FACTSTORE_CANDIDATE_FEED_RECEIPT_V1",
            receipt_digest,
        )
    }

    pub(crate) fn fact_occurrence(&self, binding_digest: &[u8; 32]) -> MutationCapability {
        self.issue_digest(b"OPENPC_FACTSTORE_FACT_OCCURRENCE_V1", binding_digest)
    }

    pub(crate) fn fact_identity(&self, binding_digest: &[u8; 32]) -> MutationCapability {
        self.issue_digest(
            b"OPENPC_FACTSTORE_CANONICAL_IDENTITY_ALLOCATION_V1",
            binding_digest,
        )
    }

    pub(crate) fn lineage(&self, binding_digest: &[u8; 32]) -> MutationCapability {
        self.issue_digest(b"OPENPC_FACTSTORE_SIGNED_LINEAGE_V1", binding_digest)
    }

    pub(crate) fn withdrawal_checkpoint(&self, binding_digest: &[u8; 32]) -> MutationCapability {
        self.issue_digest(b"OPENPC_FACTSTORE_WITHDRAWAL_CHECKPOINT_V1", binding_digest)
    }

    pub(crate) fn admission_delivery(&self, material: &[u8], data: &[u8]) -> MutationCapability {
        let mut binding = Vec::new();
        for (index, bytes) in [material, data].into_iter().enumerate() {
            binding.extend_from_slice(&((index + 1) as u16).to_be_bytes());
            binding.push(1);
            binding.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            binding.extend_from_slice(bytes);
        }
        self.issue_digest(
            b"OPENPC_FACTSTORE_ADMISSION_DELIVERY_V1",
            &pc_facts_core::sha256(&binding),
        )
    }

    pub(crate) fn control_delivery_ack(&self, material: &[u8]) -> MutationCapability {
        self.issue_digest(
            b"OPENPC_FACTSTORE_CONTROL_CUSTODY_ACK_V1",
            &pc_facts_core::sha256(material),
        )
    }

    pub(crate) fn fleet_delivery_ack(&self, material: &[u8]) -> MutationCapability {
        self.issue_digest(
            b"OPENPC_FACTSTORE_FLEET_ADMISSION_ACK_V1",
            &pc_facts_core::sha256(material),
        )
    }

    pub(crate) fn producer_delivery(&self, material: &[u8]) -> MutationCapability {
        self.issue_digest(
            b"OPENPC_FACTSTORE_PRODUCER_DELIVERY_V1",
            &pc_facts_core::sha256(material),
        )
    }

    fn issue_digest(&self, domain: &[u8], digest: &[u8; 32]) -> MutationCapability {
        let nonce: [u8; 32] = SigningKey::generate().to_bytes().into();
        let mut hmac = HmacSha256::new_from_slice(&self.secret.0)
            .expect("HMAC-SHA256 accepts a fixed 32-byte key");
        hmac.update(domain);
        hmac.update(digest);
        hmac.update(&nonce);
        MutationCapability {
            nonce,
            mac: hmac.finalize().into_bytes().into(),
        }
    }

    pub(crate) fn admit(
        &self,
        admission: &ValidatedAdmission,
        signed: &SignedFact,
        source_sequence: i64,
    ) -> MutationCapability {
        let signed_digest = signed_fact_digest(signed);
        self.issue(CapabilityFields {
            operation: "ADMIT_FACT",
            participant_id: admission.participant_id(),
            privacy_domain_id: admission.privacy_domain_id(),
            candidate_id: Some(admission.candidate_id()),
            predecessor_candidate_id: None,
            source_profile_id: Some(admission.source_profile_id()),
            generation_id: Some(admission.generation_id()),
            source_sequence: Some(source_sequence),
            payload_digest: Some(admission.payload_digest()),
            schema_id: Some(i64::from(admission.schema_id())),
            schema_version: Some(admission.schema_version()),
            schema_digest: Some(admission.schema_digest()),
            canonical_payload: Some(admission.canonical_payload()),
            fact_digest: Some(admission.canonical_fact_digest()),
            finality_anchor: Some(admission.finality_anchor()),
            observed_at_ms: Some(admission.observed_at_ms()),
            fresh_until_ms: Some(admission.fresh_until_ms()),
            fact_cose_sign1: Some(&signed.cose_sign1),
            signed_fact_digest: Some(&signed_digest),
            signer_key_id: Some(&signed.signer_key_id),
            signed_fact_purpose: Some(FACT_PURPOSE),
            provenance_digest: Some(admission.provenance_digest()),
            shard_digest: None,
            shard_cose_sign1: None,
            shard_purpose: None,
            invalidation_reason: None,
            lifecycle_intent: ADMIT_INTENT,
        })
    }

    pub(crate) fn finalize(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        candidate_id: &str,
        finality_anchor: &[u8; 32],
    ) -> MutationCapability {
        self.issue(CapabilityFields {
            operation: "FINALIZE_FACT",
            participant_id,
            privacy_domain_id,
            candidate_id: Some(candidate_id),
            predecessor_candidate_id: None,
            source_profile_id: None,
            generation_id: None,
            source_sequence: None,
            payload_digest: None,
            schema_id: None,
            schema_version: None,
            schema_digest: None,
            canonical_payload: None,
            fact_digest: None,
            finality_anchor: Some(finality_anchor),
            observed_at_ms: None,
            fresh_until_ms: None,
            fact_cose_sign1: None,
            signed_fact_digest: None,
            signer_key_id: None,
            signed_fact_purpose: None,
            provenance_digest: None,
            shard_digest: None,
            shard_cose_sign1: None,
            shard_purpose: None,
            invalidation_reason: None,
            lifecycle_intent: FINALIZE_INTENT,
        })
    }

    pub(crate) fn mark_signed_shard_ready(&self, shard: &VerifiedShard) -> MutationCapability {
        let shard_purpose = fact_schema_identity(FACT_SHARD_MANIFEST_SCHEMA_ID)
            .expect("frozen FactShardManifestV1 schema identity exists")
            .purpose_separator;
        self.issue(CapabilityFields {
            operation: "MARK_SIGNED_SHARD_READY",
            participant_id: shard.participant_id(),
            privacy_domain_id: shard.privacy_domain_id(),
            candidate_id: None,
            predecessor_candidate_id: None,
            source_profile_id: None,
            generation_id: Some(shard.generation_id()),
            source_sequence: None,
            payload_digest: None,
            schema_id: None,
            schema_version: None,
            schema_digest: None,
            canonical_payload: None,
            fact_digest: None,
            finality_anchor: None,
            observed_at_ms: None,
            fresh_until_ms: None,
            fact_cose_sign1: None,
            signed_fact_digest: None,
            signer_key_id: None,
            signed_fact_purpose: None,
            provenance_digest: None,
            shard_digest: Some(shard.shard_digest()),
            shard_cose_sign1: Some(shard.cose_sign1()),
            shard_purpose: Some(shard_purpose),
            invalidation_reason: None,
            lifecycle_intent: SHARD_READY_INTENT,
        })
    }

    pub(crate) fn invalidate(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        candidate_id: &str,
    ) -> MutationCapability {
        self.issue(CapabilityFields {
            operation: "INVALIDATE_FACT_FOR_REORG",
            participant_id,
            privacy_domain_id,
            candidate_id: Some(candidate_id),
            predecessor_candidate_id: None,
            source_profile_id: None,
            generation_id: None,
            source_sequence: None,
            payload_digest: None,
            schema_id: None,
            schema_version: None,
            schema_digest: None,
            canonical_payload: None,
            fact_digest: None,
            finality_anchor: None,
            observed_at_ms: None,
            fresh_until_ms: None,
            fact_cose_sign1: None,
            signed_fact_digest: None,
            signer_key_id: None,
            signed_fact_purpose: None,
            provenance_digest: None,
            shard_digest: None,
            shard_cose_sign1: None,
            shard_purpose: None,
            invalidation_reason: Some("REORG"),
            lifecycle_intent: INVALIDATE_INTENT,
        })
    }

    pub(crate) fn replacement(
        &self,
        predecessor_candidate_id: &str,
        admission: &ValidatedAdmission,
        signed: &SignedFact,
        source_sequence: i64,
    ) -> MutationCapability {
        let signed_digest = signed_fact_digest(signed);
        self.issue(CapabilityFields {
            operation: "ADMIT_REPLACEMENT",
            participant_id: admission.participant_id(),
            privacy_domain_id: admission.privacy_domain_id(),
            candidate_id: Some(admission.candidate_id()),
            predecessor_candidate_id: Some(predecessor_candidate_id),
            source_profile_id: Some(admission.source_profile_id()),
            generation_id: Some(admission.generation_id()),
            source_sequence: Some(source_sequence),
            payload_digest: Some(admission.payload_digest()),
            schema_id: Some(i64::from(admission.schema_id())),
            schema_version: Some(admission.schema_version()),
            schema_digest: Some(admission.schema_digest()),
            canonical_payload: Some(admission.canonical_payload()),
            fact_digest: Some(admission.canonical_fact_digest()),
            finality_anchor: Some(admission.finality_anchor()),
            observed_at_ms: Some(admission.observed_at_ms()),
            fresh_until_ms: Some(admission.fresh_until_ms()),
            fact_cose_sign1: Some(&signed.cose_sign1),
            signed_fact_digest: Some(&signed_digest),
            signer_key_id: Some(&signed.signer_key_id),
            signed_fact_purpose: Some(FACT_PURPOSE),
            provenance_digest: Some(admission.provenance_digest()),
            shard_digest: None,
            shard_cose_sign1: None,
            shard_purpose: None,
            invalidation_reason: Some("REORG"),
            lifecycle_intent: REPLACEMENT_INTENT,
        })
    }

    fn issue(&self, fields: CapabilityFields<'_>) -> MutationCapability {
        let nonce: [u8; 32] = SigningKey::generate().to_bytes().into();
        self.issue_with_nonce(fields, nonce)
    }

    fn issue_with_nonce(
        &self,
        fields: CapabilityFields<'_>,
        nonce: [u8; 32],
    ) -> MutationCapability {
        let preimage = canonical_preimage(fields, &nonce);
        let mut hmac = HmacSha256::new_from_slice(&self.secret.0)
            .expect("HMAC-SHA256 accepts a fixed 32-byte key");
        hmac.update(&preimage);
        MutationCapability {
            nonce,
            mac: hmac.finalize().into_bytes().into(),
        }
    }
}

fn canonical_preimage(fields: CapabilityFields<'_>, nonce: &[u8; 32]) -> Vec<u8> {
    let version = CAPABILITY_VERSION.to_be_bytes();
    let sequence = fields.source_sequence.map(i64::to_be_bytes);
    let schema_id = fields.schema_id.map(i64::to_be_bytes);
    let observed_at = fields.observed_at_ms.map(i64::to_be_bytes);
    let fresh_until = fields.fresh_until_ms.map(i64::to_be_bytes);
    let ordered: [(u16, Option<&[u8]>); 30] = [
        (1, Some(CAPABILITY_DOMAIN.as_bytes())),
        (2, Some(&version)),
        (3, Some(fields.operation.as_bytes())),
        (4, Some(fields.participant_id.as_bytes())),
        (5, Some(fields.privacy_domain_id.as_bytes())),
        (6, fields.candidate_id.map(str::as_bytes)),
        (7, fields.predecessor_candidate_id.map(str::as_bytes)),
        (8, fields.source_profile_id.map(str::as_bytes)),
        (9, fields.generation_id.map(str::as_bytes)),
        (10, sequence.as_ref().map(<[u8; 8]>::as_slice)),
        (11, fields.payload_digest),
        (12, schema_id.as_ref().map(<[u8; 8]>::as_slice)),
        (13, fields.schema_version.map(str::as_bytes)),
        (14, fields.schema_digest),
        (15, fields.canonical_payload),
        (16, fields.fact_digest),
        (17, fields.finality_anchor),
        (18, observed_at.as_ref().map(<[u8; 8]>::as_slice)),
        (19, fresh_until.as_ref().map(<[u8; 8]>::as_slice)),
        (20, fields.fact_cose_sign1),
        (21, fields.signed_fact_digest),
        (22, fields.signer_key_id),
        (23, fields.signed_fact_purpose.map(str::as_bytes)),
        (24, fields.provenance_digest),
        (25, fields.shard_digest),
        (26, fields.shard_cose_sign1),
        (27, fields.shard_purpose.map(str::as_bytes)),
        (28, fields.invalidation_reason.map(str::as_bytes)),
        (29, Some(fields.lifecycle_intent.as_bytes())),
        (30, Some(nonce)),
    ];
    let payload_len = ordered
        .iter()
        .map(|(_, value)| 11 + value.map_or(0, <[u8]>::len))
        .sum();
    let mut output = Vec::with_capacity(payload_len);
    for (field_id, value) in ordered {
        output.extend_from_slice(&field_id.to_be_bytes());
        output.push(u8::from(value.is_some()));
        let value = value.unwrap_or_default();
        output.extend_from_slice(
            &u64::try_from(value.len())
                .expect("bounded capability field length fits u64")
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    static ONE: [u8; 32] = [1; 32];
    static TWO: [u8; 32] = [2; 32];
    static THREE: [u8; 32] = [3; 32];
    static FOUR: [u8; 32] = [4; 32];
    static FIVE: [u8; 32] = [5; 32];
    static SIX: [u8; 32] = [6; 32];
    static NINE: [u8; 32] = [9; 32];

    fn complete_fields<'a>(payload: &'a [u8], signature: &'a [u8]) -> CapabilityFields<'a> {
        CapabilityFields {
            operation: "ADMIT_FACT",
            participant_id: "participant-a",
            privacy_domain_id: "privacy-a",
            candidate_id: Some("candidate-a"),
            predecessor_candidate_id: None,
            source_profile_id: Some("profile-a"),
            generation_id: Some("generation-a"),
            source_sequence: Some(7),
            payload_digest: Some(&ONE),
            schema_id: Some(21_006),
            schema_version: Some("1.0.0"),
            schema_digest: Some(&TWO),
            canonical_payload: Some(payload),
            fact_digest: Some(&THREE),
            finality_anchor: Some(&FOUR),
            observed_at_ms: Some(100),
            fresh_until_ms: Some(200),
            fact_cose_sign1: Some(signature),
            signed_fact_digest: Some(&FIVE),
            signer_key_id: Some(b"key-a"),
            signed_fact_purpose: Some(FACT_PURPOSE),
            provenance_digest: Some(&SIX),
            shard_digest: None,
            shard_cose_sign1: None,
            shard_purpose: None,
            invalidation_reason: None,
            lifecycle_intent: ADMIT_INTENT,
        }
    }

    #[test]
    fn canonical_encoding_is_length_delimited_ordered_and_null_explicit() {
        let fields = complete_fields(b"payload", b"signature");
        let bytes = canonical_preimage(fields, &[9; 32]);
        assert_eq!(&bytes[..2], &1_u16.to_be_bytes());
        assert_eq!(bytes[2], 1);
        assert_eq!(
            u64::from_be_bytes(bytes[3..11].try_into().unwrap()),
            u64::try_from(CAPABILITY_DOMAIN.len()).unwrap()
        );
        assert!(
            bytes
                .windows(CAPABILITY_DOMAIN.len())
                .any(|row| row == CAPABILITY_DOMAIN.as_bytes())
        );
        assert!(bytes.contains(&0));
    }

    #[test]
    fn every_field_and_nonce_rebinding_changes_the_fixed_purpose_mac() {
        let issuer = CapabilityIssuer::new([7; 32]);
        let nonce = [8; 32];
        let payload = b"payload";
        let signature = b"signature";
        let original = complete_fields(payload, signature);
        let original_mac = issuer.issue_with_nonce(original, nonce).mac;
        let mutations: Vec<CapabilityFields<'_>> = vec![
            CapabilityFields {
                operation: "FINALIZE_FACT",
                ..original
            },
            CapabilityFields {
                participant_id: "participant-b",
                ..original
            },
            CapabilityFields {
                privacy_domain_id: "privacy-b",
                ..original
            },
            CapabilityFields {
                candidate_id: Some("candidate-b"),
                ..original
            },
            CapabilityFields {
                predecessor_candidate_id: Some("predecessor"),
                ..original
            },
            CapabilityFields {
                source_profile_id: Some("profile-b"),
                ..original
            },
            CapabilityFields {
                generation_id: Some("generation-b"),
                ..original
            },
            CapabilityFields {
                source_sequence: Some(8),
                ..original
            },
            CapabilityFields {
                payload_digest: Some(&NINE),
                ..original
            },
            CapabilityFields {
                schema_id: Some(21_009),
                ..original
            },
            CapabilityFields {
                schema_version: Some("1.0.1"),
                ..original
            },
            CapabilityFields {
                schema_digest: Some(&NINE),
                ..original
            },
            CapabilityFields {
                canonical_payload: Some(b"other"),
                ..original
            },
            CapabilityFields {
                fact_digest: Some(&NINE),
                ..original
            },
            CapabilityFields {
                finality_anchor: Some(&NINE),
                ..original
            },
            CapabilityFields {
                observed_at_ms: Some(101),
                ..original
            },
            CapabilityFields {
                fresh_until_ms: Some(201),
                ..original
            },
            CapabilityFields {
                fact_cose_sign1: Some(b"other-signature"),
                ..original
            },
            CapabilityFields {
                signed_fact_digest: Some(&NINE),
                ..original
            },
            CapabilityFields {
                signer_key_id: Some(b"key-b"),
                ..original
            },
            CapabilityFields {
                signed_fact_purpose: Some("openpc:wrong:v1"),
                ..original
            },
            CapabilityFields {
                provenance_digest: Some(&NINE),
                ..original
            },
            CapabilityFields {
                shard_digest: Some(&NINE),
                ..original
            },
            CapabilityFields {
                shard_cose_sign1: Some(b"shard-signature"),
                ..original
            },
            CapabilityFields {
                shard_purpose: Some("openpc:fact-shard-manifest:v1"),
                ..original
            },
            CapabilityFields {
                invalidation_reason: Some("REORG"),
                ..original
            },
            CapabilityFields {
                lifecycle_intent: FINALIZE_INTENT,
                ..original
            },
        ];
        for mutation in mutations {
            assert_ne!(issuer.issue_with_nonce(mutation, nonce).mac, original_mac);
        }
        assert_ne!(issuer.issue_with_nonce(original, [9; 32]).mac, original_mac);
    }
}
