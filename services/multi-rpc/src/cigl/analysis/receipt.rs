//! Transport of a live, sanitized analysis to its durable public owner. The
//! producer requires the sealed observation; verification pins target trust and
//! the exact public job. A receipt never activates a profile or authorizes send.
use super::ObservedMethodAnalysis;
use pc_policy_core::cigl::analysis::MethodAnalysisV1;
use pc_runtime_types::{
    Digest, PurposeSigner, PurposeVerifier, RuntimeError, RuntimeResult, SignedEnvelope,
    canonical_bytes,
};
use serde::{Deserialize, Serialize};

pub const PURPOSE: &str = "openpc:cigl-method-analysis:v1";
pub const MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MethodAnalysisReceipt {
    schema: String,
    analysis_id: String,
    target_runtime_id: String,
    capsule_digest: Digest,
    transaction_hash: [u8; 32],
    observed_at_ms: u64,
    analysis: MethodAnalysisV1,
}

/// Resolve these from the approved durable job and current installed sources,
/// never from fields supplied alongside an uploaded receipt.
pub struct AnalysisReceiptExpectation<'a> {
    pub analysis_id: &'a str,
    pub target_runtime_id: &'a str,
    pub capsule_digest: &'a Digest,
    pub transaction_hash: &'a [u8; 32],
    pub participant_id: &'a str,
    pub privacy_domain_id: &'a str,
    pub workload_id: &'a str,
    pub root_runtime_binding_id: &'a str,
    pub root_contract_method_policy_id: &'a str,
    pub configuration_digest: &'a Digest,
    pub policy_artifact_digest: &'a Digest,
    pub policy_generation_digest: &'a Digest,
    pub settings_source_digest: &'a Digest,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Immutable, approved job bindings. The current activation owner supplies the
/// capsule digest; the target signature binds its actual installed source
/// digests. Profile publication must additionally rejoin those source bytes.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisJobExpectation {
    pub analysis_id: String,
    pub target_runtime_id: String,
    pub capsule_digest: Digest,
    pub transaction_hash: [u8; 32],
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub workload_id: String,
    pub root_runtime_binding_id: String,
    pub root_contract_method_policy_id: String,
    pub policy_generation_digest: Digest,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

pub struct VerifiedMethodAnalysisReceipt {
    receipt: MethodAnalysisReceipt,
    digest: Digest,
}
impl VerifiedMethodAnalysisReceipt {
    pub fn analysis(&self) -> &MethodAnalysisV1 {
        &self.receipt.analysis
    }
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
    pub fn observed_at_ms(&self) -> u64 {
        self.receipt.observed_at_ms
    }
}

fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == value)
}

impl ObservedMethodAnalysis {
    /// The target supplies its configured identity and purpose-separated key.
    /// The public job ID only correlates evidence; it supplies no authority.
    pub fn into_receipt(
        self,
        analysis_id: &str,
        target_runtime_id: &str,
        capsule_digest: &Digest,
        signer: &PurposeSigner,
    ) -> RuntimeResult<Vec<u8>> {
        if !uuid(analysis_id)
            || !uuid(target_runtime_id)
            || self.observed_at_ms == 0
            || capsule_digest == &Digest::of([])
        {
            return Err(RuntimeError::InvalidInput);
        }
        self.document.validate()?;
        let signed = signer.sign(MethodAnalysisReceipt {
            schema: "1.0".into(),
            analysis_id: analysis_id.into(),
            target_runtime_id: target_runtime_id.into(),
            capsule_digest: capsule_digest.clone(),
            transaction_hash: self.transaction_hash,
            observed_at_ms: self.observed_at_ms,
            analysis: self.document,
        })?;
        if signed.purpose != PURPOSE {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let bytes = canonical_bytes(&signed)?;
        if bytes.len() > MAX_BYTES {
            return Err(RuntimeError::BudgetExhausted);
        }
        Ok(bytes)
    }
}

impl MethodAnalysisReceipt {
    /// Verify historical evidence. The importing/activating transaction must
    /// independently require an unexpired current job and current sources.
    pub fn verify(
        bytes: &[u8],
        trusted_target_key: &[u8],
        expected: &AnalysisReceiptExpectation<'_>,
        now_ms: u64,
    ) -> RuntimeResult<VerifiedMethodAnalysisReceipt> {
        let verified = Self::verify_for_job(
            bytes,
            trusted_target_key,
            &AnalysisJobExpectation {
                analysis_id: expected.analysis_id.into(),
                target_runtime_id: expected.target_runtime_id.into(),
                capsule_digest: expected.capsule_digest.clone(),
                transaction_hash: *expected.transaction_hash,
                participant_id: expected.participant_id.into(),
                privacy_domain_id: expected.privacy_domain_id.into(),
                workload_id: expected.workload_id.into(),
                root_runtime_binding_id: expected.root_runtime_binding_id.into(),
                root_contract_method_policy_id: expected.root_contract_method_policy_id.into(),
                policy_generation_digest: expected.policy_generation_digest.clone(),
                created_at_ms: expected.created_at_ms,
                expires_at_ms: expected.expires_at_ms,
            },
            now_ms,
        )?;
        let analysis = verified.analysis();
        if &analysis.configuration_digest != expected.configuration_digest
            || &analysis.policy_artifact_digest != expected.policy_artifact_digest
            || &analysis.observation_context_digest != expected.settings_source_digest
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(verified)
    }

    /// Retain non-granting evidence for an approved job. The pinned target key
    /// and exact admitted capsule are authoritative; submitted source digests
    /// are never substituted for either. This does not compile or activate.
    pub fn verify_for_job(
        bytes: &[u8],
        trusted_target_key: &[u8],
        expected: &AnalysisJobExpectation,
        now_ms: u64,
    ) -> RuntimeResult<VerifiedMethodAnalysisReceipt> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(RuntimeError::BudgetExhausted);
        }
        let signed: SignedEnvelope<Self> =
            serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidInput)?;
        // The producer owns canonical bytes. Reject aliases and extra envelope
        // fields so arbitrary caller payloads cannot enter retained evidence.
        if canonical_bytes(&signed)? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        PurposeVerifier::from_sec1_bytes(PURPOSE, trusted_target_key)?.verify(&signed)?;
        let receipt = signed.claims;
        let analysis = &receipt.analysis;
        analysis.validate()?;
        if receipt.schema != "1.0"
            || !uuid(&receipt.analysis_id)
            || !uuid(&receipt.target_runtime_id)
            || receipt.analysis_id != expected.analysis_id
            || receipt.target_runtime_id != expected.target_runtime_id
            || receipt.capsule_digest != expected.capsule_digest
            || receipt.transaction_hash != expected.transaction_hash
            || expected.created_at_ms >= expected.expires_at_ms
            || receipt.observed_at_ms >= expected.expires_at_ms
            || receipt.observed_at_ms < expected.created_at_ms
            || receipt.observed_at_ms > now_ms
            || analysis.participant_id != expected.participant_id
            || analysis.privacy_domain_id != expected.privacy_domain_id
            || analysis.workload_id != expected.workload_id
            || analysis.root_runtime_binding_id != expected.root_runtime_binding_id
            || analysis.root_contract_method_policy_id != expected.root_contract_method_policy_id
            || analysis.policy_generation_digest != expected.policy_generation_digest
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(VerifiedMethodAnalysisReceipt {
            receipt,
            digest: Digest::of(bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_policy_core::cigl::TraceLimits;

    const JOB: &str = "019963de-8824-7000-8000-000000000001";
    const TARGET: &str = "019963de-8824-7000-8000-000000000002";
    const FOREIGN: &str = "019963de-8824-7000-8000-000000000003";
    const TX: [u8; 32] = [9; 32];

    fn observed() -> ObservedMethodAnalysis {
        // A structural cryptographic test only; real trace acquisition is
        // exercised by the existing target/PostgreSQL integration owner.
        ObservedMethodAnalysis {
            transaction_hash: TX,
            observed_at_ms: 150,
            document: MethodAnalysisV1 {
                schema_version: "1.0".into(),
                participant_id: JOB.into(),
                privacy_domain_id: TARGET.into(),
                workload_id: format!("urn:openpc:workload:{JOB}"),
                root_contract_method_policy_id: JOB.into(),
                root_runtime_binding_id: TARGET.into(),
                configuration_digest: Digest::of(b"configuration"),
                policy_artifact_digest: Digest::of(b"artifact"),
                policy_generation_digest: Digest::of(b"policy"),
                request_digest: Digest::of(b"request"),
                authority_digest: Digest::of(b"authority"),
                observation_digest: Digest::of(b"observation"),
                observation_context_digest: Digest::of(b"settings"),
                route_witness_set_digest: Digest::of(b"witness"),
                anchor_digest: Digest::of(b"anchor"),
                limits: TraceLimits {
                    max_depth: 16,
                    max_frames: 32,
                    max_response_bytes: 100_000,
                    timeout_ms: 5_000,
                },
                interactions: vec![],
            },
        }
    }
    fn expectation<'a>(
        source: &'a MethodAnalysisV1,
        capsule: &'a Digest,
    ) -> AnalysisReceiptExpectation<'a> {
        AnalysisReceiptExpectation {
            analysis_id: JOB,
            target_runtime_id: TARGET,
            capsule_digest: capsule,
            transaction_hash: &TX,
            participant_id: &source.participant_id,
            privacy_domain_id: &source.privacy_domain_id,
            workload_id: &source.workload_id,
            root_runtime_binding_id: &source.root_runtime_binding_id,
            root_contract_method_policy_id: &source.root_contract_method_policy_id,
            configuration_digest: &source.configuration_digest,
            policy_artifact_digest: &source.policy_artifact_digest,
            policy_generation_digest: &source.policy_generation_digest,
            settings_source_digest: &source.observation_context_digest,
            created_at_ms: 100,
            expires_at_ms: 200,
        }
    }

    #[test]
    fn analysis_receipt_binds_target_job_transaction_sources_and_sanitized_evidence() {
        let signer = PurposeSigner::from_secret_bytes(PURPOSE, [1; 32]).unwrap();
        let public = signer.verifier().sec1_bytes();
        let source = observed().document;
        let capsule = Digest::of(b"admitted-capsule");
        let expected = expectation(&source, &capsule);
        let bytes = observed()
            .into_receipt(JOB, TARGET, &capsule, &signer)
            .unwrap();
        let valid = MethodAnalysisReceipt::verify(&bytes, &public, &expected, 150).unwrap();
        assert_eq!(valid.analysis(), &source);
        assert_eq!(valid.digest(), &Digest::of(&bytes));
        assert_eq!(valid.observed_at_ms(), 150);
        // Retained evidence remains verifiable after the non-granting job ends.
        assert!(MethodAnalysisReceipt::verify(&bytes, &public, &expected, 201).is_ok());
        for change in [
            (|r: &mut MethodAnalysisReceipt| r.analysis_id = FOREIGN.into())
                as fn(&mut MethodAnalysisReceipt),
            |r| r.target_runtime_id = FOREIGN.into(),
            |r| r.capsule_digest = Digest::of(b"foreign-capsule"),
            |r| r.transaction_hash = [7; 32],
            |r| r.observed_at_ms = 99,
            |r| r.observed_at_ms = 151,
            |r| r.analysis.participant_id = FOREIGN.into(),
            |r| r.analysis.privacy_domain_id = FOREIGN.into(),
            |r| r.analysis.workload_id = "workload:foreign".into(),
            |r| r.analysis.root_contract_method_policy_id = FOREIGN.into(),
            |r| r.analysis.root_runtime_binding_id = FOREIGN.into(),
            |r| r.analysis.configuration_digest = Digest::of(b"foreign"),
            |r| r.analysis.policy_artifact_digest = Digest::of(b"foreign"),
            |r| r.analysis.policy_generation_digest = Digest::of(b"foreign"),
            |r| r.analysis.observation_context_digest = Digest::of(b"foreign"),
        ] {
            let mut signed: SignedEnvelope<MethodAnalysisReceipt> =
                serde_json::from_slice(&bytes).unwrap();
            change(&mut signed.claims);
            let wrong = canonical_bytes(&signer.sign(signed.claims).unwrap()).unwrap();
            assert!(MethodAnalysisReceipt::verify(&wrong, &public, &expected, 150).is_err());
        }
    }

    #[test]
    fn analysis_receipt_rejects_wrong_trust_purpose_tamper_aliases_and_oversized_input() {
        let signer = PurposeSigner::from_secret_bytes(PURPOSE, [1; 32]).unwrap();
        let public = signer.verifier().sec1_bytes();
        let source = observed().document;
        let capsule = Digest::of(b"admitted-capsule");
        let expected = expectation(&source, &capsule);
        let bytes = observed()
            .into_receipt(JOB, TARGET, &capsule, &signer)
            .unwrap();
        let other = PurposeSigner::from_secret_bytes(PURPOSE, [2; 32]).unwrap();
        assert!(
            MethodAnalysisReceipt::verify(&bytes, &other.verifier().sec1_bytes(), &expected, 150)
                .is_err()
        );
        let wrong_purpose =
            PurposeSigner::from_secret_bytes("openpc:other-purpose:v1", [1; 32]).unwrap();
        assert!(
            observed()
                .into_receipt(JOB, TARGET, &capsule, &wrong_purpose)
                .is_err()
        );
        let mut tampered: SignedEnvelope<MethodAnalysisReceipt> =
            serde_json::from_slice(&bytes).unwrap();
        tampered.claims.analysis_id = FOREIGN.into();
        assert!(
            MethodAnalysisReceipt::verify(
                &canonical_bytes(&tampered).unwrap(),
                &public,
                &expected,
                150
            )
            .is_err()
        );
        let mut alias = bytes.clone();
        alias.push(b' ');
        assert!(MethodAnalysisReceipt::verify(&alias, &public, &expected, 150).is_err());
        assert!(
            MethodAnalysisReceipt::verify(&vec![0; MAX_BYTES + 1], &public, &expected, 150)
                .is_err()
        );
    }
}
