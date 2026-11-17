//! Original cryptographic custody is necessary, but never sufficient, for
//! restoration. The SQL/source owner must separately admit the current exact
//! suspended head and its dependency state before any Restore can be signed.
use super::*;
use openpc_runtime_agent::{
    RuntimeActivationToken, RuntimeCapsule, RuntimeWireVerifier, TargetActivationReceipt,
};
use pc_runtime_types::target_disposition::{
    TargetDispositionAction, TargetDispositionCause, VerifiedTargetDispositionDelivery,
};

/// Authenticated original custody with a finite capsule lifetime. This type
/// deliberately exposes no signing/serving capability or caller-set readiness.
pub struct VerifiedRestoreCustody {
    pub(super) withdrawal: VerifiedTargetDispositionDelivery,
    capsule: RuntimeCapsule,
    token: RuntimeActivationToken,
    receipt: TargetActivationReceipt,
    pub(super) token_digest: Digest,
    pub(super) receipt_digest: Digest,
}

impl VerifiedRestoreCustody {
    pub fn source(&self) -> &pc_runtime_types::target_disposition::TargetDispositionSource {
        &self.withdrawal.claims().source
    }
    pub fn capsule(&self) -> &RuntimeCapsule {
        &self.capsule
    }
    pub fn activation_token(&self) -> &RuntimeActivationToken {
        &self.token
    }
    pub fn activation_receipt(&self) -> &TargetActivationReceipt {
        &self.receipt
    }
}

impl TargetDispositionStore {
    /// Verify retained original bytes against host-installed Control/target
    /// trust and the actual current withdrawn head. No caller supplies a
    /// disposition, verifier key, source identity, or asserted no-effect result.
    pub async fn verify_original_restore_custody(
        &self,
        peer: &crate::TargetIdentity,
        capsule: &RuntimeCapsule,
        signed_token: &[u8],
        signed_receipt: &[u8],
    ) -> Result<VerifiedRestoreCustody> {
        let current = self
            .current_for_installed_peer(peer)
            .await?
            .ok_or_else(unavailable)?;
        let delivery = current.signed_delivery.ok_or_else(unavailable)?;
        let acknowledgement = current.signed_acknowledgement.ok_or_else(unavailable)?;
        let envelope: pc_runtime_types::SignedEnvelope<TargetDispositionDelivery> =
            serde_json::from_slice(&delivery).map_err(|_| unavailable())?;
        let claims = &envelope.claims;
        if claims.action != TargetDispositionAction::Withdraw
            || !matches!(claims.cause, TargetDispositionCause::Activation { .. })
            || claims.target.target_id != peer.target_id
            || claims.target.certificate_digest != peer.certificate_fingerprint
            || claims.target.participant_id != self.participant
            || claims.target.privacy_domain_id != self.privacy
            || claims.revision != current.revision
            || claims.committed_admission_digest != current.admission_digest
        {
            return Err(unavailable());
        }
        let target_key = self
            .target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(&peer.target_id)
            .cloned()
            .ok_or_else(unavailable)?;
        let control_key = self.control_signer.verifier().sec1_bytes();
        let verifier = TargetDispositionVerifier::from_host_keys(
            claims.target.clone(),
            &control_key,
            &target_key,
        )
        .map_err(|_| unavailable())?;
        let withdrawal = verifier
            .verify_delivery(&delivery, &claims.source)
            .map_err(|_| unavailable())?;
        verifier
            .verify_acknowledgement(&acknowledgement, &withdrawal)
            .map_err(|_| unavailable())?;
        let runtime_target_key = self
            .runtime_target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(&peer.target_id)
            .cloned()
            .ok_or_else(unavailable)?;
        let token = self
            .runtime_control
            .verify_activation_token(signed_token)
            .map_err(|_| unavailable())?;
        let receipt = RuntimeWireVerifier::from_public_key_bytes(&runtime_target_key)
            .and_then(|v| v.verify_receipt(signed_receipt))
            .map_err(|_| unavailable())?;
        let now_ns = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| unavailable())?
                .as_nanos(),
        )
        .map_err(|_| unavailable())?;
        require_original_custody(
            capsule,
            &token,
            &receipt,
            &claims.source,
            &peer.target_id,
            now_ns,
        )?;
        Ok(VerifiedRestoreCustody {
            withdrawal,
            capsule: capsule.clone(),
            token,
            receipt,
            token_digest: Digest::of(signed_token),
            receipt_digest: Digest::of(signed_receipt),
        })
    }
}

pub(super) fn require_original_custody(
    capsule: &RuntimeCapsule,
    token: &RuntimeActivationToken,
    receipt: &TargetActivationReceipt,
    source: &pc_runtime_types::target_disposition::TargetDispositionSource,
    target: &str,
    now_ns: u64,
) -> Result<()> {
    let capsule_digest = capsule.digest().map_err(|_| unavailable())?;
    let mismatches = [
        ("capsule_digest", capsule_digest != source.capsule_digest),
        (
            "capsule_id",
            capsule.capsule_id != source.runtime_configuration_generation_id,
        ),
        ("capsule_target", capsule.target_runtime_id != target),
        (
            "capsule_predecessor",
            capsule.previous_capsule_digest != source.predecessor_capsule_digest,
        ),
        ("capsule_not_before", capsule.not_before_ns > now_ns),
        ("capsule_expired", capsule.hard_expiry_ns <= now_ns),
        ("token_target", token.target_runtime_id != target),
        (
            "token_generation",
            token.desired_generation_digest != source.capsule_digest,
        ),
        (
            "token_xds",
            token.xds_version_digest != source.xds_version_digest,
        ),
        (
            "token_predecessor",
            token.expected_previous_generation_digest != source.predecessor_capsule_digest,
        ),
        ("receipt_target", receipt.target_runtime_id != target),
        (
            "receipt_capsule",
            receipt.capsule_digest != source.capsule_digest,
        ),
        (
            "receipt_manifest",
            receipt.contract_set_manifest_digest != capsule.contract_set_manifest_digest,
        ),
        (
            "receipt_components",
            receipt.complete_component_set_digest != capsule.complete_component_set_digest,
        ),
        ("receipt_status", receipt.status != 1),
        ("receipt_reason", receipt.reason_code != "ACTIVE_LOCAL"),
        (
            "receipt_before_capsule",
            receipt.observed_at_ns < capsule.not_before_ns,
        ),
        (
            "receipt_after_capsule",
            receipt.observed_at_ns >= capsule.hard_expiry_ns,
        ),
        (
            "receipt_before_token",
            receipt.observed_at_ns < token.issued_at_ns,
        ),
        (
            "receipt_after_token",
            receipt.observed_at_ns >= token.expires_at_ns,
        ),
    ];
    let failed: Vec<_> = mismatches
        .into_iter()
        .filter_map(|(name, invalid)| invalid.then_some(name))
        .collect();
    if !failed.is_empty() {
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_activation_confirmation","stage":"original_custody_rejected","failed_fields":failed})
        );
        return Err(unavailable());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpc_runtime_agent::RuntimeWireSigner;
    use pc_runtime_types::target_disposition::TargetDispositionSource;
    use serde_json::json;

    #[test]
    fn original_custody_cannot_substitute_source_receipt_or_reuse_expired_capsule() {
        let id = |n| format!("018f0000-0000-7000-8000-{n:012x}");
        let d = Digest::of(b"test canonical custody");
        let mut value = json!({
            "capsule_id":id(8),"lifecycle_mode":1,"target_runtime_id":id(3),"fleet_id":"fixture-fleet",
            "generation":1,"previous_capsule_digest":null,"emergency_deny_generation":0,
            "issued_at_ns":0,"not_before_ns":50,"hard_expiry_ns":1000,"signer_id":"fixture-control",
            "artifact_components":[{"component_id":"fixture.component","component_type":"fixture",
            "content_digest":d,"semantic_digest":d,"schema_id":1,"schema_version":1,"size_bytes":1,"required":true}]
        });
        for key in [
            "contract_set_manifest_digest",
            "schema_registry_digest",
            "cose_purpose_registry_digest",
            "complete_component_set_digest",
            "identity_snapshot_manifest_digest",
            "policy_bundle_digest",
            "semantic_model_digest",
            "named_set_registry_digest",
            "blocklist_digest",
            "policy_fact_state_digest",
            "routing_snapshot_digest",
            "provider_certification_registry_digest",
            "mrpc_runtime_profile_digest",
            "dynamic_event_profile_digest",
            "rpc_invocation_profile_digest",
            "capability_registry_digest",
            "request_form_registry_digest",
            "error_registry_digest",
            "evidence_admission_profile_digest",
        ] {
            value[key] = json!(d);
        }
        let capsule: RuntimeCapsule = serde_json::from_value(value).unwrap();
        let source = TargetDispositionSource {
            runtime_configuration_input_id: id(5),
            configuration_digest: d.clone(),
            module_installation_id: id(6),
            module_configuration_generation_id: id(7),
            runtime_configuration_generation_id: id(8),
            capsule_digest: capsule.digest().unwrap(),
            xds_version_digest: d.clone(),
            predecessor_capsule_digest: None,
            original_work_id: id(9),
            original_operation_id: id(10),
            original_execution_attempt_id: id(11),
        };
        let token = RuntimeActivationToken {
            token_id: id(12),
            target_runtime_id: id(3),
            occurrence_id: id(10),
            desired_generation_digest: source.capsule_digest.clone(),
            xds_version_digest: d,
            expected_previous_generation_digest: None,
            issued_at_ns: 100,
            expires_at_ns: 250,
        };
        let receipt = TargetActivationReceipt {
            receipt_id: id(13),
            target_runtime_id: id(3),
            capsule_digest: source.capsule_digest.clone(),
            contract_set_manifest_digest: capsule.contract_set_manifest_digest.clone(),
            complete_component_set_digest: capsule.complete_component_set_digest.clone(),
            status: 1,
            reason_code: "ACTIVE_LOCAL".into(),
            observed_at_ns: 200,
            agent_sequence: 1,
            signer_id: "fixture-agent".into(),
        };
        let control = RuntimeWireSigner::from_secret_bytes([31; 32]).unwrap();
        let agent = RuntimeWireSigner::from_secret_bytes([33; 32]).unwrap();
        let token = control
            .verifier()
            .verify_activation_token(&control.sign_activation_token(&token).unwrap())
            .unwrap();
        let receipt = agent
            .verifier()
            .verify_receipt(&agent.sign_receipt(&receipt).unwrap())
            .unwrap();
        let check =
            |t: &RuntimeActivationToken,
             r: &TargetActivationReceipt,
             s: &TargetDispositionSource,
             now| { require_original_custody(&capsule, t, r, s, &id(3), now) };
        // The original token was consumed at 200. Verifying that historical
        // proof at 500 neither replays it nor extends the capsule's own expiry.
        assert!(check(&token, &receipt, &source, 500).is_ok());
        assert!(check(&token, &receipt, &source, 49).is_err());
        assert!(check(&token, &receipt, &source, 1000).is_err());
        for changed in [
            RuntimeActivationToken {
                target_runtime_id: id(14),
                ..token.clone()
            },
            RuntimeActivationToken {
                xds_version_digest: Digest::of(b"different xds"),
                ..token.clone()
            },
            RuntimeActivationToken {
                desired_generation_digest: Digest::of(b"different capsule"),
                ..token.clone()
            },
            RuntimeActivationToken {
                expires_at_ns: 200,
                ..token.clone()
            },
        ] {
            assert!(check(&changed, &receipt, &source, 500).is_err());
        }
        for changed in [
            TargetActivationReceipt {
                status: 2,
                ..receipt.clone()
            },
            TargetActivationReceipt {
                target_runtime_id: id(14),
                ..receipt.clone()
            },
            TargetActivationReceipt {
                observed_at_ns: 250,
                ..receipt.clone()
            },
            TargetActivationReceipt {
                contract_set_manifest_digest: Digest::of(b"different registry"),
                ..receipt.clone()
            },
        ] {
            assert!(check(&token, &changed, &source, 500).is_err());
        }
        let changed = TargetDispositionSource {
            runtime_configuration_generation_id: id(14),
            ..source.clone()
        };
        assert!(check(&token, &receipt, &changed, 500).is_err());
    }
}
