use super::*;
use crate::PurposeSigner;
use serde_json::{Value, json};

fn id(n: u32) -> String {
    format!("018f0000-0000-7000-8000-{n:012x}")
}
fn identity() -> TargetDispositionIdentity {
    TargetDispositionIdentity {
        participant_id: id(1),
        privacy_domain_id: id(2),
        target_id: id(3),
        credential_id: id(4),
        principal_id: id(12),
        credential_epoch: 1,
        principal_epoch: 2,
        certificate_digest: Digest::of(b"actual certificate"),
    }
}
fn source() -> TargetDispositionSource {
    TargetDispositionSource {
        runtime_configuration_input_id: id(5),
        configuration_digest: Digest::of(b"original full input"),
        module_installation_id: id(6),
        module_configuration_generation_id: id(7),
        runtime_configuration_generation_id: id(8),
        capsule_digest: Digest::of(b"capsule"),
        xds_version_digest: Digest::of(b"xds"),
        predecessor_capsule_digest: Some(Digest::of(b"predecessor")),
        original_work_id: id(9),
        original_operation_id: id(10),
        original_execution_attempt_id: id(11),
    }
}
fn withdrawal() -> TargetDispositionDelivery {
    TargetDispositionDelivery {
        version: 1,
        target: identity(),
        source: source(),
        cause: TargetDispositionCause::Activation {
            work_id: id(12),
            operation_id: id(13),
            execution_attempt_id: Some(id(14)),
        },
        action: TargetDispositionAction::Withdraw,
        revision: 1,
        previous_revision: 0,
        previous_delivery_digest: None,
        committed_admission_digest: Digest::of(b"committed original admission"),
    }
}

#[test]
fn platform_replacement_disposition_is_signed_denial_only() {
    let mut claims = withdrawal();
    claims.cause = TargetDispositionCause::Dependency {
        owner: TargetDispositionDependency::Platform,
        resource_id: id(20),
        operation_id: id(21),
        revision: 1,
    };
    let verified = verify(claims).unwrap();
    let acknowledgement = trust()
        .verify_acknowledgement(&signed_ack(ack(&verified)), &verified)
        .unwrap();
    assert_eq!(
        acknowledgement.claims().installed_state,
        TargetDispositionInstalledState::NewUseDenied
    );
    assert!(verify(next(&verified, TargetDispositionAction::Restore)).is_err());
    assert!(verify(next(&verified, TargetDispositionAction::ConfirmActivation)).is_err());
    let mut unbound = verified.claims().clone();
    if let TargetDispositionCause::Dependency { revision, .. } = &mut unbound.cause {
        *revision = 0;
    }
    assert!(verify(unbound).is_err());
}
fn control() -> PurposeSigner {
    PurposeSigner::from_secret_bytes(TARGET_DISPOSITION_DELIVERY_PURPOSE, [21; 32]).unwrap()
}
fn target() -> PurposeSigner {
    PurposeSigner::from_secret_bytes(TARGET_DISPOSITION_ACK_PURPOSE, [22; 32]).unwrap()
}
fn trust() -> TargetDispositionVerifier {
    TargetDispositionVerifier::from_host_keys(
        identity(),
        &control().verifier().sec1_bytes(),
        &target().verifier().sec1_bytes(),
    )
    .unwrap()
}
// Deliberately bypass the typed encoder for malformed signed-claims tests so
// verification must independently reject even a correctly signed bad shape.
fn signed_delivery(claims: TargetDispositionDelivery) -> Vec<u8> {
    canonical_bytes(&control().sign(claims).unwrap()).unwrap()
}
fn verify(claims: TargetDispositionDelivery) -> RuntimeResult<VerifiedTargetDispositionDelivery> {
    trust().verify_delivery(&signed_delivery(claims), &source())
}
fn next(
    previous: &VerifiedTargetDispositionDelivery,
    action: TargetDispositionAction,
) -> TargetDispositionDelivery {
    let mut claims = previous.claims().clone();
    claims.previous_revision = claims.revision;
    claims.revision += 1;
    claims.previous_delivery_digest = Some(previous.signed_digest().clone());
    claims.committed_admission_digest = Digest::of(b"next committed admission");
    claims.action = action;
    claims
}
fn ack(delivery: &VerifiedTargetDispositionDelivery) -> TargetDispositionAcknowledgement {
    TargetDispositionAcknowledgement {
        version: 1,
        target: delivery.claims().target.clone(),
        delivery_digest: delivery.signed_digest().clone(),
        disposition_revision: delivery.claims().revision,
        journal_sequence: 41 + delivery.claims().revision,
        installed_state: match delivery.claims().action {
            TargetDispositionAction::Withdraw => TargetDispositionInstalledState::NewUseDenied,
            TargetDispositionAction::Restore => TargetDispositionInstalledState::SuspensionCleared,
            TargetDispositionAction::ConfirmActivation => {
                TargetDispositionInstalledState::ActivationConfirmed
            }
        },
    }
}
fn signed_ack(claims: TargetDispositionAcknowledgement) -> Vec<u8> {
    canonical_bytes(&target().sign(claims).unwrap()).unwrap()
}

#[test]
fn unsigned_withdrawal_recovery_is_one_exact_denial_gap_and_replays_original_ack() {
    let mut prior = confirmation(source());
    prior.revision = 10;
    prior.previous_revision = 9;
    prior.previous_delivery_digest = Some(Digest::of(b"prior signed delivery"));
    let previous = verify(prior).unwrap();
    let abandoned = Digest::of(b"preserved unsigned admission 11");
    let mut claims = next(&previous, TargetDispositionAction::Withdraw);
    claims.revision = 12;
    claims.cause = TargetDispositionCause::UnsignedWithdrawalRecovery {
        work_id: id(20),
        operation_id: id(21),
        abandoned_revision: 11,
        abandoned_admission_digest: abandoned.clone(),
    };
    let recovered = verify(claims.clone()).unwrap();
    assert_eq!(
        recovered.compare_previous(Some(&previous)),
        Ok(TargetDispositionOrder::Successor)
    );
    assert!(
        recovered
            .check_recovery_floor(&previous, 11, &abandoned)
            .is_ok()
    );
    assert!(
        recovered
            .check_recovery_floor(&previous, 10, &previous.claims().committed_admission_digest)
            .is_ok()
    );
    for (revision, digest) in [
        (11, Digest::of(b"foreign abandoned admission")),
        (12, recovered.claims().committed_admission_digest.clone()),
        (13, abandoned.clone()),
    ] {
        assert!(
            recovered
                .check_recovery_floor(&previous, revision, &digest)
                .is_err()
        );
    }
    let replay = verify(claims.clone()).unwrap();
    assert_eq!(
        replay.compare_previous(Some(&recovered)),
        Ok(TargetDispositionOrder::ExactReplay)
    );
    let original_ack = signed_ack(ack(&recovered));
    assert!(
        trust()
            .verify_acknowledgement(&original_ack, &replay)
            .is_ok()
    );
    assert!(previous.compare_previous(Some(&recovered)).is_err());
    for action in [
        TargetDispositionAction::Restore,
        TargetDispositionAction::ConfirmActivation,
    ] {
        let mut changed = claims.clone();
        changed.action = action;
        assert!(verify(changed).is_err());
    }
    let mut changed = claims.clone();
    changed.revision = 13;
    assert!(verify(changed).is_err());
    let mut changed = claims.clone();
    changed.target.credential_epoch += 1;
    let changed_trust = TargetDispositionVerifier::from_host_keys(
        changed.target.clone(),
        &control().verifier().sec1_bytes(),
        &target().verifier().sec1_bytes(),
    )
    .unwrap();
    let checked = changed_trust
        .verify_delivery(&signed_delivery(changed), &source())
        .unwrap();
    assert!(checked.compare_previous(Some(&previous)).is_err());
    let mut changed = claims.clone();
    changed.previous_delivery_digest = Some(Digest::of(b"foreign predecessor"));
    assert!(
        verify(changed)
            .unwrap()
            .compare_previous(Some(&previous))
            .is_err()
    );
    let mut changed = claims;
    changed.source.configuration_digest = Digest::of(b"different source");
    let signed = trust()
        .verify_delivery(&signed_delivery(changed.clone()), &changed.source)
        .unwrap();
    assert!(signed.compare_previous(Some(&previous)).is_err());
    let mut applied = source();
    applied.original_work_id = id(20);
    applied.original_operation_id = id(21);
    applied.original_execution_attempt_id = id(22);
    applied.runtime_configuration_generation_id = id(23);
    applied.predecessor_capsule_digest = Some(recovered.claims().source.capsule_digest.clone());
    applied.capsule_digest = Digest::of(b"fresh admitted baseline identity capsule");
    let mut confirmed = confirmation(applied);
    confirmed.revision = 13;
    confirmed.previous_revision = 12;
    confirmed.previous_delivery_digest = Some(recovered.signed_digest().clone());
    let checked = trust()
        .verify_delivery(&signed_delivery(confirmed.clone()), &confirmed.source)
        .unwrap();
    assert_eq!(
        checked.compare_previous(Some(&recovered)),
        Ok(TargetDispositionOrder::Successor)
    );
    confirmed.source.original_work_id = id(99);
    confirmed.cause = TargetDispositionCause::Activation {
        work_id: id(99),
        operation_id: id(21),
        execution_attempt_id: Some(id(22)),
    };
    let checked = trust()
        .verify_delivery(&signed_delivery(confirmed.clone()), &confirmed.source)
        .unwrap();
    assert!(checked.compare_previous(Some(&recovered)).is_err());
}

#[test]
fn exact_signed_delivery_and_ack_roundtrip_without_mutating_originals() {
    let claims = withdrawal();
    let envelope = control().sign(claims.clone()).unwrap();
    let bytes = encode_target_disposition_delivery(&envelope).unwrap();
    let verified = trust().verify_delivery(&bytes, &source()).unwrap();
    assert_eq!(verified.claims(), &claims);
    assert_eq!(verified.signed_digest(), &Digest::of(&bytes));
    assert_eq!(
        verified.compare_previous(None),
        Ok(TargetDispositionOrder::InitialWithdrawal)
    );
    let acknowledgement = target().sign(ack(&verified)).unwrap();
    let bytes = encode_target_disposition_acknowledgement(&acknowledgement).unwrap();
    let checked = trust().verify_acknowledgement(&bytes, &verified).unwrap();
    assert_eq!(checked.claims(), &acknowledgement.claims);
    assert_eq!(checked.signed_digest(), &Digest::of(bytes));
    assert_eq!(envelope.claims, claims);
}

#[test]
fn equivalent_replay_preserves_exact_delivery_and_ack_bytes() {
    let first = verify(withdrawal()).unwrap();
    let replay = verify(withdrawal()).unwrap();
    assert_eq!(first.signed_digest(), replay.signed_digest());
    assert_eq!(
        replay.compare_previous(Some(&first)),
        Ok(TargetDispositionOrder::ExactReplay)
    );
    let bytes = signed_ack(ack(&first));
    let a = trust().verify_acknowledgement(&bytes, &first).unwrap();
    let b = trust().verify_acknowledgement(&bytes, &replay).unwrap();
    assert_eq!(
        b.compare_previous(&a),
        Ok(TargetDispositionOrder::ExactReplay)
    );
    let mut conflict = withdrawal();
    conflict.committed_admission_digest = Digest::of(b"same revision different admission");
    assert!(
        verify(conflict)
            .unwrap()
            .compare_previous(Some(&first))
            .is_err()
    );
    let mut conflict = ack(&first);
    conflict.journal_sequence += 1;
    let conflict = trust()
        .verify_acknowledgement(&signed_ack(conflict), &first)
        .unwrap();
    assert!(conflict.compare_previous(&a).is_err());
}

#[test]
fn restore_requires_exact_prior_withdrawal_and_never_initializes_a_journal() {
    let first = verify(withdrawal()).unwrap();
    let restored = verify(next(&first, TargetDispositionAction::Restore)).unwrap();
    assert_eq!(
        restored.compare_previous(Some(&first)),
        Ok(TargetDispositionOrder::Successor)
    );
    assert!(restored.compare_previous(None).is_err());
    assert!(first.compare_previous(Some(&restored)).is_err());
    assert!(
        verify(next(&restored, TargetDispositionAction::Restore))
            .unwrap()
            .compare_previous(Some(&restored))
            .is_err()
    );
    let mut changed = next(&first, TargetDispositionAction::Restore);
    changed.cause = TargetDispositionCause::Activation {
        work_id: id(99),
        operation_id: id(13),
        execution_attempt_id: Some(id(14)),
    };
    assert!(
        verify(changed)
            .unwrap()
            .compare_previous(Some(&first))
            .is_err()
    );
    let mut changed = next(&first, TargetDispositionAction::Restore);
    changed.previous_delivery_digest = Some(Digest::of(b"different suspension"));
    assert!(
        verify(changed)
            .unwrap()
            .compare_previous(Some(&first))
            .is_err()
    );
}

#[test]
fn same_bytes_with_another_generation_are_not_original_custody_or_restore() {
    let first = verify(withdrawal()).unwrap();
    for field in [
        "runtime_configuration_input_id",
        "module_installation_id",
        "module_configuration_generation_id",
        "runtime_configuration_generation_id",
        "original_work_id",
        "original_operation_id",
        "original_execution_attempt_id",
    ] {
        let mut value =
            serde_json::to_value(next(&first, TargetDispositionAction::Restore)).unwrap();
        value["source"][field] = json!(id(99));
        let changed: TargetDispositionDelivery = serde_json::from_value(value).unwrap();
        assert_eq!(
            changed.source.configuration_digest,
            first.claims().source.configuration_digest
        );
        assert!(verify(changed.clone()).is_err(), "{field}");
        // Even a verifier given the new source cannot call it restoration of
        // the old source. This is pairwise binding, not retirement eligibility.
        let parsed = trust()
            .verify_delivery(&signed_delivery(changed.clone()), &changed.source)
            .unwrap();
        assert!(parsed.compare_previous(Some(&first)).is_err(), "{field}");
    }
}

#[test]
fn retirement_withdrawal_cannot_be_converted_to_restore() {
    let mut claims = withdrawal();
    claims.cause = TargetDispositionCause::RuntimeArtifactRetirement {
        deletion_job_id: id(15),
        operation_id: id(16),
    };
    let first = verify(claims).unwrap();
    assert!(verify(next(&first, TargetDispositionAction::Restore)).is_err());
    assert_eq!(first.claims().action, TargetDispositionAction::Withdraw);
}

#[test]
fn signed_foreign_identity_and_original_digests_are_rejected() {
    for field in [
        "participant_id",
        "privacy_domain_id",
        "target_id",
        "credential_id",
        "principal_id",
        "certificate_digest",
        "credential_epoch",
        "principal_epoch",
    ] {
        let mut value = serde_json::to_value(withdrawal()).unwrap();
        value["target"][field] = if field.ends_with("epoch") {
            json!(9)
        } else if field.ends_with("digest") {
            json!(Digest::of(b"foreign"))
        } else {
            json!(id(99))
        };
        assert!(
            verify(serde_json::from_value(value).unwrap()).is_err(),
            "{field}"
        );
    }
    for field in [
        "configuration_digest",
        "capsule_digest",
        "xds_version_digest",
        "predecessor_capsule_digest",
    ] {
        let mut value = serde_json::to_value(withdrawal()).unwrap();
        value["source"][field] = json!(Digest::of(b"foreign"));
        assert!(
            verify(serde_json::from_value(value).unwrap()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn purpose_key_signature_and_claim_tampering_are_rejected() {
    for (purpose, key) in [
        (TARGET_DISPOSITION_ACK_PURPOSE, [21; 32]),
        (crate::PURPOSE_ACTIVATION_RECEIPT_V1, [21; 32]),
        (TARGET_DISPOSITION_DELIVERY_PURPOSE, [23; 32]),
    ] {
        let signer = PurposeSigner::from_secret_bytes(purpose, key).unwrap();
        let envelope = signer.sign(withdrawal()).unwrap();
        signer.verifier().verify(&envelope).unwrap(); // Existing purposes retain their semantics.
        assert!(
            trust()
                .verify_delivery(&canonical_bytes(&envelope).unwrap(), &source())
                .is_err()
        );
    }
    let mut signed = control().sign(withdrawal()).unwrap();
    signed.claims.source.configuration_digest = Digest::of(b"tamper");
    assert!(
        trust()
            .verify_delivery(&canonical_bytes(&signed).unwrap(), &source())
            .is_err()
    );
    assert!(
        TargetDispositionVerifier::from_host_keys(
            identity(),
            &control().verifier().sec1_bytes(),
            &control().verifier().sec1_bytes()
        )
        .is_err()
    );
}

#[test]
fn counters_reject_zero_overflow_gaps_and_reordering() {
    for number in [0, (i64::MAX as u64) + 1, u64::MAX] {
        for field in ["revision", "previous_revision"] {
            let mut value = serde_json::to_value(withdrawal()).unwrap();
            value[field] = json!(number);
            // Zero is the valid genesis predecessor only.
            if field == "previous_revision" && number == 0 {
                continue;
            }
            assert!(verify(serde_json::from_value(value).unwrap()).is_err());
        }
        for field in ["credential_epoch", "principal_epoch"] {
            let mut value = serde_json::to_value(withdrawal()).unwrap();
            value["target"][field] = json!(number);
            assert!(verify(serde_json::from_value(value).unwrap()).is_err());
        }
    }
    let first = verify(withdrawal()).unwrap();
    let mut gap = next(&first, TargetDispositionAction::Withdraw);
    gap.revision = 3;
    assert!(verify(gap.clone()).is_err());
    gap.previous_revision = 2;
    assert!(verify(gap).unwrap().compare_previous(Some(&first)).is_err());
    let mut maximum = withdrawal();
    maximum.previous_revision = MAX_COUNTER - 1;
    maximum.previous_delivery_digest = Some(Digest::of(b"previous"));
    maximum.revision = MAX_COUNTER;
    assert!(maximum.validate().is_ok());
    maximum.previous_revision = u64::MAX;
    assert!(maximum.validate().is_err());
}

#[test]
fn ack_requires_exact_delivery_revision_identity_and_installed_state() {
    let first = verify(withdrawal()).unwrap();
    for field in [
        "delivery_digest",
        "disposition_revision",
        "installed_state",
        "target_id",
        "journal_sequence",
    ] {
        let mut value = serde_json::to_value(ack(&first)).unwrap();
        match field {
            "delivery_digest" => value[field] = json!(Digest::of(b"other delivery")),
            "disposition_revision" => value[field] = json!(2),
            "installed_state" => value[field] = json!("SuspensionCleared"),
            "target_id" => value["target"][field] = json!(id(99)),
            "journal_sequence" => value[field] = json!(0),
            _ => unreachable!(),
        }
        assert!(
            trust()
                .verify_acknowledgement(&signed_ack(serde_json::from_value(value).unwrap()), &first)
                .is_err(),
            "{field}"
        );
    }
    for state in [
        "LeaseExpired",
        "AdsAcknowledged",
        "Unknown",
        "Applied",
        "NoEffect",
    ] {
        let mut value = serde_json::to_value(ack(&first)).unwrap();
        value["installed_state"] = json!(state);
        assert!(serde_json::from_value::<TargetDispositionAcknowledgement>(value).is_err());
    }
    let restored = verify(next(&first, TargetDispositionAction::Restore)).unwrap();
    let old_ack = trust()
        .verify_acknowledgement(&signed_ack(ack(&first)), &first)
        .unwrap();
    let new_ack = trust()
        .verify_acknowledgement(&signed_ack(ack(&restored)), &restored)
        .unwrap();
    assert_eq!(
        new_ack.compare_previous(&old_ack),
        Ok(TargetDispositionOrder::Successor)
    );
    assert!(
        trust()
            .verify_acknowledgement(&signed_ack(ack(&first)), &restored)
            .is_err()
    );
    let mut unchanged_sequence = ack(&restored);
    unchanged_sequence.journal_sequence = old_ack.claims().journal_sequence;
    let changed = trust()
        .verify_acknowledgement(&signed_ack(unchanged_sequence), &restored)
        .unwrap();
    assert!(changed.compare_previous(&old_ack).is_err());
}

#[test]
fn malformed_extra_duplicate_and_alternate_json_are_rejected() {
    let bytes = signed_delivery(withdrawal());
    for raw in [
        Vec::new(),
        vec![b'x'; MAX_TARGET_DISPOSITION_WIRE_BYTES + 1],
        b"null".to_vec(),
        b"{}".to_vec(),
        bytes[..bytes.len() - 1].to_vec(),
    ] {
        assert!(trust().verify_delivery(&raw, &source()).is_err());
    }
    for location in ["envelope", "claims", "target", "source", "cause"] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let object = match location {
            "envelope" => &mut value,
            "claims" => &mut value["claims"],
            _ => &mut value["claims"][location],
        };
        object["current_authority"] = json!(true);
        assert!(
            trust()
                .verify_delivery(&serde_json::to_vec(&value).unwrap(), &source())
                .is_err()
        );
    }
    let mut whitespace = bytes.clone();
    whitespace.push(b'\n');
    assert!(trust().verify_delivery(&whitespace, &source()).is_err());
    let mut duplicate = bytes[..bytes.len() - 1].to_vec();
    duplicate.extend_from_slice(b",\"purpose\":\"openpc:target-disposition-delivery:v1\"}");
    assert!(trust().verify_delivery(&duplicate, &source()).is_err());
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["claims"]["revision"] = json!("1");
    assert!(
        trust()
            .verify_delivery(&serde_json::to_vec(&value).unwrap(), &source())
            .is_err()
    );
}

#[test]
fn closed_identifiers_digests_versions_and_causes_are_independently_validated() {
    for invalid in [
        "",
        "018F0000-0000-7000-8000-000000000001",
        "018f0000-0000-4000-8000-000000000001",
        "018f0000-0000-7000-7000-000000000001",
        "../../target",
    ] {
        let mut claims = withdrawal();
        claims.source.original_execution_attempt_id = invalid.into();
        assert!(verify(claims).is_err());
    }
    for invalid in ["x".repeat(64), "A".repeat(64), "a".repeat(63)] {
        let mut claims = withdrawal();
        claims.committed_admission_digest = serde_json::from_value(json!(invalid)).unwrap();
        assert!(verify(claims).is_err());
    }
    let mut claims = withdrawal();
    claims.version = 2;
    assert!(verify(claims).is_err());
    let mut claims = withdrawal();
    claims.cause = TargetDispositionCause::Dependency {
        owner: TargetDispositionDependency::Module,
        resource_id: id(20),
        operation_id: id(21),
        revision: 0,
    };
    assert!(verify(claims).is_err());
    let mut unstarted = withdrawal();
    if let TargetDispositionCause::Activation {
        execution_attempt_id,
        ..
    } = &mut unstarted.cause
    {
        *execution_attempt_id = None;
    }
    assert!(verify(unstarted).is_ok());
}

#[test]
fn ack_cannot_mix_delivery_from_another_control_trust_installation() {
    let foreign_control =
        PurposeSigner::from_secret_bytes(TARGET_DISPOSITION_DELIVERY_PURPOSE, [24; 32]).unwrap();
    let foreign_trust = TargetDispositionVerifier::from_host_keys(
        identity(),
        &foreign_control.verifier().sec1_bytes(),
        &target().verifier().sec1_bytes(),
    )
    .unwrap();
    let bytes =
        encode_target_disposition_delivery(&foreign_control.sign(withdrawal()).unwrap()).unwrap();
    let foreign_delivery = foreign_trust.verify_delivery(&bytes, &source()).unwrap();
    let bytes = signed_ack(ack(&foreign_delivery));
    assert!(
        foreign_trust
            .verify_acknowledgement(&bytes, &foreign_delivery)
            .is_ok()
    );
    assert!(
        trust()
            .verify_acknowledgement(&bytes, &foreign_delivery)
            .is_err()
    );
}

#[test]
fn ack_rejects_overflow_fields_unknown_fields_and_wrong_key_or_purpose() {
    let delivery = verify(withdrawal()).unwrap();
    for count in [(i64::MAX as u64) + 1, u64::MAX] {
        for field in ["disposition_revision", "journal_sequence"] {
            let mut value = serde_json::to_value(ack(&delivery)).unwrap();
            value[field] = json!(count);
            assert!(
                trust()
                    .verify_acknowledgement(
                        &signed_ack(serde_json::from_value(value).unwrap()),
                        &delivery
                    )
                    .is_err()
            );
        }
    }
    for location in ["envelope", "claims", "target"] {
        let mut value: Value = serde_json::from_slice(&signed_ack(ack(&delivery))).unwrap();
        let object = match location {
            "envelope" => &mut value,
            "claims" => &mut value["claims"],
            _ => &mut value["claims"][location],
        };
        object["lease_expired"] = json!(true);
        assert!(
            trust()
                .verify_acknowledgement(&serde_json::to_vec(&value).unwrap(), &delivery)
                .is_err()
        );
    }
    for (purpose, key) in [
        (TARGET_DISPOSITION_DELIVERY_PURPOSE, [22; 32]),
        (TARGET_DISPOSITION_ACK_PURPOSE, [25; 32]),
    ] {
        let signer = PurposeSigner::from_secret_bytes(purpose, key).unwrap();
        assert!(
            trust()
                .verify_acknowledgement(
                    &canonical_bytes(&signer.sign(ack(&delivery)).unwrap()).unwrap(),
                    &delivery
                )
                .is_err()
        );
    }
}

fn confirmation(source: TargetDispositionSource) -> TargetDispositionDelivery {
    let mut value = withdrawal();
    value.action = TargetDispositionAction::ConfirmActivation;
    value.cause = TargetDispositionCause::Activation {
        work_id: source.original_work_id.clone(),
        operation_id: source.original_operation_id.clone(),
        execution_attempt_id: Some(source.original_execution_attempt_id.clone()),
    };
    value.source = source;
    value
}

#[test]
fn first_activation_confirmation_requires_exact_applied_identity_and_distinct_ack() {
    let mut original = source();
    original.predecessor_capsule_digest = None;
    let claims = confirmation(original.clone());
    let delivery = trust()
        .verify_delivery(&signed_delivery(claims.clone()), &original)
        .unwrap();
    assert_eq!(
        delivery.compare_previous(None),
        Ok(TargetDispositionOrder::InitialActivation)
    );
    let bytes = signed_ack(ack(&delivery));
    assert!(trust().verify_acknowledgement(&bytes, &delivery).is_ok());
    for state in [
        TargetDispositionInstalledState::SuspensionCleared,
        TargetDispositionInstalledState::NewUseDenied,
    ] {
        let mut wrong = ack(&delivery);
        wrong.installed_state = state;
        assert!(
            trust()
                .verify_acknowledgement(&signed_ack(wrong), &delivery)
                .is_err()
        );
    }
    for field in ["work_id", "operation_id", "execution_attempt_id"] {
        let mut changed = serde_json::to_value(&claims).unwrap();
        changed["cause"][field] = json!(id(99));
        assert!(
            trust()
                .verify_delivery(
                    &signed_delivery(serde_json::from_value(changed).unwrap()),
                    &original
                )
                .is_err()
        );
    }
    let mut absent = claims.clone();
    if let TargetDispositionCause::Activation {
        execution_attempt_id,
        ..
    } = &mut absent.cause
    {
        *execution_attempt_id = None;
    }
    assert!(absent.validate().is_err());
    let mut wrong_first = claims;
    wrong_first.source.predecessor_capsule_digest = Some(Digest::of(b"missing predecessor"));
    assert!(wrong_first.validate().is_err());
}

#[test]
fn activation_confirmation_cannot_bypass_or_restore_a_different_withdrawal() {
    let mut prior = withdrawal();
    // Withdrawal precedes effect admission, so its original cause has no attempt.
    prior.cause = TargetDispositionCause::Activation {
        work_id: id(20),
        operation_id: id(21),
        execution_attempt_id: None,
    };
    let previous = verify(prior).unwrap();
    let mut applied = source();
    applied.runtime_configuration_generation_id = id(22);
    applied.original_work_id = id(20);
    applied.original_operation_id = id(21);
    applied.original_execution_attempt_id = id(23);
    applied.predecessor_capsule_digest = Some(previous.claims().source.capsule_digest.clone());
    applied.capsule_digest = Digest::of(b"actually applied successor");
    let mut claims = confirmation(applied);
    claims.revision = 2;
    claims.previous_revision = 1;
    claims.previous_delivery_digest = Some(previous.signed_digest().clone());
    let check = |claims: TargetDispositionDelivery| {
        trust()
            .verify_delivery(&signed_delivery(claims.clone()), &claims.source)
            .and_then(|checked| checked.compare_previous(Some(&previous)))
    };
    assert_eq!(check(claims.clone()), Ok(TargetDispositionOrder::Successor));
    let verified = trust()
        .verify_delivery(&signed_delivery(claims.clone()), &claims.source)
        .unwrap();
    assert!(verified.compare_previous(None).is_err());
    assert_eq!(
        verified.compare_previous(Some(&verified)),
        Ok(TargetDispositionOrder::ExactReplay)
    );
    for field in [
        "original_work_id",
        "original_operation_id",
        "predecessor_capsule_digest",
        "capsule_digest",
    ] {
        let mut changed = claims.clone();
        match field {
            "original_work_id" => {
                changed.source.original_work_id = id(99);
                if let TargetDispositionCause::Activation { work_id, .. } = &mut changed.cause {
                    *work_id = id(99);
                }
            }
            "original_operation_id" => {
                changed.source.original_operation_id = id(99);
                if let TargetDispositionCause::Activation { operation_id, .. } = &mut changed.cause
                {
                    *operation_id = id(99);
                }
            }
            "predecessor_capsule_digest" => {
                changed.source.predecessor_capsule_digest = Some(Digest::of(b"other predecessor"))
            }
            _ => changed.source.capsule_digest = previous.claims().source.capsule_digest.clone(),
        }
        assert!(check(changed).is_err(), "{field}");
    }
    let mut restoration = claims.clone();
    restoration.action = TargetDispositionAction::Restore;
    assert!(check(restoration).is_err());
    let mut old_attempt = previous.claims().clone();
    if let TargetDispositionCause::Activation {
        execution_attempt_id,
        ..
    } = &mut old_attempt.cause
    {
        *execution_attempt_id = Some(id(99));
    }
    let old_attempt = verify(old_attempt).unwrap();
    claims.previous_delivery_digest = Some(old_attempt.signed_digest().clone());
    assert!(
        trust()
            .verify_delivery(&signed_delivery(claims.clone()), &claims.source)
            .unwrap()
            .compare_previous(Some(&old_attempt))
            .is_err()
    );
}

fn expired_handover(
    observed_revision: u64,
) -> (VerifiedTargetDispositionDelivery, TargetDispositionDelivery) {
    let mut predecessor = withdrawal();
    predecessor.revision = 2;
    predecessor.previous_revision = 1;
    predecessor.previous_delivery_digest = Some(Digest::of(b"first signed delivery"));
    predecessor.source.capsule_digest = source().predecessor_capsule_digest.unwrap();
    predecessor.source.original_work_id = id(40);
    predecessor.source.original_operation_id = id(41);
    predecessor.source.original_execution_attempt_id = id(42);
    predecessor.cause = TargetDispositionCause::Activation {
        work_id: source().original_work_id,
        operation_id: source().original_operation_id,
        execution_attempt_id: None,
    };
    let previous = trust()
        .verify_delivery(&signed_delivery(predecessor.clone()), &predecessor.source)
        .unwrap();
    let mut value = next(&previous, TargetDispositionAction::Withdraw);
    value.source = source();
    value.revision = 4;
    value.cause = TargetDispositionCause::ExpiredObservedDenialHandover {
        work_id: value.source.original_work_id.clone(),
        operation_id: value.source.original_operation_id.clone(),
        execution_attempt_id: value.source.original_execution_attempt_id.clone(),
        abandoned_revision: 3,
        abandoned_admission_digest: Digest::of(b"placeholder"),
        original_receipt_wire_digest: Digest::of(b"signed original receipt wire"),
        installed_revision: 2,
        installed_delivery_digest: previous.signed_digest().clone(),
        observed_revision,
        observed_admission_digest: previous.claims().committed_admission_digest.clone(),
    };
    let reconstructed = expired_handover::reconstruct_abandoned(&value).unwrap();
    if let TargetDispositionCause::ExpiredObservedDenialHandover {
        abandoned_admission_digest,
        observed_admission_digest,
        ..
    } = &mut value.cause
    {
        *abandoned_admission_digest = reconstructed.clone();
        if observed_revision == 3 {
            *observed_admission_digest = reconstructed;
        }
    }
    (previous, value)
}

#[test]
fn expired_observed_handover_binds_unsigned_projection_and_exact_authenticated_floor() {
    for floor in [2, 3] {
        let (previous, value) = expired_handover(floor);
        let checked = verify(value.clone()).unwrap();
        assert_eq!(
            checked.compare_previous(Some(&previous)),
            Ok(TargetDispositionOrder::Successor)
        );
        let TargetDispositionCause::ExpiredObservedDenialHandover {
            observed_admission_digest,
            ..
        } = &value.cause
        else {
            panic!()
        };
        assert!(
            checked
                .check_recovery_floor(&previous, floor, observed_admission_digest)
                .is_ok()
        );
        for n in [1, 4, 5] {
            assert!(
                checked
                    .check_recovery_floor(&previous, n, observed_admission_digest)
                    .is_err()
            );
        }
        assert!(
            checked
                .check_recovery_floor(&previous, floor, &Digest::of(b"foreign floor"))
                .is_err()
        );
        assert!(
            checked
                .check_recovery_floor(
                    &previous,
                    if floor == 2 { 3 } else { 2 },
                    observed_admission_digest
                )
                .is_err()
        );
        let replay = verify(value).unwrap();
        assert_eq!(
            replay.compare_previous(Some(&checked)),
            Ok(TargetDispositionOrder::ExactReplay)
        );
        assert!(previous.compare_previous(Some(&checked)).is_err());
    }
}

#[test]
fn expired_observed_handover_is_denial_only_and_cannot_rebind_or_form_a_chain() {
    let (previous, value) = expired_handover(3);
    for action in [
        TargetDispositionAction::Restore,
        TargetDispositionAction::ConfirmActivation,
    ] {
        let mut changed = value.clone();
        changed.action = action;
        assert!(verify(changed).is_err());
    }
    for key in [
        "capsule",
        "source",
        "target",
        "work",
        "attempt",
        "abandoned",
        "installed",
        "order",
    ] {
        let mut changed = value.clone();
        match key {
            "capsule" => changed.source.capsule_digest = Digest::of(b"foreign capsule"),
            "source" => changed.source.configuration_digest = Digest::of(b"foreign configuration"),
            "target" => changed.target.credential_epoch += 1,
            "work" => {
                if let TargetDispositionCause::ExpiredObservedDenialHandover { work_id, .. } =
                    &mut changed.cause
                {
                    *work_id = id(55)
                }
            }
            "attempt" => {
                if let TargetDispositionCause::ExpiredObservedDenialHandover {
                    execution_attempt_id,
                    ..
                } = &mut changed.cause
                {
                    *execution_attempt_id = id(56)
                }
            }
            "abandoned" => {
                if let TargetDispositionCause::ExpiredObservedDenialHandover {
                    abandoned_admission_digest,
                    ..
                } = &mut changed.cause
                {
                    *abandoned_admission_digest = Digest::of(b"foreign admission")
                }
            }
            "installed" => {
                changed.previous_delivery_digest = Some(Digest::of(b"foreign signed predecessor"))
            }
            _ => changed.revision += 1,
        }
        assert!(verify(changed).is_err(), "accepted changed {key}");
    }
    let checked = verify(value.clone()).unwrap();
    let mut another = next(&checked, TargetDispositionAction::Withdraw);
    another.revision += 1;
    assert!(verify(another).is_err());
    let mut bad_previous = previous.claims().clone();
    bad_previous.action = TargetDispositionAction::ConfirmActivation;
    assert!(
        expired_handover::compare_installed(&value, &bad_previous, previous.signed_digest())
            .is_err()
    );
}

#[test]
#[ignore = "requires the preserved exact private unsigned admission binding and signed predecessor"]
fn frozen_expired_handover_reconstruction_matches_original_admission_bytes() {
    let path = std::env::var("OPENPC_FROZEN_EXPIRED_DENIAL_HANDOVER_BINDING_FILE").unwrap();
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let binding = fixture["binding"].clone();
    let digest: Digest = serde_json::from_value(fixture["admissionDigest"].clone()).unwrap();
    assert_eq!(Digest::of(canonical_bytes(&binding).unwrap()), digest);
    let mut material = binding.clone();
    material["committed_admission_digest"] = json!(Digest::of(b"new committed native handover"));
    let mut value: TargetDispositionDelivery = serde_json::from_value(material).unwrap();
    let installed_revision = value.previous_revision;
    let installed_delivery_digest = value.previous_delivery_digest.clone().unwrap();
    value.revision = value.revision.checked_add(1).unwrap();
    value.cause = TargetDispositionCause::ExpiredObservedDenialHandover {
        work_id: value.source.original_work_id.clone(),
        operation_id: value.source.original_operation_id.clone(),
        execution_attempt_id: value.source.original_execution_attempt_id.clone(),
        abandoned_revision: 3,
        abandoned_admission_digest: digest.clone(),
        original_receipt_wire_digest: serde_json::from_value(
            fixture["originalReceiptWireDigest"].clone(),
        )
        .unwrap(),
        installed_revision,
        installed_delivery_digest,
        observed_revision: 3,
        observed_admission_digest: digest.clone(),
    };
    assert_eq!(
        expired_handover::reconstruct_abandoned(&value).unwrap(),
        digest
    );
    value.validate().unwrap();
    let mut credential = value.clone();
    let abandoned_target = credential.target.clone();
    credential.target.credential_id = id(110);
    credential.target.credential_epoch += 1;
    credential.target.certificate_digest =
        Digest::of(b"synthetic successor for reconstruction comparison only");
    let TargetDispositionCause::ExpiredObservedDenialHandover {
        work_id,
        operation_id,
        execution_attempt_id,
        abandoned_revision,
        abandoned_admission_digest,
        original_receipt_wire_digest,
        installed_revision,
        installed_delivery_digest,
        observed_revision,
        observed_admission_digest,
    } = credential.cause
    else {
        panic!()
    };
    credential.cause = TargetDispositionCause::ExpiredObservedCredentialDenialHandover {
        work_id,
        operation_id,
        execution_attempt_id,
        abandoned_revision,
        abandoned_admission_digest,
        original_receipt_wire_digest,
        installed_revision,
        installed_delivery_digest,
        observed_revision,
        observed_admission_digest,
        abandoned_target,
        credential_rotation_operation_id: id(111),
    };
    credential.validate().unwrap();
    assert_eq!(
        expired_handover::reconstruct_abandoned(
            &expired_credential_handover::historical_projection(&credential).unwrap()
        )
        .unwrap(),
        digest
    );
    let mut changed = value;
    changed.source.xds_version_digest = Digest::of(b"substituted xDS");
    assert!(changed.validate().is_err());
}

fn credential_denial_handover() -> (VerifiedTargetDispositionDelivery, TargetDispositionDelivery) {
    let (previous, mut value) = expired_handover(3);
    let abandoned_target = value.target.clone();
    value.target.credential_id = id(80);
    value.target.credential_epoch += 1;
    value.target.certificate_digest = Digest::of(b"current ordinarily rotated target certificate");
    let TargetDispositionCause::ExpiredObservedDenialHandover {
        work_id,
        operation_id,
        execution_attempt_id,
        abandoned_revision,
        abandoned_admission_digest,
        original_receipt_wire_digest,
        installed_revision,
        installed_delivery_digest,
        observed_revision,
        observed_admission_digest,
    } = value.cause
    else {
        panic!()
    };
    value.cause = TargetDispositionCause::ExpiredObservedCredentialDenialHandover {
        work_id,
        operation_id,
        execution_attempt_id,
        abandoned_revision,
        abandoned_admission_digest,
        original_receipt_wire_digest,
        installed_revision,
        installed_delivery_digest,
        observed_revision,
        observed_admission_digest,
        abandoned_target,
        credential_rotation_operation_id: id(81),
    };
    (previous, value)
}
fn verify_credential_handover(
    value: TargetDispositionDelivery,
    expected: &TargetDispositionIdentity,
) -> RuntimeResult<VerifiedTargetDispositionDelivery> {
    TargetDispositionVerifier::from_host_keys(
        expected.clone(),
        &control().verifier().sec1_bytes(),
        &target().verifier().sec1_bytes(),
    )?
    .verify_delivery(&signed_delivery(value), &source())
}

#[test]
fn credential_denial_handover_reconstructs_the_exact_old_identity_and_authenticated_floor() {
    let (previous, value) = credential_denial_handover();
    let projection = expired_credential_handover::historical_projection(&value).unwrap();
    assert_eq!(projection.target, previous.claims().target);
    let checked = verify_credential_handover(value.clone(), &value.target).unwrap();
    assert_eq!(
        checked.compare_previous(Some(&previous)),
        Ok(TargetDispositionOrder::Successor)
    );
    let TargetDispositionCause::ExpiredObservedCredentialDenialHandover {
        abandoned_admission_digest,
        ..
    } = &value.cause
    else {
        panic!()
    };
    assert!(
        checked
            .check_recovery_floor(&previous, 3, abandoned_admission_digest)
            .is_ok()
    );
    for floor in [1, 2, 4, 5] {
        assert!(
            checked
                .check_recovery_floor(&previous, floor, abandoned_admission_digest)
                .is_err()
        );
    }
    assert!(
        checked
            .check_recovery_floor(&previous, 3, &Digest::of(b"foreign observed floor"))
            .is_err()
    );
    let replay = verify_credential_handover(value.clone(), &value.target).unwrap();
    assert_eq!(
        replay.compare_previous(Some(&checked)),
        Ok(TargetDispositionOrder::ExactReplay)
    );
    // The projected historical object is never a current credential delivery.
    assert!(verify_credential_handover(projection, &value.target).is_err());
}

#[test]
fn credential_denial_handover_rejects_identity_lineage_source_order_and_serving_changes() {
    let (previous, value) = credential_denial_handover();
    for changed in [
        "principal",
        "principal_epoch",
        "credential",
        "epoch",
        "certificate",
        "old_identity",
        "rotation_id",
        "source",
        "floor",
        "order",
        "restore",
        "confirm",
    ] {
        let mut bad = value.clone();
        match changed {
            "principal" => bad.target.principal_id = id(90),
            "principal_epoch" => bad.target.principal_epoch += 1,
            "credential" => {
                bad.target.credential_id = previous.claims().target.credential_id.clone()
            }
            "epoch" => bad.target.credential_epoch += 1,
            "certificate" => {
                bad.target.certificate_digest = previous.claims().target.certificate_digest.clone()
            }
            "old_identity" => {
                if let TargetDispositionCause::ExpiredObservedCredentialDenialHandover {
                    abandoned_target,
                    ..
                } = &mut bad.cause
                {
                    abandoned_target.credential_id = id(91);
                }
            }
            "rotation_id" => {
                if let TargetDispositionCause::ExpiredObservedCredentialDenialHandover {
                    credential_rotation_operation_id,
                    ..
                } = &mut bad.cause
                {
                    *credential_rotation_operation_id = "not-a-governed-operation".into();
                }
            }
            "source" => {
                bad.source.configuration_digest = Digest::of(b"different original configuration")
            }
            "floor" => {
                if let TargetDispositionCause::ExpiredObservedCredentialDenialHandover {
                    observed_revision,
                    ..
                } = &mut bad.cause
                {
                    *observed_revision = 2;
                }
            }
            "order" => bad.revision += 1,
            "restore" => bad.action = TargetDispositionAction::Restore,
            _ => bad.action = TargetDispositionAction::ConfirmActivation,
        }
        assert!(
            verify_credential_handover(bad, &value.target).is_err(),
            "accepted changed {changed}"
        );
    }
    let checked = verify_credential_handover(value.clone(), &value.target).unwrap();
    let mut wrong_previous = previous.claims().clone();
    wrong_previous.source.original_work_id = id(92);
    let wrong = trust()
        .verify_delivery(
            &signed_delivery(wrong_previous.clone()),
            &wrong_previous.source,
        )
        .unwrap();
    assert!(checked.compare_previous(Some(&wrong)).is_err());
    assert!(
        verify_credential_handover(
            next(&checked, TargetDispositionAction::Withdraw),
            &value.target
        )
        .is_err()
    );
}
