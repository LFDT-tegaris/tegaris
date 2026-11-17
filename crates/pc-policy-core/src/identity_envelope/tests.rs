use super::*;
use serde::Deserialize;
use std::{path::Path, process::Command, sync::OnceLock};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Vector {
    envelope: Envelope,
    payload: Vec<u8>,
    cose: Vec<u8>,
    spki: Vec<u8>,
    wrong_cose: Vec<Vec<u8>>,
}
fn vector() -> &'static Vector {
    static VALUE: OnceLock<Vector> = OnceLock::new();
    VALUE.get_or_init(|| {
        let output = Command::new("node")
            .args([
                "--import",
                "tsx",
                "packages/security-kernel/src/identity-envelope/native-fixture.mjs",
            ])
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .output()
            .expect("fresh TypeScript canonical fixture must run");
        assert!(
            output.status.success(),
            "TypeScript canonical fixture failed"
        );
        serde_json::from_slice(&output.stdout).expect("exact typed fixture contract")
    })
}
fn child(parent: &Envelope, rotation: bool) -> Proposal {
    let mut proposal = Proposal::decode(&parent.proposal_bytes.0).unwrap();
    proposal.issuer.parent = OptionalParent(Some(Parent {
        envelope_id: proposal.envelope_id.clone(),
        active_version: parent.activation.active_version.clone(),
        semantic_revision: proposal.semantic_revision.clone(),
        artifact_digest: digest(&parent.encode().unwrap()),
        authority_epoch: proposal.authority_epoch.clone(),
        delegation_epoch: proposal.delegation_epoch.clone(),
    }));
    proposal.issuer.authority.authority_envelope_id = proposal.envelope_id.clone();
    proposal.issuer.kind = IssuerKind::Participant;
    if rotation {
        proposal.issuance = Issuance::Rotation;
        proposal.semantic_revision = Positive("2".to_owned());
    } else {
        proposal.issuance = Issuance::Child;
        proposal.envelope_id = DomainUuid("018f0000-0000-7000-8000-00000000003d".to_owned());
        proposal.usable.onward_delegation_depth.0 -= 1;
        proposal.grantable.onward_delegation_depth.0 -= 1;
    }
    proposal
}
#[test]
fn exact_typescript_native_bytes_and_fresh_es256() {
    let v = vector();
    assert_eq!(v.envelope.encode().unwrap(), v.payload);
    assert_eq!(Envelope::decode(&v.payload).unwrap(), v.envelope);
    assert_eq!(
        Envelope::verify_cose(&v.payload, &v.spki, &v.cose).unwrap(),
        v.envelope
    );
    assert_eq!(
        v.envelope.proposal_digest,
        digest(&v.envelope.proposal_bytes.0)
    );
    assert_ne!(v.envelope.proposal_digest, digest(&v.payload));
    let proposal = Proposal::decode(&v.envelope.proposal_bytes.0).unwrap();
    assert_eq!(proposal.encode().unwrap(), v.envelope.proposal_bytes.0);
    assert_eq!(
        proposal.usable.administration.action_intent_ids.0[0].0,
        "ACT-PARTICIPANTS_UPDATE_RESOURCE-V1"
    );
    assert_eq!(
        proposal.usable.runtime.capability_ids.0,
        vec![RuntimeCapability::Call]
    );
    assert_eq!(
        proposal.grantable.administration.data_classes.0,
        vec![Identifier("METADATA".to_owned())]
    );
}

#[test]
#[ignore = "requires the real PostgreSQL/public-governance/provider fixture"]
fn postgres_envelope_activation_original_wire() {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Original {
        envelope_id: String,
        participant_id: String,
        payload: Vec<u8>,
        cose: Vec<u8>,
        spki: Vec<u8>,
    }
    let path = std::env::var("OPENPC_ENVELOPE_ACTIVATION_PUBLIC_FIXTURE")
        .expect("the real governed fixture is required");
    assert!(Path::new(&path).is_absolute());
    let bytes = std::fs::read(path).expect("read the original public signed wire");
    assert!(bytes.len() < 600_000);
    let original: Original = serde_json::from_slice(&bytes).expect("exact original wire contract");
    let envelope = Envelope::verify_cose(&original.payload, &original.spki, &original.cose)
        .expect("actual provider signature and canonical SQL-checked payload");
    assert_eq!(envelope.encode().unwrap(), original.payload);
    let proposal = Proposal::decode(&envelope.proposal_bytes.0).unwrap();
    assert_eq!(proposal.envelope_id.0, original.envelope_id);
    assert_eq!(proposal.participant_id.0, original.participant_id);
    assert_eq!(proposal.issuance, Issuance::PlatformRoot);
    assert!(proposal.usable.runtime.capability_ids.0.is_empty());
    let mut tampered = original.cose.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(Envelope::verify_cose(&original.payload, &original.spki, &tampered).is_err());
}
#[test]
fn authentic_but_wrong_signature_context_is_not_an_envelope() {
    let v = vector();
    assert_eq!(v.wrong_cose.len(), 7);
    for wrong in &v.wrong_cose {
        assert!(Envelope::verify_cose(&v.payload, &v.spki, wrong).is_err());
    }
    assert!(Envelope::verify_cose(&v.payload, &v.spki, &v.cose[1..]).is_err());
    let mut wrong_key = v.spki.clone();
    wrong_key[40] ^= 1;
    assert!(Envelope::verify_cose(&v.payload, &wrong_key, &v.cose).is_err());
    let mut trailing = v.payload.clone();
    trailing.push(0);
    assert!(Envelope::decode(&trailing).is_err());
    let mut wrong_digest = v.envelope.clone();
    wrong_digest.proposal_digest = Hash32(format!("sha256:{}", "00".repeat(32)));
    assert!(wrong_digest.encode().is_err());
}
#[test]
fn child_requires_actual_grantable_narrowing_but_rotation_preserves_equal_bounds() {
    let parent = &vector().envelope;
    assert!(parent.assert_child(&child(parent, false)).is_ok());
    assert!(parent.assert_child(&child(parent, true)).is_ok());
    let mut equal = child(parent, false);
    equal.usable.onward_delegation_depth.0 = 2;
    equal.grantable.onward_delegation_depth.0 = 2;
    assert!(parent.assert_child(&equal).is_err());
    let mut wider = child(parent, false);
    wider.usable.runtime.target_profile_ids = FiniteSet(vec![Identifier("other".to_owned())]);
    assert!(parent.assert_child(&wider).is_err());
    let mut no_grant = parent.clone();
    let mut semantics = Proposal::decode(&no_grant.proposal_bytes.0).unwrap();
    semantics
        .grantable
        .administration
        .action_intent_ids
        .0
        .clear();
    no_grant.proposal_bytes = ProposalBytes(semantics.encode().unwrap());
    no_grant.proposal_digest = digest(&no_grant.proposal_bytes.0);
    assert!(no_grant.assert_child(&child(&no_grant, false)).is_err());
    let mut cyclic = child(parent, false);
    cyclic.envelope_id = cyclic.issuer.parent.0.as_ref().unwrap().envelope_id.clone();
    assert!(cyclic.encode().is_err());
    let mut orphan = child(parent, false);
    orphan.issuer.parent = OptionalParent(None);
    assert!(orphan.encode().is_err());
}
#[test]
fn original_intent_and_independent_step_up_are_bound_to_actual_versions() {
    let original = &vector().envelope;
    let mut value = original.clone();
    value.activation.candidate_id = value.submission.candidate_id.clone();
    assert!(value.encode().is_err());
    let mut value = original.clone();
    value.activation.expected_approved_version = Positive("2".to_owned());
    assert!(value.encode().is_err());
    let mut value = original.clone();
    value.submission.checker.authority.principal_id =
        value.submission.maker.authority.principal_id.clone();
    assert!(value.encode().is_err());
    let mut value = original.clone();
    value.activation.maker.step_up_challenge_id =
        value.submission.maker.step_up_challenge_id.clone();
    assert!(value.encode().is_err());
    let mut value = original.clone();
    value.submission.maker.authority.assignment_version = Positive("99".to_owned());
    assert!(value.encode().is_err());
}
