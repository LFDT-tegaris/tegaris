//! Cross-language SQL/TLS publication regression, invoked by the Compose gate.
use crate::{
    WorkloadPeer,
    identity_state::{
        InstalledWorkloadIdentities, RuntimeAuthorityRequest, RuntimeIdentityContext,
        RuntimeInvocationAuthorityRequest,
    },
};
use openpc_pds::{IdentityAssertionEvidence, IdentityAssertionVerifier, IdentitySnapshotTrust};
use pc_policy_core::cigl::grants::{CurrentInteractionSubjects, GrantSubject};
use pc_policy_core::invocation_capability::InvocationCapability;
use pc_runtime_types::Digest;
use serde::Deserialize;
use std::collections::BTreeMap;

#[path = "decision_owner_tests.rs"]
mod decision_owner;

#[derive(Deserialize)]
struct Content {
    digest: String,
    payload: String,
}
#[derive(Deserialize)]
struct Publication {
    manifest_payload: String,
    manifest_cose: String,
    manifest_digest: String,
    profile_payload: String,
    profile_cose: String,
    profile_digest: String,
    verification_time_ns: String,
    assertion_payload: String,
    assertion_cose: String,
    shards: Vec<String>,
    content: Vec<Content>,
}
#[derive(Deserialize)]
struct Fixture {
    participant_id: String,
    privacy_domain_id: String,
    target_runtime_id: String,
    principal_id: String,
    role_id: String,
    identity_public_key: String,
    certificate_pem: String,
    uri_san: String,
    first: Publication,
    revoked: Publication,
    regranted: Publication,
    runtime_granted: Publication,
    runtime_narrowed: Publication,
    ancestor_revoked: Publication,
}
fn bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn digest(text: &str) -> [u8; 32] {
    bytes(text).try_into().unwrap()
}
fn evidence(payload: &str, cose: &str) -> IdentityAssertionEvidence {
    IdentityAssertionEvidence {
        payload_cbor: bytes(payload),
        cose_sign1: bytes(cose),
    }
}
fn context(f: &Fixture) -> RuntimeIdentityContext {
    RuntimeIdentityContext {
        participant_id: f.participant_id.clone(),
        privacy_domain_id: f.privacy_domain_id.clone(),
        target_runtime_id: f.target_runtime_id.clone(),
    }
}
fn admit(
    f: &Fixture,
    p: &Publication,
    verifier: &IdentityAssertionVerifier,
) -> InstalledWorkloadIdentities {
    admit_context(context(f), p, verifier)
}
fn admit_context(
    context: RuntimeIdentityContext,
    p: &Publication,
    verifier: &IdentityAssertionVerifier,
) -> InstalledWorkloadIdentities {
    let profile = verifier
        .verify_runtime_authority_profile(
            &evidence(&p.profile_payload, &p.profile_cose),
            &digest(&p.profile_digest),
            "local-test-identity",
        )
        .unwrap();
    let now = p.verification_time_ns.parse().unwrap();
    let snapshot = verifier
        .verify_snapshot(
            &evidence(&p.manifest_payload, &p.manifest_cose),
            &p.shards.iter().map(|s| bytes(s)).collect::<Vec<_>>(),
            &IdentitySnapshotTrust {
                manifest_digest: digest(&p.manifest_digest),
                target_scope_digest: context.target_scope_digest(),
                release_profile_registry_digest: digest(&p.profile_digest),
                signer_id: "local-test-identity".into(),
                profiles: vec![profile.clone()],
                maximum_total_bytes: 4 * 1024 * 1024,
            },
            now,
        )
        .unwrap();
    assert_eq!(snapshot.actor_count(), 1);
    let mut artifacts: BTreeMap<_, _> = p
        .content
        .iter()
        .map(|c| (Digest::parse(&c.digest).unwrap(), bytes(&c.payload)))
        .collect();
    let accepted =
        InstalledWorkloadIdentities::admit(snapshot.clone(), &artifacts, context.clone(), &profile)
            .unwrap();
    let role_digest = snapshot
        .actors()
        .next()
        .unwrap()
        .role_assignment_set_digest();
    let key = Digest::parse(
        role_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
    .unwrap();
    artifacts.get_mut(&key).unwrap()[0] ^= 1;
    assert!(
        InstalledWorkloadIdentities::admit(snapshot.clone(), &artifacts, context.clone(), &profile)
            .is_err()
    );
    artifacts.remove(&key);
    assert!(InstalledWorkloadIdentities::admit(snapshot, &artifacts, context, &profile).is_err());
    accepted
}

#[derive(Deserialize)]
struct WalletFixture {
    participant_id: String,
    privacy_domain_id: String,
    target_runtime_id: String,
    principal_id: String,
    wallet_binding_id: String,
    role_id: String,
    runtime_binding_id: String,
    conditional_runtime_binding_id: String,
    identity_public_key: String,
    certificate_pem: String,
    uri_san: String,
    empty: Publication,
    active: Publication,
    submission_granted: Publication,
    status_granted: Publication,
    revoked: Publication,
}

#[test]
fn governed_wallet_publication_binds_recovered_signer_without_granting_permission() {
    let Ok(path) = std::env::var("OPENPC_ASTRA07_WALLET_PUBLICATION_FIXTURE") else {
        return;
    };
    let fixture: WalletFixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let context = RuntimeIdentityContext {
        participant_id: fixture.participant_id.clone(),
        privacy_domain_id: fixture.privacy_domain_id.clone(),
        target_runtime_id: fixture.target_runtime_id.clone(),
    };
    let verifier =
        IdentityAssertionVerifier::new(&[bytes(&fixture.identity_public_key)], 60_000).unwrap();
    let pem = x509_parser::pem::parse_x509_pem(fixture.certificate_pem.as_bytes())
        .unwrap()
        .1;
    let escaped = fixture
        .certificate_pem
        .bytes()
        .map(|b| format!("%{b:02X}"))
        .collect::<String>();
    let now = fixture.active.verification_time_ns.parse::<u64>().unwrap();
    let peer = WorkloadPeer::from_envoy_headers(
        &[(
            "x-forwarded-client-cert".into(),
            format!(
                "Hash={};Cert=\"{}\";URI={}",
                Digest::of(&pem.contents).as_str(),
                escaped,
                fixture.uri_san
            )
            .into_bytes(),
        )],
        now / 1_000_000,
    )
    .unwrap();
    let transaction = openpc_multi_rpc::signed_transaction::SignedTransaction::decode(&bytes(
        "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
    )).unwrap();
    let empty = admit_context(context.clone(), &fixture.empty, &verifier);
    assert!(
        empty
            .validate_call_sender(&peer, transaction.chain_id(), transaction.signer(), now)
            .is_err()
    );
    assert!(
        empty
            .wallet_association_for_transaction(&peer, &transaction, now)
            .is_err()
    );
    let active = admit_context(context.clone(), &fixture.active, &verifier);
    let binding = active
        .wallet_association_for_transaction(&peer, &transaction, now)
        .unwrap();
    assert_eq!(binding.id(), fixture.wallet_binding_id);
    assert_eq!(binding.epoch(), 1);
    active
        .validate_call_sender(&peer, transaction.chain_id(), transaction.signer(), now)
        .unwrap();
    assert!(
        active
            .validate_call_sender(&peer, transaction.chain_id() + 1, transaction.signer(), now)
            .is_err()
    );
    assert!(
        active
            .validate_call_sender(&peer, transaction.chain_id(), &[0x35; 20], now)
            .is_err()
    );
    assert!(
        active
            .authorize_runtime(
                &peer,
                &RuntimeInvocationAuthorityRequest {
                    capability: InvocationCapability::CallResultDisclosure,
                    resource_id: &fixture.runtime_binding_id,
                    risk_class: "LOW",
                },
                now
            )
            .is_err()
    );
    let (active_identity, principal) = active.identity_for_peer(&peer, now).unwrap();
    assert_eq!(principal, fixture.principal_id);
    verifier
        .verify(
            &evidence(
                &fixture.active.assertion_payload,
                &fixture.active.assertion_cose,
            ),
            &active_identity,
            now / 1_000_000,
        )
        .unwrap();
    assert!(
        active
            .authorize_runtime(
                &peer,
                &RuntimeInvocationAuthorityRequest {
                    capability: InvocationCapability::SignedTransactionSubmission,
                    resource_id: "fixture-contract",
                    risk_class: "HIGH",
                },
                now
            )
            .is_err()
    );
    let submission = RuntimeInvocationAuthorityRequest {
        capability: InvocationCapability::SignedTransactionSubmission,
        resource_id: &fixture.runtime_binding_id,
        risk_class: "LOW",
    };
    assert!(
        active
            .authorize_submission(&peer, &transaction, &submission, now)
            .is_err()
    );
    let granted = admit_context(context.clone(), &fixture.submission_granted, &verifier);
    let granted_now = fixture
        .submission_granted
        .verification_time_ns
        .parse::<u64>()
        .unwrap();
    let authorization = granted
        .authorize_submission(&peer, &transaction, &submission, granted_now)
        .unwrap();
    assert!(
        granted
            .authorize_submission(
                &peer,
                &transaction,
                &RuntimeInvocationAuthorityRequest {
                    capability: InvocationCapability::SignedTransactionSubmission,
                    resource_id: &fixture.conditional_runtime_binding_id,
                    risk_class: "LOW",
                },
                granted_now,
            )
            .is_err()
    );
    verifier
        .verify(
            &evidence(
                &fixture.submission_granted.assertion_payload,
                &fixture.submission_granted.assertion_cose,
            ),
            &authorization.identity,
            granted_now / 1_000_000,
        )
        .unwrap();
    for (capability, resource_id, risk_class) in [
        (
            InvocationCapability::CallResultDisclosure,
            fixture.runtime_binding_id.as_str(),
            "LOW",
        ),
        (
            InvocationCapability::GasEstimateDisclosure,
            fixture.runtime_binding_id.as_str(),
            "LOW",
        ),
        (
            InvocationCapability::UnsignedTransactionPreparation,
            fixture.runtime_binding_id.as_str(),
            "LOW",
        ),
        (
            InvocationCapability::OperationStatusDisclosure,
            fixture.runtime_binding_id.as_str(),
            "LOW",
        ),
        (
            InvocationCapability::SignedTransactionSubmission,
            "foreign-binding",
            "LOW",
        ),
        (
            InvocationCapability::SignedTransactionSubmission,
            fixture.runtime_binding_id.as_str(),
            "HIGH",
        ),
    ] {
        let query = RuntimeInvocationAuthorityRequest {
            capability,
            resource_id,
            risk_class,
        };
        assert!(
            granted
                .authorize_runtime(&peer, &query, granted_now)
                .is_err()
        );
        assert!(
            granted
                .authorize_submission(&peer, &transaction, &query, granted_now)
                .is_err()
        );
    }
    let revoked = admit_context(context, &fixture.revoked, &verifier);
    let revoked_now = fixture.revoked.verification_time_ns.parse::<u64>().unwrap();
    assert!(
        revoked
            .validate_call_sender(
                &peer,
                transaction.chain_id(),
                transaction.signer(),
                revoked_now
            )
            .is_err()
    );
    assert!(
        revoked
            .wallet_association_for_transaction(&peer, &transaction, revoked_now)
            .is_err()
    );
    assert!(
        revoked
            .authorize_submission(&peer, &transaction, &submission, revoked_now)
            .is_err()
    );
    let (revoked_identity, _) = revoked.identity_for_peer(&peer, revoked_now).unwrap();
    assert!(
        verifier
            .verify(
                &evidence(
                    &fixture.active.assertion_payload,
                    &fixture.active.assertion_cose
                ),
                &revoked_identity,
                revoked_now / 1_000_000
            )
            .is_err()
    );
    verifier
        .verify(
            &evidence(
                &fixture.revoked.assertion_payload,
                &fixture.revoked.assertion_cose,
            ),
            &revoked_identity,
            revoked_now / 1_000_000,
        )
        .unwrap();
}

/// This is capsule/identity-owner acceptance only. Other product components
/// are deliberately absent; this does not establish a complete runtime journey.
fn verify_capsule_custody(f: &Fixture, p: &Publication, peer: &WorkloadPeer) {
    use crate::{
        ArtifactComponent, CapsuleTrust, RuntimeAgent, RuntimeWireSigner,
        identity_custody::IdentityArtifactAdmission,
    };
    use std::sync::Arc;
    let now = p.verification_time_ns.parse::<u64>().unwrap();
    let mut capsule = crate::wire_tests::capsule();
    capsule.target_runtime_id = f.target_runtime_id.clone();
    capsule.identity_snapshot_manifest_digest = Digest::parse(&p.manifest_digest).unwrap();
    capsule.issued_at_ns = now;
    capsule.not_before_ns = now + 1;
    capsule.hard_expiry_ns = now + 1_000_000;
    let mut artifacts: BTreeMap<_, _> = p
        .content
        .iter()
        .map(|c| (Digest::parse(&c.digest).unwrap(), bytes(&c.payload)))
        .collect();
    for shard in &p.shards {
        let payload = bytes(shard);
        artifacts.insert(Digest::of(&payload), payload);
    }
    capsule.artifact_components = [
        (
            3004,
            "identity-snapshot",
            &p.manifest_cose,
            &p.manifest_digest,
        ),
        (3010, "identity-profile", &p.profile_cose, &p.profile_digest),
    ]
    .into_iter()
    .map(|(schema, id, cose, semantic)| {
        let payload = bytes(cose);
        let component = ArtifactComponent {
            component_id: id.into(),
            component_type: id.into(),
            content_digest: Digest::of(&payload),
            semantic_digest: Digest::parse(semantic).unwrap(),
            schema_id: schema,
            schema_version: 2,
            size_bytes: payload.len() as u64,
            required: true,
        };
        artifacts.insert(component.content_digest.clone(), payload);
        component
    })
    .collect();
    capsule.artifact_components.reverse();
    let signer = RuntimeWireSigner::from_secret_bytes([32; 32]).unwrap();
    let policy_owner = crate::invocation_publication_fixture::install(
        &f.participant_id,
        &f.privacy_domain_id,
        peer.workload_id(),
        &f.role_id,
        &mut capsule,
        &mut artifacts,
        &signer,
    );
    let mrpc_signer = pc_policy_core::runtime_wire::Signer::from_secret_bytes([55; 32]).unwrap();
    let mrpc_profile = openpc_multi_rpc::runtime_profile::MrpcRuntimeProfile {
        profile_id: "local-custody-mrpc".into(),
        capability_registry_digest: Digest::of(b"test-local MRPC capability registry"),
        endpoint_role_rules_digest: Digest::of(b"test-local endpoint roles"),
        coherence_rules_digest: Digest::of(b"test-local coherence rules"),
        signer_id: "local-mrpc-owner".into(),
    };
    let profile_bytes = mrpc_profile.sign(&mrpc_signer).unwrap();
    capsule.mrpc_runtime_profile_digest = mrpc_profile.semantic_digest().unwrap();
    capsule.artifact_components.push(ArtifactComponent {
        component_id: "mrpc-profile".into(),
        component_type: "mrpc-runtime-profile".into(),
        content_digest: Digest::of(&profile_bytes),
        semantic_digest: capsule.mrpc_runtime_profile_digest.clone(),
        schema_id: 2014,
        schema_version: 3,
        size_bytes: profile_bytes.len() as u64,
        required: true,
    });
    artifacts.insert(Digest::of(&profile_bytes), profile_bytes);
    capsule.artifact_components.sort_by(|a, b| {
        a.component_id
            .len()
            .cmp(&b.component_id.len())
            .then(a.component_id.cmp(&b.component_id))
    });
    let mrpc_owner = Arc::new(
        crate::mrpc_custody::MrpcProfileAdmission::new(
            mrpc_signer.verifier(),
            crate::mrpc_custody::MrpcProfileTrust {
                profile_id: mrpc_profile.profile_id.clone(),
                signer_id: mrpc_profile.signer_id.clone(),
                capability_registry_digest: mrpc_profile.capability_registry_digest.clone(),
                endpoint_role_rules_digest: mrpc_profile.endpoint_role_rules_digest.clone(),
                coherence_rules_digest: mrpc_profile.coherence_rules_digest.clone(),
            },
            policy_owner.clone(),
        )
        .unwrap(),
    );
    assert_eq!(
        mrpc_owner.admit_profile(&capsule, &artifacts).unwrap().0,
        mrpc_profile
    );
    let mut wrong_profile = capsule.clone();
    wrong_profile.mrpc_runtime_profile_digest = Digest::of(b"different profile");
    assert!(
        mrpc_owner
            .admit_profile(&wrong_profile, &artifacts)
            .is_err()
    );
    let admission = Arc::new(
        IdentityArtifactAdmission::new(
            IdentityAssertionVerifier::new(&[bytes(&f.identity_public_key)], 60_000).unwrap(),
            context(f),
            Digest::parse(&p.profile_digest).unwrap(),
            "local-test-identity".into(),
            4 * 1024 * 1024,
            mrpc_owner.clone(),
        )
        .unwrap(),
    );
    let trust = CapsuleTrust {
        target_id: capsule.target_runtime_id.clone(),
        fleet_id: capsule.fleet_id.clone(),
        fleet_signer_id: capsule.signer_id.clone(),
        agent_signer_id: "agent-custody".into(),
        contract_set_manifest_digest: capsule.contract_set_manifest_digest.clone(),
        schema_registry_digest: capsule.schema_registry_digest.clone(),
        cose_purpose_registry_digest: capsule.cose_purpose_registry_digest.clone(),
        complete_component_set_digest: capsule.complete_component_set_digest.clone(),
    };
    let fixture_path =
        std::path::PathBuf::from(std::env::var("OPENPC_ASTRA05_PUBLICATION_FIXTURE").unwrap());
    let directory = fixture_path
        .parent()
        .unwrap()
        .join("target-identity-custody");
    let open = || {
        RuntimeAgent::open_canonical(
            trust.clone(),
            &signer.verifier().public_key_bytes(),
            [33; 32],
            8,
            4 * 1024 * 1024,
            &directory,
            admission.clone(),
        )
        .unwrap()
    };
    let agent = open();
    let signed = signer.sign_capsule(&capsule).unwrap();
    // Preparation also observes not-before. Use the signed boundary for every
    // admission attempt so negative cases cannot pass merely due to a bad clock.
    let admission_time = capsule.not_before_ns;
    let mut extra = artifacts.clone();
    extra.insert(Digest::of(b"unreferenced"), b"unreferenced".to_vec());
    assert!(
        agent
            .prepare_capsule(signed.clone(), extra, admission_time)
            .is_err()
    );
    let mut missing = artifacts.clone();
    missing.remove(&Digest::of(bytes(&p.shards[0])));
    assert!(
        agent
            .prepare_capsule(signed.clone(), missing, admission_time)
            .is_err()
    );
    let mut wrong = capsule.clone();
    wrong.identity_snapshot_manifest_digest = Digest::of(b"foreign-manifest");
    assert!(
        agent
            .prepare_capsule(
                signer.sign_capsule(&wrong).unwrap(),
                artifacts.clone(),
                admission_time
            )
            .is_err()
    );
    let expected = agent
        .prepare_capsule(signed, artifacts, admission_time)
        .unwrap();
    agent.activate_capsule(&expected, admission_time).unwrap();
    drop(agent);
    let agent = open();
    agent
        .with_active_capsule(|active, bytes| {
            let (identities, _) = admission.admit_identity(active, bytes)?;
            let (policies, _) = policy_owner.admit_policies(active, bytes)?;
            assert_eq!(
                policies
                    .policies_for(peer, &f.privacy_domain_id, active)?
                    .len(),
                1
            );
            assert!(
                policies
                    .policies_for(peer, "foreign privacy", active)
                    .is_err()
            );
            let granted = identities.authorize(
                peer,
                &RuntimeAuthorityRequest {
                    action_intent_id: "ACT-POLICY_READ_EFFECTIVE_ACCESS-V1",
                    resource_id: "fixture-contract",
                    risk_class: "LOW",
                },
                now,
            )?;
            assert_eq!(
                granted.authorization.facts().actor_principal_id,
                f.principal_id
            );
            assert_eq!(active.digest()?, expected);
            Ok(())
        })
        .unwrap();
    drop(agent);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn postgres_tls_publication_is_admitted_by_the_real_target_identity_owner() {
    let Ok(path) = std::env::var("OPENPC_ASTRA05_PUBLICATION_FIXTURE") else {
        return;
    };
    let f: Fixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let verifier =
        IdentityAssertionVerifier::new(&[bytes(&f.identity_public_key)], 60_000).unwrap();
    let pem = x509_parser::pem::parse_x509_pem(f.certificate_pem.as_bytes())
        .unwrap()
        .1;
    let certificate_digest = Digest::of(&pem.contents);
    let escaped = f
        .certificate_pem
        .bytes()
        .map(|b| format!("%{b:02X}"))
        .collect::<String>();
    let peer = WorkloadPeer::from_envoy_headers(
        &[(
            "x-forwarded-client-cert".into(),
            format!(
                "Hash={};Cert=\"{}\";URI={}",
                certificate_digest.as_str(),
                escaped,
                f.uri_san
            )
            .into_bytes(),
        )],
        f.first.verification_time_ns.parse::<u64>().unwrap() / 1_000_000,
    )
    .unwrap();
    let request = RuntimeAuthorityRequest {
        action_intent_id: "ACT-POLICY_READ_EFFECTIVE_ACCESS-V1",
        resource_id: "fixture-contract",
        risk_class: "LOW",
    };
    let first = admit(&f, &f.first, &verifier);
    verify_capsule_custody(&f, &f.first, &peer);
    let now = f.first.verification_time_ns.parse::<u64>().unwrap();
    let allowed = first.authorize(&peer, &request, now).unwrap();
    let (identity_only, principal) = first.identity_for_peer(&peer, now).unwrap();
    assert_eq!(principal, f.principal_id);
    verifier
        .verify(
            &evidence(&f.first.assertion_payload, &f.first.assertion_cose),
            &identity_only,
            now / 1_000_000,
        )
        .unwrap();
    let runtime_request = RuntimeInvocationAuthorityRequest {
        capability: InvocationCapability::CallResultDisclosure,
        resource_id: "fixture-contract",
        risk_class: "LOW",
    };
    assert!(
        first
            .authorize_runtime(&peer, &runtime_request, now)
            .is_err()
    );
    assert_eq!(allowed.authorization.facts().roles, vec![f.role_id.clone()]);
    assert_eq!(
        allowed.authorization.facts().actor_principal_id,
        f.principal_id
    );
    verifier
        .verify(
            &evidence(&f.first.assertion_payload, &f.first.assertion_cose),
            &allowed.identity,
            now / 1_000_000,
        )
        .unwrap();
    assert!(
        first
            .authorize(
                &peer,
                &RuntimeAuthorityRequest {
                    action_intent_id: "ungranted-action",
                    ..request
                },
                now
            )
            .is_err()
    );
    let revoked = admit(&f, &f.revoked, &verifier);
    assert!(
        revoked
            .authorize(
                &peer,
                &request,
                f.revoked.verification_time_ns.parse().unwrap()
            )
            .is_err()
    );
    let regranted = admit(&f, &f.regranted, &verifier);
    let now = f.regranted.verification_time_ns.parse::<u64>().unwrap();
    let current = regranted.authorize(&peer, &request, now).unwrap();
    // Reacquiring identity after I/O checks the current authority vector even
    // before requesting a new invocation grant. An old valid signature fails.
    let (current_identity, principal) = regranted.identity_for_peer(&peer, now).unwrap();
    assert_eq!(principal, f.principal_id);
    assert!(
        verifier
            .verify(
                &evidence(&f.first.assertion_payload, &f.first.assertion_cose),
                &current_identity,
                now / 1_000_000,
            )
            .is_err()
    );
    verifier
        .verify(
            &evidence(&f.regranted.assertion_payload, &f.regranted.assertion_cose),
            &current.identity,
            now / 1_000_000,
        )
        .unwrap();
    assert!(
        verifier
            .verify(
                &evidence(&f.first.assertion_payload, &f.first.assertion_cose),
                &current.identity,
                now / 1_000_000
            )
            .is_err()
    );
    assert!(
        regranted
            .authorize(&peer, &request, current.valid_until_ns)
            .is_err()
    );
    let ancestor_revoked = admit(&f, &f.ancestor_revoked, &verifier);
    let runtime_granted = admit(&f, &f.runtime_granted, &verifier);
    let now = f.runtime_granted.verification_time_ns.parse().unwrap();
    let runtime_authorization = runtime_granted
        .authorize_runtime(&peer, &runtime_request, now)
        .unwrap();
    runtime_authorization.require_current(now).unwrap();
    for subject in [
        GrantSubject::Role {
            id: f.role_id.clone(),
        },
        GrantSubject::Workload {
            id: peer.workload_id().into(),
        },
        GrantSubject::Participant {
            id: f.participant_id.clone(),
        },
        GrantSubject::AnyAuthenticated {},
    ] {
        assert!(runtime_authorization.matches(&subject).unwrap());
    }
    for subject in [
        GrantSubject::User {
            id: f.principal_id.clone(),
        },
        GrantSubject::Group {
            id: f.role_id.clone(),
        },
        GrantSubject::Workload {
            id: f.principal_id.clone(),
        },
        GrantSubject::Participant {
            id: "foreign-participant".into(),
        },
    ] {
        assert!(!runtime_authorization.matches(&subject).unwrap());
    }
    assert!(
        runtime_authorization
            .require_current(runtime_authorization.valid_until_ns)
            .is_err()
    );
    assert_eq!(
        runtime_authorization.authorization.facts().roles,
        vec![f.role_id.clone()]
    );
    verifier
        .verify(
            &evidence(
                &f.runtime_granted.assertion_payload,
                &f.runtime_granted.assertion_cose,
            ),
            &runtime_authorization.identity,
            now / 1_000_000,
        )
        .unwrap();
    assert!(
        runtime_granted
            .authorize_runtime(
                &peer,
                &RuntimeInvocationAuthorityRequest {
                    capability: InvocationCapability::SignedTransactionSubmission,
                    ..runtime_request
                },
                now
            )
            .is_err()
    );
    assert!(
        runtime_granted
            .authorize_runtime(
                &peer,
                &RuntimeInvocationAuthorityRequest {
                    risk_class: "HIGH",
                    ..runtime_request
                },
                now
            )
            .is_err()
    );
    assert!(
        runtime_granted
            .authorize_runtime(
                &peer,
                &runtime_request,
                runtime_authorization.valid_until_ns
            )
            .is_err()
    );
    let runtime_narrowed = admit(&f, &f.runtime_narrowed, &verifier);
    assert!(
        runtime_narrowed
            .authorize_runtime(
                &peer,
                &runtime_request,
                f.runtime_narrowed.verification_time_ns.parse().unwrap()
            )
            .is_err()
    );
    assert!(
        ancestor_revoked
            .authorize_runtime(
                &peer,
                &runtime_request,
                f.ancestor_revoked.verification_time_ns.parse().unwrap()
            )
            .is_err()
    );
    assert!(
        ancestor_revoked
            .authorize(
                &peer,
                &request,
                f.ancestor_revoked.verification_time_ns.parse().unwrap()
            )
            .is_err()
    );
}
