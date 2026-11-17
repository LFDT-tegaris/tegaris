use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;
use p256::pkcs8::EncodePublicKey;

/// Called by the ordinary Fleet preflight before PostgreSQL allocation. The
/// TypeScript producer supplies freshly signed bytes, not a native fixture.
#[test]
#[ignore = "requires the TypeScript profile wire producer"]
fn typescript_profile_wire_interoperability() {
    let wire: serde_json::Value = serde_json::from_str(
        &std::env::var("OPENPC_FACT_PROFILE_WIRE").expect("profile wire fixture"),
    )
    .unwrap();
    let claim = &wire["profile"];
    let string = |field: &str| claim[field].as_str().unwrap().to_owned();
    let bytes = |field: &str| {
        let value = wire[field].as_str().unwrap();
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let cose = bytes("cose");
    let installed = InstalledFactConsumerProfile {
        issuer_spki_der: bytes("spki"),
        signed_profile_digest: format!("sha256:{}", hex(&Sha256::digest(&cose))),
        environment_id: string("environmentId"),
        participant_id: string("participantId"),
        privacy_domain_id: string("privacyDomainId"),
        profile_id: string("profileId"),
        revision: string("revision"),
        consumer_id: string("consumerId"),
        subscription_id: string("subscriptionId"),
        workload_credential_id: string("workloadCredentialId"),
        workload_credential_epoch: string("workloadCredentialEpoch"),
        database_role: string("databaseRole"),
    };
    let now = wire["nowMs"].as_u64().unwrap();
    let result = verify_installed_fact_consumer_profile(&installed, &bytes("payload"), &cose, now);
    assert_eq!(result.is_ok(), wire["accepted"].as_bool().unwrap());
    if wire["derived"].as_bool().unwrap() {
        assert_eq!(
            installed.database_role,
            runtime_source_login(&installed.participant_id, &installed.privacy_domain_id).unwrap()
        );
    }
    println!("OPENPC_FACT_PROFILE_WIRE|PASS");
}

/// Called by the ordinary PostgreSQL Fleet gate after the TypeScript installer
/// commits initial trust, then again after revocation. This proves native/TS
/// signature and live database admission interoperability, not Fact production.
#[tokio::test]
#[ignore = "requires the owned PostgreSQL Fleet integration fixture"]
async fn postgres_typescript_consumer_profile_native_admission() {
    let env = |key| std::env::var(key).expect("required consumer profile fixture");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&env("OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL"))
        .await
        .unwrap();
    let participant = env("OPENPC_FACT_CONSUMER_PARTICIPANT");
    let privacy = env("OPENPC_FACT_CONSUMER_PRIVACY");
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-OPERATIONS_READ_OPERATION-V1',true)")
        .bind(&participant).bind(&privacy).execute(&mut *tx).await.unwrap();
    let result =
        lock_installed_fact_consumer_profile(&mut tx, &participant, &privacy, "LS-FLEET-CONTROL")
            .await;
    if env("OPENPC_FACT_CONSUMER_EXPECT_BLOCKED") == "1" {
        assert!(
            result.is_err(),
            "revoked workload must not regain native admission"
        );
    } else {
        let verified = result.unwrap();
        assert_eq!(
            verified.profile_digest(),
            env("OPENPC_FACT_CONSUMER_DIGEST")
        );
    }
    tx.rollback().await.unwrap();
    pool.close().await;
}

struct Fixture {
    key: SigningKey,
    installed: InstalledFactConsumerProfile,
    fields: Vec<(Value, Value)>,
}
impl Fixture {
    fn new() -> Self {
        let key = SigningKey::generate();
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let tenant = "018f0000-0000-7000-8000-000000000101";
        let privacy = "018f0000-0000-7000-8000-000000000201";
        let credential = "018f0000-0000-7000-8000-000000000301";
        let definition: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../schemas/canonical/fact-consumer-profile-v1.json"
        ))
        .unwrap();
        let definition_digest = Sha256::digest(serde_json::to_vec(&definition).unwrap());
        assert_eq!(hex(&definition_digest), generated::DEFINITION_DIGEST);
        let text = |s: &str| Value::Text(s.into());
        let id = |s| Value::Bytes(Uuid::parse_str(s).unwrap().as_bytes().to_vec());
        let fields = vec![
            (uint(0), Value::Bytes(definition_digest.to_vec())),
            (uint(1), text("local-acceptance")),
            (uint(2), id(tenant)),
            (uint(3), id(privacy)),
            (uint(4), text("fact-admission")),
            (uint(5), uint(u64::MAX)),
            (uint(6), text("LS-FLEET-CONTROL")),
            (uint(7), text("SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1")),
            (uint(8), uint(1000)),
            (uint(9), uint(100000)),
            (uint(10), Value::Bytes(Sha256::digest(&spki).to_vec())),
            (uint(11), id(credential)),
            (uint(12), uint(u64::MAX)),
            (uint(13), text("fact_consumer")),
            (uint(14), uint(5)),
            (uint(15), uint(100)),
            (uint(16), uint(300)),
        ];
        Self {
            key,
            fields,
            installed: InstalledFactConsumerProfile {
                issuer_spki_der: spki,
                signed_profile_digest: String::new(),
                environment_id: "local-acceptance".into(),
                participant_id: tenant.into(),
                privacy_domain_id: privacy.into(),
                profile_id: "fact-admission".into(),
                revision: u64::MAX.to_string(),
                consumer_id: "LS-FLEET-CONTROL".into(),
                subscription_id: "SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1".into(),
                workload_credential_id: credential.into(),
                workload_credential_epoch: u64::MAX.to_string(),
                database_role: "fact_consumer".into(),
            },
        }
    }
    fn sign(&self, payload: &[u8], header: Vec<u8>) -> (InstalledFactConsumerProfile, Vec<u8>) {
        let input = encode(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(header.clone()),
            Value::Bytes(b"pcplane:cose-sign1:v2\0".to_vec()),
            Value::Bytes(payload.to_vec()),
        ]))
        .unwrap();
        let signature: Signature = self.key.sign(&input);
        let mut cose = vec![0xd2];
        cose.extend(
            encode(&Value::Array(vec![
                Value::Bytes(header),
                Value::Map(vec![]),
                Value::Bytes(payload.to_vec()),
                Value::Bytes(signature.to_bytes().to_vec()),
            ]))
            .unwrap(),
        );
        let mut installed = self.installed.clone();
        installed.signed_profile_digest = format!("sha256:{}", hex(&Sha256::digest(&cose)));
        (installed, cose)
    }
    fn encoded(&self) -> (InstalledFactConsumerProfile, Vec<u8>, Vec<u8>) {
        let payload = encode(&Value::Map(self.fields.clone())).unwrap();
        let (installed, cose) = self.sign(
            &payload,
            protected(&self.installed.issuer_spki_der).unwrap(),
        );
        (installed, payload, cose)
    }
}

#[test]
fn installed_scope_and_finite_retry_schedule_preserve_full_u64_epochs() {
    for fleet in [true, false] {
        let mut fixture = Fixture::new();
        if !fleet {
            fixture.installed.consumer_id = "LS-CONTROL-WORK".into();
            fixture.installed.subscription_id = "SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1".into();
            fixture.fields[6].1 = Value::Text(fixture.installed.consumer_id.clone());
            fixture.fields[7].1 = Value::Text(fixture.installed.subscription_id.clone());
        }
        let (installed, payload, cose) = fixture.encoded();
        let verified =
            verify_installed_fact_consumer_profile(&installed, &payload, &cose, 1000).unwrap();
        for (attempt, deadline) in [(1, 1100), (2, 1200), (3, 1300), (4, 1300)] {
            assert_eq!(
                verified.retry_after_failure(attempt, 1000).unwrap(),
                ConsumerRetryDecision::Retry {
                    not_before_ms: deadline
                }
            );
        }
        assert_eq!(
            verified.retry_after_failure(5, 1000).unwrap(),
            ConsumerRetryDecision::Quarantine
        );
        assert_eq!(
            verified.retry_after_failure(1, 99900).unwrap(),
            ConsumerRetryDecision::ProfileNotCurrent
        );
        assert!(verified.retry_after_failure(0, 1000).is_err());
        assert!(verified.retry_after_failure(1001, 1000).is_err());
    }
}

#[test]
fn every_installation_pin_and_current_time_is_required() {
    let fixture = Fixture::new();
    let (installed, payload, cose) = fixture.encoded();
    for index in 0..13 {
        let mut changed = installed.clone();
        match index {
            0 => changed.environment_id.push('x'),
            1 => changed.participant_id.push('x'),
            2 => changed.privacy_domain_id.push('x'),
            3 => changed.profile_id.push('x'),
            4 => changed.revision = "1".into(),
            5 => changed.consumer_id = "LS-CONTROL-WORK".into(),
            6 => changed.subscription_id = "SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1".into(),
            7 => changed.workload_credential_id.push('x'),
            8 => changed.workload_credential_epoch = "0".into(),
            9 => changed.database_role.push('x'),
            10 => changed.signed_profile_digest.push('0'),
            11 => changed.issuer_spki_der = Fixture::new().installed.issuer_spki_der,
            12 => changed.revision = format!("0{}", changed.revision),
            _ => unreachable!(),
        }
        assert!(
            verify_installed_fact_consumer_profile(&changed, &payload, &cose, 1000).is_err(),
            "pin {index}"
        );
    }
    for now in [0, 999, 100000, SAFE_UINT + 1] {
        assert!(verify_installed_fact_consumer_profile(&installed, &payload, &cose, now).is_err());
    }
}

#[test]
fn authentic_signatures_cannot_admit_malformed_claims_or_changed_cose_context() {
    for (field, value) in [
        (0, Value::Bytes(vec![0; 32])),
        (5, uint(0)),
        (7, Value::Text("other".into())),
        (9, uint(1000)),
        (9, uint(SAFE_UINT + 1)),
        (10, Value::Bytes(vec![0; 32])),
        (14, uint(0)),
        (14, uint(1001)),
        (15, uint(0)),
        (16, uint(99)),
        (16, uint(3600001)),
    ] {
        let mut fixture = Fixture::new();
        fixture.fields[field].1 = value;
        let (installed, payload, cose) = fixture.encoded();
        assert!(
            verify_installed_fact_consumer_profile(&installed, &payload, &cose, 1000).is_err(),
            "field {field}"
        );
    }
    let fixture = Fixture::new();
    let (_, payload, _) = fixture.encoded();
    let header = decode(
        &protected(&fixture.installed.issuer_spki_der).unwrap(),
        65536,
    )
    .unwrap();
    for (field, replacement) in [(4, 24002), (5, 2), (6, 339), (7, 1)] {
        let mut altered = header.as_map().unwrap().clone();
        altered[field].1 = uint(replacement);
        let (installed, cose) = fixture.sign(&payload, encode(&Value::Map(altered)).unwrap());
        assert!(verify_installed_fact_consumer_profile(&installed, &payload, &cose, 1000).is_err());
    }
    for bad in [
        [payload.as_slice(), &[0]].concat(),
        [&[0xb8, 17][..], &payload[1..]].concat(),
    ] {
        let (installed, cose) =
            fixture.sign(&bad, protected(&fixture.installed.issuer_spki_der).unwrap());
        assert!(verify_installed_fact_consumer_profile(&installed, &bad, &cose, 1000).is_err());
    }
}

#[test]
fn retry_exhaustion_expiry_and_saturation_cannot_restore_attempts() {
    let mut fixture = Fixture::new();
    fixture.fields[14].1 = uint(1000);
    let (installed, payload, cose) = fixture.encoded();
    let verified =
        verify_installed_fact_consumer_profile(&installed, &payload, &cose, 1000).unwrap();
    assert_eq!(
        verified.retry_after_failure(999, 1000).unwrap(),
        ConsumerRetryDecision::Retry {
            not_before_ms: 1300
        }
    );
    assert_eq!(
        verified.retry_after_failure(1000, 1000).unwrap(),
        ConsumerRetryDecision::Quarantine
    );
    fixture.fields[14].1 = uint(3);
    fixture.fields[9].1 = uint(SAFE_UINT);
    let (installed, payload, cose) = fixture.encoded();
    let verified =
        verify_installed_fact_consumer_profile(&installed, &payload, &cose, 1000).unwrap();
    assert_eq!(
        verified.retry_after_failure(4, 1000).unwrap(),
        ConsumerRetryDecision::Quarantine
    );
    assert_eq!(
        verified.retry_after_failure(1, SAFE_UINT - 50).unwrap(),
        ConsumerRetryDecision::ProfileNotCurrent
    );
}
