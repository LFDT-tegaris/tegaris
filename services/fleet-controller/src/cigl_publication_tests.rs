use super::*;
use pc_policy_core::cigl::settings::{InstalledCiglSettings, SettingsScope};
use pc_policy_core::invocation::{
    ActiveInvocationConfigurationV1, ConfigurationArtifactV1, InvocationConfigurationAssetV1,
    encode_active_invocation_configuration,
};
use pc_runtime_types::RequestClass;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicSource {
    configuration_artifact_cbor: String,
    configuration_artifact_digest: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    participant_id: String,
    privacy_domain_id: String,
    source: PublicSource,
}
fn configuration(source: &ConfiguredCiglSettings) -> ActiveInvocationConfigurationV1 {
    let payload = source.to_cbor().unwrap();
    ActiveInvocationConfigurationV1 {
        workload_scope: None,
        visibility_resources: Vec::new(),
        schema_version: "1.0".into(),
        deployment_policies: vec![],
        // A legacy method is sufficient to test settings source custody. This
        // fixture is not a contract-registration or invocation-permission claim.
        assets: vec![InvocationConfigurationAssetV1 {
            asset_id: "source-provenance".into(),
            runtime_binding_id: None,
            transaction_policy: None,
            tenant_id: source.participant_id.clone(),
            privacy_domain_id: source.privacy_domain_id.clone(),
            workload_id: "settings-source-workload".into(),
            rpc_method: "eth_call".into(),
            request_class: RequestClass::Read,
            chain_id: "92870".into(),
            network_id: "devnet".into(),
            genesis_digest: Digest::of("genesis"),
            contract_address: [1; 20],
            proxy_address: None,
            implementation_address: None,
            code_digest: Digest::of("code"),
            implementation_code_digest: None,
            abi_digest: Digest::of("abi"),
            canonical_signature: "read()".into(),
            selector: [1; 4],
            input_types: vec![],
            named_sets: vec![],
        }],
        resource_artifacts: vec![ConfigurationArtifactV1 {
            artifact_id: source.settings_id.clone(),
            artifact_kind: ConfigurationArtifactKind::CiglSettings,
            artifact_digest: Digest::of(&payload),
            payload_cbor: payload,
        }],
    }
}
async fn verify(
    pool: &sqlx::PgPool,
    f: &Fixture,
    config: &ActiveInvocationConfigurationV1,
    participant: &str,
    privacy: &str,
) -> RuntimeResult<VerifiedCiglSettingsSources> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_SETTINGS_READ_RESOURCE-V1',false)")
        .bind(&f.participant_id).bind(&f.privacy_domain_id).execute(&mut *tx).await.unwrap();
    let bytes = encode_active_invocation_configuration(config).unwrap();
    let result =
        verify_settings_sources(&mut tx, participant, privacy, &bytes, &Digest::of(&bytes)).await;
    tx.rollback().await.unwrap();
    result
}

#[tokio::test]
#[ignore = "requires public governed CIGL settings producer and PostgreSQL worker role"]
async fn postgres_cigl_settings_source_requires_exact_public_provenance() {
    let f: Fixture = serde_json::from_slice(
        &std::fs::read(std::env::var("OPENPC_CIGL_SETTINGS_PUBLICATION_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    let encoded = f
        .source
        .configuration_artifact_cbor
        .strip_prefix("0x")
        .unwrap();
    let payload: Vec<_> = (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(
        format!("sha256:{}", Digest::of(&payload).as_str()),
        f.source.configuration_artifact_digest
    );
    let source = ConfiguredCiglSettings::from_cbor(&payload).unwrap();
    assert_eq!(source.participant_id, f.participant_id);
    assert_eq!(source.privacy_domain_id, f.privacy_domain_id);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let config = configuration(&source);
    let bytes = encode_active_invocation_configuration(&config).unwrap();
    let verified = verify(&pool, &f, &config, &f.participant_id, &f.privacy_domain_id)
        .await
        .unwrap();
    verified.require_configuration(&Digest::of(&bytes)).unwrap();
    assert!(
        verified
            .require_configuration(&Digest::of("another approved configuration"))
            .is_err()
    );
    for change in 0..5 {
        let mut changed = source.clone();
        match change {
            0 => changed.definition.trace_limits.max_frames += 1,
            1 => changed.publication_operation_id = uuid::Uuid::now_v7().to_string(),
            2 => changed.publication_authority_digest = Digest::of("fabricated approval"),
            3 => changed.settings_id = uuid::Uuid::now_v7().to_string(),
            _ => {
                changed.definition.scope = SettingsScope::Chain {
                    chain_id: "92870".into(),
                    network_id: "devnet".into(),
                    genesis_digest: format!("sha256:{}", Digest::of("genesis").as_str()),
                }
            }
        }
        changed.definition_digest = changed.definition.digest().unwrap();
        let changed = configuration(&changed);
        assert!(
            verify(&pool, &f, &changed, &f.participant_id, &f.privacy_domain_id)
                .await
                .is_err(),
            "change {change}"
        );
    }
    let foreign = uuid::Uuid::now_v7().to_string();
    assert!(
        verify(&pool, &f, &config, &foreign, &f.privacy_domain_id)
            .await
            .is_err()
    );
    assert!(
        verify(&pool, &f, &config, &f.participant_id, &foreign)
            .await
            .is_err()
    );
    let mut foreign_context = f;
    foreign_context.privacy_domain_id = foreign;
    assert!(
        verify(
            &pool,
            &foreign_context,
            &config,
            &source.participant_id,
            &source.privacy_domain_id
        )
        .await
        .is_err()
    );

    let installed = InstalledCiglSettings::load(
        &bytes,
        &Digest::of(&bytes),
        &source.participant_id,
        &source.privacy_domain_id,
    )
    .unwrap();
    assert_eq!(
        installed
            .for_environment(
                &source.participant_id,
                &source.privacy_domain_id,
                "92870",
                "devnet",
                &Digest::of("genesis")
            )
            .unwrap(),
        Some(&source)
    );
    // Selection semantics use the exact installed document; only the original
    // source above was verified for publication by the real database owner.
    let mut chain = source.clone();
    chain.settings_id = uuid::Uuid::now_v7().to_string();
    chain.definition.mode = pc_policy_core::cigl::settings::GovernanceMode::Off;
    chain.definition.scope = SettingsScope::Chain {
        chain_id: "92870".into(),
        network_id: "devnet".into(),
        genesis_digest: format!("sha256:{}", Digest::of("genesis").as_str()),
    };
    chain.definition_digest = chain.definition.digest().unwrap();
    let mut joined = config.clone();
    joined
        .resource_artifacts
        .extend(configuration(&chain).resource_artifacts);
    for reverse in [false, true] {
        if reverse {
            joined.resource_artifacts.reverse();
        }
        let bytes = encode_active_invocation_configuration(&joined).unwrap();
        let installed = InstalledCiglSettings::load(
            &bytes,
            &Digest::of(&bytes),
            &source.participant_id,
            &source.privacy_domain_id,
        )
        .unwrap();
        for (network, genesis, expected) in [
            ("devnet", Digest::of("genesis"), &chain),
            ("different network", Digest::of("genesis"), &source),
            ("devnet", Digest::of("other genesis"), &source),
        ] {
            assert_eq!(
                installed
                    .for_environment(
                        &source.participant_id,
                        &source.privacy_domain_id,
                        "92870",
                        network,
                        &genesis
                    )
                    .unwrap(),
                Some(expected)
            );
        }
        assert!(
            InstalledCiglSettings::load(
                &bytes,
                &Digest::of(&bytes),
                &source.participant_id,
                &uuid::Uuid::now_v7().to_string()
            )
            .is_err()
        );
    }
    let mut duplicate = source.clone();
    duplicate.settings_id = uuid::Uuid::now_v7().to_string();
    joined
        .resource_artifacts
        .extend(configuration(&duplicate).resource_artifacts);
    let bytes = encode_active_invocation_configuration(&joined).unwrap();
    assert!(
        InstalledCiglSettings::load(
            &bytes,
            &Digest::of(&bytes),
            &source.participant_id,
            &source.privacy_domain_id
        )
        .is_err()
    );
    pool.close().await;
}
