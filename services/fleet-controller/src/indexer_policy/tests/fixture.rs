//! Disposable database resolver regression. These are initial reference rows,
//! not evidence of public approval, source activation or acquisition.
use super::*;
use openpc_indexer_adapter::{AcquisitionConfiguration, AcquisitionRequest};
use pc_policy_core::{
    indexer_policy::{IndexerDataClass, IndexerDataRule, IndexerPolicy},
    invocation::{ConfigurationArtifactKind, decode_active_invocation_configuration},
    rpc_policy::{RpcEffect, RpcRule, RpcSurfacePolicy},
    semantics::ModuleBinding,
};
use serde_json::json;

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub(super) fn source_input() -> (PolicySemanticDocument, Vec<u8>) {
    let participant = "018f0000-0000-7000-8000-000000000101";
    let privacy = "018f0000-0000-7000-8000-000000000201";
    let source = "018f0000-0000-7000-8000-000000000301";
    let plan = "018f0000-0000-7000-8000-000000000401";
    let provider = "018f0000-0000-7000-8000-000000000501";
    let workload = "urn:openpc:workload:018f0000-0000-7000-8000-000000000601";
    let base = crate::local_fixture::build_local_configuration_fixture(
        Some(provider),
        Some(source),
        Some(plan),
        Some(workload),
    )
    .unwrap();
    let prepared = crate::local_fixture::indexer::acquisition_input(
        &bytes(&base.configuration_cbor_hex),
        source,
        plan,
        provider,
        AcquisitionConfiguration {
            rate_limit: None,
            runtime_target_id: "018f0000-0000-7000-8000-000000000801".into(),
            request: AcquisitionRequest::StateCall {
                target_address: format!("0x{}", "11".repeat(20)),
                calldata: "0x12345678".into(),
            },
        },
        crate::local_fixture::indexer::AcquisitionFixtureOptions {
            generation: 1,
            confirmation_count: 1,
            state_candidates: false,
        },
    )
    .unwrap();
    let configuration_bytes = bytes(prepared["configurationCborHex"].as_str().unwrap());
    let configuration_digest = Digest::of(&configuration_bytes);
    let configuration =
        decode_active_invocation_configuration(&configuration_bytes, &configuration_digest)
            .unwrap();
    let artifact = |kind| {
        configuration
            .resource_artifacts
            .iter()
            .find(|a| a.artifact_kind == kind)
            .unwrap()
    };
    let profile_artifact = artifact(ConfigurationArtifactKind::ClientIndexerProfile);
    let profile =
        pc_provider_api::decode_client_indexer_profile_pc_cbor(&profile_artifact.payload_cbor)
            .unwrap();
    let plan_artifact = artifact(ConfigurationArtifactKind::ProjectionPlan);
    let rpc = RpcSurfacePolicy {
        schema_version: "1.0.0".into(),
        participant_id: participant.into(),
        privacy_domain_id: privacy.into(),
        rules: vec![RpcRule {
            method: "eth_call".into(),
            effect: RpcEffect::Allow,
            required_roles: vec!["source-reader".into()],
        }],
    };
    let tag = |d: &Digest| format!("sha256:{}", d.as_str());
    let source_digest = tag(&profile_artifact.artifact_digest);
    let plan_digest = tag(&plan_artifact.artifact_digest);
    let document = PolicySemanticDocument {
        visibility_policies: Vec::new(),
        fact_conditions: Vec::new(),
        schema_version: "1.0.0".into(),
        participant_id: participant.into(),
        privacy_domain_id: privacy.into(),
        module_bindings: ["pc.indexing.dedicated-policy", "pc.policy.rpc-surface"]
            .into_iter()
            .map(|module_id| ModuleBinding {
                module_id: module_id.into(),
                semantic_version: "1.0.0".into(),
                manifest_digest: tag(&Digest::of(module_id)),
                configuration_digest: tag(&configuration_digest),
            })
            .collect(),
        indexer_policies: vec![IndexerPolicy {
            schema_version: "1.0.0".into(),
            participant_id: participant.into(),
            privacy_domain_id: privacy.into(),
            workload_id: workload.into(),
            indexer_profile_id: source.into(),
            profile_artifact_digest: source_digest.clone(),
            projection_plan_id: plan.into(),
            plan_artifact_digest: plan_digest.clone(),
            acquisition_configuration_digest: profile.configuration_digest.clone(),
            rpc_policy_digest: tag(&rpc.digest().unwrap()),
            range_start: "1".into(),
            range_end: "10".into(),
            maximum_range_blocks: "10".into(),
            maximum_response_bytes: 10_000,
            rules: vec![IndexerDataRule {
                data_class: IndexerDataClass::StateCall,
                effect: RpcEffect::Allow,
                required_roles: vec!["source-reader".into()],
            }],
        }],
        rpc_policies: vec![rpc],
        contract_policies: vec![],
        deployment_policies: vec![],
        required_facts: vec![],
    };
    document.validate().unwrap();
    (document, configuration_bytes)
}

#[tokio::test]
#[ignore = "requires the disposable migrated Control database owner"]
async fn postgres_source_policy_resolution_with_initial_reference_rows() {
    let admin = sqlx::PgPool::connect(&std::env::var("OPENPC_I02_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let (document, configuration_bytes) = source_input();
    let participant = document.participant_id.as_str();
    let privacy = document.privacy_domain_id.as_str();
    let source = document.indexer_policies[0].indexer_profile_id.as_str();
    let plan = document.indexer_policies[0].projection_plan_id.as_str();
    let source_digest = document.indexer_policies[0].profile_artifact_digest.clone();
    let plan_digest = document.indexer_policies[0].plan_artifact_digest.clone();
    let module = "018f0000-0000-7000-8000-000000000701";
    let installation = "018f0000-0000-7000-8000-000000000702";
    let generation = "018f0000-0000-7000-8000-000000000703";
    let configuration_digest = Digest::of(&configuration_bytes);
    let mut setup = admin.begin().await.unwrap();
    let baseline: i64 = sqlx::query_scalar("select count(*) from control.participant p join control.privacy_domain d on d.participant_id=p.participant_id where p.participant_id=$1::text::uuid and d.privacy_domain_id=$2::text::uuid and p.state='ACTIVE' and d.state='ACTIVE'").bind(participant).bind(privacy).fetch_one(&mut *setup).await.unwrap();
    assert_eq!(baseline, 1, "canonical migrated local scope required");
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true)").bind(participant).bind(privacy).execute(&mut *setup).await.unwrap();
    sqlx::query("insert into control.indexer_profile(indexer_profile_id,participant_id,privacy_domain_id,engine,engine_version,method_profile_digest,policy_generation_digest) values($1::text::uuid,$2::text::uuid,$3::text::uuid,'CLIENT_INDEXER','1.0.0',$4,$4)").bind(source).bind(participant).bind(privacy).bind(&source_digest).execute(&mut *setup).await.unwrap();
    sqlx::query("insert into control.projection_plan(projection_plan_id,participant_id,privacy_domain_id,indexer_profile_id,plan_digest,readiness,policy_generation_digest) values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5,'NOT_READY',$5)").bind(plan).bind(participant).bind(privacy).bind(source).bind(&plan_digest).execute(&mut *setup).await.unwrap();
    sqlx::query("insert into control.module_registration(module_id,display_name,owner) values('pc.config.assets','Source resolver reference module','test')").execute(&mut *setup).await.unwrap();
    sqlx::query("insert into control.module_version(module_version_id,module_id,semantic_version,manifest_cbor,manifest_digest,cose_sign1,sbom_digest,provenance_digest,build_receipt_digest) values($1::text::uuid,'pc.config.assets','1.0.0',$2,sha256($2),$2,sha256($2),sha256($2),sha256($2))").bind(module).bind(b"reference module bytes".as_slice()).execute(&mut *setup).await.unwrap();
    sqlx::query("insert into control.module_installation(module_installation_id,participant_id,privacy_domain_id,module_version_id,state,authority_epoch,delegation_epoch,desired_manifest_digest,lifecycle_operation_id,idempotency_key) values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,'ENABLED',1,1,sha256($5),uuidv7(),'resolver-initial-reference')").bind(installation).bind(participant).bind(privacy).bind(module).bind(b"reference module bytes".as_slice()).execute(&mut *setup).await.unwrap();
    sqlx::query("insert into control.module_configuration_generation(generation_id,participant_id,privacy_domain_id,module_installation_id,generation,configuration_cbor,configuration_digest,active) values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,1,$5,sha256($5),true)").bind(generation).bind(participant).bind(privacy).bind(installation).bind(&configuration_bytes).execute(&mut *setup).await.unwrap();
    let bindings = json!([
        {"kind":"ClientIndexerProfile","id":source,"digest":source_digest,"engineVersion":"1.0.0"},
        {"kind":"ProjectionPlan","id":plan,"digest":plan_digest},
    ]);
    setup.commit().await.unwrap();
    let pool = sqlx::PgPool::connect(
        &std::env::var("OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL").unwrap(),
    )
    .await
    .unwrap();
    // Initial reference rows above are component fixtures. Runtime input
    // admission must still use the installed nonsuperuser consumer and fences.
    let mut input = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)").bind(participant).bind(privacy).execute(&mut *input).await.unwrap();
    sqlx::query("insert into control.runtime_configuration_input(participant_id,privacy_domain_id,module_installation_id,module_configuration_generation_id,configuration_cbor,configuration_digest,resource_bindings,selected) values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5,sha256($5),$6,true)").bind(participant).bind(privacy).bind(installation).bind(generation).bind(&configuration_bytes).bind(bindings).execute(&mut *input).await.unwrap();
    input.commit().await.unwrap();
    verify_resolution(pool, document, configuration_digest).await;
    admin.close().await;
}
