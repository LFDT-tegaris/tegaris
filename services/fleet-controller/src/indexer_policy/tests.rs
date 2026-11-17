use super::*;
use pc_policy_core::{
    contract_simulation::compile_document_with_indexers,
    invocation::decode_active_invocation_policy_generation,
};

#[tokio::test]
#[ignore = "requires the real public source-policy publication and Control worker role"]
async fn postgres_resolves_published_source_policy_for_fleet() {
    let pool = sqlx::PgPool::connect(&std::env::var("OPENPC_SOURCE_POLICY_CONTROL_URL").unwrap())
        .await
        .unwrap();
    let participant = std::env::var("OPENPC_SOURCE_POLICY_PARTICIPANT").unwrap();
    let privacy = std::env::var("OPENPC_SOURCE_POLICY_PRIVACY").unwrap();
    let version = std::env::var("OPENPC_SOURCE_POLICY_SEMANTIC_VERSION").unwrap();
    let policy_id = std::env::var("OPENPC_SOURCE_POLICY_ID").unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true)")
        .bind(&participant).bind(&privacy).execute(&mut *tx).await.unwrap();
    let can_update_module: bool = sqlx::query_scalar(
        "select has_table_privilege(current_user,'control.module_version','UPDATE')",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(
        !can_update_module,
        "use the least-privilege Fleet worker role"
    );
    let semantic: Vec<u8> = sqlx::query_scalar(
        "select version.semantic_cbor from control.policy_version version where version.version=$1 and version.participant_id=$2::text::uuid and version.privacy_domain_id=$3::text::uuid and version.policy_id=$4::text::uuid",
    ).bind(&version).bind(&participant).bind(&privacy).bind(&policy_id).fetch_one(&mut *tx).await.unwrap();
    let document = PolicySemanticDocument::decode(&semantic).unwrap();
    assert!(!document.indexer_policies.is_empty());
    let stored: String = sqlx::query_scalar("select encode(configuration_digest,'hex') from control.runtime_configuration_input_current where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and active")
        .bind(&participant).bind(&privacy).fetch_one(&mut *tx).await.unwrap();
    let configuration_digest = Digest::parse(stored).unwrap();
    tx.rollback().await.unwrap();
    verify_resolution(pool, document, configuration_digest).await;
}

async fn verify_resolution(
    pool: sqlx::PgPool,
    document: PolicySemanticDocument,
    configuration_digest: Digest,
) {
    let participant = document.participant_id.clone();
    let privacy = document.privacy_domain_id.clone();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true)")
        .bind(&participant).bind(&privacy).execute(&mut *tx).await.unwrap();
    let inputs = load_indexer_policy_inputs(&mut tx, &document, &configuration_digest)
        .await
        .unwrap();
    let generation = document.digest().unwrap();
    let compiled = compile_document_with_indexers(
        &document,
        &[],
        &[],
        &inputs,
        &document.indexer_policies[0].workload_id,
        &generation,
    )
    .unwrap();
    let actual =
        decode_active_invocation_policy_generation(&compiled.policy_cbor, &compiled.policy_digest)
            .unwrap();
    assert_eq!(actual.indexer_policies, document.indexer_policies);
    assert!(
        actual.required_facts.is_empty(),
        "source compilation must not invent facts"
    );
    for variant in 0..6 {
        let mut changed = document.clone();
        let policy = &mut changed.indexer_policies[0];
        match variant {
            0 => policy.profile_artifact_digest = format!("sha256:{}", "99".repeat(32)),
            1 => policy.plan_artifact_digest = format!("sha256:{}", "99".repeat(32)),
            2 => policy.acquisition_configuration_digest = format!("sha256:{}", "99".repeat(32)),
            3 => {
                policy.workload_id =
                    "urn:openpc:workload:018f0000-0000-7000-8000-000000000999".into()
            }
            4 => changed.privacy_domain_id = "018f0000-0000-7000-8000-000000000999".into(),
            5 => policy.indexer_profile_id = "018f0000-0000-7000-8000-000000000999".into(),
            _ => unreachable!(),
        }
        assert!(
            load_indexer_policy_inputs(&mut tx, &changed, &configuration_digest)
                .await
                .is_err(),
            "substitution {variant}"
        );
    }
    assert!(
        load_indexer_policy_inputs(&mut tx, &document, &Digest::of(b"old configuration"))
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut restarted = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true)")
        .bind(&participant).bind(&privacy).execute(&mut *restarted).await.unwrap();
    let again = load_indexer_policy_inputs(&mut restarted, &document, &configuration_digest)
        .await
        .unwrap();
    assert_eq!(inputs[0].configuration_cbor, again[0].configuration_cbor);
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true)")
        .bind(&participant).bind("018f0000-0000-7000-8000-000000000999")
        .execute(&mut *restarted).await.unwrap();
    assert!(
        load_indexer_policy_inputs(&mut restarted, &document, &configuration_digest)
            .await
            .is_err(),
        "a valid document cannot override database tenant scope"
    );
    restarted.rollback().await.unwrap();
    pool.close().await;
}

mod fixture;

mod custody;
mod source_request;
