use super::*;
use openpc_runtime_agent::{
    ArtifactAdmission, ArtifactComponent, RuntimeWireSigner,
    authority_artifact::AuthoritySourceBinding,
};
use pc_policy_core::cigl::grants::GrantEffect;
use std::{path::Path, sync::Arc};

struct RejectOther;
impl ArtifactAdmission for RejectOther {
    fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
        Err(RuntimeError::Denied)
    }
}
async fn wait_file(root: &Path, name: &str) -> Vec<u8> {
    // Source acquisition keeps its short bound. Later durable grant/API
    // regressions perform many independent WebAuthn decisions under the CPU cap;
    // their coordination deadline grants no capsule or source lifetime.
    let seconds = if matches!(
        name,
        "profile-publication.json"
            | "profile-activation-queued.json"
            | "profile-grant-source-changed"
            | "profile-stale-ready"
    ) {
        90
    } else {
        25
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(seconds);
    loop {
        if let Ok(bytes) = std::fs::read(root.join(name)) {
            return bytes;
        }
        assert!(
            !root.join("analysis-api-failed").exists(),
            "public prerequisite failed; compilation BLOCKED"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "public prerequisite {name} timed out"
        );
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
}
async fn context<'a>(
    pool: &'a sqlx::PgPool,
    participant: &str,
    privacy: &str,
) -> Transaction<'a, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
        .bind(participant).bind(privacy).execute(&mut *tx).await.unwrap();
    tx
}

#[tokio::test]
#[ignore = "requires the public analysis/review and live target producer in run-decision-owner.py --cigl-analysis"]
async fn postgres_review_compiles_exact_sources_and_complete_shared_grants() {
    let root =
        std::path::PathBuf::from(std::env::var("OPENPC_ASTRA05_DECISION_OWNER_ROOT").unwrap());
    let source: Value =
        serde_json::from_slice(&wait_file(&root, "analysis-request.json").await).unwrap();
    let material: Value =
        serde_json::from_slice(&wait_file(&root, "analysis-compilation-source.json").await)
            .unwrap();
    let review: Value =
        serde_json::from_slice(&wait_file(&root, "profile-review.json").await).unwrap();
    let participant = field(&source, "participantId").unwrap();
    let privacy = field(&source, "privacyDomainId").unwrap();
    let capsule = RuntimeCapsule::decode(
        &serde_json::from_value::<Vec<u8>>(material["capsule"].clone()).unwrap(),
    )
    .unwrap();
    let artifacts: BTreeMap<Digest, Vec<u8>> =
        serde_json::from_value(material["artifacts"].clone()).unwrap();
    // Pin the existing fixture's deployment trust, never trust an uploaded key.
    let binding = |id: &str| AuthoritySourceBinding {
        artifact_id: id.into(),
        artifact_class: 1,
        source_media_type: "application/cbor".into(),
        definition_digest: Digest::of(format!("test-local {id} definition")),
        signer_id: "fixture-policy-owner".into(),
        maximum_source_bytes: 1024 * 1024,
    };
    let invocation = InvocationArtifactAdmission::new(
        RuntimeWireSigner::from_secret_bytes([94; 32])
            .unwrap()
            .verifier(),
        participant.into(),
        privacy.into(),
        binding("configuration"),
        binding("policy"),
        Arc::new(RejectOther),
    )
    .unwrap();
    let target_key = pc_runtime_types::PurposeSigner::from_secret_bytes(
        openpc_multi_rpc::cigl::analysis::receipt::PURPOSE,
        [84; 32],
    )
    .unwrap()
    .verifier()
    .sec1_bytes();
    let installed = InstalledAnalysisSources {
        capsule: &capsule,
        artifacts: &artifacts,
        invocation: &invocation,
        target_verification_key: &target_key,
    };
    let review_digest = digest(field(&review, "reviewDigest").unwrap()).unwrap();
    let request = ReviewCompilationRequest {
        analysis_id: field(&review, "analysisId").unwrap(),
        review_digest: &review_digest,
        profile_id: field(&review, "profileId").unwrap(),
        revision: 1,
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("OPENPC_CIGL_COMPILATION_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut tx = context(&pool, participant, privacy).await;
    let compiled = compile_reviewed_profile(&mut tx, &installed, &request)
        .await
        .unwrap();
    assert_eq!(compiled.configured().definition.interactions.len(), 1);
    assert_eq!(compiled.methods().len(), 2);
    assert_eq!(compiled.grants().len(), 3);
    assert_eq!(
        compiled
            .configured()
            .grants
            .grants
            .iter()
            .filter(|g| g.effect == GrantEffect::Deny && g.status == GrantStatus::Active)
            .count(),
        1
    );
    assert_eq!(
        compiled
            .configured()
            .grants
            .grants
            .iter()
            .filter(|g| g.status == GrantStatus::Disabled)
            .count(),
        1
    );
    let mut other = context(&pool, participant, privacy).await;
    sqlx::query("SET LOCAL lock_timeout='50ms'")
        .execute(&mut *other)
        .await
        .unwrap();
    assert!(
        sqlx::query("select openpc.lock_cigl_grant_sources()")
            .execute(&mut *other)
            .await
            .is_err(),
        "new DENY rows must not appear inside a compiled snapshot"
    );
    other.rollback().await.unwrap();
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("OPENPC_ASTRA05_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut mutation = admin.begin().await.unwrap();
    sqlx::query("set local role openpc_configuration_runtime")
        .execute(&mut *mutation)
        .await
        .unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1',true)")
        .bind(participant).bind(privacy).execute(&mut *mutation).await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='50ms'")
        .execute(&mut *mutation)
        .await
        .unwrap();
    let blocked = sqlx::query("update control.cigl_method_access_grants set status='DISABLED',revision=revision+1,publication_operation_id=current_setting('openpc.operation_id')::uuid where grant_id=$1::text::uuid")
        .bind(&compiled.grants()[0].grant_id).execute(&mut *mutation).await.unwrap_err();
    assert_eq!(
        blocked.as_database_error().unwrap().code().as_deref(),
        Some("55P03"),
        "the mutation trigger must take the same fence before changing authority"
    );
    mutation.rollback().await.unwrap();
    admin.close().await;
    tx.rollback().await.unwrap();
    let mut old_snapshot = pool.begin().await.unwrap();
    sqlx::query("set transaction isolation level repeatable read")
        .execute(&mut *old_snapshot)
        .await
        .unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
        .bind(participant).bind(privacy).execute(&mut *old_snapshot).await.unwrap();
    assert!(matches!(
        compile_reviewed_profile(&mut old_snapshot, &installed, &request).await,
        Err(RuntimeError::InvalidInput)
    ));
    old_snapshot.rollback().await.unwrap();
    for case in 0..4 {
        let mut changed_capsule = capsule.clone();
        let mut changed_artifacts = artifacts.clone();
        let wrong = Digest::of("unapproved review");
        let mut changed = InstalledAnalysisSources { ..installed };
        let mut changed_request = ReviewCompilationRequest { ..request };
        match case {
            0 => {
                changed_capsule.generation += 1;
                changed.capsule = &changed_capsule;
            }
            1 => {
                let bytes = changed_artifacts
                    .get_mut(&capsule.semantic_model_digest)
                    .unwrap();
                bytes[0] ^= 1;
                changed.artifacts = &changed_artifacts;
            }
            2 => {
                changed.target_verification_key = &[];
            }
            _ => {
                changed_request.review_digest = &wrong;
            }
        }
        let mut tx = context(&pool, participant, privacy).await;
        assert!(
            compile_reviewed_profile(&mut tx, &changed, &changed_request)
                .await
                .is_err(),
            "case {case}"
        );
        tx.rollback().await.unwrap();
    }
    let foreign = uuid::Uuid::now_v7().to_string();
    let mut tx = context(&pool, participant, &foreign).await;
    assert!(
        compile_reviewed_profile(&mut tx, &installed, &request)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    // Reconnect and recompile actual retained public state; no intermediate
    // profile/approval state is seeded by this consumer.
    pool.close().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("OPENPC_CIGL_COMPILATION_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut tx = context(&pool, participant, privacy).await;
    let replay = compile_reviewed_profile(&mut tx, &installed, &request)
        .await
        .unwrap();
    assert_eq!(replay.configured(), compiled.configured());
    tx.rollback().await.unwrap();
    let snapshot = invocation
        .analysis_source_snapshot(&capsule, &artifacts)
        .unwrap();
    assert_eq!(snapshot.len(), 4);
    let sources = InstalledAnalysisSources {
        artifacts: &snapshot,
        ..installed
    };
    use crate::cigl_publication::profile_store;
    let work = profile_store::claim_next(&pool, participant, privacy, "fixture-profile-worker")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(work.profile_id, request.profile_id);
    assert!(
        profile_store::claim_next(&pool, participant, privacy, "other-worker")
            .await
            .unwrap()
            .is_none()
    );
    profile_store::fail_or_retry(&pool, &work, RuntimeError::RuntimeUnavailable)
        .await
        .unwrap();
    let work = profile_store::claim_next(&pool, participant, privacy, "fixture-profile-worker")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(work.attempt_count, 2);
    let signer = pc_runtime_types::PurposeSigner::from_secret_bytes(
        pc_policy_core::cigl::profile::publication::PURPOSE,
        [94; 32],
    )
    .unwrap();
    profile_store::compile_and_commit(&pool, &work, &sources, &signer)
        .await
        .unwrap();
    assert!(
        profile_store::compile_and_commit(&pool, &work, &sources, &signer)
            .await
            .is_err()
    );
    assert!(
        profile_store::claim_next(&pool, participant, privacy, "restarted-worker")
            .await
            .unwrap()
            .is_none()
    );
    std::fs::write(
        root.join("profile-compilation-passed"),
        "Exact sources and complete grants compiled",
    )
    .unwrap();
    use crate::cigl_publication::profile_publication::{
        ProfilePublicationRequest, prepare_publication,
    };
    use pc_policy_core::cigl::profile::publication::grant_sources_digest;
    let publication_sources: Value =
        serde_json::from_slice(&wait_file(&root, "profile-publication.json").await).unwrap();
    let current_grants: Vec<GrantSourceVersion> =
        serde_json::from_value(publication_sources["grants"].clone()).unwrap();
    let current_grants_digest = grant_sources_digest(&current_grants).unwrap();
    assert_eq!(
        current_grants_digest,
        digest(field(&publication_sources, "grantSourcesDigest").unwrap()).unwrap()
    );
    let historical_grants_digest = grant_sources_digest(compiled.grants()).unwrap();
    assert_ne!(current_grants_digest, historical_grants_digest);
    let publication = ProfilePublicationRequest {
        profile_id: request.profile_id,
        revision: request.revision,
        profile_digest: &compiled.configured().definition.digest().unwrap(),
        compilation_artifact_digest: &Digest::of(compiled.configured().to_cbor().unwrap()),
        current_grants_digest: &current_grants_digest,
        participant_epoch: field(&publication_sources, "participantEpoch")
            .unwrap()
            .parse()
            .unwrap(),
    };
    let key = signer.verifier().sec1_bytes();
    let mut tx = context(&pool, participant, privacy).await;
    let prepared = prepare_publication(&mut tx, &installed, &key, &publication)
        .await
        .unwrap();
    assert_eq!(
        prepared.configured().definition,
        compiled.configured().definition
    );
    assert_eq!(prepared.methods(), compiled.methods());
    assert_eq!(prepared.grants().len(), 4);
    assert_eq!(
        grant_sources_digest(prepared.grants()).unwrap(),
        current_grants_digest
    );
    assert_eq!(
        prepared
            .configured()
            .grants
            .grants
            .iter()
            .filter(|g| g.status == GrantStatus::Disabled)
            .count(),
        2
    );
    assert_ne!(
        prepared.configured().to_cbor().unwrap(),
        compiled.configured().to_cbor().unwrap()
    );
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("OPENPC_ASTRA05_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut epoch_change = admin.begin().await.unwrap();
    sqlx::query("set local lock_timeout='50ms'")
        .execute(&mut *epoch_change)
        .await
        .unwrap();
    let blocked = sqlx::query("update control.participant set authority_epoch=authority_epoch+1 where participant_id=$1::text::uuid")
        .bind(participant).execute(&mut *epoch_change).await.unwrap_err();
    assert_eq!(
        blocked.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    epoch_change.rollback().await.unwrap();
    admin.close().await;
    let denied =
        sqlx::query("update control.participant set authority_epoch=authority_epoch where false")
            .execute(&mut *tx)
            .await
            .unwrap_err();
    assert_eq!(
        denied.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
    tx.rollback().await.unwrap();
    let wrong = Digest::of("unapproved publication source");
    for case in 0..6 {
        let mut request = ProfilePublicationRequest { ..publication };
        match case {
            0 => request.current_grants_digest = &historical_grants_digest,
            1 => request.profile_digest = &wrong,
            2 => request.compilation_artifact_digest = &wrong,
            3 => request.participant_epoch += 1,
            4 => request.revision += 1,
            _ => {}
        }
        let mut tx = context(
            &pool,
            participant,
            if case == 5 { &foreign } else { privacy },
        )
        .await;
        assert!(
            prepare_publication(&mut tx, &installed, &key, &request)
                .await
                .is_err(),
            "publication case {case}"
        );
        tx.rollback().await.unwrap();
    }
    let mut tx = context(&pool, participant, privacy).await;
    assert!(
        prepare_publication(&mut tx, &installed, &target_key, &publication)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    std::fs::write(
        root.join("profile-publication-passed"),
        "Reviewed graph retained; exact current shared grants pinned",
    )
    .unwrap();
    let queued: Value =
        serde_json::from_slice(&wait_file(&root, "profile-activation-queued.json").await).unwrap();
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("OPENPC_ASTRA05_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut tx = context(&pool, participant, privacy).await;
    let selected: Value = sqlx::query_scalar("select generation.cigl_profile_selection from control.runtime_configuration_generation generation join control.configuration_work work on work.runtime_configuration_generation_id=generation.runtime_configuration_generation_id where work.configuration_work_id=$1::text::uuid")
        .bind(field(&queued,"workId").unwrap()).fetch_one(&mut *tx).await.unwrap();
    assert!(
        crate::cigl_publication::profile_invalidation::selection_is_current(
            &mut tx,
            participant,
            privacy,
            selected.clone()
        )
        .await
        .unwrap()
    );
    let mut changed = selected.clone();
    // A governance writer cannot cross the source check's authority-root fence.
    // Acquire only its row lock; do not fabricate a lifecycle business state.
    let mut participant_writer = admin.begin().await.unwrap();
    sqlx::query("set local lock_timeout='100ms'")
        .execute(&mut *participant_writer)
        .await
        .unwrap();
    let blocked = sqlx::query("select participant_id from control.participant where participant_id=$1::text::uuid for update")
        .bind(participant).fetch_one(&mut *participant_writer).await.unwrap_err();
    assert_eq!(
        blocked.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    participant_writer.rollback().await.unwrap();
    changed["participantEpoch"] = serde_json::json!("0");
    assert!(
        !crate::cigl_publication::profile_invalidation::selection_is_current(
            &mut tx,
            participant,
            privacy,
            changed
        )
        .await
        .unwrap()
    );
    let mut changed = selected.clone();
    changed["profiles"][0]["grantSourcesDigest"] = serde_json::json!(format!(
        "sha256:{}",
        Digest::of("another grant set").as_str()
    ));
    assert!(
        !crate::cigl_publication::profile_invalidation::selection_is_current(
            &mut tx,
            participant,
            privacy,
            changed
        )
        .await
        .unwrap()
    );
    // Queued approval must never be mistaken for an installed target effect.
    assert!(
        crate::cigl_publication::profile_invalidation::generation_is_invalidated(
            &mut tx,
            &capsule.target_runtime_id,
            field(&queued, "generationId").unwrap(),
            &capsule.digest().unwrap()
        )
        .await
        .is_err()
    );
    let activation = crate::cigl_publication::profile_activation::prepare_activation(
        &mut tx,
        &installed,
        &key,
        field(&queued, "workId").unwrap(),
    )
    .await
    .unwrap();
    activation
        .require_work(
            field(&queued, "workId").unwrap(),
            &digest(field(&queued, "generationDigest").unwrap()).unwrap(),
            &capsule.digest().unwrap(),
        )
        .unwrap();
    assert!(
        activation
            .require_work(request.analysis_id, &wrong, &capsule.digest().unwrap())
            .is_err()
    );
    let (configuration, policy) = invocation
        .analysis_source_bytes(&capsule, &artifacts)
        .unwrap();
    let mut base = pc_policy_core::contract_policy::CompiledContractPolicyBundle {
        configuration_cbor: configuration.to_vec(),
        configuration_digest: Digest::of(configuration),
        policy_cbor: policy.to_vec(),
        policy_digest: Digest::of(policy),
        policies: Vec::new(),
        deployment_policies: Vec::new(),
    };
    // The installed fixture already contains a historical CIGL profile. The
    // production contract compiler supplies base method configuration only;
    // generic resource/profile bytes never enter the composition boundary.
    assert!(activation.bind_invocation(base.clone()).is_err());
    let mut base_configuration =
        pc_policy_core::invocation::decode_active_invocation_configuration(
            configuration,
            &Digest::of(configuration),
        )
        .unwrap();
    base_configuration.resource_artifacts.retain(|artifact| {
        artifact.artifact_kind != pc_policy_core::invocation::ConfigurationArtifactKind::CiglProfile
    });
    base.configuration_cbor =
        pc_policy_core::invocation::encode_active_invocation_configuration(&base_configuration)
            .unwrap();
    base.configuration_digest = Digest::of(&base.configuration_cbor);
    let composed = activation.bind_invocation(base.clone()).unwrap();
    let mut after = pc_policy_core::invocation::decode_active_invocation_policy_generation(
        &composed.policy_cbor,
        &composed.policy_digest,
    )
    .unwrap();
    let before = pc_policy_core::invocation::decode_active_invocation_policy_generation(
        policy,
        &Digest::of(policy),
    )
    .unwrap();
    let root_id = &compiled
        .configured()
        .definition
        .root_contract_method_policy_id;
    let root_policy = after
        .assets
        .iter_mut()
        .find(|asset| &asset.asset_id == root_id)
        .unwrap();
    assert_eq!(
        root_policy.nested_call_set_digest.as_ref(),
        Some(&compiled.configured().definition.digest().unwrap())
    );
    root_policy.nested_call_set_digest = before
        .assets
        .iter()
        .find(|asset| &asset.asset_id == root_id)
        .unwrap()
        .nested_call_set_digest
        .clone();
    assert_eq!(
        after, before,
        "base authorization and version must remain exact"
    );
    let configured = pc_policy_core::invocation::decode_active_invocation_configuration(
        &composed.configuration_cbor,
        &composed.configuration_digest,
    )
    .unwrap();
    let published = configured
        .resource_artifacts
        .iter()
        .find(|artifact| {
            artifact.artifact_kind
                == pc_policy_core::invocation::ConfigurationArtifactKind::CiglProfile
        })
        .unwrap();
    assert_eq!(
        published.payload_cbor,
        prepared.configured().to_cbor().unwrap()
    );
    activation.require_profile_artifacts(&configured).unwrap();
    let mut substituted = configured.clone();
    substituted
        .resource_artifacts
        .iter_mut()
        .find(|artifact| {
            artifact.artifact_kind
                == pc_policy_core::invocation::ConfigurationArtifactKind::CiglProfile
        })
        .unwrap()
        .payload_cbor
        .push(0);
    assert!(activation.require_profile_artifacts(&substituted).is_err());
    let mut missing = configured.clone();
    missing.resource_artifacts.retain(|artifact| {
        artifact.artifact_kind != pc_policy_core::invocation::ConfigurationArtifactKind::CiglProfile
    });
    assert!(activation.require_profile_artifacts(&missing).is_err());
    assert!(
        activation.bind_invocation(composed).is_err(),
        "caller-provided profile artifacts cannot replace the selection"
    );
    let mut changed = base.clone();
    let mut changed_policy = before.clone();
    changed_policy
        .assets
        .iter_mut()
        .find(|asset| &asset.asset_id == root_id)
        .unwrap()
        .required_roles
        .push("unreviewed-role".into());
    changed.policy_cbor =
        pc_policy_core::invocation::encode_active_invocation_policy_generation(&changed_policy)
            .unwrap();
    changed.policy_digest = Digest::of(&changed.policy_cbor);
    assert!(
        activation.bind_invocation(changed).is_err(),
        "same source version cannot hide changed base authority"
    );
    // The source fence must not block STARTED's separate durable transaction.
    // Exercise its work-row lock without seeding a lease or execution result.
    let mut work_update = admin.begin().await.unwrap();
    sqlx::query("set local lock_timeout='100ms'")
        .execute(&mut *work_update)
        .await
        .unwrap();
    assert_eq!(sqlx::query("update control.configuration_work set updated_at=updated_at where configuration_work_id=$1::text::uuid")
        .bind(field(&queued,"workId").unwrap()).execute(&mut *work_update).await.unwrap().rows_affected(), 1);
    work_update.rollback().await.unwrap();
    admin.close().await;
    tx.rollback().await.unwrap();
    let mut tx = context(&pool, participant, privacy).await;
    assert!(
        crate::cigl_publication::profile_activation::prepare_activation(
            &mut tx,
            &installed,
            &key,
            request.analysis_id
        )
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    std::fs::write(
        root.join("profile-activation-composed"),
        "Exact queued approval composes the root binding without changing base authorization",
    )
    .unwrap();
    wait_file(&root, "profile-grant-source-changed").await;
    let mut tx = context(&pool, participant, privacy).await;
    assert!(
        !crate::cigl_publication::profile_invalidation::selection_is_current(
            &mut tx,
            participant,
            privacy,
            selected
        )
        .await
        .unwrap()
    );
    tx.rollback().await.unwrap();
    std::fs::write(
        root.join("profile-grant-invalidation-derived"),
        "The public grant change invalidates the approved source snapshot",
    )
    .unwrap();
    wait_file(&root, "profile-stale-ready").await;
    let mut tx = context(&pool, participant, privacy).await;
    assert!(
        crate::cigl_publication::profile_activation::prepare_activation(
            &mut tx,
            &installed,
            &key,
            field(&queued, "workId").unwrap()
        )
        .await
        .is_err()
    );
    assert!(
        compile_reviewed_profile(&mut tx, &installed, &request)
            .await
            .is_err()
    );
    assert!(
        prepare_publication(&mut tx, &installed, &key, &publication)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    std::fs::write(
        root.join("profile-stale-passed"),
        "Changed generation rejected",
    )
    .unwrap();
    pool.close().await;
}
